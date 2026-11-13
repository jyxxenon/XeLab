//! Public cancellation with PostgreSQL journals and a loopback mTLS provider.
use super::*;

async fn read_task(f: &TaskFixture, task: Uuid) -> Value {
    let (status, value) = f
        .host
        .call(
            "getTask",
            &[("task_id", task)],
            Value::Null,
            None,
            "cancel-read-task",
            None,
        )
        .await;
    assert_eq!(status, 200, "{value}");
    value
}

async fn cancel(
    f: &TaskFixture,
    task: Uuid,
    revision: Option<i64>,
    key: &str,
    body: Value,
    token: Option<&str>,
) -> (u16, Value) {
    f.host
        .call(
            "cancelTask",
            &[("task_id", task)],
            body,
            revision,
            key,
            token,
        )
        .await
}

async fn submit(f: &TaskFixture, workflow: Uuid, key: &str) -> Uuid {
    let (status, value) = f
        .host
        .call(
            "createTask",
            &[],
            json!({"workflow_id":workflow,"input":{"message":"task input"}}),
            None,
            key,
            None,
        )
        .await;
    assert_eq!(status, 201, "{value}");
    contracts::id(&value, "id").unwrap()
}

async fn token_with_task_action(f: &TaskFixture, owner: Uuid, action: &str) -> String {
    let (status, key) = f
        .host
        .call(
            "createApiKey",
            &[("account_id", owner)],
            json!({
                "name":format!("Cancellation test {action}"),
                "inheritance":{"mode":"selected","rules":[{
                    "action":action,"resource":{"kind":"task","match":"ids","ids":[f.task]}
                }]},
                "conditions":{"expires_at":Utc::now()+chrono::Duration::days(1)}
            }),
            None,
            action,
            None,
        )
        .await;
    assert_eq!(
        status, 201,
        "Could not create scoped credential for {action}"
    );
    key["secret"].as_str().unwrap().to_owned()
}

async fn cancel_events(c: &tokio_postgres::Client, task: Uuid) -> (i64, i64) {
    let row = c
        .query_one(
            "SELECT count(*) FILTER (WHERE topic='task.cancel.requested'),
                count(*) FILTER (WHERE topic='task.canceled')
         FROM outbox WHERE aggregate_id=$1",
            &[&task],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

#[tokio::test]
async fn postgres_task_cancel_queued_and_leased_work_without_admitting_a_call() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let c = f.host.app.db.connect().await.unwrap();
    let task = read_task(&f, f.task).await;
    let owner = contracts::id(&task, "owner_id").unwrap();
    let revision = task["revision"].as_i64().unwrap();
    let request = json!({"reason":"No further work needed"});
    let (status, error) = cancel(&f, f.task, None, "missing-revision", request.clone(), None).await;
    assert_eq!(status, 428, "{error}");
    for (action, expected) in [("task.read", 403), ("task.cancel", 404)] {
        let token = token_with_task_action(&f, owner, action).await;
        let (status, error) = cancel(
            &f,
            f.task,
            Some(revision),
            action,
            request.clone(),
            Some(&token),
        )
        .await;
        assert_eq!(status, expected, "{action}: {error}");
    }
    assert_eq!(read_task(&f, f.task).await, task);
    assert_eq!(cancel_events(&c, f.task).await, (0, 0));

    let (status, canceled) = cancel(
        &f,
        f.task,
        Some(revision),
        "cancel-queued",
        request.clone(),
        None,
    )
    .await;
    assert_eq!(status, 200, "{canceled}");
    assert_eq!(canceled["state"], "canceled");
    assert_eq!(
        cancel(
            &f,
            f.task,
            Some(revision),
            "cancel-queued",
            request.clone(),
            None
        )
        .await,
        (200, canceled)
    );
    let (status, error) = cancel(
        &f,
        f.task,
        Some(revision),
        "cancel-queued",
        json!({"reason":"A different reason"}),
        None,
    )
    .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(error["error"]["code"], "IDEMPOTENCY_CONFLICT");
    let (status, error) = cancel(
        &f,
        f.task,
        Some(revision),
        "stale-cancel-revision",
        request.clone(),
        None,
    )
    .await;
    assert_eq!(status, 412, "{error}");
    assert_eq!(cancel_events(&c, f.task).await, (1, 1));

    let queued_step = c
        .query_one(
            "SELECT state,attempt_count FROM task_steps WHERE task_id=$1",
            &[&f.task],
        )
        .await
        .unwrap();
    assert_eq!(queued_step.get::<_, String>("state"), "canceled");
    assert_eq!(queued_step.get::<_, i32>("attempt_count"), 0);

    let leased = submit(&f, f.workflow, "cancel-leased-submit").await;
    let lease = f.claim().await;
    assert_eq!(lease.task_id, leased);
    let revision = read_task(&f, leased).await["revision"].as_i64().unwrap();
    let (status, value) = cancel(&f, leased, Some(revision), "cancel-leased", request, None).await;
    assert_eq!(status, 200, "{value}");
    assert_eq!(value["state"], "canceled");
    let error = crate::broker::invoke_task(&f.host.app, &lease)
        .await
        .unwrap_err();
    assert_eq!(error.code, "STATE_CONFLICT");
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let row = c.query_one(
        "SELECT s.state AS step_state,a.state AS attempt_state,a.broker_call_id,q.daily_calls_used,q.concurrent_calls_used,
                (SELECT count(*) FROM calls) AS calls,
                (SELECT count(*) FROM call_credential_charges) AS charges,
                (SELECT count(*) FROM reservations WHERE kind='call') AS reservations
         FROM task_steps s JOIN attempts a ON a.step_id=s.id JOIN tasks t ON t.id=s.task_id
         JOIN quotas q ON q.account_id=t.owner_id WHERE a.id=$1",
        &[&lease.attempt_id],
    ).await.unwrap();
    assert_eq!(row.get::<_, String>("step_state"), "canceled");
    assert_eq!(row.get::<_, String>("attempt_state"), "expired");
    assert!(row.get::<_, Option<Uuid>>("broker_call_id").is_none());
    for column in [
        "daily_calls_used",
        "concurrent_calls_used",
        "calls",
        "charges",
        "reservations",
    ] {
        assert_eq!(row.get::<_, i64>(column), 0, "{column}");
    }
    assert_eq!(cancel_events(&c, leased).await, (1, 1));
}

async fn add_descendant_reservation(c: &mut tokio_postgres::Client, parent: Uuid) -> Uuid {
    let tx = c.transaction().await.unwrap();
    crate::db::call_lock(&tx).await.unwrap();
    let provider = Uuid::new_v4();
    tx.execute(
        "INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at)
         SELECT $2,i.deployment_id,i.generation,1,'ready','alive',i.limits,now(),now()
         FROM calls c JOIN instances i ON i.id=c.provider_instance_id WHERE c.id=$1",
        &[&parent, &provider],
    ).await.unwrap();
    let child = Uuid::new_v4();
    tx.execute(
        "INSERT INTO calls(id,owner_id,credential_id,provider_instance_id,parent_call_id,root_call_id,
                           contract,input_digest,state,deadline_at,created_at)
         SELECT $2,owner_id,credential_id,$3,id,id,contract,input_digest,'running',deadline_at,now()
         FROM calls WHERE id=$1",
        &[&parent, &child, &provider],
    ).await.unwrap();
    let ticket = Uuid::new_v4();
    tx.execute(
        "INSERT INTO host_call_tickets(id,parent_call_id,instance_id,generation,delegation_digest,
                    verification_digest,rpc_context,invocation,bounds,idempotency_key,fingerprint,
                    input_digest,requested_call_id,expires_at)
         SELECT $2,c.id,i.id,i.generation,$3,$4,'{}','{}','[]','cancellation-fixture-child',
                    c.input_digest,c.input_digest,$5,c.deadline_at
         FROM calls c JOIN instances i ON i.id=c.provider_instance_id WHERE c.id=$1",
        &[&parent, &ticket, &vec![1_u8; 32], &vec![2_u8; 32], &child],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO host_child_calls(child_call_id,parent_call_id,ticket_id) VALUES($1,$2,$3)",
        &[&child, &parent, &ticket],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO reservations(id,account_id,kind,status,expires_at,created_at)
         SELECT id,owner_id,'call','active',deadline_at,now() FROM calls WHERE id=$1",
        &[&child],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE quotas SET concurrent_calls_used=concurrent_calls_used+1
         WHERE account_id=(SELECT owner_id FROM calls WHERE id=$1)",
        &[&child],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    child
}

async fn record_test_fence(c: &mut tokio_postgres::Client, call: Uuid) {
    // Model the Controller's post-stop ledger commit. The loopback and seeded
    // descendant fixtures do not exercise OCI runtime fencing.
    let tx = c.transaction().await.unwrap();
    crate::db::call_lock(&tx).await.unwrap();
    assert_eq!(tx.execute(
        "UPDATE reservations SET status='released' WHERE id=$1 AND kind='call' AND status='active'",
        &[&call],
    ).await.unwrap(), 1);
    assert_eq!(
        tx.execute(
            "UPDATE quotas SET concurrent_calls_used=concurrent_calls_used-1
         WHERE account_id=(SELECT owner_id FROM calls WHERE id=$1) AND concurrent_calls_used>0",
            &[&call],
        )
        .await
        .unwrap(),
        1
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn postgres_task_cancel_holds_physical_reservations_until_fenced() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (plugin, server) = echo_with(
        &f.host,
        f.instance,
        Echo {
            unary_gate: Some(gate.clone()),
            ..Echo::default()
        },
    )
    .await;
    let app = f.host.app.clone();
    let dispatch = tokio::spawn(async move { crate::task_worker::run_once(&app).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while plugin.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("The real mTLS provider must enter Invoke");
    let held = f.journal().await;
    let call = held.get::<_, Uuid>("broker_call_id");
    assert_eq!(held.get::<_, String>("call_state"), "running");
    assert_eq!(held.get::<_, String>("reservation_status"), "active");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);

    let mut c = f.host.app.db.connect().await.unwrap();
    // A separate provider journal isolates the descendant reservation check.
    let child = add_descendant_reservation(&mut c, call).await;
    let revision = read_task(&f, f.task).await["revision"].as_i64().unwrap();
    let (status, value) = cancel(
        &f,
        f.task,
        Some(revision),
        "cancel-held",
        json!({"reason":"Stop future dispatch"}),
        None,
    )
    .await;
    assert_eq!(status, 200, "{value}");
    assert_eq!(value["state"], "cancel_requested");
    let pending = f.journal().await;
    for column in ["step_state", "attempt_state", "call_state"] {
        assert_eq!(pending.get::<_, String>(column), "unknown", "{column}");
    }
    assert_eq!(pending.get::<_, String>("reservation_status"), "active");
    assert_eq!(pending.get::<_, i64>("concurrent_calls_used"), 2);
    assert_eq!(cancel_events(&c, f.task).await, (1, 0));
    for id in [call, child] {
        let row = c.query_one(
            "SELECT c.state,c.error,r.status FROM calls c JOIN reservations r ON r.id=c.id WHERE c.id=$1",
            &[&id],
        ).await.unwrap();
        assert_eq!(row.get::<_, String>("state"), "unknown");
        assert_eq!(row.get::<_, Value>("error")["code"], "CANCELED");
        assert_eq!(row.get::<_, String>("status"), "active");
    }

    gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), dispatch)
        .await
        .expect("Canceled dispatch must finish")
        .unwrap()
        .unwrap();
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let retained = f.journal().await;
    assert_eq!(retained.get::<_, String>("task_state"), "cancel_requested");
    assert_eq!(retained.get::<_, String>("call_state"), "unknown");
    assert_eq!(retained.get::<_, String>("reservation_status"), "active");
    assert_eq!(retained.get::<_, i64>("concurrent_calls_used"), 2);
    assert!(retained.get::<_, Option<Value>>("call_result").is_none());

    server.abort();
    let _ = server.await;
    record_test_fence(&mut c, call).await;
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(read_task(&f, f.task).await["state"], "cancel_requested");
    assert_eq!(cancel_events(&c, f.task).await, (1, 0));

    record_test_fence(&mut c, child).await;
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(read_task(&f, f.task).await["state"], "canceled");
    let row = f.journal().await;
    f.assert_admission(&row);
    for column in ["step_state", "attempt_state", "call_state"] {
        assert_eq!(row.get::<_, String>(column), "unknown", "{column}");
    }
    assert_eq!(row.get::<_, Uuid>("broker_call_id"), call);
    assert_eq!(row.get::<_, String>("reservation_status"), "released");
    assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 0);
    assert_eq!(cancel_events(&c, f.task).await, (1, 1));
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn postgres_task_cancel_preserves_committed_call_success_without_starting_dependents() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let revision = read_task(&f, f.task).await["revision"].as_i64().unwrap();
    let (status, value) = cancel(
        &f,
        f.task,
        Some(revision),
        "cancel-unused-fixture",
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, 200, "{value}");

    let (status, workflow) = f
        .host
        .call(
            "createWorkflow",
            &[],
            json!({
                "name":"cancel-committed-call", "input_schema":{"type":"object"},
                "steps":[{
                    "id":"echo","skill_id":f.skill,"depends_on":[],"timeout_ms":20000,
                    "input_mapping":{"message":{"task_input":"/message"}}
                },{
                    "id":"dependent","skill_id":f.skill,"depends_on":["echo"],"timeout_ms":20000,
                    "input_mapping":{"message":{"step_output":{"step":"echo","pointer":"/message"}}}
                }]
            }),
            None,
            "cancel-follow-up-workflow",
            None,
        )
        .await;
    assert_eq!(status, 201, "{workflow}");
    let task = submit(
        &f,
        contracts::id(&workflow, "id").unwrap(),
        "cancel-committed-task",
    )
    .await;
    let (plugin, server) = echo(&f.host, f.instance).await;
    let lease = f.claim().await;
    assert_eq!(lease.task_id, task);
    let result = crate::broker::invoke_task(&f.host.app, &lease)
        .await
        .unwrap();
    let call = contracts::id(&result["call"], "call_id").unwrap();
    let running = read_task(&f, task).await;
    assert_eq!(running["state"], "running");
    let (status, value) = cancel(
        &f,
        task,
        running["revision"].as_i64(),
        "cancel-after-settled-call",
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, 200, "{value}");
    assert_eq!(value["state"], "canceled");

    let c = f.host.app.db.connect().await.unwrap();
    let row = c
        .query_one(
            "SELECT s.state AS step_state,s.output,a.state AS attempt_state,a.broker_call_id,
                c.state AS call_state,c.result,r.status AS reservation_status,
                (SELECT count(*) FROM call_credential_charges) AS charges
         FROM task_steps s JOIN attempts a ON a.step_id=s.id JOIN calls c ON c.id=a.broker_call_id
         JOIN reservations r ON r.id=c.id WHERE a.id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("step_state"), "succeeded");
    assert_eq!(row.get::<_, String>("attempt_state"), "succeeded");
    assert_eq!(row.get::<_, Uuid>("broker_call_id"), call);
    assert_eq!(row.get::<_, String>("call_state"), "succeeded");
    assert_eq!(row.get::<_, Value>("result"), result["call"]);
    assert_eq!(row.get::<_, Value>("output"), result["call"]["output"]);
    assert_eq!(row.get::<_, String>("reservation_status"), "released");
    assert_eq!(row.get::<_, i64>("charges"), 1);
    let dependent = c
        .query_one(
            "SELECT state,attempt_count FROM task_steps WHERE task_id=$1 AND step_key='dependent'",
            &[&task],
        )
        .await
        .unwrap();
    assert_eq!(dependent.get::<_, String>("state"), "canceled");
    assert_eq!(dependent.get::<_, i32>("attempt_count"), 0);
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(cancel_events(&c, task).await, (1, 1));
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}
