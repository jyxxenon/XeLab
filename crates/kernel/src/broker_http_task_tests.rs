//! Workflow Task execution through the fixed HTTP Broker and a loopback mTLS provider.
use super::*;

struct Submitted {
    task: Uuid,
    skill: Uuid,
    definition_digest: String,
}

async fn submit(f: &Component, index: usize, mapping: Value, input: Value) -> Submitted {
    let definition = &f.manifest["skills"][index];
    let registered = management(
        &f.router,
        "registerSkill",
        &[],
        &f.token,
        json!({"installation_id":f.installation,"definition":definition}),
        &format!("task-http-register-{index}"),
        None,
    )
    .await;
    assert_eq!(registered.0, 201, "{}", registered.1);
    let skill = contracts::id(&registered.1, "id").unwrap();
    let enabled = management(
        &f.router,
        "setSkillEnabled",
        &[("skill_id", skill.to_string())],
        &f.token,
        json!({"enabled":true}),
        &format!("task-http-enable-{index}"),
        Some(1),
    )
    .await;
    assert_eq!(enabled.0, 200, "{}", enabled.1);
    let workflow = management(
        &f.router,
        "createWorkflow",
        &[],
        &f.token,
        json!({
            "name":format!("task-http-{index}"), "input_schema":{"type":"object"},
            "steps":[{
                "id":"http", "skill_id":skill, "depends_on":[],
                "input_mapping":mapping, "timeout_ms":6000, "maximum_attempts":2
            }]
        }),
        &format!("task-http-workflow-{index}"),
        None,
    )
    .await;
    assert_eq!(workflow.0, 201, "{}", workflow.1);
    let task = management(
        &f.router,
        "createTask",
        &[],
        &f.token,
        json!({"workflow_id":workflow.1["id"],"input":input}),
        &format!("task-http-submit-{index}"),
        None,
    )
    .await;
    assert_eq!(task.0, 201, "{}", task.1);
    assert_eq!(task.1["state"], "queued");
    Submitted {
        task: contracts::id(&task.1, "id").unwrap(),
        skill,
        definition_digest: crate::skills::definition_digest(definition).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_task_http_fixed_skill_executes_json_and_bodyless_operations() {
    let Some(f) = Component::new().await else {
        return;
    };
    let c = f.app.db.connect().await.unwrap();
    let issuer = f
        .app
        .auth
        .authenticate(&c, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap()
        .credential;
    let approval: Uuid = c
        .query_one(
            "SELECT credential_id FROM plugin_http_approvals WHERE deployment_id=$1",
            &[&f.deployment],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(approval, issuer);

    for (index, method, path, mapping, input, output, bytes, calls) in [
        (
            3,
            "PUT",
            "/plugins/org.xelab.http-echo/created",
            json!({"message":{"task_input":"/message"}}),
            json!({"message":"fixed Task PUT"}),
            json!({"message":"fixed Task PUT"}),
            br#"{"message":"fixed Task PUT"}"#.as_slice(),
            1,
        ),
        (
            5,
            "DELETE",
            "/plugins/org.xelab.http-echo/discard",
            json!({}),
            json!({}),
            Value::Null,
            b"".as_slice(),
            2,
        ),
    ] {
        let submitted = submit(&f, index, mapping, input).await;
        assert!(crate::task_worker::run_once(&f.app).await.unwrap());
        let row = c
            .query_one(
                "SELECT t.state AS task_state,t.output AS task_output,t.delegation_id AS task_delegation,
                        s.state AS step_state,s.id AS step_id,a.state AS attempt_state,a.broker_call_id,
                        c.state AS call_state,c.result,c.credential_id,c.skill_id,c.skill_definition_digest,
                        c.input_digest,c.idempotency_key,c.delegation_id AS call_delegation,c.http_binding,
                        i.deployment_id,r.status AS reservation_status,q.daily_calls_used,q.concurrent_calls_used,
                        (SELECT count(*) FROM call_credential_charges WHERE call_id=c.id) AS charges,
                        (SELECT count(*) FROM call_credential_charges WHERE call_id=c.id AND credential_id=$2) AS issuer_charges,
                        (SELECT count(*) FROM calls) AS calls
                 FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN attempts a ON a.step_id=s.id
                 JOIN calls c ON c.id=a.broker_call_id JOIN instances i ON i.id=c.provider_instance_id
                 JOIN reservations r ON r.id=c.id AND r.kind='call' JOIN quotas q ON q.account_id=t.owner_id
                 WHERE t.id=$1",
                &[&submitted.task, &issuer],
            )
            .await
            .unwrap();
        for column in ["task_state", "step_state", "attempt_state", "call_state"] {
            assert_eq!(
                row.get::<_, String>(column),
                "succeeded",
                "{method}: {column}"
            );
        }
        assert_eq!(row.get::<_, Uuid>("skill_id"), submitted.skill);
        assert_eq!(
            row.get::<_, String>("skill_definition_digest"),
            submitted.definition_digest
        );
        assert_eq!(row.get::<_, Uuid>("credential_id"), issuer);
        assert_eq!(row.get::<_, Uuid>("deployment_id"), f.deployment);
        assert_ne!(
            row.get::<_, Uuid>("task_delegation"),
            row.get::<_, Uuid>("call_delegation")
        );
        assert_eq!(row.get::<_, String>("input_digest"), digest(bytes));
        assert_eq!(
            row.get::<_, String>("idempotency_key"),
            format!("task-step:{}", row.get::<_, Uuid>("step_id"))
        );
        assert_eq!(row.get::<_, String>("reservation_status"), "released");
        assert_eq!(row.get::<_, i64>("daily_calls_used"), calls);
        assert_eq!(row.get::<_, i64>("calls"), calls);
        assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 0);
        assert_eq!(row.get::<_, i64>("charges"), 1);
        assert_eq!(row.get::<_, i64>("issuer_charges"), 1);
        let call = row.get::<_, Uuid>("broker_call_id");
        let result = row.get::<_, Value>("result");
        assert_eq!(result["call_id"], json!(call));
        assert_eq!(result["output"], output);
        assert_eq!(row.get::<_, Value>("task_output"), json!({"http":output}));
        let target = &f.manifest["skills"][index]["target"];
        assert_eq!(
            row.get::<_, Value>("http_binding"),
            json!({
                "installation_id":f.installation, "deployment_id":f.deployment, "generation":1,
                "http_contract_digest":target["http_contract_digest"], "operation_id":target["http_operation_id"],
                "method":method, "path":path, "required_action":"plugin.http.invoke"
            })
        );
        assert!(!crate::task_worker::run_once(&f.app).await.unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_task_http_approval_withdrawn_after_claim_prevents_admission() {
    let Some(f) = Component::new().await else {
        return;
    };
    let submitted = submit(
        &f,
        3,
        json!({"message":{"task_input":"/message"}}),
        json!({"message":"approval withdrawal"}),
    )
    .await;
    let mut c = f.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let lease = crate::task_engine::claim_broker(&tx, &f.app.auth)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(lease.task_id, submitted.task);
    assert_eq!(
        c.execute(
            "DELETE FROM plugin_http_approvals WHERE deployment_id=$1",
            &[&f.deployment],
        )
        .await
        .unwrap(),
        1
    );

    let error = crate::broker::invoke_task(&f.app, &lease)
        .await
        .unwrap_err();
    assert_eq!(error.code, "PERMISSION_DENIED");
    let row = c
        .query_one(
            "SELECT a.state,a.broker_call_id,q.daily_calls_used,q.concurrent_calls_used,
                    (SELECT count(*) FROM calls) AS calls,
                    (SELECT count(*) FROM call_credential_charges) AS charges,
                    (SELECT count(*) FROM reservations WHERE kind='call') AS reservations
             FROM attempts a JOIN task_steps s ON s.id=a.step_id JOIN tasks t ON t.id=s.task_id
             JOIN quotas q ON q.account_id=t.owner_id WHERE a.id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("state"), "leased");
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_task_http_resolves_bodyless_call_after_approval_withdrawal() {
    let Some(f) = Component::new().await else {
        return;
    };
    let submitted = submit(&f, 5, json!({}), json!({})).await;
    let mut c = f.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let lease = crate::task_engine::claim_broker(&tx, &f.app.auth)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(lease.task_id, submitted.task);
    let invoked = crate::broker::invoke_task(&f.app, &lease).await.unwrap();
    let result = &invoked["call"];
    assert_eq!(result.get("output"), Some(&Value::Null));
    let call = contracts::id(result, "call_id").unwrap();

    // Simulate worker loss between committing the HTTP response and settling
    // the Task, then remove the provider's authority for further execution.
    let tx = c.transaction().await.unwrap();
    crate::db::auth_lock(&tx, true).await.unwrap();
    assert_eq!(
        tx.execute(
            "UPDATE attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap(),
        1
    );
    assert!(crate::task_engine::expire(&tx).await.unwrap());
    assert_eq!(
        tx.execute(
            "DELETE FROM plugin_http_approvals WHERE deployment_id=$1",
            &[&f.deployment],
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        tx.execute(
            "UPDATE deployments SET spec=jsonb_set(spec,'{enabled}','false') WHERE id=$1",
            &[&f.deployment],
        )
        .await
        .unwrap(),
        1
    );
    tx.commit().await.unwrap();

    let row = c
        .query_one(
            "SELECT t.state AS task_state,t.error,s.state AS step_state,s.revision
         FROM tasks t JOIN task_steps s ON s.task_id=t.id WHERE s.id=$1",
            &[&lease.step_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("task_state"), "unknown");
    assert_eq!(row.get::<_, Value>("error")["resource_id"], json!(call));
    assert_eq!(row.get::<_, String>("step_state"), "unknown");
    let revision: i64 = row.get("revision");
    let params = [("step_id", lease.step_id.to_string())];
    let body = json!({"resolution":"confirmed_succeeded","evidence":"Durable HTTP DELETE result"});
    let missing = management(
        &f.router,
        "resolveUnknownStep",
        &params,
        &f.token,
        body.clone(),
        "task-http-resolve-missing-output",
        Some(revision),
    )
    .await;
    assert_eq!(missing.0, 400, "{}", missing.1);
    assert_eq!(missing.1["error"]["code"], "INVALID_ARGUMENT");

    let mut body = body;
    body["output"] = Value::Null;
    let resolved = management(
        &f.router,
        "resolveUnknownStep",
        &params,
        &f.token,
        body,
        "task-http-resolve-explicit-null",
        Some(revision),
    )
    .await;
    assert_eq!(resolved.0, 200, "{}", resolved.1);
    assert_eq!(resolved.1["state"], "succeeded");
    assert_eq!(resolved.1["revision"], revision + 1);
    let task = management(
        &f.router,
        "getTask",
        &[("task_id", submitted.task.to_string())],
        &f.token,
        Value::Null,
        "task-http-read-resolved",
        None,
    )
    .await;
    assert_eq!(task.0, 200, "{}", task.1);
    assert_eq!(task.1["state"], "succeeded");
    assert_eq!(task.1["output"], json!({"http":null}));

    let row = c.query_one(
        "SELECT a.state AS attempt_state,a.broker_call_id,c.state AS call_state,c.result,
                q.daily_calls_used,q.concurrent_calls_used,
                (SELECT count(*) FROM calls) AS calls,
                (SELECT count(*) FROM call_credential_charges) AS charges,
                (SELECT count(*) FROM task_step_resolutions WHERE attempt_id=a.id AND call_id=c.id) AS resolutions
         FROM attempts a JOIN calls c ON c.id=a.broker_call_id JOIN quotas q ON q.account_id=c.owner_id
         WHERE a.id=$1",
        &[&lease.attempt_id],
    ).await.unwrap();
    assert_eq!(row.get::<_, Uuid>("broker_call_id"), call);
    assert_eq!(row.get::<_, String>("attempt_state"), "unknown");
    assert_eq!(row.get::<_, String>("call_state"), "succeeded");
    assert_eq!(&row.get::<_, Value>("result"), result);
    for column in ["daily_calls_used", "calls", "charges", "resolutions"] {
        assert_eq!(row.get::<_, i64>(column), 1, "{column}");
    }
    assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_task_http_retries_only_after_confirmed_no_send() {
    let Some(f) = Component::new().await else {
        return;
    };
    let output = json!({"message":"HTTP retry after confirmed no-send"});
    let submitted = submit(
        &f,
        3,
        json!({"message":{"task_input":"/message"}}),
        output.clone(),
    )
    .await;
    let mut c = f.app.db.connect().await.unwrap();
    let instance: Uuid = c
        .query_one(
            "SELECT id FROM instances WHERE deployment_id=$1",
            &[&f.deployment],
        )
        .await
        .unwrap()
        .get(0);
    let network = f
        .app
        .config
        .root()
        .join("runtime")
        .join(instance.to_string())
        .join("network.json");
    let hidden = network.with_extension("missing");
    fs::rename(&network, &hidden).unwrap();
    assert!(f.app.runtime.address(instance).is_err());
    assert!(crate::task_worker::run_once(&f.app).await.unwrap());

    let old = c.query_one(
        "SELECT a.id,a.broker_call_id,a.idempotency_key,a.dispatch_started,a.state AS attempt_state,
                s.id AS step_id,s.revision,s.state AS step_state,c.state AS call_state,r.status
         FROM task_steps s JOIN attempts a ON a.step_id=s.id JOIN calls c ON c.id=a.broker_call_id
         JOIN reservations r ON r.id=c.id AND r.kind='call' WHERE s.task_id=$1",
        &[&submitted.task],
    ).await.unwrap();
    let old_attempt: Uuid = old.get("id");
    let old_call: Uuid = old.get("broker_call_id");
    let step: Uuid = old.get("step_id");
    let step_revision: i64 = old.get("revision");
    let business_key = format!("task-step:{step}");
    assert_eq!(old.get::<_, String>("idempotency_key"), business_key);
    assert_eq!(old.get::<_, Option<bool>>("dispatch_started"), Some(false));
    for column in ["attempt_state", "step_state", "call_state"] {
        assert_eq!(old.get::<_, String>(column), "unknown", "{column}");
    }
    assert_eq!(old.get::<_, String>("status"), "active");

    // Model the Controller's ledger commit after stop confirmation. This
    // loopback fixture leaves its HTTP server available for the next attempt.
    let tx = c.transaction().await.unwrap();
    crate::db::call_lock(&tx).await.unwrap();
    let released = tx.execute(
        "WITH released AS (
             UPDATE reservations SET status='released' WHERE id=$1 AND kind='call' AND status='active'
             RETURNING account_id
         ) UPDATE quotas q SET concurrent_calls_used=concurrent_calls_used-1
           FROM released r WHERE q.account_id=r.account_id AND q.concurrent_calls_used=1",
        &[&old_call],
    ).await.unwrap();
    assert_eq!(released, 1);
    tx.commit().await.unwrap();
    let resolved = management(
        &f.router,
        "resolveUnknownStep",
        &[("step_id", step.to_string())],
        &f.token,
        json!({"resolution":"confirmed_not_executed","evidence":"The HTTP runtime address was absent before dispatch"}),
        "task-http-confirm-no-send",
        Some(step_revision),
    )
    .await;
    assert_eq!(resolved.0, 200, "{}", resolved.1);
    assert_eq!(resolved.1["state"], "failed");

    fs::rename(&hidden, &network).unwrap();
    assert!(!crate::task_worker::run_once(&f.app).await.unwrap());
    let task_params = [("task_id", submitted.task.to_string())];
    let failed = management(
        &f.router,
        "getTask",
        &task_params,
        &f.token,
        Value::Null,
        "task-http-read-failed",
        None,
    )
    .await;
    assert_eq!(failed.0, 200, "{}", failed.1);
    assert_eq!(failed.1["state"], "failed");
    let retried = management(
        &f.router,
        "retryTask",
        &task_params,
        &f.token,
        Value::Null,
        "task-http-explicit-retry",
        Some(failed.1["revision"].as_i64().unwrap()),
    )
    .await;
    assert_eq!(retried.0, 200, "{}", retried.1);
    assert_eq!(retried.1["state"], "running");
    assert!(crate::task_worker::run_once(&f.app).await.unwrap());

    let calls = c.query(
        "SELECT a.id,a.dispatch_started,a.state AS attempt_state,a.idempotency_key AS attempt_key,
                c.id AS call_id,c.idempotency_key AS call_key,c.state AS call_state,c.result,
                c.provider_instance_id,r.status,t.state AS task_state,t.output,q.daily_calls_used,
                q.concurrent_calls_used
         FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN attempts a ON a.step_id=s.id
         JOIN calls c ON c.id=a.broker_call_id JOIN reservations r ON r.id=c.id AND r.kind='call'
         JOIN quotas q ON q.account_id=t.owner_id WHERE t.id=$1 ORDER BY a.number",
        &[&submitted.task],
    ).await.unwrap();
    let [unsent, sent] = calls.as_slice() else {
        panic!("expected one unsent Call and one retried Call");
    };
    assert_eq!(unsent.get::<_, Uuid>("id"), old_attempt);
    assert_eq!(unsent.get::<_, Uuid>("call_id"), old_call);
    assert_eq!(
        unsent.get::<_, Option<bool>>("dispatch_started"),
        Some(false)
    );
    assert_eq!(unsent.get::<_, String>("call_state"), "unknown");
    assert!(unsent.get::<_, Option<Value>>("result").is_none());
    assert_ne!(sent.get::<_, Uuid>("call_id"), old_call);
    assert_eq!(sent.get::<_, Option<bool>>("dispatch_started"), Some(true));
    for column in ["attempt_state", "call_state", "task_state"] {
        assert_eq!(sent.get::<_, String>(column), "succeeded", "{column}");
    }
    assert_eq!(sent.get::<_, Value>("result")["output"], output);
    assert_eq!(sent.get::<_, Value>("output"), json!({"http":output}));
    for call in calls {
        assert_eq!(call.get::<_, String>("attempt_key"), business_key);
        assert_eq!(call.get::<_, String>("call_key"), business_key);
        assert_eq!(call.get::<_, Uuid>("provider_instance_id"), instance);
        assert_eq!(call.get::<_, String>("status"), "released");
        assert_eq!(call.get::<_, i64>("daily_calls_used"), 2);
        assert_eq!(call.get::<_, i64>("concurrent_calls_used"), 0);
    }
}
