//! Public Task resolution backed by PostgreSQL and an actual Broker mTLS Call.
use super::*;

async fn resolve(
    f: &TaskFixture,
    step: Uuid,
    revision: i64,
    key: &str,
    body: Value,
    token: Option<&str>,
) -> (u16, Value) {
    f.host
        .call(
            "resolveUnknownStep",
            &[("step_id", step)],
            body,
            Some(revision),
            key,
            token,
        )
        .await
}

async fn step_version(c: &tokio_postgres::Client, step: Uuid) -> (i64, i64) {
    let row = c
        .query_one(
            "SELECT revision,fence FROM task_steps WHERE id=$1",
            &[&step],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

async fn resolution_count(c: &tokio_postgres::Client) -> i64 {
    c.query_one("SELECT count(*) FROM task_step_resolutions", &[])
        .await
        .unwrap()
        .get(0)
}

async fn scoped_token(f: &TaskFixture, owner: Uuid, action: &str) -> String {
    let (status, key) = f
        .host
        .call(
            "createApiKey",
            &[("account_id", owner)],
            json!({
                "name":format!("Resolution test {action}"),
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

#[tokio::test]
async fn postgres_task_resolution_accepts_only_durable_output_and_replays_once() {
    // Unary Tasks also support capability definitions that offer streaming.
    let Some(f) = TaskFixture::with_capability("none", false, CapabilityFixture::DualMode).await
    else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    let lease = f.claim().await;
    let result = crate::broker::invoke_task(&f.host.app, &lease)
        .await
        .unwrap();
    let call = contracts::id(&result["call"], "call_id").unwrap();
    let output = &result["call"]["output"];
    assert_eq!(*output, json!({"message":"proxied"}));

    let c = f.host.app.db.connect().await.unwrap();
    assert_eq!(
        c.execute(
            "UPDATE attempts SET lease_expires_at=clock_timestamp() WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap(),
        1
    );
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let before = f.journal().await;
    for column in ["task_state", "step_state", "attempt_state"] {
        assert_eq!(before.get::<_, String>(column), "unknown", "{column}");
    }
    assert_eq!(before.get::<_, String>("call_state"), "succeeded");
    let durable_result: Value = before.get("call_result");
    let attempt: Value = c
        .query_one(
            "SELECT to_jsonb(a) FROM attempts a WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap()
        .get(0);
    let owner: Uuid = c
        .query_one("SELECT owner_id FROM tasks WHERE id=$1", &[&f.task])
        .await
        .unwrap()
        .get(0);
    let (revision, fence) = step_version(&c, lease.step_id).await;
    let evidence = "Compared the durable Broker Call result with the provider receipt";
    let body = json!({"resolution":"confirmed_succeeded","evidence":evidence,"output":output});

    for (key, payload, etag, wanted) in [
        (
            "no-evidence",
            json!({"resolution":"confirmed_succeeded","output":output}),
            revision,
            400,
        ),
        (
            "blank-evidence",
            json!({"resolution":"confirmed_succeeded","evidence":" \t\n ","output":output}),
            revision,
            400,
        ),
        (
            "no-output",
            json!({"resolution":"confirmed_succeeded","evidence":evidence}),
            revision,
            400,
        ),
        (
            "different-output",
            json!({"resolution":"confirmed_succeeded","evidence":evidence,"output":{"message":"not the durable result"}}),
            revision,
            409,
        ),
        ("old-revision", body.clone(), revision - 1, 412),
        (
            "not-executed",
            json!({"resolution":"confirmed_not_executed","evidence":"A statement alone is not execution proof"}),
            revision,
            409,
        ),
    ] {
        let (status, error) = resolve(&f, lease.step_id, etag, key, payload, None).await;
        assert_eq!(status, wanted, "{key}: {error}");
    }

    for (action, expected) in [("task.read", 403), ("task.resolve", 404)] {
        let token = scoped_token(&f, owner, action).await;
        let (status, error) = resolve(
            &f,
            lease.step_id,
            revision,
            action,
            body.clone(),
            Some(&token),
        )
        .await;
        assert_eq!(status, expected, "{action}: {error}");
    }

    c.execute(
        "UPDATE task_steps SET fence=fence+1 WHERE id=$1",
        &[&lease.step_id],
    )
    .await
    .unwrap();
    let (status, error) = resolve(
        &f,
        lease.step_id,
        revision,
        "stale-fence",
        body.clone(),
        None,
    )
    .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(step_version(&c, lease.step_id).await, (revision, fence + 1));
    c.execute(
        "UPDATE task_steps SET fence=$2 WHERE id=$1",
        &[&lease.step_id, &fence],
    )
    .await
    .unwrap();

    c.execute(
        "UPDATE calls SET result=result-'output' WHERE id=$1",
        &[&call],
    )
    .await
    .unwrap();
    let (status, error) = resolve(
        &f,
        lease.step_id,
        revision,
        "missing-durable-output",
        body.clone(),
        None,
    )
    .await;
    assert_eq!(status, 409, "{error}");
    c.execute(
        "UPDATE calls SET result=$2 WHERE id=$1",
        &[&call, &durable_result],
    )
    .await
    .unwrap();
    assert_eq!(resolution_count(&c).await, 0);
    assert_eq!(step_version(&c, lease.step_id).await, (revision, fence));
    let untouched = f.journal().await;
    for column in ["task_state", "step_state", "attempt_state"] {
        assert_eq!(untouched.get::<_, String>(column), "unknown", "{column}");
    }

    let (status, resolved) = resolve(
        &f,
        lease.step_id,
        revision,
        "confirm-result",
        body.clone(),
        None,
    )
    .await;
    assert_eq!(status, 200, "{resolved}");
    assert_eq!(resolved["id"], json!(lease.step_id));
    assert_eq!(resolved["state"], "succeeded");
    assert_eq!(
        step_version(&c, lease.step_id).await,
        (revision + 1, fence + 1)
    );
    assert_eq!(
        resolve(
            &f,
            lease.step_id,
            revision,
            "confirm-result",
            body.clone(),
            None
        )
        .await,
        (200, resolved.clone())
    );
    let mut changed = body.clone();
    changed["evidence"] = json!("Different request under the same key");
    let (status, error) =
        resolve(&f, lease.step_id, revision, "confirm-result", changed, None).await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(error["error"]["code"], "IDEMPOTENCY_CONFLICT");
    let (status, error) = resolve(
        &f,
        lease.step_id,
        revision + 1,
        "second-confirmation",
        body,
        None,
    )
    .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(
        step_version(&c, lease.step_id).await,
        (revision + 1, fence + 1)
    );

    let row = c.query_one(
        "SELECT call_id,actor_subject_id,actor_credential_id,request_id,resolution,evidence,output_digest
         FROM task_step_resolutions WHERE attempt_id=$1",
        &[&lease.attempt_id],
    ).await.unwrap();
    assert_eq!(resolution_count(&c).await, 1);
    assert_eq!(row.get::<_, Uuid>("call_id"), call);
    assert_eq!(row.get::<_, Uuid>("actor_subject_id"), owner);
    assert_eq!(row.get::<_, Uuid>("actor_credential_id"), f.issuer);
    assert!(!row.get::<_, Uuid>("request_id").is_nil());
    assert_eq!(row.get::<_, String>("resolution"), "confirmed_succeeded");
    assert_eq!(row.get::<_, String>("evidence"), evidence);
    assert_eq!(
        row.get::<_, String>("output_digest"),
        contracts::digest(&serde_json::to_vec(output).unwrap())
    );
    assert_eq!(
        c.query_one(
            "SELECT to_jsonb(a) FROM attempts a WHERE id=$1",
            &[&lease.attempt_id]
        )
        .await
        .unwrap()
        .get::<_, Value>(0),
        attempt
    );
    let finished = f.journal().await;
    f.assert_admission(&finished);
    assert_eq!(finished.get::<_, String>("task_state"), "succeeded");
    assert_eq!(finished.get::<_, String>("step_state"), "succeeded");
    assert_eq!(finished.get::<_, String>("attempt_state"), "unknown");
    assert_eq!(
        finished.get::<_, Value>("task_output"),
        json!({"echo":output})
    );
    assert!(finished.get::<_, Option<Value>>("task_error").is_none());
    assert_eq!(finished.get::<_, Value>("call_result"), durable_result);
    assert_eq!(finished.get::<_, String>("reservation_status"), "released");
    let accounting = c
        .query_one(
            "SELECT (SELECT count(*) FROM calls), (SELECT count(*) FROM call_credential_charges)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(accounting.get::<_, i64>(0), 1);
    assert_eq!(accounting.get::<_, i64>(1), 1);
    crate::task_engine::validate_resolution_history(&c)
        .await
        .unwrap();
    let mut check = f.host.app.db.connect().await.unwrap();
    let tx = check.transaction().await.unwrap();
    tx.execute(
        "UPDATE task_step_resolutions SET output_digest=$2 WHERE attempt_id=$1",
        &[&lease.attempt_id, &contracts::digest(b"different output")],
    )
    .await
    .unwrap();
    assert_eq!(
        crate::task_engine::validate_resolution_history(&tx)
            .await
            .unwrap_err()
            .code,
        "STATE_CONFLICT"
    );
    tx.rollback().await.unwrap();
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn postgres_task_resolution_refuses_a_linked_call_with_unknown_outcome() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    *plugin.unary_failure.lock().unwrap() = Some(tonic::Status::unavailable(
        "Simulated transport failure after dispatch",
    ));
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let c = f.host.app.db.connect().await.unwrap();
    let before = f.journal().await;
    let step = before.get::<_, Uuid>("step_id");
    let original = step_version(&c, step).await;
    let (status, error) = resolve(&f, step, original.0, "unconfirmed-call", json!({
        "resolution":"confirmed_succeeded","evidence":"No successful result was returned","output":{"message":"proxied"}
    }), None).await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(resolution_count(&c).await, 0);
    assert_eq!(step_version(&c, step).await, original);
    let row = f.journal().await;
    f.assert_admission(&row);
    for column in ["task_state", "step_state", "attempt_state", "call_state"] {
        assert_eq!(row.get::<_, String>(column), "unknown", "{column}");
    }
    assert_eq!(row.get::<_, String>("reservation_status"), "active");
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}
