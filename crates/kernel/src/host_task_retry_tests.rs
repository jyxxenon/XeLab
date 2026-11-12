//! Capability Task retry through the public API and PostgreSQL Broker journals.
use super::*;

async fn task(f: &TaskFixture, id: Uuid) -> Value {
    let (status, body) = f
        .host
        .call(
            "getTask",
            &[("task_id", id)],
            Value::Null,
            None,
            "retry-read-task",
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    body
}

async fn retry(f: &TaskFixture, id: Uuid, revision: i64, key: &str) -> (u16, Value) {
    f.host
        .call(
            "retryTask",
            &[("task_id", id)],
            Value::Null,
            Some(revision),
            key,
            None,
        )
        .await
}

async fn confirm_no_send(f: &TaskFixture, step: Uuid, revision: i64, key: &str) -> (u16, Value) {
    f.host.call(
        "resolveUnknownStep",
        &[("step_id", step)],
        json!({"resolution":"confirmed_not_executed","evidence":"Checked the original transport record"}),
        Some(revision),
        key,
        None,
    ).await
}

async fn attempts(c: &tokio_postgres::Client, id: Uuid) -> Vec<Row> {
    c.query(
        "SELECT a.*,s.state AS step_state,s.revision AS step_revision,s.fence AS step_fence,
                c.state AS call_state,c.result,r.status AS reservation_status
         FROM attempts a JOIN task_steps s ON s.id=a.step_id
         LEFT JOIN calls c ON c.id=a.broker_call_id LEFT JOIN reservations r ON r.id=c.id AND r.kind='call'
         WHERE s.task_id=$1 ORDER BY a.number",
        &[&id],
    ).await.unwrap()
}

async fn release_after_test_stop(c: &mut tokio_postgres::Client, call: Uuid) {
    // Model the Controller's ledger commit after positive process termination.
    // This component does not start or fence an OCI process.
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
async fn postgres_task_retry_requires_proven_no_send_and_explicit_requeue() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    // Real provider metadata is healthy, but no runtime network address has
    // been created. Broker admission journals a Call and cannot send Invoke.
    assert!(f.host.app.runtime.address(f.instance).is_err());
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let mut c = f.host.app.db.connect().await.unwrap();
    let original = attempts(&c, f.task).await;
    assert_eq!(original.len(), 1);
    let old = &original[0];
    let attempt: Uuid = old.get("id");
    let call: Uuid = old.get("broker_call_id");
    let step: Uuid = old.get("step_id");
    let revision: i64 = old.get("step_revision");
    let fence: i64 = old.get("fence");
    let business_key: String = old.get("idempotency_key");
    assert_eq!(old.get::<_, Option<bool>>("dispatch_started"), Some(false));
    for column in ["state", "step_state", "call_state"] {
        assert_eq!(old.get::<_, String>(column), "unknown", "{column}");
    }
    assert_eq!(old.get::<_, String>("reservation_status"), "active");
    f.assert_admission(&f.journal().await);

    let unknown = task(&f, f.task).await;
    assert_eq!(unknown["state"], "unknown");
    let (status, error) = retry(
        &f,
        f.task,
        unknown["revision"].as_i64().unwrap(),
        "retry-unknown",
    )
    .await;
    assert_eq!(status, 409, "{error}");
    let (status, error) = confirm_no_send(&f, step, revision, "before-runtime-fence").await;
    assert_eq!(status, 409, "{error}");
    release_after_test_stop(&mut c, call).await;

    let (status, resolved) = confirm_no_send(&f, step, revision, "confirm-no-send").await;
    assert_eq!(status, 200, "{resolved}");
    assert_eq!(resolved["state"], "failed");
    assert_eq!(
        confirm_no_send(&f, step, revision, "confirm-no-send").await,
        (200, resolved)
    );
    let row = c
        .query_one(
            "SELECT call_id,resolution,evidence,output_digest FROM task_step_resolutions WHERE attempt_id=$1",
            &[&attempt],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Uuid>("call_id"), call);
    assert_eq!(row.get::<_, String>("resolution"), "confirmed_not_executed");
    assert_eq!(
        row.get::<_, String>("evidence"),
        "Checked the original transport record"
    );
    assert!(row.get::<_, Option<String>>("output_digest").is_none());
    let closed = attempts(&c, f.task).await;
    assert_eq!(closed[0].get::<_, String>("state"), "unknown");
    assert_eq!(closed[0].get::<_, String>("call_state"), "unknown");
    assert_eq!(closed[0].get::<_, i64>("step_fence"), fence + 1);
    let failed = task(&f, f.task).await;
    assert_eq!(failed["state"], "failed");
    let failed_revision = failed["revision"].as_i64().unwrap();

    let (plugin, server) = echo(&f.host, f.instance).await;
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 0);
    assert_eq!(attempts(&c, f.task).await.len(), 1);
    let (status, error) = f
        .host
        .call(
            "retryTask",
            &[("task_id", f.task)],
            json!({}),
            Some(failed_revision),
            "retry-with-body",
            None,
        )
        .await;
    assert_eq!(status, 400, "{error}");
    let (status, error) = retry(&f, f.task, failed_revision - 1, "retry-stale").await;
    assert_eq!(status, 412, "{error}");

    let deadline: DateTime<Utc> = c
        .query_one("SELECT deadline_at FROM tasks WHERE id=$1", &[&f.task])
        .await
        .unwrap()
        .get(0);
    c.execute(
        "UPDATE tasks SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        &[&f.task],
    )
    .await
    .unwrap();
    let (status, error) = retry(&f, f.task, failed_revision, "retry-after-deadline").await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(error["error"]["code"], "STATE_CONFLICT");
    c.execute(
        "UPDATE tasks SET deadline_at=$2 WHERE id=$1",
        &[&f.task, &deadline],
    )
    .await
    .unwrap();

    let (status, requeued) = retry(&f, f.task, failed_revision, "retry-with-proof").await;
    assert_eq!(status, 200, "{requeued}");
    assert_eq!(requeued["state"], "running");
    assert_eq!(
        retry(&f, f.task, failed_revision, "retry-with-proof").await,
        (200, requeued)
    );
    assert_eq!(attempts(&c, f.task).await.len(), 1);
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let rows = attempts(&c, f.task).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, Uuid>("id"), attempt);
    assert_eq!(rows[0].get::<_, String>("state"), "unknown");
    assert_eq!(rows[0].get::<_, Uuid>("broker_call_id"), call);
    let replacement = &rows[1];
    assert_ne!(replacement.get::<_, Uuid>("id"), attempt);
    assert_ne!(replacement.get::<_, Uuid>("broker_call_id"), call);
    assert_eq!(replacement.get::<_, i32>("number"), 2);
    assert!(replacement.get::<_, i64>("fence") > fence);
    assert_eq!(
        replacement.get::<_, String>("idempotency_key"),
        business_key
    );
    assert_eq!(
        replacement.get::<_, Option<bool>>("dispatch_started"),
        Some(true)
    );
    assert_eq!(replacement.get::<_, String>("state"), "succeeded");
    assert_eq!(replacement.get::<_, String>("call_state"), "succeeded");
    assert_eq!(
        replacement.get::<_, String>("reservation_status"),
        "released"
    );
    let finished = task(&f, f.task).await;
    assert_eq!(finished["state"], "succeeded");
    assert_eq!(finished["output"], json!({"echo":{"message":"proxied"}}));
    crate::tasks::snapshot::validate(&c).await.unwrap();
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn postgres_task_retry_rejects_sent_and_legacy_ambiguous_attempts() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    plugin.fail_after_dispatch.store(true, Ordering::SeqCst);
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let mut c = f.host.app.db.connect().await.unwrap();
    let rows = attempts(&c, f.task).await;
    let old = &rows[0];
    let attempt: Uuid = old.get("id");
    let call: Uuid = old.get("broker_call_id");
    let step: Uuid = old.get("step_id");
    let revision: i64 = old.get("step_revision");
    assert_eq!(old.get::<_, Option<bool>>("dispatch_started"), Some(true));
    assert_eq!(old.get::<_, String>("call_state"), "unknown");
    server.abort();
    let _ = server.await;
    release_after_test_stop(&mut c, call).await;

    let (status, error) = confirm_no_send(&f, step, revision, "sent-is-not-proof").await;
    assert_eq!(status, 409, "{error}");
    c.execute(
        "UPDATE attempts SET dispatch_started=NULL WHERE id=$1",
        &[&attempt],
    )
    .await
    .unwrap();
    let (status, error) = confirm_no_send(&f, step, revision, "legacy-is-not-proof").await;
    assert_eq!(status, 409, "{error}");

    let still_unknown = task(&f, f.task).await;
    assert_eq!(still_unknown["state"], "unknown");
    let (status, error) = retry(
        &f,
        f.task,
        still_unknown["revision"].as_i64().unwrap(),
        "retry-ambiguous",
    )
    .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM task_step_resolutions WHERE attempt_id=$1",
            &[&attempt],
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let rows = attempts(&c, f.task).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, String>("state"), "unknown");
    assert_eq!(rows[0].get::<_, i64>("step_revision"), revision);
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
}

async fn fail_before_dispatch(f: &TaskFixture) -> (Uuid, Value) {
    let initial = task(f, f.task).await;
    let (status, canceled) = f
        .host
        .call(
            "cancelTask",
            &[("task_id", f.task)],
            json!({}),
            initial["revision"].as_i64(),
            "cancel-unneeded-fixture-task",
            None,
        )
        .await;
    assert_eq!(status, 200, "{canceled}");
    assert_eq!(canceled["state"], "canceled");

    // This Workflow allows an empty input object, but its first mapping reads
    // /message. The worker therefore fails while still holding an unsent lease.
    let (status, created) = f
        .host
        .call(
            "createTask",
            &[],
            json!({"workflow_id":f.workflow,"input":{}}),
            None,
            "submit-missing-mapping-input",
            None,
        )
        .await;
    assert_eq!(status, 201, "{created}");
    let id = contracts::id(&created, "id").unwrap();
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let failed = task(f, id).await;
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["error"]["code"], "INVALID_ARGUMENT");
    (id, failed)
}

#[tokio::test]
async fn postgres_task_retry_pre_dispatch_failure_rechecks_issuer_and_attempt_budget() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let (id, failed) = fail_before_dispatch(&f).await;
    let c = f.host.app.db.connect().await.unwrap();
    let revision = failed["revision"].as_i64().unwrap();
    let rows = attempts(&c, id).await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].get::<_, bool>("pre_dispatch_failure"));
    assert!(rows[0].get::<_, Option<Uuid>>("broker_call_id").is_none());
    let fence: i64 = rows[0].get("fence");
    let key: String = rows[0].get("idempotency_key");

    let owner = contracts::id(&failed, "owner_id").unwrap();
    let actor = f
        .host
        .app
        .auth
        .login(
            &c,
            owner,
            "correct horse secret test password".into(),
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let operator = actor["access_token"].as_str().unwrap();
    c.execute(
        "UPDATE credentials SET status='revoked' WHERE id=$1",
        &[&f.issuer],
    )
    .await
    .unwrap();
    let (status, error) = f
        .host
        .call(
            "retryTask",
            &[("task_id", id)],
            Value::Null,
            Some(revision),
            "retry-revoked-issuer",
            Some(operator),
        )
        .await;
    assert!(matches!(status, 401 | 403), "{status}: {error}");
    c.execute(
        "UPDATE credentials SET status='active' WHERE id=$1",
        &[&f.issuer],
    )
    .await
    .unwrap();
    assert_eq!(task(&f, id).await, failed);

    let (status, requeued) = retry(&f, id, revision, "retry-before-dispatch").await;
    assert_eq!(status, 200, "{requeued}");
    assert_eq!(requeued["state"], "running");
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let rows = attempts(&c, id).await;
    assert_eq!(rows.len(), 2);
    assert!(rows[1].get::<_, bool>("pre_dispatch_failure"));
    assert!(rows[1].get::<_, Option<Uuid>>("broker_call_id").is_none());
    assert!(rows[1].get::<_, i64>("fence") > fence);
    assert_eq!(rows[1].get::<_, String>("idempotency_key"), key);

    let exhausted = task(&f, id).await;
    assert_eq!(exhausted["state"], "failed");
    let (status, error) = retry(
        &f,
        id,
        exhausted["revision"].as_i64().unwrap(),
        "retry-over-budget",
    )
    .await;
    assert_eq!(status, 409, "{error}");
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let accounting = c
        .query_one(
            "SELECT (SELECT count(*) FROM calls),(SELECT count(*) FROM call_credential_charges),
                (SELECT count(*) FROM reservations WHERE kind='call')",
            &[],
        )
        .await
        .unwrap();
    for column in 0..3 {
        assert_eq!(accounting.get::<_, i64>(column), 0);
    }
}

#[tokio::test]
async fn postgres_task_retry_rechecks_expiring_action_after_step_lock_wait() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let (id, failed) = fail_before_dispatch(&f).await;
    let owner = contracts::id(&failed, "owner_id").unwrap();
    let c = f.host.app.db.connect().await.unwrap();
    let step: Uuid = c
        .query_one("SELECT id FROM task_steps WHERE task_id=$1", &[&id])
        .await
        .unwrap()
        .get(0);
    let mut blocker = f.host.app.db.connect().await.unwrap();
    let lock = blocker.transaction().await.unwrap();
    let blocker_pid: i32 = lock
        .query_one(
            "SELECT pg_backend_pid() FROM task_steps WHERE id=$1 FOR UPDATE",
            &[&step],
        )
        .await
        .unwrap()
        .get(0);

    let expires_at = Utc::now() + chrono::Duration::seconds(8);
    let resource = json!({"kind":"task","match":"ids","ids":[id]});
    let (status, operator) = f.host.call(
        "createApiKey", &[("account_id", owner)],
        json!({
            "name":"Retry action expires during Step lock wait",
            "inheritance":{"mode":"selected","rules":[
                {"action":"task.read","resource":resource},
                {"action":"task.retry","resource":resource,"conditions":{"expires_at":expires_at}},
            ]},
            "conditions":{"expires_at":Utc::now()+chrono::Duration::minutes(5)}
        }),
        None, "create-retry-expiring-action", None,
    ).await;
    assert_eq!(status, 201, "Could not create scoped retry credential");
    let operator_id = contracts::id(&operator["credential"], "id").unwrap();
    let token = operator["secret"].as_str().unwrap();
    let key = "retry-expired-during-step-lock";
    let journal = "SELECT jsonb_build_object('step',to_jsonb(s),
        'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.number) FROM attempts a WHERE a.step_id=s.id),
        'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM outbox o WHERE o.aggregate_id IN (s.id,s.task_id)),
        'idempotency',(SELECT count(*) FROM idempotency_records WHERE credential_id=$2 AND key=$3))
        FROM task_steps s WHERE s.id=$1";
    let before: Value = c
        .query_one(journal, &[&step, &operator_id, &key])
        .await
        .unwrap()
        .get(0);
    assert_eq!(before["attempts"][0]["pre_dispatch_failure"], true);
    assert_eq!(before["idempotency"], 0);

    let params = [("task_id", id)];
    let retry = f.host.call(
        "retryTask",
        &params,
        Value::Null,
        failed["revision"].as_i64(),
        key,
        Some(token),
    );
    tokio::pin!(retry);
    let wait_for_expiry = async {
        let observed: DateTime<Utc> = loop {
            if let Some(row) = c
                .query_opt(
                    "SELECT clock_timestamp() FROM pg_stat_activity WHERE datname=current_database()
                     AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))
                     AND query LIKE '%FOR UPDATE OF s'",
                    &[&blocker_pid],
                )
                .await
                .unwrap()
            {
                break row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(
            observed < expires_at,
            "Retry must reach the lock while authorized"
        );
        tokio::time::sleep((expires_at - Utc::now()).to_std().unwrap_or_default()).await;
        while !c
            .query_one("SELECT clock_timestamp()>=$1", &[&expires_at])
            .await
            .unwrap()
            .get::<_, bool>(0)
            || Utc::now() < expires_at
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    tokio::select! {
        (status, error) = &mut retry => panic!("Retry finished before the Step lock was released: {status} {error}"),
        expired = tokio::time::timeout(Duration::from_secs(12), wait_for_expiry) => {
            expired.expect("Retry must wait on the Step lock until the scoped action expires");
        }
    }
    lock.rollback().await.unwrap();
    let (status, error) = tokio::time::timeout(Duration::from_secs(5), retry)
        .await
        .expect("Retry did not return after release of the Step lock");
    assert_eq!(status, 403, "{error}");
    assert_eq!(error["error"]["code"], "PERMISSION_DENIED");

    let (status, current) = f
        .host
        .call(
            "getTask",
            &params,
            Value::Null,
            None,
            "read-after-retry-expiry",
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{current}");
    assert_eq!(current, failed);
    let after: Value = c
        .query_one(journal, &[&step, &operator_id, &key])
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, before);
}
