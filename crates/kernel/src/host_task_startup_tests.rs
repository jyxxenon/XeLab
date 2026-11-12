//! Real PostgreSQL startup metadata settlement after fixture process stop.
use super::*;

async fn startup_connection(fixture: &TaskFixture) -> tokio_postgres::Client {
    let mut c = fixture.host.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    crate::admission::initialize(
        &tx,
        &fixture.host.app.config.value["resources"],
        8000,
        34_359_738_368,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    c
}

async fn settle_startup(c: &mut tokio_postgres::Client) {
    // Exercise the Controller transaction that follows a positive stop. This
    // component does not start or fence an OCI workload.
    let tx = c.transaction().await.unwrap();
    crate::controller::settle_startup_metadata(&tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn lease_deadline_is_future(c: &tokio_postgres::Client, attempt: Uuid) -> bool {
    c.query_one(
        "SELECT lease_expires_at>clock_timestamp() FROM attempts WHERE id=$1",
        &[&attempt],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
async fn postgres_task_startup_fences_live_dispatched_attempt_without_replaying_confirmed_call() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    let lease = f.claim().await;
    let completed = crate::broker::invoke_task(&f.host.app, &lease)
        .await
        .unwrap();
    let call = contracts::id(&completed["call"], "call_id").unwrap();
    let before = f.journal().await;
    for column in ["task_state", "step_state", "attempt_state"] {
        assert_eq!(before.get::<_, String>(column), "running", "{column}");
    }
    assert_eq!(before.get::<_, String>("call_state"), "succeeded");
    assert_eq!(before.get::<_, Value>("call_result"), completed["call"]);
    assert_eq!(before.get::<_, String>("reservation_status"), "released");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);

    let mut c = startup_connection(&f).await;
    assert_eq!(
        crate::controller::startup_runtime_ids(&c).await.unwrap(),
        vec![f.instance]
    );
    server.abort();
    let _ = server.await;
    assert!(lease_deadline_is_future(&c, lease.attempt_id).await);
    settle_startup(&mut c).await;
    assert!(lease_deadline_is_future(&c, lease.attempt_id).await);
    assert!(crate::controller::startup_runtime_ids(&c)
        .await
        .unwrap()
        .is_empty());
    settle_startup(&mut c).await;

    let row = f.journal().await;
    f.assert_admission(&row);
    for column in ["task_state", "step_state", "attempt_state"] {
        assert_eq!(row.get::<_, String>(column), "unknown", "{column}");
    }
    assert_eq!(row.get::<_, Uuid>("broker_call_id"), call);
    assert_eq!(row.get::<_, String>("call_state"), "succeeded");
    assert_eq!(row.get::<_, Value>("call_result"), completed["call"]);
    assert_eq!(row.get::<_, String>("reservation_status"), "released");
    assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 0);
    let error: Value = row.get("task_error");
    assert_eq!(error["code"], "OUTCOME_UNKNOWN");
    assert_eq!(error["resource_id"], json!(call));

    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let event: Value = c
        .query_one(
            "SELECT payload FROM outbox WHERE topic='task.step.completed' AND aggregate_id=$1",
            &[&lease.step_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        event,
        json!({"task_id":f.task,"step_id":lease.step_id,"attempt_id":lease.attempt_id,"state":"unknown"})
    );
    let counts = c
        .query_one(
            "SELECT (SELECT count(*) FROM attempts),(SELECT count(*) FROM calls),
                (SELECT count(*) FROM call_credential_charges)",
            &[],
        )
        .await
        .unwrap();
    for column in 0..3 {
        assert_eq!(counts.get::<_, i64>(column), 1);
    }
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn postgres_task_startup_requeues_live_unbegun_lease_with_higher_fence_and_same_key() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let lease = f.claim().await;
    let mut c = startup_connection(&f).await;
    assert!(lease_deadline_is_future(&c, lease.attempt_id).await);
    settle_startup(&mut c).await;
    assert!(lease_deadline_is_future(&c, lease.attempt_id).await);
    settle_startup(&mut c).await;
    let row = f.unadmitted().await;
    assert_eq!(row.get::<_, String>("task_state"), "running");
    assert_eq!(row.get::<_, String>("step_state"), "ready");
    assert_eq!(row.get::<_, String>("attempt_state"), "expired");

    // Model the next healthy observation after startup resets provider state.
    c.execute(
        "UPDATE instances SET phase='ready',health='alive',last_heartbeat_at=clock_timestamp()
         WHERE id=$1",
        &[&f.instance],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE provider_records p SET availability='ready',observed_generation=i.generation,
             observed_at=clock_timestamp() FROM instances i WHERE p.instance_id=i.id AND i.id=$1",
        &[&f.instance],
    )
    .await
    .unwrap();
    let replacement = f.claim().await;
    assert_eq!(replacement.step_id, lease.step_id);
    assert_ne!(replacement.attempt_id, lease.attempt_id);
    assert_ne!(replacement.execution_id, lease.execution_id);
    assert!(replacement.fence > lease.fence);
    assert_eq!(replacement.idempotency_key, lease.idempotency_key);

    let tx = c.transaction().await.unwrap();
    let stale = crate::task_engine::complete(
        &tx,
        &f.host.app.auth,
        &lease,
        crate::task_engine::Outcome::Succeeded(json!({"message":"stale output"})),
    )
    .await
    .unwrap_err();
    assert_eq!(stale.code, "STATE_CONFLICT");
    tx.rollback().await.unwrap();
    let attempts = c
        .query(
            "SELECT id,state,broker_call_id FROM attempts WHERE step_id=$1 ORDER BY number",
            &[&lease.step_id],
        )
        .await
        .unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].get::<_, Uuid>("id"), lease.attempt_id);
    assert_eq!(attempts[0].get::<_, String>("state"), "expired");
    assert_eq!(attempts[1].get::<_, Uuid>("id"), replacement.attempt_id);
    assert_eq!(attempts[1].get::<_, String>("state"), "leased");
    for attempt in attempts {
        assert!(attempt.get::<_, Option<Uuid>>("broker_call_id").is_none());
    }
    let unchanged = c.query_one(
        "SELECT (SELECT count(*) FROM calls),(SELECT count(*) FROM call_credential_charges),
                (SELECT count(*) FROM reservations WHERE kind='call'),
                (SELECT count(*) FROM outbox WHERE topic='task.step.completed' AND aggregate_id=$1)",
        &[&lease.step_id],
    ).await.unwrap();
    for column in 0..4 {
        assert_eq!(unchanged.get::<_, i64>(column), 0);
    }
}

#[tokio::test]
async fn postgres_task_startup_preserves_cancel_intent_when_expiring_a_live_lease() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let lease = f.claim().await;
    let mut c = startup_connection(&f).await;
    // Represent persisted cancellation intent with an older unfinished lease.
    let reason = crate::error::Error::new(
        "CANCELED",
        "Persisted cancellation intent",
        axum::http::StatusCode::CONFLICT,
    )
    .detail();
    c.execute(
        "UPDATE tasks SET state='cancel_requested',error=$2 WHERE id=$1",
        &[&f.task, &reason],
    )
    .await
    .unwrap();
    assert!(lease_deadline_is_future(&c, lease.attempt_id).await);

    settle_startup(&mut c).await;
    settle_startup(&mut c).await;
    let row = f.unadmitted().await;
    assert_eq!(row.get::<_, String>("task_state"), "canceled");
    assert_eq!(row.get::<_, String>("step_state"), "canceled");
    assert_eq!(row.get::<_, String>("attempt_state"), "expired");
    let error: Value = c
        .query_one("SELECT error FROM tasks WHERE id=$1", &[&f.task])
        .await
        .unwrap()
        .get(0);
    assert_eq!(error, reason);
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM outbox WHERE topic='task.canceled' AND aggregate_id=$1",
            &[&f.task],
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
}
