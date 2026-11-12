//! A live caller does not revive an expired independent proxy approver.
use super::*;
use futures_util::StreamExt;

#[tokio::test]
async fn host_event_subscription_rechecks_expiring_approver_after_storage_wait() {
    approver_expiry(false).await;
}
#[tokio::test]
async fn host_event_subscription_rechecks_expiring_approver_after_subscription_row_wait() {
    approver_expiry(true).await;
}
async fn approver_expiry(subscription_row: bool) {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, instance) = f.workload().await;
    let (topic, owner) = event_proxy(&f, deployment).await;
    let mut c = f.app.db.connect().await.unwrap();
    let issued = f
        .app
        .auth
        .login(
            &c,
            owner.subject,
            "correct horse secret test password".into(),
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let approver = f
        .app
        .auth
        .authenticate(
            &c,
            issued["access_token"].as_str().unwrap(),
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_ne!(approver.credential, owner.credential);
    let tx = c.transaction().await.unwrap();
    db::auth_lock(&tx, true).await.unwrap();
    let row=tx.query_one("SELECT t.manifest,d.approval FROM deployments d JOIN installations t ON t.id=d.installation_id WHERE d.id=$1",&[&deployment]).await.unwrap();
    crate::host_blobs::approve(
        &tx,
        &approver,
        deployment,
        &row.get("manifest"),
        &row.get("approval"),
        owner.subject,
    )
    .await
    .unwrap();
    let (sub, _) = events::execute(
        &tx,
        &f.app,
        &owner,
        "createSubscription",
        &std::collections::HashMap::new(),
        &json!({"topic":topic,"name":"expiring approver","start":"earliest"}),
        &axum::http::HeaderMap::new(),
        "",
    )
    .await
    .unwrap();
    let sub: Uuid = sub["id"].as_str().unwrap().parse().unwrap();
    events::append(&tx,&f.app.auth,&owner,&json!({"topic":topic,"version":"1.0.0","payload":{"value":1},"dedupe_key":"approval-expiry"})).await.unwrap();
    events::materialize(&tx).await.unwrap();
    tx.commit().await.unwrap();
    let source = f.source(b"approval-expiry-source".to_vec()).await;
    let (_, context) = f.delegation(deployment, instance, source).await;
    let mut stream = crate::host_events::subscribe(
        f.app.clone(),
        crate::host_calls::Workload {
            instance,
            generation: 7,
        },
        rpc::SubscribeRequest {
            context: Some(context),
            subscription_id: sub.to_string(),
        },
        tokio::time::Instant::now() + Duration::from_secs(120),
    )
    .await
    .unwrap();
    let mut held = f.app.db.connect().await.unwrap();
    let held = held.transaction().await.unwrap();
    if subscription_row {
        held.query_one(
            "SELECT id FROM subscriptions WHERE id=$1 FOR UPDATE",
            &[&sub],
        )
        .await
        .unwrap();
    } else {
        events::fence(&held).await.unwrap();
    }
    let expires:chrono::DateTime<chrono::Utc>=c.query_one(
        "UPDATE credentials SET expires_at=clock_timestamp()+interval '6 seconds' WHERE id=$1 RETURNING expires_at",
        &[&approver.credential],
    )
    .await
    .unwrap().get(0);
    let pending = tokio::spawn(async move { stream.next().await });
    tokio::time::timeout(Duration::from_secs(4),async{
        loop{
            let pattern=if subscription_row {"%subscriptions%FOR UPDATE%"}else{"%event_store_limits%"};
            let blocked:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)",&[&pattern]).await.unwrap().get(0);
            if blocked{break;}
            assert!(!pending.is_finished(),"subscription must wait at the storage fence");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("subscription did not reach the storage fence");
    // The expiry uses wall time, while Tokio sleeps on a monotonic clock.
    // Keep the fence held until both the database and the authority clock see it expire.
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let expired_in_db: bool = c
                .query_one("SELECT clock_timestamp() >= $1", &[&expires])
                .await
                .unwrap()
                .get(0);
            if expired_in_db && chrono::Utc::now() >= expires {
                break;
            }
            assert!(
                !pending.is_finished(),
                "subscription ended before approval expiry"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("approval did not expire while the storage fence was held");
    held.rollback().await.unwrap();
    let next = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    let error = match next {
        Some(Err(error)) => error,
        _ => panic!("expired approver must fail without an event"),
    };
    assert!(
        matches!(
            error.code(),
            tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
        ),
        "expiry must be checked by authority, not hidden by a frame timeout"
    );
    assert!(
        f.app
            .auth
            .authenticate(&c, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
            .await
            .is_ok(),
        "the original caller remains live"
    );
    let count: i64 = c
        .query_one(
            "SELECT count(*) FROM event_deliveries WHERE subscription_id=$1",
            &[&sub],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn host_event_lost_controller_leadership_rolls_back_a_blocked_outbox() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, instance) = f.workload().await;
    let (topic, _) = event_proxy(&f, deployment).await;
    let source = f.source(b"leader-loss-source".to_vec()).await;
    let (_, mut context) = f.delegation(deployment, instance, source).await;
    context.idempotency_key = "leader-loss-publication".into();
    let leader: i32 = f
        .app
        .leader
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let mut held = f.app.db.connect().await.unwrap();
    let held = held.transaction().await.unwrap();
    held.batch_execute("LOCK TABLE outbox IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let request = rpc::PublishEventRequest {
        context: Some(context),
        topic,
        version: "1.0.0".into(),
        payload_json: serde_json::to_vec(&json!({"value":1})).unwrap(),
        dedupe_key: "lost-controller".into(),
    };
    let app = f.app.clone();
    let pending = tokio::spawn(async move {
        crate::host_events::publish(
            &app,
            crate::host_calls::Workload {
                instance,
                generation: 7,
            },
            request,
        )
        .await
    });
    let c = f.app.db.connect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5),async{
        loop{
            let blocked:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO outbox%')",&[]).await.unwrap().get(0);
            if blocked{break;}
            assert!(!pending.is_finished(),"publication must reach the outbox after its authority gate");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("publication did not reach the blocked outbox");
    c.query_one("SELECT pg_terminate_backend($1)", &[&leader])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        while !f.app.leader.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    held.rollback().await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, "NOT_READY");
    let count: i64 = c
        .query_one(
            "SELECT count(*) FROM events WHERE dedupe_key='lost-controller'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 0,
        "a former controller must not commit its pending event"
    );
}
