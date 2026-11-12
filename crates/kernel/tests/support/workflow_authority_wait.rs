use super::{request, Fixture, Reply, WORKFLOWS};
use axum::http::Method;
use chrono::{DateTime, Utc};
use serde_json::json;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_postgres::Client;

async fn expiring_rule_key(f: &Fixture, c: &Client, action: &str) -> (String, DateTime<Utc>) {
    let expires_at: DateTime<Utc> = c
        .query_one("SELECT clock_timestamp()+interval '5 seconds'", &[])
        .await
        .unwrap()
        .get(0);
    let resource = json!({"kind":"workflow","match":"owned_by","owner_id":f.owner});
    let mut rules =
        vec![json!({"action":action,"resource":resource,"conditions":{"expires_at":expires_at}})];
    if action == "workflow.archive" {
        rules.push(json!({"action":"workflow.read","resource":resource}));
    }
    let response = request(
        &f.router,
        Method::POST,
        &format!("/api/platform/v1/accounts/{}/api-keys", f.owner),
        Some(&f.token),
        Some(&json!({
            "name":action,
            "inheritance":{"mode":"selected","rules":rules},
            "conditions":{"expires_at":Utc::now()+chrono::Duration::days(1)}
        })),
        &[("idempotency-key", action)],
    )
    .await
    .expect(201);
    (
        response.body["secret"].as_str().unwrap().to_owned(),
        expires_at,
    )
}

async fn wait_for_rule_expiry(
    c: &Client,
    blocker_pid: i32,
    expires_at: DateTime<Utc>,
    pending: &JoinHandle<Reply>,
) {
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut saw_wait_while_live = false;
        loop {
            let row = c
                .query_one(
                    "SELECT clock_timestamp() < $2, EXISTS (
                     SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
                     AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))
                 )",
                    &[&blocker_pid, &expires_at],
                )
                .await
                .unwrap();
            let live: bool = row.get(0);
            let blocked: bool = row.get(1);
            assert!(
                !pending.is_finished(),
                "request must wait for the held lock"
            );
            saw_wait_while_live |= live && blocked;
            if !live {
                assert!(
                    saw_wait_while_live && blocked,
                    "request must reach the lock before authority expires"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("database clock must cross the rule expiration");
}

async fn assert_denied_without_replay(c: &Client, pending: JoinHandle<Reply>, key: &str) {
    let result = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("request must complete after lock release")
        .unwrap()
        .expect(403);
    assert_eq!(result.body["error"]["code"], "PERMISSION_DENIED");
    let recorded: bool = c
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM idempotency_records WHERE key=$1)",
            &[&key],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !recorded,
        "denied request must not store a successful replay"
    );
}

#[tokio::test]
async fn publish_rechecks_workflow_authority_after_version_lock() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let spec = f.spec("expiring publisher");
    let observer = f.db.connect().await.unwrap();
    let mut blocker = f.db.connect().await.unwrap();
    let pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let hold = blocker.transaction().await.unwrap();
    let lock = format!(
        "workflow-version:{}:{}",
        f.owner,
        spec["name"].as_str().unwrap()
    );
    hold.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        &[&lock],
    )
    .await
    .unwrap();

    let key = "publish-after-rule-expiration";
    let (token, expires_at) = expiring_rule_key(&f, &observer, "workflow.create").await;
    let router = f.router.clone();
    let pending = tokio::spawn(async move {
        request(
            &router,
            Method::POST,
            WORKFLOWS,
            Some(&token),
            Some(&spec),
            &[("idempotency-key", key)],
        )
        .await
    });
    wait_for_rule_expiry(&observer, pid, expires_at, &pending).await;
    hold.rollback().await.unwrap();
    assert_denied_without_replay(&observer, pending, key).await;

    let count: i64 = observer
        .query_one("SELECT count(*) FROM workflows", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    assert_eq!(
        f.publish(
            &f.token,
            &f.spec("authorized publication"),
            "live-publisher"
        )
        .await
        .expect(201)
        .body["version"],
        1
    );
}

#[tokio::test]
async fn archive_rechecks_workflow_authority_after_row_lock() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let before = f
        .publish(&f.token, &f.spec("archive test"), "publish-archive-target")
        .await
        .expect(201);
    let id = super::contracts::id(&before.body, "id").unwrap();
    let uri = format!("{WORKFLOWS}/{id}");
    let observer = f.db.connect().await.unwrap();
    let mut blocker = f.db.connect().await.unwrap();
    let pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let hold = blocker.transaction().await.unwrap();
    hold.query_one("SELECT id FROM workflows WHERE id=$1 FOR UPDATE", &[&id])
        .await
        .unwrap();

    let key = "archive-after-rule-expiration";
    let (token, expires_at) = expiring_rule_key(&f, &observer, "workflow.archive").await;
    let actor = token.clone();
    let router = f.router.clone();
    let target = uri.clone();
    let etag = before.etag.as_deref().unwrap().to_owned();
    let pending = tokio::spawn(async move {
        request(
            &router,
            Method::DELETE,
            &target,
            Some(&actor),
            None,
            &[("idempotency-key", key), ("if-match", &etag)],
        )
        .await
    });
    wait_for_rule_expiry(&observer, pid, expires_at, &pending).await;
    hold.rollback().await.unwrap();
    assert_denied_without_replay(&observer, pending, key).await;

    let after = f.read(&token, &uri).await.expect(200);
    assert_eq!(after.body, before.body);
    assert_eq!(after.etag, before.etag);
}
