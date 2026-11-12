//! Schedule control-plane, durable fires, and loopback Task execution.
use super::*;
use chrono::TimeDelta;
use tokio_postgres::Client;

fn spec(f: &TaskFixture) -> Value {
    json!({
        "name": "schedule-fixture",
        "workflow_id": f.workflow,
        "cron": "* * * * *",
        "input": {"message": "scheduled input"}
    })
}

async fn create(f: &TaskFixture, spec: Value, key: &str) -> Value {
    let (status, value) = f
        .host
        .call("createSchedule", &[], spec, None, key, None)
        .await;
    assert_eq!(status, 201, "{value}");
    value
}

async fn schedule_call(
    f: &TaskFixture,
    op: &str,
    id: Uuid,
    body: Value,
    revision: Option<i64>,
    key: &str,
) -> (u16, Value) {
    f.host
        .call(op, &[("schedule_id", id)], body, revision, key, None)
        .await
}

async fn get(f: &TaskFixture, id: Uuid) -> Value {
    let (status, value) =
        schedule_call(f, "getSchedule", id, Value::Null, None, "read-schedule").await;
    assert_eq!(status, 200, "{value}");
    value
}

async fn list_page(f: &TaskFixture, cursor: Option<&str>) -> Value {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", "1");
    if let Some(cursor) = cursor {
        query.append_pair("cursor", cursor);
    }
    let mut request = Request::get(format!("/api/platform/v1/schedules?{}", query.finish()))
        .header(
            "host",
            crate::plugin_http_gateway::core_authority(&f.host.app.config).unwrap(),
        )
        .header("authorization", format!("Bearer {}", f.host.token))
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:30000".parse::<SocketAddr>().unwrap(),
    ));
    let response = f.host.router.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, 200, "{value}");
    value
}

async fn read_task(f: &TaskFixture, id: Uuid) -> Value {
    let (status, value) = f
        .host
        .call(
            "getTask",
            &[("task_id", id)],
            Value::Null,
            None,
            "schedule-read-task",
            None,
        )
        .await;
    assert_eq!(status, 200, "{value}");
    value
}

async fn cancel_fixture_task(f: &TaskFixture) {
    let revision = read_task(f, f.task).await["revision"].as_i64().unwrap();
    let (status, value) = f
        .host
        .call(
            "cancelTask",
            &[("task_id", f.task)],
            json!({"reason": "Leave only scheduled work eligible for dispatch"}),
            Some(revision),
            "schedule-cancel-fixture",
            None,
        )
        .await;
    assert_eq!(status, 200, "{value}");
    assert_eq!(value["state"], "canceled");
}

fn next(schedule: &Value) -> DateTime<Utc> {
    schedule["next_fire_at"].as_str().unwrap().parse().unwrap()
}

async fn tick(f: &TaskFixture, now: DateTime<Utc>, startup_cutoff: DateTime<Utc>) -> bool {
    let mut c = f.host.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let worked = crate::schedules::tick(&tx, &f.host.app.auth, now, startup_cutoff)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    worked
}

async fn fires(c: &Client, id: Uuid) -> Vec<(DateTime<Utc>, String, Option<Uuid>)> {
    c.query(
        "SELECT scheduled_at,outcome,task_id FROM schedule_fires
         WHERE schedule_id=$1 ORDER BY scheduled_at",
        &[&id],
    )
    .await
    .unwrap()
    .into_iter()
    .map(|row| (row.get(0), row.get(1), row.get(2)))
    .collect()
}

async fn task_count(c: &Client) -> i64 {
    c.query_one("SELECT count(*) FROM tasks", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn postgres_task_schedule_api_etags_idempotency_and_paging() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let body = spec(&f);
    let first = create(&f, body.clone(), "schedule-create-first").await;
    let id = contracts::id(&first, "id").unwrap();
    assert_eq!(first["revision"], 1);
    assert_eq!(first["spec"]["timezone"], "Asia/Shanghai");
    assert_eq!(first["spec"]["misfire"], "skip");
    assert_eq!(first["spec"]["overlap"], "skip");
    assert_eq!(
        create(&f, body.clone(), "schedule-create-first").await,
        first
    );
    assert_eq!(get(&f, id).await, first);

    let mut changed = body;
    changed["enabled"] = json!(false);
    let (status, value) = f
        .host
        .call(
            "createSchedule",
            &[],
            changed.clone(),
            None,
            "schedule-create-first",
            None,
        )
        .await;
    assert_eq!(status, 409, "{value}");
    assert_eq!(value["error"]["code"], "IDEMPOTENCY_CONFLICT");

    let second = create(&f, changed.clone(), "schedule-create-second").await;
    assert!(second["next_fire_at"].is_null());
    let page_one = list_page(&f, None).await;
    let cursor = page_one["next_cursor"].as_str().unwrap();
    let page_two = list_page(&f, Some(cursor)).await;
    assert!(page_two["next_cursor"].is_null());
    let mut ids: Vec<_> = [&page_one, &page_two]
        .iter()
        .map(|page| {
            let items = page["items"].as_array().unwrap();
            assert_eq!(items.len(), 1);
            contracts::id(&items[0], "id").unwrap()
        })
        .collect();
    ids.sort_unstable();
    let mut expected = [id, contracts::id(&second, "id").unwrap()];
    expected.sort_unstable();
    assert_eq!(ids, expected);

    let (status, error) = schedule_call(
        &f,
        "updateSchedule",
        id,
        changed.clone(),
        None,
        "schedule-no-etag",
    )
    .await;
    assert_eq!(status, 428, "{error}");
    let (status, disabled) = schedule_call(
        &f,
        "updateSchedule",
        id,
        changed.clone(),
        Some(1),
        "schedule-disable",
    )
    .await;
    assert_eq!(status, 200, "{disabled}");
    assert_eq!(disabled["revision"], 2);
    assert_eq!(disabled["spec"]["enabled"], false);
    assert!(disabled["next_fire_at"].is_null());
    assert_eq!(
        schedule_call(
            &f,
            "updateSchedule",
            id,
            changed.clone(),
            Some(1),
            "schedule-disable"
        )
        .await,
        (200, disabled)
    );
    let (status, error) =
        schedule_call(&f, "updateSchedule", id, changed, Some(1), "schedule-stale").await;
    assert_eq!(status, 412, "{error}");
    for _ in 0..2 {
        assert_eq!(
            schedule_call(
                &f,
                "deleteSchedule",
                id,
                Value::Null,
                Some(2),
                "schedule-delete"
            )
            .await,
            (204, Value::Null)
        );
    }
    assert_eq!(
        schedule_call(
            &f,
            "getSchedule",
            id,
            Value::Null,
            None,
            "schedule-after-delete"
        )
        .await
        .0,
        404
    );
    let remaining = list_page(&f, None).await;
    assert_eq!(remaining["items"], json!([second]));
    assert!(remaining["next_cursor"].is_null());
}

#[tokio::test]
async fn postgres_task_schedule_concurrent_fire_replay_and_execution_after_delete() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    cancel_fixture_task(&f).await;
    let body = spec(&f);
    let schedule = create(&f, body.clone(), "schedule-concurrent").await;
    let id = contracts::id(&schedule, "id").unwrap();
    let at = next(&schedule);
    let cutoff = at - TimeDelta::minutes(1);
    let mut a = f.host.app.db.connect().await.unwrap();
    let mut b = f.host.app.db.connect().await.unwrap();
    let left = a.transaction().await.unwrap();
    let right = b.transaction().await.unwrap();
    let auth = &f.host.app.auth;
    // Keep both transactions open while they contend for the same schedule.
    let (one, two) = tokio::join!(
        crate::schedules::tick(&left, auth, at, cutoff),
        crate::schedules::tick(&right, auth, at, cutoff)
    );
    assert_ne!(one.unwrap(), two.unwrap());
    left.commit().await.unwrap();
    right.commit().await.unwrap();

    let first = fires(&a, id).await;
    assert_eq!(first.len(), 1);
    let task = first[0].2.unwrap();
    assert_eq!(first[0], (at, "created".to_owned(), Some(task)));
    assert_eq!(task_count(&a).await, 2);
    assert!(!tick(&f, at, cutoff).await);

    // Replay a persisted cursor with a known link. The existing Task must win
    // before the scheduler considers overlap or inserts a new fire.
    a.execute(
        "UPDATE schedule_fires SET outcome='pending' WHERE schedule_id=$1 AND scheduled_at=$2",
        &[&id, &at],
    )
    .await
    .unwrap();
    a.execute(
        "UPDATE schedules SET next_fire_at=$2 WHERE id=$1",
        &[&id, &at],
    )
    .await
    .unwrap();
    assert!(tick(&f, at, cutoff).await);
    assert_eq!(fires(&a, id).await, first);
    assert_eq!(task_count(&a).await, 2);

    let original = read_task(&f, task).await;
    assert_eq!(original["state"], "queued");
    assert_eq!(original["workflow_id"], json!(f.workflow));
    assert_eq!(original["input"], body["input"]);
    let delegation = contracts::id(&original, "delegation_id").unwrap();
    assert_ne!(
        delegation,
        contracts::id(&schedule, "delegation_id").unwrap()
    );
    let saved = a
        .query_one(
            "SELECT issuer_credential_id,status FROM execution_delegations WHERE id=$1",
            &[&delegation],
        )
        .await
        .unwrap();
    assert_eq!(saved.get::<_, Uuid>(0), f.issuer);
    assert_eq!(saved.get::<_, &str>(1), "active");

    let mut changed = body;
    changed["input"] = json!({"message": "new scheduled input"});
    let revision = get(&f, id).await["revision"].as_i64().unwrap();
    let (status, updated) = schedule_call(
        &f,
        "updateSchedule",
        id,
        changed,
        Some(revision),
        "schedule-change-input",
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert_ne!(updated["delegation_id"], schedule["delegation_id"]);
    assert_eq!(
        schedule_call(
            &f,
            "deleteSchedule",
            id,
            Value::Null,
            updated["revision"].as_i64(),
            "schedule-delete-active",
        )
        .await,
        (204, Value::Null)
    );
    assert_eq!(read_task(&f, task).await, original);
    assert_eq!(fires(&a, id).await, first);

    let (plugin, server) = echo(&f.host, f.instance).await;
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    let completed = read_task(&f, task).await;
    assert_eq!(completed["state"], "succeeded");
    assert_eq!(completed["output"], json!({"echo":{"message":"proxied"}}));
    server.abort();
}

#[tokio::test]
async fn postgres_task_schedule_queue_one_replaces_pending_and_drains_after_terminal() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    cancel_fixture_task(&f).await;
    let mut body = spec(&f);
    body["overlap"] = json!("queue_one");
    let schedule = create(&f, body, "schedule-queue-one").await;
    let id = contracts::id(&schedule, "id").unwrap();
    let first = next(&schedule);
    let cutoff = first - TimeDelta::minutes(1);
    let second = first + TimeDelta::minutes(1);
    let third = first + TimeDelta::minutes(2);
    for at in [first, second, third] {
        assert!(tick(&f, at, cutoff).await);
    }
    let c = f.host.app.db.connect().await.unwrap();
    let rows = fires(&c, id).await;
    assert_eq!(rows.len(), 3);
    let first_task = rows[0].2.unwrap();
    assert_eq!(rows[0], (first, "created".to_owned(), Some(first_task)));
    assert_eq!(rows[1], (second, "skipped".to_owned(), None));
    assert_eq!(rows[2], (third, "pending".to_owned(), None));
    assert_eq!(task_count(&c).await, 2);

    let (plugin, server) = echo(&f.host, f.instance).await;
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(read_task(&f, first_task).await["state"], "succeeded");
    let between = third + TimeDelta::seconds(10);
    assert!(tick(&f, between, cutoff).await);
    let drained = fires(&c, id).await;
    let second_task = drained[2].2.unwrap();
    assert_ne!(first_task, second_task);
    assert_eq!(drained[..2], rows[..2]);
    assert_eq!(drained[2], (third, "created".to_owned(), Some(second_task)));
    assert_eq!(task_count(&c).await, 3);
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(read_task(&f, second_task).await["state"], "succeeded");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    assert!(!tick(&f, between, cutoff).await);
    server.abort();
}

#[tokio::test]
async fn postgres_task_schedule_overlap_skip_does_not_replay_after_terminal() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    cancel_fixture_task(&f).await;
    let schedule = create(&f, spec(&f), "schedule-overlap-skip").await;
    let id = contracts::id(&schedule, "id").unwrap();
    let first = next(&schedule);
    let second = first + TimeDelta::minutes(1);
    let cutoff = first - TimeDelta::seconds(1);
    let c = f.host.app.db.connect().await.unwrap();
    assert!(tick(&f, first, cutoff).await);
    assert!(tick(&f, second, cutoff).await);
    let saved = fires(&c, id).await;
    let task = saved[0].2.unwrap();
    assert_eq!(
        saved,
        [
            (first, "created".to_owned(), Some(task)),
            (second, "skipped".to_owned(), None),
        ]
    );
    let (plugin, server) = echo(&f.host, f.instance).await;
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(read_task(&f, task).await["state"], "succeeded");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    assert!(!tick(&f, second, cutoff).await);
    assert_eq!(fires(&c, id).await, saved);
    assert_eq!(task_count(&c).await, 2);
    server.abort();
}

#[tokio::test]
async fn postgres_task_schedule_startup_replays_only_latest_or_skips() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let skip = create(&f, spec(&f), "schedule-startup-skip").await;
    let mut body = spec(&f);
    body["misfire"] = json!("run_once");
    let run_once = create(&f, body, "schedule-startup-run-once").await;
    let skip_id = contracts::id(&skip, "id").unwrap();
    let run_id = contracts::id(&run_once, "id").unwrap();
    let start = next(&skip);
    let latest = start + TimeDelta::minutes(8);
    let now = latest + TimeDelta::seconds(15);
    let mut c = super::startup::startup_connection(&f).await;
    c.execute("UPDATE schedules SET next_fire_at=$1", &[&start])
        .await
        .unwrap();
    super::startup::settle_startup(&mut c).await;
    assert!(tick(&f, now, now).await);
    assert!(tick(&f, now, now).await);
    assert!(!tick(&f, now, now).await);
    assert_eq!(
        fires(&c, skip_id).await,
        [(latest, "skipped".to_owned(), None)]
    );
    let saved = fires(&c, run_id).await;
    assert_eq!(saved.len(), 2);
    assert_eq!(
        saved[0],
        (latest - TimeDelta::minutes(1), "skipped".to_owned(), None)
    );
    let task = saved[1].2.unwrap();
    assert_eq!(saved[1], (latest, "created".to_owned(), Some(task)));
    assert_eq!(read_task(&f, task).await["state"], "queued");
    assert_eq!(task_count(&c).await, 2);
    for id in [skip_id, run_id] {
        assert_eq!(next(&get(&f, id).await), latest + TimeDelta::minutes(1));
    }
}

#[tokio::test]
async fn postgres_task_schedule_revoked_issuer_pauses_without_enqueuing() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let schedule = create(&f, spec(&f), "schedule-revoked-issuer").await;
    let id = contracts::id(&schedule, "id").unwrap();
    let at = next(&schedule);
    let cutoff = at - TimeDelta::minutes(1);
    let mut c = f.host.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    crate::db::auth_lock(&tx, true).await.unwrap();
    assert_eq!(
        tx.execute(
            "UPDATE credentials SET status='revoked',updated_at=clock_timestamp() WHERE id=$1",
            &[&f.issuer],
        )
        .await
        .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    assert!(tick(&f, at, cutoff).await);
    assert_eq!(fires(&c, id).await, [(at, "paused".to_owned(), None)]);
    let saved = c
        .query_one("SELECT next_fire_at FROM schedules WHERE id=$1", &[&id])
        .await
        .unwrap();
    assert_eq!(saved.get::<_, Option<DateTime<Utc>>>(0), None);
    assert_eq!(task_count(&c).await, 1);
    assert!(!tick(&f, at + TimeDelta::minutes(1), cutoff).await);
}
