//! PostgreSQL Task authority reconciliation independently of provider readiness.
use super::*;
use tokio_postgres::{Client, GenericClient};

async fn task_record(c: &impl GenericClient, id: Uuid) -> Value {
    c.query_one("SELECT to_jsonb(t) FROM tasks t WHERE id=$1", &[&id])
        .await
        .unwrap()
        .get(0)
}

async fn make_provider_unavailable(c: &Client, instance: Uuid) {
    assert_eq!(
        c.execute(
            "UPDATE provider_records SET availability='unavailable' WHERE instance_id=$1",
            &[&instance],
        )
        .await
        .unwrap(),
        1
    );
}

async fn revoke_issuer(c: &Client, issuer: Uuid) {
    assert_eq!(
        c.execute(
            "UPDATE credentials SET status='revoked',updated_at=clock_timestamp() WHERE id=$1",
            &[&issuer],
        )
        .await
        .unwrap(),
        1
    );
}

async fn assert_no_work(c: &Client) {
    let counts = c
        .query_one(
            "SELECT (SELECT count(*) FROM attempts),(SELECT count(*) FROM calls),
                (SELECT count(*) FROM call_credential_charges),
                (SELECT count(*) FROM reservations WHERE kind='call')",
            &[],
        )
        .await
        .unwrap();
    for column in 0..4 {
        assert_eq!(counts.get::<_, i64>(column), 0);
    }
}

async fn assert_paused(c: &Client, task: Uuid) -> Value {
    let record = task_record(c, task).await;
    assert_eq!(record["state"], "paused_authorization");
    assert!(
        matches!(
            record["error"]["code"].as_str(),
            Some("PERMISSION_DENIED" | "INVALID_CREDENTIAL")
        ),
        "{record}"
    );
    let step = c
        .query_one(
            "SELECT state,attempt_count FROM task_steps WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap();
    assert_eq!(step.get::<_, String>("state"), "ready");
    assert_eq!(step.get::<_, i32>("attempt_count"), 0);
    record
}

async fn submit(f: &TaskFixture, key: &str) -> Uuid {
    let (status, task) = f
        .host
        .call(
            "createTask",
            &[],
            json!({"workflow_id":f.workflow,"input":{"message":"task input"}}),
            None,
            key,
            None,
        )
        .await;
    assert_eq!(status, 201, "{task}");
    contracts::id(&task, "id").unwrap()
}

#[tokio::test]
async fn postgres_task_idle_authority_pauses_revoked_issuer_while_provider_is_unready() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let c = f.host.app.db.connect().await.unwrap();
    let before = task_record(&c, f.task).await;
    make_provider_unavailable(&c, f.instance).await;
    revoke_issuer(&c, f.issuer).await;
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let paused = assert_paused(&c, f.task).await;
    assert_eq!(paused["revision"], before["revision"].as_i64().unwrap() + 1);
    for field in ["admission", "deadline_at", "delegation_id", "input"] {
        assert_eq!(paused[field], before[field], "{field}");
    }
    assert!(c
        .query_one(
            "SELECT deadline_at>clock_timestamp() FROM tasks WHERE id=$1",
            &[&f.task],
        )
        .await
        .unwrap()
        .get::<_, bool>(0));
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(task_record(&c, f.task).await, paused);
    assert_no_work(&c).await;
}

#[tokio::test]
async fn postgres_task_idle_authority_rejects_replacement_grant_while_deployment_disabled() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let mut c = f.host.app.db.connect().await.unwrap();
    let before = task_record(&c, f.task).await;
    let owner = contracts::id(&before, "owner_id").unwrap();
    let original: Uuid = c
        .query_one(
            "SELECT id FROM grants WHERE subject_id=$1 AND scope->>'kind'='skill'
         AND role_id='Owner' AND status='active'",
            &[&owner],
        )
        .await
        .unwrap()
        .get(0);
    assert!(before["admission"]["steps"][0]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|target| {
            target["action"] == "skill.invoke"
                && target["paths"].as_array().unwrap().iter().any(|path| {
                    path["sources"]
                        .as_array()
                        .unwrap()
                        .contains(&json!(original))
                })
        }));
    let tx = c.transaction().await.unwrap();
    crate::db::auth_lock(&tx, true).await.unwrap();
    tx.execute(
        "INSERT INTO grants(id,subject_id,issuer_id,issuer_credential_id,role_id,scope,expires_at,status,created_at,updated_at)
         SELECT $2,subject_id,issuer_id,issuer_credential_id,role_id,scope,expires_at,'active',created_at,clock_timestamp()
         FROM grants WHERE id=$1",
        &[&original, &Uuid::new_v4()],
    ).await.unwrap();
    tx.execute(
        "UPDATE grants SET status='revoked',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        &[&original],
    ).await.unwrap();
    tx.execute(
        "UPDATE deployments SET spec=jsonb_set(spec,'{enabled}','false'),phase='disabled'
         WHERE id=(SELECT deployment_id FROM instances WHERE id=$1)",
        &[&f.instance],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let ctx = f
        .host
        .app
        .auth
        .authenticate(
            &c,
            &f.host.token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    crate::auth::authorize(
        &c,
        &ctx,
        "skill.invoke",
        &crate::auth::Resource::new("skill", f.skill, Some(owner)),
    )
    .await
    .unwrap();
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let paused = assert_paused(&c, f.task).await;
    assert_eq!(paused["error"]["code"], "PERMISSION_DENIED");
    assert_eq!(paused["admission"], before["admission"]);
    assert_no_work(&c).await;
}

#[tokio::test]
async fn postgres_task_idle_authority_leaves_live_authority_queued_and_deadline_takes_precedence() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let c = f.host.app.db.connect().await.unwrap();
    make_provider_unavailable(&c, f.instance).await;
    let before = task_record(&c, f.task).await;
    assert_eq!(before["state"], "queued");
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(task_record(&c, f.task).await, before);
    assert_no_work(&c).await;

    c.execute(
        "UPDATE tasks SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        &[&f.task],
    )
    .await
    .unwrap();
    revoke_issuer(&c, f.issuer).await;
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    let expired = task_record(&c, f.task).await;
    assert_eq!(expired["state"], "failed");
    assert_eq!(expired["error"]["code"], "DEADLINE_EXCEEDED");
    assert_no_work(&c).await;
}

#[tokio::test]
async fn postgres_task_idle_authority_preserves_active_leases_and_unknown_calls() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    let lease = f.claim().await;
    let second = submit(&f, "idle-authority-unknown-fixture").await;
    let (plugin, server) = echo(&f.host, f.instance).await;
    plugin.fail_after_dispatch.store(true, Ordering::SeqCst);
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());

    let c = f.host.app.db.connect().await.unwrap();
    let running = task_record(&c, f.task).await;
    let unknown = task_record(&c, second).await;
    assert_eq!(running["state"], "running");
    assert_eq!(unknown["state"], "unknown");
    let call: Uuid = unknown["error"]["resource_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let before: Value = c
        .query_one(
            "SELECT to_jsonb(a) FROM attempts a WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(before["state"], "leased");
    assert!(c
        .query_one(
            "SELECT lease_expires_at>clock_timestamp() FROM attempts WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap()
        .get::<_, bool>(0));

    make_provider_unavailable(&c, f.instance).await;
    revoke_issuer(&c, f.issuer).await;
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(task_record(&c, f.task).await, running);
    assert_eq!(task_record(&c, second).await, unknown);
    assert_eq!(
        c.query_one(
            "SELECT to_jsonb(a) FROM attempts a WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap()
        .get::<_, Value>(0),
        before
    );
    let ledger = c
        .query_one(
            "SELECT c.state,r.status FROM calls c JOIN reservations r ON r.id=c.id WHERE c.id=$1",
            &[&call],
        )
        .await
        .unwrap();
    assert_eq!(ledger.get::<_, String>("state"), "unknown");
    assert_eq!(ledger.get::<_, String>("status"), "active");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}

async fn sweep(c: &mut Client, auth: &crate::auth::Auth, cursor: &mut Option<Uuid>) -> u64 {
    let tx = c.transaction().await.unwrap();
    let count = tokio::time::timeout(
        Duration::from_secs(3),
        crate::task_engine::pause_idle_unauthorized(&tx, auth, cursor),
    )
    .await
    .expect("Idle authority sweep must skip a locked Task")
    .unwrap();
    tx.commit().await.unwrap();
    count
}

#[tokio::test]
async fn postgres_task_idle_authority_sweep_advances_cursor_and_revisits_locked_task() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let mut ids = vec![f.task];
    for index in 0..3 {
        ids.push(submit(&f, &format!("idle-authority-page-{index}")).await);
    }
    ids.sort_unstable();
    let mut c = f.host.app.db.connect().await.unwrap();
    make_provider_unavailable(&c, f.instance).await;
    revoke_issuer(&c, f.issuer).await;
    let mut locker = f.host.app.db.connect().await.unwrap();
    let lock = locker.transaction().await.unwrap();
    lock.query_one("SELECT id FROM tasks WHERE id=$1 FOR UPDATE", &[&ids[0]])
        .await
        .unwrap();

    let mut cursor = None;
    for (index, id) in ids.iter().enumerate().skip(1) {
        assert_eq!(sweep(&mut c, &f.host.app.auth, &mut cursor).await, 1);
        assert_eq!(cursor, Some(*id));
        assert_paused(&c, *id).await;
        assert_eq!(task_record(&c, ids[0]).await["state"], "queued");
        if let Some(next) = ids.get(index + 1) {
            assert_eq!(task_record(&c, *next).await["state"], "queued");
        }
    }
    assert_eq!(sweep(&mut c, &f.host.app.auth, &mut cursor).await, 0);
    assert_eq!(cursor, None);
    lock.rollback().await.unwrap();
    assert_eq!(sweep(&mut c, &f.host.app.auth, &mut cursor).await, 1);
    assert_paused(&c, ids[0]).await;
    assert_no_work(&c).await;
}
