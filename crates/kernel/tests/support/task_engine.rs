use super::{request, Fixture, WORKFLOWS};
use axum::http::Method;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;
use xelab_kernel::{
    auth::{self, Auth, Resource},
    contracts,
    task_engine::{begin, claim, complete, expire, expire_idle, renew, Lease, Outcome},
};

struct EngineFixture {
    base: Fixture,
    auth: Auth,
    workflow: Uuid,
    task: Uuid,
    skill: Uuid,
    deployment: Uuid,
    root: Uuid,
    follow_up: Uuid,
}

async fn submit_task(base: &Fixture, workflow: Uuid, key: &str) -> Uuid {
    let task = request(
        &base.router,
        Method::POST,
        "/api/platform/v1/tasks",
        Some(&base.token),
        Some(&json!({"workflow_id":workflow,"input":{"text":"hello"}})),
        &[("idempotency-key", key)],
    )
    .await
    .expect(201)
    .body;
    contracts::id(&task, "id").unwrap()
}

impl EngineFixture {
    async fn new() -> Option<Self> {
        let base = Fixture::new().await?;
        let conn = base.db.connect().await.unwrap();
        let deployment = Uuid::new_v4();
        conn.execute(
            "INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at)
             SELECT $1,$2,id,jsonb_build_object('installation_id',id,'enabled',true,'limits',manifest->'minimum_resources'),'waiting_resources',now(),now()
             FROM installations WHERE id=$3",
            &[&deployment, &base.owner, &base.installation],
        )
        .await
        .unwrap();
        let skill = request(
            &base.router,
            Method::POST,
            "/api/platform/v1/skills",
            Some(&base.token),
            Some(&json!({
                "installation_id": base.installation,
                "definition": base.skill_definition,
                "enabled": true
            })),
            &[("idempotency-key", "engine-register-skill")],
        )
        .await
        .expect(201)
        .body;
        let spec = json!({
            "name": "engine-workflow",
            "input_schema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
                "additionalProperties": false
            },
            "steps": [
                {
                    "id": "echo",
                    "skill_id": skill["id"],
                    "depends_on": [],
                    "input_mapping": {"message": {"task_input": "/text"}},
                    "timeout_ms": 10000,
                    "maximum_attempts": 2
                },
                {
                    "id": "follow-up",
                    "skill_id": skill["id"],
                    "depends_on": ["echo"],
                    "input_mapping": {"message": {"step_output": {"step": "echo", "pointer": "/message"}}},
                    "timeout_ms": 10000,
                    "maximum_attempts": 2
                }
            ]
        });
        let workflow = base
            .publish(&base.token, &spec, "engine-publish-workflow")
            .await
            .expect(201)
            .body;
        let workflow = contracts::id(&workflow, "id").unwrap();
        let task = submit_task(&base, workflow, "engine-submit-task").await;
        let rows = conn
            .query(
                "SELECT step_key,id FROM task_steps WHERE task_id=$1 ORDER BY step_key",
                &[&task],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<_, String>("step_key"), "echo");
        assert_eq!(rows[1].get::<_, String>("step_key"), "follow-up");
        Some(Self {
            base,
            auth: Auth::new(vec![55; 32]).unwrap(),
            workflow,
            task,
            skill: contracts::id(&skill, "id").unwrap(),
            deployment,
            root: rows[0].get("id"),
            follow_up: rows[1].get("id"),
        })
    }

    async fn connect(&self) -> Client {
        self.base.db.connect().await.unwrap()
    }

    async fn claim_one(&self) -> Lease {
        let mut conn = self.connect().await;
        let tx = conn.transaction().await.unwrap();
        let lease = claim(&tx, &self.auth).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        lease
    }

    async fn assert_no_claim(&self) {
        let mut conn = self.connect().await;
        let tx = conn.transaction().await.unwrap();
        assert!(claim(&tx, &self.auth).await.unwrap().is_none());
        tx.commit().await.unwrap();
    }

    async fn move_past_expiry(&self, lease: &Lease) {
        assert_eq!(
            self.connect()
                .await
                .execute(
                    "UPDATE attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
                    &[&lease.attempt_id],
                )
                .await
                .unwrap(),
            1
        );
    }
}

async fn outbox_count(c: &impl GenericClient, step: Uuid) -> i64 {
    c.query_one(
        "SELECT count(*) FROM outbox WHERE topic='task.step.completed' AND aggregate_id=$1",
        &[&step],
    )
    .await
    .unwrap()
    .get(0)
}

async fn state(c: &impl GenericClient, fixture: &EngineFixture) -> (String, String, String) {
    let row = c
        .query_one(
            "SELECT t.state,a.state,b.state FROM tasks t
             JOIN task_steps a ON a.task_id=t.id AND a.id=$2
             JOIN task_steps b ON b.task_id=t.id AND b.id=$3 WHERE t.id=$1",
            &[&fixture.task, &fixture.root, &fixture.follow_up],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

async fn task_snapshots(c: &impl GenericClient) -> Vec<Value> {
    c.query("SELECT to_jsonb(t) FROM tasks t ORDER BY id", &[])
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn deadline_history(c: &impl GenericClient) -> Value {
    c.query_one(
        "SELECT jsonb_build_object(
            'steps',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM task_steps s),
            'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM attempts a),
            'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM outbox o),
            'calls',(SELECT count(*) FROM calls),
            'reservations',(SELECT count(*) FROM reservations WHERE kind='call'))",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

async fn reconcile_idle(c: &mut Client) -> u64 {
    let tx = c.transaction().await.unwrap();
    let updated = tokio::time::timeout(Duration::from_secs(3), expire_idle(&tx))
        .await
        .expect("Task deadline reconciliation must skip a locked candidate")
        .unwrap();
    tx.commit().await.unwrap();
    updated
}

#[tokio::test]
async fn postgres_task_deadline_fails_idle_parents_and_preserves_execution_history() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let lease = fixture.claim_one().await;
    let mut conn = fixture.connect().await;
    let tx = conn.transaction().await.unwrap();
    begin(&tx, &fixture.auth, &lease).await.unwrap();
    tx.commit().await.unwrap();
    let tx = conn.transaction().await.unwrap();
    complete(
        &tx,
        &fixture.auth,
        &lease,
        Outcome::Succeeded(json!({"message":"completed before overall deadline"})),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        state(&conn, &fixture).await,
        ("running".into(), "succeeded".into(), "ready".into())
    );
    assert_eq!(outbox_count(&conn, fixture.root).await, 1);

    let queued = submit_task(&fixture.base, fixture.workflow, "idle-queued").await;
    let waiting = submit_task(&fixture.base, fixture.workflow, "idle-waiting").await;
    conn.execute(
        "UPDATE tasks SET state='waiting_dependency' WHERE id=$1",
        &[&waiting],
    )
    .await
    .unwrap();
    let uri = format!("{WORKFLOWS}/{}", fixture.workflow);
    let workflow = fixture
        .base
        .read(&fixture.base.token, &uri)
        .await
        .expect(200);
    fixture
        .base
        .archive(&uri, "idle-archive-workflow", workflow.etag.as_deref())
        .await
        .expect(204);
    assert_eq!(
        conn.execute(
            "UPDATE tasks SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=ANY($1)",
            &[&[fixture.task, queued, waiting].as_slice()],
        )
        .await
        .unwrap(),
        3
    );
    let before = task_snapshots(&conn).await;
    let history = deadline_history(&conn).await;
    let tx = conn.transaction().await.unwrap();
    assert_eq!(expire_idle(&tx).await.unwrap(), 3);
    assert_eq!(
        state(&tx, &fixture).await,
        ("failed".into(), "succeeded".into(), "ready".into())
    );
    assert_eq!(deadline_history(&tx).await, history);
    tx.rollback().await.unwrap();
    assert_eq!(task_snapshots(&conn).await, before);
    assert_eq!(deadline_history(&conn).await, history);

    assert_eq!(reconcile_idle(&mut conn).await, 3);
    for old in &before {
        let uri = format!(
            "/api/platform/v1/tasks/{}",
            contracts::id(old, "id").unwrap()
        );
        let task = fixture
            .base
            .read(&fixture.base.token, &uri)
            .await
            .expect(200)
            .body;
        assert_eq!(task["state"], "failed");
        assert_eq!(task["error"]["code"], "DEADLINE_EXCEEDED");
        assert_eq!(task["revision"], old["revision"].as_i64().unwrap() + 1);
        for field in ["workflow_id", "delegation_id", "input", "output"] {
            assert_eq!(task[field], old[field], "{field}");
        }
    }
    assert_eq!(deadline_history(&conn).await, history);
    let settled = task_snapshots(&conn).await;
    assert_eq!(reconcile_idle(&mut conn).await, 0);
    assert_eq!(task_snapshots(&conn).await, settled);
    fixture.assert_no_claim().await;
}

#[tokio::test]
async fn postgres_task_deadline_leaves_live_and_noneligible_work_untouched() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let lease = fixture.claim_one().await;
    let mut conn = fixture.connect().await;
    for (key, state, step_state) in [
        ("future", "queued", None),
        ("legacy", "queued", None),
        ("paused", "paused_authorization", None),
        ("cancel-requested", "cancel_requested", None),
        ("unknown", "unknown", Some("unknown")),
        ("canceled", "canceled", Some("canceled")),
        ("running-step", "running", Some("running")),
        ("unknown-step", "running", Some("unknown")),
    ] {
        let task = submit_task(&fixture.base, fixture.workflow, key).await;
        conn.execute(
            "UPDATE tasks SET state=$2,admission=CASE WHEN $3 THEN NULL ELSE admission END,
                deadline_at=clock_timestamp()+CASE WHEN $4 THEN interval '1 hour' ELSE interval '-1 second' END
             WHERE id=$1",
            &[&task, &state, &(key == "legacy"), &(key == "future")],
        )
        .await
        .unwrap();
        if let Some(step_state) = step_state {
            conn.execute(
                "UPDATE task_steps SET state=$2 WHERE task_id=$1 AND step_key='echo'",
                &[&task, &step_state],
            )
            .await
            .unwrap();
        }
    }
    conn.execute(
        "UPDATE tasks SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        &[&lease.task_id],
    )
    .await
    .unwrap();
    conn.execute(
        "UPDATE attempts SET lease_expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
        &[&lease.attempt_id],
    )
    .await
    .unwrap();
    let before = task_snapshots(&conn).await;
    let history = deadline_history(&conn).await;
    assert_eq!(reconcile_idle(&mut conn).await, 0);
    assert_eq!(task_snapshots(&conn).await, before);
    assert_eq!(deadline_history(&conn).await, history);

    // Exercise the active-attempt guard independently of the running-step guard.
    conn.execute(
        "UPDATE task_steps SET state='ready' WHERE id=$1",
        &[&lease.step_id],
    )
    .await
    .unwrap();
    let history = deadline_history(&conn).await;
    assert_eq!(reconcile_idle(&mut conn).await, 0);
    assert_eq!(task_snapshots(&conn).await, before);
    assert_eq!(deadline_history(&conn).await, history);
}

#[tokio::test]
async fn postgres_task_deadline_reconciliation_bounds_batch_and_skips_locked_task() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    for index in 0..17 {
        submit_task(
            &fixture.base,
            fixture.workflow,
            &format!("idle-batch-{index}"),
        )
        .await;
    }
    let mut holder = fixture.connect().await;
    let mut conn = fixture.connect().await;
    assert_eq!(
        conn.execute(
            "UPDATE tasks SET deadline_at=clock_timestamp()-CASE
                WHEN id=$1 THEN interval '2 seconds' ELSE interval '1 second' END",
            &[&fixture.task],
        )
        .await
        .unwrap(),
        18
    );
    let lock = holder.transaction().await.unwrap();
    lock.query_one(
        "SELECT id FROM tasks WHERE id=$1 FOR UPDATE",
        &[&fixture.task],
    )
    .await
    .unwrap();
    let history = deadline_history(&conn).await;

    assert_eq!(reconcile_idle(&mut conn).await, 16);
    assert_eq!(reconcile_idle(&mut conn).await, 1);
    assert_eq!(reconcile_idle(&mut conn).await, 0);
    assert_eq!(state(&conn, &fixture).await.0, "queued");
    lock.rollback().await.unwrap();
    assert_eq!(reconcile_idle(&mut conn).await, 1);
    assert_eq!(reconcile_idle(&mut conn).await, 0);

    let tasks = task_snapshots(&conn).await;
    assert_eq!(tasks.len(), 18);
    assert!(tasks.iter().all(|task| task["state"] == "failed"
        && task["revision"] == 2
        && task["error"]["code"] == "DEADLINE_EXCEEDED"));
    assert_eq!(deadline_history(&conn).await, history);
}

#[tokio::test]
async fn postgres_workers_skip_a_locked_candidate_and_keep_only_one_active_attempt() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let mut first = fixture.connect().await;
    let mut second = fixture.connect().await;
    let tx = first.transaction().await.unwrap();
    let lease = claim(&tx, &fixture.auth).await.unwrap().unwrap();
    assert_eq!(lease.task_id, fixture.task);
    assert_eq!(lease.step_id, fixture.root);
    assert!(!lease.idempotency_key.is_empty());
    let racing_tx = second.transaction().await.unwrap();
    let racing_claim =
        tokio::time::timeout(Duration::from_secs(2), claim(&racing_tx, &fixture.auth))
            .await
            .expect("a competing worker must skip the candidate instead of waiting")
            .unwrap();
    assert!(racing_claim.is_none());
    racing_tx.commit().await.unwrap();
    tx.commit().await.unwrap();
    fixture.assert_no_claim().await;
    let row = first
        .query_one(
            "SELECT count(*),count(*) FILTER (WHERE state IN ('leased','running')) FROM attempts WHERE step_id=$1",
            &[&fixture.root],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
}

#[tokio::test]
async fn postgres_undispatched_expiry_can_be_reclaimed_with_a_new_fence_and_stable_key() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let old = fixture.claim_one().await;
    fixture.move_past_expiry(&old).await;
    let mut conn = fixture.connect().await;
    let tx = conn.transaction().await.unwrap();
    assert!(renew(&tx, &fixture.auth, &old).await.is_err());
    tx.rollback().await.unwrap();
    let tx = conn.transaction().await.unwrap();
    assert!(expire(&tx).await.unwrap());
    tx.commit().await.unwrap();

    let mut replacement = fixture.claim_one().await;
    assert_eq!(replacement.task_id, old.task_id);
    assert_eq!(replacement.step_id, old.step_id);
    assert_ne!(replacement.attempt_id, old.attempt_id);
    assert_ne!(replacement.execution_id, old.execution_id);
    assert!(replacement.fence > old.fence);
    assert_eq!(replacement.idempotency_key, old.idempotency_key);
    let tx = conn.transaction().await.unwrap();
    assert!(begin(&tx, &fixture.auth, &old).await.is_err());
    tx.rollback().await.unwrap();
    let tx = conn.transaction().await.unwrap();
    let fence = replacement.fence;
    replacement.fence = old.fence;
    assert!(renew(&tx, &fixture.auth, &replacement).await.is_err());
    tx.rollback().await.unwrap();
    replacement.fence = fence;
    let tx = conn.transaction().await.unwrap();
    let new_expiry = renew(&tx, &fixture.auth, &replacement).await.unwrap();
    let row = tx
        .query_one(
            "SELECT lease_expires_at,clock_timestamp() FROM attempts WHERE id=$1",
            &[&replacement.attempt_id],
        )
        .await
        .unwrap();
    assert_eq!(new_expiry, row.get::<_, DateTime<Utc>>(0));
    assert!(new_expiry > row.get::<_, DateTime<Utc>>(1));
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn postgres_dispatched_expiry_stops_the_task_in_unknown_without_reclaiming() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let lease = fixture.claim_one().await;
    let mut conn = fixture.connect().await;
    let tx = conn.transaction().await.unwrap();
    begin(&tx, &fixture.auth, &lease).await.unwrap();
    tx.commit().await.unwrap();
    fixture.move_past_expiry(&lease).await;
    let tx = conn.transaction().await.unwrap();
    assert!(expire(&tx).await.unwrap());
    tx.commit().await.unwrap();
    let (task, root, follow_up) = state(&conn, &fixture).await;
    assert_eq!(task, "unknown");
    assert_eq!(root, "unknown");
    assert_eq!(follow_up, "pending");
    let row = conn
        .query_one(
            "SELECT state FROM attempts WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "unknown");
    assert_eq!(outbox_count(&conn, fixture.root).await, 1);
    fixture.assert_no_claim().await;

    let tx = conn.transaction().await.unwrap();
    assert!(complete(
        &tx,
        &fixture.auth,
        &lease,
        Outcome::Succeeded(json!({"message":"late"}))
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn postgres_completion_updates_dependency_and_outbox_in_one_transaction() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let lease = fixture.claim_one().await;
    let mut conn = fixture.connect().await;
    let tx = conn.transaction().await.unwrap();
    let invocation = begin(&tx, &fixture.auth, &lease).await.unwrap();
    assert_eq!(invocation.input, json!({"message":"hello"}));
    assert_eq!(invocation.deployment_id, fixture.deployment);
    tx.commit().await.unwrap();
    let original = state(&conn, &fixture).await;
    assert_eq!(original.1, "running");
    assert_eq!(original.2, "pending");
    assert_eq!(outbox_count(&conn, fixture.root).await, 0);
    let output = json!({"message":"from root"});

    let tx = conn.transaction().await.unwrap();
    assert!(complete(
        &tx,
        &fixture.auth,
        &lease,
        Outcome::Succeeded(json!({"message":42}))
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert_eq!(state(&conn, &fixture).await, original);
    assert_eq!(outbox_count(&conn, fixture.root).await, 0);

    let tx = conn.transaction().await.unwrap();
    complete(
        &tx,
        &fixture.auth,
        &lease,
        Outcome::Succeeded(output.clone()),
    )
    .await
    .unwrap();
    assert_eq!(state(&tx, &fixture).await.1, "succeeded");
    assert_eq!(state(&tx, &fixture).await.2, "ready");
    assert_eq!(outbox_count(&tx, fixture.root).await, 1);
    tx.rollback().await.unwrap();
    assert_eq!(state(&conn, &fixture).await, original);
    assert_eq!(outbox_count(&conn, fixture.root).await, 0);

    let tx = conn.transaction().await.unwrap();
    let completed = complete(
        &tx,
        &fixture.auth,
        &lease,
        Outcome::Succeeded(output.clone()),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(outbox_count(&conn, fixture.root).await, 1);
    let row = conn
        .query_one(
            "SELECT payload FROM outbox WHERE topic='task.step.completed' AND aggregate_id=$1",
            &[&fixture.root],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, Value>(0),
        json!({"task_id":fixture.task,"step_id":fixture.root,"attempt_id":lease.attempt_id,"state":"succeeded"})
    );
    let tx = conn.transaction().await.unwrap();
    let replay = complete(
        &tx,
        &fixture.auth,
        &lease,
        Outcome::Succeeded(output.clone()),
    )
    .await
    .unwrap();
    assert_eq!(replay, completed);
    tx.commit().await.unwrap();
    assert_eq!(outbox_count(&conn, fixture.root).await, 1);
    let child = fixture.claim_one().await;
    assert_eq!(child.step_id, fixture.follow_up);
    let tx = conn.transaction().await.unwrap();
    let child_invocation = begin(&tx, &fixture.auth, &child).await.unwrap();
    assert_eq!(child_invocation.input, output);
    tx.commit().await.unwrap();
    let tx = conn.transaction().await.unwrap();
    complete(
        &tx,
        &fixture.auth,
        &child,
        Outcome::Succeeded(json!({"message":"from child"})),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (task, root, follow_up) = state(&conn, &fixture).await;
    assert_eq!(task, "succeeded");
    assert_eq!(root, "succeeded");
    assert_eq!(follow_up, "succeeded");
    assert_eq!(outbox_count(&conn, fixture.follow_up).await, 1);
    fixture.assert_no_claim().await;
}

#[tokio::test]
async fn postgres_a_replacement_grant_cannot_restore_a_lease_frozen_to_the_original_source() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let lease = fixture.claim_one().await;
    let mut conn = fixture.connect().await;
    let original: Uuid = conn
        .query_one(
            "SELECT id FROM grants WHERE subject_id=$1 AND scope->>'kind'='skill' AND status='active'",
            &[&fixture.base.owner],
        )
        .await
        .unwrap()
        .get(0);
    let tx = conn.transaction().await.unwrap();
    tx.execute(
        "INSERT INTO grants(id,subject_id,issuer_id,issuer_credential_id,role_id,scope,expires_at,status,created_at,updated_at)
         SELECT $2,subject_id,issuer_id,issuer_credential_id,role_id,scope,expires_at,'active',created_at,clock_timestamp()
         FROM grants WHERE id=$1",
        &[&original, &Uuid::new_v4()],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE grants SET status='revoked',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        &[&original],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let ctx = fixture
        .auth
        .authenticate(
            &conn,
            &fixture.base.token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    auth::authorize(
        &conn,
        &ctx,
        "skill.invoke",
        &Resource::new("skill", fixture.skill, Some(fixture.base.owner)),
    )
    .await
    .unwrap();

    let tx = conn.transaction().await.unwrap();
    let error = begin(&tx, &fixture.auth, &lease).await.err().unwrap();
    assert_eq!(error.code, "PERMISSION_DENIED");
    tx.rollback().await.unwrap();
    let row = conn
        .query_one(
            "SELECT state FROM attempts WHERE id=$1",
            &[&lease.attempt_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "leased");
}

#[tokio::test]
async fn postgres_a_revoked_task_issuer_pauses_the_task_without_creating_an_attempt() {
    let Some(fixture) = EngineFixture::new().await else {
        return;
    };
    let conn = fixture.connect().await;
    let updated = conn
        .execute(
            "UPDATE credentials SET status='revoked',updated_at=clock_timestamp()
             WHERE id=(SELECT e.issuer_credential_id FROM tasks t
                       JOIN execution_delegations e ON e.id=t.delegation_id WHERE t.id=$1)",
            &[&fixture.task],
        )
        .await
        .unwrap();
    assert_eq!(updated, 1);

    fixture.assert_no_claim().await;
    let (task, root, follow_up) = state(&conn, &fixture).await;
    assert_eq!(task, "paused_authorization");
    assert_eq!(root, "ready");
    assert_eq!(follow_up, "pending");
    let row = conn
        .query_one(
            "SELECT count(*) FROM attempts a JOIN task_steps s ON s.id=a.step_id WHERE s.task_id=$1",
            &[&fixture.task],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
}
