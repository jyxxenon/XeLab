use super::{request, Fixture};
use axum::http::Method;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;
use xelab_kernel::{
    auth::{self, Auth, Resource},
    contracts,
    task_engine::{begin, claim, complete, expire, renew, Lease, Outcome},
};

struct EngineFixture {
    base: Fixture,
    auth: Auth,
    task: Uuid,
    skill: Uuid,
    deployment: Uuid,
    root: Uuid,
    follow_up: Uuid,
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
        let task = request(
            &base.router,
            Method::POST,
            "/api/platform/v1/tasks",
            Some(&base.token),
            Some(&json!({"workflow_id": workflow["id"], "input": {"text": "hello"}})),
            &[("idempotency-key", "engine-submit-task")],
        )
        .await
        .expect(201)
        .body;
        let task = contracts::id(&task, "id").unwrap();
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
