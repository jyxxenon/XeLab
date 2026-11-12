//! Actual PostgreSQL and loopback capability mTLS, using installed metadata fixtures.
use super::*;
use tokio_postgres::Row;

struct TaskFixture {
    host: Fixture,
    task: Uuid,
    skill: Uuid,
    instance: Uuid,
    issuer: Uuid,
}

impl TaskFixture {
    async fn new(side_effect: &str, use_blob: bool) -> Option<Self> {
        let host = Fixture::new().await?;
        let (deployment, instance) = host.workload().await;
        let c = host.app.db.connect().await.unwrap();
        let installation = c
            .query_one(
                "SELECT installation_id FROM deployments WHERE id=$1",
                &[&deployment],
            )
            .await
            .unwrap()
            .get::<_, Uuid>(0);
        let mut manifest: Value = c
            .query_one(
                "SELECT manifest FROM installations WHERE id=$1",
                &[&installation],
            )
            .await
            .unwrap()
            .get(0);
        if !use_blob {
            let baseline: Value =
                serde_json::from_str(include_str!("../tests/fixtures/secret-manifest.json"))
                    .unwrap();
            manifest["capabilities"][0]["input_schema"] =
                baseline["capabilities"][0]["input_schema"].clone();
        }
        manifest["capabilities"][0]["side_effect"] = json!(side_effect);
        crate::artifact::validate_profile(&manifest).unwrap();
        c.execute(
            "UPDATE installations SET manifest=$2 WHERE id=$1",
            &[&installation, &manifest],
        )
        .await
        .unwrap();
        let (skill, _) = skill(&host, deployment).await;

        let (field, input) = if use_blob {
            let source = host.source(b"task fixture Blob".to_vec()).await;
            ("source", json!({"source":source}))
        } else {
            ("message", json!({"message":"task input"}))
        };
        let (status, workflow) = host
            .call(
                "createWorkflow",
                &[],
                json!({
                    "name":"task-broker-fixture",
                    "input_schema":{"type":"object"},
                    "steps":[{
                        "id":"echo", "skill_id":skill, "depends_on":[],
                        "input_mapping":{(field):{"task_input":format!("/{field}")}},
                        "timeout_ms":20000,"maximum_attempts":2
                    }]
                }),
                None,
                "task-broker-workflow",
                None,
            )
            .await;
        assert_eq!(status, 201, "{workflow}");
        let (status, task) = host
            .call(
                "createTask",
                &[],
                json!({"workflow_id":workflow["id"], "input":input}),
                None,
                "task-broker-submit",
                None,
            )
            .await;
        assert_eq!(status, 201, "{task}");
        assert_eq!(task["state"], "queued");
        let issuer = host
            .app
            .auth
            .authenticate(
                &c,
                &host.token,
                "127.0.0.1".parse().unwrap(),
                Uuid::new_v4(),
            )
            .await
            .unwrap()
            .credential;
        Some(Self {
            host,
            task: contracts::id(&task, "id").unwrap(),
            skill,
            instance,
            issuer,
        })
    }

    async fn journal(&self) -> Row {
        let c = self.host.app.db.connect().await.unwrap();
        c.query_one(
            "SELECT t.state AS task_state,t.output AS task_output,t.delegation_id AS task_delegation,
                    s.state AS step_state,s.id AS step_id,a.state AS attempt_state,a.broker_call_id,
                    c.state AS call_state,c.result AS call_result,c.credential_id,c.skill_id,c.input_digest,
                    c.provider_instance_id,c.idempotency_key,c.delegation_id AS call_delegation,
                    q.daily_calls_used,q.concurrent_calls_used,r.status AS reservation_status,
                    x.read_blob_ids,x.proxy_source_paths,
                    (SELECT count(*) FROM call_credential_charges WHERE call_id=c.id AND credential_id=$2) AS issuer_charges
             FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN attempts a ON a.step_id=s.id
             JOIN calls c ON c.id=a.broker_call_id JOIN reservations r ON r.id=c.id AND r.kind='call'
             JOIN quotas q ON q.account_id=t.owner_id JOIN host_rpc_contexts x ON x.call_id=c.id
             WHERE t.id=$1",
            &[&self.task, &self.issuer],
        )
        .await
        .unwrap()
    }

    fn assert_admission(&self, row: &Row) {
        assert_eq!(row.get::<_, Uuid>("skill_id"), self.skill);
        assert_eq!(row.get::<_, Uuid>("provider_instance_id"), self.instance);
        assert_eq!(row.get::<_, Uuid>("credential_id"), self.issuer);
        assert_eq!(
            row.get::<_, String>("input_digest"),
            contracts::digest(&serde_json::to_vec(&json!({"message":"task input"})).unwrap())
        );
        assert_ne!(
            row.get::<_, Uuid>("task_delegation"),
            row.get::<_, Uuid>("call_delegation")
        );
        assert_eq!(
            row.get::<_, String>("idempotency_key"),
            format!("task-step:{}", row.get::<_, Uuid>("step_id"))
        );
        assert_eq!(row.get::<_, i64>("issuer_charges"), 1);
        assert_eq!(row.get::<_, i64>("daily_calls_used"), 1);
        assert_eq!(row.get::<_, Value>("read_blob_ids"), json!([]));
        assert_eq!(row.get::<_, Value>("proxy_source_paths"), json!([]));
    }

    async fn unadmitted(&self) -> Row {
        let c = self.host.app.db.connect().await.unwrap();
        let row = c
            .query_one(
                "SELECT t.state AS task_state,s.state AS step_state,a.state AS attempt_state,
                        a.broker_call_id,q.daily_calls_used,q.concurrent_calls_used,
                        (SELECT count(*) FROM calls) AS calls,
                        (SELECT count(*) FROM call_credential_charges) AS charges,
                        (SELECT count(*) FROM reservations WHERE kind='call') AS reservations
                 FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN attempts a ON a.step_id=s.id
                 JOIN quotas q ON q.account_id=t.owner_id WHERE t.id=$1",
                &[&self.task],
            )
            .await
            .unwrap();
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
        row
    }
}

#[tokio::test]
async fn postgres_task_broker_success_is_journaled_and_charged_once() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    let row = f.journal().await;
    f.assert_admission(&row);
    for column in ["task_state", "step_state", "attempt_state", "call_state"] {
        assert_eq!(row.get::<_, String>(column), "succeeded", "{column}");
    }
    assert_eq!(
        row.get::<_, Value>("task_output"),
        json!({"echo":{"message":"proxied"}})
    );
    let call = row.get::<_, Uuid>("broker_call_id");
    let result: Value = row.get("call_result");
    assert_eq!(result["call_id"], json!(call));
    assert_eq!(result["output"], json!({"message":"proxied"}));
    assert_eq!(row.get::<_, String>("reservation_status"), "released");
    assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 0);
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn postgres_task_broker_lost_reply_records_unknown_without_redispatch() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    plugin.fail_after_dispatch.store(true, Ordering::SeqCst);
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let row = f.journal().await;
    f.assert_admission(&row);
    for column in ["task_state", "step_state", "attempt_state", "call_state"] {
        assert_eq!(row.get::<_, String>(column), "unknown", "{column}");
    }
    assert!(row.get::<_, Option<Value>>("call_result").is_none());
    assert_eq!(row.get::<_, String>("reservation_status"), "active");
    assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 1);
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn postgres_task_broker_blob_input_requires_frozen_blob_authority() {
    let Some(f) = TaskFixture::new("none", true).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    assert!(crate::task_worker::run_once(&f.host.app).await.unwrap());
    let row = f.unadmitted().await;
    assert_eq!(row.get::<_, String>("task_state"), "paused_authorization");
    assert_eq!(row.get::<_, String>("step_state"), "ready");
    assert_eq!(row.get::<_, String>("attempt_state"), "expired");
    assert!(!crate::task_worker::run_once(&f.host.app).await.unwrap());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn postgres_task_broker_requires_current_provider_generation_at_admission() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    let mut c = f.host.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let lease = crate::task_engine::claim_broker(&tx, &f.host.app.auth)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        c.execute(
            "UPDATE provider_records SET observed_generation=observed_generation-1 WHERE instance_id=$1",
            &[&f.instance],
        )
        .await
        .unwrap(),
        1
    );
    let error = crate::broker::invoke_task(&f.host.app, &lease)
        .await
        .unwrap_err();
    assert_eq!(error.code, "NOT_READY");
    let row = f.unadmitted().await;
    assert_eq!(row.get::<_, String>("attempt_state"), "leased");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 0);
    server.abort();
}
