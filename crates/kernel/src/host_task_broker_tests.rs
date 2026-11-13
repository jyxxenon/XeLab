//! Actual PostgreSQL and loopback capability mTLS, using installed metadata fixtures.
use super::*;
use chrono::{DateTime, Utc};
use tokio_postgres::Row;

#[path = "host_task_startup_tests.rs"]
mod startup;

#[path = "host_task_cancel_tests.rs"]
mod cancellation;

#[path = "host_task_resolution_tests.rs"]
mod resolution;

#[path = "host_task_retry_tests.rs"]
mod retry;

const QUEUE_PROFILE: &str =
    r#"{"max_active_requests":1,"max_queue_requests":2,"queue_timeout_ms":5000}"#;

struct TaskFixture {
    host: Fixture,
    workflow: Uuid,
    task: Uuid,
    skill: Uuid,
    instance: Uuid,
    issuer: Uuid,
}

#[derive(PartialEq)]
enum CapabilityFixture {
    Unary,
    DualMode,
    FixedHealth,
    Queued,
}

impl TaskFixture {
    async fn new(side_effect: &str, use_blob: bool) -> Option<Self> {
        Self::with_capability(side_effect, use_blob, CapabilityFixture::Unary).await
    }

    async fn with_capability(
        side_effect: &str,
        use_blob: bool,
        capability: CapabilityFixture,
    ) -> Option<Self> {
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
        if capability == CapabilityFixture::DualMode {
            manifest["capabilities"][0]["stream_item_schema"] =
                manifest["capabilities"][0]["output_schema"].clone();
        }
        let queued = capability == CapabilityFixture::Queued;
        if queued {
            manifest["business_entry"] = json!("skill_required");
            manifest["concurrency"] = serde_json::from_str(QUEUE_PROFILE).unwrap();
        } else {
            crate::artifact::validate_profile(&manifest).unwrap();
        }
        c.execute(
            "UPDATE installations SET manifest=$2 WHERE id=$1",
            &[&installation, &manifest],
        )
        .await
        .unwrap();
        let (skill, _) = skill_with_health_updates(
            &host,
            deployment,
            capability != CapabilityFixture::FixedHealth,
        )
        .await;
        if queued {
            let manifest: Value = c
                .query_one(
                    "SELECT manifest FROM installations WHERE id=$1",
                    &[&installation],
                )
                .await
                .unwrap()
                .get(0);
            crate::artifact::validate_profile(&manifest).unwrap();
        }

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
            workflow: contracts::id(&workflow, "id").unwrap(),
            task: contracts::id(&task, "id").unwrap(),
            skill,
            instance,
            issuer,
        })
    }

    async fn claim(&self) -> crate::task_engine::Lease {
        let mut c = self.host.app.db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        let lease = crate::task_engine::claim_broker(&tx, &self.host.app.auth)
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        lease
    }

    async fn journal(&self) -> Row {
        let c = self.host.app.db.connect().await.unwrap();
        c.query_one(
            "SELECT t.state AS task_state,t.output AS task_output,t.error AS task_error,
                    t.delegation_id AS task_delegation,
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
async fn postgres_task_waits_for_the_shared_skill_slot_without_admitting_a_call() {
    let Some(f) = TaskFixture::with_capability("none", false, CapabilityFixture::Queued).await
    else {
        return;
    };
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (plugin, server) = echo_with(
        &f.host,
        f.instance,
        Echo {
            unary_gate: Some(gate.clone()),
            ..Echo::default()
        },
    )
    .await;
    let app = f.host.app.clone();
    let token = f.host.token.clone();
    let skill = f.skill;
    let direct = tokio::spawn(async move {
        crate::broker::invoke_skill(
            &app,
            &token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
            skill,
            &json!({"input":{"message":"occupy the slot"},"timeout_ms":15000}),
            "queue-occupied",
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while plugin.calls.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("direct Skill must occupy the provider slot");

    let app = f.host.app.clone();
    let worker = tokio::spawn(async move { crate::task_worker::run_once(&app).await });
    let provider = crate::broker_queue::Instance {
        id: f.instance,
        generation: 7,
    };
    let queue = &f.host.app.runtime.business_queue;
    tokio::time::timeout(Duration::from_secs(5), async {
        while queue.len(provider) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Task must wait behind the direct Skill");
    let c = f.host.app.db.connect().await.unwrap();
    let row = c
        .query_one(
            "SELECT a.state,a.broker_call_id,q.daily_calls_used,q.concurrent_calls_used,
                    (SELECT count(*) FROM calls) AS calls
             FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN attempts a ON a.step_id=s.id
             JOIN quotas q ON q.account_id=t.owner_id WHERE t.id=$1",
            &[&f.task],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("state"), "leased");
    assert!(row.get::<_, Option<Uuid>>("broker_call_id").is_none());
    assert_eq!(row.get::<_, i64>("calls"), 1);
    assert_eq!(row.get::<_, i64>("daily_calls_used"), 1);
    assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 1);
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);

    gate.add_permits(2);
    direct.await.unwrap().unwrap();
    assert!(worker.await.unwrap().unwrap());
    let row = f.journal().await;
    for column in ["task_state", "step_state", "attempt_state", "call_state"] {
        assert_eq!(row.get::<_, String>(column), "succeeded", "{column}");
    }
    assert_eq!(row.get::<_, i64>("daily_calls_used"), 2);
    assert_eq!(row.get::<_, i64>("concurrent_calls_used"), 0);
    assert_eq!(row.get::<_, i64>("issuer_charges"), 1);
    assert_eq!(row.get::<_, String>("reservation_status"), "released");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    assert_eq!(queue.len(provider), 0);
    server.abort();
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
async fn postgres_task_deadline_reconciles_while_another_call_is_held() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (plugin, server) = echo_with(
        &f.host,
        f.instance,
        Echo {
            unary_gate: Some(gate.clone()),
            ..Echo::default()
        },
    )
    .await;
    let scenario = async {
        while plugin.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (status, task) = f
            .host
            .call(
                "createTask",
                &[],
                json!({"workflow_id":f.workflow,"input":{"message":"due while another call is held"}}),
                None,
                "task-broker-submit-due",
                None,
            )
            .await;
        assert_eq!(status, 201, "{task}");
        let due = contracts::id(&task, "id").unwrap();
        let c = f.host.app.db.connect().await.unwrap();
        assert_eq!(
            c.execute(
                "UPDATE tasks SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1",
                &[&due],
            )
            .await
            .unwrap(),
            1
        );
        let expired = wait_for_task(&f.host, due, "failed").await;
        assert_eq!(expired["error"]["code"], "DEADLINE_EXCEEDED");
        assert_eq!(
            c.query_one(
                "SELECT count(*) FROM attempts a JOIN task_steps s ON s.id=a.step_id WHERE s.task_id=$1",
                &[&due],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0
        );

        let held = f.journal().await;
        assert_eq!(held.get::<_, String>("call_state"), "running");
        assert_eq!(held.get::<_, String>("attempt_state"), "running");
        assert_eq!(held.get::<_, String>("reservation_status"), "active");
        assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);

        gate.add_permits(1);
        let completed = wait_for_task(&f.host, f.task, "succeeded").await;
        assert_eq!(completed["output"], json!({"echo":{"message":"proxied"}}));
        let settled = f.journal().await;
        assert_eq!(settled.get::<_, String>("call_state"), "succeeded");
        assert_eq!(settled.get::<_, String>("reservation_status"), "released");
        assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    };
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::select! {
            () = crate::task_worker::run(f.host.app.clone()) => panic!("Task worker stopped early"),
            () = scenario => (),
        }
    })
    .await;
    server.abort();
    let _ = server.await;
    result.expect("A held capability Call must not block Task deadline reconciliation");
}

async fn wait_for_task(fixture: &Fixture, task: Uuid, expected: &str) -> Value {
    loop {
        let (status, value) = fixture
            .call(
                "getTask",
                &[("task_id", task)],
                Value::Null,
                None,
                "task-broker-poll",
                None,
            )
            .await;
        assert_eq!(status, 200, "{value}");
        match value["state"].as_str() {
            Some(state) if state == expected => return value,
            Some("queued" | "running") => (),
            _ => panic!("Unexpected Task state while waiting for {expected}: {value}"),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn postgres_task_broker_lost_reply_records_unknown_without_redispatch() {
    let Some(f) = TaskFixture::new("non_repeatable", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    *plugin.unary_failure.lock().unwrap() = Some(tonic::Status::unavailable(
        "Simulated transport failure after dispatch",
    ));
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
    let lease = f.claim().await;
    let c = f.host.app.db.connect().await.unwrap();
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

#[tokio::test]
async fn postgres_task_broker_provider_freshness_expires_during_admission_lock_wait() {
    // The fixture starts with a fresh observation, then this test owns its
    // clock. A concurrent heartbeat would legitimately make admission safe.
    let Some(f) = TaskFixture::with_capability("none", false, CapabilityFixture::FixedHealth).await
    else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    let lease = f.claim().await;
    let mut blocker = f.host.app.db.connect().await.unwrap();
    let lock = blocker.transaction().await.unwrap();
    crate::db::call_lock(&lock).await.unwrap();
    let blocker_pid: i32 = lock
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let app = f.host.app.clone();
    let pending = tokio::spawn(async move { crate::broker::invoke_task(&app, &lease).await });

    let observer = f.host.app.db.connect().await.unwrap();
    let started: DateTime<Utc> = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(row) = observer
                .query_opt(
                    "SELECT xact_start FROM pg_stat_activity WHERE datname=current_database()
                     AND wait_event_type='Lock' AND wait_event='advisory'
                     AND $1=ANY(pg_blocking_pids(pid))",
                    &[&blocker_pid],
                )
                .await
                .unwrap()
            {
                break row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Broker must wait on the call ledger lock");

    // Position the health expiry after the waiting transaction's fixed now().
    // Holding the lock through expiry tests wall-clock freshness at admission.
    let expires = started + chrono::Duration::milliseconds(100);
    let observed_at: DateTime<Utc> = lock
        .query_one(
            "UPDATE provider_records p SET observed_at=$2::timestamptz-interval '1 millisecond'*
                ((n.manifest->'health'->>'interval_ms')::bigint*
                 (n.manifest->'health'->>'failure_threshold')::bigint+
                 (n.manifest->'health'->>'timeout_ms')::bigint)
             FROM instances i JOIN deployments d ON d.id=i.deployment_id
             JOIN installations n ON n.id=d.installation_id
             WHERE p.instance_id=i.id AND i.id=$1 RETURNING p.observed_at",
            &[&f.instance, &expires],
        )
        .await
        .unwrap()
        .get(0);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !lock
            .query_one("SELECT clock_timestamp()>=$1", &[&expires])
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("provider observation must expire while the call ledger lock is held");
    lock.commit().await.unwrap();
    let stale: bool = observer
        .query_one(
            "SELECT observed_at=$2 AND clock_timestamp()>=$3
             FROM provider_records WHERE instance_id=$1",
            &[&f.instance, &observed_at, &expires],
        )
        .await
        .unwrap()
        .get(0);
    assert!(stale, "the expired observation must remain committed");

    let error = pending.await.unwrap().unwrap_err();
    assert_eq!(error.code, "NOT_READY");
    assert_eq!(
        f.unadmitted().await.get::<_, String>("attempt_state"),
        "leased"
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn postgres_task_broker_expired_attempt_exposes_settled_call_without_redispatch() {
    let Some(f) = TaskFixture::new("none", false).await else {
        return;
    };
    let (plugin, server) = echo(&f.host, f.instance).await;
    let lease = f.claim().await;
    let result = crate::broker::invoke_task(&f.host.app, &lease)
        .await
        .unwrap();
    let call = contracts::id(&result["call"], "call_id").unwrap();

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
    let row = f.journal().await;
    f.assert_admission(&row);
    for column in ["task_state", "step_state", "attempt_state"] {
        assert_eq!(row.get::<_, String>(column), "unknown", "{column}");
    }
    let error: Value = row.get("task_error");
    assert_eq!(error["code"], "OUTCOME_UNKNOWN");
    assert_eq!(error["resource_id"], json!(call));
    assert_eq!(row.get::<_, Uuid>("broker_call_id"), call);
    assert_eq!(row.get::<_, String>("call_state"), "succeeded");
    assert_eq!(row.get::<_, String>("reservation_status"), "released");
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}
