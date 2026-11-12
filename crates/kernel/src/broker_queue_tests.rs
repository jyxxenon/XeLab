//! Real PostgreSQL admission and mTLS dispatch with a controllable provider.
use super::*;
use crate::{broker, broker_queue::Instance, error::Result};
use tokio::{
    sync::Semaphore,
    task::JoinHandle,
    time::{timeout, Instant},
};

struct Component {
    fixture: Fixture,
    provider: Instance,
    deployment: Uuid,
    source: Uuid,
    primary: Uuid,
    secondary: Uuid,
    gate: Arc<Semaphore>,
    plugin: Echo,
    server: JoinHandle<()>,
}

impl Drop for Component {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn object_concurrency() -> Value {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../docs/preset-plugins/object-storage/manifest.json"
    ))
    .unwrap();
    assert_eq!(
        manifest["concurrency"],
        json!({
            "max_active_requests":4,"max_queue_requests":32,"queue_timeout_ms":5000
        })
    );
    manifest["concurrency"].clone()
}

impl Component {
    async fn new(concurrency: Value) -> Option<Self> {
        let f = Fixture::new().await?;
        let mut c = f.app.db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        crate::admission::initialize(&tx, &f.app.config.value["resources"], 8000, 34359738368)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let (deployment, instance) = f.workload().await;
        let (primary, first) = skill(&f, deployment).await;
        let row = c.query_one(
            "SELECT n.id,n.manifest FROM installations n JOIN deployments d ON d.installation_id=n.id WHERE d.id=$1",
            &[&deployment],
        ).await.unwrap();
        let installation: Uuid = row.get(0);
        let mut manifest: Value = row.get(1);
        manifest["concurrency"] = concurrency;
        manifest["business_entry"] = json!("skill_required");
        let mut second = first.clone();
        second["name"] = json!("org.xelab.echo-python.queue-second");
        manifest["skills"] = json!([first, second]);
        crate::artifact::validate_profile(&manifest).unwrap();
        c.execute(
            "UPDATE installations SET manifest=$2 WHERE id=$1",
            &[&installation, &manifest],
        )
        .await
        .unwrap();
        c.execute(
            "UPDATE deployments SET spec=$2 WHERE id=$1",
            &[&deployment, &json!({"installation_id":installation,"display_name":"Queue fixture","enabled":true,
                "replicas":1,"limits":manifest["minimum_resources"],"config":{},"volume_ids":[]})],
        ).await.unwrap();
        let registered = f
            .call(
                "registerSkill",
                &[],
                json!({"installation_id":installation,"definition":second,"enabled":true}),
                None,
                "queue-second-skill",
                None,
            )
            .await;
        assert_eq!(registered.0, 201, "{}", registered.1);
        let source = f.source(b"queue input".to_vec()).await;
        let gate = Arc::new(Semaphore::new(0));
        let (plugin, server) = echo_with(
            &f,
            instance,
            Echo {
                unary_gate: Some(gate.clone()),
                ..Echo::default()
            },
        )
        .await;
        Some(Self {
            fixture: f,
            provider: Instance {
                id: instance,
                generation: 7,
            },
            deployment,
            source,
            primary,
            secondary: contracts::id(&registered.1, "id").unwrap(),
            gate,
            plugin,
            server,
        })
    }

    fn start(
        &self,
        token: &str,
        skill: Uuid,
        key: &str,
        timeout_ms: u64,
    ) -> JoinHandle<Result<Value>> {
        let app = self.fixture.app.clone();
        let token = token.to_owned();
        let key = key.to_owned();
        let request = json!({"input":{"source":self.source},"timeout_ms":timeout_ms});
        tokio::spawn(async move {
            broker::invoke_skill(
                &app,
                &token,
                "127.0.0.1".parse().unwrap(),
                Uuid::new_v4(),
                skill,
                &request,
                &key,
            )
            .await
        })
    }

    fn owner_call(&self, key: &str, timeout_ms: u64) -> JoinHandle<Result<Value>> {
        self.start(&self.fixture.token, self.primary, key, timeout_ms)
    }

    async fn pending(&self, count: usize) {
        self.until(&format!("{count} waiters"), || {
            self.fixture.app.runtime.business_queue.len(self.provider) == count
        })
        .await;
    }

    async fn entered(&self, count: usize) {
        self.until(&format!("{count} dispatches"), || {
            self.plugin.calls.load(Ordering::SeqCst) == count
        })
        .await;
    }

    async fn until(&self, expected: &str, ready: impl Fn() -> bool) {
        timeout(Duration::from_secs(3), async {
            while !ready() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Expected {expected}, observed {} waiters and {} dispatches",
                self.fixture.app.runtime.business_queue.len(self.provider),
                self.plugin.calls.load(Ordering::SeqCst)
            )
        });
    }

    async fn ledger(&self) -> (i64, i64, i64) {
        let c = self.fixture.app.db.connect().await.unwrap();
        let row = c.query_one(
            "SELECT
              (SELECT count(*) FROM calls WHERE provider_instance_id=$1),
              (SELECT count(*) FROM reservations r JOIN calls c ON c.id=r.id WHERE c.provider_instance_id=$1 AND r.status<>'released'),
              (SELECT sum(daily_calls_used)::bigint FROM quotas)",
            &[&self.provider.id],
        ).await.unwrap();
        (row.get(0), row.get(1), row.get(2))
    }

    async fn caller(&self) -> (Uuid, String) {
        let f = &self.fixture;
        let c = f.app.db.connect().await.unwrap();
        let subject = Uuid::new_v4();
        let password = "isolated broker queue test password";
        let hash = auth::password_hash(password).unwrap();
        // A second fixture root has only explicitly issued grants.
        c.execute(
            "INSERT INTO accounts(id,kind,status,display_name,password_hash,created_at,updated_at) VALUES($1,'user','active','Queue caller',$2,now(),now())",
            &[&subject,&hash],
        ).await.unwrap();
        c.execute("INSERT INTO account_closure VALUES($1,$1,0)", &[&subject])
            .await
            .unwrap();
        c.execute(
            "INSERT INTO quotas(account_id,spec,daily_bucket,created_at,updated_at) SELECT $1,q.spec,current_date,now(),now() FROM quotas q JOIN accounts a ON a.id=q.account_id WHERE a.independent_owner",
            &[&subject],
        ).await.unwrap();
        let capability = f.call(
            "createGrant", &[("account_id",subject)],
            json!({"source":"role","role_id":"Guest","scope":{"kind":"capability","match":"all"}}),
            None, "queue-caller-capability", None,
        ).await;
        assert_eq!(capability.0, 201, "{}", capability.1);
        self.grant_rule(
            subject,
            "queue-caller-blob",
            "blob.read",
            json!({"kind":"blob","match":"ids","ids":[self.source]}),
        )
        .await;
        let login = f
            .call(
                "login",
                &[],
                json!({"account_id":subject,"password":password}),
                None,
                "queue-caller-login",
                None,
            )
            .await;
        assert_eq!(login.0, 200);
        (
            subject,
            login.1["access_token"].as_str().unwrap().to_owned(),
        )
    }

    async fn grant(&self, caller: Uuid, name: &str) -> Uuid {
        self.grant_rule(
            caller,
            name,
            "skill.invoke",
            json!({"kind":"skill","match":"ids","ids":[self.secondary]}),
        )
        .await
    }

    async fn grant_rule(&self, caller: Uuid, name: &str, action: &str, resource: Value) -> Uuid {
        let f = &self.fixture;
        let group = f
            .call(
                "createGroup",
                &[],
                json!({"name":name,"rules":[{"action":action,"resource":resource}]}),
                None,
                name,
                None,
            )
            .await;
        assert_eq!(group.0, 201, "{}", group.1);
        let grant = f.call(
            "createGrant", &[("account_id",caller)],
            json!({"source":"group","group_version":{"group_id":group.1["id"],"version":1},"scope":resource}),
            None, name, None,
        ).await;
        assert_eq!(grant.0, 201, "{}", grant.1);
        contracts::id(&grant.1, "id").unwrap()
    }
}

#[tokio::test]
async fn object_limits_share_fifo_across_skills_and_subjects_without_queue_charges() {
    let Some(c) = Component::new(object_concurrency()).await else {
        return;
    };
    let (caller, token) = c.caller().await;
    c.grant(caller, "first-caller-skill").await;
    let active: Vec<_> = (0..4)
        .map(|n| c.owner_call(&format!("active-{n}"), 15000))
        .collect();
    c.entered(4).await;
    // Fill the pool in one burst. Sequential admission batches would spend
    // the first tickets' signed wait budget while later batches start.
    let mut waiting: Vec<_> = (0..32)
        .map(|n| c.owner_call(&format!("pending-{n}"), 15000))
        .collect();
    c.pending(32).await;
    let full = c
        .start(&token, c.secondary, "full-queue", 15000)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(full.code, "RESOURCE_EXHAUSTED");
    assert!(full.resource_id.is_none());
    assert_eq!(c.ledger().await, (4, 4, 4));
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 4);

    // A normal write can acquire the shared Broker lock while all waiters sleep.
    timeout(Duration::from_secs(1), async {
        let mut db = c.fixture.app.db.connect().await.unwrap();
        let tx = db.transaction().await.unwrap();
        crate::db::call_lock(&tx).await.unwrap();
        tx.rollback().await.unwrap();
    })
    .await
    .unwrap();

    let canceled = waiting.pop().unwrap();
    canceled.abort();
    assert!(canceled.await.unwrap_err().is_cancelled());
    for request in &waiting {
        request.abort();
    }
    for request in waiting {
        match request.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(result) => assert_eq!(result.unwrap_err().code, "DEADLINE_EXCEEDED"),
        }
    }
    c.pending(0).await;
    assert_eq!(c.ledger().await, (4, 4, 4));

    // The same saturated instance takes the oldest queued Skill from another
    // subject before a later request for its original Skill.
    let mut first = c.start(&token, c.secondary, "first-waiter", 15000);
    c.pending(1).await;
    let second = c.owner_call("second-waiter", 15000);
    c.pending(2).await;
    c.gate.add_permits(1);
    tokio::select! {
        _ = c.entered(5) => {},
        result = &mut first => panic!("FIFO head ended before dispatch: {result:?}"),
    }
    second.abort();
    assert!(second.await.unwrap_err().is_cancelled());
    c.pending(0).await;
    assert_eq!(c.ledger().await, (5, 4, 5));
    c.gate.add_permits(4);
    for request in active {
        request.await.unwrap().unwrap();
    }
    let first = first.await.unwrap().unwrap();
    assert_eq!(first["skill_id"], c.secondary.to_string());
    assert_eq!(c.ledger().await, (5, 0, 5));
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn concurrent_same_key_waiters_dispatch_once_and_replay_the_confirmed_result() {
    let mut concurrency = object_concurrency();
    concurrency["max_active_requests"] = json!(1);
    let Some(c) = Component::new(concurrency).await else {
        return;
    };
    let active = c.owner_call("held-for-replay", 15000);
    c.entered(1).await;
    let first = c.owner_call("same-key", 15000);
    c.pending(1).await;
    let duplicate = c.owner_call("same-key", 15000);
    c.pending(2).await;
    c.gate.add_permits(1);
    c.entered(2).await;
    let duplicate = duplicate.await.unwrap().unwrap_err();
    assert_eq!(duplicate.code, "OUTCOME_UNKNOWN");
    c.pending(0).await;
    c.gate.add_permits(1);
    active.await.unwrap().unwrap();
    let first = first.await.unwrap().unwrap();
    assert_eq!(
        duplicate.resource_id.as_deref(),
        first["call"]["call_id"].as_str()
    );
    assert_eq!(
        c.owner_call("same-key", 15000).await.unwrap().unwrap(),
        first
    );
    assert_eq!(c.ledger().await, (2, 0, 2));
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn concurrent_unary_completions_release_slots_during_a_burst() {
    let Some(c) = Component::new(object_concurrency()).await else {
        return;
    };
    c.gate.add_permits(12);
    let requests: Vec<_> = (0..12)
        .map(|n| c.owner_call(&format!("burst-{n}"), 15000))
        .collect();
    for request in requests {
        request.await.unwrap().unwrap();
    }
    assert_eq!(c.ledger().await, (12, 0, 12));
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 12);
}

#[tokio::test]
async fn terminal_rejection_is_durable_replayable_and_wakes_the_next_call() {
    let mut limits = object_concurrency();
    limits["max_active_requests"] = json!(1);
    let Some(c) = Component::new(limits).await else {
        return;
    };
    *c.plugin.terminal_failure.lock().unwrap() = Some("RESOURCE_EXHAUSTED".into());
    let first = c.owner_call("terminal-rejection", 15000);
    c.entered(1).await;
    let next = c.owner_call("next-after-terminal-rejection", 15000);
    c.pending(1).await;
    c.gate.add_permits(1);
    let error = first.await.unwrap().unwrap_err();
    assert_eq!(error.code, "RESOURCE_EXHAUSTED");
    let id: Uuid = error.resource_id.as_ref().unwrap().parse().unwrap();
    *c.plugin.terminal_failure.lock().unwrap() = None;
    c.entered(2).await;
    c.gate.add_permits(1);
    next.await.unwrap().unwrap();
    assert_eq!(c.ledger().await, (2, 0, 2));
    let db = c.fixture.app.db.connect().await.unwrap();
    let row = db.query_one(
        "SELECT c.state,c.completed_at,c.error,r.status,(SELECT sum(concurrent_calls_used)::bigint FROM quotas) AS active
           FROM calls c JOIN reservations r ON r.id=c.id WHERE c.id=$1",
        &[&id],
    ).await.unwrap();
    assert_eq!(row.get::<_, String>("state"), "failed");
    assert!(row
        .get::<_, Option<chrono::DateTime<chrono::Utc>>>("completed_at")
        .is_some());
    assert_eq!(row.get::<_, Value>("error"), error.detail());
    assert_eq!(row.get::<_, String>("status"), "released");
    assert_eq!(row.get::<_, i64>("active"), 0);
    let inspected = c
        .fixture
        .call(
            "getCall",
            &[("call_id", id)],
            Value::Null,
            None,
            "inspect-terminal-rejection",
            None,
        )
        .await;
    assert_eq!(inspected.0, 200, "{}", inspected.1);
    assert_eq!(inspected.1["state"], "failed");
    assert_eq!(inspected.1["error"], error.detail());
    let replay = c
        .owner_call("terminal-rejection", 15000)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(replay.detail(), error.detail());
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 2);
    assert_eq!(c.ledger().await, (2, 0, 2));
}

#[tokio::test]
async fn terminal_reply_does_not_clear_a_canceled_or_stale_call() {
    for change in ["cancel", "generation", "skill"] {
        let Some(c) = Component::new(object_concurrency()).await else {
            return;
        };
        let db = c.fixture.app.db.connect().await.unwrap();
        *c.plugin.terminal_failure.lock().unwrap() = Some("STATE_CONFLICT".into());
        let request = c.owner_call("terminal-fence", 15000);
        c.entered(1).await;
        let call: Uuid = db
            .query_one(
                "SELECT id FROM calls WHERE idempotency_key='terminal-fence'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        match change {
            "cancel" => {
                let canceled = c
                    .fixture
                    .call(
                        "cancelCall",
                        &[("call_id", call)],
                        Value::Null,
                        None,
                        "cancel-terminal",
                        None,
                    )
                    .await;
                assert_eq!(canceled.0, 204, "{}", canceled.1);
            }
            "generation" => {
                db.execute(
                    "UPDATE instances SET generation=generation+1 WHERE id=$1",
                    &[&c.provider.id],
                )
                .await
                .unwrap();
            }
            "skill" => {
                db.execute("UPDATE skills SET enabled=false WHERE id=$1", &[&c.primary])
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        c.gate.add_permits(1);
        let error = request.await.unwrap().unwrap_err();
        assert_eq!(
            error.code,
            if change == "cancel" {
                "CANCELED"
            } else {
                "NOT_READY"
            }
        );
        let state: String = db
            .query_one("SELECT state FROM calls WHERE id=$1", &[&call])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "unknown", "{change}");
        assert_eq!(c.ledger().await, (1, 1, 1), "{change}");
    }
}

#[tokio::test]
async fn terminal_reply_cannot_settle_after_the_original_deadline() {
    let Some(c) = Component::new(object_concurrency()).await else {
        return;
    };
    *c.plugin.terminal_failure.lock().unwrap() = Some("STATE_CONFLICT".into());
    let request = c.owner_call("terminal-deadline", 3000);
    c.entered(1).await;
    let mut db = c.fixture.app.db.connect().await.unwrap();
    let held = db.transaction().await.unwrap();
    crate::db::call_lock(&held).await.unwrap();
    c.gate.add_permits(1);
    let error = request.await.unwrap().unwrap_err();
    assert_eq!(error.code, "DEADLINE_EXCEEDED");
    held.rollback().await.unwrap();
    assert_eq!(c.ledger().await, (1, 1, 1));
    let state: String = db
        .query_one(
            "SELECT state FROM calls WHERE idempotency_key='terminal-deadline'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(matches!(state.as_str(), "running" | "unknown"));
}

#[tokio::test]
async fn zero_waiting_slots_reject_overload_without_a_queue() {
    let mut concurrency = object_concurrency();
    concurrency["max_active_requests"] = json!(1);
    concurrency["max_queue_requests"] = json!(0);
    let Some(c) = Component::new(concurrency).await else {
        return;
    };
    let active = c.owner_call("active-zero-queue", 15000);
    c.entered(1).await;
    let full = timeout(
        Duration::from_secs(1),
        c.owner_call("full-zero-queue", 15000),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap_err();
    assert_eq!(full.code, "RESOURCE_EXHAUSTED");
    assert!(full.resource_id.is_none());
    assert!(!c.fixture.app.runtime.business_queue.has_waiters(c.provider));
    assert_eq!(c.ledger().await, (1, 1, 1));
    c.gate.add_permits(1);
    active.await.unwrap().unwrap();
}

#[tokio::test]
async fn queued_calls_expire_at_the_smaller_absolute_deadline_without_dispatch() {
    let mut concurrency = object_concurrency();
    concurrency["max_active_requests"] = json!(1);
    let Some(c) = Component::new(concurrency).await else {
        return;
    };
    let active = c.owner_call("held-deadline", 15000);
    c.entered(1).await;
    let before = Instant::now();
    let short = c.owner_call("short-caller", 400);
    c.pending(1).await;
    let error = short.await.unwrap().unwrap_err();
    assert_eq!(error.code, "DEADLINE_EXCEEDED");
    assert!(error.resource_id.is_none());
    assert!(before.elapsed() < Duration::from_secs(3));
    c.pending(0).await;

    let before = Instant::now();
    let signed = c.owner_call("signed-timeout", 15000);
    c.pending(1).await;
    let mut db = c.fixture.app.db.connect().await.unwrap();
    let blocked = db.transaction().await.unwrap();
    crate::db::call_lock(&blocked).await.unwrap();
    let error = timeout(Duration::from_secs(7), signed)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, "DEADLINE_EXCEEDED");
    assert!(error.resource_id.is_none());
    assert!(before.elapsed() >= Duration::from_millis(4900));
    blocked.rollback().await.unwrap();
    c.pending(0).await;
    assert_eq!(c.ledger().await, (1, 1, 1));
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 1);
    c.gate.add_permits(1);
    active.await.unwrap().unwrap();
}

#[tokio::test]
async fn queued_original_grant_loss_and_deployment_disable_release_waiters() {
    let mut concurrency = object_concurrency();
    concurrency["max_active_requests"] = json!(1);
    let Some(c) = Component::new(concurrency).await else {
        return;
    };
    let (caller, token) = c.caller().await;
    let grant = c.grant(caller, "queue-original").await;
    let active = c.owner_call("held-authority", 15000);
    c.entered(1).await;
    let queued = c.start(&token, c.secondary, "original-source", 15000);
    c.pending(1).await;
    c.grant(caller, "queue-replacement").await;
    let f = &c.fixture;
    let revoked = f
        .call(
            "revokeGrant",
            &[("grant_id", grant)],
            Value::Null,
            Some(1),
            "queue-revoke",
            None,
        )
        .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let fresh = f.call(
        "checkAuthorization", &[], json!({"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[c.secondary]}}),
        None, "queue-fresh-authority", Some(&token),
    ).await;
    assert_eq!(fresh.0, 200, "{}", fresh.1);
    assert_eq!(fresh.1["allowed"], true);
    let denied = timeout(Duration::from_secs(3), queued)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "PERMISSION_DENIED");
    assert!(denied.resource_id.is_none());
    c.pending(0).await;

    let queued = c.owner_call("before-disable", 15000);
    c.pending(1).await;
    let current = f
        .call(
            "getDeployment",
            &[("deployment_id", c.deployment)],
            Value::Null,
            None,
            "queue-read",
            None,
        )
        .await;
    assert_eq!(current.0, 200, "{}", current.1);
    let disabled = f
        .call(
            "setDeploymentEnabled",
            &[("deployment_id", c.deployment)],
            json!({"enabled":false}),
            current.1["revision"].as_i64(),
            "queue-disable",
            None,
        )
        .await;
    assert_eq!(disabled.0, 202, "{}", disabled.1);
    let gone = timeout(Duration::from_secs(3), queued)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(gone.code, "NOT_READY");
    assert!(gone.resource_id.is_none());
    c.pending(0).await;
    assert_eq!(c.ledger().await.0, 1);
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 1);
    active.abort();
}

#[tokio::test]
async fn waiters_never_move_to_a_replacement_generation() {
    let mut concurrency = object_concurrency();
    concurrency["max_active_requests"] = json!(1);
    let Some(c) = Component::new(concurrency).await else {
        return;
    };
    let active = c.owner_call("held-generation", 15000);
    c.entered(1).await;
    let queued = c.owner_call("old-generation", 15000);
    c.pending(1).await;
    let mut db = c.fixture.app.db.connect().await.unwrap();
    let tx = db.transaction().await.unwrap();
    crate::db::call_lock(&tx).await.unwrap();
    let new = Uuid::new_v4();
    tx.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,runtime_id,created_at,updated_at) SELECT $2,deployment_id,generation+1,ordinal,'ready','alive',limits,$3,now(),now() FROM instances WHERE id=$1", &[&c.provider.id,&new,&new.to_string()]).await.unwrap();
    tx.execute("INSERT INTO provider_records(instance_id,name,version,availability,features,observed_generation,observed_at) SELECT $2,name,version,'ready',features,observed_generation+1,now() FROM provider_records WHERE instance_id=$1", &[&c.provider.id,&new]).await.unwrap();
    tx.execute(
        "UPDATE instances SET phase='stopped',runtime_id=NULL WHERE id=$1",
        &[&c.provider.id],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE provider_records SET availability='unavailable' WHERE instance_id=$1",
        &[&c.provider.id],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let gone = timeout(Duration::from_secs(3), queued)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(gone.code, "NOT_READY");
    assert!(gone.resource_id.is_none());
    c.pending(0).await;
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM calls WHERE idempotency_key='old-generation'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(c.plugin.calls.load(Ordering::SeqCst), 1);
    active.abort();
}
