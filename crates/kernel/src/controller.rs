use crate::{
    admission,
    api::App,
    artifact::Artifact,
    auth::{authorize, Resource},
    contracts::{digest, strict_json},
    db,
    error::{Error, Result},
    rpc::{self, plugin_lifecycle_client::PluginLifecycleClient},
    tls,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ops::Bound::{Excluded, Unbounded},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use uuid::Uuid;

pub fn context(subject: Option<Uuid>) -> rpc::RpcContext {
    rpc::RpcContext {
        request_id: Uuid::new_v4().to_string(),
        delegation_token: String::new(),
        deadline_unix_ms: (chrono::Utc::now() + chrono::Duration::seconds(30)).timestamp_millis(),
        idempotency_key: String::new(),
        subject_id: subject.map(|s| s.to_string()).unwrap_or_default(),
        actor_instance_id: String::new(),
    }
}

pub async fn run(app: Arc<App>) {
    let mut state = ControllerState::default();
    let mut rotate = tokio::time::Instant::now();
    loop {
        if app.shutdown.load(Ordering::SeqCst) {
            break;
        }
        if app.leader.is_closed() {
            app.ready.store(false, Ordering::SeqCst);
            tracing::error!(reason_code = "LEADER_CONNECTION_LOST");
            break;
        }
        if rotate.elapsed() > Duration::from_secs(1800)
            && tls::issue(
                &app.config,
                None,
                &app.config.root().join("kernel-identity"),
            )
            .is_ok()
        {
            rotate = tokio::time::Instant::now();
        }
        match reconcile_tick(&app, &mut state).await {
            Ok(()) => {}
            Err(e) => {
                app.ready.store(false, Ordering::SeqCst);
                tracing::error!(
                    reason_code = e.code,
                    message = e.message,
                    "Controller reconciliation failed"
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    app.ready.store(false, Ordering::SeqCst);
}

#[derive(Default)]
struct Probe {
    instance: Option<(Uuid, i64)>,
    next: Option<tokio::time::Instant>,
    started: Option<tokio::time::Instant>,
    failures: u64,
}
impl Probe {
    fn bind(&mut self, id: Uuid, generation: i64) {
        if self.instance != Some((id, generation)) {
            *self = Self {
                instance: Some((id, generation)),
                ..Self::default()
            };
        }
    }
}

// Separate lanes prevent an arbitrarily large disabled prefix from delaying
// healthy providers. Budgets are checked BETWEEN reconciliations: cancelling a
// runtime mutation at a wall-clock deadline would leave ambiguous side effects.
const DEPLOYMENTS_PER_LANE: usize = 16;
const LANE_TIME_SLICE: Duration = Duration::from_millis(250);
const PROBES_PER_TICK: usize = 64;

type DeploymentPosition = (chrono::DateTime<chrono::Utc>, Uuid);

#[derive(Default)]
struct Sweep {
    after: Option<DeploymentPosition>,
    through: Option<DeploymentPosition>,
    initial_complete: bool,
}
impl Sweep {
    fn finish(&mut self) {
        self.after = None;
        self.through = None;
        self.initial_complete = true;
    }
}

#[derive(Default)]
struct ControllerState {
    startup_fenced: bool,
    active: Sweep,
    inactive: Sweep,
    probes: BTreeMap<Uuid, Probe>,
    probe_after: Option<Uuid>,
}

// The cursor contains values, not a reference to a row that may be deleted.
// A fixed upper watermark gives every sweep an end despite concurrent inserts.
async fn deployment_page(
    c: &impl tokio_postgres::GenericClient,
    sweep: &mut Sweep,
    active: bool,
) -> Result<Vec<tokio_postgres::Row>> {
    // Settled disabled/archived records need no recurring runtime work. Pending
    // operations and live instances still force cleanup, including after archive.
    let predicate = if active {
        "d.archived_at IS NULL AND d.spec->'enabled'='true'::jsonb"
    } else {
        "(d.archived_at IS NOT NULL OR d.spec->'enabled' IS DISTINCT FROM 'true'::jsonb) AND (d.phase<>'disabled' OR EXISTS(SELECT 1 FROM instances i WHERE i.deployment_id=d.id AND i.phase<>'stopped') OR EXISTS(SELECT 1 FROM operations o WHERE o.resource_id=d.id::text AND o.kind IN ('createDeployment','setDeploymentEnabled') AND o.state IN ('pending','running')))"
    };
    if sweep.through.is_none() {
        let end = c.query_opt(&format!("SELECT d.created_at,d.id FROM deployments d WHERE {predicate} ORDER BY d.created_at DESC,d.id DESC LIMIT 1"), &[]).await?;
        sweep.through = end.map(|r| (r.get(0), r.get(1)));
    }
    let Some(through) = sweep.through else {
        sweep.finish();
        return Ok(Vec::new());
    };
    let (created, id) = sweep
        .after
        .map(|(created, id)| (Some(created), Some(id)))
        .unwrap_or((None, None));
    let rows = c.query(&format!("SELECT d.created_at,d.id FROM deployments d WHERE {predicate} AND ($1::timestamptz IS NULL OR (d.created_at,d.id)>($1,$2)) AND (d.created_at,d.id)<=($3,$4) ORDER BY d.created_at,d.id LIMIT $5"), &[&created, &id, &through.0, &through.1, &(DEPLOYMENTS_PER_LANE as i64)]).await?;
    if rows.is_empty() {
        sweep.finish();
    }
    Ok(rows)
}

async fn prune_probes(
    c: &impl tokio_postgres::GenericClient,
    state: &mut ControllerState,
) -> Result<()> {
    let start = state.probe_after.map(Excluded).unwrap_or(Unbounded);
    let ids: Vec<Uuid> = state
        .probes
        .range((start, Unbounded))
        .take(PROBES_PER_TICK)
        .map(|(id, _)| *id)
        .collect();
    if ids.is_empty() {
        state.probe_after = None;
        return Ok(());
    }
    let rows = c.query("SELECT id FROM deployments WHERE id=ANY($1) AND archived_at IS NULL AND spec->'enabled'='true'::jsonb", &[&ids]).await?;
    let keep: std::collections::HashSet<Uuid> = rows.iter().map(|r| r.get(0)).collect();
    for id in &ids {
        if !keep.contains(id) {
            state.probes.remove(id);
        }
    }
    state.probe_after = ids.last().copied();
    Ok(())
}

// A successful bounded batch does not mean startup recovery has caught up.
// Keep this transition shared by the daemon and the HTTP readiness regression.
async fn reconcile_tick(app: &App, state: &mut ControllerState) -> Result<()> {
    let result = tick(app, !state.startup_fenced, state).await;
    app.ready.store(
        result.is_ok()
            && state.startup_fenced
            && state.active.initial_complete
            && state.inactive.initial_complete,
        Ordering::SeqCst,
    );
    result
}

async fn tick(app: &App, first: bool, state: &mut ControllerState) -> Result<()> {
    let mut c = app.db.connect().await?;
    if first {
        c.execute("UPDATE node_budget SET admission_enabled=false", &[])
            .await?;
        c.execute(
            "UPDATE provider_records SET availability='unavailable'",
            &[],
        )
        .await?;
        // A new controller must fence every old process before returning call slots.
        // Stable instance IDs and their resource reservations survive this restart.
        let mut old: std::collections::BTreeSet<Uuid> =
            app.runtime.inventory().await?.into_iter().collect();
        // A lost container record does not prove that its old cgroup is empty.
        // Every durable attachment also needs an explicit stop proof.
        old.extend(
            c.query("SELECT DISTINCT instance_id FROM volume_attachments", &[])
                .await?
                .into_iter()
                .map(|r| r.get::<_, Uuid>(0)),
        );
        old.extend(
            c.query("SELECT DISTINCT instance_id FROM plugin_http_requests", &[])
                .await?
                .into_iter()
                .map(|row| row.get::<_, Uuid>(0)),
        );
        for id in old {
            app.runtime.stop(id).await?;
        }
        let tx = c.transaction().await?;
        db::call_lock(&tx).await?;
        crate::volumes::release_stopped(&tx, None).await?;
        tx.execute("DELETE FROM plugin_http_requests", &[]).await?;
        tx.execute(
            "UPDATE calls SET state='unknown',error=$1 WHERE state IN ('accepted','running')",
            &[&Error::new(
                "OUTCOME_UNKNOWN",
                "Kernel restarted before the result was committed",
                axum::http::StatusCode::CONFLICT,
            )
            .detail()],
        )
        .await?;
        tx.execute(
            "UPDATE rpc_delegations SET status='revoked' WHERE status='active'",
            &[],
        )
        .await?;
        crate::tasks::revoke_transient_delegations(&tx).await?;
        tx.execute(
            "UPDATE reservations SET status='released' WHERE kind='call' AND status<>'released'",
            &[],
        )
        .await?;
        tx.execute("UPDATE quotas SET concurrent_calls_used=0", &[])
            .await?;
        tx.execute("UPDATE instances SET phase='pending',health='unknown',restart_count=0,revision=revision+1,updated_at=now() WHERE phase<>'stopped'", &[]).await?;
        tx.commit().await?;
        c.execute(
            "UPDATE node_budget SET admission_enabled=true,revision=revision+1,updated_at=now()",
            &[],
        )
        .await?;
    }
    // Do not repeat global fencing after a later maintenance/page failure: it
    // would invalidate work already covered by the initial sweep markers.
    state.startup_fenced = true;
    // Maintenance is revisited every bounded batch, rather than once per full
    // deployment sweep. Recovery precedes potentially slow image installation.
    recover_expired_calls(app).await?;
    process_installations(app).await?;
    {
        let mut events_connection = app.db.connect().await?;
        let tx = events_connection.transaction().await?;
        crate::events::maintenance(&tx).await?;
        tx.commit().await?;
    }
    prune_probes(&c, state).await?;
    for active in [true, false] {
        let sweep = if active {
            &mut state.active
        } else {
            &mut state.inactive
        };
        let rows = deployment_page(&c, sweep, active).await?;
        let started = tokio::time::Instant::now();
        for r in rows {
            if app.shutdown.load(Ordering::SeqCst) || app.leader.is_closed() {
                return Err(Error::unavailable("Controller is stopping"));
            }
            let id: Uuid = r.get("id");
            // Advance even after an individual failure, so one unhealthy row
            // cannot starve its successors. Re-read current state in reconcile.
            sweep.after = Some((r.get("created_at"), id));
            if let Err(e) = reconcile(app, id, &mut state.probes).await {
                tracing::warn!(deployment_id=%id,reason_code=e.code,message=e.message,"Deployment is not ready");
                c.execute("UPDATE provider_records SET availability='unavailable' WHERE instance_id IN(SELECT id FROM instances WHERE deployment_id=$1)", &[&id]).await?;
                let failed:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM instances WHERE deployment_id=$1 AND phase='failed')", &[&id]).await?.get(0);
                let phase = if failed {
                    "failed"
                } else if e.code == "RESOURCE_EXHAUSTED" {
                    "waiting_resources"
                } else {
                    "degraded"
                };
                if failed {
                    c.execute("UPDATE operations SET state='failed',error=$2,revision=revision+1,updated_at=now() WHERE resource_id=$1 AND state IN ('pending','running')", &[&id.to_string(),&e.detail()]).await?;
                }
                c.execute(
                    "UPDATE deployments SET revision=revision+CASE WHEN phase<>$2 OR conditions<>$3 THEN 1 ELSE 0 END,phase=$2,conditions=$3,updated_at=now() WHERE id=$1",
                    &[&id, &phase, &json!([e.code])],
                ).await?;
            }
            if started.elapsed() >= LANE_TIME_SLICE {
                break;
            }
        }
        if sweep.after.is_some() && sweep.after == sweep.through {
            sweep.finish();
        }
    }
    Ok(())
}

// Cancellation is an intent whose physical outcome is still unknown. Keep it
// stable across process fencing so the Broker can emit canceled(requested).
const FENCE_EXPIRED_CALLS: &str = "UPDATE calls SET state='unknown',error=CASE WHEN error->>'code'='CANCELED' THEN error ELSE $2 END WHERE provider_instance_id=$1 AND (state IN ('accepted','running') OR (state='unknown' AND EXISTS(SELECT 1 FROM reservations WHERE id=calls.id AND kind='call' AND status<>'released'))) RETURNING id,owner_id";

async fn recover_expired_calls(app: &App) -> Result<()> {
    let mut c = app.db.connect().await?;
    let rows=c.query("SELECT DISTINCT provider_instance_id FROM calls c JOIN reservations r ON r.id=c.id AND r.kind='call' AND r.status<>'released' WHERE (c.state='unknown' OR (c.state IN ('accepted','running') AND deadline_at<now()-interval '1 second')) AND provider_instance_id IS NOT NULL UNION SELECT instance_id FROM plugin_http_requests WHERE state='unknown' OR expires_at<now()-interval '1 second'", &[]).await?;
    for row in rows {
        let instance: Uuid = row.get(0);
        let tx = c.transaction().await?;
        db::call_lock(&tx).await?;
        // A running provider cannot receive another call after this fence commits.
        let deployment: Uuid = tx
            .query_one(
                "SELECT deployment_id FROM instances WHERE id=$1 FOR UPDATE",
                &[&instance],
            )
            .await?
            .get(0);
        // Preserve the exact recovery predicates and capture their fixed counts
        // before a successful physical fence deletes the durable evidence.
        let reasons = tx.query_one("SELECT EXISTS(SELECT 1 FROM calls c JOIN reservations r ON r.id=c.id AND r.kind='call' AND r.status<>'released' WHERE c.provider_instance_id=$1 AND (c.state='unknown' OR (c.state IN ('accepted','running') AND c.deadline_at<now()-interval '1 second'))) OR EXISTS(SELECT 1 FROM plugin_http_requests WHERE instance_id=$1 AND (state='unknown' OR expires_at<now()-interval '1 second')),(SELECT count(*) FROM calls c JOIN reservations r ON r.id=c.id AND r.kind='call' AND r.status<>'released' WHERE c.provider_instance_id=$1 AND c.state='unknown'),(SELECT count(*) FROM calls c JOIN reservations r ON r.id=c.id AND r.kind='call' AND r.status<>'released' WHERE c.provider_instance_id=$1 AND c.state IN ('accepted','running') AND c.deadline_at<now()-interval '1 second'),(SELECT count(*) FROM plugin_http_requests WHERE instance_id=$1 AND state='unknown'),(SELECT count(*) FROM plugin_http_requests WHERE instance_id=$1 AND expires_at<now()-interval '1 second')",&[&instance]).await?;
        let needed: bool = reasons.get(0);
        let counts: [i64; 4] = std::array::from_fn(|index| reasons.get(index + 1));
        if !needed {
            tx.rollback().await?;
            continue;
        }
        tx.execute(
            "UPDATE provider_records SET availability='unavailable' WHERE instance_id=$1",
            &[&instance],
        )
        .await?;
        // HTTP and static admission uses the instance observation directly;
        // revoke it before the process fence, alongside capability providers.
        tx.execute("UPDATE instances SET phase='draining',health='unhealthy',revision=revision+1,updated_at=now() WHERE id=$1 AND phase<>'stopped'",&[&instance]).await?;
        tx.commit().await?;
        tracing::info!(target: "xelab.controller_transition", code = "UNCERTAIN_WORK_FENCE", stage = "recovery", instance_id = %instance, deployment_id = %deployment, call_unknown = counts[0], call_expired = counts[1], static_unknown = counts[2], static_expired = counts[3]);
        app.runtime.stop(instance).await?;
        // Only confirmed process termination permits slot reuse. Concurrent late
        // responses are fenced by the same call-state conditional update.
        let tx = c.transaction().await?;
        db::call_lock(&tx).await?;
        let error = Error::new(
            "OUTCOME_UNKNOWN",
            "Call lease expired before its result was committed",
            axum::http::StatusCode::CONFLICT,
        )
        .detail();
        let calls = tx.query(FENCE_EXPIRED_CALLS, &[&instance, &error]).await?;
        for call in calls {
            let id: Uuid = call.get(0);
            let owner: Uuid = call.get(1);
            let released=tx.execute("UPDATE reservations SET status='released' WHERE id=$1 AND kind='call' AND status<>'released'", &[&id]).await?;
            if released == 1 {
                for ancestor in tx.query("SELECT ancestor_id FROM account_closure WHERE descendant_id=$1 ORDER BY depth DESC", &[&owner]).await? {
                    tx.execute("UPDATE quotas SET concurrent_calls_used=greatest(0,concurrent_calls_used-1) WHERE account_id=$1", &[&ancestor.get::<_,Uuid>(0)]).await?;
                }
            }
            tx.execute(
                "UPDATE rpc_delegations SET status='revoked' WHERE call_id=$1",
                &[&id],
            )
            .await?;
            tx.execute("UPDATE execution_delegations SET status='revoked' WHERE id IN(SELECT delegation_id FROM calls WHERE id=$1)", &[&id]).await?;
            db::audit(
                &tx,
                owner,
                None,
                Uuid::new_v4(),
                "capability.invoke",
                &Resource::new("call", id, Some(owner)).json(),
                "failed",
                "CALL_LEASE_EXPIRED",
            )
            .await?;
        }
        tx.execute(
            "DELETE FROM plugin_http_requests WHERE instance_id=$1",
            &[&instance],
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn mark_stopping(app: &App, instance: Uuid) -> Result<()> {
    let mut connection = app.db.connect().await?;
    let transaction = connection.transaction().await?;
    db::call_lock(&transaction).await?;
    transaction
        .query_one(
            "SELECT id FROM instances WHERE id=$1 FOR UPDATE",
            &[&instance],
        )
        .await?;
    transaction.execute("UPDATE instances SET phase='draining',health='unhealthy',revision=revision+1,updated_at=now() WHERE id=$1 AND phase<>'stopped'",&[&instance]).await?;
    transaction
        .execute(
            "UPDATE provider_records SET availability='unavailable' WHERE instance_id=$1",
            &[&instance],
        )
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn process_installations(app: &App) -> Result<()> {
    let c = app.db.connect().await?;
    let rows=c.query("SELECT b.id,b.aggregate_id,b.payload FROM outbox b JOIN operations o ON o.id=b.aggregate_id WHERE b.topic='kernel.install' AND b.delivered_at IS NULL AND o.state IN ('pending','running') ORDER BY b.created_at LIMIT 4",&[]).await?;
    for row in rows {
        let event: Uuid = row.get(0);
        let operation: Uuid = row.get(1);
        let payload: Value = row.get(2);
        let request = &payload["request"];
        let result = install(app, request, operation, &payload).await;
        let mut c = app.db.connect().await?;
        let tx = c.transaction().await?;
        db::complete(&tx, operation, result).await?;
        tx.execute(
            "UPDATE outbox SET delivered_at=now(),attempts=attempts+1 WHERE id=$1",
            &[&event],
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn install(app: &App, request: &Value, operation: Uuid, payload: &Value) -> Result<Value> {
    let credential = crate::contracts::id(payload, "credential_id")?;
    let peer = payload["peer"]
        .as_str()
        .and_then(|x| x.parse().ok())
        .ok_or_else(Error::credential)?;
    if app.leader.is_closed() {
        return Err(Error::unavailable("Controller leadership is lost"));
    }
    let c = app.db.connect().await?;
    app.auth.resume(&c, credential, peer, operation).await?;
    let publisher = crate::contracts::id(request, "publisher_id")?;
    let c = app.db.connect().await?;
    let row = c
        .query_opt(
            "SELECT public_key_pem FROM publishers WHERE id=$1 AND status='trusted'",
            &[&publisher],
        )
        .await?
        .ok_or_else(Error::denied)?;
    let artifact = Artifact::inspect(&app.runtime, request, &row.get::<_, String>(0)).await?;
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    if tx
        .query_opt(
            "SELECT id FROM publishers WHERE id=$1 AND status='trusted' FOR SHARE",
            &[&publisher],
        )
        .await?
        .is_none()
    {
        return Err(Error::denied());
    }
    let ctx = app.auth.resume(&tx, credential, peer, operation).await?;
    let plugin = artifact.manifest["plugin_id"].as_str().unwrap();
    authorize(
        &tx,
        &ctx,
        "plugin.install",
        &Resource::new("plugin", plugin, Some(ctx.subject)),
    )
    .await?;
    let version = artifact.manifest["version"].as_str().unwrap();
    let existing=tx.query_opt("SELECT id,image_digest,manifest_digest FROM installations WHERE plugin_id=$1 AND version=$2 FOR UPDATE",&[&plugin,&version]).await?;
    let id = if let Some(r) = existing {
        if r.get::<_, String>("image_digest") != artifact.image_digest
            || r.get::<_, String>("manifest_digest") != artifact.manifest_digest
        {
            return Err(Error::conflict(
                "Installed version already has different immutable content",
            ));
        }
        r.get("id")
    } else {
        let id = Uuid::new_v4();
        tx.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'installed',now(),now())",&[&id,&plugin,&version,&publisher,&artifact.image_digest,&artifact.manifest_digest,&artifact.manifest]).await?;
        for cap in artifact.manifest["capabilities"].as_array().unwrap() {
            let contract = &cap["contract"];
            let name = contract["name"].as_str().unwrap();
            let v = contract["version"].as_str().unwrap();
            let d = contract["schema_digest"].as_str().unwrap();
            tx.execute("INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4) ON CONFLICT(name,version) DO NOTHING",&[&name,&v,&d,&cap]).await?;
            let current=tx.query_one("SELECT schema_digest FROM capability_contracts WHERE name=$1 AND version=$2 FOR SHARE",&[&name,&v]).await?;
            if current.get::<_, String>(0) != d {
                return Err(Error::conflict(
                    "Capability version has a different schema digest",
                ));
            }
        }
        id
    };
    crate::events::store(&tx, id, &artifact.manifest).await?;
    crate::http_contracts::store(
        &tx,
        id,
        &artifact.manifest,
        artifact.http_contract.as_deref(),
    )
    .await?;
    // The immutable full reference is retained in the operation result and a private, root-owned image index.
    tls::atomic_file(
        &app.config
            .root()
            .join("images")
            .join(&artifact.image_digest[7..])
            .with_extension("reference"),
        artifact.image.as_bytes(),
        0o600,
    )?;
    tx.execute(
        "UPDATE operations SET resource_id=$2 WHERE id=$1",
        &[&operation, &id.to_string()],
    )
    .await?;
    db::outbox(&tx, "installation.installed", id, &json!({})).await?;
    if app.leader.is_closed() {
        return Err(Error::unavailable("Controller leadership is lost"));
    }
    tx.commit().await?;
    Ok(json!({"installation_id":id}))
}

async fn reconcile(app: &App, deployment: Uuid, probes: &mut BTreeMap<Uuid, Probe>) -> Result<()> {
    // Check holds after taking the runtime fence. A previous reconciliation
    // cannot create a writer after a backup worker has proved it stopped.
    let Some(_runtime_fence) = db::deployment_fence(&app.db, deployment).await? else {
        return Ok(());
    };
    let c = app.db.connect().await?;
    if c.query_opt(
        "SELECT deployment_id FROM deployment_storage_holds WHERE deployment_id=$1",
        &[&deployment],
    )
    .await?
    .is_some()
    {
        probes.remove(&deployment);
        return Ok(());
    }
    let Some(d)=c.query_opt("SELECT d.*,i.manifest,i.manifest_digest,i.image_digest FROM deployments d JOIN installations i ON i.id=d.installation_id WHERE d.id=$1",&[&deployment]).await? else {
        probes.remove(&deployment);
        return Ok(());
    };
    let spec: Value = d.get("spec");
    let manifest: Value = d.get("manifest");
    let instances=c.query("SELECT * FROM instances WHERE deployment_id=$1 AND phase<>'stopped' ORDER BY generation",&[&deployment]).await?;
    let archived = d
        .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
        .is_some();
    if spec["enabled"] != true || archived {
        probes.remove(&deployment);
        c.execute("UPDATE provider_records SET availability='unavailable' WHERE instance_id IN(SELECT id FROM instances WHERE deployment_id=$1)",&[&deployment]).await?;
        for i in instances {
            let id: Uuid = i.get("id");
            if let Ok(address) = app.runtime.address(id) {
                if let Ok(channel) =
                    tls::channel(&app.config, id, i.get("generation"), &address).await
                {
                    let mut client = PluginLifecycleClient::new(channel);
                    let mut request = tonic::Request::new(rpc::DrainRequest {
                        context: Some(context(None)),
                        grace_ms: 30000,
                    });
                    request.set_timeout(Duration::from_secs(30));
                    let _ = client.drain(request).await;
                }
            }
            app.runtime.stop(id).await?;
            let mut c = app.db.connect().await?;
            let tx = c.transaction().await?;
            tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
                .await?;
            tx.execute("UPDATE instances SET phase='stopped',health='unknown',updated_at=now(),revision=revision+1 WHERE id=$1",&[&id]).await?;
            tx.execute(
                "DELETE FROM plugin_http_requests WHERE instance_id=$1",
                &[&id],
            )
            .await?;
            crate::volumes::release_stopped(&tx, Some(id)).await?;
            admission::release_stopped(&tx, id).await?;
            tx.commit().await?;
        }
        c.execute(
            "UPDATE deployments SET phase='disabled',conditions='[]',updated_at=now() WHERE id=$1",
            &[&deployment],
        )
        .await?;
        if archived {
            c.execute("UPDATE operations SET state='failed',error=$2,revision=revision+1,updated_at=now() WHERE resource_id=$1 AND kind IN ('createDeployment','setDeploymentEnabled') AND state IN ('pending','running')", &[&deployment.to_string(), &Error::conflict("Deployment was archived").detail()]).await?;
        } else {
            finish_deployment_operations(&c, deployment, false).await?;
        }
        return Ok(());
    }
    let dependency_state = {
        let mut connection = app.db.connect().await?;
        let tx = connection.transaction().await?;
        db::auth_lock(&tx, false).await?;
        let result = crate::dependencies::check_ready(&tx, app, deployment).await;
        // Preserve a fail-policy latch even when readiness was rejected.
        tx.commit().await?;
        result
    };
    if let Err(error) = dependency_state {
        probes.remove(&deployment);
        for instance in &instances {
            let instance_id: Uuid = instance.get("id");
            mark_stopping(app, instance_id).await?;
            app.runtime.stop(instance_id).await?;
            // Keep the original generation intent for wait-policy recovery.
            // Stop proof precedes any storage/resource release or new startup.
            let mut connection = app.db.connect().await?;
            let tx = connection.transaction().await?;
            tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
                .await?;
            tx.execute("UPDATE instances SET phase='pending',runtime_id=NULL,health='unknown',updated_at=now() WHERE id=$1", &[&instance_id]).await?;
            tx.execute(
                "DELETE FROM plugin_http_requests WHERE instance_id=$1",
                &[&instance_id],
            )
            .await?;
            crate::volumes::release_stopped(&tx, Some(instance_id)).await?;
            // The reservation remains held while dependency recovery is pending.
            tx.commit().await?;
        }
        return Err(error);
    }
    crate::host_blobs::check_approval(&c, app, deployment, &manifest).await?;
    crate::plugin_http_gateway::check_approval(&c, app, deployment, &manifest).await?;
    let Some(i) = instances.last() else {
        probes.remove(&deployment);
        return Err(Error::conflict(
            "Enabled deployment has no admitted instance intent",
        ));
    };
    let id: Uuid = i.get("id");
    let generation: i64 = i.get("generation");
    let probe = probes.entry(deployment).or_default();
    probe.bind(id, generation);
    let limits: Value = i.get("limits");
    let running = app.runtime.running(id).await?;
    let mounts = match crate::volumes::mounts(app, deployment, id, generation, &manifest).await {
        Ok(mounts) => mounts,
        Err(error) => {
            mark_stopping(app, id).await?;
            app.runtime.stop(id).await?;
            let mut dbc = app.db.connect().await?;
            let tx = dbc.transaction().await?;
            crate::volumes::release_stopped(&tx, Some(id)).await?;
            tx.execute(
                "DELETE FROM plugin_http_requests WHERE instance_id=$1",
                &[&id],
            )
            .await?;
            tx.execute(
                "UPDATE provider_records SET availability='unavailable' WHERE instance_id=$1",
                &[&id],
            )
            .await?;
            tx.commit().await?;
            return Err(error);
        }
    };
    if running
        && probe
            .next
            .is_some_and(|at| tokio::time::Instant::now() < at)
    {
        return Ok(());
    }
    probe.next = Some(
        tokio::time::Instant::now()
            + Duration::from_millis(manifest["health"]["interval_ms"].as_u64().unwrap()),
    );
    if !running {
        let count = i.get::<_, i32>("restart_count");
        if count >= 5 {
            c.execute("UPDATE instances SET phase='failed',health='unhealthy',revision=revision+1,updated_at=now() WHERE id=$1 AND phase<>'failed'", &[&id]).await?;
            return Err(Error::unavailable(
                "Instance exhausted its restart budget; disable and enable to retry",
            ));
        }
        let since = (chrono::Utc::now() - i.get::<_, chrono::DateTime<chrono::Utc>>("updated_at"))
            .num_seconds();
        if count > 0 && since < (1i64 << count.min(5)) {
            return Err(Error::unavailable("Instance restart backoff is active"));
        }
    }
    let mut dbc = app.db.connect().await?;
    let tx = dbc.transaction().await?;
    admission::reserve(&tx, id).await?;
    tx.commit().await?;
    let sha: String = d.get("image_digest");
    let image = std::fs::read_to_string(
        app.config
            .root()
            .join("images")
            .join(&sha[7..])
            .with_extension("reference"),
    )?;
    if !running {
        probe.started = Some(tokio::time::Instant::now());
        c.execute("UPDATE instances SET restart_count=restart_count+1,phase='starting',health='unknown',updated_at=now(),revision=revision+1 WHERE id=$1", &[&id]).await?;
    }
    let obs = app
        .runtime
        .ensure(
            id, deployment, generation, &manifest, &image, &sha, &limits, &mounts,
        )
        .await?;
    if !obs.running {
        return Err(Error::unavailable("OCI task is not running"));
    }
    let mut health_stage = "channel";
    let checked: Result<rpc::HealthResponse> = async {
        let channel = tls::channel(&app.config, id, generation, &obs.address).await?;
        let mut client = PluginLifecycleClient::new(channel);
        if !running || i.get::<_, String>("phase") != "ready" {
            health_stage = "describe";
            let description = client
                .describe(rpc::DescribeRequest {
                    context: Some(context(None)),
                })
                .await?
                .into_inner();
            if description.manifest_digest != d.get::<_, String>("manifest_digest")
                || digest(&description.manifest_json) != description.manifest_digest
                || strict_json(&description.manifest_json, 1048576)? != manifest
            {
                return Err(Error::conflict(
                    "Describe does not match the signed installation",
                ));
            }
            health_stage = "initialize";
            let initialized = client
                .initialize(rpc::InitializeRequest {
                    context: Some(context(None)),
                    deployment_id: deployment.to_string(),
                    instance_id: id.to_string(),
                    generation: generation as u64,
                    config_json: serde_json::to_vec(&spec["config"])?,
                    config_digest: digest(&serde_json::to_vec(&spec["config"])?),
                    approval_revision: d.get::<_, i64>("revision") as u64,
                })
                .await?
                .into_inner();
            if !initialized.initialized || initialized.observed_generation != generation as u64 {
                return Err(Error::conflict("Plugin initialization generation differs"));
            }
        }
        let mut health_request = tonic::Request::new(rpc::HealthRequest {
            context: Some(context(None)),
        });
        health_request.set_timeout(Duration::from_millis(
            manifest["health"]["timeout_ms"].as_u64().unwrap(),
        ));
        health_stage = "get_health";
        let health = client.get_health(health_request).await?.into_inner();
        if !health.alive || health.observed_generation != generation as u64 {
            return Err(Error::unavailable("Plugin health generation differs"));
        }
        if manifest["routes"]
            .as_array()
            .is_some_and(|routes| !routes.is_empty())
        {
            health_stage = "http_probe";
            tokio::time::timeout(
                Duration::from_secs(2),
                crate::plugin_http::transport::InstanceHttp::from_runtime(
                    &app.config,
                    &app.runtime,
                    id,
                    generation,
                )?
                .probe(),
            )
            .await
            .map_err(|_| Error::unavailable("Plugin HTTP TLS readiness probe timed out"))??;
        }
        Ok(health)
    }
    .await;
    let health = match checked {
        Ok(health) => {
            probe.failures = 0;
            health
        }
        Err(error) => {
            probe.failures += 1;
            let was_ready = i.get::<_, String>("phase") == "ready";
            let threshold = manifest["health"]["failure_threshold"].as_u64().unwrap();
            tracing::info!(target: "xelab.controller_transition", code = "HEALTH_REJECTED", stage = health_stage, instance_id = %id, deployment_id = %deployment, failures = probe.failures, threshold, was_ready);
            c.execute("UPDATE instances SET health='unhealthy',revision=revision+1,updated_at=now() WHERE id=$1 AND health<>'unhealthy'", &[&id]).await?;
            let failed = if was_ready {
                probe.failures >= threshold
            } else {
                probe.started.is_some_and(|at| {
                    at.elapsed()
                        >= Duration::from_millis(
                            manifest["health"]["startup_timeout_ms"].as_u64().unwrap(),
                        )
                })
            };
            if failed {
                tracing::info!(target: "xelab.controller_transition", code = "HEALTH_THRESHOLD_STOP", stage = health_stage, instance_id = %id, deployment_id = %deployment, failures = probe.failures, threshold, was_ready);
                mark_stopping(app, id).await?;
                app.runtime.stop(id).await?;
                c.execute(
                    "DELETE FROM plugin_http_requests WHERE instance_id=$1",
                    &[&id],
                )
                .await?;
                probe.failures = 0;
            }
            return Err(error);
        }
    };
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    db::auth_lock(&tx, false).await?;
    crate::volumes::check_approval(&tx, app, deployment, generation, &spec, &manifest).await?;
    crate::host_blobs::check_approval(&tx, app, deployment, &manifest).await?;
    crate::plugin_http_gateway::check_approval(&tx, app, deployment, &manifest).await?;
    crate::dependencies::check_ready(&tx, app, deployment).await?;
    let current = tx
        .query_one(
            "SELECT spec,approval,archived_at FROM deployments WHERE id=$1 FOR UPDATE",
            &[&deployment],
        )
        .await?;
    if current
        .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
        .is_some()
        || current.get::<_, Value>("spec") != spec
        || current.get::<_, Value>("approval") != d.get::<_, Value>("approval")
    {
        return Err(Error::conflict(
            "Deployment changed while runtime was starting",
        ));
    }
    let mut all_ready = true;
    for cap in manifest["capabilities"].as_array().unwrap() {
        let name = cap["contract"]["name"].as_str().unwrap();
        let version = cap["contract"]["version"].as_str().unwrap();
        let digest = cap["contract"]["schema_digest"].as_str().unwrap();
        let ready = health.capabilities.iter().any(|h| {
            h.ready
                && h.contract.as_ref().is_some_and(|c| {
                    c.name == name && c.version == version && c.schema_digest == digest
                })
        });
        all_ready &= ready;
        let features = health
            .capabilities
            .iter()
            .find(|h| {
                h.contract.as_ref().is_some_and(|c| {
                    c.name == name && c.version == version && c.schema_digest == digest
                })
            })
            .map(|h| h.features.clone())
            .unwrap_or_default();
        if features.len() > 256
            || features
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
            || features
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != features.len()
        {
            return Err(Error::invalid("Invalid provider feature observation"));
        }
        let state = if ready { "ready" } else { "unavailable" };
        tx.execute("INSERT INTO provider_records(instance_id,name,version,availability,features,observed_generation,observed_at) VALUES($1,$2,$3,$4,$6,$5,now()) ON CONFLICT(instance_id,name,version) DO UPDATE SET availability=excluded.availability,features=excluded.features,observed_generation=excluded.observed_generation,observed_at=now()",&[&id,&name,&version,&state,&generation,&json!(features)]).await?;
    }
    let phase = if all_ready { "ready" } else { "degraded" };
    tx.execute("UPDATE instances SET phase=$2,health='alive',runtime_id=$3,last_heartbeat_at=now(),updated_at=now(),revision=revision+1 WHERE id=$1",&[&id,&phase,&id.to_string()]).await?;
    let dependency_conditions =
        json!(crate::dependencies::optional_conditions(&tx, deployment).await?);
    tx.execute("UPDATE deployments SET revision=revision+CASE WHEN phase<>$2 OR observed_generation<>$3 OR conditions<>$4 THEN 1 ELSE 0 END,phase=$2,observed_generation=$3,conditions=$4,updated_at=now() WHERE id=$1",&[&deployment,&phase,&generation,&dependency_conditions]).await?;
    if app.leader.is_closed() {
        return Err(Error::unavailable("Controller leadership is lost"));
    }
    if all_ready {
        finish_deployment_operations(&tx, deployment, true).await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn finish_deployment_operations(
    c: &impl tokio_postgres::GenericClient,
    id: Uuid,
    enabled: bool,
) -> Result<()> {
    let Some(row) = c.query_opt("SELECT to_jsonb(d) FROM deployments d WHERE d.id=$1 AND (d.spec->>'enabled')::boolean=$2 AND EXISTS(SELECT 1 FROM operations o WHERE o.resource_id=d.id::text AND o.kind IN ('createDeployment','setDeploymentEnabled') AND o.state IN ('pending','running'))", &[&id,&enabled]).await? else { return Ok(()); };
    let raw: Value = row.get(0);
    let result = crate::api::object_value(&raw, "Deployment")?;
    // The projected result and completion must describe the same observation.
    // A concurrent intent/revision change leaves this operation for a new tick.
    c.execute("UPDATE operations SET state='succeeded',progress_percent=100,result=$2,updated_at=now(),revision=revision+1 WHERE resource_id=$1 AND kind IN ('createDeployment','setDeploymentEnabled') AND state IN ('pending','running') AND EXISTS(SELECT 1 FROM deployments d WHERE d.id=$3 AND (d.spec->>'enabled')::boolean=$4 AND to_jsonb(d)=$5)",&[&id.to_string(),&result,&id,&enabled,&raw]).await?;
    Ok(())
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[tokio::test]
    async fn fenced_call_journal_preserves_cancel_intent_and_only_changes_unsettled_instance_work()
    {
        let Some(f) = crate::backups::tests::Fixture::new().await else {
            return;
        };
        let mut c = f.app.db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        let deployment = tx
            .query_one("SELECT id,owner_id FROM deployments LIMIT 1", &[])
            .await
            .unwrap();
        let owner: Uuid = deployment.get("owner_id");
        let instance = Uuid::new_v4();
        let unrelated = Uuid::new_v4();
        for (ordinal, id) in [instance, unrelated].into_iter().enumerate() {
            tx.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,$3,0,'ready','alive','{}',now(),now())", &[&id,&deployment.get::<_, Uuid>("id"),&((ordinal+1) as i64)]).await.unwrap();
        }
        let canceled = Error::new(
            "CANCELED",
            "Call cancellation was requested; physical outcome remains unknown",
            axum::http::StatusCode::CONFLICT,
        )
        .detail();
        let previous = Error::unavailable("prior failure").detail();
        let mut ids = Vec::new();
        for (provider, state, error, reservation) in [
            (instance, "unknown", Some(canceled.clone()), "active"),
            (instance, "running", None, "active"),
            (instance, "unknown", Some(previous.clone()), "active"),
            (instance, "succeeded", None, "released"),
            (instance, "unknown", Some(previous.clone()), "released"),
            (unrelated, "running", None, "active"),
        ] {
            let id = Uuid::new_v4();
            tx.execute("INSERT INTO calls(id,owner_id,provider_instance_id,contract,input_digest,state,error,deadline_at,created_at) VALUES($1,$2,$3,'{}',$4,$5,$6,now()+interval '1 minute',now())", &[&id,&owner,&provider,&digest(b"metadata-only recovery"),&state,&error]).await.unwrap();
            tx.execute("INSERT INTO reservations(id,account_id,kind,status,created_at) VALUES($1,$2,'call',$3,now())", &[&id,&owner,&reservation]).await.unwrap();
            ids.push(id);
        }
        let unknown = Error::new(
            "OUTCOME_UNKNOWN",
            "Physical process stopped before result confirmation",
            axum::http::StatusCode::CONFLICT,
        )
        .detail();
        let changed = tx
            .query(FENCE_EXPIRED_CALLS, &[&instance, &unknown])
            .await
            .unwrap();
        let changed: std::collections::BTreeSet<Uuid> =
            changed.iter().map(|row| row.get("id")).collect();
        assert_eq!(changed, ids[..3].iter().copied().collect());
        for (index, id) in ids.iter().enumerate() {
            let row = tx.query_one("SELECT c.state,c.error,r.status FROM calls c JOIN reservations r ON r.id=c.id WHERE c.id=$1", &[&id]).await.unwrap();
            let error: Option<Value> = row.get("error");
            match index {
                0 => {
                    assert_eq!(row.get::<_, String>("state"), "unknown");
                    assert_eq!(error, Some(canceled.clone()));
                }
                1 | 2 => {
                    assert_eq!(row.get::<_, String>("state"), "unknown");
                    assert_eq!(error, Some(unknown.clone()));
                }
                3 => {
                    assert_eq!(row.get::<_, String>("state"), "succeeded");
                    assert!(error.is_none());
                }
                4 => assert_eq!(error, Some(previous.clone())),
                5 => {
                    assert_eq!(row.get::<_, String>("state"), "running");
                    assert!(error.is_none());
                }
                _ => unreachable!(),
            }
            assert_eq!(
                row.get::<_, String>("status"),
                if matches!(index, 3 | 4) {
                    "released"
                } else {
                    "active"
                }
            );
        }
        // Metadata query evidence only. Physical stop, delegation revocation and
        // slot release remain exercised by the actual OCI cancellation test.
        tx.rollback().await.unwrap();
    }
}

#[cfg(test)]
#[path = "deployment_operation_tests.rs"]
mod operation_tests;

#[cfg(test)]
mod pagination_tests {
    use super::*;

    #[test]
    fn probe_rebind_preserves_same_instance_and_resets_redeployment() {
        let id = Uuid::new_v4();
        let mut probe = Probe::default();
        probe.bind(id, 1);
        let now = tokio::time::Instant::now();
        probe.next = Some(now + Duration::from_secs(30));
        probe.started = Some(now);
        probe.failures = 3;
        probe.bind(id, 1);
        assert_eq!(probe.failures, 3);
        assert_eq!(probe.started, Some(now));
        assert_eq!(probe.next, Some(now + Duration::from_secs(30)));
        probe.bind(Uuid::new_v4(), 2);
        assert_eq!(probe.failures, 0);
        assert!(probe.started.is_none() && probe.next.is_none());
    }

    #[tokio::test]
    async fn controller_reconciles_deployment_1001_after_disabled_prefix() {
        let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            return;
        };
        let admin = db::Db::new(base.clone()).unwrap().connect().await.unwrap();
        let database = format!("controller_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .await
            .unwrap();
        let db = db::Db::new(format!("{base} dbname={database}")).unwrap();
        db.migrate().await.unwrap();
        let c = db.connect().await.unwrap();
        let owner = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let installation = Uuid::new_v4();
        c.execute("INSERT INTO accounts(id,kind,status,display_name,created_at,updated_at) VALUES($1,'user','active','fixture',now(),now())", &[&owner]).await.unwrap();
        c.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'fixture','fixture','unused','trusted',now(),now())", &[&publisher]).await.unwrap();
        c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,'org.xelab.fixture','1.0.0',$2,'test','test','{}','installed',now(),now())", &[&installation,&publisher]).await.unwrap();
        for n in 1..=1001u128 {
            c.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,approval,phase,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'reconciling',now(),now())", &[&Uuid::from_u128(n),&owner,&installation,&json!({"enabled":n==1001}),&json!({"rules":[],"egress":[]})]).await.unwrap();
        }
        let value: toml::Value =
            toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
        let config =
            crate::config::Config::from_value(serde_json::to_value(value).unwrap()).unwrap();
        let app = App {
            runtime: crate::runtime::Runtime::new(config.clone()),
            config,
            db: db.clone(),
            auth: crate::auth::Auth::new(vec![42; 32]).unwrap(),
            leader: Arc::new(db.leader().await.unwrap()),
            ready: std::sync::atomic::AtomicBool::new(false),
            shutdown: std::sync::atomic::AtomicBool::new(false),
            blob_uploads: tokio::sync::Semaphore::new(4),
        };
        let mut state = ControllerState::default();
        // Losing an instance intent must also discard its obsolete probe.
        state.probes.insert(Uuid::from_u128(1001), Probe::default());
        tokio::time::timeout(Duration::from_secs(10), tick(&app, false, &mut state))
            .await
            .unwrap()
            .unwrap();
        let tail = c
            .query_one(
                "SELECT phase,conditions FROM deployments WHERE id=$1",
                &[&Uuid::from_u128(1001)],
            )
            .await
            .unwrap();
        // No instance intent is provided: reconciliation must actually reach
        // the tail and record that error, without needing an OCI runtime.
        assert_eq!(tail.get::<_, String>(0), "degraded");
        assert_ne!(tail.get::<_, Value>(1), json!([]));
        let disabled: i64 = c
            .query_one(
                "SELECT count(*) FROM deployments WHERE phase='disabled'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(disabled > 0 && disabled <= DEPLOYMENTS_PER_LANE as i64);
        assert!(
            state.probes.is_empty(),
            "inactive/missing-instance rows need no probe"
        );
        // The continuation is retained across ticks, and every disabled row
        // eventually settles even though active errors keep being retried.
        for _ in 0..1002 {
            if c.query_one(
                "SELECT count(*) FROM deployments WHERE phase='disabled'",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
                == 1000
            {
                break;
            }
            tick(&app, false, &mut state).await.unwrap();
        }
        assert_eq!(
            c.query_one(
                "SELECT count(*) FROM deployments WHERE phase='disabled'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1000
        );
        // Simulate the post-fencing state of a controller restart with a large
        // active backlog. The global fencing path itself is covered by OCI.
        c.execute(
            r#"UPDATE deployments SET spec='{"enabled":true}',phase='reconciling'"#,
            &[],
        )
        .await
        .unwrap();
        c.execute(r#"INSERT INTO deployments(id,owner_id,installation_id,spec,approval,phase,created_at,updated_at) SELECT md5(n::text)::uuid,$1,$2,'{"enabled":true}',$3,'reconciling',now(),now() FROM generate_series(2000,2598) n"#, &[&owner,&installation,&json!({"rules":[],"egress":[]})]).await.unwrap();
        // The inactive lane must also complete before readiness can open.
        let inactive = Uuid::new_v4();
        c.execute(r#"INSERT INTO deployments(id,owner_id,installation_id,spec,approval,phase,created_at,updated_at) VALUES($1,$2,$3,'{"enabled":false}',$4,'reconciling',now(),now())"#, &[&inactive,&owner,&installation,&json!({"rules":[],"egress":[]})]).await.unwrap();
        let app = Arc::new(app);
        let router = crate::api::router(app.clone());
        use tower::ServiceExt;
        let path = crate::contracts::openapi()["paths"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, methods)| methods["get"]["operationId"] == "getReadiness")
            .unwrap()
            .0
            .clone();
        let mut restart = ControllerState {
            startup_fenced: true,
            ..Default::default()
        };
        let mut rounds = 0;
        loop {
            reconcile_tick(&app, &mut restart).await.unwrap();
            rounds += 1;
            let pending: i64 = c
                .query_one(
                    "SELECT count(*) FROM deployments WHERE phase='reconciling'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            let mut request = axum::http::Request::builder()
                .uri(&path)
                .header(
                    "host",
                    crate::plugin_http_gateway::core_authority(&app.config).unwrap(),
                )
                .body(axum::body::Body::empty())
                .unwrap();
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                "127.0.0.1:30000".parse::<std::net::SocketAddr>().unwrap(),
            ));
            let response = router.clone().oneshot(request).await.unwrap();
            if pending > 0 {
                assert_eq!(
                    response.status(),
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                );
            } else if response.status() == axum::http::StatusCode::OK {
                break;
            }
            assert!(rounds <= 1602, "initial recovery never completes");
        }
        assert!(
            rounds >= 100,
            "readiness must wait for all 1600 active rows"
        );
        assert!(restart.active.initial_complete && restart.inactive.initial_complete);
        // Subsequent sweeps never reset the initial-completion barrier.
        reconcile_tick(&app, &mut restart).await.unwrap();
        assert!(app.ready.load(Ordering::SeqCst));
        c.batch_execute("ALTER TABLE outbox RENAME TO outbox_unavailable")
            .await
            .unwrap();
        assert!(reconcile_tick(&app, &mut restart).await.is_err());
        assert!(!app.ready.load(Ordering::SeqCst));
        assert!(restart.startup_fenced && restart.active.initial_complete);
        c.batch_execute("ALTER TABLE outbox_unavailable RENAME TO outbox")
            .await
            .unwrap();
        reconcile_tick(&app, &mut restart).await.unwrap();
        assert!(app.ready.load(Ordering::SeqCst));
        // A selected row may disappear or become archived before reconcile.
        // Both paths release the probe without needing a runtime adapter.
        let tail = Uuid::from_u128(1001);
        c.execute(
            "UPDATE deployments SET archived_at=now() WHERE id=$1",
            &[&tail],
        )
        .await
        .unwrap();
        state.probes.insert(tail, Probe::default());
        reconcile(&app, tail, &mut state.probes).await.unwrap();
        assert!(!state.probes.contains_key(&tail));
        c.execute("DELETE FROM deployments WHERE id=$1", &[&tail])
            .await
            .unwrap();
        state.probes.insert(tail, Probe::default());
        reconcile(&app, tail, &mut state.probes).await.unwrap();
        assert!(!state.probes.contains_key(&tail));
    }

    #[tokio::test]
    async fn deployment_sweep_passes_disabled_prefix_and_handles_deletions() {
        let Ok(dsn) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            return;
        };
        let db = db::Db::new(dsn).unwrap();
        let mut c = db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        tx.batch_execute("CREATE TEMP TABLE deployments(id uuid PRIMARY KEY,created_at timestamptz NOT NULL,archived_at timestamptz,spec jsonb) ON COMMIT DROP").await.unwrap();
        let at = chrono::Utc::now();
        for n in 1..=1100u128 {
            tx.execute(
                "INSERT INTO deployments VALUES($1,$2,NULL,$3)",
                &[&Uuid::from_u128(n), &at, &json!({"enabled":true})],
            )
            .await
            .unwrap();
        }
        let mut sweep = Sweep::default();
        assert!(!sweep.initial_complete);
        let first = deployment_page(&tx, &mut sweep, true).await.unwrap();
        assert_eq!(first.len(), DEPLOYMENTS_PER_LANE);
        // Consume just one item (a slow reconciliation exhausted the time slice).
        // The other fetched items MUST be returned again in the following tick.
        sweep.after = Some((first[0].get(0), first[0].get(1)));
        let page = deployment_page(&tx, &mut sweep, true).await.unwrap();
        assert_eq!(page[0].get::<_, Uuid>(1), Uuid::from_u128(2));
        tx.execute(
            "DELETE FROM deployments WHERE id=$1",
            &[&Uuid::from_u128(1)],
        )
        .await
        .unwrap();
        tx.execute(
            "UPDATE deployments SET archived_at=now() WHERE id=$1",
            &[&Uuid::from_u128(2)],
        )
        .await
        .unwrap();
        tx.execute(
            "UPDATE deployments SET spec=$2 WHERE id=$1",
            &[&Uuid::from_u128(3), &json!({"enabled":false})],
        )
        .await
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        for n in 0..100u128 {
            // A continuously growing tail must not move the captured watermark.
            tx.execute(
                "INSERT INTO deployments VALUES($1,$2,NULL,$3)",
                &[&Uuid::from_u128(1200 + n), &at, &json!({"enabled":true})],
            )
            .await
            .unwrap();
            let page = deployment_page(&tx, &mut sweep, true).await.unwrap();
            assert!(page.len() <= DEPLOYMENTS_PER_LANE);
            if page.is_empty() {
                break;
            }
            for row in page {
                let id: Uuid = row.get(1);
                assert!(seen.insert(id));
                assert!(id <= Uuid::from_u128(1100));
                sweep.after = Some((row.get(0), id));
            }
        }
        assert_eq!(seen.len(), 1097);
        assert!(sweep.through.is_none());
        assert!(sweep.initial_complete);
        // Enable a row behind the old cursor; it is visible on the next sweep.
        tx.execute(
            "UPDATE deployments SET spec=$2 WHERE id=$1",
            &[&Uuid::from_u128(3), &json!({"enabled":true})],
        )
        .await
        .unwrap();
        let next = deployment_page(&tx, &mut sweep, true).await.unwrap();
        assert_eq!(next[0].get::<_, Uuid>(1), Uuid::from_u128(3));
        assert!(sweep.through.unwrap().1 > Uuid::from_u128(1100));
        tx.execute("DELETE FROM deployments", &[]).await.unwrap();
        // Deleted watermark ends the old sweep; an empty initial sweep is done.
        assert!(deployment_page(&tx, &mut sweep, true)
            .await
            .unwrap()
            .is_empty());
        let mut empty = Sweep::default();
        assert!(deployment_page(&tx, &mut empty, true)
            .await
            .unwrap()
            .is_empty());
        assert!(empty.initial_complete);
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn probe_churn_is_reclaimed_without_resetting_active_health_state() {
        let Ok(dsn) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            return;
        };
        let db = db::Db::new(dsn).unwrap();
        let mut c = db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        tx.batch_execute("CREATE TEMP TABLE deployments(id uuid PRIMARY KEY,archived_at timestamptz,spec jsonb) ON COMMIT DROP").await.unwrap();
        let mut state = ControllerState::default();
        let stable = Uuid::from_u128(1);
        let now = tokio::time::Instant::now();
        state.probes.insert(
            stable,
            Probe {
                instance: Some((stable, 7)),
                next: Some(now + Duration::from_secs(30)),
                started: Some(now),
                failures: 2,
            },
        );
        tx.execute(
            "INSERT INTO deployments VALUES($1,NULL,$2)",
            &[&stable, &json!({"enabled":true})],
        )
        .await
        .unwrap();
        for round in 0..40u128 {
            // Each cycle exceeds one GC batch, mixing disabled, archived and
            // deleted rows, followed by re-deployment under new instance IDs.
            for n in 0..130u128 {
                let id = Uuid::from_u128(2 + round * 130 + n);
                tx.execute(
                    "INSERT INTO deployments VALUES($1,NULL,$2)",
                    &[&id, &json!({"enabled":true})],
                )
                .await
                .unwrap();
                state.probes.insert(id, Probe::default());
                match n % 3 {
                    0 => {
                        tx.execute(
                            "UPDATE deployments SET archived_at=now() WHERE id=$1",
                            &[&id],
                        )
                        .await
                        .unwrap();
                    }
                    1 => {
                        tx.execute(
                            "UPDATE deployments SET spec=$2 WHERE id=$1",
                            &[&id, &json!({"enabled":false})],
                        )
                        .await
                        .unwrap();
                    }
                    _ => {
                        tx.execute("DELETE FROM deployments WHERE id=$1", &[&id])
                            .await
                            .unwrap();
                    }
                }
            }
            for _ in 0..5 {
                prune_probes(&tx, &mut state).await.unwrap();
            }
            assert_eq!(state.probes.len(), 1);
            let probe = &state.probes[&stable];
            assert_eq!(probe.instance, Some((stable, 7)));
            assert_eq!(probe.failures, 2);
            assert_eq!(probe.started, Some(now));
            assert_eq!(probe.next, Some(now + Duration::from_secs(30)));
        }
        tx.rollback().await.unwrap();
    }
}
