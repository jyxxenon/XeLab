//! Durable recreate admission for stateless and same-schema volume upgrades.
use crate::{
    api::{self, App},
    artifact::{self, Artifact},
    auth::{self, Context, Resource},
    contracts::{id, validate},
    db,
    error::{Error, Result},
    policy::{self, Policy},
};
use axum::http::HeaderMap;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use tokio_postgres::{GenericClient, Row};
use uuid::Uuid;

#[path = "upgrades_backups.rs"]
pub mod migration_backup;
#[path = "upgrades_schema.rs"]
mod schema_transition;
pub(crate) use schema_transition::{
    registration as schema_registration, revalidate as revalidate_schema_child,
};
#[path = "upgrades_volumes.rs"]
mod volume_group;
#[path = "upgrades_worker.rs"]
mod worker;
pub(crate) use worker::artifact;
pub use worker::run;

fn metadata(row: &Row) -> Value {
    json!({"id":row.get::<_,Uuid>("id"),"publisher_id":row.get::<_,Uuid>("publisher_id"),"plugin_id":row.get::<_,String>("plugin_id"),"version":row.get::<_,String>("version"),"image_digest":row.get::<_,String>("image_digest"),"manifest_digest":row.get::<_,String>("manifest_digest"),"manifest":row.get::<_,Value>("manifest")})
}
pub(crate) async fn installation(
    c: &(impl GenericClient + Sync),
    installation: Uuid,
) -> Result<Value> {
    let row=c.query_opt("SELECT i.* FROM installations i JOIN publishers p ON p.id=i.publisher_id WHERE i.id=$1 AND i.state='installed' AND p.status='trusted' FOR SHARE OF i,p",&[&installation]).await?.ok_or_else(||Error::conflict("Upgrade installation is not currently trusted"))?;
    let value = metadata(&row);
    artifact::validate_runtime_profile(&value["manifest"])?;
    if ["publisher_id", "plugin_id", "version"]
        .iter()
        .any(|field| value[*field] != value["manifest"][*field])
    {
        return Err(Error::conflict(
            "Upgrade installation header differs from its manifest",
        ));
    }
    Ok(value)
}
/// Shared by new requests AND idempotent replay. Replaying a stored Operation
/// does not bypass any of the original composite resource permissions.
pub async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    deployment: Uuid,
    action: &str,
    body: &Value,
) -> Result<()> {
    if !matches!(action, "plugin.upgrade" | "plugin.rollback") {
        return Err(Error::invalid("Invalid upgrade action"));
    }
    let owner: Uuid = c
        .query_opt(
            "SELECT owner_id FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await?
        .ok_or_else(Error::not_found)?
        .get(0);
    if owner != ctx.subject {
        return Err(Error::denied());
    }
    let spec: Value = c
        .query_one("SELECT spec FROM deployments WHERE id=$1", &[&deployment])
        .await?
        .get(0);
    volume_group::authorize_group(c, ctx, &spec["volume_ids"]).await?;
    for required in [action, "plugin.read", "plugin.enable"] {
        auth::authorize(
            c,
            ctx,
            required,
            &Resource::new("deployment", deployment, Some(owner)),
        )
        .await?;
    }
    let plugin: String = c
        .query_opt(
            "SELECT plugin_id FROM installations WHERE id=$1",
            &[&id(body, "installation_id")?],
        )
        .await?
        .ok_or_else(Error::not_found)?
        .get(0);
    auth::authorize(
        c,
        ctx,
        "plugin.read",
        &Resource::new("plugin", plugin, None),
    )
    .await?;
    if body.get("backup_id").is_some() {
        let backup = id(body, "backup_id")?;
        let owner: Uuid = c
            .query_opt("SELECT created_by FROM backups WHERE id=$1", &[&backup])
            .await?
            .ok_or_else(Error::not_found)?
            .get(0);
        auth::authorize(
            c,
            ctx,
            "backup.read",
            &Resource::new("backup", backup, Some(owner)),
        )
        .await?;
    }
    Ok(())
}
/// Replay uses the original operation mapping after deployment UUIDs change.
pub async fn authorize_replay(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    operation: Uuid,
) -> Result<()> {
    let row = c
        .query_one(
            "SELECT * FROM deployment_upgrade_jobs WHERE operation_id=$1",
            &[&operation],
        )
        .await?;
    if row.get::<_, Uuid>("subject_id") != ctx.subject
        || row.get::<_, Uuid>("credential_id") != ctx.credential
    {
        return Err(Error::denied());
    }
    let saved: Vec<policy::Path> =
        serde_json::from_value(row.get("authority")).map_err(|_| Error::denied())?;
    let available = policy::rules(
        &Policy::for_context(c, ctx)
            .revalidate(&saved, ctx.credential)
            .await?,
    );
    volume_group::authorize_saved(c, ctx, &row, &available).await
}

/// Caller owns the authorization-fenced admission transaction.
pub async fn create(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    deployment: Uuid,
    action: &str,
    body: &Value,
    headers: &HeaderMap,
) -> Result<(Value, u16)> {
    crate::dependencies::dependency_lock(c).await?;
    validate("UpgradeRequest", body)?;
    if !matches!(action, "plugin.upgrade" | "plugin.rollback") {
        return Err(Error::invalid("Invalid upgrade action"));
    }
    if body["strategy"] != "recreate" || body["allow_downtime"] != true {
        return Err(Error::invalid(
            "This upgrade profile requires recreate and explicit downtime",
        ));
    }
    if !app.ready.load(Ordering::SeqCst) || app.leader.is_closed() {
        return Err(Error::unavailable(
            "Upgrade waits for startup runtime fencing",
        ));
    }
    let row = c
        .query_opt("SELECT * FROM deployments WHERE id=$1", &[&deployment])
        .await?
        .ok_or_else(Error::not_found)?;
    api::etag(headers, row.get("revision"))?;
    let original_revision: i64 = row.get("revision");
    if !(1..9_007_199_254_740_990).contains(&original_revision) {
        return Err(Error::exhausted());
    }
    let revision = original_revision + 1;
    if row.get::<_, Uuid>("owner_id") != ctx.subject
        || row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
    {
        return Err(Error::denied());
    }
    for required in [action, "plugin.read", "plugin.enable"] {
        auth::authorize(
            c,
            ctx,
            required,
            &Resource::new("deployment", deployment, Some(ctx.subject)),
        )
        .await?;
    }
    crate::backups::ensure_unheld(c, deployment).await?;
    if c.query_one("SELECT count(*) FROM deployment_storage_holds", &[])
        .await?
        .get::<_, i64>(0)
        >= 2
    {
        return Err(Error::exhausted());
    }
    let source_id: Uuid = row.get("installation_id");
    let target_id = id(body, "installation_id")?;
    if source_id == target_id {
        return Err(Error::conflict(
            "Upgrade target is already installed on the deployment",
        ));
    }
    let source = installation(c, source_id).await?;
    let target = installation(c, target_id).await?;
    let source_version = semver::Version::parse(source["version"].as_str().unwrap())
        .map_err(|_| Error::conflict("Invalid installed source version"))?;
    let target_version = semver::Version::parse(target["version"].as_str().unwrap())
        .map_err(|_| Error::conflict("Invalid installed target version"))?;
    let order = target_version.cmp_precedence(&source_version);
    if (action == "plugin.upgrade" && !order.is_gt())
        || (action == "plugin.rollback" && !order.is_lt())
    {
        return Err(Error::conflict(
            "Installed target does not match upgrade or rollback direction",
        ));
    }
    if source["plugin_id"] != target["plugin_id"]
        || source["publisher_id"] != target["publisher_id"]
        || target["manifest"]["upgrade_strategy"] != "recreate"
    {
        return Err(Error::conflict(
            "Upgrade plugin, publisher or declared strategy differs",
        ));
    }
    auth::authorize(
        c,
        ctx,
        "plugin.read",
        &Resource::new("plugin", target["plugin_id"].as_str().unwrap(), None),
    )
    .await?;
    let original: Value = row.get("spec");
    // The worker clears approvals when publishing a new installation. A
    // versioned target with required Blob grants must be approved while disabled.
    if original["enabled"] == true
        && target["manifest"]["data_schema_version"] != "none"
        && target["manifest"]["requested_rules"]
            .as_array()
            .is_some_and(|rules| rules.iter().any(|request| request["required"] == true))
    {
        return Err(Error::conflict(
            "Disable the deployment before changing to a versioned installation that requires Blob approvals",
        ));
    }
    let mut next = original.clone();
    next["installation_id"] = json!(target_id);
    Artifact {
        http_contract: None,
        image: String::new(),
        manifest: target["manifest"].clone(),
        raw: Vec::new(),
        image_digest: target["image_digest"].as_str().unwrap().into(),
        manifest_digest: target["manifest_digest"].as_str().unwrap().into(),
    }
    .validate_deployment(&next)?;
    schema_transition::precheck(&row, body, &source, &target)?;
    let volumes = volume_group::plan(c, app, ctx, &original, &source, &target).await?;
    let transition = schema_transition::plan(
        c,
        app,
        ctx,
        &row,
        action,
        body,
        &source,
        &target,
        volumes.as_ref(),
    )
    .await?;
    if let Some(group) = &volumes {
        next["volume_ids"] = json!(group
            .items
            .iter()
            .map(|item| item.target)
            .collect::<Vec<_>>());
    }
    // Binding/geometry above uses independent transactions. Take the runtime
    // budget and deployment locks only after it completes, then recheck intent.
    c.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    let locked = c.query_one("SELECT revision,spec,installation_id,owner_id,archived_at FROM deployments WHERE id=$1 FOR UPDATE", &[&deployment]).await?;
    if locked.get::<_, i64>("revision") != original_revision
        || locked.get::<_, Value>("spec") != original
        || locked.get::<_, Uuid>("installation_id") != source_id
        || locked.get::<_, Uuid>("owner_id") != ctx.subject
        || locked
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
    {
        return Err(Error::conflict("Upgrade source changed during admission"));
    }
    crate::backups::ensure_unheld(c, deployment).await?;
    if c.query_one("SELECT count(*) FROM deployment_storage_holds", &[])
        .await?
        .get::<_, i64>(0)
        >= 2
    {
        return Err(Error::exhausted());
    }
    let backup = body
        .get("backup_id")
        .map(|_| id(body, "backup_id"))
        .transpose()?;
    if let Some(backup) = backup {
        let row=c.query_opt("SELECT created_by FROM backups WHERE id=$1 AND deployment_id=$2 AND state='ready' AND off_host FOR SHARE",&[&backup,&deployment]).await?.ok_or_else(||Error::conflict("Supplied upgrade backup is unavailable"))?;
        auth::authorize(
            c,
            ctx,
            "backup.read",
            &Resource::new("backup", backup, Some(row.get::<_, Uuid>(0))),
        )
        .await?;
    }
    let rows=c.query("SELECT id,generation FROM instances WHERE deployment_id=$1 AND phase<>'stopped' ORDER BY id LIMIT 33",&[&deployment]).await?;
    if rows.len() > 32 {
        return Err(Error::exhausted());
    }
    let instances: Vec<_> = rows
        .into_iter()
        .map(|r| json!({"id":r.get::<_,Uuid>(0),"generation":r.get::<_,i64>(1)}))
        .collect();
    let generation: i64 = c
        .query_one(
            "SELECT coalesce(max(generation),0)+1 FROM instances WHERE deployment_id=$1",
            &[&deployment],
        )
        .await?
        .get(0);
    if !(1..=9_007_199_254_740_991).contains(&generation) {
        return Err(Error::exhausted());
    }
    let authority = serde_json::to_value(
        Policy::for_context(c, ctx)
            .credential(ctx.credential, 0)
            .await?,
    )?;
    if serde_json::to_vec(&authority)?.len() > 1048576 {
        return Err(Error::exhausted());
    }
    let kind = if action == "plugin.upgrade" {
        "upgradeDeployment"
    } else {
        "rollbackDeployment"
    };
    let operation = db::operation(c, ctx.subject, kind, Some(deployment.to_string())).await?;
    let candidate = Uuid::new_v4();
    c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,$3,0,'pending','unknown',$4,now(),now())",&[&candidate,&deployment,&generation,&next["limits"]]).await?;
    c.execute("INSERT INTO deployment_upgrade_jobs(operation_id,deployment_id,action,credential_id,subject_id,peer,authority,source_installation_id,target_installation_id,source_metadata,target_metadata,original_spec,target_spec,instances,candidate_id,candidate_generation,strategy,state,backup_id,source_revision) VALUES($1,$2,$3,$4,$5,$6::text::inet,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'recreate','freezing',$17,$18)",&[&operation,&deployment,&action,&ctx.credential,&ctx.subject,&ctx.peer.to_string(),&authority,&source_id,&target_id,&source,&target,&original,&next,&json!(instances),&candidate,&generation,&backup,&revision]).await?;
    crate::dependencies::stage_upgrade(c, ctx, deployment, target_id, operation).await?;
    if let Some(group) = volumes {
        volume_group::reserve(c, ctx, deployment, operation, group).await?;
    }
    c.execute(
        "INSERT INTO deployment_storage_holds(deployment_id,operation_id) VALUES($1,$2)",
        &[&deployment, &operation],
    )
    .await?;
    if let Some(transition) = transition {
        schema_transition::reserve(c, ctx, operation, transition).await?;
    }
    c.execute("UPDATE provider_records SET availability='unavailable' WHERE instance_id IN(SELECT id FROM instances WHERE deployment_id=$1)",&[&deployment]).await?;
    c.execute(
        "UPDATE deployments SET phase='draining',revision=revision+1,updated_at=now() WHERE id=$1",
        &[&deployment],
    )
    .await?;
    Ok((db::operation_value(c, operation).await?, 202))
}
pub async fn revalidate(c: &(impl GenericClient + Sync), app: &App, row: &Row) -> Result<Context> {
    if app.leader.is_closed()
        || row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at") <= chrono::Utc::now()
    {
        return Err(Error::unavailable("Upgrade leadership or deadline is lost"));
    }
    let operation: Uuid = row.get("operation_id");
    let deployment: Uuid = row.get("deployment_id");
    let credential: Uuid = row.get("credential_id");
    let peer = row
        .get::<_, String>("approved_peer")
        .parse()
        .map_err(|_| Error::denied())?;
    let ctx = app.auth.resume(c, credential, peer, operation).await?;
    if ctx.subject != row.get::<_, Uuid>("subject_id") {
        return Err(Error::denied());
    }
    crate::dependencies::check_upgrade(c, app, &ctx, operation).await?;
    let current=c.query_opt("SELECT d.owner_id,d.spec,d.installation_id,d.revision,d.archived_at FROM deployments d JOIN deployment_storage_holds h ON h.deployment_id=d.id AND h.operation_id=$2 WHERE d.id=$1",&[&deployment,&operation]).await?.ok_or_else(||Error::conflict("Upgrade deployment hold is missing"))?;
    if current.get::<_, Uuid>("owner_id") != ctx.subject
        || current.get::<_, Uuid>("installation_id") != row.get::<_, Uuid>("source_installation_id")
        || current.get::<_, Value>("spec") != row.get::<_, Value>("original_spec")
        || current
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
    {
        return Err(Error::conflict("Upgrade source deployment changed"));
    }
    for (column, key) in [
        ("source_installation_id", "source_metadata"),
        ("target_installation_id", "target_metadata"),
    ] {
        if installation(c, row.get(column)).await? != row.get::<_, Value>(key) {
            return Err(Error::conflict("Upgrade immutable installation changed"));
        }
    }
    let saved: Vec<policy::Path> =
        serde_json::from_value(row.get("authority")).map_err(|_| Error::denied())?;
    let available = policy::rules(&Policy::new(c, peer).revalidate(&saved, credential).await?);
    volume_group::authorize_saved(c, &ctx, row, &available).await?;
    for action in [
        row.get::<_, String>("action").as_str(),
        "plugin.read",
        "plugin.enable",
    ] {
        if !auth::rules_allow(
            &available,
            action,
            &Resource::new("deployment", deployment, Some(ctx.subject)),
            peer,
        ) {
            return Err(Error::denied());
        }
    }
    let target: Value = row.get("target_metadata");
    if !auth::rules_allow(
        &available,
        "plugin.read",
        &Resource::new("plugin", target["plugin_id"].as_str().unwrap(), None),
        peer,
    ) {
        return Err(Error::denied());
    }
    if let Some(backup) = row.get::<_, Option<Uuid>>("backup_id") {
        let b=c.query_opt("SELECT created_by FROM backups WHERE id=$1 AND deployment_id=$2 AND state='ready' AND off_host",&[&backup,&deployment]).await?.ok_or_else(||Error::conflict("Upgrade backup is no longer available"))?;
        if !auth::rules_allow(
            &available,
            "backup.read",
            &Resource::new("backup", backup, Some(b.get::<_, Uuid>(0))),
            peer,
        ) {
            return Err(Error::denied());
        }
    }
    if let Some(child) = c
        .query_opt(
            "SELECT * FROM volume_schema_jobs WHERE operation_id=$1 AND kind<>'bootstrap'",
            &[&operation],
        )
        .await?
    {
        crate::schema_jobs::authorize_child(c, &ctx, &child).await?;
        schema_transition::registration(&child)?
            .revalidate(c, &ctx, &saved)
            .await?;
    }
    Ok(ctx)
}

#[cfg(test)]
#[path = "upgrades_tests.rs"]
mod tests;
