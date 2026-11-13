//! Durable bootstrap and parent-owned format transitions. Public versioned
//! artifact admission remains closed pending complete runtime acceptance.
use crate::{
    api::App,
    auth::{self, Context, Resource},
    contracts::id,
    error::{Error, Result},
    policy::{self, Policy},
    upgrades, volumes,
};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use tokio_postgres::{GenericClient, Row};
use uuid::Uuid;

#[path = "schema_jobs_worker.rs"]
mod worker;
pub use worker::run;
pub(crate) use worker::{commit_upgrade, run_upgrade, UpgradeReady};

pub(crate) struct Admission {
    original: Value,
    installation: Value,
    items: Value,
    scratch: Uuid,
    reservation: volumes::RestorePlan,
}

/// No budget/deployment row lock may precede this independent geometry step.
pub(crate) async fn preflight(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    deployment: Uuid,
) -> Result<Option<Admission>> {
    let row = c.query_opt("SELECT d.spec,d.owner_id,d.installation_id,i.manifest FROM deployments d JOIN installations i ON i.id=d.installation_id WHERE d.id=$1", &[&deployment]).await?.ok_or_else(Error::not_found)?;
    let original: Value = row.get("spec");
    let manifest: Value = row.get("manifest");
    if original["enabled"] == true || manifest["data_schema_version"] == "none" {
        return Ok(None);
    }
    if row.get::<_, Uuid>("owner_id") != ctx.subject {
        return Err(Error::denied());
    }
    if !app.ready.load(Ordering::SeqCst) || app.leader.is_closed() {
        return Err(Error::unavailable(
            "Schema bootstrap waits for startup runtime fencing",
        ));
    }
    // Reuses the trusted immutable internal execution profile. This does not
    // open public Artifact::inspect admission for versioned manifests.
    let installation = upgrades::installation(c, row.get("installation_id")).await?;
    volumes::validate_selection(c, ctx, &original, &manifest).await?;
    let selected = original["volume_ids"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 16)
        .ok_or_else(|| {
            Error::invalid("A versioned deployment needs its complete business volume group")
        })?;
    if manifest["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["access"] != "rw" || v["scope"] != "deployment")
    {
        return Err(Error::invalid(
            "This schema profile requires exclusive writable deployment volumes",
        ));
    }
    let mut items = Vec::new();
    let mut all_verified = true;
    for value in selected {
        let volume: Uuid = value
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::invalid("Invalid schema volume"))?;
        let row = c.query_one("SELECT a.*,v.spec AS public_spec,v.owner_id AS public_owner,r.filesystem_uuid FROM volume_allocations a JOIN volumes v ON v.id=a.volume_id JOIN volume_storage_root r ON r.id=a.root_id WHERE a.volume_id=$1", &[&volume]).await?;
        if row.get::<_, Uuid>("owner_id") != ctx.subject
            || row.get::<_, Uuid>("public_owner") != ctx.subject
            || row.get::<_, Value>("spec") != row.get::<_, Value>("public_spec")
            || row.get::<_, String>("state") != "ready"
        {
            return Err(Error::conflict("Schema source allocation changed"));
        }
        let state: String = row.get("schema_state");
        if state == "initializing"
            && (row.get::<_, Option<Uuid>>("schema_deployment_id") != Some(deployment)
                || row
                    .get::<_, Option<String>>("schema_manifest_digest")
                    .as_deref()
                    != installation["manifest_digest"].as_str())
        {
            return Err(Error::conflict(
                "Incomplete initialization belongs to another immutable deployment intent",
            ));
        }
        all_verified &= state == "verified";
        items.push(json!({"id":volume,"spec":row.get::<_,Value>("spec"),"root":row.get::<_,Uuid>("root_id"),"filesystem":row.get::<_,Uuid>("filesystem_uuid"),"project":row.get::<_,i32>("project_id"),"schema_state":state,"schema":row.get::<_,Option<String>>("data_schema_version")}));
    }
    if all_verified {
        return Ok(None);
    }
    for action in ["plugin.read", "plugin.enable"] {
        auth::authorize(
            c,
            ctx,
            action,
            &Resource::new("deployment", deployment, Some(ctx.subject)),
        )
        .await?;
    }
    auth::authorize(
        c,
        ctx,
        "plugin.read",
        &Resource::new("plugin", installation["plugin_id"].as_str().unwrap(), None),
    )
    .await?;
    auth::authorize(
        c,
        ctx,
        "volume.create",
        &Resource::new("volume", "new", Some(ctx.subject)),
    )
    .await?;
    let scratch = Uuid::new_v4();
    auth::authorize(
        c,
        ctx,
        "volume.read",
        &Resource::new("volume", scratch, Some(ctx.subject)),
    )
    .await?;
    let reservation = volumes::plan_restore(app, vec![(scratch, json!({"name":"kernel-schema-scratch","capacity_bytes":67108864,"access":"single_writer","scope":"deployment"}), None)]).await?;
    Ok(Some(Admission {
        original,
        installation,
        items: json!(items),
        scratch,
        reservation,
    }))
}

#[allow(clippy::too_many_arguments)] // Mirrors the enclosing enable transaction and admitted identities.
pub(crate) async fn reserve(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    deployment: Uuid,
    operation: Uuid,
    instance: Uuid,
    generation: i64,
    admission: Admission,
) -> Result<()> {
    let current = c
        .query_one(
            "SELECT spec,installation_id,owner_id FROM deployments WHERE id=$1 FOR UPDATE",
            &[&deployment],
        )
        .await?;
    if !(1..=9_007_199_254_740_991).contains(&generation)
        || current.get::<_, Value>("spec") != admission.original
        || current.get::<_, Uuid>("owner_id") != ctx.subject
        || current.get::<_, Uuid>("installation_id") != id(&admission.installation, "id")?
    {
        return Err(Error::conflict("Schema bootstrap source intent changed"));
    }
    crate::backups::ensure_unheld(c, deployment).await?;
    if c.query_one("SELECT count(*) FROM deployment_storage_holds", &[])
        .await?
        .get::<_, i64>(0)
        >= 2
    {
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
    volumes::reserve_restore(c, ctx, operation, admission.reservation).await?;
    for item in admission.items.as_array().unwrap() {
        let volume = id(item, "id")?;
        let row = c.query_one("SELECT a.*,v.owner_id AS public_owner,v.spec AS public_spec FROM volume_allocations a JOIN volumes v ON v.id=a.volume_id WHERE a.volume_id=$1 FOR UPDATE OF a,v", &[&volume]).await?;
        if row.get::<_, Uuid>("owner_id") != ctx.subject
            || row.get::<_, Uuid>("public_owner") != ctx.subject
            || row.get::<_, Value>("spec") != item["spec"]
            || row.get::<_, Value>("public_spec") != item["spec"]
            || row.get::<_, Uuid>("root_id") != id(item, "root")?
            || row.get::<_, i32>("project_id") as i64 != item["project"].as_i64().unwrap()
            || row.get::<_, String>("state") != "ready"
            || json!(row.get::<_, Option<String>>("data_schema_version")) != item["schema"]
            || json!(row.get::<_, String>("schema_state")) != item["schema_state"]
        {
            return Err(Error::conflict(
                "Schema bootstrap volume changed during admission",
            ));
        }
        if c.query_opt("SELECT a.instance_id FROM volume_attachments a JOIN instances i ON i.id=a.instance_id WHERE a.volume_id=$1 AND i.deployment_id<>$2 LIMIT 1", &[&volume,&deployment]).await?.is_some() { return Err(Error::conflict("Schema bootstrap volume has an external attachment")); }
        c.execute("INSERT INTO volume_holds(volume_id,operation_id,kind) VALUES($1,$2,'migration') ON CONFLICT DO NOTHING", &[&volume,&operation]).await?;
        if c.query_one(
            "SELECT operation_id FROM volume_holds WHERE volume_id=$1",
            &[&volume],
        )
        .await?
        .get::<_, Uuid>(0)
            != operation
        {
            return Err(Error::conflict("Schema bootstrap volume is held"));
        }
    }
    let mut next = admission.original;
    next["enabled"] = json!(true);
    c.execute("INSERT INTO volume_schema_jobs(operation_id,kind,deployment_id,instance_id,generation,installation_id,credential_id,subject_id,peer,authority,deployment_spec,installation_metadata,source_schema,target_schema,scratch_volume_id,volume_ids,volume_plan,state) VALUES($1,'bootstrap',$2,$3,$4,$5,$6,$7,$8::text::inet,$9,$10,$11,'none',$12,$13,$14,$15,'planning')", &[&operation,&deployment,&instance,&generation,&id(&admission.installation,"id")?,&ctx.credential,&ctx.subject,&ctx.peer.to_string(),&authority,&next,&admission.installation,&admission.installation["manifest"]["data_schema_version"].as_str().unwrap(),&admission.scratch,&next["volume_ids"],&admission.items]).await?;
    c.execute(
        "INSERT INTO deployment_storage_holds(deployment_id,operation_id) VALUES($1,$2)",
        &[&deployment, &operation],
    )
    .await?;
    Ok(())
}

/// Called under the API's authorization transaction for the exact cached enable
/// Operation. There is no latest-job lookup after a source selection changes.
pub(crate) async fn authorize_replay(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    operation: Uuid,
) -> Result<()> {
    let Some(row) = c
        .query_opt(
            "SELECT * FROM volume_schema_jobs WHERE operation_id=$1",
            &[&operation],
        )
        .await?
    else {
        return Ok(());
    };
    authorize_saved(c, ctx, &row).await
}

async fn authorize_saved(c: &(impl GenericClient + Sync), ctx: &Context, row: &Row) -> Result<()> {
    if row.get::<_, Uuid>("credential_id") != ctx.credential
        || row.get::<_, Uuid>("subject_id") != ctx.subject
    {
        return Err(Error::denied());
    }
    let deployment: Uuid = row.get("deployment_id");
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
    let saved: Vec<policy::Path> =
        serde_json::from_value(row.get("authority")).map_err(|_| Error::denied())?;
    let rules = policy::rules(
        &Policy::for_context(c, ctx)
            .revalidate(&saved, ctx.credential)
            .await?,
    );
    let kind: String = row.get("kind");
    let action = match kind.as_str() {
        "bootstrap" => "plugin.enable",
        "upgrade" => "plugin.upgrade",
        "rollback" => "plugin.rollback",
        _ => return Err(Error::conflict("Invalid schema job action")),
    };
    for action in ["plugin.read", "plugin.enable", action] {
        if !auth::rules_allow(
            &rules,
            action,
            &Resource::new("deployment", deployment, Some(owner)),
            ctx.peer,
        ) {
            return Err(Error::denied());
        }
    }
    let metadata: Value = row.get("installation_metadata");
    let plugin = metadata["plugin_id"]
        .as_str()
        .ok_or_else(|| Error::conflict("Missing bootstrap plugin binding"))?;
    if !auth::rules_allow(
        &rules,
        "plugin.read",
        &Resource::new("plugin", plugin, None),
        ctx.peer,
    ) || !auth::rules_allow(
        &rules,
        "volume.create",
        &Resource::new("volume", "new", Some(owner)),
        ctx.peer,
    ) {
        return Err(Error::denied());
    }
    let selected: Value = row.get("volume_ids");
    let selected = selected
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 16)
        .ok_or_else(|| Error::conflict("Incomplete schema volume group"))?;
    let mut ids = std::collections::BTreeSet::new();
    for value in selected {
        let volume = value
            .as_str()
            .and_then(|v| v.parse::<Uuid>().ok())
            .filter(|id| !id.is_nil() && ids.insert(*id))
            .ok_or_else(|| Error::conflict("Invalid schema volume identity"))?;
        let current = c.query_opt("SELECT a.owner_id,v.owner_id AS public_owner FROM volume_allocations a LEFT JOIN volumes v ON v.id=a.volume_id WHERE a.volume_id=$1", &[&volume]).await?.ok_or_else(Error::not_found)?;
        if current.get::<_, Uuid>("owner_id") != owner
            || current
                .get::<_, Option<Uuid>>("public_owner")
                .is_some_and(|public| public != owner)
            || (kind == "bootstrap"
                && current.get::<_, Option<Uuid>>("public_owner") != Some(owner))
            || !auth::rules_allow(
                &rules,
                "volume.read",
                &Resource::new("volume", volume, Some(owner)),
                ctx.peer,
            )
        {
            return Err(Error::denied());
        }
    }
    let scratch: Uuid = row.get("scratch_volume_id");
    let scratch_owner: Uuid = c
        .query_one(
            "SELECT owner_id FROM volume_allocations WHERE volume_id=$1",
            &[&scratch],
        )
        .await?
        .get(0);
    if ids.contains(&scratch)
        || scratch_owner != owner
        || !auth::rules_allow(
            &rules,
            "volume.read",
            &Resource::new("volume", scratch, Some(owner)),
            ctx.peer,
        )
    {
        return Err(Error::denied());
    }
    if let Some(backup) = row.get::<_, Option<Uuid>>("backup_id") {
        let creator: Uuid = c
            .query_one("SELECT created_by FROM backups WHERE id=$1", &[&backup])
            .await?
            .get(0);
        if !auth::rules_allow(
            &rules,
            "backup.read",
            &Resource::new("backup", backup, Some(creator)),
            ctx.peer,
        ) {
            return Err(Error::denied());
        }
    }
    if kind != "bootstrap" {
        upgrades::schema_registration(row)?
            .authorize_replay(c, ctx, &saved)
            .await?;
    }
    Ok(())
}

pub(crate) async fn authorize_child(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    row: &Row,
) -> Result<()> {
    authorize_saved(c, ctx, row).await
}

/// Execution/publication caller must also own the deployment runtime fence.
/// New grants or a new login cannot replace any saved authority path.
pub(crate) async fn revalidate(
    c: &(impl GenericClient + Sync),
    app: &App,
    row: &Row,
) -> Result<Context> {
    if row.get::<_, String>("kind") != "bootstrap" {
        return upgrades::revalidate_schema_child(c, app, row).await;
    }
    if app.leader.is_closed()
        || row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at") <= chrono::Utc::now()
    {
        return Err(Error::unavailable(
            "Schema bootstrap leadership or deadline is lost",
        ));
    }
    let operation: Uuid = row.get("operation_id");
    let peer = row
        .get::<_, String>("approved_peer")
        .parse()
        .map_err(|_| Error::denied())?;
    let ctx = app
        .auth
        .resume(c, row.get("credential_id"), peer, operation)
        .await?;
    authorize_saved(c, &ctx, row).await?;
    let deployment: Uuid = row.get("deployment_id");
    let metadata: Value = row.get("installation_metadata");
    let current = c.query_opt("SELECT d.spec,d.installation_id,d.archived_at FROM deployments d JOIN deployment_storage_holds h ON h.deployment_id=d.id AND h.operation_id=$2 WHERE d.id=$1", &[&deployment,&operation]).await?.ok_or_else(|| Error::conflict("Schema bootstrap deployment hold is missing"))?;
    if current.get::<_, Value>("spec") != row.get::<_, Value>("deployment_spec")
        || current.get::<_, Uuid>("installation_id") != row.get::<_, Uuid>("installation_id")
        || current
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
        || upgrades::installation(c, row.get("installation_id")).await? != metadata
    {
        return Err(Error::conflict(
            "Schema bootstrap immutable deployment changed",
        ));
    }
    if metadata["manifest"]["requested_rules"]
        .as_array()
        .is_some_and(|rules| !rules.is_empty())
    {
        crate::host_blobs::check_approval(c, app, deployment, &metadata["manifest"]).await?;
    }
    let instance: Uuid = row.get("instance_id");
    let current = c
        .query_one(
            "SELECT deployment_id,generation,limits,phase FROM instances WHERE id=$1",
            &[&instance],
        )
        .await?;
    if current.get::<_, Uuid>("deployment_id") != deployment
        || current.get::<_, i64>("generation") != row.get::<_, i64>("generation")
        || current.get::<_, Value>("limits") != row.get::<_, Value>("deployment_spec")["limits"]
        || current.get::<_, String>("phase") == "stopped"
    {
        return Err(Error::conflict("Schema bootstrap instance intent changed"));
    }
    let items: Value = row.get("volume_plan");
    if items.as_array().map_or(0, Vec::len)
        != row
            .get::<_, Value>("volume_ids")
            .as_array()
            .map_or(0, Vec::len)
    {
        return Err(Error::conflict("Schema bootstrap physical plan differs"));
    }
    for item in items
        .as_array()
        .ok_or_else(|| Error::conflict("Invalid bootstrap physical plan"))?
    {
        let volume = id(item, "id")?;
        let current = c.query_one("SELECT a.root_id,a.project_id,a.spec,a.state,v.spec AS public_spec,h.operation_id,r.filesystem_uuid FROM volume_allocations a JOIN volumes v ON v.id=a.volume_id JOIN volume_holds h ON h.volume_id=v.id JOIN volume_storage_root r ON r.id=a.root_id AND r.state='ready' WHERE a.volume_id=$1", &[&volume]).await?;
        if current.get::<_, Uuid>("operation_id") != operation
            || current.get::<_, Uuid>("root_id") != id(item, "root")?
            || current.get::<_, Uuid>("filesystem_uuid") != id(item, "filesystem")?
            || current.get::<_, i32>("project_id") as i64
                != item["project"]
                    .as_i64()
                    .ok_or_else(|| Error::conflict("Invalid bootstrap project"))?
            || current.get::<_, Value>("spec") != item["spec"]
            || current.get::<_, Value>("public_spec") != item["spec"]
            || current.get::<_, String>("state") != "ready"
        {
            return Err(Error::conflict("Schema bootstrap source volume changed"));
        }
    }
    let current = c
        .query_one(
            "SELECT operation_id,state FROM volume_allocations WHERE volume_id=$1",
            &[&row.get::<_, Uuid>("scratch_volume_id")],
        )
        .await?;
    if current.get::<_, Uuid>("operation_id") != operation
        || current.get::<_, String>("state") != "restoring"
    {
        return Err(Error::conflict(
            "Schema bootstrap scratch allocation changed",
        ));
    }
    Ok(ctx)
}
