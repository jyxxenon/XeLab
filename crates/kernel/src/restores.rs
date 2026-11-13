//! Restore verified data into newly budgeted UUID/project identities. Original
//! volumes remain intact; only the final metadata transaction switches routing.
use crate::{
    api::App,
    auth::{self, Context, Resource},
    backup_repository::Settings,
    backups,
    contracts::{digest, id, validate},
    db,
    error::{Error, Result},
    policy::Policy,
    volumes,
};
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::atomic::Ordering, time::Duration};
use tokio_postgres::GenericClient;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    backup: Uuid,
) -> Result<()> {
    auth::authorize(
        c,
        ctx,
        "volume.create",
        &Resource::new("volume", "new", Some(ctx.subject)),
    )
    .await?;
    let row = c
        .query_opt("SELECT volume_ids FROM backups WHERE id=$1", &[&backup])
        .await?
        .ok_or_else(Error::not_found)?;
    for value in row
        .get::<_, Value>(0)
        .as_array()
        .ok_or_else(|| Error::unavailable("Invalid source volume group"))?
    {
        let volume: Uuid = value
            .as_str()
            .ok_or_else(|| Error::unavailable("Invalid source volume"))?
            .parse()
            .map_err(|_| Error::unavailable("Invalid source volume"))?;
        let owner: Uuid = c
            .query_one("SELECT owner_id FROM volumes WHERE id=$1", &[&volume])
            .await?
            .get(0);
        auth::authorize(
            c,
            ctx,
            "volume.read",
            &Resource::new("volume", volume, Some(owner)),
        )
        .await?;
    }
    Ok(())
}
pub(crate) async fn create(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    body: &Value,
) -> Result<(Value, u16)> {
    if body["allow_downtime"] != true {
        return Err(Error::invalid(
            "Restore requires explicit allow_downtime=true",
        ));
    }
    if !app.ready.load(Ordering::SeqCst) {
        return Err(Error::unavailable(
            "Restore waits for startup runtime fencing",
        ));
    }
    let backup = id(body, "backup_id")?;
    let deployment = id(body, "target_deployment_id")?;
    let source=c.query_opt("SELECT b.*,j.repository_id,j.master_key_id,j.manifest_object_id,j.installation_metadata,j.manifest,j.operation_id AS source_operation FROM backups b JOIN storage_recovery_jobs j ON j.backup_id=b.id AND j.kind='backup' AND j.state='succeeded' WHERE b.id=$1 AND b.state='ready' AND b.off_host FOR SHARE OF b,j",&[&backup]).await?.ok_or_else(||Error::conflict("Restore requires a verified off-host backup"))?;
    let source_manifest: Value = source
        .get::<_, Option<Value>>("manifest")
        .ok_or_else(|| Error::unavailable("Backup manifest metadata is missing"))?;
    if source
        .get::<_, Option<String>>("manifest_digest")
        .as_deref()
        != Some(digest(&serde_json::to_vec(&source_manifest)?).as_str())
    {
        return Err(Error::unavailable("Backup manifest registration differs"));
    }
    let settings = Settings::from_host(&app.config)?;
    if !settings.client()?.off_host() {
        return Err(Error::unavailable("Restore requires an off-host backend"));
    }
    let key = backups::master(&app.config)?;
    if digest(key.as_ref()) != source.get::<_, String>("master_key_id") {
        return Err(Error::unavailable("Restore master key reference differs"));
    }
    let target=c.query_one("SELECT d.*,i.image_digest,i.manifest_digest,i.manifest,i.state AS installation_state,p.status AS publisher_status FROM deployments d JOIN installations i ON i.id=d.installation_id JOIN publishers p ON p.id=i.publisher_id WHERE d.id=$1",&[&deployment]).await?;
    let original: Value = target.get("spec");
    let installation: Value = source.get("installation_metadata");
    if target.get::<_, Uuid>("owner_id") != ctx.subject
        || target
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
        || target.get::<_, String>("installation_state") != "installed"
        || target.get::<_, String>("publisher_status") != "trusted"
        || target.get::<_, String>("image_digest")
            != installation["image_digest"].as_str().unwrap_or("")
        || target.get::<_, String>("manifest_digest")
            != installation["manifest_digest"].as_str().unwrap_or("")
    {
        return Err(Error::conflict(
            "Restore requires the exact trusted installation digests",
        ));
    }
    // Schema-changing restore belongs to the explicit migration protocol.
    if installation["manifest"]["data_schema_version"] != "none" {
        return Err(Error::conflict(
            "Schema migration is required before this restore",
        ));
    }
    let source_volumes=c.query("SELECT * FROM backup_job_volumes WHERE operation_id=$1 AND state='verified' ORDER BY source_volume_id",&[&source.get::<_,Uuid>("source_operation")]).await?;
    if source_volumes.is_empty()
        || source_volumes.len() > 16
        || source_volumes.len()
            != source
                .get::<_, Value>("volume_ids")
                .as_array()
                .map_or(0, Vec::len)
    {
        return Err(Error::unavailable("Backup volume manifest is incomplete"));
    }
    let mut plan = Vec::new();
    let mut mappings = Vec::new();
    for volume in &source_volumes {
        let fresh = Uuid::new_v4();
        let spec: Value = volume.get("volume_spec");
        validate("VolumeSpec", &spec)?;
        if spec["capacity_bytes"].as_i64() != Some(volume.get("capacity_bytes"))
            || volume.get::<_, i64>("capacity_bytes") > 63 * 1024 * 1024 * 1024
            || volume
                .get::<_, Option<String>>("data_schema_version")
                .is_some()
        {
            return Err(Error::conflict("Backup data schema or capacity differs"));
        }
        plan.push((fresh, spec, None));
        mappings.push(fresh);
    }
    let plan = volumes::plan_restore(app, plan).await?;
    c.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    c.query_one(
        "SELECT id FROM volume_storage_root WHERE state='ready' FOR UPDATE",
        &[],
    )
    .await?;
    let current = c
        .query_one(
            "SELECT spec,revision,installation_id FROM deployments WHERE id=$1 FOR UPDATE",
            &[&deployment],
        )
        .await?;
    if current.get::<_, Value>("spec") != original
        || current.get::<_, Uuid>("installation_id") != target.get::<_, Uuid>("installation_id")
        || current.get::<_, i64>("revision") != target.get::<_, i64>("revision")
    {
        return Err(Error::conflict("Restore target changed during admission"));
    }
    if c.query_one("SELECT count(*) FROM deployment_storage_holds", &[])
        .await?
        .get::<_, i64>(0)
        >= 2
        || c.query_opt(
            "SELECT deployment_id FROM deployment_storage_holds WHERE deployment_id=$1",
            &[&deployment],
        )
        .await?
        .is_some()
    {
        return Err(Error::conflict(
            "Recovery capacity or deployment is occupied",
        ));
    }
    let previous: Vec<Uuid> = original["volume_ids"]
        .as_array()
        .ok_or_else(|| Error::conflict("Invalid target volume group"))?
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap()
                .parse()
                .map_err(|_| Error::conflict("Invalid target volume"))
        })
        .collect::<Result<_>>()?;
    let unique: BTreeSet<_> = previous.iter().copied().collect();
    if unique.len() != previous.len() || previous.len() != mappings.len() {
        return Err(Error::conflict(
            "Restore volume aliases must match the target group",
        ));
    }
    for volume in unique {
        let row=c.query_one("SELECT v.owner_id,v.spec,a.state FROM volumes v JOIN volume_allocations a ON a.volume_id=v.id WHERE v.id=$1 FOR UPDATE OF a,v",&[&volume]).await?;
        if row.get::<_, Uuid>("owner_id") != ctx.subject || row.get::<_, String>("state") != "ready"
        {
            return Err(Error::conflict("Target volume is not owned and ready"));
        }
        auth::authorize(
            c,
            ctx,
            "volume.read",
            &Resource::new("volume", volume, Some(ctx.subject)),
        )
        .await?;
        if c.query_opt("SELECT a.instance_id FROM volume_attachments a JOIN instances i ON i.id=a.instance_id WHERE a.volume_id=$1 AND i.deployment_id<>$2 LIMIT 1",&[&volume,&deployment]).await?.is_some() {return Err(Error::conflict("Target has attachments outside the restore group"));}
    }
    let operation = db::operation(
        c,
        ctx.subject,
        "restoreBackup",
        Some(deployment.to_string()),
    )
    .await?;
    let paths = Policy::for_context(c, ctx)
        .credential(ctx.credential, 0)
        .await?;
    let authority = serde_json::to_value(paths)?;
    if serde_json::to_vec(&authority)?.len() > 1048576 {
        return Err(Error::exhausted());
    }
    let instances:Vec<Value>=c.query("SELECT id,generation FROM instances WHERE deployment_id=$1 AND phase<>'stopped' ORDER BY id",&[&deployment]).await?.into_iter().map(|r|json!({"id":r.get::<_,Uuid>(0),"generation":r.get::<_,i64>(1)})).collect();
    if instances.len() > 32 {
        return Err(Error::exhausted());
    }
    let metadata = json!({"id":target.get::<_,Uuid>("installation_id"),"image_digest":target.get::<_,String>("image_digest"),"manifest_digest":target.get::<_,String>("manifest_digest"),"manifest":target.get::<_,Value>("manifest")});
    c.execute("INSERT INTO storage_recovery_jobs(operation_id,kind,backup_id,deployment_id,repository_id,credential_id,subject_id,peer,authority,state,original_spec,installation_digest,installation_metadata,instances,manifest_object_id,master_key_id,manifest) VALUES($1,'restore',$2,$3,$4,$5,$6,$7::text::inet,$8,'freezing',$9,$10,$11,$12,$13,$14,$15)",&[&operation,&backup,&deployment,&source.get::<_,Uuid>("repository_id"),&ctx.credential,&ctx.subject,&ctx.peer.to_string(),&authority,&original,&target.get::<_,String>("image_digest"),&metadata,&json!(instances),&source.get::<_,Uuid>("manifest_object_id"),&source.get::<_,String>("master_key_id"),&source_manifest]).await?;
    volumes::reserve_restore(c, ctx, operation, plan).await?;
    for (source, fresh) in source_volumes.iter().zip(&mappings) {
        c.execute("INSERT INTO backup_job_volumes(operation_id,source_volume_id,object_id,state,volume_spec,capacity_bytes,data_schema_version,transfer_summary,part_etags,restored_volume_id,cleanup_pending) VALUES($1,$2,$3,'pending',$4,$5,$6,$7,$8,$9,false)",&[&operation,&source.get::<_,Uuid>("source_volume_id"),&source.get::<_,Uuid>("object_id"),&source.get::<_,Value>("volume_spec"),&source.get::<_,i64>("capacity_bytes"),&source.get::<_,Option<String>>("data_schema_version"),&source.get::<_,Option<Value>>("transfer_summary"),&source.get::<_,Option<Value>>("part_etags"),fresh]).await?;
    }
    c.execute(
        "INSERT INTO deployment_storage_holds(deployment_id,operation_id) VALUES($1,$2)",
        &[&deployment, &operation],
    )
    .await?;
    for volume in previous {
        c.execute("INSERT INTO volume_holds(volume_id,operation_id,kind) VALUES($1,$2,'restore') ON CONFLICT DO NOTHING",&[&volume,&operation]).await?;
        if c.query_one(
            "SELECT operation_id FROM volume_holds WHERE volume_id=$1",
            &[&volume],
        )
        .await?
        .get::<_, Uuid>(0)
            != operation
        {
            return Err(Error::conflict("Target volume is occupied"));
        }
    }
    let mut stopped = original;
    stopped["enabled"] = json!(false);
    c.execute("UPDATE deployments SET spec=$2,phase='draining',revision=revision+1,updated_at=now() WHERE id=$1",&[&deployment,&stopped]).await?;
    c.execute("UPDATE provider_records SET availability='unavailable' WHERE instance_id IN(SELECT id FROM instances WHERE deployment_id=$1)",&[&deployment]).await?;
    db::outbox(
        c,
        "restore.requested",
        deployment,
        &json!({"operation_id":operation,"backup_id":backup}),
    )
    .await?;
    Ok((db::operation_value(c, operation).await?, 202))
}

pub(crate) async fn process(
    app: &App,
    operation: Uuid,
    fence: &db::DeploymentFence,
    pool: &crate::storage::backup_transfer::Pool,
) -> Result<()> {
    use crate::storage::backup_transfer::{Object, SavedUpload, Verified};
    let row = backups::job(app, operation).await?;
    let deployment: Uuid = row.get("deployment_id");
    if !fence.protects(deployment) {
        return Err(Error::conflict("Restore runtime fence differs"));
    }
    if row.get::<_, String>("state") == "succeeded" {
        return Ok(());
    }
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    backups::revalidate(&tx, app, &row).await?;
    tx.execute("UPDATE operations SET state='running',revision=revision+1,updated_at=now() WHERE id=$1 AND state='pending'",&[&operation]).await?;
    tx.commit().await?;
    let master = backups::master(&app.config)?;
    if digest(master.as_ref()) != row.get::<_, String>("master_key_id") {
        return Err(Error::unavailable("Restore master key reference differs"));
    }
    let repo = Settings::from_host(&app.config)?
        .bind(&app.db, row.get("repository_id"))
        .await?;
    if !repo.objects.off_host() {
        return Err(Error::unavailable(
            "Restore requires an off-host repository",
        ));
    }
    let backup: Uuid = row.get("backup_id");
    let source = c
        .query_one(
            "SELECT manifest_digest FROM backups WHERE id=$1 AND state='ready' AND off_host",
            &[&backup],
        )
        .await?;
    let expected_digest: String = source
        .get::<_, Option<String>>(0)
        .ok_or_else(|| Error::unavailable("Backup digest is unavailable"))?;
    let manifest = repo
        .read_manifest(
            backup,
            row.get("manifest_object_id"),
            &master,
            &expected_digest,
        )
        .await?;
    if manifest
        != row
            .get::<_, Option<Value>>("manifest")
            .ok_or_else(|| Error::unavailable("Restore manifest is missing"))?
        || manifest["format"] != 1
        || manifest["backup_id"] != backup.to_string()
        || manifest["installation"]["image_digest"]
            != row.get::<_, Value>("installation_metadata")["image_digest"]
        || manifest["installation"]["manifest_digest"]
            != row.get::<_, Value>("installation_metadata")["manifest_digest"]
    {
        return Err(Error::unavailable("Authenticated restore manifest differs"));
    }
    if row.get::<_, String>("state") == "freezing" {
        stop_target(app, operation, fence).await?;
    }
    let row = backups::job(app, operation).await?;
    let tx = c.transaction().await?;
    backups::revalidate(&tx, app, &row).await?;
    tx.execute("UPDATE storage_recovery_jobs SET state='transferring',updated_at=now() WHERE operation_id=$1 AND state='stopped'",&[&operation]).await?;
    tx.commit().await?;
    // FOR UPDATE waits for a pre-crash verification COMMIT before deciding
    // whether a private tree is complete or an interrupted partial extraction.
    let records=c.query("SELECT * FROM backup_job_volumes WHERE operation_id=$1 ORDER BY source_volume_id FOR UPDATE",&[&operation]).await?;
    let entries = manifest["volumes"]
        .as_array()
        .ok_or_else(|| Error::unavailable("Invalid restore volume manifest"))?;
    if records.len() != entries.len() || records.is_empty() || records.len() > 16 {
        return Err(Error::unavailable("Restore volume count differs"));
    }
    let mut fresh = Vec::new();
    for record in records {
        let source: Uuid = record.get("source_volume_id");
        let object_id: Uuid = record.get("object_id");
        let entry = entries
            .iter()
            .find(|v| v["source_volume_id"] == source.to_string())
            .ok_or_else(|| Error::unavailable("Restore object is absent from manifest"))?;
        if entry["object_id"] != object_id.to_string()
            || entry["volume_spec"] != record.get::<_, Value>("volume_spec")
            || entry["capacity_bytes"] != record.get::<_, i64>("capacity_bytes")
            || entry["data_schema_version"]
                != json!(record.get::<_, Option<String>>("data_schema_version"))
            || entry["transfer"]
                != record
                    .get::<_, Option<Value>>("transfer_summary")
                    .ok_or_else(|| Error::unavailable("Restore preparation is missing"))?
        {
            return Err(Error::unavailable(
                "Restore record differs from authenticated manifest",
            ));
        }
        let restored: Uuid = record
            .get::<_, Option<Uuid>>("restored_volume_id")
            .ok_or_else(|| Error::unavailable("Restore allocation mapping is absent"))?;
        let saved: SavedUpload = serde_json::from_value(entry["transfer"].clone())?;
        let expected = Verified {
            plaintext: saved.plaintext,
            ciphertext: saved.ciphertext,
            archive: saved.archive,
            off_host: true,
        };
        let capacity = record.get::<_, i64>("capacity_bytes") as u64;
        let object = Object {
            backup,
            object: object_id,
            volume: source,
            maximum_data: capacity,
            maximum_archive: (capacity + capacity / 128 + 65 * 1024 * 1024)
                .min(64 * 1024 * 1024 * 1024),
        };
        let end = (row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at") - chrono::Utc::now())
            .to_std()
            .map_err(|_| Error::conflict("Restore deadline expired"))?
            .min(Duration::from_secs(3600));
        let state: String = record.get("state");
        let verified = match state.as_str() {
            "pending" => {
                let tx = c.transaction().await?;
                backups::revalidate(&tx, app, &row).await?;
                tx.execute("UPDATE backup_job_volumes SET state='restoring',updated_at=now() WHERE operation_id=$1 AND source_volume_id=$2",&[&operation,&source]).await?;
                tx.commit().await?;
                let target = volumes::private_restore_path(app, operation, restored, true).await?;
                pool.restore(
                    repo.objects.clone(),
                    target.path,
                    object,
                    Zeroizing::new(*master),
                    expected,
                    end,
                )?
                .wait()
                .await?
            }
            "restored" => {
                let target = volumes::private_restore_path(app, operation, restored, false).await?;
                pool.verify_restored(
                    repo.objects.clone(),
                    target.path,
                    object,
                    Zeroizing::new(*master),
                    expected,
                    end,
                )?
                .wait()
                .await?
            }
            "restoring" => {
                return Err(Error::conflict(
                    "Interrupted private restore requires a new recovery operation",
                ))
            }
            _ => return Err(Error::conflict("Restore object state is invalid")),
        };
        if !verified.off_host {
            return Err(Error::unavailable(
                "Restore source verification is not off-host",
            ));
        }
        let tx = c.transaction().await?;
        backups::revalidate(&tx, app, &row).await?;
        let changed=tx.execute("UPDATE volume_allocations SET state='restored',updated_at=now() WHERE volume_id=$1 AND operation_id=$2 AND state IN ('restoring','restored') AND NOT EXISTS(SELECT 1 FROM volumes WHERE id=$1)",&[&restored,&operation]).await?;
        if changed != 1 {
            return Err(Error::conflict("Private restore allocation changed"));
        }
        tx.execute("UPDATE backup_job_volumes SET state='restored',updated_at=now() WHERE operation_id=$1 AND source_volume_id=$2",&[&operation,&source]).await?;
        if app.leader.is_closed() {
            return Err(Error::unavailable("Restore leadership is lost"));
        }
        tx.commit().await?;
        fresh.push(restored);
    }
    let publication = volumes::prepare_restore_publication(app, operation, &fresh).await?;
    let tx = c.transaction().await?;
    let ctx = backups::revalidate(&tx, app, &row).await?;
    tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    tx.query_one(
        "SELECT id FROM volume_storage_root WHERE state='ready' FOR UPDATE",
        &[],
    )
    .await?;
    tx.query_one(
        "SELECT id FROM deployments WHERE id=$1 FOR UPDATE",
        &[&deployment],
    )
    .await?;
    volumes::publish_restored(&tx, publication).await?;
    let mut updated: Value = row.get("original_spec");
    let previous = updated["volume_ids"].clone();
    updated["volume_ids"] = json!(fresh);
    updated["enabled"] = json!(false);
    tx.execute("UPDATE deployments SET spec=$2,phase='disabled',revision=revision+1,updated_at=now() WHERE id=$1",&[&deployment,&updated]).await?;
    tx.batch_execute("SAVEPOINT restore_enable").await?;
    let enable_scheduled = if row.get::<_, Value>("original_spec")["enabled"] == true {
        match enable_restored(&tx, app, &ctx, &row, &fresh).await {
            Ok(()) => true,
            Err(_) => {
                tx.batch_execute("ROLLBACK TO SAVEPOINT restore_enable")
                    .await?;
                false
            }
        }
    } else {
        false
    };
    tx.execute(
        "DELETE FROM volume_holds WHERE operation_id=$1",
        &[&operation],
    )
    .await?;
    tx.execute(
        "DELETE FROM deployment_storage_holds WHERE operation_id=$1",
        &[&operation],
    )
    .await?;
    tx.execute(
        "UPDATE storage_recovery_jobs SET state='succeeded',updated_at=now() WHERE operation_id=$1",
        &[&operation],
    )
    .await?;
    db::complete(&tx,operation,Ok(json!({"restore_id":operation,"backup_id":backup,"target_deployment_id":deployment,"volume_ids":fresh,"previous_volume_ids":previous,"deployment_enable_scheduled":enable_scheduled}))).await?;
    db::audit(
        &tx,
        ctx.subject,
        Some(ctx.credential),
        operation,
        "backup.restore",
        &Resource::new("backup", backup, None).json(),
        "succeeded",
        "RESTORE_VERIFIED_SWITCH",
    )
    .await?;
    db::outbox(
        &tx,
        "restore.succeeded",
        deployment,
        &json!({"operation_id":operation,"volume_ids":fresh}),
    )
    .await?;
    if app.leader.is_closed() {
        return Err(Error::unavailable("Restore leadership is lost"));
    }
    tx.commit().await?;
    Ok(())
}

async fn stop_target(app: &App, operation: Uuid, fence: &db::DeploymentFence) -> Result<()> {
    let row = backups::job(app, operation).await?;
    let deployment: Uuid = row.get("deployment_id");
    if !fence.protects(deployment) {
        return Err(Error::conflict("Restore stop fence differs"));
    }
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    backups::revalidate(&tx, app, &row).await?;
    tx.commit().await?;
    let records=c.query("SELECT id,generation FROM instances WHERE deployment_id=$1 AND phase<>'stopped' UNION SELECT i.id,i.generation FROM instances i JOIN volume_attachments a ON a.instance_id=i.id JOIN volume_holds h ON h.volume_id=a.volume_id WHERE h.operation_id=$2 LIMIT 513",&[&deployment,&operation]).await?;
    if records.len() > 512 {
        return Err(Error::exhausted());
    }
    for instance in &records {
        let id: Uuid = instance.get(0);
        // Drain is attempted for the old target; only the already verified
        // backup supplies the restored consistency point. Stop must be proven.
        if app.runtime.running(id).await? {
            if let Ok(address) = app.runtime.address(id) {
                if let Ok(channel) =
                    crate::tls::channel(&app.config, id, instance.get(1), &address).await
                {
                    let mut client =
                        crate::rpc::plugin_lifecycle_client::PluginLifecycleClient::new(channel);
                    let mut request = tonic::Request::new(crate::rpc::DrainRequest {
                        context: Some(crate::controller::context(None)),
                        grace_ms: 30000,
                    });
                    request.set_timeout(Duration::from_secs(30));
                    let _ = client.drain(request).await;
                }
            }
        }
        app.runtime.stop(id).await?;
    }
    let tx = c.transaction().await?;
    backups::revalidate(&tx, app, &row).await?;
    tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    for instance in records {
        let id: Uuid = instance.get(0);
        tx.execute("UPDATE instances SET phase='stopped',health='unknown',runtime_id=NULL,revision=revision+1,updated_at=now() WHERE id=$1",&[&id]).await?;
        volumes::release_stopped(&tx, Some(id)).await?;
        crate::admission::release_stopped(&tx, id).await?;
    }
    tx.execute(
        "UPDATE deployments SET phase='disabled',revision=revision+1,updated_at=now() WHERE id=$1",
        &[&deployment],
    )
    .await?;
    tx.execute("UPDATE storage_recovery_jobs SET state='stopped',stopped_at=now(),updated_at=now() WHERE operation_id=$1 AND state='freezing'",&[&operation]).await?;
    if app.leader.is_closed() {
        return Err(Error::unavailable("Restore leadership is lost"));
    }
    tx.commit().await?;
    Ok(())
}

async fn enable_restored(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    row: &tokio_postgres::Row,
    fresh: &[Uuid],
) -> Result<()> {
    let deployment: Uuid = row.get("deployment_id");
    let manifest = &row.get::<_, Value>("installation_metadata")["manifest"];
    crate::host_blobs::check_approval(c, app, deployment, manifest).await?;
    let generation: i64 = c
        .query_one(
            "SELECT revision+1 FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await?
        .get(0);
    let mut spec: Value = row.get("original_spec");
    spec["volume_ids"] = json!(fresh);
    spec["enabled"] = json!(true);
    volumes::approve_mounts(c, ctx, deployment, generation, &spec, manifest).await?;
    c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,$3,0,'pending','unknown',$4,now(),now())",&[&Uuid::new_v4(),&deployment,&generation,&spec["limits"]]).await?;
    c.execute("UPDATE deployments SET spec=$2,phase='reconciling',revision=revision+1,updated_at=now() WHERE id=$1",&[&deployment,&spec]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn explicit_downtime_and_ready_backup_are_required_before_any_admission() {
        use axum::{
            body::{to_bytes, Body},
            extract::ConnectInfo,
            http::Request,
        };
        use tower::ServiceExt;
        let Some(f) = crate::backups::tests::Fixture::new().await else {
            return;
        };
        let c = f.app.db.connect().await.unwrap();
        let target: Uuid = c
            .query_one(
                "SELECT deployment_id FROM backups WHERE id=$1",
                &[&f.backup],
            )
            .await
            .unwrap()
            .get(0);
        for (allowed, expected) in [(false, 400), (true, 409)] {
            let body = json!({"backup_id":f.backup,"target_deployment_id":target,"allow_downtime":allowed});
            let mut request = Request::builder()
                .header(
                    "host",
                    crate::plugin_http_gateway::core_authority(&f.app.config).unwrap(),
                )
                .method("POST")
                .uri("/api/platform/v1/restores")
                .header("authorization", format!("Bearer {}", f.token))
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            request.extensions_mut().insert(ConnectInfo(
                "127.0.0.1:30000".parse::<std::net::SocketAddr>().unwrap(),
            ));
            let response = crate::api::router(f.app.clone())
                .oneshot(request)
                .await
                .unwrap();
            let status = response.status().as_u16();
            let detail = to_bytes(response.into_body(), 1048576).await.unwrap();
            assert_eq!(status, expected, "{}", String::from_utf8_lossy(&detail));
        }
        assert_eq!(
            c.query_one("SELECT count(*) FROM volume_allocations", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        assert_eq!(
            c.query_one("SELECT count(*) FROM storage_recovery_jobs", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
    }
}
