//! Durable recovery intents. API dispatch is enabled only together with the
//! owned worker; a stored hold is never released by cancellation or timeout.
use crate::{
    api::{self, App},
    auth::{self, Context, Resource},
    backup_repository::Settings,
    config::read_private,
    contracts::{digest, id},
    db,
    error::{Error, Result},
    policy::{self, Policy},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};
use tokio_postgres::GenericClient;
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct JobJournal {
    pub app: std::sync::Arc<App>,
}
#[tonic::async_trait]
impl crate::storage::backup_transfer::Journal for JobJournal {
    async fn prepared(
        &self,
        object: crate::storage::backup_transfer::Object,
        upload: &str,
        etags: &[String],
        plaintext: &crate::storage::backup_crypto::Summary,
        ciphertext: &crate::storage::backup_crypto::Summary,
        archive: &crate::storage::archive::Summary,
    ) -> Result<()> {
        let mut c = self.app.db.connect().await?;
        let tx = c.transaction().await?;
        db::auth_lock(&tx, false).await?;
        let row=tx.query_opt("SELECT j.*,host(j.peer) AS approved_peer FROM storage_recovery_jobs j JOIN backup_job_volumes v ON v.operation_id=j.operation_id WHERE j.backup_id=$1 AND j.kind='backup' AND j.state='transferring' AND v.object_id=$2 AND v.source_volume_id=$3 AND v.upload_id=$4 AND v.state='uploading' FOR UPDATE OF j,v",&[&object.backup,&object.object,&object.volume,&upload]).await?.ok_or_else(||Error::conflict("Backup upload no longer owns the job"))?;
        revalidate(&tx, &self.app, &row).await?;
        let saved = crate::storage::backup_transfer::SavedUpload {
            id: upload.to_owned(),
            etags: etags.to_vec(),
            plaintext: plaintext.clone(),
            ciphertext: ciphertext.clone(),
            archive: archive.clone(),
        };
        tx.execute("UPDATE backup_job_volumes SET state='prepared',transfer_summary=$3,part_etags=$4,updated_at=now() WHERE operation_id=$1 AND object_id=$2",&[&row.get::<_,Uuid>("operation_id"),&object.object,&serde_json::to_value(saved)?,&json!(etags)]).await?;
        if self.app.leader.is_closed() {
            return Err(Error::unavailable("Backup leadership is lost"));
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Caller owns this deployment's fence inside its uncancellable job supervisor.
/// A drain failure still stops old writers, then records failure; it never
/// becomes a successful consistent snapshot merely because SIGKILL worked.
pub(crate) async fn freeze(app: &App, operation: Uuid, fence: &db::DeploymentFence) -> Result<()> {
    let mut c = app.db.connect().await?;
    let row=c.query_one("SELECT j.*,host(j.peer) AS approved_peer FROM storage_recovery_jobs j WHERE operation_id=$1",&[&operation]).await?;
    let deployment: Uuid = row.get("deployment_id");
    if !fence.protects(deployment) {
        return Err(Error::conflict("Deployment runtime fence differs"));
    }
    if row.get::<_, String>("state") != "freezing" {
        return Ok(());
    }
    let tx = c.transaction().await?;
    let mut valid = revalidate(&tx, app, &row).await.map(|_| ());
    if tx.query_opt("SELECT deployment_id FROM deployment_storage_holds WHERE deployment_id=$1 AND operation_id=$2",&[&deployment,&operation]).await?.is_none() {return Err(Error::conflict("Backup deployment hold differs"));}
    tx.commit().await?;
    let recorded: Value = row.get("instances");
    let original = recorded
        .as_array()
        .ok_or_else(|| Error::unavailable("Invalid backup instance journal"))?;
    let mut stopped = BTreeSet::new();
    for instance in original {
        let instance_id = id(instance, "id")?;
        let generation = instance["generation"]
            .as_i64()
            .filter(|v| *v > 0)
            .ok_or_else(|| Error::unavailable("Invalid backup generation"))?;
        let drained: Result<()> = async {
            if valid.is_err() {
                return Err(Error::denied());
            }
            if !app.runtime.running(instance_id).await? {
                return Err(Error::conflict(
                    "Backup instance exited before consistent drain",
                ));
            }
            let address = app.runtime.address(instance_id)?;
            let channel =
                crate::tls::channel(&app.config, instance_id, generation, &address).await?;
            let mut client =
                crate::rpc::plugin_lifecycle_client::PluginLifecycleClient::new(channel);
            let mut request = tonic::Request::new(crate::rpc::DrainRequest {
                context: Some(crate::controller::context(None)),
                grace_ms: 30000,
            });
            request.set_timeout(std::time::Duration::from_secs(30));
            let result = client.drain(request).await?.into_inner();
            if result.accepting_requests || result.active_calls != 0 || !result.drained {
                return Err(Error::conflict(
                    "Plugin did not acknowledge a complete drain",
                ));
            }
            Ok(())
        }
        .await;
        if valid.is_ok() {
            valid = drained;
        }
        app.runtime.stop(instance_id).await?;
        stopped.insert(instance_id);
    }
    // Include durable attachments even when their instance bookkeeping no
    // longer claims it is live. Absence of a record is never a stop proof.
    let extra=c.query("SELECT id FROM instances WHERE deployment_id=$1 AND phase<>'stopped' UNION SELECT a.instance_id FROM volume_attachments a JOIN volume_holds h ON h.volume_id=a.volume_id WHERE h.operation_id=$2",&[&deployment,&operation]).await?;
    for instance in extra {
        let instance: Uuid = instance.get(0);
        if stopped.insert(instance) {
            app.runtime.stop(instance).await?;
        }
    }
    if valid.is_ok() {
        let ids:Vec<Uuid>=c.query("SELECT source_volume_id FROM backup_job_volumes WHERE operation_id=$1 ORDER BY source_volume_id",&[&operation]).await?.iter().map(|r|r.get(0)).collect();
        let sources = crate::volumes::backup_sources(app, operation, &ids).await?;
        let path = sources[0].path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
            let fd = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)?;
            if unsafe { libc::syncfs(fd.as_raw_fd()) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::unavailable("Backup sync worker stopped"))??;
    }
    let tx = c.transaction().await?;
    db::auth_lock(&tx, false).await?;
    tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    for instance in stopped {
        tx.execute("UPDATE instances SET phase='stopped',health='unknown',runtime_id=NULL,revision=revision+1,updated_at=now() WHERE id=$1",&[&instance]).await?;
        crate::volumes::release_stopped(&tx, Some(instance)).await?;
        crate::admission::release_stopped(&tx, instance).await?;
    }
    tx.execute("UPDATE deployments SET phase='disabled',conditions='[]',revision=revision+1,updated_at=now() WHERE id=$1",&[&deployment]).await?;
    if valid.is_ok() {
        valid = revalidate(&tx, app, &row).await.map(|_| ());
    }
    match valid {
        Ok(()) => {
            tx.execute("UPDATE storage_recovery_jobs SET state='stopped',metadata_point=pg_current_wal_lsn(),stopped_at=now(),updated_at=now() WHERE operation_id=$1 AND state='freezing'",&[&operation]).await?;
        }
        Err(error) => {
            tx.execute("UPDATE storage_recovery_jobs SET state='failed',failure=$2,updated_at=now() WHERE operation_id=$1",&[&operation,&error.detail()]).await?;
            tx.execute("UPDATE backups SET state='failed',revision=revision+1,updated_at=now() WHERE id=$1",&[&row.get::<_,Uuid>("backup_id")]).await?;
            db::complete(&tx, operation, Err(error)).await?;
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
        }
    }
    if app.leader.is_closed() {
        return Err(Error::unavailable("Backup leadership is lost"));
    }
    tx.commit().await?;
    Ok(())
}

pub fn handles(name: &str) -> bool {
    matches!(
        name,
        "createBackup" | "getBackup" | "listBackups" | "restoreBackup"
    )
}
pub async fn ensure_unheld(c: &(impl GenericClient + Sync), deployment: Uuid) -> Result<()> {
    if c.query_opt(
        "SELECT deployment_id FROM deployment_storage_holds WHERE deployment_id=$1",
        &[&deployment],
    )
    .await?
    .is_some()
    {
        return Err(Error::conflict(
            "Deployment is held by backup, restore, or migration",
        ));
    }
    Ok(())
}
pub fn master(config: &crate::config::Config) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(read_private(
        Path::new(config.text("security", "master_key_file")),
        32,
    )?);
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::unavailable("Backup master key is invalid"))?;
    Ok(Zeroizing::new(bytes))
}
pub async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
) -> Result<()> {
    if name == "listBackups" {
        return Ok(());
    }
    if name == "createBackup" {
        auth::authorize(
            c,
            ctx,
            "backup.create",
            &Resource::new("backup", "new", Some(ctx.subject)),
        )
        .await?;
    } else {
        let backup = if name == "restoreBackup" {
            id(body, "backup_id")?
        } else {
            api::path_id(params, "backup_id")?
        };
        let owner: Uuid = c
            .query_opt("SELECT created_by FROM backups WHERE id=$1", &[&backup])
            .await?
            .ok_or_else(Error::not_found)?
            .get(0);
        auth::authorize(
            c,
            ctx,
            if name == "getBackup" {
                "backup.read"
            } else {
                "backup.restore"
            },
            &Resource::new("backup", backup, Some(owner)),
        )
        .await
        .map_err(|e| {
            if name == "getBackup" && e.code == "PERMISSION_DENIED" {
                Error::not_found()
            } else {
                e
            }
        })?;
        if name == "getBackup" {
            return Ok(());
        }
    }
    let deployment = id(
        body,
        if name == "createBackup" {
            "deployment_id"
        } else {
            "target_deployment_id"
        },
    )?;
    let row = c
        .query_opt(
            "SELECT owner_id FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, Uuid>(0) != ctx.subject {
        return Err(Error::denied());
    }
    let resource = Resource::new("deployment", deployment, Some(ctx.subject));
    auth::authorize(c, ctx, "plugin.read", &resource).await?;
    auth::authorize(c, ctx, "plugin.enable", &resource).await?;
    if name == "restoreBackup" {
        crate::restores::authorize(c, ctx, id(body, "backup_id")?).await?;
    }
    if name == "createBackup" {
        for value in body["volume_ids"]
            .as_array()
            .ok_or_else(|| Error::invalid("Volume IDs are required"))?
        {
            let volume: Uuid = value
                .as_str()
                .ok_or_else(|| Error::invalid("Invalid volume ID"))?
                .parse()
                .map_err(|_| Error::invalid("Invalid volume ID"))?;
            let owner: Uuid = c
                .query_opt("SELECT owner_id FROM volumes WHERE id=$1", &[&volume])
                .await?
                .ok_or_else(Error::not_found)?
                .get(0);
            if owner != ctx.subject {
                return Err(Error::denied());
            }
            auth::authorize(
                c,
                ctx,
                "volume.read",
                &Resource::new("volume", volume, Some(owner)),
            )
            .await?;
        }
    }
    Ok(())
}
pub async fn execute(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
    query: &str,
) -> Result<(Value, u16)> {
    match name {
        "getBackup" => Ok((
            api::read_object(c, "backups", api::path_id(params, "backup_id")?, "Backup").await?,
            200,
        )),
        "listBackups" => Ok((
            crate::identity::list(c, &app.auth, ctx, name, params, query).await?,
            200,
        )),
        "createBackup" => create(c, app, ctx, body).await,
        "restoreBackup" => crate::restores::create(c, app, ctx, body).await,
        _ => Err(Error::not_found()),
    }
}
async fn create(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    body: &Value,
) -> Result<(Value, u16)> {
    if !app.ready.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Error::unavailable(
            "Backup waits for startup runtime fencing",
        ));
    }
    let settings = Settings::from_host(&app.config)?;
    let client = settings.client()?;
    if !client.off_host() {
        return Err(Error::unavailable(
            "Public backups require an off-host backend",
        ));
    }
    let key = master(&app.config)?;
    let key_id = digest(key.as_ref());
    let repository = settings.register(c).await?;
    c.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    if c.query_opt(
        "SELECT id FROM volume_storage_root WHERE state='ready' FOR UPDATE",
        &[],
    )
    .await?
    .is_none()
    {
        return Err(Error::unavailable("Volume namespace is not ready"));
    }
    let deployment = id(body, "deployment_id")?;
    let d=c.query_one("SELECT d.*,i.image_digest,i.manifest_digest,i.manifest,i.plugin_id,i.version FROM deployments d JOIN installations i ON i.id=d.installation_id WHERE d.id=$1 FOR UPDATE OF d",&[&deployment]).await?;
    let original: Value = d.get("spec");
    if d.get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
        .is_some()
        || original["enabled"] != true
        || d.get::<_, String>("phase") != "ready"
    {
        return Err(Error::conflict(
            "A consistent backup requires a ready enabled deployment to drain",
        ));
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
    let requested: Vec<Uuid> = body["volume_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    let ids: BTreeSet<Uuid> = requested.iter().copied().collect();
    let selected: BTreeSet<Uuid> = original["volume_ids"]
        .as_array()
        .ok_or_else(|| Error::conflict("Deployment has no volume group"))?
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    if ids.len() != requested.len() || ids != selected {
        return Err(Error::invalid(
            "Backup must contain the exact deployment volume group",
        ));
    }
    let live=c.query("SELECT id,generation,phase FROM instances WHERE deployment_id=$1 AND phase<>'stopped' ORDER BY id",&[&deployment]).await?;
    if live.is_empty()
        || live.iter().any(|i| {
            i.get::<_, String>("phase") != "ready"
                || i.get::<_, i64>("generation") != d.get::<_, i64>("observed_generation")
        })
    {
        return Err(Error::conflict(
            "Backup requires the current ready instance generation",
        ));
    }
    let instances: Vec<Value> = live
        .iter()
        .map(|i| json!({"id":i.get::<_,Uuid>("id"),"generation":i.get::<_,i64>("generation")}))
        .collect();
    let paths = Policy::for_context(c, ctx)
        .credential(ctx.credential, 0)
        .await?;
    let authority = serde_json::to_value(paths)?;
    if serde_json::to_vec(&authority)?.len() > 1048576 {
        return Err(Error::exhausted());
    }
    let backup = Uuid::new_v4();
    let operation = db::operation(c, ctx.subject, "createBackup", Some(backup.to_string())).await?;
    c.execute("INSERT INTO backups(id,deployment_id,created_by,volume_ids,off_host,state,created_at,updated_at) VALUES($1,$2,$3,$4,false,'creating',now(),now())",&[&backup,&deployment,&ctx.subject,&json!(requested)]).await?;
    let installation = json!({"id":d.get::<_,Uuid>("installation_id"),"image_digest":d.get::<_,String>("image_digest"),"manifest_digest":d.get::<_,String>("manifest_digest"),"plugin_id":d.get::<_,String>("plugin_id"),"version":d.get::<_,String>("version"),"manifest":d.get::<_,Value>("manifest")});
    c.execute("INSERT INTO storage_recovery_jobs(operation_id,kind,backup_id,deployment_id,repository_id,credential_id,subject_id,peer,authority,state,original_spec,installation_digest,installation_metadata,instances,manifest_object_id,master_key_id) VALUES($1,'backup',$2,$3,$4,$5,$6,$7::text::inet,$8,'freezing',$9,$10,$11,$12,$13,$14)",&[&operation,&backup,&deployment,&repository,&ctx.credential,&ctx.subject,&ctx.peer.to_string(),&authority,&original,&d.get::<_,String>("image_digest"),&installation,&json!(instances),&Uuid::new_v4(),&key_id]).await?;
    c.execute(
        "INSERT INTO deployment_storage_holds(deployment_id,operation_id) VALUES($1,$2)",
        &[&deployment, &operation],
    )
    .await?;
    for volume in ids {
        let row=c.query_opt("SELECT a.state,a.data_schema_version,a.schema_state,a.schema_plugin_id,a.schema_publisher_id,v.spec,v.capacity_bytes FROM volume_allocations a JOIN volumes v ON v.id=a.volume_id WHERE a.volume_id=$1 FOR UPDATE OF a,v",&[&volume]).await?.ok_or_else(Error::not_found)?;
        if row.get::<_, String>("state") != "ready"
            || row.get::<_, String>("schema_state") == "initializing"
            || (row
                .get::<_, Option<String>>("data_schema_version")
                .is_some_and(|v| v != "none")
                && row.get::<_, String>("schema_state") != "verified")
            || row.get::<_, i64>("capacity_bytes") > 63 * 1024 * 1024 * 1024
        {
            return Err(Error::conflict(
                "Backup volume allocation is not supported or ready",
            ));
        }
        let schema: Option<String> = row.get("data_schema_version");
        if let Some(schema) = schema.filter(|v| v != "none") {
            let manifest: Value = d.get("manifest");
            if manifest["data_schema_version"] != schema
                || row.get::<_, Option<String>>("schema_plugin_id").as_deref()
                    != manifest["plugin_id"].as_str()
                || row
                    .get::<_, Option<Uuid>>("schema_publisher_id")
                    .map(|id| id.to_string())
                    .as_deref()
                    != manifest["publisher_id"].as_str()
            {
                return Err(Error::conflict(
                    "Backup business schema does not match its installation",
                ));
            }
        }
        if c.query_opt("SELECT i.id FROM volume_attachments a JOIN instances i ON i.id=a.instance_id WHERE a.volume_id=$1 AND i.deployment_id<>$2 LIMIT 1",&[&volume,&deployment]).await?.is_some() {return Err(Error::conflict("Volume has an attachment outside the consistency group"));}
        c.execute("INSERT INTO volume_holds(volume_id,operation_id,kind) VALUES($1,$2,'backup') ON CONFLICT DO NOTHING",&[&volume,&operation]).await?;
        let held: Uuid = c
            .query_one(
                "SELECT operation_id FROM volume_holds WHERE volume_id=$1",
                &[&volume],
            )
            .await?
            .get(0);
        if held != operation {
            return Err(Error::conflict("Volume is already held"));
        }
        c.execute("INSERT INTO backup_job_volumes(operation_id,source_volume_id,object_id,state,volume_spec,capacity_bytes,data_schema_version) VALUES($1,$2,$3,'pending',$4,$5,$6)",&[&operation,&volume,&Uuid::new_v4(),&row.get::<_,Value>("spec"),&row.get::<_,i64>("capacity_bytes"),&row.get::<_,Option<String>>("data_schema_version")]).await?;
    }
    let mut stopped = original;
    stopped["enabled"] = json!(false);
    c.execute("UPDATE deployments SET spec=$2,phase='draining',revision=revision+1,updated_at=now() WHERE id=$1",&[&deployment,&stopped]).await?;
    c.execute("UPDATE provider_records SET availability='unavailable' WHERE instance_id IN(SELECT id FROM instances WHERE deployment_id=$1)",&[&deployment]).await?;
    db::outbox(
        c,
        "backup.requested",
        backup,
        &json!({"operation_id":operation,"deployment_id":deployment}),
    )
    .await?;
    Ok((db::operation_value(c, operation).await?, 202))
}

pub async fn revalidate(
    c: &(impl GenericClient + Sync),
    app: &App,
    row: &tokio_postgres::Row,
) -> Result<Context> {
    if row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at") <= chrono::Utc::now() {
        return Err(Error::conflict("Backup recovery intent expired"));
    }
    let credential: Uuid = row.get("credential_id");
    let peer: std::net::IpAddr = row
        .get::<_, String>("approved_peer")
        .parse()
        .map_err(|_| Error::denied())?;
    let ctx = app
        .auth
        .resume(c, credential, peer, row.get("operation_id"))
        .await?;
    if ctx.subject != row.get::<_, Uuid>("subject_id") {
        return Err(Error::denied());
    }
    let operation: Uuid = row.get("operation_id");
    let deployment_id: Uuid = row.get("deployment_id");
    let current=c.query_opt("SELECT d.owner_id,d.spec,d.archived_at,i.id,i.image_digest,i.manifest_digest,i.state,p.status FROM deployments d JOIN installations i ON i.id=d.installation_id JOIN publishers p ON p.id=i.publisher_id JOIN deployment_storage_holds h ON h.deployment_id=d.id AND h.operation_id=$2 WHERE d.id=$1",&[&deployment_id,&operation]).await?.ok_or_else(||Error::conflict("Recovery deployment hold is missing"))?;
    let installation: Value = row.get("installation_metadata");
    if current.get::<_, Uuid>("owner_id") != ctx.subject
        || current
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
        || current.get::<_, Uuid>("id").to_string() != installation["id"].as_str().unwrap_or("")
        || current.get::<_, String>("image_digest")
            != installation["image_digest"].as_str().unwrap_or("")
        || current.get::<_, String>("manifest_digest")
            != installation["manifest_digest"].as_str().unwrap_or("")
        || current.get::<_, String>("state") != "installed"
        || current.get::<_, String>("status") != "trusted"
        || current.get::<_, Value>("spec")["volume_ids"]
            != row.get::<_, Value>("original_spec")["volume_ids"]
    {
        return Err(Error::conflict("Recovery deployment identity changed"));
    }
    let saved: Vec<policy::Path> =
        serde_json::from_value(row.get("authority")).map_err(|_| Error::denied())?;
    let available = policy::rules(&Policy::new(c, peer).revalidate(&saved, credential).await?);
    let backup: Uuid = row.get("backup_id");
    let backup_owner: Uuid = c
        .query_one("SELECT created_by FROM backups WHERE id=$1", &[&backup])
        .await?
        .get(0);
    let resource = if row.get::<_, String>("kind") == "backup" {
        Resource::new("backup", "new", Some(ctx.subject))
    } else {
        Resource::new("backup", backup, Some(backup_owner))
    };
    let action = if row.get::<_, String>("kind") == "backup" {
        "backup.create"
    } else {
        "backup.restore"
    };
    if !auth::rules_allow(&available, action, &resource, peer) {
        return Err(Error::denied());
    }
    let deployment = Resource::new(
        "deployment",
        row.get::<_, Uuid>("deployment_id"),
        Some(ctx.subject),
    );
    for action in ["plugin.enable", "plugin.read"] {
        if !auth::rules_allow(&available, action, &deployment, peer) {
            return Err(Error::denied());
        }
    }
    for volume in c.query("SELECT j.source_volume_id,v.owner_id,h.operation_id AS held_by FROM backup_job_volumes j JOIN volumes v ON v.id=j.source_volume_id LEFT JOIN volume_holds h ON h.volume_id=j.source_volume_id WHERE j.operation_id=$1",&[&operation]).await? {
        if row.get::<_,String>("kind")=="backup" && volume.get::<_,Option<Uuid>>("held_by")!=Some(operation) {return Err(Error::conflict("Recovery volume hold is missing"));}
        if !auth::rules_allow(&available,"volume.read",&Resource::new("volume",volume.get::<_,Uuid>(0),Some(volume.get::<_,Uuid>(1))),peer) {return Err(Error::denied());}
    }
    if row.get::<_, String>("kind") == "restore" {
        if !auth::rules_allow(
            &available,
            "volume.create",
            &Resource::new("volume", "new", Some(ctx.subject)),
            peer,
        ) {
            return Err(Error::denied());
        }
        let spec: Value = row.get("original_spec");
        for value in spec["volume_ids"]
            .as_array()
            .ok_or_else(|| Error::conflict("Restore target volume group is invalid"))?
        {
            let volume: Uuid = value
                .as_str()
                .ok_or_else(|| Error::conflict("Invalid target volume"))?
                .parse()
                .map_err(|_| Error::conflict("Invalid target volume"))?;
            let old=c.query_opt("SELECT v.owner_id,h.operation_id FROM volumes v JOIN volume_holds h ON h.volume_id=v.id WHERE v.id=$1",&[&volume]).await?.ok_or_else(||Error::conflict("Restore target hold is missing"))?;
            if old.get::<_, Uuid>("operation_id") != operation
                || old.get::<_, Uuid>("owner_id") != ctx.subject
                || !auth::rules_allow(
                    &available,
                    "volume.read",
                    &Resource::new("volume", volume, Some(ctx.subject)),
                    peer,
                )
            {
                return Err(Error::denied());
            }
        }
        let valid: bool = c
            .query_one(
                "SELECT state='ready' AND off_host FROM backups WHERE id=$1",
                &[&backup],
            )
            .await?
            .get(0);
        if !valid {
            return Err(Error::conflict("Restore source is no longer ready"));
        }
    }
    Ok(ctx)
}

#[cfg(test)]
#[path = "backups_tests.rs"]
pub(crate) mod tests;

pub(crate) async fn job(app: &App, operation: Uuid) -> Result<tokio_postgres::Row> {
    app.db.connect().await?.query_one("SELECT j.*,host(j.peer) AS approved_peer,j.metadata_point::text AS metadata_reference FROM storage_recovery_jobs j WHERE operation_id=$1",&[&operation]).await.map_err(Into::into)
}

/// The daemon owns the supervisor, not an HTTP request. A dropped receiver does
/// not cancel a job or release its deployment fence while file workers run.
pub async fn run(app: std::sync::Arc<App>) {
    use std::{sync::atomic::Ordering, time::Duration};
    let active_limit = if app.config.compact() { 1 } else { 2 };
    let poll = Duration::from_millis(if app.config.compact() { 1000 } else { 250 });
    let pool =
        crate::storage::backup_transfer::Pool::with_journal(std::sync::Arc::new(JobJournal {
            app: app.clone(),
        }));
    let mut queue = crate::maintenance::Queue::default();
    let mut active: HashMap<Uuid, tokio::sync::oneshot::Receiver<()>> = HashMap::new();
    let mut cleanup: Option<tokio::sync::oneshot::Receiver<()>> = None;
    let mut cleaned = tokio::time::Instant::now() - Duration::from_secs(30);
    loop {
        if app.shutdown.load(Ordering::SeqCst) || app.leader.is_closed() {
            break;
        }
        active.retain(|_, receiver| {
            matches!(
                receiver.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            )
        });
        if app.ready.load(Ordering::SeqCst) {
            if let Ok(c) = app.db.connect().await {
                if let Ok(rows) = queue
                    .candidates(&c, crate::maintenance::Kind::Backup, app.config.compact())
                    .await
                {
                    for row in rows {
                        let operation: Uuid = row.get(0);
                        if active.len() >= active_limit || active.contains_key(&operation) {
                            continue;
                        }
                        let Some(maintenance) = crate::maintenance::try_start(
                            app.config.compact(),
                            crate::maintenance::Kind::Backup,
                        ) else {
                            continue;
                        };
                        queue.attempted(operation);
                        let deployment: Uuid = row.get(1);
                        let (sender, receiver) = tokio::sync::oneshot::channel();
                        active.insert(operation, receiver);
                        let owner = app.clone();
                        let pool = pool.clone();
                        tokio::spawn(async move {
                            let _maintenance = maintenance;
                            if let Ok(Some(fence)) =
                                db::deployment_fence(&owner.db, deployment).await
                            {
                                if let Err(error) = process(&owner, operation, &fence, &pool).await
                                {
                                    if fail_stopped(&owner, operation, &fence, error)
                                        .await
                                        .is_err()
                                    {
                                        tracing::error!(reason_code = "BACKUP_CLEANUP_PENDING");
                                    }
                                }
                            }
                            let _ = sender.send(());
                        });
                    }
                }
            }
            if cleanup.as_mut().is_some_and(|r| {
                !matches!(
                    r.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                )
            }) {
                cleanup = None;
            }
            if cleanup.is_none() && cleaned.elapsed() >= Duration::from_secs(30) {
                if let Some(maintenance) = crate::maintenance::try_start(
                    app.config.compact(),
                    crate::maintenance::Kind::Cleanup,
                ) {
                    cleaned = tokio::time::Instant::now();
                    let owner = app.clone();
                    let (sender, receiver) = tokio::sync::oneshot::channel();
                    cleanup = Some(receiver);
                    tokio::spawn(async move {
                        let _maintenance = maintenance;
                        // Inventory and abort are replay safe; pending flags remain
                        // set to catch a late response from a lost initiate request.
                        let _ =
                            tokio::time::timeout(Duration::from_secs(60), cleanup_uploads(&owner))
                                .await;
                        let _ = sender.send(());
                    });
                }
            }
        }
        tokio::time::sleep(poll).await;
    }
}

async fn process(
    app: &App,
    operation: Uuid,
    fence: &db::DeploymentFence,
    pool: &crate::storage::backup_transfer::Pool,
) -> Result<()> {
    use crate::storage::backup_transfer::{Object, SavedUpload};
    use std::time::Duration;
    let row = job(app, operation).await?;
    if row.get::<_, String>("kind") == "restore" {
        return crate::restores::process(app, operation, fence, pool).await;
    }
    if row.get::<_, String>("state") == "freezing" {
        freeze(app, operation, fence).await?;
    }
    let row = job(app, operation).await?;
    if matches!(
        row.get::<_, String>("state").as_str(),
        "failed" | "succeeded"
    ) {
        return Ok(());
    }
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    revalidate(&tx, app, &row).await?;
    tx.execute("UPDATE operations SET state='running',revision=revision+1,updated_at=now() WHERE id=$1 AND state='pending'",&[&operation]).await?;
    tx.commit().await?;
    let master = master(&app.config)?;
    if digest(master.as_ref()) != row.get::<_, String>("master_key_id") {
        return Err(Error::unavailable("Backup master key reference differs"));
    }
    let repo = Settings::from_host(&app.config)?
        .bind(&app.db, row.get("repository_id"))
        .await?;
    if !repo.objects.off_host() {
        return Err(Error::unavailable(
            "Backup storage has no off-host evidence",
        ));
    }
    let backup: Uuid = row.get("backup_id");
    let volume_rows = c
        .query(
            "SELECT * FROM backup_job_volumes WHERE operation_id=$1 ORDER BY source_volume_id",
            &[&operation],
        )
        .await?;
    let ids: Vec<Uuid> = volume_rows
        .iter()
        .map(|r| r.get("source_volume_id"))
        .collect();
    let sources = crate::volumes::backup_sources(app, operation, &ids).await?;
    if row.get::<_, String>("state") != "committing" {
        let tx = c.transaction().await?;
        revalidate(&tx, app, &row).await?;
        tx.execute("UPDATE storage_recovery_jobs SET state='transferring',updated_at=now() WHERE operation_id=$1",&[&operation]).await?;
        tx.commit().await?;
    }
    for (source, volume) in sources.iter().zip(&volume_rows) {
        if row.get::<_, String>("state") == "committing"
            && volume.get::<_, String>("state") != "verified"
        {
            return Err(Error::conflict(
                "Committing backup has an unverified object",
            ));
        }
        if source.spec != volume.get::<_, Value>("volume_spec")
            || source.capacity_bytes != volume.get::<_, i64>("capacity_bytes") as u64
            || source.data_schema_version != volume.get::<_, Option<String>>("data_schema_version")
        {
            return Err(Error::conflict("Backup source metadata changed"));
        }
        let object = Object {
            backup,
            object: volume.get("object_id"),
            volume: source.id,
            maximum_data: source.capacity_bytes,
            maximum_archive: (source.capacity_bytes
                + source.capacity_bytes / 128
                + 65 * 1024 * 1024)
                .min(64 * 1024 * 1024 * 1024),
        };
        let end = (row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at") - chrono::Utc::now())
            .to_std()
            .map_err(|_| Error::conflict("Backup deadline expired"))?
            .min(Duration::from_secs(3600));
        let transfer = match volume.get::<_, String>("state").as_str() {
            "prepared" | "verified" => {
                let saved: SavedUpload = serde_json::from_value(
                    volume
                        .get::<_, Option<Value>>("transfer_summary")
                        .ok_or_else(|| Error::unavailable("Backup preparation is missing"))?,
                )?;
                pool.recover(
                    repo.objects.clone(),
                    object,
                    Zeroizing::new(*master),
                    saved,
                    end,
                )?
                .wait()
                .await?
            }
            "pending" | "uploading" => {
                if repo.objects.get_optional(&object.key()).await?.is_some() {
                    return Err(Error::conflict("Unjournaled backup object is quarantined"));
                }
                if let Some(upload) = volume.get::<_, Option<String>>("upload_id") {
                    repo.objects.abort(&object.key(), &upload).await?;
                }
                // Bound total reconciliation work. Another pass after an
                // ambiguous initiate can remove more of this exact key.
                let (pending, more) = repo.objects.pending_uploads(&object.key()).await?;
                for upload in pending {
                    repo.objects.abort(&object.key(), &upload).await?;
                }
                if more {
                    return Err(Error::unavailable("Backup multipart cleanup is pending"));
                }
                let upload = repo.objects.initiate(&object.key()).await?;
                let tx = c.transaction().await?;
                revalidate(&tx, app, &job(app, operation).await?).await?;
                tx.execute("UPDATE backup_job_volumes SET upload_id=$3,state='uploading',updated_at=now() WHERE operation_id=$1 AND source_volume_id=$2",&[&operation,&source.id,&upload]).await?;
                tx.commit().await?;
                pool.upload(
                    repo.objects.clone(),
                    source.path.clone(),
                    object,
                    Zeroizing::new(*master),
                    upload,
                    end,
                )?
                .wait()
                .await?
            }
            _ => return Err(Error::conflict("Backup object state is invalid")),
        };
        if !transfer.off_host {
            return Err(Error::unavailable("Backup readback is not off-host"));
        }
        let tx = c.transaction().await?;
        revalidate(&tx, app, &job(app, operation).await?).await?;
        tx.execute("UPDATE backup_job_volumes SET state='verified',cleanup_pending=false,updated_at=now() WHERE operation_id=$1 AND source_volume_id=$2 AND state IN ('prepared','verified')",&[&operation,&source.id]).await?;
        tx.commit().await?;
    }
    let mut objects = Vec::new();
    for volume in c
        .query(
            "SELECT * FROM backup_job_volumes WHERE operation_id=$1 ORDER BY source_volume_id",
            &[&operation],
        )
        .await?
    {
        if volume.get::<_, String>("state") != "verified" {
            return Err(Error::conflict("Backup object verification is incomplete"));
        }
        objects.push(json!({"source_volume_id":volume.get::<_,Uuid>("source_volume_id"),"object_id":volume.get::<_,Uuid>("object_id"),"volume_spec":volume.get::<_,Value>("volume_spec"),"capacity_bytes":volume.get::<_,i64>("capacity_bytes"),"data_schema_version":volume.get::<_,Option<String>>("data_schema_version"),"transfer":volume.get::<_,Value>("transfer_summary")}));
    }
    let manifest = json!({"format":1,"backup_id":backup,"deployment_id":row.get::<_,Uuid>("deployment_id"),"deployment_spec":row.get::<_,Value>("original_spec"),"installation":row.get::<_,Value>("installation_metadata"),"volumes":objects,"metadata_recovery_point":{"kind":"deployment_snapshot","wal_lsn":row.get::<_,Option<String>>("metadata_reference")},"created_by":row.get::<_,Uuid>("subject_id"),"created_at":row.get::<_,chrono::DateTime<chrono::Utc>>("created_at"),"stopped_at":row.get::<_,Option<chrono::DateTime<chrono::Utc>>>("stopped_at"),"master_key_reference":row.get::<_,String>("master_key_id")});
    let manifest = if let Some(previous) = row.get::<_, Option<Value>>("manifest") {
        if previous != manifest {
            return Err(Error::conflict("Persisted backup manifest differs"));
        }
        previous
    } else {
        manifest
    };
    let tx = c.transaction().await?;
    revalidate(&tx, app, &row).await?;
    tx.execute("UPDATE storage_recovery_jobs SET state='committing',manifest=$2,updated_at=now() WHERE operation_id=$1",&[&operation,&manifest]).await?;
    if app.leader.is_closed() {
        return Err(Error::unavailable("Backup leadership is lost"));
    }
    tx.commit().await?;
    let manifest_object: Uuid = row.get("manifest_object_id");
    let hash = repo
        .write_manifest(backup, manifest_object, &master, &manifest)
        .await?;
    let tx = c.transaction().await?;
    let ctx = revalidate(&tx, app, &row).await?;
    tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    let deployment: Uuid = row.get("deployment_id");
    tx.query_one(
        "SELECT id FROM deployments WHERE id=$1 FOR UPDATE",
        &[&deployment],
    )
    .await?;
    let reference = repo
        .objects
        .reference(&format!("{backup}/{manifest_object}.sealed"))?;
    tx.execute("UPDATE backups SET state='ready',off_host=true,manifest_digest=$2,object_reference=$3,revision=revision+1,updated_at=now() WHERE id=$1 AND state='creating'",&[&backup,&hash,&reference]).await?;
    tx.batch_execute("SAVEPOINT backup_resume").await?;
    let resumed = match resume(&tx, app, &ctx, &row).await {
        Ok(value) => value,
        Err(_) => {
            tx.batch_execute("ROLLBACK TO SAVEPOINT backup_resume")
                .await?;
            false
        }
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
    db::complete(
        &tx,
        operation,
        Ok(json!({"backup_id":backup,"deployment_enable_scheduled":resumed})),
    )
    .await?;
    db::outbox(
        &tx,
        "backup.ready",
        backup,
        &json!({"deployment_id":deployment,"manifest_digest":hash}),
    )
    .await?;
    db::audit(
        &tx,
        ctx.subject,
        Some(ctx.credential),
        operation,
        "backup.create",
        &Resource::new("backup", backup, Some(ctx.subject)).json(),
        "succeeded",
        "BACKUP_VERIFIED",
    )
    .await?;
    if app.leader.is_closed() {
        return Err(Error::unavailable("Backup leadership is lost"));
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn resume(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    row: &tokio_postgres::Row,
) -> Result<bool> {
    let spec: Value = row.get("original_spec");
    if spec["enabled"] != true {
        return Ok(false);
    }
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
    crate::volumes::approve_mounts(c, ctx, deployment, generation, &spec, manifest).await?;
    c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,$3,0,'pending','unknown',$4,now(),now())",&[&Uuid::new_v4(),&deployment,&generation,&spec["limits"]]).await?;
    c.execute("UPDATE deployments SET spec=$2,phase='reconciling',revision=revision+1,updated_at=now() WHERE id=$1",&[&deployment,&spec]).await?;
    Ok(true)
}

async fn fail_stopped(
    app: &App,
    operation: Uuid,
    fence: &db::DeploymentFence,
    error: Error,
) -> Result<()> {
    let row = job(app, operation).await?;
    let deployment: Uuid = row.get("deployment_id");
    if !fence.protects(deployment) {
        return Err(Error::conflict("Cleanup runtime fence differs"));
    }
    let mut c = app.db.connect().await?;
    // Locking the intent row waits for an ambiguous final COMMIT to settle.
    // Inspect it before stopping anything: success may have already resumed.
    let tx = c.transaction().await?;
    let state: String = tx
        .query_one(
            "SELECT state FROM storage_recovery_jobs WHERE operation_id=$1 FOR UPDATE",
            &[&operation],
        )
        .await?
        .get(0);
    if state == "succeeded" {
        return Ok(());
    }
    if tx.query_opt("SELECT deployment_id FROM deployment_storage_holds WHERE deployment_id=$1 AND operation_id=$2",&[&deployment,&operation]).await?.is_none() {return Err(Error::conflict("Cleanup no longer owns the deployment"));}
    tx.commit().await?;
    let original: Vec<Uuid> = row
        .get::<_, Value>("instances")
        .as_array()
        .ok_or_else(|| Error::unavailable("Invalid cleanup journal"))?
        .iter()
        .map(|v| id(v, "id"))
        .collect::<Result<_>>()?;
    let rows=c.query("SELECT id FROM instances WHERE deployment_id=$1 AND (phase<>'stopped' OR id=ANY($3)) UNION SELECT a.instance_id FROM volume_attachments a JOIN volume_holds h ON h.volume_id=a.volume_id WHERE h.operation_id=$2 LIMIT 513",&[&deployment,&operation,&original]).await?;
    if rows.len() > 512 {
        return Err(Error::exhausted());
    }
    for instance in &rows {
        app.runtime.stop(instance.get(0)).await?;
    }
    let tx = c.transaction().await?;
    db::auth_lock(&tx, false).await?;
    tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    tx.query_one(
        "SELECT id FROM deployments WHERE id=$1 FOR UPDATE",
        &[&deployment],
    )
    .await?;
    // An ambiguous final COMMIT may already have succeeded and resumed the
    // deployment. Never turn a terminal success into failure or release another
    // operation's holds; inspect the durable result before any failure mutation.
    let current: String = tx
        .query_one(
            "SELECT state FROM storage_recovery_jobs WHERE operation_id=$1 FOR UPDATE",
            &[&operation],
        )
        .await?
        .get(0);
    if current == "succeeded" {
        return Ok(());
    }
    for instance in rows {
        let instance: Uuid = instance.get(0);
        tx.execute("UPDATE instances SET phase='stopped',health='unknown',runtime_id=NULL,revision=revision+1,updated_at=now() WHERE id=$1",&[&instance]).await?;
        crate::volumes::release_stopped(&tx, Some(instance)).await?;
        crate::admission::release_stopped(&tx, instance).await?;
    }
    let mut spec: Value = tx
        .query_one("SELECT spec FROM deployments WHERE id=$1", &[&deployment])
        .await?
        .get(0);
    spec["enabled"] = json!(false);
    tx.execute("UPDATE deployments SET spec=$2,phase='disabled',revision=revision+1,updated_at=now() WHERE id=$1",&[&deployment,&spec]).await?;
    tx.execute("UPDATE backups SET state='failed',revision=revision+1,updated_at=now() WHERE id=$1 AND state='creating'",&[&row.get::<_,Uuid>("backup_id")]).await?;
    tx.execute("UPDATE storage_recovery_jobs SET state='failed',failure=coalesce(failure,$2),updated_at=now() WHERE operation_id=$1",&[&operation,&error.detail()]).await?;
    tx.execute("UPDATE volume_allocations a SET state='quarantined',updated_at=now() WHERE a.operation_id=$1 AND a.state IN ('restoring','restored') AND NOT EXISTS(SELECT 1 FROM volumes v WHERE v.id=a.volume_id)",&[&operation]).await?;
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
    db::complete(&tx, operation, Err(error)).await?;
    tx.commit().await?;
    Ok(())
}

async fn cleanup_uploads(app: &App) -> Result<()> {
    let c = app.db.connect().await?;
    let rows=c.query("SELECT v.*,j.backup_id,j.repository_id FROM backup_job_volumes v JOIN storage_recovery_jobs j ON j.operation_id=v.operation_id WHERE j.state='failed' AND v.cleanup_pending ORDER BY v.updated_at,v.operation_id,v.source_volume_id LIMIT 4",&[]).await?;
    if rows.is_empty() {
        return Ok(());
    }
    let settings = Settings::from_host(&app.config)?;
    for row in rows {
        let repo = settings.bind(&app.db, row.get("repository_id")).await?;
        let key = format!(
            "{}/{}.sealed",
            row.get::<_, Uuid>("backup_id"),
            row.get::<_, Uuid>("object_id")
        );
        if let Some(upload) = row.get::<_, Option<String>>("upload_id") {
            repo.objects.abort(&key, &upload).await?;
        }
        let (ids, _) = repo.objects.pending_uploads(&key).await?;
        for id in ids {
            repo.objects.abort(&key, &id).await?;
        }
        // Keep the flag: an initiation response lost during process death can
        // materialize after this inventory. A later bounded sweep catches it.
        c.execute("UPDATE backup_job_volumes SET updated_at=now() WHERE operation_id=$1 AND source_volume_id=$2",&[&row.get::<_,Uuid>("operation_id"),&row.get::<_,Uuid>("source_volume_id")]).await?;
    }
    Ok(())
}
