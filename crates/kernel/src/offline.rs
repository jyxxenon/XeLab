//! Host-admin maintenance under the same process-lifetime lease as xelabd.
//! A frozen source cannot outlive its session, and no source is returned after
//! a failed Drain/stop. This layer does not publish an off-host backup.
use crate::{
    admission, artifact,
    config::{read_private, require_host_admin, Config},
    contracts::{digest, strict_json},
    db::{self, Db},
    error::{Error, Result},
    runtime::Runtime,
    storage::metadata_snapshot,
    tls, volumes,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
use tokio::{io::AsyncWrite, sync::Mutex};
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;
use zeroize::Zeroize;

const MAX_INSTANCES: usize = 512;
const MAX_VOLUMES: i64 = 16;

#[path = "offline_workspace.rs"]
pub mod workspace;

#[path = "offline_backup.rs"]
pub mod backup;

#[path = "offline_formats.rs"]
mod formats;
#[path = "offline_restore.rs"]
pub mod restore;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationImage {
    pub installation: Uuid,
    pub image: String,
    pub image_digest: String,
    pub manifest_digest: String,
}
#[derive(Clone, Debug)]
struct Instance {
    id: Uuid,
    generation: i64,
    requires_drain: bool,
}
pub struct Session {
    runtime: Runtime,
    db: Db,
    leader: Client,
    root: File,
    mutation: Mutex<()>,
}
pub struct FrozenSource<'a> {
    session: &'a Session,
    _exclusive: tokio::sync::MutexGuard<'a, ()>,
    images: Vec<InstallationImage>,
    observed_lsn: String,
}
impl Session {
    pub async fn open(config: Config, allow_downtime: bool) -> Result<Self> {
        require_host_admin()?;
        if !allow_downtime {
            return Err(Error::invalid(
                "Offline maintenance requires explicit downtime",
            ));
        }
        let runtime = Runtime::new(config.clone());
        // Retained until OS process exit, including Tokio blocking-worker joins.
        runtime.retain_daemon_host_lease()?;
        let (dsn, mut key) = config.secrets()?;
        key.zeroize();
        let db = Db::new(dsn)?;
        db.check().await?;
        let leader = db.leader().await?;
        let root = protected_directory(&config.root())?;
        Ok(Self {
            runtime,
            db,
            leader,
            root,
            mutation: Mutex::new(()),
        })
    }
    fn check_leader(&self) -> Result<()> {
        if self.leader.is_closed() {
            return Err(Error::unavailable("Offline database lease was lost"));
        }
        Ok(())
    }
    /// Source preflight precedes any stop or metadata mutation. On failure after
    /// drain begins, stopped writers stay stopped and no frozen proof is issued.
    pub async fn freeze_source(&self) -> Result<FrozenSource<'_>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(3600),
            self.freeze_source_inner(),
        )
        .await
        .map_err(|_| Error::unavailable("Offline source freeze exceeded its deadline"))?
    }
    async fn freeze_source_inner(&self) -> Result<FrozenSource<'_>> {
        let exclusive = self
            .mutation
            .try_lock()
            .map_err(|_| Error::conflict("Offline source is already in use"))?;
        self.check_leader()?;
        let mut c = self.db.connect().await?;
        source_preflight(&c).await?;
        let images = self.installation_images(&c).await?;
        let live = self.runtime.inventory().await?;
        let mut ids: BTreeSet<Uuid> = live.iter().copied().collect();
        ids.extend(cgroup_ids()?);
        for row in c.query("SELECT id FROM instances WHERE phase<>'stopped' UNION SELECT instance_id FROM volume_attachments LIMIT 513",&[]).await?{ids.insert(row.get(0));}
        if ids.len() > MAX_INSTANCES {
            return Err(Error::exhausted());
        }
        let mut instances = Vec::new();
        for id in ids {
            let row = c
                .query_opt("SELECT generation,phase,EXISTS(SELECT 1 FROM volume_attachments WHERE instance_id=$1 AND access='rw') AS writer FROM instances WHERE id=$1", &[&id])
                .await?
                .ok_or_else(|| {
                    Error::conflict("Offline source has an untracked runtime identity")
                })?;
            let generation: i64 = row.get(0);
            if generation < 1 {
                return Err(Error::conflict("Offline source generation is invalid"));
            }
            let phase: String = row.get("phase");
            let requires_drain = row.get::<_, bool>("writer")
                || matches!(
                    phase.as_str(),
                    "starting" | "ready" | "degraded" | "draining"
                );
            instances.push(Instance {
                id,
                generation,
                requires_drain,
            });
        }
        tls::issue(
            &self.runtime.config,
            None,
            &self.runtime.config.root().join("kernel-identity"),
        )?;
        self.check_leader()?;
        let tx = c.transaction().await?;
        db::auth_lock(&tx, true).await?;
        source_preflight(&tx).await?;
        tx.execute(
            "UPDATE provider_records SET availability='unavailable'",
            &[],
        )
        .await?;
        tx.execute("UPDATE deployments SET phase='draining',revision=revision+1,updated_at=now() WHERE spec->>'enabled'='true'",&[]).await?;
        tx.commit().await?;
        let mut drained = Ok(());
        let mut stopped = Vec::new();
        let mut stop_error = None;
        let tracked: BTreeSet<Uuid> = instances.iter().map(|i| i.id).collect();
        for instance in instances {
            let outcome = async {
                if !self.runtime.running(instance.id).await? {
                    if instance.requires_drain {
                        return Err(Error::conflict(
                            "Offline writer exited before consistent drain",
                        )
                        .with_resource(instance.id));
                    }
                    return Ok(());
                }
                let address = self.runtime.address(instance.id)?;
                let channel = tls::channel(
                    &self.runtime.config,
                    instance.id,
                    instance.generation,
                    &address,
                )
                .await?;
                let mut client =
                    crate::rpc::plugin_lifecycle_client::PluginLifecycleClient::new(channel);
                let mut request = tonic::Request::new(crate::rpc::DrainRequest {
                    context: Some(crate::controller::context(None)),
                    grace_ms: 30000,
                });
                request.set_timeout(std::time::Duration::from_secs(30));
                let result = client.drain(request).await?.into_inner();
                if result.accepting_requests || result.active_calls != 0 || !result.drained {
                    return Err(Error::conflict("Offline source did not completely drain"));
                }
                Ok(())
            }
            .await;
            if drained.is_ok() {
                drained = outcome;
            }
            match self.runtime.stop(instance.id).await {
                Ok(()) => stopped.push(instance.id),
                Err(error) => {
                    if stop_error.is_none() {
                        stop_error = Some(error);
                    }
                }
            }
        }
        // Persist only positive stop observations, even if another writer or
        // Drain failed. Never refund reservations belonging to an unproved stop.
        let tx = c.transaction().await?;
        db::auth_lock(&tx, true).await?;
        for id in stopped {
            tx.execute("UPDATE instances SET phase='stopped',health='unknown',runtime_id=NULL,revision=revision+1,updated_at=now() WHERE id=$1",&[&id]).await?;
            volumes::release_stopped(&tx, Some(id)).await?;
            admission::release_stopped(&tx, id).await?;
            tx.execute(
                "DELETE FROM plugin_http_requests WHERE instance_id=$1",
                &[&id],
            )
            .await?;
        }
        tx.commit().await?;
        if let Some(error) = stop_error {
            return Err(error);
        }
        drained?;
        self.check_leader()?;
        if !self.runtime.inventory().await?.is_empty() {
            return Err(Error::conflict("Offline source still has containers"));
        }
        for id in cgroup_ids()? {
            if !tracked.contains(&id) {
                return Err(Error::conflict(
                    "A new runtime identity appeared during offline freeze",
                ));
            }
            self.runtime.stop(id).await?;
        }
        let root = self.root.try_clone()?;
        let volume_path = self.runtime.config.root().join("volumes");
        let has_volumes: i64 = c
            .query_one("SELECT count(*) FROM volumes WHERE state<>'deleted'", &[])
            .await?
            .get(0);
        tokio::task::spawn_blocking(move || -> Result<()> {
            sync(&root)?;
            if has_volumes > 0 {
                sync(&protected_directory(&volume_path)?)?;
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::unavailable("Offline filesystem sync stopped"))??;
        let tx = c.transaction().await?;
        db::auth_lock(&tx, true).await?;
        source_preflight(&tx).await?;
        let error = Error::conflict("Offline maintenance stopped unfinished calls").detail();
        // Global namespace/cgroup absence also confirms historical stopped rows
        // whose runtime identifiers or released-resource bookkeeping were stale.
        tx.execute("UPDATE instances SET runtime_id=NULL,revision=revision+1,updated_at=now() WHERE phase='stopped' AND runtime_id IS NOT NULL",&[]).await?;
        tx.execute("DELETE FROM plugin_http_requests", &[]).await?;
        tx.execute(
            "UPDATE calls SET state='unknown',error=$1 WHERE state IN ('accepted','running')",
            &[&error],
        )
        .await?;
        crate::task_engine::reconcile_stopped(&tx).await?;
        tx.execute(
            "UPDATE reservations SET status='released' WHERE status<>'released'",
            &[],
        )
        .await?;
        tx.execute("UPDATE node_budget SET reserved_cpu_millis=0,reserved_memory_bytes=0,revision=revision+1,updated_at=now()",&[]).await?;
        tx.execute(
            "UPDATE quotas SET concurrent_calls_used=0,revision=revision+1,updated_at=now()",
            &[],
        )
        .await?;
        tx.execute("UPDATE deployments SET phase='disabled',conditions='[]',revision=revision+1,updated_at=now()",&[]).await?;
        let observed_lsn: String = tx
            .query_one("SELECT pg_current_wal_lsn()::text", &[])
            .await?
            .get(0);
        self.check_leader()?;
        tx.commit().await?;
        Ok(FrozenSource {
            session: self,
            _exclusive: exclusive,
            images,
            observed_lsn,
        })
    }
    async fn installation_images(
        &self,
        c: &(impl GenericClient + Sync),
    ) -> Result<Vec<InstallationImage>> {
        let rows=c.query("SELECT id,image_digest,manifest_digest,manifest FROM installations WHERE state='installed' ORDER BY id LIMIT 129",&[]).await?;
        if rows.len() > 128 {
            return Err(Error::exhausted());
        }
        let mut images = Vec::new();
        for row in rows {
            let image_digest: String = row.get("image_digest");
            if !valid_digest(&image_digest) {
                return Err(Error::conflict("Installed image digest is invalid"));
            }
            let path = self
                .runtime
                .config
                .root()
                .join("images")
                .join(&image_digest[7..])
                .with_extension("reference");
            let image = String::from_utf8(read_private(&path, 2048)?)
                .map_err(|_| Error::invalid("Image index is not UTF-8"))?;
            if artifact::image_ref(&image)? != image_digest {
                return Err(Error::conflict("Private image index digest differs"));
            }
            // Installation verified the original publisher signature. Here the
            // trusted database supplies the immutable image/manifest digests;
            // no new installation or publisher authority is created.
            self.runtime.verify_image(&image, &image_digest).await?;
            let root = self.runtime.mount_image(&image, &image_digest).await?;
            let raw = artifact::read_image_file(&root, "xelab/plugin.json", 1048576)?;
            let manifest = strict_json(&raw, 1048576)?;
            let manifest_digest: String = row.get("manifest_digest");
            if digest(&raw) != manifest_digest || manifest != row.get::<_, Value>("manifest") {
                return Err(Error::conflict(
                    "Installed image does not match its metadata",
                ));
            }
            artifact::validate_runtime_profile(&manifest)?;
            crate::http_contracts::verify_image(c, row.get("id"), &manifest, &root).await?;
            images.push(InstallationImage {
                installation: row.get("id"),
                image,
                image_digest,
                manifest_digest,
            });
        }
        Ok(images)
    }
}
impl FrozenSource<'_> {
    pub fn images(&self) -> &[InstallationImage] {
        &self.images
    }
    pub fn stopped_lsn(&self) -> &str {
        &self.observed_lsn
    }
    pub async fn export_metadata(
        &self,
        output: &mut (impl AsyncWrite + Unpin),
    ) -> Result<metadata_snapshot::Summary> {
        self.session.check_leader()?;
        let mut c = self.session.db.connect().await?;
        let summary = metadata_snapshot::export(&mut c, output).await?;
        self.session.check_leader()?;
        Ok(summary)
    }
    /// Resolve every live logical volume from its exact durable allocation and
    /// physical quota namespace. This session excludes all daemon mutations.
    pub async fn volume_sources(&self) -> Result<Vec<volumes::BackupSource>> {
        self.session.check_leader()?;
        let c = self.session.db.connect().await?;
        let rows=c.query("SELECT a.*,r.filesystem_uuid,v.spec AS volume_spec FROM volume_allocations a JOIN volume_storage_root r ON r.id=a.root_id JOIN volumes v ON v.id=a.volume_id WHERE v.state<>'deleted' AND a.state='ready' AND r.state='ready' ORDER BY a.volume_id LIMIT 17",&[]).await?;
        let expected: i64 = c
            .query_one("SELECT count(*) FROM volumes WHERE state<>'deleted'", &[])
            .await?
            .get(0);
        if rows.len() as i64 != expected || expected > MAX_VOLUMES {
            return Err(Error::conflict("Offline volume allocation set differs"));
        }
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let path = self.session.runtime.config.root().join("volumes");
        let sources = tokio::task::spawn_blocking(move || -> Result<Vec<volumes::BackupSource>> {
            use crate::storage::xfs::{Limits, ProjectStore};
            let mut store = ProjectStore::open(&path)?;
            let root: Uuid = rows[0].get("root_id");
            let filesystem: Uuid = rows[0].get("filesystem_uuid");
            store.namespace_identity(filesystem, root, false)?;
            let mut result = Vec::new();
            for row in rows {
                let id: Uuid = row.get("volume_id");
                let project = row.get::<_, i32>("project_id") as u32;
                let limits = Limits {
                    capacity_bytes: row.get::<_, i64>("capacity_bytes") as u64,
                    inodes: row.get::<_, i64>("inode_limit") as u64,
                };
                if row.get::<_, Uuid>("root_id") != root
                    || row.get::<_, Uuid>("filesystem_uuid") != filesystem
                    || store.inspect(id, project)?.limits != limits
                {
                    return Err(Error::conflict(
                        "Offline volume namespace or hard quota differs",
                    ));
                }
                result.push(volumes::BackupSource {
                    id,
                    spec: row.get("volume_spec"),
                    capacity_bytes: limits.capacity_bytes,
                    data_schema_version: row.get("data_schema_version"),
                    filesystem_uuid: filesystem,
                    project_id: project,
                    path: store.data_path(id, project)?,
                });
            }
            Ok(result)
        })
        .await
        .map_err(|_| Error::unavailable("Offline source inspection stopped"))??;
        self.session.check_leader()?;
        Ok(sources)
    }
}
fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
async fn source_preflight(c: &(impl GenericClient + Sync)) -> Result<()> {
    db::verify_migration(c).await?;
    let row=c.query_one("SELECT EXISTS(SELECT 1 FROM storage_recovery_jobs WHERE state NOT IN ('succeeded','failed')) OR EXISTS(SELECT 1 FROM deployment_storage_holds) OR EXISTS(SELECT 1 FROM volume_holds) OR EXISTS(SELECT 1 FROM volume_allocations WHERE state NOT IN ('ready','deleted')) OR EXISTS(SELECT 1 FROM backups WHERE state='creating') OR EXISTS(SELECT 1 FROM platform_recovery_state WHERE phase<>'ready')",&[]).await?;
    if row.get::<_, bool>(0) {
        return Err(Error::conflict(
            "Unsettled storage or recovery work blocks offline snapshot",
        ));
    }
    if c.query_one("SELECT EXISTS(SELECT 1 FROM deployment_upgrade_jobs WHERE state NOT IN ('succeeded','failed'))", &[]).await?.get::<_,bool>(0) {
        return Err(Error::conflict("Unsettled deployment upgrade blocks offline snapshot"));
    }
    if c.query_one("SELECT EXISTS(SELECT 1 FROM volume_schema_jobs WHERE state NOT IN ('verified','failed')) OR EXISTS(SELECT 1 FROM volume_allocations WHERE state<>'deleted' AND schema_state='initializing')", &[]).await?.get::<_,bool>(0) {
        return Err(Error::conflict("Unverified business initialization blocks offline snapshot"));
    }
    if !c.query_one("SELECT EXISTS(SELECT 1 FROM accounts WHERE independent_owner AND parent_id IS NULL AND kind='user' AND status<>'archived')",&[]).await?.get::<_,bool>(0){return Err(Error::conflict("Offline source has no eligible recovery Owner"));}
    let volumes: i64 = c
        .query_one("SELECT count(*) FROM volumes WHERE state<>'deleted'", &[])
        .await?
        .get(0);
    if volumes > MAX_VOLUMES {
        return Err(Error::exhausted());
    }
    if c.query_one("SELECT EXISTS(SELECT 1 FROM volumes v LEFT JOIN volume_allocations a ON a.volume_id=v.id LEFT JOIN volume_storage_root r ON r.id=a.root_id WHERE v.state<>'deleted' AND (a.volume_id IS NULL OR a.state<>'ready' OR r.state<>'ready' OR a.owner_id<>v.owner_id OR a.spec<>v.spec OR a.capacity_bytes<>v.capacity_bytes OR v.capacity_bytes>67645734912))",&[]).await?.get::<_,bool>(0){return Err(Error::conflict("Offline source volumes are incomplete or too large"));}
    if c.query_one("SELECT EXISTS(SELECT 1 FROM volume_allocations a LEFT JOIN volumes v ON v.id=a.volume_id WHERE a.state<>'deleted' AND (v.id IS NULL OR v.state='deleted'))", &[]).await?.get::<_,bool>(0) {
        return Err(Error::conflict("Offline allocation has no live logical volume"));
    }
    for row in c.query("SELECT volume_id FROM volume_allocations WHERE state<>'deleted' ORDER BY volume_id LIMIT 17", &[]).await? {
        formats::binding(c, row.get("volume_id")).await?;
    }
    crate::http_contracts::validate_snapshot_bindings(c).await?;
    crate::skills::validate_snapshot_bindings(c).await?;
    crate::oauth::snapshot::validate_snapshot(c).await?;
    crate::ui::validate_snapshot(c).await?;
    crate::webui::validate_snapshot(c).await?;
    crate::events::snapshot::validate_snapshot(c).await?;
    crate::tasks::snapshot::validate(c).await?;
    for name in [
        "schedules",
        "micro_plugins",
        "extension_plugins",
        "skill_batches",
    ] {
        if c.query_one(&format!("SELECT EXISTS(SELECT 1 FROM {name})"), &[])
            .await?
            .get::<_, bool>(0)
        {
            return Err(Error::conflict(
                "Offline snapshot does not yet support this platform profile",
            ));
        }
    }
    Ok(())
}
fn sync(file: &File) -> Result<()> {
    if unsafe { libc::syncfs(file.as_raw_fd()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn protected_directory(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(Error::invalid("Offline storage path must be absolute"));
    }
    let mut fd = File::open("/")?;
    for part in path.components() {
        match part {
            Component::RootDir => continue,
            Component::Normal(name) => {
                let m = fd.metadata()?;
                if m.uid() != 0 || (m.mode() & 0o022 != 0 && m.mode() & libc::S_ISVTX == 0) {
                    return Err(Error::invalid("Offline storage ancestor is unsafe"));
                }
                let name = std::ffi::CString::new(name.as_bytes())
                    .map_err(|_| Error::invalid("Invalid offline storage path"))?;
                let next = unsafe {
                    libc::openat(
                        fd.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                fd = unsafe { File::from_raw_fd(next) };
            }
            _ => return Err(Error::invalid("Invalid offline storage path")),
        }
    }
    let meta = fd.metadata()?;
    if meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(Error::invalid(
            "Offline storage root must be root-owned and private",
        ));
    }
    Ok(fd)
}
fn cgroup_ids() -> Result<Vec<Uuid>> {
    let path = Path::new("/sys/fs/cgroup/xelab/plugins");
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if ids.len() >= MAX_INSTANCES {
            return Err(Error::exhausted());
        }
        ids.push(
            entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::conflict("Unrecognized plugin cgroup"))?,
        );
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backups::tests::Fixture;
    #[tokio::test]
    async fn actual_postgres_source_rejects_a_ready_allocation_for_a_deleted_volume() {
        // Metadata-only orphan regression, never a physical source proof.
        let Some(f) = Fixture::new().await else {
            return;
        };
        let c = f.app.db.connect().await.unwrap();
        c.batch_execute("UPDATE storage_recovery_jobs SET state='failed'; UPDATE backups SET state='failed'; DELETE FROM deployment_storage_holds; DELETE FROM volume_holds; UPDATE volumes SET state='deleted'").await.unwrap();
        source_preflight(&c).await.unwrap();
        let volume = c
            .query_one(
                "SELECT id,owner_id,spec FROM volumes ORDER BY id LIMIT 1",
                &[],
            )
            .await
            .unwrap();
        let job = c
            .query_one(
                "SELECT operation_id,credential_id FROM storage_recovery_jobs LIMIT 1",
                &[],
            )
            .await
            .unwrap();
        let root = Uuid::new_v4();
        c.execute("INSERT INTO volume_storage_root(id,filesystem_uuid,state,capacity_bytes,reserved_bytes) VALUES($1,$2,'ready',134217728,1114112)", &[&root,&Uuid::new_v4()]).await.unwrap();
        c.execute("INSERT INTO volume_allocations(volume_id,root_id,project_id,owner_id,spec,capacity_bytes,inode_limit,metadata_charge,desired_capacity,desired_inodes,desired_metadata_charge,state,operation_id,credential_id,peer) VALUES($1,$2,41,$3,$4,1048576,128,65536,1048576,128,65536,'ready',$5,$6,'127.0.0.1')", &[&volume.get::<_,Uuid>("id"),&root,&volume.get::<_,Uuid>("owner_id"),&volume.get::<_,Value>("spec"),&job.get::<_,Uuid>("operation_id"),&job.get::<_,Uuid>("credential_id")]).await.unwrap();
        assert!(
            source_preflight(&c).await.is_err(),
            "an orphan allocation would be omitted from the archive but imported from metadata"
        );
    }
    #[tokio::test]
    async fn actual_postgres_source_preflight_requires_settled_supported_metadata() {
        let Some(f) = Fixture::new().await else {
            return;
        };
        let c = f.app.db.connect().await.unwrap();
        assert!(source_preflight(&c).await.is_err());
        c.batch_execute("UPDATE storage_recovery_jobs SET state='failed'; UPDATE backups SET state='failed'; DELETE FROM deployment_storage_holds; DELETE FROM volume_holds").await.unwrap();
        assert!(
            source_preflight(&c).await.is_err(),
            "logical volumes without physical allocations are incomplete"
        );
        c.batch_execute("UPDATE volumes SET state='deleted'")
            .await
            .unwrap();
        source_preflight(&c).await.unwrap();
        let owner: Uuid = c
            .query_one("SELECT created_by FROM backups WHERE id=$1", &[&f.backup])
            .await
            .unwrap()
            .get(0);
        let workflow = Uuid::new_v4();
        c.execute("INSERT INTO workflows(id,owner_id,name,version,spec,status,created_at,updated_at) VALUES($1,$2,'invalid source workflow',1,'{}','active',now(),now())",&[&workflow,&owner]).await.unwrap();
        assert_eq!(
            source_preflight(&c).await.unwrap_err().code,
            "STATE_CONFLICT"
        );
        c.execute("DELETE FROM workflows WHERE id=$1", &[&workflow])
            .await
            .unwrap();
        source_preflight(&c).await.unwrap();
        c.execute("INSERT INTO platform_recovery_state(recovery_id,backup_id,phase) VALUES($1,$2,'rebuilding')",&[&Uuid::new_v4(),&f.backup]).await.unwrap();
        assert!(source_preflight(&c).await.is_err());
    }
    #[tokio::test]
    async fn explicit_downtime_is_required_before_opening_storage_or_database() {
        // Host-admin preflight rejects this nonroot environment too; neither
        // refusal is a claim that a real host lease or OCI freeze was exercised.
        let t: toml::Value =
            toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
        let config = Config::from_value(serde_json::to_value(t).unwrap()).unwrap();
        assert!(Session::open(config, false).await.is_err());
    }
}
