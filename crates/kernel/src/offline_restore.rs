//! Fresh-target recovery. A durable importing/rebuilding database gate precedes
//! all target data; only physical proofs may eventually open that gate.
use super::backup::{Manifest, Receipt};
use super::*;
use crate::{
    backup_repository::{Repository, Settings},
    backups,
    offline::workspace::{Header, Workspace},
    storage::backup_transfer::{self, raw},
};
use std::sync::Arc;
#[path = "offline_restore_volumes.rs"]
mod volume_restore;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReceipt {
    pub recovery_id: Uuid,
    pub backup_id: Uuid,
    pub owner_id: Uuid,
    pub images: usize,
    pub blobs: u64,
    pub volumes: usize,
    pub gate: String,
    pub runtime_started: bool,
    pub off_host: bool,
}
/// Dropping the caller's waiter does not cancel the coordinator. Its owned
/// target, global leases and worker joins last through the terminal checkpoint.
pub async fn run(
    config: Config,
    receipt: Receipt,
    source_host_fenced: bool,
    recovery: Option<Uuid>,
    owner: Uuid,
    password: zeroize::Zeroizing<String>,
) -> Result<RecoveryReceipt> {
    tokio::spawn(async move {
        let mut target = Target::open(config, receipt, source_host_fenced).await?;
        if let Some(id) = recovery {
            target.resume(id).await?;
        } else {
            target.begin().await?;
        }
        if target.gate_phase().await? == "ready" {
            return target.completed_receipt().await;
        }
        target.import_metadata(owner, &password).await?;
        target.login_sanity(owner, &password).await?;
        target.restore_images().await?;
        target.restore_blobs().await?;
        target.restore_volumes().await?;
        target.complete(owner, &password).await
    })
    .await
    .map_err(|_| Error::unavailable("Platform recovery coordinator stopped"))?
}

struct Target {
    session: Arc<Session>,
    recovery: Uuid,
    receipt: Receipt,
    manifest: Manifest,
    repository: Repository,
    master: zeroize::Zeroizing<[u8; 32]>,
    workspace: Option<Workspace>,
    pool: backup_transfer::Pool,
}
impl Target {
    fn check_fresh_storage(&self, journal: Option<Uuid>) -> Result<()> {
        for entry in fs::read_dir(format!("/proc/self/fd/{}", self.session.root.as_raw_fd()))? {
            let entry = entry?;
            if entry.file_name() == ".platform-restores" && entry.file_type()?.is_dir() {
                let Some(journal) = journal else {
                    return Err(Error::conflict(
                        "Fresh recovery contains an existing journal",
                    ));
                };
                for child in fs::read_dir(entry.path())? {
                    let child = child?;
                    if child.file_name() != journal.to_string().as_str()
                        || !child.file_type()?.is_dir()
                    {
                        return Err(Error::conflict("Fresh recovery contains another journal"));
                    }
                }
                continue;
            }
            if entry.file_name() != "volumes" || !entry.file_type()?.is_dir() {
                return Err(Error::conflict(
                    "Platform recovery requires a fresh private storage root",
                ));
            }
            // read_dir on the pinned descriptor yields /proc/self/fd/... entry
            // paths. The XFS backend deliberately rejects that proc symlink;
            // pass the configured absolute path so it can verify every ancestor.
            let store = crate::storage::xfs::ProjectStore::open(
                &self.session.runtime.config.root().join("volumes"),
            )?;
            store.verify_mount_root()?;
            let filesystem = store.status()?.filesystem_uuid;
            if self
                .manifest
                .volumes
                .iter()
                .any(|v| v.filesystem_uuid == filesystem)
            {
                return Err(Error::conflict(
                    "Recovery volume filesystem must have a new UUID",
                ));
            }
            if fs::read_dir(entry.path())?.next().is_some() {
                return Err(Error::conflict("Recovery volume filesystem must be empty"));
            }
        }
        if !self.manifest.volumes.is_empty()
            && !self
                .session
                .runtime
                .config
                .root()
                .join("volumes")
                .try_exists()?
        {
            return Err(Error::conflict(
                "Recovery requires a fresh dedicated volume filesystem",
            ));
        }
        Ok(())
    }
    fn target_identity(&self) -> Result<Value> {
        let meta = self.session.root.metadata()?;
        Ok(
            serde_json::json!({"device":meta.dev(),"inode":meta.ino(),"socket":self.session.runtime.config.text("runtime","socket"),"namespace":self.session.runtime.config.text("runtime","namespace")}),
        )
    }
    async fn gate_phase(&self) -> Result<String> {
        self.session.check_leader()?;
        let c = self.session.db.connect().await?;
        Ok(c.query_one(
            "SELECT phase FROM platform_recovery_state WHERE recovery_id=$1 AND backup_id=$2",
            &[&self.recovery, &self.receipt.backup_id],
        )
        .await?
        .get(0))
    }
    async fn resume(&mut self, recovery: Uuid) -> Result<()> {
        if recovery.is_nil() {
            return Err(Error::invalid("Invalid recovery identity"));
        }
        let workspace = match Workspace::resume_restore(
            &self.session.root,
            recovery,
            self.receipt.repository_id,
            &self.manifest.master_key_reference,
        ) {
            Ok(workspace) => workspace,
            Err(original) => {
                let c = self.session.db.connect().await?;
                if c.query_opt("SELECT recovery_id FROM platform_recovery_state WHERE recovery_id=$1 AND backup_id=$2 AND phase='importing' AND recovery_owner_id IS NULL",&[&recovery,&self.receipt.backup_id]).await?.is_none() {return Err(original);}
                for table in db::snapshot_tables()
                    .into_iter()
                    .chain(["recovery_owner_anchors"])
                {
                    if c.query_one(
                        &format!("SELECT EXISTS(SELECT 1 FROM public.\"{table}\")"),
                        &[],
                    )
                    .await?
                    .get::<_, bool>(0)
                    {
                        return Err(original);
                    }
                }
                if !self.session.runtime.inventory().await?.is_empty() || !cgroup_ids()?.is_empty()
                {
                    return Err(original);
                }
                self.check_fresh_storage(Some(recovery))?;
                if !String::from_utf8(
                    self.session
                        .runtime
                        .ctr(&["images".into(), "list".into(), "--quiet".into()])
                        .await?,
                )
                .map_err(|_| Error::unavailable("Invalid recovery image inventory"))?
                .trim()
                .is_empty()
                {
                    return Err(original);
                }
                Workspace::recover_restore_creation(
                    &self.session.root,
                    Header {
                        format: 1,
                        snapshot: recovery,
                        repository: self.receipt.repository_id,
                        master_key_reference: self.manifest.master_key_reference.clone(),
                        phase: "preparing".into(),
                        context: serde_json::json!({"receipt":self.receipt,"manifest":self.manifest,"target":self.target_identity()?}),
                    },
                )?
            }
        };
        let header = workspace.header()?;
        if !matches!(header.phase.as_str(), "preparing" | "succeeded")
            || header.context["receipt"] != serde_json::to_value(&self.receipt)?
            || header.context["manifest"] != serde_json::to_value(&self.manifest)?
            || header.context["target"] != self.target_identity()?
        {
            return Err(Error::conflict(
                "Recovery workspace belongs to another target or snapshot",
            ));
        }
        self.recovery = recovery;
        self.workspace = Some(workspace);
        let phase = self.gate_phase().await?;
        if !matches!(phase.as_str(), "importing" | "rebuilding" | "ready")
            || (header.phase == "succeeded" && phase != "ready")
        {
            return Err(Error::conflict("Recovery journal and database gate differ"));
        }
        Ok(())
    }
    async fn login_sanity(&self, owner: Uuid, password: &str) -> Result<()> {
        self.require_rebuilding().await?;
        let mut c = self.session.db.connect().await?;
        let tx = c.transaction().await?;
        let (_, key) = self.session.runtime.config.secrets()?;
        let auth = crate::auth::Auth::new(key)?;
        let check = async {
            let issued = auth
                .login(
                    &tx,
                    owner,
                    password.to_owned(),
                    "127.0.0.1".parse().unwrap(),
                    Uuid::new_v4(),
                )
                .await?;
            let token = issued["access_token"]
                .as_str()
                .ok_or_else(|| Error::unavailable("Recovery login returned no token"))?;
            let context = auth
                .authenticate(&tx, token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
                .await?;
            crate::auth::authorize(
                &tx,
                &context,
                "platform.read",
                &crate::auth::Resource::new("platform", "node", None),
            )
            .await?;
            Ok(())
        }
        .await;
        // Exercise the real login/policy path without leaving any live session
        // behind, including process death between issuing and revoking it.
        tx.rollback().await?;
        check
    }
    fn receipt_for(&self, owner: Uuid) -> RecoveryReceipt {
        RecoveryReceipt {
            recovery_id: self.recovery,
            backup_id: self.receipt.backup_id,
            owner_id: owner,
            images: self
                .manifest
                .images
                .as_ref()
                .map_or(0, |image| image.archive.images.len()),
            blobs: self.manifest.blob_count,
            volumes: self.manifest.volumes.len(),
            gate: "ready".into(),
            runtime_started: false,
            off_host: self.manifest.off_host,
        }
    }
    async fn completed_receipt(&self) -> Result<RecoveryReceipt> {
        self.session.check_leader()?;
        let c = self.session.db.connect().await?;
        let row=c.query_one("SELECT recovery_owner_id,metadata_summary FROM platform_recovery_state WHERE recovery_id=$1 AND backup_id=$2 AND phase='ready'",&[&self.recovery,&self.receipt.backup_id]).await?;
        let owner: Option<Uuid> = row.get("recovery_owner_id");
        let owner = owner
            .filter(|id| self.manifest.recovery_owners.contains(id))
            .ok_or_else(|| Error::conflict("Completed recovery Owner differs"))?;
        if row.get::<_, Option<Value>>("metadata_summary")
            != Some(serde_json::to_value(&self.manifest.metadata_summary)?)
        {
            return Err(Error::conflict("Completed recovery metadata proof differs"));
        }
        let result = self.receipt_for(owner);
        let workspace = self
            .workspace
            .as_ref()
            .ok_or_else(|| Error::conflict("Recovery workspace is unavailable"))?;
        let mut header = workspace.header()?;
        if header.phase == "preparing" {
            header.context["result"] = serde_json::to_value(&result)?;
            workspace.complete_restore(header.context)?;
        }
        workspace.remove_staged_data()?;
        Ok(result)
    }
    async fn verify_blobs(&self) -> Result<()> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or_else(|| Error::conflict("Recovery workspace is unavailable"))?;
        let context = workspace.header()?.context;
        if context["blobs_verified"] != true {
            return Err(Error::conflict("Blob restoration is incomplete"));
        }
        let c = self.session.db.connect().await?;
        let rows = c
            .query(
                "SELECT id,size_bytes,digest,backend_reference FROM blobs ORDER BY id LIMIT 65537",
                &[],
            )
            .await?;
        if rows.len() > 65536 || rows.len() as u64 != self.manifest.blob_count {
            return Err(Error::conflict("Recovered Blob set differs"));
        }
        if let Some(source) = self.manifest.blob_root {
            let root = context["blob_root"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .filter(|id| !id.is_nil() && *id != source)
                .ok_or_else(|| Error::conflict("New Blob root proof is missing"))?;
            if c.query_opt(
                "SELECT id FROM blob_storage_root WHERE id=$1 AND state='ready'",
                &[&root],
            )
            .await?
            .is_none()
            {
                return Err(Error::conflict("Recovered Blob binding differs"));
            }
            let store = crate::storage::blob::Store::open(&self.session.runtime.config.root())?;
            store.identity(root, false)?;
            for row in rows {
                self.session.check_leader()?;
                let id: Uuid = row.get("id");
                let size: i64 = row.get("size_bytes");
                let hash: String = row.get("digest");
                if !(0..=67108864).contains(&size)
                    || id.is_nil()
                    || !valid_digest(&hash)
                    || row.get::<_, String>("backend_reference") != id.to_string()
                {
                    return Err(Error::conflict("Recovered Blob metadata differs"));
                }
                let store = store.clone();
                tokio::task::spawn_blocking(move || store.verify(id, size as u64, &hash))
                    .await
                    .map_err(|_| Error::unavailable("Recovered Blob verification stopped"))??;
            }
        } else if !rows.is_empty()
            || c.query_one("SELECT EXISTS(SELECT 1 FROM blob_storage_root)", &[])
                .await?
                .get::<_, bool>(0)
        {
            return Err(Error::conflict("Unexpected recovered Blob root"));
        }
        Ok(())
    }
    async fn complete(&self, owner: Uuid, password: &str) -> Result<RecoveryReceipt> {
        self.require_rebuilding().await?;
        let workspace = self
            .workspace
            .as_ref()
            .ok_or_else(|| Error::conflict("Recovery workspace is unavailable"))?;
        let context = workspace.header()?.context;
        if context["images_verified"] != true {
            return Err(Error::conflict("Image restoration is incomplete"));
        }
        if let Some(image) = &self.manifest.images {
            let mut file = tokio::fs::File::from_std(workspace.staged_file(true)?);
            self.session
                .runtime
                .verify_restored_images(&mut file, &image.archive)
                .await?;
        }
        let c = self.session.db.connect().await?;
        self.session.installation_images(&c).await?;
        self.verify_blobs().await?;
        let volumes = volume_restore::verify(self).await?;
        self.login_sanity(owner, password).await?;
        if !self.session.runtime.inventory().await?.is_empty() || !cgroup_ids()?.is_empty() {
            return Err(Error::conflict(
                "A workload appeared during offline recovery",
            ));
        }
        self.session.check_leader()?;
        let mut c = self.session.db.connect().await?;
        let tx = c.transaction().await?;
        db::auth_lock(&tx, true).await?;
        let row=tx.query_one("SELECT recovery_owner_id,metadata_summary FROM platform_recovery_state WHERE recovery_id=$1 AND backup_id=$2 AND phase='rebuilding' FOR UPDATE",&[&self.recovery,&self.receipt.backup_id]).await?;
        if row.get::<_, Option<Uuid>>("recovery_owner_id") != Some(owner)
            || row.get::<_, Option<Value>>("metadata_summary")
                != Some(serde_json::to_value(&self.manifest.metadata_summary)?)
        {
            return Err(Error::conflict("Recovery gate changed before publication"));
        }
        let unsafe_authority:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM credentials WHERE status='active') OR EXISTS(SELECT 1 FROM accounts WHERE status='active' AND id<>$1) OR NOT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND kind='user' AND status='active' AND parent_id IS NULL AND independent_owner AND password_hash IS NOT NULL) OR EXISTS(SELECT 1 FROM grants g WHERE status='active' AND NOT EXISTS(SELECT 1 FROM recovery_owner_anchors a WHERE a.grant_id=g.id AND a.account_id=$1 AND a.recovery_id=$2)) OR EXISTS(SELECT 1 FROM publishers WHERE status='trusted') OR EXISTS(SELECT 1 FROM secrets WHERE status='active') OR EXISTS(SELECT 1 FROM secret_bindings WHERE status='active') OR EXISTS(SELECT 1 FROM deployments WHERE spec->>'enabled'='true') OR EXISTS(SELECT 1 FROM instances WHERE phase<>'stopped' OR runtime_id IS NOT NULL) OR EXISTS(SELECT 1 FROM provider_records WHERE availability<>'unavailable') OR EXISTS(SELECT 1 FROM volume_attachments) OR EXISTS(SELECT 1 FROM volume_mount_approvals) OR EXISTS(SELECT 1 FROM host_proxy_approvals) OR EXISTS(SELECT 1 FROM volume_holds) OR EXISTS(SELECT 1 FROM deployment_storage_holds) OR EXISTS(SELECT 1 FROM reservations WHERE status<>'released') OR EXISTS(SELECT 1 FROM node_budget WHERE admission_enabled OR reserved_cpu_millis<>0 OR reserved_memory_bytes<>0)",&[&owner,&self.recovery]).await?.get(0);
        if unsafe_authority {
            return Err(Error::conflict(
                "Historical authority or runtime state became active during recovery",
            ));
        }
        crate::oauth::snapshot::ensure_authority_reset(&tx).await?;
        crate::events::snapshot::ensure_authority_reset(&tx).await?;
        crate::recovery::ensure_m4_authority_reset(&tx).await?;
        crate::recovery::ensure_task_authority_reset(&tx).await?;
        volume_restore::publish(&tx, volumes).await?;
        tx.execute("UPDATE platform_recovery_state SET phase='ready',updated_at=now() WHERE recovery_id=$1 AND phase='rebuilding'",&[&self.recovery]).await?;
        crate::db::audit(
            &tx,
            owner,
            None,
            Uuid::new_v4(),
            "platformRecovery",
            &crate::auth::Resource::new("backup", self.receipt.backup_id, Some(owner)).json(),
            "succeeded",
            "PLATFORM_RECOVERY_VERIFIED",
        )
        .await?;
        self.session.check_leader()?;
        tx.commit().await?;
        self.completed_receipt().await
    }
    pub async fn restore_volumes(&mut self) -> Result<()> {
        self.require_rebuilding().await?;
        volume_restore::restore(self).await
    }
    /// The operator must independently fence the old host. Configured database,
    /// storage and runtime namespace must belong to this fresh recovery target.
    pub async fn open(config: Config, receipt: Receipt, source_host_fenced: bool) -> Result<Self> {
        require_host_admin()?;
        if !source_host_fenced {
            return Err(Error::invalid(
                "Platform recovery requires the source host to be fenced",
            ));
        }
        let settings = Settings::from_host(&config)?;
        let master = backups::master(&config)?;
        let repository = settings.reader(receipt.repository_id).await?;
        if !repository.objects.off_host() || !receipt.off_host {
            return Err(Error::unavailable(
                "Platform recovery requires an off-host source repository",
            ));
        }
        let manifest: Manifest = serde_json::from_value(
            repository
                .read_manifest(
                    receipt.backup_id,
                    receipt.manifest_object,
                    &master,
                    &receipt.manifest_digest,
                )
                .await?,
        )?;
        manifest.validate_receipt(&receipt, &digest(master.as_ref()))?;
        let runtime = Runtime::new(config.clone());
        runtime.retain_daemon_host_lease()?;
        let (dsn, mut hmac) = config.secrets()?;
        hmac.zeroize();
        let db = Db::new(dsn)?;
        let c = db.connect().await?;
        db::verify_migration(&c).await?;
        let leader = db.leader().await?;
        let root = protected_directory(&config.root())?;
        let session = Arc::new(Session {
            runtime,
            db,
            leader,
            root,
            mutation: Mutex::new(()),
        });
        let recovery = Uuid::new_v4();
        Ok(Self {
            session,
            recovery,
            receipt,
            manifest,
            repository,
            master,
            workspace: None,
            pool: backup_transfer::Pool::default(),
        })
    }
    /// Persist a gate before creating any target data. A later failure retains
    /// the closed gate across process death and configuration changes.
    pub async fn begin(&mut self) -> Result<Uuid> {
        if self.workspace.is_some() {
            return Err(Error::conflict("Recovery target was already started"));
        }
        self.session.check_leader()?;
        if !self.session.runtime.inventory().await?.is_empty()
            || !cgroup_ids()?.is_empty()
            || !String::from_utf8(
                self.session
                    .runtime
                    .ctr(&["images".into(), "list".into(), "--quiet".into()])
                    .await?,
            )
            .map_err(|_| Error::unavailable("Invalid target image inventory"))?
            .trim()
            .is_empty()
        {
            return Err(Error::conflict(
                "Recovery target runtime namespace must be empty",
            ));
        }
        self.check_fresh_storage(None)?;
        let mut c = self.session.db.connect().await?;
        let tx = c.transaction().await?;
        db::auth_lock(&tx, true).await?;
        db::verify_migration(&tx).await?;
        for table in db::snapshot_tables()
            .into_iter()
            .chain(["recovery_owner_anchors", "platform_recovery_state"])
        {
            if tx
                .query_one(
                    &format!("SELECT EXISTS(SELECT 1 FROM public.\"{table}\")"),
                    &[],
                )
                .await?
                .get::<_, bool>(0)
            {
                return Err(Error::conflict(
                    "Platform recovery requires an empty target database",
                ));
            }
        }
        tx.execute("INSERT INTO platform_recovery_state(recovery_id,backup_id,phase) VALUES($1,$2,'importing')",&[&self.recovery,&self.receipt.backup_id]).await?;
        tx.commit().await?;
        self.session.check_leader()?;
        self.workspace = Some(Workspace::create_restore(
            &self.session.root,
            Header {
                format: 1,
                snapshot: self.recovery,
                repository: self.receipt.repository_id,
                master_key_reference: self.manifest.master_key_reference.clone(),
                phase: "preparing".into(),
                context: serde_json::json!({"receipt":self.receipt,"manifest":self.manifest,"target":self.target_identity()?}),
            },
        )?);
        Ok(self.recovery)
    }
    /// Native metadata only: all old authority is revoked and the gate remains
    /// rebuilding until the independent physical recovery is proven complete.
    pub async fn import_metadata(
        &mut self,
        owner: Uuid,
        password: &str,
    ) -> Result<metadata_snapshot::Summary> {
        if !self.manifest.recovery_owners.contains(&owner) {
            return Err(Error::invalid(
                "Recovery Owner is not in the authenticated candidate set",
            ));
        }
        let workspace = self
            .workspace
            .as_ref()
            .ok_or_else(|| Error::conflict("Recovery gate was not started"))?;
        self.session.check_leader()?;
        let c = self.session.db.connect().await?;
        let row=c.query_one("SELECT phase,recovery_owner_id,metadata_summary FROM platform_recovery_state WHERE recovery_id=$1 AND backup_id=$2",&[&self.recovery,&self.receipt.backup_id]).await?;
        if row.get::<_, String>("phase") == "rebuilding" {
            if row.get::<_, Option<Uuid>>("recovery_owner_id") != Some(owner)
                || row.get::<_, Option<Value>>("metadata_summary")
                    != Some(serde_json::to_value(&self.manifest.metadata_summary)?)
            {
                return Err(Error::conflict(
                    "Imported recovery checkpoint or Owner differs",
                ));
            }
            return Ok(self.manifest.metadata_summary.clone());
        }
        if row.get::<_, String>("phase") != "importing" {
            return Err(Error::conflict("Recovery metadata is already terminal"));
        }
        workspace.discard_staged(false)?;
        let file = workspace.reserve_file(
            false,
            self.manifest.metadata.plaintext.bytes,
            128 * 1024 * 1024,
        )?;
        let object = raw::Object {
            backup: self.receipt.backup_id,
            object: self.manifest.metadata.object,
            maximum_bytes: self.manifest.metadata.plaintext.bytes,
        };
        let value = self
            .pool
            .raw(None)
            .download_file(
                self.repository.objects.clone(),
                raw::Target::new(file)?,
                object,
                zeroize::Zeroizing::new(*self.master),
                raw::Expected {
                    plaintext: self.manifest.metadata.plaintext.clone(),
                    ciphertext: self.manifest.metadata.ciphertext.clone(),
                },
                std::time::Duration::from_secs(300),
            )?
            .wait()
            .await?;
        self.session.check_leader()?;
        let mut input = tokio::fs::File::from_std(value.file);
        let mut c = self.session.db.connect().await?;
        let summary = metadata_snapshot::import(
            &mut c,
            &mut input,
            &self.manifest.metadata_summary,
            self.recovery,
            owner,
            password,
        )
        .await?;
        self.session.check_leader()?;
        let header = workspace.header()?;
        let mut context = header.context;
        context["metadata_imported"] = Value::Bool(true);
        context["owner_id"] = serde_json::json!(owner);
        workspace.update_header(&header.phase, context)?;
        Ok(summary)
    }
    async fn require_rebuilding(&self) -> Result<()> {
        self.session.check_leader()?;
        let c = self.session.db.connect().await?;
        let row=c.query_opt("SELECT metadata_summary FROM platform_recovery_state WHERE recovery_id=$1 AND backup_id=$2 AND phase='rebuilding' AND recovery_owner_id IS NOT NULL",&[&self.recovery,&self.receipt.backup_id]).await?.ok_or_else(||Error::conflict("Matching metadata recovery is not rebuilding"))?;
        if row.get::<_, Option<Value>>(0)
            != Some(serde_json::to_value(&self.manifest.metadata_summary)?)
        {
            return Err(Error::conflict("Imported recovery metadata proof differs"));
        }
        Ok(())
    }
    /// Recover real OCI content and verify the raw plugin manifests against
    /// authenticated metadata, while leaving publishers revoked and the gate shut.
    pub async fn restore_images(&mut self) -> Result<()> {
        self.require_rebuilding().await?;
        let workspace = self
            .workspace
            .as_ref()
            .ok_or_else(|| Error::conflict("Recovery workspace is unavailable"))?;
        let c = self.session.db.connect().await?;
        let installed=c.query("SELECT id,image_digest,manifest_digest FROM installations WHERE state='installed' ORDER BY id LIMIT 129",&[]).await?;
        let wanted: std::collections::BTreeMap<_, _> = self
            .manifest
            .installations
            .iter()
            .map(|i| (i.installation, (&i.image_digest, &i.manifest_digest)))
            .collect();
        if installed.len() != wanted.len()
            || installed.iter().any(|r| {
                wanted
                    .get(&r.get::<_, Uuid>("id"))
                    .is_none_or(|(image, manifest)| {
                        r.get::<_, String>("image_digest") != **image
                            || r.get::<_, String>("manifest_digest") != **manifest
                    })
            })
        {
            return Err(Error::conflict(
                "Imported installations differ from the platform manifest",
            ));
        }
        if let Some(image) = &self.manifest.images {
            workspace.discard_staged(true)?;
            let file =
                workspace.reserve_file(true, image.data.plaintext.bytes, 128 * 1024 * 1024)?;
            let restored = self
                .pool
                .raw(None)
                .download_file(
                    self.repository.objects.clone(),
                    raw::Target::new(file)?,
                    raw::Object {
                        backup: self.receipt.backup_id,
                        object: image.data.object,
                        maximum_bytes: image.data.plaintext.bytes,
                    },
                    zeroize::Zeroizing::new(*self.master),
                    raw::Expected {
                        plaintext: image.data.plaintext.clone(),
                        ciphertext: image.data.ciphertext.clone(),
                    },
                    std::time::Duration::from_secs(300),
                )?
                .wait()
                .await?;
            self.session.check_leader()?;
            let mut file = tokio::fs::File::from_std(restored.file);
            self.session
                .runtime
                .resume_images(&mut file, &image.archive)
                .await?;
            let mut refs = std::collections::BTreeMap::new();
            for installation in &self.manifest.installations {
                if refs
                    .insert(&installation.image_digest, &installation.image)
                    .is_some_and(|old| old != &installation.image)
                {
                    return Err(Error::conflict("Restored image index aliases disagree"));
                }
            }
            for (hash, image) in refs {
                super::workspace::image_index(&self.session.root, hash, image)?;
            }
            self.session.installation_images(&c).await?;
        }
        self.session.check_leader()?;
        let header = workspace.header()?;
        let mut context = header.context;
        context["images_verified"] = Value::Bool(true);
        workspace.update_header(&header.phase, context)
    }
    /// Preserve logical Blob UUIDs while binding a new private physical root.
    /// Every existing completed target is re-read; partial staging is unpublished.
    pub async fn restore_blobs(&mut self) -> Result<()> {
        self.require_rebuilding().await?;
        let workspace = self
            .workspace
            .as_ref()
            .ok_or_else(|| Error::conflict("Recovery workspace is unavailable"))?;
        let mut c = self.session.db.connect().await?;
        let rows = c
            .query(
                "SELECT id,size_bytes,digest,backend_reference FROM blobs ORDER BY id LIMIT 65537",
                &[],
            )
            .await?;
        if rows.len() > 65536 || rows.len() as u64 != self.manifest.blob_count {
            return Err(Error::conflict("Imported Blob count differs"));
        }
        let mut header = workspace.header()?;
        if let Some(source) = self.manifest.blob_root {
            let root = match header.context["blob_root"].as_str() {
                Some(id) => {
                    Uuid::parse_str(id).map_err(|_| Error::invalid("Invalid recovery Blob root"))?
                }
                None => {
                    let id = Uuid::new_v4();
                    header.context["blob_root"] = serde_json::json!(id);
                    workspace.update_header(&header.phase, header.context.clone())?;
                    id
                }
            };
            if root.is_nil() || root == source {
                return Err(Error::conflict(
                    "Recovery Blob root must have a new identity",
                ));
            }
            let tx = c.transaction().await?;
            let binding = tx
                .query_one("SELECT id FROM blob_storage_root FOR UPDATE", &[])
                .await?;
            let current: Uuid = binding.get(0);
            if current != source && current != root {
                return Err(Error::conflict("Recovery Blob storage identity differs"));
            }
            tx.execute(
                "UPDATE blob_storage_root SET id=$1,state='preparing' WHERE id=$2",
                &[&root, &current],
            )
            .await?;
            tx.commit().await?;
            self.session.check_leader()?;
            let store = crate::storage::blob::Store::open(&self.session.runtime.config.root())?;
            store.identity(root, true)?;
            let pool = self.pool.raw(None);
            for row in rows {
                self.session.check_leader()?;
                let id: Uuid = row.get("id");
                let bytes: i64 = row.get("size_bytes");
                let hash: String = row.get("digest");
                if id.is_nil()
                    || !(0..=67108864).contains(&bytes)
                    || !valid_digest(&hash)
                    || row.get::<_, String>("backend_reference") != id.to_string()
                {
                    return Err(Error::conflict("Imported Blob source metadata is invalid"));
                }
                match store.open_optional(id)? {
                    Some(_) => {
                        let verify = store.clone();
                        let hash = hash.clone();
                        tokio::task::spawn_blocking(move || verify.verify(id, bytes as u64, &hash))
                            .await
                            .map_err(|_| {
                                Error::unavailable("Blob verification worker stopped")
                            })??;
                    }
                    None => {
                        let stage_store = store.clone();
                        let mut staged = tokio::task::spawn_blocking(move || {
                            stage_store.stage_empty(bytes as u64)
                        })
                        .await
                        .map_err(|_| Error::unavailable("Blob staging worker stopped"))??;
                        let target = staged
                            .file
                            .as_ref()
                            .unwrap()
                            .try_clone()
                            .await?
                            .into_std()
                            .await;
                        let restored = pool
                            .download_file(
                                self.repository.objects.clone(),
                                raw::Target::new(target)?,
                                raw::Object {
                                    backup: self.receipt.backup_id,
                                    object: id,
                                    maximum_bytes: bytes as u64,
                                },
                                zeroize::Zeroizing::new(*self.master),
                                raw::Expected {
                                    plaintext: crate::storage::backup_crypto::Summary {
                                        bytes: bytes as u64,
                                        digest: hash,
                                    },
                                    ciphertext: None,
                                },
                                std::time::Duration::from_secs(300),
                            )?
                            .wait()
                            .await?;
                        self.session.check_leader()?;
                        drop(restored);
                        staged.publish(id).await?;
                    }
                }
            }
            self.session.check_leader()?;
            c.execute(
                "UPDATE blob_storage_root SET state='ready' WHERE id=$1",
                &[&root],
            )
            .await?;
        } else if !rows.is_empty()
            || c.query_one("SELECT EXISTS(SELECT 1 FROM blob_storage_root)", &[])
                .await?
                .get::<_, bool>(0)
        {
            return Err(Error::conflict("Unexpected imported Blob storage root"));
        }
        self.session.check_leader()?;
        let mut header = workspace.header()?;
        header.context["blobs_verified"] = Value::Bool(true);
        workspace.update_header(&header.phase, header.context)
    }
}
#[cfg(test)]
#[path = "offline_restore_tests.rs"]
mod tests;
