//! Durable single-node volume allocation, capacity admission and recovery.
//! Filesystem work is performed by the bounded storage worker, never an API
//! transaction. Writer attachment transfer is separately fenced by runtime proof.
use crate::{
    api::{self, App},
    auth::{self, Context, Resource},
    db,
    error::{Error, Result},
    storage::xfs::{Limits, ProjectStatus, ProjectStore, ROOT_LOCK_BUSY},
};
use axum::http::HeaderMap;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio_postgres::GenericClient;
use uuid::Uuid;
const ROOT_LOCK: i64 = 0x58454c564f4c5254;
const TOMBSTONE: i64 = 65536;
#[cfg(test)]
#[path = "volumes_restore_tests.rs"]
mod restore_tests;
#[derive(serde::Serialize)]
pub struct BackupSource {
    pub id: Uuid,
    pub spec: Value,
    pub capacity_bytes: u64,
    pub data_schema_version: Option<String>,
    pub filesystem_uuid: Uuid,
    pub project_id: u32,
    #[serde(skip)]
    pub path: std::path::PathBuf,
}
/// Paths are returned only for this job's durable holds and exact admitted
/// namespace/quota. The worker must retain the holds until all reads settle.
pub async fn backup_sources(app: &App, operation: Uuid, ids: &[Uuid]) -> Result<Vec<BackupSource>> {
    let c = app.db.connect().await?;
    let rows=c.query("SELECT a.*,r.filesystem_uuid,v.spec AS volume_spec FROM volume_allocations a JOIN volume_storage_root r ON r.id=a.root_id JOIN volumes v ON v.id=a.volume_id JOIN volume_holds h ON h.volume_id=a.volume_id WHERE a.volume_id=ANY($1) AND h.operation_id=$2 AND a.state='ready' AND r.state='ready' ORDER BY a.volume_id", &[&ids,&operation]).await?;
    if rows.len() != ids.len() || rows.is_empty() || rows.len() > 16 {
        return Err(Error::conflict("Backup source holds or allocations differ"));
    }
    let path = app.config.root().join("volumes");
    blocking(move || {
        let mut store = ProjectStore::open(&path)?;
        let root: Uuid = rows[0].get("root_id");
        let filesystem: Uuid = rows[0].get("filesystem_uuid");
        store.namespace_identity(filesystem, root, false)?;
        let mut sources = Vec::new();
        for row in rows {
            let volume: Uuid = row.get("volume_id");
            let project = row.get::<_, i32>("project_id") as u32;
            let limits = Limits {
                capacity_bytes: row.get::<_, i64>("capacity_bytes") as u64,
                inodes: row.get::<_, i64>("inode_limit") as u64,
            };
            if row.get::<_, Uuid>("root_id") != root
                || row.get::<_, Uuid>("filesystem_uuid") != filesystem
                || store.inspect(volume, project)?.limits != limits
            {
                return Err(Error::unavailable(
                    "Backup source namespace or quota differs",
                ));
            }
            sources.push(BackupSource {
                id: volume,
                spec: row.get("volume_spec"),
                capacity_bytes: limits.capacity_bytes,
                data_schema_version: row.get("data_schema_version"),
                filesystem_uuid: filesystem,
                project_id: project,
                path: store.data_path(volume, project)?,
            });
        }
        Ok(sources)
    })
    .await
}
#[derive(Clone, Copy)]
struct Binding {
    id: Uuid,
    filesystem: Uuid,
}
pub(crate) struct RestorePlan {
    bound: Binding,
    volumes: Vec<(Uuid, Value, Option<String>, Limits, i64)>,
}
/// Compute geometry before the API takes root/deployment row locks; binding
/// recovery uses a separate short transaction and cannot run under those locks.
pub(crate) async fn plan_restore(
    app: &App,
    volumes: Vec<(Uuid, Value, Option<String>)>,
) -> Result<RestorePlan> {
    if volumes.is_empty() || volumes.len() > 16 {
        return Err(Error::invalid("Invalid restore volume group"));
    }
    let bound = binding(app).await?;
    let mut planned = Vec::new();
    for (id, spec, schema) in volumes {
        crate::contracts::validate("VolumeSpec", &spec)?;
        let capacity = spec["capacity_bytes"]
            .as_u64()
            .ok_or_else(|| Error::invalid("Invalid restore capacity"))?;
        let (limits, charge) = geometry(app, bound, capacity).await?;
        planned.push((id, spec, schema, limits, charge));
    }
    Ok(RestorePlan {
        bound,
        volumes: planned,
    })
}
/// Persist all bytes/inodes and unique project IDs before any filesystem work.
pub(crate) async fn reserve_restore(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    operation: Uuid,
    plan: RestorePlan,
) -> Result<()> {
    let total = plan
        .volumes
        .iter()
        .try_fold(0i64, |sum, (_, _, _, limits, charge)| {
            sum.checked_add(limits.capacity_bytes as i64)
                .and_then(|n| n.checked_add(*charge))
                .ok_or_else(Error::exhausted)
        })?;
    budget(c, plan.bound, total).await?;
    for (id, spec, schema, limits, charge) in plan.volumes {
        let project: i64 = c
            .query_one("SELECT nextval('volume_project_ids')", &[])
            .await?
            .get(0);
        let project = i32::try_from(project).map_err(|_| Error::exhausted())?;
        c.execute("INSERT INTO volume_allocations(volume_id,root_id,project_id,owner_id,spec,capacity_bytes,inode_limit,metadata_charge,desired_capacity,desired_inodes,desired_metadata_charge,state,operation_id,credential_id,peer,data_schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$6,$7,$8,'restoring',$9,$10,$11::text::inet,$12)",&[&id,&plan.bound.id,&project,&ctx.subject,&spec,&(limits.capacity_bytes as i64),&(limits.inodes as i64),&charge,&operation,&ctx.credential,&ctx.peer.to_string(),&schema]).await?;
    }
    Ok(())
}
/// A restore owns this UUID/project exclusively. A partially extracted tree is
/// failed/quarantined instead of being treated as an empty retry destination.
pub(crate) async fn private_restore_path(
    app: &App,
    operation: Uuid,
    volume: Uuid,
    create: bool,
) -> Result<BackupSource> {
    let c = app.db.connect().await?;
    let row=c.query_opt("SELECT a.*,r.filesystem_uuid FROM volume_allocations a JOIN volume_storage_root r ON r.id=a.root_id WHERE a.volume_id=$1 AND a.operation_id=$2 AND a.state IN ('restoring','restored') AND r.state='ready' AND NOT EXISTS(SELECT 1 FROM volumes v WHERE v.id=a.volume_id)",&[&volume,&operation]).await?.ok_or_else(||Error::conflict("Restore allocation is not private"))?;
    let path = app.config.root().join("volumes");
    blocking(move || {
        let mut store = ProjectStore::open(&path)?;
        let filesystem: Uuid = row.get("filesystem_uuid");
        let project = row.get::<_, i32>("project_id") as u32;
        let limits = Limits {
            capacity_bytes: row.get::<_, i64>("capacity_bytes") as u64,
            inodes: row.get::<_, i64>("inode_limit") as u64,
        };
        store.namespace_identity(filesystem, row.get("root_id"), false)?;
        if create {
            store.recover_create(volume, project, limits)?;
            store.prepare_data(volume, project)?;
        }
        if store.inspect(volume, project)?.limits != limits {
            return Err(Error::unavailable("Restore quota differs from reservation"));
        }
        Ok(BackupSource {
            id: volume,
            spec: row.get("spec"),
            capacity_bytes: limits.capacity_bytes,
            data_schema_version: row.get("data_schema_version"),
            filesystem_uuid: filesystem,
            project_id: project,
            path: store.data_path(volume, project)?,
        })
    })
    .await
}
pub(crate) struct RestorePublication {
    operation: Uuid,
    items: Vec<(Uuid, Uuid, Uuid, Uuid, Value, u32, ProjectStatus)>,
}
/// Inspect the filesystem before taking the final authorization transaction.
pub(crate) async fn prepare_restore_publication(
    app: &App,
    operation: Uuid,
    ids: &[Uuid],
) -> Result<RestorePublication> {
    let c = app.db.connect().await?;
    let rows=c.query("SELECT a.*,r.filesystem_uuid FROM volume_allocations a JOIN volume_storage_root r ON r.id=a.root_id JOIN operations o ON o.id=a.operation_id AND o.owner_id=a.owner_id WHERE a.volume_id=ANY($1) AND a.operation_id=$2 AND a.state='restored' AND r.state='ready' ORDER BY a.volume_id",&[&ids,&operation]).await?;
    if rows.len() != ids.len() {
        return Err(Error::conflict(
            "Restore verification journal is incomplete",
        ));
    }
    let path = app.config.root().join("volumes");
    let statuses = blocking(move || {
        let mut store = ProjectStore::open(&path)?;
        let mut out = Vec::new();
        for row in rows {
            let id: Uuid = row.get("volume_id");
            let project = row.get::<_, i32>("project_id") as u32;
            let fs: Uuid = row.get("filesystem_uuid");
            store.namespace_identity(fs, row.get("root_id"), false)?;
            let status = store.inspect(id, project)?;
            if status.limits.capacity_bytes != row.get::<_, i64>("capacity_bytes") as u64
                || status.limits.inodes != row.get::<_, i64>("inode_limit") as u64
            {
                return Err(Error::unavailable("Restored quota differs"));
            }
            store.data_path(id, project)?;
            out.push((
                id,
                row.get::<_, Uuid>("root_id"),
                fs,
                row.get::<_, Uuid>("owner_id"),
                row.get::<_, Value>("spec"),
                project,
                status,
            ));
        }
        Ok(out)
    })
    .await?;
    Ok(RestorePublication {
        operation,
        items: statuses,
    })
}
/// Publish metadata without filesystem/network I/O after checking that the
/// reservation still matches its inspected namespace and limits.
pub(crate) async fn publish_restored(
    c: &(impl GenericClient + Sync),
    publication: RestorePublication,
) -> Result<()> {
    let root = c
        .query_one(
            "SELECT id,filesystem_uuid FROM volume_storage_root WHERE state='ready' FOR UPDATE",
            &[],
        )
        .await?;
    for (id, root_id, filesystem, owner, spec, project, status) in publication.items {
        let row=c.query_one("SELECT * FROM volume_allocations WHERE volume_id=$1 AND operation_id=$2 AND state='restored' FOR UPDATE",&[&id,&publication.operation]).await?;
        if root.get::<_, Uuid>("id") != root_id
            || root.get::<_, Uuid>("filesystem_uuid") != filesystem
            || row.get::<_, Uuid>("root_id") != root_id
            || row.get::<_, Uuid>("owner_id") != owner
            || row.get::<_, i32>("project_id") as u32 != project
            || row.get::<_, Value>("spec") != spec
            || row.get::<_, i64>("capacity_bytes") as u64 != status.limits.capacity_bytes
            || row.get::<_, i64>("inode_limit") as u64 != status.limits.inodes
        {
            return Err(Error::conflict(
                "Restore reservation changed after verification",
            ));
        }
        let backend = format!("xfs:{filesystem}:{project}");
        let full = status.used_bytes >= status.limits.capacity_bytes
            || status.used_inodes >= status.limits.inodes;
        let state = if full { "full" } else { "available" };
        c.execute("INSERT INTO volumes(id,owner_id,spec,backend_id,capacity_bytes,used_bytes,write_fence,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,1,$7,now(),now())",&[&id,&owner,&spec,&backend,&(status.limits.capacity_bytes as i64),&(status.used_bytes as i64),&state]).await?;
        if full {
            db::outbox(c, "volume_full", id, &json!({"volume_id":id})).await?;
        }
        c.execute(
            "UPDATE volume_allocations SET state='ready',updated_at=now() WHERE volume_id=$1",
            &[&id],
        )
        .await?;
    }
    Ok(())
}
pub fn handles(name: &str) -> bool {
    matches!(
        name,
        "createVolume" | "getVolume" | "listVolumes" | "resizeVolume" | "deleteVolume"
    )
}
pub fn confirm_delete(params: &HashMap<String, String>, query: &str) -> Result<()> {
    let values: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    if values.len() != 1
        || values[0].0 != "confirm_volume_id"
        || values[0].1.parse::<Uuid>().ok() != Some(api::path_id(params, "volume_id")?)
    {
        return Err(Error::invalid(
            "confirm_volume_id must equal the path volume ID",
        ));
    }
    Ok(())
}
pub async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
) -> Result<()> {
    if name == "listVolumes" {
        return Ok(());
    }
    let (action, resource) = if name == "createVolume" {
        (
            "volume.create",
            Resource::new("volume", "new", Some(ctx.subject)),
        )
    } else {
        let id = api::path_id(params, "volume_id")?;
        let row = c
            .query_opt("SELECT owner_id FROM volumes WHERE id=$1", &[&id])
            .await?
            .ok_or_else(Error::not_found)?;
        (
            match name {
                "getVolume" => "volume.read",
                "resizeVolume" => "volume.resize",
                "deleteVolume" => "volume.delete",
                _ => return Err(Error::not_found()),
            },
            Resource::new("volume", id, Some(row.get(0))),
        )
    };
    auth::authorize(c, ctx, action, &resource)
        .await
        .map_err(|e| {
            if name == "getVolume" && e.code == "PERMISSION_DENIED" {
                Error::not_found()
            } else {
                e
            }
        })
}
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| Error::unavailable("Volume worker stopped"))?
        .map_err(|error| {
            if error.code == "PERMISSION_DENIED" {
                Error::unavailable("Volume backend requires host privileges")
            } else {
                error
            }
        })
}
async fn binding(app: &App) -> Result<Binding> {
    let path = app.config.root().join("volumes");
    let status = blocking(move || {
        let store = ProjectStore::open(&path)?;
        store.verify_mount_root()?;
        store.status()
    })
    .await?;
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ROOT_LOCK])
        .await?;
    tx.execute("INSERT INTO volume_storage_root(id,filesystem_uuid,state) VALUES($1,$2,'preparing') ON CONFLICT(singleton) DO NOTHING",&[&Uuid::new_v4(),&status.filesystem_uuid]).await?;
    tx.commit().await?;
    let tx = c.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ROOT_LOCK])
        .await?;
    let row = tx
        .query_one("SELECT * FROM volume_storage_root FOR UPDATE", &[])
        .await?;
    let bound = Binding {
        id: row.get("id"),
        filesystem: row.get("filesystem_uuid"),
    };
    if bound.filesystem != status.filesystem_uuid {
        return Err(Error::unavailable(
            "Volume filesystem differs from durable binding",
        ));
    }
    let creating = row.get::<_, String>("state") == "preparing";
    let path = app.config.root().join("volumes");
    let capacity = blocking(move || {
        let mut store = ProjectStore::open(&path)?;
        store.namespace_identity(bound.filesystem, bound.id, creating)?;
        let status = store.status()?;
        let available = store
            .available_bytes()?
            .saturating_sub(64 * 1024 * 1024)
            .min(9_007_199_254_740_991);
        Ok(available / status.block_size * status.block_size)
    })
    .await?;
    if creating {
        if capacity < 1048576 {
            return Err(Error::exhausted());
        }
        tx.execute(
            "UPDATE volume_storage_root SET state='ready',capacity_bytes=$2 WHERE id=$1",
            &[&bound.id, &(capacity as i64)],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(bound)
}
async fn geometry(app: &App, bound: Binding, capacity: u64) -> Result<(Limits, i64)> {
    let path = app.config.root().join("volumes");
    blocking(move || {
        let mut store = ProjectStore::open(&path)?;
        store.namespace_identity(bound.filesystem, bound.id, false)?;
        let limits = store.aligned_limits(capacity)?;
        let charge = store.metadata_charge(limits)?;
        let charge = i64::try_from(charge).map_err(|_| Error::exhausted())?;
        Ok((limits, charge))
    })
    .await
}
async fn budget(c: &impl GenericClient, bound: Binding, additional: i64) -> Result<()> {
    let row = c
        .query_one(
            "SELECT * FROM volume_storage_root WHERE id=$1 FOR UPDATE",
            &[&bound.id],
        )
        .await?;
    if row.get::<_, String>("state") != "ready"
        || row.get::<_, Uuid>("filesystem_uuid") != bound.filesystem
    {
        return Err(Error::unavailable("Volume namespace is not ready"));
    }
    let next = row
        .get::<_, i64>("reserved_bytes")
        .checked_add(additional)
        .filter(|n| *n >= 0 && *n <= row.get::<_, i64>("capacity_bytes"))
        .ok_or_else(Error::exhausted)?;
    c.execute(
        "UPDATE volume_storage_root SET reserved_bytes=$2 WHERE id=$1",
        &[&bound.id, &next],
    )
    .await?;
    Ok(())
}
pub async fn value(c: &(impl GenericClient + Sync), volume: Uuid) -> Result<Value> {
    api::read_object(c, "kernel_volumes", volume, "Volume").await
}
// Live observations come from kernel quota accounting, including inode exhaustion.
async fn observe(c: &(impl GenericClient + Sync), app: &App, ids: &[Uuid]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    c.query("SELECT id FROM volume_storage_root FOR UPDATE", &[])
        .await?;
    let rows = c.query("SELECT a.*,r.id,r.filesystem_uuid FROM volume_allocations a JOIN volume_storage_root r ON r.id=a.root_id WHERE a.volume_id=ANY($1) AND a.state<>'deleted' ORDER BY a.volume_id FOR UPDATE OF a", &[&ids]).await?;
    if rows.is_empty() {
        return Ok(());
    }
    if rows
        .iter()
        .any(|r| r.get::<_, String>("state") == "quarantined")
    {
        return Err(Error::unavailable("Volume needs operator recovery"));
    }
    let bound = Binding {
        id: rows[0].get("id"),
        filesystem: rows[0].get("filesystem_uuid"),
    };
    let projects: Vec<_> = rows
        .iter()
        .filter(|r| matches!(r.get::<_, String>("state").as_str(), "ready" | "resizing"))
        .map(|r| {
            (
                r.get::<_, Uuid>("volume_id"),
                r.get::<_, i32>("project_id") as u32,
                Limits {
                    capacity_bytes: r.get::<_, i64>("capacity_bytes") as u64,
                    inodes: r.get::<_, i64>("inode_limit") as u64,
                },
                Limits {
                    capacity_bytes: r.get::<_, i64>("desired_capacity") as u64,
                    inodes: r.get::<_, i64>("desired_inodes") as u64,
                },
            )
        })
        .collect();
    let path = app.config.root().join("volumes");
    let observed = blocking(move || {
        let mut store = ProjectStore::open(&path)?;
        store.namespace_identity(bound.filesystem, bound.id, false)?;
        projects
            .into_iter()
            .map(|(id, project, current, desired)| {
                let status = store.inspect(id, project)?;
                if status.limits != current && status.limits != desired {
                    return Err(Error::unavailable(
                        "Volume quota differs from durable intent",
                    ));
                }
                Ok((id, status))
            })
            .collect::<Result<Vec<_>>>()
    })
    .await?;
    for (id, status) in observed {
        let full = status.used_bytes >= status.limits.capacity_bytes
            || status.used_inodes >= status.limits.inodes;
        let row = c
            .query_one("SELECT state FROM volumes WHERE id=$1 FOR UPDATE", &[&id])
            .await?;
        let previous: String = row.get(0);
        if matches!(previous.as_str(), "deleting" | "deleted") {
            continue;
        }
        let attached = c
            .query_opt(
                "SELECT instance_id FROM volume_attachments WHERE volume_id=$1 LIMIT 1",
                &[&id],
            )
            .await?
            .is_some();
        let state = if full {
            "full"
        } else if attached {
            "attached"
        } else {
            "available"
        };
        c.execute("UPDATE volumes SET used_bytes=$2,state=$3,revision=revision+CASE WHEN used_bytes<>$2 OR state<>$3 THEN 1 ELSE 0 END,updated_at=CASE WHEN used_bytes<>$2 OR state<>$3 THEN now() ELSE updated_at END WHERE id=$1",&[&id,&(status.used_bytes as i64),&state]).await?;
        c.execute(
            "UPDATE volume_allocations SET observed_at=now() WHERE volume_id=$1",
            &[&id],
        )
        .await?;
        if full && previous != "full" {
            db::outbox(c, "volume_full", id, &json!({"volume_id":id})).await?;
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)] // Operation arguments mirror the API transaction envelope.
pub async fn execute(
    c: &(impl GenericClient + Sync),
    app: &App,
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
    headers: &HeaderMap,
    query: &str,
) -> Result<(Value, u16)> {
    if name == "listVolumes" {
        let mut page = crate::identity::list(c, &app.auth, ctx, name, params, query).await?;
        let ids: Vec<Uuid> = page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap().parse().unwrap())
            .collect();
        observe(c, app, &ids).await?;
        for item in page["items"].as_array_mut().unwrap() {
            *item = value(c, item["id"].as_str().unwrap().parse().unwrap()).await?;
        }
        return Ok((page, 200));
    }
    let volume = if name == "createVolume" {
        Uuid::new_v4()
    } else {
        api::path_id(params, "volume_id")?
    };
    if name == "getVolume" {
        observe(c, app, &[volume]).await?;
        return Ok((value(c, volume).await?, 200));
    }
    if !app.ready.load(Ordering::SeqCst) {
        return Err(Error::unavailable(
            "Volume mutations wait for startup runtime fencing",
        ));
    }
    let bound = binding(app).await?;
    if name == "createVolume" {
        let capacity = body["capacity_bytes"].as_u64().unwrap();
        let (limits, charge) = geometry(app, bound, capacity).await?;
        budget(
            c,
            bound,
            (capacity as i64)
                .checked_add(charge)
                .ok_or_else(Error::exhausted)?,
        )
        .await?;
        let project: i64 = c
            .query_one("SELECT nextval('volume_project_ids')", &[])
            .await?
            .get(0);
        let project = i32::try_from(project).map_err(|_| Error::exhausted())?;
        let operation = db::operation(c, ctx.subject, name, Some(volume.to_string())).await?;
        let peer = ctx.peer.to_string();
        c.execute("INSERT INTO volume_allocations(volume_id,root_id,project_id,owner_id,spec,capacity_bytes,inode_limit,metadata_charge,desired_capacity,desired_inodes,desired_metadata_charge,state,operation_id,credential_id,peer) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$6,$7,$8,'creating',$9,$10,$11::text::inet)",&[&volume,&bound.id,&project,&ctx.subject,&body,&(capacity as i64),&(limits.inodes as i64),&charge,&operation,&ctx.credential,&peer]).await?;
        return Ok((db::operation_value(c, operation).await?, 202));
    }
    c.query_one(
        "SELECT id FROM volume_storage_root WHERE id=$1 FOR UPDATE",
        &[&bound.id],
    )
    .await?;
    let allocation = c
        .query_one(
            "SELECT * FROM volume_allocations WHERE volume_id=$1 FOR UPDATE",
            &[&volume],
        )
        .await?;
    let row = c
        .query_one("SELECT * FROM volumes WHERE id=$1 FOR UPDATE", &[&volume])
        .await?;
    api::etag(headers, row.get("revision"))?;
    if allocation.get::<_, Uuid>("root_id") != bound.id {
        return Err(Error::unavailable("Volume belongs to another storage root"));
    }
    let state = allocation.get::<_, String>("state");
    if state != "ready" && !(name == "deleteVolume" && state == "quarantined") {
        return Err(Error::conflict(
            "Volume already has an active storage operation",
        ));
    }
    if c.query_opt(
        "SELECT volume_id FROM volume_holds WHERE volume_id=$1",
        &[&volume],
    )
    .await?
    .is_some()
    {
        return Err(Error::conflict("Volume is held by recovery or migration"));
    }
    let operation = db::operation(c, ctx.subject, name, Some(volume.to_string())).await?;
    let peer = ctx.peer.to_string();
    if name == "resizeVolume" {
        let capacity = body["capacity_bytes"].as_u64().unwrap();
        if capacity <= row.get::<_, i64>("capacity_bytes") as u64 {
            return Err(Error::conflict("Volume capacity can only grow"));
        }
        let (limits, charge) = geometry(app, bound, capacity).await?;
        let additional = (capacity as i64)
            .checked_sub(allocation.get("capacity_bytes"))
            .and_then(|n| n.checked_add(charge - allocation.get::<_, i64>("metadata_charge")))
            .ok_or_else(Error::exhausted)?;
        budget(c, bound, additional).await?;
        c.execute("UPDATE volume_allocations SET desired_capacity=$2,desired_inodes=$3,desired_metadata_charge=$4,state='resizing',operation_id=$5,credential_id=$6,peer=$7::text::inet,updated_at=now() WHERE volume_id=$1",&[&volume,&(capacity as i64),&(limits.inodes as i64),&charge,&operation,&ctx.credential,&peer]).await?;
    } else {
        if c.query_opt(
            "SELECT instance_id FROM volume_attachments WHERE volume_id=$1 LIMIT 1",
            &[&volume],
        )
        .await?
        .is_some()
        {
            return Err(Error::conflict("Volume is still attached"));
        }
        c.execute("UPDATE volume_allocations SET state='deleting',operation_id=$2,credential_id=$3,peer=$4::text::inet,updated_at=now() WHERE volume_id=$1",&[&volume,&operation,&ctx.credential,&peer]).await?;
        c.execute(
            "UPDATE volumes SET state='deleting',revision=revision+1,updated_at=now() WHERE id=$1",
            &[&volume],
        )
        .await?;
    }
    Ok((db::operation_value(c, operation).await?, 202))
}

async fn job_authority(
    c: &(impl GenericClient + Sync),
    app: &App,
    row: &tokio_postgres::Row,
) -> Result<Context> {
    let peer = row
        .get::<_, String>("approved_peer")
        .parse()
        .map_err(|_| Error::denied())?;
    let operation: Uuid = row.get("operation_id");
    let ctx = app
        .auth
        .resume(c, row.get("credential_id"), peer, operation)
        .await?;
    let state: String = row.get("state");
    let (action, resource) = if state == "creating" {
        (
            "volume.create",
            Resource::new("volume", "new", Some(row.get("owner_id"))),
        )
    } else {
        (
            if state == "resizing" {
                "volume.resize"
            } else {
                "volume.delete"
            },
            Resource::new(
                "volume",
                row.get::<_, Uuid>("volume_id"),
                Some(row.get("owner_id")),
            ),
        )
    };
    auth::authorize(c, &ctx, action, &resource).await?;
    Ok(ctx)
}
async fn fail_job(c: &impl GenericClient, row: &tokio_postgres::Row, error: Error) -> Result<()> {
    let volume: Uuid = row.get("volume_id");
    let operation: Uuid = row.get("operation_id");
    c.execute(
        "UPDATE volume_allocations SET state='quarantined',updated_at=now() WHERE volume_id=$1",
        &[&volume],
    )
    .await?;
    db::complete(c, operation, Err(error)).await
}
struct Outcome {
    status: Option<ProjectStatus>,
    removed: bool,
}
async fn process(app: &App, bound: Binding, volume: Uuid) -> Result<()> {
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    db::auth_lock(&tx, false).await?;
    tx.query_one(
        "SELECT id FROM volume_storage_root WHERE id=$1 FOR UPDATE",
        &[&bound.id],
    )
    .await?;
    let Some(row)=tx.query_opt("SELECT a.*,host(a.peer) AS approved_peer FROM volume_allocations a WHERE volume_id=$1 FOR UPDATE",&[&volume]).await?else{return Ok(())};
    let state: String = row.get("state");
    if state == "ready" || state == "deleted" {
        return Ok(());
    }
    let public = tx
        .query_opt("SELECT id FROM volumes WHERE id=$1", &[&volume])
        .await?
        .is_some();
    if state == "quarantined" && public {
        return Ok(());
    }
    tx.execute(
        "UPDATE volume_allocations SET updated_at=now() WHERE volume_id=$1",
        &[&volume],
    )
    .await?;
    if state != "quarantined" {
        if let Err(error) = job_authority(&tx, app, &row).await {
            fail_job(&tx, &row, error).await?;
            tx.commit().await?;
            return Ok(());
        }
    }

    let operation: Uuid = row.get("operation_id");
    let project = row.get::<_, i32>("project_id") as u32;
    let limits = Limits {
        capacity_bytes: row.get::<_, i64>("desired_capacity") as u64,
        inodes: row.get::<_, i64>("desired_inodes") as u64,
    };
    tx.execute(
        "UPDATE operations SET state='running',updated_at=now() WHERE id=$1 AND state='pending'",
        &[&operation],
    )
    .await?;
    tx.commit().await?;
    let path = app.config.root().join("volumes");
    let action = state.clone();
    let result = blocking(move || {
        let Some(mut store) = ProjectStore::try_open(&path)? else {
            return Ok(None);
        };
        store.namespace_identity(bound.filesystem, bound.id, false)?;
        let outcome = match action.as_str() {
            "creating" => {
                store.recover_create(volume, project, limits)?;
                store.prepare_data(volume, project)?;
                Ok(Outcome {
                    status: Some(store.inspect(volume, project)?),
                    removed: false,
                })
            }
            "resizing" => {
                let current = store.inspect(volume, project)?;
                let status = if current.limits == limits {
                    current
                } else {
                    store.expand(volume, project, limits)?
                };
                Ok(Outcome {
                    status: Some(status),
                    removed: false,
                })
            }
            "deleting" => Ok(Outcome {
                status: None,
                removed: store.remove_data(volume, project)?,
            }),
            "quarantined" => Ok(Outcome {
                status: None,
                removed: store.discard_create(volume, project)?,
            }),
            _ => Err(Error::conflict("Unknown volume intent")),
        }?;
        Ok(Some(outcome))
    })
    .await;
    let result = match result {
        Ok(None) => return Ok(()),
        Ok(Some(outcome)) => Ok(outcome),
        Err(error) => Err(error),
    };
    let tx = c.transaction().await?;
    db::auth_lock(&tx, false).await?;
    tx.query_one(
        "SELECT id FROM volume_storage_root WHERE id=$1 FOR UPDATE",
        &[&bound.id],
    )
    .await?;
    let current=tx.query_one("SELECT a.*,host(a.peer) AS approved_peer FROM volume_allocations a WHERE volume_id=$1 FOR UPDATE",&[&volume]).await?;
    if current.get::<_, Uuid>("operation_id") != operation
        || current.get::<_, String>("state") != state
    {
        return Err(Error::conflict(
            "Volume intent changed during filesystem work",
        ));
    }
    let outcome = match result {
        Ok(value) => value,
        Err(error) => {
            fail_job(&tx, &current, error).await?;
            tx.commit().await?;
            return Ok(());
        }
    };
    let authority = if state == "quarantined" {
        None
    } else {
        job_authority(&tx, app, &current).await.ok()
    };
    if state == "creating" && authority.is_none() {
        fail_job(&tx, &current, Error::credential()).await?;
        tx.commit().await?;
        return Ok(());
    }
    match state.as_str() {
        "creating" => {
            let status = outcome.status.unwrap();
            let owner: Uuid = current.get("owner_id");
            let spec: Value = current.get("spec");
            let backend = format!("xfs:{}:{project}", bound.filesystem);
            tx.execute("INSERT INTO volumes(id,owner_id,spec,backend_id,capacity_bytes,used_bytes,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'available',now(),now())",&[&volume,&owner,&spec,&backend,&(status.limits.capacity_bytes as i64),&(status.used_bytes as i64)]).await?;
            tx.execute(
                "UPDATE volume_allocations SET state='ready',updated_at=now() WHERE volume_id=$1",
                &[&volume],
            )
            .await?;
            db::complete(&tx, operation, Ok(json!({"volume_id":volume}))).await?;
        }
        "resizing" => {
            let status = outcome.status.unwrap();
            let mut spec: Value = tx
                .query_one(
                    "SELECT spec FROM volumes WHERE id=$1 FOR UPDATE",
                    &[&volume],
                )
                .await?
                .get(0);
            spec["capacity_bytes"] = json!(status.limits.capacity_bytes);
            tx.execute("UPDATE volumes SET spec=$2,capacity_bytes=$3,used_bytes=$4,revision=revision+1,updated_at=now() WHERE id=$1",&[&volume,&spec,&(status.limits.capacity_bytes as i64),&(status.used_bytes as i64)]).await?;
            tx.execute("UPDATE volume_allocations SET capacity_bytes=desired_capacity,inode_limit=desired_inodes,metadata_charge=desired_metadata_charge,state='ready',spec=$2,updated_at=now() WHERE volume_id=$1",&[&volume,&spec]).await?;
            if authority.is_some() {
                db::complete(&tx, operation, Ok(json!({"volume_id":volume}))).await?;
            } else {
                db::complete(
                    &tx,
                    operation,
                    Err(Error::conflict(
                        "Capacity changed before authorization was withdrawn; inspect the volume",
                    )),
                )
                .await?;
            }
        }
        "deleting" | "quarantined" if outcome.removed => {
            let release = current.get::<_, i64>("desired_capacity")
                + current.get::<_, i64>("desired_metadata_charge")
                - TOMBSTONE;
            budget(&tx, bound, -release).await?;
            tx.execute("UPDATE volume_allocations SET state='deleted',metadata_charge=$2,desired_metadata_charge=$2,updated_at=now() WHERE volume_id=$1",&[&volume,&TOMBSTONE]).await?;
            tx.execute("UPDATE volumes SET state='deleted',used_bytes=0,writer_instance_id=NULL,revision=revision+1,updated_at=now() WHERE id=$1",&[&volume]).await?;
            if state == "deleting" {
                db::complete(&tx, operation, Ok(json!({"volume_id":volume}))).await?;
            }
        }
        _ => (),
    }
    if let Some(ctx) = authority {
        db::audit(
            &tx,
            ctx.subject,
            Some(ctx.credential),
            operation,
            match state.as_str() {
                "creating" => "volume.create",
                "resizing" => "volume.resize",
                _ => "volume.delete",
            },
            &Resource::new("volume", volume, Some(current.get("owner_id"))).json(),
            "succeeded",
            "OBSERVED",
        )
        .await?;
    }
    if app.leader.is_closed() {
        return Err(Error::unavailable("Controller leadership is lost"));
    }
    tx.commit().await?;
    Ok(())
}
pub async fn tick(app: &App) -> Result<()> {
    if app.leader.is_closed() || !app.ready.load(Ordering::SeqCst) {
        return Ok(());
    }
    let c = app.db.connect().await?;
    let rows=c.query("SELECT a.volume_id FROM volume_allocations a WHERE state IN ('creating','resizing','deleting') OR (state='quarantined' AND NOT EXISTS(SELECT 1 FROM volumes v WHERE v.id=a.volume_id)) ORDER BY updated_at,volume_id LIMIT 4",&[]).await?;
    if !rows.is_empty() {
        let bound = match binding(app).await {
            Ok(bound) => bound,
            Err(error) if root_lock_busy(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        for row in rows {
            let id: Uuid = row.get(0);
            if let Err(error) = process(app, bound, id).await {
                tracing::warn!(volume_id=%id,reason_code=error.code,"Volume intent is pending");
            }
        }
    }
    let ids:Vec<Uuid>=c.query("SELECT volume_id FROM volume_allocations WHERE state='ready' ORDER BY observed_at,volume_id LIMIT 8",&[]).await?.into_iter().map(|r|r.get(0)).collect();
    if !ids.is_empty() {
        let mut dbc = app.db.connect().await?;
        let tx = dbc.transaction().await?;
        match observe(&tx, app, &ids).await {
            Ok(()) => (),
            Err(error) if root_lock_busy(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
        tx.commit().await?;
    }
    Ok(())
}

fn root_lock_busy(error: &Error) -> bool {
    error.code == "STATE_CONFLICT" && error.message == ROOT_LOCK_BUSY
}

pub async fn run(app: Arc<App>) {
    while !app.shutdown.load(Ordering::SeqCst) && !app.leader.is_closed() {
        if let Err(error) = tick(&app).await {
            tracing::warn!(
                reason_code = error.code,
                "Volume reconciliation is incomplete"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[derive(Clone, Debug)]
pub struct Mount {
    pub volume: Uuid,
    pub source: std::path::PathBuf,
    pub destination: String,
    pub access: String,
    pub fence: i64,
}
/// Validate the signed destination before an image or a volume is touched.
pub fn validate_mounts(manifest: &Value) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    let mut paths: Vec<String> = Vec::new();
    for request in manifest["volumes"]
        .as_array()
        .ok_or_else(|| Error::invalid("Missing volume requirements"))?
    {
        let path = request["mount_path"].as_str().unwrap_or("");
        let pieces: Vec<_> = path.split('/').collect();
        if !names.insert(request["name"].as_str().unwrap_or(""))
            || path.contains('\0')
            || !path.starts_with('/')
            || pieces.len() < 2
            || pieces[1..]
                .iter()
                .any(|v| v.is_empty() || *v == "." || *v == "..")
            || matches!(
                pieces[1],
                "proc"
                    | "sys"
                    | "dev"
                    | "run"
                    | "tmp"
                    | "etc"
                    | "bin"
                    | "sbin"
                    | "lib"
                    | "lib64"
                    | "usr"
                    | "boot"
                    | "root"
            )
            || paths.iter().any(|other| {
                path == other
                    || path.starts_with(&format!("{other}/"))
                    || other.starts_with(&format!("{path}/"))
            })
        {
            return Err(Error::invalid(
                "Unsafe, duplicate or overlapping volume destination",
            ));
        }
        paths.push(path.into());
    }
    Ok(())
}
pub async fn validate_selection(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    spec: &Value,
    manifest: &Value,
) -> Result<()> {
    validate_mounts(manifest)?;
    let requested = manifest["volumes"].as_array().unwrap();
    let selected = spec["volume_ids"].as_array().unwrap();
    if selected.len() != requested.len() {
        return Err(Error::invalid(
            "Selected volumes must match every signed requirement",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    for id in selected {
        let id: Uuid = id
            .as_str()
            .unwrap()
            .parse()
            .map_err(|_| Error::invalid("Invalid volume ID"))?;
        if !ids.insert(id) {
            return Err(Error::invalid("Duplicate volume ID"));
        }
        let row=c.query_opt("SELECT v.owner_id,v.spec,v.state,a.state AS allocation_state,a.data_schema_version,a.schema_state,a.schema_plugin_id,a.schema_publisher_id FROM volumes v JOIN volume_allocations a ON a.volume_id=v.id WHERE v.id=$1",&[&id]).await?.ok_or_else(Error::not_found)?;
        // Metadata read access never grants another owner's writable storage.
        let owner: Uuid = row.get("owner_id");
        if owner != ctx.subject {
            return Err(Error::denied());
        }
        auth::authorize(
            c,
            ctx,
            "volume.read",
            &Resource::new("volume", id, Some(owner)),
        )
        .await?;
        check_schema_selection(&row, spec, manifest)?;
        if row.get::<_, String>("allocation_state") != "ready"
            || matches!(
                row.get::<_, String>("state").as_str(),
                "deleted" | "deleting"
            )
        {
            return Err(Error::conflict("Volume is not ready"));
        }
        let v: Value = row.get("spec");
        let requirement = requested
            .iter()
            .find(|r| r["name"] == v["name"])
            .ok_or_else(|| Error::invalid("Volume alias does not match manifest"))?;
        if !names.insert(v["name"].as_str().unwrap().to_owned())
            || requirement["scope"] != v["scope"]
            || v["capacity_bytes"].as_u64() < requirement["minimum_bytes"].as_u64()
            || (requirement["access"] == "rw" && v["access"] != "single_writer")
        {
            return Err(Error::invalid(
                "Volume scope, access or capacity differs from manifest",
            ));
        }
    }
    Ok(())
}
/// Disabled specs describe an intent only; they do not authorize mounting an
/// unverified format. The bootstrap owner must prove emptiness, persist its
/// binding and verify the actual business format before normal runtime mounts.
fn check_schema_selection(row: &tokio_postgres::Row, spec: &Value, manifest: &Value) -> Result<()> {
    let expected = manifest["data_schema_version"]
        .as_str()
        .ok_or_else(|| Error::invalid("Missing business schema"))?;
    let observed: Option<String> = row.get("data_schema_version");
    let state: String = row.get("schema_state");
    if expected == "none" {
        if state != "unversioned" || observed.as_deref().is_some_and(|v| v != "none") {
            return Err(Error::conflict(
                "An unversioned plugin cannot mount versioned business data",
            ));
        }
        return Ok(());
    }
    if state == "unversioned"
        && observed.as_deref().is_none_or(|v| v == "none")
        && spec["enabled"] == false
    {
        return Ok(()); // metadata-only intent; no empty/verified claim
    }
    if observed.as_deref() != Some(expected)
        || row.get::<_, Option<String>>("schema_plugin_id").as_deref()
            != manifest["plugin_id"].as_str()
        || row
            .get::<_, Option<Uuid>>("schema_publisher_id")
            .map(|id| id.to_string())
            .as_deref()
            != manifest["publisher_id"].as_str()
        || (state != "verified" && !(state == "initializing" && spec["enabled"] == false))
    {
        return Err(Error::conflict(
            "Business schema requires its bound initialization or migration worker",
        ));
    }
    Ok(())
}
/// Caller holds node_budget before deployment/instance rows. The approval is
/// checked again by the controller before each runtime ensure/reconciliation.
pub async fn approve_mounts(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    deployment: Uuid,
    generation: i64,
    spec: &Value,
    manifest: &Value,
) -> Result<()> {
    validate_selection(c, ctx, spec, manifest).await?;
    if spec["volume_ids"].as_array().unwrap().is_empty() {
        return Ok(());
    }
    let peer = ctx.peer.to_string();
    c.execute("INSERT INTO volume_mount_approvals(deployment_id,credential_id,peer,generation) VALUES($1,$2,$3::text::inet,$4) ON CONFLICT(deployment_id) DO UPDATE SET credential_id=$2,peer=$3::text::inet,generation=$4,created_at=now()",&[&deployment,&ctx.credential,&peer,&generation]).await?;
    Ok(())
}
pub async fn check_approval(
    c: &(impl GenericClient + Sync),
    app: &App,
    deployment: Uuid,
    generation: i64,
    spec: &Value,
    manifest: &Value,
) -> Result<()> {
    if manifest["volumes"].as_array().unwrap().is_empty() {
        return Ok(());
    }
    let d=c.query_one("SELECT d.spec,d.owner_id,d.archived_at,a.credential_id,host(a.peer),a.generation FROM deployments d JOIN volume_mount_approvals a ON a.deployment_id=d.id WHERE d.id=$1",&[&deployment]).await?;
    if d.get::<_, Value>("spec") != *spec {
        return Err(Error::conflict("Deployment selection changed"));
    }
    if spec["enabled"] != true
        || d.get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
        || d.get::<_, i64>("generation") != generation
    {
        return Err(Error::conflict("Volume mount approval is stale"));
    }
    let peer = d
        .get::<_, String>("host")
        .parse()
        .map_err(|_| Error::denied())?;
    let ctx = app
        .auth
        .resume(c, d.get("credential_id"), peer, Uuid::new_v4())
        .await?;
    if ctx.subject != d.get::<_, Uuid>("owner_id") {
        return Err(Error::denied());
    }
    auth::authorize(
        c,
        &ctx,
        "plugin.enable",
        &Resource::new("deployment", deployment, Some(ctx.subject)),
    )
    .await?;
    validate_selection(c, &ctx, spec, manifest).await?;
    Ok(())
}
/// Durable attachments precede OCI side effects. A failed start keeps them until
/// the runtime positively proves the entire old task/container has disappeared.
pub async fn mounts(
    app: &App,
    deployment: Uuid,
    instance: Uuid,
    generation: i64,
    manifest: &Value,
) -> Result<Vec<Mount>> {
    try_mounts(app, deployment, instance, generation, manifest)
        .await?
        .ok_or_else(|| Error::conflict(ROOT_LOCK_BUSY))
}

pub(crate) async fn try_mounts(
    app: &App,
    deployment: Uuid,
    instance: Uuid,
    generation: i64,
    manifest: &Value,
) -> Result<Option<Vec<Mount>>> {
    if manifest["volumes"].as_array().unwrap().is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    db::auth_lock(&tx, false).await?;
    tx.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    let root = tx
        .query_one(
            "SELECT id,filesystem_uuid FROM volume_storage_root WHERE state='ready' FOR UPDATE",
            &[],
        )
        .await?;
    let bound = Binding {
        id: root.get(0),
        filesystem: root.get(1),
    };
    let spec: Value = tx
        .query_one("SELECT spec FROM deployments WHERE id=$1", &[&deployment])
        .await?
        .get(0);
    check_approval(&tx, app, deployment, generation, &spec, manifest).await?;
    let live = tx
        .query_one(
            "SELECT generation,phase FROM instances WHERE id=$1 AND deployment_id=$2 FOR UPDATE",
            &[&instance, &deployment],
        )
        .await?;
    if live.get::<_, i64>("generation") != generation || live.get::<_, String>("phase") == "stopped"
    {
        return Err(Error::conflict("Stale instance cannot mount volumes"));
    }
    let mut ids: Vec<Uuid> = spec["volume_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    ids.sort();
    let mut mounts = Vec::new();
    for id in ids {
        let allocation = tx
            .query_one(
                "SELECT * FROM volume_allocations WHERE volume_id=$1 FOR UPDATE",
                &[&id],
            )
            .await?;
        if allocation.get::<_, String>("state") != "ready"
            || allocation.get::<_, Uuid>("root_id") != bound.id
        {
            return Err(Error::conflict("Volume allocation is not ready"));
        }
        let v = tx
            .query_one(
                "SELECT spec,writer_instance_id,write_fence FROM volumes WHERE id=$1 FOR UPDATE",
                &[&id],
            )
            .await?;
        if tx
            .query_opt(
                "SELECT volume_id FROM volume_holds WHERE volume_id=$1",
                &[&id],
            )
            .await?
            .is_some()
        {
            return Err(Error::conflict("Volume is held by recovery or migration"));
        }
        let vs: Value = v.get("spec");
        let request = manifest["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == vs["name"])
            .unwrap();
        let access = request["access"].as_str().unwrap();
        let destination = request["mount_path"].as_str().unwrap();
        let existing=tx.query_opt("SELECT access,fence,generation,mount_path FROM volume_attachments WHERE volume_id=$1 AND instance_id=$2",&[&id,&instance]).await?;
        let fence = if let Some(existing) = existing {
            if existing.get::<_, i64>("generation") != generation
                || existing.get::<_, String>("access") != access
                || existing.get::<_, String>("mount_path") != destination
                || (access == "rw"
                    && v.get::<_, Option<Uuid>>("writer_instance_id") != Some(instance))
            {
                return Err(Error::conflict("Volume attachment identity differs"));
            }
            existing.get::<_, i64>("fence")
        } else {
            let others=tx.query_one("SELECT count(*)::bigint AS n,coalesce(bool_or(access='rw'),false) AS writing FROM volume_attachments WHERE volume_id=$1",&[&id]).await?;
            if others.get::<_, i64>("n") >= 32
                || (access == "rw" && others.get::<_, i64>("n") > 0)
                || others.get::<_, bool>("writing")
                || v.get::<_, Option<Uuid>>("writer_instance_id").is_some()
            {
                return Err(Error::conflict(
                    "Volume already has a writer or too many readers",
                ));
            }
            let fence = v
                .get::<_, i64>("write_fence")
                .checked_add(1)
                .ok_or_else(Error::exhausted)?;
            let writer = if access == "rw" { Some(instance) } else { None };
            tx.execute("INSERT INTO volume_attachments(volume_id,instance_id,access,fence,generation,mount_path) VALUES($1,$2,$3,$4,$5,$6)",&[&id,&instance,&access,&fence,&generation,&destination]).await?;
            tx.execute("UPDATE volumes SET write_fence=$2,writer_instance_id=$3,state=CASE WHEN state='full' THEN state ELSE 'attached' END,revision=revision+1,updated_at=now() WHERE id=$1",&[&id,&fence,&writer]).await?;
            fence
        };
        let project = allocation.get::<_, i32>("project_id") as u32;
        let expected = Limits {
            capacity_bytes: allocation.get::<_, i64>("capacity_bytes") as u64,
            inodes: allocation.get::<_, i64>("inode_limit") as u64,
        };
        let path = app.config.root().join("volumes");
        let source = blocking(move || {
            let Some(mut store) = ProjectStore::try_open(&path)? else {
                return Ok(None);
            };
            store.namespace_identity(bound.filesystem, bound.id, false)?;
            if store.inspect(id, project)?.limits != expected {
                return Err(Error::unavailable(
                    "Volume quota differs from admitted limits",
                ));
            }
            store.data_path(id, project).map(Some)
        })
        .await?;
        let Some(source) = source else {
            // Any attachment inserted earlier in this attempt is provisional.
            tx.rollback().await?;
            return Ok(None);
        };
        mounts.push(Mount {
            volume: id,
            source,
            destination: destination.into(),
            access: access.into(),
            fence,
        });
    }
    if app.leader.is_closed() {
        return Err(Error::unavailable("Controller leadership is lost"));
    }
    tx.commit().await?;
    Ok(Some(mounts))
}
/// Only call after Runtime::stop confirms task, cgroup and container removal.
pub async fn release_stopped(c: &impl GenericClient, instance: Option<Uuid>) -> Result<()> {
    c.query_one("SELECT id FROM node_budget FOR UPDATE", &[])
        .await?;
    let ids:Vec<Uuid>=c.query("SELECT DISTINCT volume_id FROM volume_attachments WHERE $1::uuid IS NULL OR instance_id=$1 ORDER BY volume_id",&[&instance]).await?.into_iter().map(|r|r.get(0)).collect();
    for id in ids {
        c.query_one("SELECT id FROM volumes WHERE id=$1 FOR UPDATE", &[&id])
            .await?;
        c.execute("DELETE FROM volume_attachments WHERE volume_id=$1 AND ($2::uuid IS NULL OR instance_id=$2)",&[&id,&instance]).await?;
        c.execute("UPDATE volumes SET writer_instance_id=CASE WHEN $2::uuid IS NULL OR writer_instance_id=$2 THEN NULL ELSE writer_instance_id END,state=CASE WHEN state IN ('full','deleting','deleted') THEN state WHEN EXISTS(SELECT 1 FROM volume_attachments WHERE volume_id=$1) THEN 'attached' ELSE 'available' END,revision=revision+1,updated_at=now() WHERE id=$1",&[&id,&instance]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn actual_postgres_business_schema_intent_never_grants_a_runtime_mount() {
        let Some(f) = crate::backups::tests::Fixture::new().await else {
            return;
        };
        let mut c = f.app.db.connect().await.unwrap();
        let ctx = f
            .app
            .auth
            .authenticate(&c, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
            .await
            .unwrap();
        let volume: Uuid = c
            .query_one("SELECT id FROM volumes LIMIT 1", &[])
            .await
            .unwrap()
            .get(0);
        let deployment: Uuid = c
            .query_one(
                "SELECT deployment_id FROM backups WHERE id=$1",
                &[&f.backup],
            )
            .await
            .unwrap()
            .get(0);
        let publisher: Uuid = c
            .query_one("SELECT publisher_id FROM installations LIMIT 1", &[])
            .await
            .unwrap()
            .get(0);
        let operation = db::operation(&c, ctx.subject, "schema_fixture", None)
            .await
            .unwrap();
        let root = Uuid::new_v4();
        c.execute("INSERT INTO volume_storage_root(id,filesystem_uuid,state,capacity_bytes) VALUES($1,$2,'ready',67108864)", &[&root,&Uuid::new_v4()]).await.unwrap();
        let vs: Value = c
            .query_one("SELECT spec FROM volumes WHERE id=$1", &[&volume])
            .await
            .unwrap()
            .get(0);
        c.execute("INSERT INTO volume_allocations(volume_id,root_id,project_id,owner_id,spec,capacity_bytes,inode_limit,metadata_charge,desired_capacity,desired_inodes,desired_metadata_charge,state,operation_id,credential_id,peer) VALUES($1,$2,nextval('volume_project_ids'),$3,$4,1048576,256,65536,1048576,256,65536,'ready',$5,$6,'127.0.0.1')", &[&volume,&root,&ctx.subject,&vs,&operation,&ctx.credential]).await.unwrap();
        let manifest = json!({"plugin_id":"org.xelab.schema-fixture","publisher_id":publisher,"data_schema_version":"1","volumes":[{"name":vs["name"],"mount_path":"/data","access":"rw","scope":"deployment","minimum_bytes":1048576}]});
        let mut spec = json!({"enabled":false,"volume_ids":[volume]});
        validate_selection(&c, &ctx, &spec, &manifest)
            .await
            .unwrap();
        spec["enabled"] = json!(true);
        assert!(
            validate_selection(&c, &ctx, &spec, &manifest)
                .await
                .is_err(),
            "metadata-only intent must not mount"
        );
        let constraint = c.transaction().await.unwrap();
        assert!(constraint.execute("UPDATE volume_allocations SET data_schema_version='1',schema_state='verified' WHERE volume_id=$1", &[&volume]).await.is_err(), "verified state requires all durable binding/proof fields");
        constraint.rollback().await.unwrap();
        // Metadata fixtures only; no claim of physical emptiness or a verified
        // business format. The real worker must provide those proofs separately.
        c.execute("UPDATE volume_allocations SET data_schema_version='1',schema_state='initializing',schema_deployment_id=$2,schema_plugin_id='org.xelab.schema-fixture',schema_publisher_id=$3,schema_manifest_digest=$4,schema_operation_id=$5 WHERE volume_id=$1", &[&volume,&deployment,&publisher,&crate::contracts::digest(b"schema metadata fixture"),&operation]).await.unwrap();
        assert!(validate_selection(&c, &ctx, &spec, &manifest)
            .await
            .is_err());
        spec["enabled"] = json!(false);
        validate_selection(&c, &ctx, &spec, &manifest)
            .await
            .unwrap();
        let mut unversioned = manifest.clone();
        unversioned["data_schema_version"] = json!("none");
        assert!(validate_selection(&c, &ctx, &spec, &unversioned)
            .await
            .is_err());
        c.execute("UPDATE volume_allocations SET schema_state='verified',schema_proof='{\"metadata_fixture\":true}' WHERE volume_id=$1", &[&volume]).await.unwrap();
        spec["enabled"] = json!(true);
        validate_selection(&c, &ctx, &spec, &manifest)
            .await
            .unwrap();
        for field in ["data_schema_version", "plugin_id", "publisher_id"] {
            let mut other = manifest.clone();
            other[field] = if field == "publisher_id" {
                json!(Uuid::new_v4())
            } else {
                json!("different")
            };
            assert!(
                validate_selection(&c, &ctx, &spec, &other).await.is_err(),
                "binding field {field} must match"
            );
        }
        assert!(validate_selection(&c, &ctx, &spec, &unversioned)
            .await
            .is_err());
    }
    #[test]
    fn signed_volume_destinations_cannot_shadow_runtime_or_overlap() {
        let request = |path: &str, name: &str| json!({"name":name,"mount_path":path,"access":"rw","scope":"deployment","minimum_bytes":1048576});
        for path in [
            "/",
            "data",
            "/data/",
            "//data",
            "/data/../run",
            "/data/./db",
            "/run/secret",
            "/proc/x",
            "/sys",
            "/dev",
            "/tmp",
            "/etc/x",
            "/usr/share",
        ] {
            assert!(
                validate_mounts(&json!({"volumes":[request(path,"data")]})).is_err(),
                "{path}"
            );
        }
        for (left, right) in [
            ("/data", "/data/sub"),
            ("/app/state", "/app"),
            ("/data", "/data"),
        ] {
            assert!(
                validate_mounts(&json!({"volumes":[request(left,"a"),request(right,"b")]}))
                    .is_err()
            );
        }
        assert!(validate_mounts(
            &json!({"volumes":[request("/data","same"),request("/app/state","same")]})
        )
        .is_err());
        validate_mounts(&json!({"volumes":[request("/data","a"),request("/app/state","b")]}))
            .unwrap();
    }
}
