use crate::{
    contracts::{digest, validate},
    error::{Error, Result},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio_postgres::{Client, GenericClient, NoTls, Row};
use uuid::Uuid;

pub const BASELINE: &str = include_str!("../../../docs/contracts/metadata.sql");
const CALL_CHARGES: &str = include_str!("../migrations/0002_call_credential_charges.sql");
const SECRET_AUTHORITY: &str = include_str!("../migrations/0003_secret_authority.sql");
const BLOB_DELETIONS: &str = include_str!("../migrations/0004_blob_deletions.sql");
const VOLUME_SERVICE: &str = include_str!("../migrations/0005_volume_service.sql");
const HOST_BLOB: &str = include_str!("../migrations/0006_host_blob.sql");
const BACKUP_JOBS: &str = include_str!("../migrations/0007_backup_jobs.sql");
const RESTORE_VOLUMES: &str = include_str!("../migrations/0008_restore_volumes.sql");
const PLATFORM_RECOVERY: &str = include_str!("../migrations/0009_platform_recovery.sql");
const DEPLOYMENT_UPGRADES: &str = include_str!("../migrations/0010_deployment_upgrades.sql");
const UPGRADE_VOLUME_CLONES: &str = include_str!("../migrations/0011_upgrade_volume_clones.sql");
const VOLUME_SCHEMA_JOBS: &str = include_str!("../migrations/0012_volume_schema_jobs.sql");
const SCHEMA_BACKUP_REGISTRATION: &str =
    include_str!("../migrations/0013_schema_backup_registration.sql");
const RECOVERED_ACCOUNT_ACTIVATIONS: &str =
    include_str!("../migrations/0014_recovered_account_activations.sql");
const PLUGIN_HTTP_CONTRACTS: &str = include_str!("../migrations/0015_plugin_http_contracts.sql");
const OAUTH_STATE: &str = include_str!("../migrations/0016_oauth_state.sql");
const DEPENDENCIES: &str = include_str!("../migrations/0017_dependencies.sql");
const HOST_CALLS: &str = include_str!("../migrations/0018_host_calls.sql");
const EVENT_STORE: &str = include_str!("../migrations/0019_events.sql");
const TASK_ADMISSION: &str = include_str!("../migrations/0020_task_admission.sql");
const TASK_BROKER_CALL: &str = include_str!("../migrations/0021_task_broker_call.sql");
const TASK_DEADLINE_INDEXES: &str = include_str!("../migrations/0022_task_deadline_indexes.sql");
const TASK_STEP_RESOLUTIONS: &str = include_str!("../migrations/0023_task_step_resolutions.sql");
const TASK_CANCELLATIONS: &str = include_str!("../migrations/0024_task_cancellations.sql");
const MIGRATIONS: [&str; 24] = [
    BASELINE,
    CALL_CHARGES,
    SECRET_AUTHORITY,
    BLOB_DELETIONS,
    VOLUME_SERVICE,
    HOST_BLOB,
    BACKUP_JOBS,
    RESTORE_VOLUMES,
    PLATFORM_RECOVERY,
    DEPLOYMENT_UPGRADES,
    UPGRADE_VOLUME_CLONES,
    VOLUME_SCHEMA_JOBS,
    SCHEMA_BACKUP_REGISTRATION,
    RECOVERED_ACCOUNT_ACTIVATIONS,
    PLUGIN_HTTP_CONTRACTS,
    OAUTH_STATE,
    DEPENDENCIES,
    HOST_CALLS,
    EVENT_STORE,
    TASK_ADMISSION,
    TASK_BROKER_CALL,
    TASK_DEADLINE_INDEXES,
    TASK_STEP_RESOLUTIONS,
    TASK_CANCELLATIONS,
];
pub const SCHEMA_VERSION: u64 = MIGRATIONS.len() as u64;
pub const LEADER_LOCK: i64 = 0x58454c41424d3101;

#[cfg(test)]
#[path = "db_oauth_tests.rs"]
mod oauth_migration_tests;

#[cfg(test)]
#[path = "db_connection_limit_tests.rs"]
mod connection_limit_tests;

/// Only code-owned base tables can enter an offline metadata snapshot. Views,
/// migration history and the target's recovery gate are never imported.
pub(crate) fn snapshot_tables() -> Vec<&'static str> {
    let mut tables: Vec<_> = MIGRATIONS
        .iter()
        .flat_map(|sql| sql.lines())
        .filter_map(|line| line.trim_start().strip_prefix("CREATE TABLE "))
        .filter_map(|line| line.split([' ', '(']).next())
        .filter(|name| {
            !matches!(
                *name,
                "schema_migrations" | "platform_recovery_state" | "recovery_owner_anchors"
            )
        })
        .collect();
    tables.sort_unstable();
    tables
}
pub(crate) fn migration_fingerprints() -> Vec<String> {
    MIGRATIONS
        .iter()
        .map(|sql| digest(sql.as_bytes()))
        .collect()
}

/// Serialize a deployment's OCI mutations without holding an authorization
/// transaction across RPC/disk work. Keep the owning connection until all
/// mutations settle; dropping it releases this session lock.
pub(crate) struct DeploymentFence {
    _connection: Client,
    _local: tokio::sync::OwnedMutexGuard<()>,
    deployment: Uuid,
}
impl DeploymentFence {
    pub(crate) fn protects(&self, deployment: Uuid) -> bool {
        self.deployment == deployment && !self._connection.is_closed()
    }
}
pub(crate) async fn deployment_fence(db: &Db, deployment: Uuid) -> Result<Option<DeploymentFence>> {
    type LocalFences = std::collections::BTreeMap<Uuid, std::sync::Weak<tokio::sync::Mutex<()>>>;
    static LOCAL: std::sync::OnceLock<std::sync::Mutex<LocalFences>> = std::sync::OnceLock::new();
    let local = {
        let mut guards = LOCAL
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| Error::unavailable("Runtime fence is unavailable"))?;
        guards.retain(|_, guard| guard.strong_count() > 0);
        match guards.get(&deployment).and_then(std::sync::Weak::upgrade) {
            Some(guard) => guard,
            None => {
                let guard = Arc::new(tokio::sync::Mutex::new(()));
                guards.insert(deployment, Arc::downgrade(&guard));
                guard
            }
        }
    };
    let Ok(local) = local.try_lock_owned() else {
        return Ok(None);
    };
    let c = db.connect().await?;
    let name = format!("xelab/deployment-runtime/{deployment}");
    let held: bool = c
        .query_one(
            "SELECT pg_try_advisory_lock(hashtextextended($1,0))",
            &[&name],
        )
        .await?
        .get(0);
    Ok(held.then_some(DeploymentFence {
        _connection: c,
        _local: local,
        deployment,
    }))
}

#[cfg(test)]
mod recovered_account_migration_tests {
    use super::*;

    #[tokio::test]
    async fn actual_postgres_v13_recovery_migrates_without_restoring_inherited_rights() {
        let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: recovered-account migration requires PostgreSQL");
            return;
        };
        let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
        let name = format!("recovered_account_v13_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let db = Db::new(format!("{base} dbname={name}")).unwrap();
        let mut c = db.connect().await.unwrap();
        // Construct the actual immutable released layout; never downgrade a
        // current fixture or rewrite any released migration/checksum.
        for (offset, sql) in MIGRATIONS.iter().take(13).enumerate() {
            c.batch_execute(sql).await.unwrap();
            c.execute(
                "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES($1,$2,now())",
                &[&((offset + 1) as i64), &digest(sql.as_bytes())],
            )
            .await
            .unwrap();
        }
        let parent = crate::auth::bootstrap(&c, "recovered root", "current recovered owner password", &serde_json::json!({"maximum_depth":4,"maximum_descendants":20,"maximum_api_keys":50,"maximum_concurrent_calls":16,"daily_calls":10000})).await.unwrap();
        let child = Uuid::new_v4();
        c.execute("INSERT INTO accounts(id,parent_id,kind,status,display_name,created_at,updated_at) VALUES($1,$2,'user','disabled','historical cleared child',now(),now())", &[&child,&parent]).await.unwrap();
        c.execute("INSERT INTO account_closure(ancestor_id,descendant_id,depth) VALUES($2,$2,0),($1,$2,1)", &[&parent,&child]).await.unwrap();
        c.execute("INSERT INTO inheritance_grants(account_id,parent_id,mode,maximum_rules,created_at,updated_at) VALUES($1,$2,'selected','[]',now(),now())", &[&child,&parent]).await.unwrap();
        c.execute("INSERT INTO platform_recovery_state(recovery_id,backup_id,phase,recovery_owner_id) VALUES($1,$2,'ready',$3)", &[&Uuid::new_v4(),&Uuid::new_v4(),&parent]).await.unwrap();
        let before: Vec<(i64, String)> = c
            .query(
                "SELECT version,checksum FROM schema_migrations ORDER BY version",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        assert!(db.check().await.is_err());
        db.migrate().await.unwrap();
        db.migrate().await.unwrap();
        db.check().await.unwrap();
        let after: Vec<(i64, String)> = c
            .query(
                "SELECT version,checksum FROM schema_migrations WHERE version<=13 ORDER BY version",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        assert_eq!(before, after);
        let inheritance = c.query_one("SELECT mode,maximum_rules,issuer_credential_id FROM inheritance_grants WHERE account_id=$1", &[&child]).await.unwrap();
        assert_eq!(inheritance.get::<_, String>(0), "all_snapshot");
        assert_eq!(inheritance.get::<_, Value>(1), serde_json::json!([]));
        assert!(inheritance.get::<_, Option<Uuid>>(2).is_none());
        crate::contracts::validate(
            "Account",
            &crate::identity::account_value(&c, child).await.unwrap(),
        )
        .unwrap();
        assert!(crate::policy::Policy::new(&c, "127.0.0.1".parse().unwrap())
            .account(child, 0)
            .await
            .is_err());
        let tx = c.transaction().await.unwrap();
        tx.execute("UPDATE accounts SET status='active' WHERE id=$1", &[&child])
            .await
            .unwrap();
        let peer = "127.0.0.1".parse().unwrap();
        let paths = crate::policy::Policy::new(&tx, peer)
            .account(child, 0)
            .await
            .unwrap();
        assert!(!crate::auth::rules_allow(
            &crate::policy::rules(&paths),
            "plugin.deploy",
            &crate::auth::Resource::new("deployment", "new", Some(child)),
            peer
        ));
        tx.rollback().await.unwrap();
        assert_eq!(
            c.query_one("SELECT count(*) FROM recovered_account_activations", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
}

#[cfg(test)]
mod runtime_fence_tests {
    use super::*;
    #[tokio::test]
    async fn actual_postgres_runtime_mutations_serialize_until_connection_release() {
        let Ok(dsn) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: runtime fence requires PostgreSQL");
            return;
        };
        let db = Db::new(dsn).unwrap();
        let deployment = Uuid::new_v4();
        let first = deployment_fence(&db, deployment).await.unwrap().unwrap();
        assert!(deployment_fence(&db, deployment).await.unwrap().is_none());
        let unrelated = deployment_fence(&db, Uuid::new_v4())
            .await
            .unwrap()
            .unwrap();
        assert!(!unrelated._connection.is_closed());
        // PostgreSQL restarting must not unlock another task in this process
        // while the old task is still completing an OCI mutation.
        let pid: i32 = first
            ._connection
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let admin = db.connect().await.unwrap();
        admin
            .query_one("SELECT pg_terminate_backend($1)", &[&pid])
            .await
            .unwrap();
        assert!(deployment_fence(&db, deployment).await.unwrap().is_none());
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if deployment_fence(&db, deployment).await.unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}

#[cfg(test)]
mod scoped_connection_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn abandoned_scoped_query_releases_its_backend_before_the_lock_holder() {
        let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: scoped connection cancellation requires PostgreSQL");
            return;
        };
        let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
        let name = format!("scoped_cancel_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let db = Db::new(format!("{base} dbname={name}")).unwrap();
        db.migrate().await.unwrap();
        let mut holder = db.connect().await.unwrap();
        let held = holder.transaction().await.unwrap();
        call_lock(&held).await.unwrap();
        let observer = db.connect().await.unwrap();
        let mut scoped = db.connect_scoped(Duration::from_secs(10)).await.unwrap();
        assert_eq!(
            scoped
                .query_one("SHOW statement_timeout", &[])
                .await
                .unwrap()
                .get::<_, String>(0),
            "10s"
        );
        let pid: i32 = scoped
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let waiting = tokio::spawn(async move {
            let transaction = scoped.transaction().await.unwrap();
            call_lock(&transaction).await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let blocked: bool = observer
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)",
                        &[&pid],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if blocked {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the scoped backend must actually reach the held lock");
        let unrelated = db.connect().await.unwrap();
        let unaffected = tokio::spawn(async move {
            unrelated
                .query_one("SELECT pg_sleep(0.2),42::integer", &[])
                .await
                .unwrap()
                .get::<_, i32>(1)
        });
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let gone: bool = observer
                    .query_one(
                        "SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                        &[&pid],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if gone {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("abandoned backend must disappear while the holder still owns the lock");
        assert_eq!(unaffected.await.unwrap(), 42);
        assert_eq!(
            observer
                .query_one("SELECT count(*) FROM reservations", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        held.rollback().await.unwrap();
        let normal = db.connect_scoped(Duration::from_secs(2)).await.unwrap();
        assert_eq!(
            normal
                .query_one("SELECT 7::integer", &[])
                .await
                .unwrap()
                .get::<_, i32>(0),
            7
        );
        drop(normal);
        assert_eq!(
            observer
                .query_one("SELECT 9::integer", &[])
                .await
                .unwrap()
                .get::<_, i32>(0),
            9
        );
    }
}

#[derive(Clone)]
pub struct Db {
    dsn: Arc<str>,
    connections: Option<Arc<tokio::sync::Semaphore>>,
}

/// A request-owned connection. Dropping a PostgreSQL query future alone does
/// not interrupt its server statement or the detached protocol driver.
pub(crate) struct ScopedClient {
    client: Client,
    driver: Option<ScopedDriver>,
}
struct ScopedDriver(tokio::task::JoinHandle<()>);
impl Drop for ScopedDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl std::ops::Deref for ScopedClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.client
    }
}
impl std::ops::DerefMut for ScopedClient {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.client
    }
}
impl Drop for ScopedClient {
    fn drop(&mut self) {
        let Some(driver) = self.driver.take() else {
            return;
        };
        let cancel = self.client.cancel_token();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                // A lost socket alone may leave an advisory-lock waiter alive.
                // Cancel its exact backend first; then close the owned socket.
                // This Client cannot be reused by another application request.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    cancel.cancel_query(NoTls),
                )
                .await;
                drop(driver);
            });
        } else {
            drop(driver);
        }
    }
}
impl Db {
    pub fn new(dsn: String) -> Result<Self> {
        let c: tokio_postgres::Config = dsn
            .parse()
            .map_err(|_| Error::invalid("Invalid PostgreSQL DSN"))?;
        for host in c.get_hosts() {
            match host {
                tokio_postgres::config::Host::Tcp(h)
                    if h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback()) => {}
                tokio_postgres::config::Host::Unix(_) => (),
                _ => {
                    return Err(Error::invalid(
                        "M1 PostgreSQL must use a local Unix socket or numeric loopback address",
                    ))
                }
            }
        }
        Ok(Self {
            dsn: dsn.into(),
            connections: None,
        })
    }
    /// Share a backend budget with every subsequent clone. Admission must not
    /// wait: a caller can already own a transaction or a deployment fence.
    pub fn with_connection_limit(mut self, limit: usize) -> Self {
        self.connections = Some(Arc::new(tokio::sync::Semaphore::new(limit)));
        self
    }
    fn connection_permit(&self) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
        self.connections
            .as_ref()
            .map(|limit| {
                limit
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::exhausted())
            })
            .transpose()
    }
    pub async fn connect(&self) -> Result<Client> {
        let permit = self.connection_permit()?;
        let (c, connection) = tokio_postgres::connect(&self.dsn, NoTls).await?;
        tokio::spawn(async move {
            // Dropping a Client or its request may leave queued statements in
            // flight. Count the backend until its actual driver has stopped.
            let _permit = permit;
            if connection.await.is_err() {
                tracing::error!(reason_code = "DATABASE_CONNECTION_LOST");
            }
        });
        Ok(c)
    }
    pub(crate) async fn connect_scoped(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ScopedClient> {
        let permit = self.connection_permit()?;
        let (client, connection) = tokio_postgres::connect(&self.dsn, NoTls).await?;
        let driver = tokio::spawn(async move {
            let _permit = permit;
            if connection.await.is_err() {
                tracing::error!(reason_code = "DATABASE_CONNECTION_LOST");
            }
        });
        let scoped = ScopedClient {
            client,
            driver: Some(ScopedDriver(driver)),
        };
        // A server-side bound still applies if the cancellation connection is
        // unavailable. Never use zero, which disables PostgreSQL's timeout.
        let milliseconds = timeout.as_millis().clamp(1, 300000).to_string();
        scoped
            .query_one(
                "SELECT set_config('statement_timeout',$1,false)",
                &[&milliseconds],
            )
            .await?;
        Ok(scoped)
    }
    pub async fn check(&self) -> Result<()> {
        let c = self.connect().await?;
        verify_migration(&c).await?;
        if c.query_one(
            "SELECT EXISTS(SELECT 1 FROM platform_recovery_state WHERE phase<>'ready')",
            &[],
        )
        .await?
        .get::<_, bool>(0)
        {
            return Err(Error::unavailable(
                "Offline platform recovery has not completed",
            ));
        }
        Ok(())
    }
    pub async fn migrate(&self) -> Result<()> {
        let mut c = self.connect().await?;
        let tx = c.transaction().await?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&LEADER_LOCK])
            .await?;
        let present: Option<String> = tx
            .query_one("SELECT to_regclass('public.schema_migrations')::text", &[])
            .await?
            .get(0);
        if present.is_none() {
            let sql = BASELINE.replacen("BEGIN;", "", 1);
            let sql = sql
                .strip_suffix("COMMIT;\n")
                .or_else(|| sql.strip_suffix("COMMIT;"))
                .ok_or_else(|| Error::invalid("Unexpected baseline framing"))?;
            tx.batch_execute(sql).await?;
            tx.execute(
                "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(1,$1,now())",
                &[&digest(BASELINE.as_bytes())],
            )
            .await?;
        } else {
            verify_migrations(&tx, false).await?;
        }
        let version: i64 = tx
            .query_one("SELECT max(version) FROM schema_migrations", &[])
            .await?
            .get(0);
        for (offset, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            tx.batch_execute(sql).await?;
            tx.execute(
                "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES($1,$2,now())",
                &[&((offset + 1) as i64), &digest(sql.as_bytes())],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn leader(&self) -> Result<Client> {
        let c = self.connect().await?;
        let acquired: bool = c
            .query_one("SELECT pg_try_advisory_lock($1)", &[&LEADER_LOCK])
            .await?
            .get(0);
        if !acquired {
            return Err(Error::conflict(
                "A kernel controller already owns this database",
            ));
        }
        Ok(c)
    }
}

pub async fn verify_migration(c: &impl GenericClient) -> Result<()> {
    verify_migrations(c, true).await
}

async fn verify_migrations(c: &impl GenericClient, latest: bool) -> Result<()> {
    let r = c
        .query(
            "SELECT version,checksum FROM schema_migrations ORDER BY version",
            &[],
        )
        .await?;
    if r.is_empty()
        || r.len() > MIGRATIONS.len()
        || (latest && r.len() != MIGRATIONS.len())
        || r.iter().enumerate().any(|(i, row)| {
            row.get::<_, i64>(0) != (i + 1) as i64
                || row.get::<_, String>(1) != digest(MIGRATIONS[i].as_bytes())
        })
    {
        return Err(Error::conflict(
            "Metadata migration version or checksum differs",
        ));
    }
    Ok(())
}

pub fn stamp(row: &Row) -> Value {
    json!({"id":row.get::<_,Uuid>("id"),"revision":row.get::<_,i64>("revision"),"created_at":row.get::<_,chrono::DateTime<chrono::Utc>>("created_at"),"updated_at":row.get::<_,chrono::DateTime<chrono::Utc>>("updated_at")})
}
pub fn project(row: &Row, fields: &[&str]) -> Result<Value> {
    let mut out = stamp(row);
    for name in fields {
        let val: Value = row
            .try_get(*name)
            .map_err(|_| Error::unavailable("Invalid metadata projection"))?;
        out[*name] = val;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)] // Audit fields mirror the immutable event envelope.
pub async fn audit(
    c: &impl GenericClient,
    subject: Uuid,
    credential: Option<Uuid>,
    request: Uuid,
    action: &str,
    resource: &Value,
    outcome: &str,
    reason: &str,
) -> Result<()> {
    c.execute("INSERT INTO audit_events(id,subject_id,credential_id,request_id,action,resource,outcome,policy_revision,reason_code,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,(SELECT authz_revision FROM accounts WHERE id=$2),$8,now(),now())",&[&Uuid::new_v4(),&subject,&credential,&request,&action,&resource,&outcome,&reason]).await?;
    Ok(())
}
pub async fn outbox(c: &impl GenericClient, topic: &str, id: Uuid, payload: &Value) -> Result<()> {
    c.execute(
        "INSERT INTO outbox(id,topic,aggregate_id,payload,created_at) VALUES($1,$2,$3,$4,now())",
        &[&Uuid::new_v4(), &topic, &id, &payload],
    )
    .await?;
    Ok(())
}

pub async fn operation(
    c: &impl GenericClient,
    owner: Uuid,
    kind: &str,
    resource: Option<String>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    c.execute("INSERT INTO operations(id,owner_id,kind,state,resource_id,created_at,updated_at) VALUES($1,$2,$3,'pending',$4,now(),now())",&[&id,&owner,&kind,&resource]).await?;
    Ok(id)
}
pub async fn operation_value(c: &impl GenericClient, id: Uuid) -> Result<Value> {
    let r = c
        .query_opt("SELECT * FROM operations WHERE id=$1", &[&id])
        .await?
        .ok_or_else(Error::not_found)?;
    let mut v = stamp(&r);
    v["kind"] = json!(r.get::<_, String>("kind"));
    v["state"] = json!(r.get::<_, String>("state"));
    v["progress_percent"] = json!(r.get::<_, i32>("progress_percent"));
    v["resource_id"] = json!(r.get::<_, Option<String>>("resource_id"));
    v["result"] = r.get::<_, Option<Value>>("result").unwrap_or(Value::Null);
    v["error"] = r.get::<_, Option<Value>>("error").unwrap_or(Value::Null);
    validate("Operation", &v)?;
    Ok(v)
}
pub async fn complete(
    c: &impl GenericClient,
    id: Uuid,
    result: std::result::Result<Value, Error>,
) -> Result<()> {
    let (state, value, error) = match result {
        Ok(v) => ("succeeded", Some(v), None),
        Err(e) => ("failed", None, Some(e.detail())),
    };
    c.execute("UPDATE operations SET state=$2,result=$3,error=$4,progress_percent=100,revision=revision+1,updated_at=now() WHERE id=$1 AND state IN ('pending','running')",&[&id,&state,&value,&error]).await?;
    Ok(())
}

/// Single-node authorization fence. Acquire exclusive BEFORE authentication for
/// identity mutations, shared for all protected side effects. No lock upgrades.
pub async fn auth_lock(c: &impl GenericClient, write: bool) -> Result<()> {
    let sql = if write {
        "SELECT pg_advisory_xact_lock($1)"
    } else {
        "SELECT pg_advisory_xact_lock_shared($1)"
    };
    c.query_one(sql, &[&0x58454c4142415554_i64]).await?;
    Ok(())
}

/// Order: authorization fence, call ledger, provider, root-to-leaf quota rows.
/// Never hold this short transaction lock across an OCI or RPC operation.
pub async fn call_lock(c: &impl GenericClient) -> Result<()> {
    auth_lock(c, false).await?;
    c.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&0x58454c414243414c_i64],
    )
    .await?;
    Ok(())
}
