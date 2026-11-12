//! A bounded, data-only metadata stream. All COPY statements and restored
//! constraints come from the current trusted schema, never from the input.
//! Binary COPY is deliberately restricted to the same PostgreSQL major and
//! exact migration/column layout. This is not a cross-version database upgrade.
use crate::{
    config::require_host_admin,
    contracts::strict_json,
    db::{self, SCHEMA_VERSION},
    error::{Error, Result},
    recovery,
};
use axum::body::Bytes;
use futures_util::{SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_postgres::{Client, GenericClient, Transaction};
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"XELABDB1";
const FOOTER: &[u8; 8] = b"DBEND001";
const CHUNK: usize = 65536;
const MAX_HEADER: usize = 256 * 1024;
const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ROW: i32 = 8 * 1024 * 1024;
const MAX_ROWS: u64 = 10_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Column {
    name: String,
    data_type: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    name: String,
    columns: Vec<Column>,
    rows: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema_version: u64,
    migrations: Vec<String>,
    postgres_major: u32,
    snapshot: Uuid,
    lsn: String,
    project_high_water: i64,
    tables: Vec<Table>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub snapshot: Uuid,
    pub schema_version: u64,
    pub postgres_major: u32,
    pub lsn: String,
    pub bytes: u64,
    pub rows: u64,
    pub sha256: String,
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn relation(name: &str) -> String {
    format!("public.{}", quoted(name))
}
fn copy_sql(table: &Table, direction: &str) -> String {
    let columns = table
        .columns
        .iter()
        .map(|c| quoted(&c.name))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "COPY {} ({columns}) {direction} WITH (FORMAT binary)",
        relation(&table.name)
    )
}
async fn major(c: &(impl GenericClient + Sync)) -> Result<u32> {
    let version: String = c.query_one("SHOW server_version_num", &[]).await?.get(0);
    Ok(version
        .parse::<u32>()
        .map_err(|_| Error::unavailable("PostgreSQL version is invalid"))?
        / 10000)
}
async fn layout(c: &(impl GenericClient + Sync), name: &str) -> Result<Vec<Column>> {
    let rows = c.query("SELECT a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attgenerated,a.attidentity FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class t ON t.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relname=$1 AND t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum", &[&name]).await?;
    if rows.is_empty()
        || rows.len() > 256
        || rows
            .iter()
            .any(|r| r.get::<_, i8>(2) != 0 || r.get::<_, i8>(3) != 0)
    {
        return Err(Error::conflict(
            "Metadata table has an unsupported column layout",
        ));
    }
    Ok(rows
        .into_iter()
        .map(|r| Column {
            name: r.get(0),
            data_type: r.get(1),
        })
        .collect())
}
#[derive(Default)]
struct Meter {
    hash: Sha256,
    bytes: u64,
}
impl Meter {
    fn add(&mut self, bytes: &[u8]) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(Error::exhausted)?;
        if self.bytes > MAX_BYTES {
            return Err(Error::exhausted());
        }
        self.hash.update(bytes);
        Ok(())
    }
    async fn write(&mut self, out: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
        self.add(bytes)?;
        out.write_all(bytes).await?;
        Ok(())
    }
    async fn read(&mut self, input: &mut (impl AsyncRead + Unpin), bytes: &mut [u8]) -> Result<()> {
        input.read_exact(bytes).await?;
        self.add(bytes)
    }
    fn summary(self, header: &Header) -> Summary {
        Summary {
            snapshot: header.snapshot,
            schema_version: header.schema_version,
            postgres_major: header.postgres_major,
            lsn: header.lsn.clone(),
            bytes: self.bytes,
            rows: header.tables.iter().map(|t| t.rows).sum(),
            sha256: format!("{:x}", self.hash.finalize()),
        }
    }
}

/// The offline coordinator must own both leases, fence/stop all writers and
/// retain them until this and the filesystem snapshot finish. The caller owns
/// the private output, its fsync and subsequent authenticated encryption.
pub async fn export(c: &mut Client, out: &mut (impl AsyncWrite + Unpin)) -> Result<Summary> {
    require_host_admin()?;
    tokio::time::timeout(std::time::Duration::from_secs(300), export_inner(c, out))
        .await
        .map_err(|_| Error::unavailable("Metadata snapshot exceeded its deadline"))?
}
async fn export_inner(c: &mut Client, out: &mut (impl AsyncWrite + Unpin)) -> Result<Summary> {
    let tx = c.transaction().await?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .await?;
    db::verify_migration(&tx).await?;
    crate::http_contracts::validate_snapshot_bindings(&tx).await?;
    crate::oauth::snapshot::validate_snapshot(&tx).await?;
    crate::ui::validate_snapshot(&tx).await?;
    crate::webui::validate_snapshot(&tx).await?;
    crate::events::snapshot::validate_snapshot(&tx).await?;
    crate::tasks::snapshot::validate_snapshot(&tx).await?;
    if tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM platform_recovery_state WHERE phase<>'ready')",
            &[],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Err(Error::conflict(
            "Cannot snapshot an incomplete platform recovery",
        ));
    }
    let mut tables = Vec::new();
    let mut total_rows = 0u64;
    for name in db::snapshot_tables() {
        let columns = layout(&tx, name).await?;
        // A bytea OpenAPI member is at most 4 MiB. row_to_json hex-encodes it,
        // so its text size is not the binary COPY row size. Account for its
        // actual payload plus bounded scalar columns; retain the existing
        // generic 8 MiB limit for every other table.
        let maximum_row = if name == "plugin_http_contracts" {
            "octet_length(raw)+octet_length(digest)+128".to_owned()
        } else {
            "octet_length(row_to_json(t)::text)".to_owned()
        };
        let row = tx
            .query_one(
                &format!(
                    "SELECT count(*),coalesce(max({maximum_row}),0) FROM {} t",
                    relation(name)
                ),
                &[],
            )
            .await?;
        let count: i64 = row.get(0);
        let maximum: i32 = row.get(1);
        total_rows = total_rows
            .checked_add(count as u64)
            .ok_or_else(Error::exhausted)?;
        if maximum > MAX_ROW || total_rows > MAX_ROWS {
            return Err(Error::exhausted());
        }
        tables.push(Table {
            name: name.to_owned(),
            columns,
            rows: count as u64,
        });
    }
    let high:i64=tx.query_one("SELECT greatest(last_value,(SELECT coalesce(max(project_id),0) FROM volume_allocations)) FROM volume_project_ids", &[]).await?.get(0);
    let header = Header {
        schema_version: SCHEMA_VERSION,
        migrations: db::migration_fingerprints(),
        postgres_major: major(&tx).await?,
        snapshot: Uuid::new_v4(),
        lsn: tx
            .query_one("SELECT pg_current_wal_lsn()::text", &[])
            .await?
            .get(0),
        project_high_water: high,
        tables,
    };
    let encoded = serde_json::to_vec(&header)?;
    if encoded.len() > MAX_HEADER {
        return Err(Error::exhausted());
    }
    let mut meter = Meter::default();
    meter.write(out, MAGIC).await?;
    meter
        .write(out, &(encoded.len() as u32).to_be_bytes())
        .await?;
    meter.write(out, &encoded).await?;
    for table in &header.tables {
        let stream = tx.copy_out(&copy_sql(table, "TO STDOUT")).await?;
        tokio::pin!(stream);
        let mut hash = Sha256::new();
        while let Some(bytes) = stream.try_next().await? {
            // A single database row is bounded before COPY starts.
            if bytes.len() > MAX_ROW as usize + CHUNK {
                return Err(Error::exhausted());
            }
            for part in bytes.chunks(CHUNK) {
                hash.update(part);
                meter.write(out, &(part.len() as u32).to_be_bytes()).await?;
                meter.write(out, part).await?;
            }
        }
        meter.write(out, &0u32.to_be_bytes()).await?;
        meter.write(out, &hash.finalize()).await?;
    }
    meter.write(out, FOOTER).await?;
    out.flush().await?;
    tx.commit().await?;
    Ok(meter.summary(&header))
}

/// Import only into a trusted, current, otherwise empty schema with a durable
/// importing gate. The authenticated outer manifest supplies `expected`.
/// The entire import, constraint validation and authority reset commit together.
/// The gate remains `rebuilding`; this alone can never admit daemon startup.
pub async fn import(
    c: &mut Client,
    input: &mut (impl AsyncRead + Unpin),
    expected: &Summary,
    recovery: Uuid,
    owner: Uuid,
    password: &str,
) -> Result<Summary> {
    require_host_admin()?;
    tokio::time::timeout(
        std::time::Duration::from_secs(300),
        import_inner(c, input, expected, recovery, owner, password),
    )
    .await
    .map_err(|_| Error::unavailable("Metadata import exceeded its deadline"))?
}
async fn import_inner(
    c: &mut Client,
    input: &mut (impl AsyncRead + Unpin),
    expected: &Summary,
    recovery: Uuid,
    owner: Uuid,
    password: &str,
) -> Result<Summary> {
    let tx = c.transaction().await?;
    db::verify_migration(&tx).await?;
    let held=tx.query_opt("SELECT recovery_id FROM platform_recovery_state WHERE recovery_id=$1 AND phase='importing' AND recovery_owner_id IS NULL FOR UPDATE", &[&recovery]).await?.is_some();
    if !held {
        return Err(Error::conflict(
            "Empty target has no importing recovery gate",
        ));
    }
    let mut meter = Meter::default();
    let mut magic = [0; 8];
    meter.read(input, &mut magic).await?;
    if &magic != MAGIC {
        return Err(Error::invalid("Metadata snapshot header is invalid"));
    }
    let mut len = [0; 4];
    meter.read(input, &mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_HEADER {
        return Err(Error::invalid("Metadata snapshot header exceeds its limit"));
    }
    let mut encoded = vec![0; len];
    meter.read(input, &mut encoded).await?;
    let header: Header = serde_json::from_value(strict_json(&encoded, MAX_HEADER)?)?;
    if header.schema_version != SCHEMA_VERSION
        || header.migrations != db::migration_fingerprints()
        || header.postgres_major != major(&tx).await?
        || header.project_high_water < 1
        || header.project_high_water > i32::MAX as i64
        || header
            .tables
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>()
            != db::snapshot_tables()
        || header
            .tables
            .iter()
            .try_fold(0u64, |n, t| n.checked_add(t.rows))
            .is_none_or(|n| n > MAX_ROWS)
    {
        return Err(Error::conflict(
            "Metadata snapshot version or table set is incompatible",
        ));
    }
    for table in &header.tables {
        if table.columns != layout(&tx, &table.name).await? {
            return Err(Error::conflict(
                "Metadata snapshot column layout is incompatible",
            ));
        }
        if tx
            .query_one(
                &format!("SELECT EXISTS(SELECT 1 FROM {})", relation(&table.name)),
                &[],
            )
            .await?
            .get::<_, bool>(0)
        {
            return Err(Error::conflict("Metadata import requires an empty target"));
        }
    }
    if tx
        .query_one("SELECT EXISTS(SELECT 1 FROM recovery_owner_anchors)", &[])
        .await?
        .get::<_, bool>(0)
    {
        return Err(Error::conflict("Recovery anchors already exist"));
    }
    // Trusted target constraints only. Drop/re-add handles cyclic account/grant
    // references without disabling triggers or requiring a PostgreSQL superuser.
    let constraints = foreign_keys(&tx).await?;
    for (table, name, _) in &constraints {
        tx.batch_execute(&format!(
            "ALTER TABLE {} DROP CONSTRAINT {}",
            relation(table),
            quoted(name)
        ))
        .await?;
    }
    for table in &header.tables {
        let sink = tx
            .copy_in::<_, Bytes>(&copy_sql(table, "FROM STDIN"))
            .await?;
        tokio::pin!(sink);
        let mut hash = Sha256::new();
        loop {
            let mut len = [0; 4];
            meter.read(input, &mut len).await?;
            let len = u32::from_be_bytes(len) as usize;
            if len == 0 {
                break;
            }
            if len > CHUNK {
                return Err(Error::invalid("Metadata COPY frame exceeds its limit"));
            }
            let mut bytes = vec![0; len];
            meter.read(input, &mut bytes).await?;
            hash.update(&bytes);
            sink.send(Bytes::from(bytes)).await?;
        }
        let mut expected_hash = [0; 32];
        meter.read(input, &mut expected_hash).await?;
        if hash.finalize().as_slice() != expected_hash {
            return Err(Error::invalid("Metadata COPY digest does not match"));
        }
        if sink.finish().await? != table.rows {
            return Err(Error::invalid("Metadata COPY row count does not match"));
        }
    }
    let mut footer = [0; 8];
    meter.read(input, &mut footer).await?;
    let mut trailing = [0];
    if &footer != FOOTER || input.read(&mut trailing).await? != 0 {
        return Err(Error::invalid("Metadata snapshot end is invalid"));
    }
    let summary = meter.summary(&header);
    if &summary != expected {
        return Err(Error::invalid(
            "Metadata snapshot does not match its authenticated manifest",
        ));
    }
    for (table, name, definition) in constraints {
        tx.batch_execute(&format!(
            "ALTER TABLE {} ADD CONSTRAINT {} {definition}",
            relation(&table),
            quoted(&name)
        ))
        .await?;
    }
    crate::http_contracts::validate_snapshot_bindings(&tx).await?;
    crate::skills::validate_snapshot_bindings(&tx).await?;
    crate::oauth::snapshot::validate_snapshot(&tx).await?;
    crate::ui::validate_snapshot(&tx).await?;
    crate::webui::validate_snapshot(&tx).await?;
    crate::events::snapshot::validate_snapshot(&tx).await?;
    crate::tasks::snapshot::validate_snapshot(&tx).await?;
    recovery::reset_rows(&tx, owner, password, recovery).await?;
    tx.execute(
        "UPDATE platform_recovery_state SET metadata_summary=$2 WHERE recovery_id=$1",
        &[&recovery, &serde_json::to_value(&summary)?],
    )
    .await?;
    // Sequences are not transactional. Advancing on a failed commit is safe;
    // moving backwards could recycle a project identity, so it is forbidden.
    tx.query_one("SELECT setval('volume_project_ids',greatest($1,(SELECT last_value FROM volume_project_ids),(SELECT coalesce(max(project_id),0) FROM volume_allocations)),true)",&[&header.project_high_water]).await?;
    tx.commit().await?;
    Ok(summary)
}
async fn foreign_keys(tx: &Transaction<'_>) -> Result<Vec<(String, String, String)>> {
    let names: Vec<String> = db::snapshot_tables()
        .into_iter()
        .map(str::to_owned)
        .collect();
    Ok(tx.query("SELECT t.relname,c.conname,pg_catalog.pg_get_constraintdef(c.oid) FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace WHERE c.contype='f' AND n.nspname='public' AND t.relname=ANY($1) ORDER BY t.relname,c.conname",&[&names]).await?.into_iter().map(|r|(r.get(0),r.get(1),r.get(2))).collect())
}

#[cfg(test)]
#[path = "metadata_snapshot_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "metadata_snapshot_m4_tests.rs"]
mod m4_tests;
