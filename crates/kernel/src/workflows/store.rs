use crate::{
    api::{etag, read_object},
    contracts::string,
    error::{Error, Result},
};
use axum::http::HeaderMap;
use serde_json::Value;
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub(super) async fn owner(c: &(impl GenericClient + Sync), id: Uuid) -> Result<Uuid> {
    let row = c
        .query_opt("SELECT owner_id FROM workflows WHERE id=$1", &[&id])
        .await?
        .ok_or_else(Error::not_found)?;
    Ok(row.get(0))
}

pub(super) async fn publish(
    c: &(impl GenericClient + Sync),
    owner: Uuid,
    spec: &Value,
) -> Result<Value> {
    if contains_nul(spec) {
        return Err(Error::invalid(
            "Workflow spec cannot contain NUL characters",
        ));
    }
    let name = string(spec, "name")?;
    // A row lock cannot serialize the first publication. Acquire the family
    // lock in the API transaction before reading the latest version.
    let lock = format!("workflow-version:{owner}:{name}");
    c.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        &[&lock],
    )
    .await?;
    let latest: i64 = c
        .query_one(
            "SELECT coalesce(max(version),0) FROM workflows WHERE owner_id=$1 AND name=$2",
            &[&owner, &name],
        )
        .await?
        .get(0);
    let version = latest
        .checked_add(1)
        .filter(|version| *version <= i64::from(i32::MAX))
        .ok_or_else(|| Error::conflict("Workflow version limit reached"))?;

    let id = Uuid::new_v4();
    c.execute(
        "INSERT INTO workflows(id,owner_id,name,version,spec,status,created_at,updated_at)
         VALUES($1,$2,$3,$4,$5,'active',now(),now())",
        &[&id, &owner, &name, &version, &spec],
    )
    .await?;
    read_object(c, "workflows", id, "Workflow").await
}

pub(super) async fn archive(
    c: &(impl GenericClient + Sync),
    id: Uuid,
    headers: &HeaderMap,
) -> Result<()> {
    let row = c
        .query_opt(
            "SELECT revision,status FROM workflows WHERE id=$1 FOR UPDATE",
            &[&id],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    etag(headers, row.get("revision"))?;
    if row.get::<_, String>("status") == "active" {
        c.execute(
            "UPDATE workflows SET status='archived',revision=revision+1,updated_at=now()
             WHERE id=$1",
            &[&id],
        )
        .await?;
    }
    Ok(())
}

// PostgreSQL text and jsonb reject the JSON escape for U+0000.
fn contains_nul(value: &Value) -> bool {
    match value {
        Value::String(value) => value.contains('\0'),
        Value::Array(values) => values.iter().any(contains_nul),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key.contains('\0') || contains_nul(value)),
        _ => false,
    }
}
