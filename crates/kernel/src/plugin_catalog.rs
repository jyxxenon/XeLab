//! Public catalog reads. Each page uses the existing current policy and
//! actual object owner. Cursors convey position only, and encrypt positions so
//! they cannot disclose identifiers belonging to invisible objects.
use crate::{
    api::{object_value, read_object},
    auth::{self, Auth, Context, Resource},
    contracts::{digest, strict_json, strict_urlencoded, validate},
    error::{Error, Result},
    policy::{self, Path, Policy},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tokio_postgres::{types::ToSql, GenericClient};
use uuid::Uuid;
use zeroize::Zeroizing;

const CURSOR_DOMAIN: &str = "xelab-plugin-catalog-cursor-v1";
const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_AUTHORITY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Collection {
    table: &'static str,
    model: &'static str,
    action: &'static str,
    kind: &'static str,
    source: &'static str,
}
fn collection(name: &str) -> Result<Collection> {
    let (table, model, action, kind, source) = match name {
        "listPublishers" => ("publishers", "Publisher", "publisher.read", "publisher", "SELECT t.id,t.created_at,t.id::text AS resource_id,NULL::uuid AS owner_id,NULL::text AS plugin_id,NULL::uuid AS deployment_id FROM publishers t"),
        "listInstallations" => ("installations", "Installation", "plugin.read", "plugin", "SELECT t.id,t.created_at,t.plugin_id AS resource_id,NULL::uuid AS owner_id,t.plugin_id,NULL::uuid AS deployment_id FROM installations t"),
        "listDeployments" => ("deployments", "Deployment", "plugin.read", "deployment", "SELECT t.id,t.created_at,t.id::text AS resource_id,t.owner_id,NULL::text AS plugin_id,t.id AS deployment_id FROM deployments t WHERE t.archived_at IS NULL"),
        "listInstances" => ("instances", "Instance", "plugin.read", "instance", "SELECT t.id,t.created_at,t.id::text AS resource_id,d.owner_id,NULL::text AS plugin_id,t.deployment_id FROM instances t JOIN deployments d ON d.id=t.deployment_id WHERE d.archived_at IS NULL"),
        "listWorkflows" => ("workflows", "Workflow", "workflow.read", "workflow", "SELECT t.id,t.created_at,t.id::text AS resource_id,t.owner_id,NULL::text AS plugin_id,NULL::uuid AS deployment_id FROM workflows t"),
        "listTasks" => ("tasks", "Task", "task.read", "task", "SELECT t.id,t.created_at,t.id::text AS resource_id,t.owner_id,NULL::text AS plugin_id,NULL::uuid AS deployment_id,t.state FROM tasks t"),
        "listTaskSteps" => ("task_steps", "TaskStep", "task.read", "task", "SELECT s.id,s.created_at,t.id::text AS resource_id,t.owner_id,NULL::text AS plugin_id,NULL::uuid AS deployment_id,s.task_id FROM task_steps s JOIN tasks t ON t.id=s.task_id"),
        _ => return Err(Error::invalid("Unknown plugin catalog operation")),
    };
    Ok(Collection {
        table,
        model,
        action,
        kind,
        source,
    })
}

pub(crate) fn handles(name: &str) -> bool {
    matches!(
        name,
        "listPublishers" | "listInstallations" | "listDeployments" | "listInstances"
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    binding: Value,
    watermark: DateTime<Utc>,
    last_time: DateTime<Utc>,
    last_id: String,
    expires_at: DateTime<Utc>,
}
fn cipher(auth: &Auth, domain: &'static str) -> Result<LessSafeKey> {
    let key = Zeroizing::new(auth.token_digest(domain));
    Ok(LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| Error::unavailable("Catalog cursor cipher is unavailable"))?,
    ))
}
fn encode(auth: &Auth, cursor: &Cursor) -> Result<String> {
    encode_opaque_cursor(auth, CURSOR_DOMAIN, "c1", cursor)
}

/// Shared position confidentiality; callers supply fixed, distinct purpose and
/// wire-version constants, never caller-selected keys or authorization policy.
pub(crate) fn encode_opaque_cursor(
    auth: &Auth,
    domain: &'static str,
    version: &'static str,
    cursor: &impl Serialize,
) -> Result<String> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut ciphertext = serde_json::to_vec(cursor)?;
    cipher(auth, domain)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(domain),
            &mut ciphertext,
        )
        .map_err(|_| Error::unavailable("Catalog cursor encryption failed"))?;
    let mut bytes = nonce.to_vec();
    bytes.extend(ciphertext);
    let value = format!("{version}.{}", URL_SAFE_NO_PAD.encode(bytes));
    if value.len() > 2048 {
        return Err(Error::exhausted());
    }
    Ok(value)
}
fn decode(auth: &Auth, value: &str) -> Result<Cursor> {
    decode_opaque_cursor(auth, CURSOR_DOMAIN, "c1", value)
}

pub(crate) fn decode_opaque_cursor<T: serde::de::DeserializeOwned>(
    auth: &Auth,
    domain: &'static str,
    version: &'static str,
    value: &str,
) -> Result<T> {
    let invalid = || Error::invalid("Invalid plugin catalog cursor");
    if value.len() > 2048 {
        return Err(invalid());
    }
    let mut bytes = URL_SAFE_NO_PAD
        .decode(
            value
                .strip_prefix(&format!("{version}."))
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
    if bytes.len() < 29 {
        return Err(invalid());
    }
    let nonce: [u8; 12] = bytes[..12].try_into().map_err(|_| invalid())?;
    let plaintext = cipher(auth, domain)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(domain),
            &mut bytes[12..],
        )
        .map_err(|_| invalid())?;
    serde_json::from_value(strict_json(plaintext, 1536).map_err(|_| invalid())?)
        .map_err(|_| invalid())
}

pub(crate) struct Selectors {
    pub(crate) all: bool,
    pub(crate) ids: BTreeSet<String>,
    pub(crate) owners: BTreeSet<Uuid>,
}
pub(crate) fn selectors(
    paths: &[Path],
    action: &str,
    kind: &str,
    ctx: &Context,
) -> Result<Selectors> {
    let mut selected = Selectors {
        all: false,
        ids: BTreeSet::new(),
        owners: BTreeSet::new(),
    };
    for path in paths {
        let rule = &path.rule;
        if rule["action"] != action
            || rule["resource"]["kind"] != kind
            || rule
                .get("conditions")
                .is_some_and(|conditions| !auth::conditions_match(conditions, ctx.peer, Utc::now()))
        {
            continue;
        }
        match rule["resource"]["match"].as_str() {
            Some("all") => selected.all = true,
            Some("ids") => {
                for id in rule["resource"]["ids"]
                    .as_array()
                    .ok_or_else(Error::denied)?
                {
                    selected
                        .ids
                        .insert(id.as_str().ok_or_else(Error::denied)?.to_owned());
                }
            }
            Some("owned_by") => {
                let raw = rule["resource"]["owner_id"]
                    .as_str()
                    .ok_or_else(Error::denied)?;
                let owner: Uuid = raw.parse().map_err(|_| Error::denied())?;
                if owner.to_string() == raw {
                    selected.owners.insert(owner);
                }
            }
            _ => return Err(Error::denied()),
        }
        if selected.ids.len() > 4096 || selected.owners.len() > 4096 {
            return Err(Error::exhausted());
        }
    }
    Ok(selected)
}

pub(crate) fn reserve_authority_bytes(used: &mut usize, bytes: usize) -> Result<()> {
    let next = used.checked_add(bytes).ok_or_else(Error::exhausted)?;
    if next > MAX_AUTHORITY_BYTES {
        return Err(Error::exhausted());
    }
    *used = next;
    Ok(())
}

pub(crate) async fn authority_binding(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    paths: &[Path],
) -> Result<String> {
    let mut canonical_paths = Vec::new();
    let mut bytes = 0usize;
    for path in paths {
        let encoded = serde_jcs::to_vec(path)?;
        reserve_authority_bytes(&mut bytes, encoded.len())?;
        canonical_paths.push(encoded);
    }
    canonical_paths.sort();
    let sources: Vec<Uuid> = paths
        .iter()
        .flat_map(|path| path.sources.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if sources.len() > 4096 {
        return Err(Error::exhausted());
    }
    let grants: Vec<Value> = c
        .query(
            "SELECT id,revision FROM grants WHERE id=ANY($1::uuid[]) ORDER BY id",
            &[&sources],
        )
        .await?
        .iter()
        .map(|row| json!([row.get::<_, Uuid>(0), row.get::<_, i64>(1).to_string()]))
        .collect();
    let credentials: Vec<Value> = c
        .query(
            "SELECT id,revision FROM credentials WHERE id=ANY($1::uuid[]) ORDER BY id",
            &[&ctx.chain],
        )
        .await?
        .iter()
        .map(|row| json!([row.get::<_, Uuid>(0), row.get::<_, i64>(1).to_string()]))
        .collect();
    let accounts: Vec<Value> = c.query("SELECT DISTINCT a.id,a.authz_revision FROM credentials c JOIN account_closure x ON x.descendant_id=c.owner_id JOIN accounts a ON a.id=x.ancestor_id WHERE c.id=ANY($1::uuid[]) ORDER BY a.id", &[&ctx.chain]).await?.iter().map(|row|json!([row.get::<_,Uuid>(0),row.get::<_,i64>(1).to_string()])).collect();
    Ok(digest(&serde_jcs::to_vec(
        &json!({"paths":canonical_paths,"grants":grants,"credentials":credentials,"accounts":accounts}),
    )?))
}

pub(crate) async fn execute(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    query: &str,
) -> Result<(Value, u16)> {
    list(c, auth, ctx, name, query, None).await
}

pub(crate) async fn list_task_steps(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    task: Uuid,
    query: &str,
) -> Result<(Value, u16)> {
    list(c, auth, ctx, "listTaskSteps", query, Some(task)).await
}

pub(crate) async fn read_task(
    c: &(impl GenericClient + Sync),
    task: Uuid,
    state: Option<&str>,
) -> Result<Option<Value>> {
    // Keep the internal admission proof outside even the SQL payload.
    let row = c.query_opt(
        "SELECT to_jsonb(t) FROM (SELECT id,revision,created_at,updated_at,owner_id,workflow_id,delegation_id,state,input,output,deadline_at,error FROM tasks WHERE id=$1 AND ($2::text IS NULL OR state COLLATE \"C\"=$2)) t",
        &[&task, &state],
    ).await?;
    row.map(|row| object_value(&row.get(0), "Task")).transpose()
}

async fn list(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    query: &str,
    task: Option<Uuid>,
) -> Result<(Value, u16)> {
    let selected = collection(name)?;
    if !policy::registered(c, selected.action, selected.kind).await? {
        return Err(Error::denied());
    }
    let mut args = if query.is_empty() {
        serde_json::Map::new()
    } else {
        strict_urlencoded(query.as_bytes(), 4096, 4)?
    };
    let limit = args
        .remove("limit")
        .map(|value| value.as_str().unwrap().parse::<usize>())
        .transpose()
        .map_err(|_| Error::invalid("Invalid catalog page limit"))?
        .unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(Error::invalid("Invalid catalog page limit"));
    }
    let plugin = if name == "listInstallations" {
        args.remove("plugin_id")
            .map(|value| value.as_str().unwrap().to_owned())
    } else {
        None
    };
    if let Some(plugin) = &plugin {
        crate::contracts::validate_business(
            &crate::contracts::openapi()["components"]["schemas"]["Installation"]["properties"]
                ["plugin_id"],
            &json!(plugin),
        )?;
    }
    let deployment = if name == "listInstances" {
        args.remove("deployment_id")
            .map(|value| value.as_str().unwrap().parse::<Uuid>())
            .transpose()
            .map_err(|_| Error::invalid("Invalid catalog deployment filter"))?
    } else {
        None
    };
    let state = if name == "listTasks" {
        args.remove("state")
            .map(|value| value.as_str().unwrap().to_owned())
    } else {
        None
    };
    if state
        .as_ref()
        .is_some_and(|state| !(1..=80).contains(&state.chars().count()) || state.contains('\0'))
    {
        return Err(Error::invalid("Invalid task state filter"));
    }
    let supplied_cursor = args.remove("cursor");
    if !args.is_empty() {
        return Err(Error::invalid("Unsupported plugin catalog filter"));
    }
    let all_paths = Policy::for_context(c, ctx)
        .credential(ctx.credential, 0)
        .await?;
    let paths: Vec<Path> = all_paths
        .into_iter()
        .filter(|path| {
            path.rule["action"] == selected.action && path.rule["resource"]["kind"] == selected.kind
        })
        .collect();
    let proof = authority_binding(c, ctx, &paths).await?;
    let mut binding = json!({"subject":ctx.subject,"credential":ctx.credential,"chain":digest(&serde_jcs::to_vec(&ctx.chain)?),"origin":ctx.browser_origin,"peer":ctx.peer,"operation":name,"limit":limit,"plugin_id":plugin,"deployment_id":deployment,"authority":proof});
    if name == "listTasks" {
        binding["state"] = json!(state);
    }
    if let Some(task) = task {
        binding["task_id"] = json!(task);
    }
    let now = Utc::now();
    let mut cursor = if let Some(value) = supplied_cursor {
        decode(auth, value.as_str().unwrap())?
    } else {
        Cursor {
            binding: binding.clone(),
            watermark: now,
            last_time: DateTime::<Utc>::UNIX_EPOCH,
            last_id: String::new(),
            expires_at: now + chrono::Duration::minutes(15),
        }
    };
    if cursor.binding != binding
        || cursor.expires_at <= now
        || cursor.watermark > now
        || cursor.last_time > cursor.watermark
        || cursor.last_time < DateTime::<Utc>::UNIX_EPOCH
        || cursor.expires_at != cursor.watermark + chrono::Duration::minutes(15)
    {
        return Err(Error::invalid(
            "Catalog cursor authority, filters or expiry changed",
        ));
    }
    let visible = selectors(&paths, selected.action, selected.kind, ctx)?;
    let ids: Vec<String> = visible.ids.into_iter().collect();
    let owners: Vec<Uuid> = visible.owners.into_iter().collect();
    // SQL preselection contains only the same currently allowed selector set.
    // It avoids count/existence leaks from scanning unrelated private rows.
    // Every selected object is checked again by the existing rule predicate.
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![
        &cursor.watermark,
        &cursor.last_time,
        &cursor.last_id,
        &visible.all,
        &ids,
        &owners,
        &plugin,
        &deployment,
    ];
    let task_filter = match name {
        "listTasks" => {
            params.push(&state);
            "AND ($9::text IS NULL OR state COLLATE \"C\"=$9)"
        }
        "listTaskSteps" => {
            if task.is_none() {
                return Err(Error::not_found());
            }
            params.push(&task);
            "AND task_id=$9"
        }
        _ => "",
    };
    let sql = format!("WITH catalog AS ({}) SELECT * FROM catalog WHERE created_at<=$1 AND (created_at,id::text)>($2,$3) AND ($4 OR resource_id=ANY($5::text[]) OR owner_id=ANY($6::uuid[])) AND ($7::text IS NULL OR plugin_id=$7) AND ($8::uuid IS NULL OR deployment_id=$8) {task_filter} ORDER BY created_at,id LIMIT 201",selected.source);
    let rows = c.query(&sql, &params).await?;
    let rules = policy::rules(&paths);
    let mut items = Vec::new();
    let mut bytes = 4096;
    let mut more = false;
    for (index, row) in rows.into_iter().enumerate() {
        let id: Uuid = row.get("id");
        let resource = Resource::new(
            selected.kind,
            row.get::<_, String>("resource_id"),
            row.get("owner_id"),
        );
        if !auth::rules_allow(&rules, selected.action, &resource, ctx.peer) {
            return Err(Error::invalid(
                "Catalog authority changed; restart pagination",
            ));
        }
        if items.len() == limit || index == 200 {
            more = true;
            break;
        }
        let value = if name == "listTasks" {
            // A task may change state after the ID scan in a READ COMMITTED
            // transaction. Recheck against the same snapshot as the payload.
            let Some(value) = read_task(c, id, state.as_deref()).await? else {
                cursor.last_time = row.get("created_at");
                cursor.last_id = id.to_string();
                continue;
            };
            value
        } else {
            read_object(c, selected.table, id, selected.model).await?
        };
        let size = serde_json::to_vec(&value)?.len();
        if bytes + size > MAX_PAGE_BYTES {
            if items.is_empty() {
                return Err(Error::exhausted());
            }
            more = true;
            break;
        }
        bytes += size;
        items.push(value);
        cursor.last_time = row.get("created_at");
        cursor.last_id = id.to_string();
    }
    let next = if more {
        Some(encode(auth, &cursor)?)
    } else {
        None
    };
    let value = json!({"items":items,"next_cursor":next});
    validate(&format!("{}Page", selected.model), &value)?;
    Ok((value, 200))
}

#[cfg(test)]
#[path = "plugin_catalog_tests.rs"]
mod tests;

#[cfg(test)]
mod authority_budget_tests {
    use super::*;
    #[test]
    fn combined_authority_budget_rejects_before_growth_without_charging_failed_reservations() {
        let mut used = 0;
        reserve_authority_bytes(&mut used, MAX_AUTHORITY_BYTES - 1).unwrap();
        reserve_authority_bytes(&mut used, 1).unwrap();
        assert_eq!(used, MAX_AUTHORITY_BYTES);
        for bytes in [1, usize::MAX] {
            assert_eq!(
                reserve_authority_bytes(&mut used, bytes).unwrap_err().code,
                "RESOURCE_EXHAUSTED"
            );
            assert_eq!(used, MAX_AUTHORITY_BYTES);
        }
        reserve_authority_bytes(&mut used, 0).unwrap();
    }
}
