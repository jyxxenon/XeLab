//! Immutable, signed OCI Skill definitions and their current routing state.
//! This module does not execute plugin business logic or mint execution authority.
use crate::{
    api::{etag, path_id},
    auth::{self, Auth, Context, Resource},
    contracts::{compile_business, digest, id, string, validate},
    db,
    error::{Error, Result},
};
use axum::http::{HeaderMap, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use tokio_postgres::{GenericClient, Row};
use uuid::Uuid;

pub fn handles(name: &str) -> bool {
    matches!(
        name,
        "registerSkill" | "getSkill" | "listSkills" | "setSkillEnabled" | "archiveSkill"
    )
}

pub(crate) fn definition_digest(definition: &Value) -> Result<String> {
    let mut bytes = Vec::new();
    canonical(definition, &mut bytes)?;
    Ok(digest(&bytes))
}

// serde_jcs 0.1 provides ECMAScript number formatting but orders object keys as
// escaped UTF-8 bytes. RFC 8785 instead requires raw UTF-16 code-unit order.
fn canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Object(map) => {
            let mut fields: Vec<_> = map.iter().collect();
            fields.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (index, (key, value)) in fields.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&serde_json::to_vec(key)?);
                out.push(b':');
                canonical(value, out)?;
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                canonical(value, out)?;
            }
            out.push(b']');
        }
        Value::Number(number) => {
            // I-JSON interoperable integers avoid ambiguous digest collisions
            // between distinct serde_json integers after IEEE-754 conversion.
            if number
                .as_i64()
                .is_some_and(|v| !(-9007199254740991..=9007199254740991).contains(&v))
                || number.as_u64().is_some_and(|v| v > 9007199254740991)
            {
                return Err(Error::invalid(
                    "Skill definition integers must be exactly interoperable I-JSON numbers",
                ));
            }
            let bytes = serde_jcs::to_vec(number)
                .map_err(|_| Error::invalid("Skill definition cannot be canonicalized"))?;
            out.extend_from_slice(&bytes);
        }
        _ => out.extend_from_slice(&serde_json::to_vec(value)?),
    }
    Ok(())
}

fn conflict() -> Error {
    Error::new(
        "CONTRACT_CONFLICT",
        "Skill version or signed target differs",
        StatusCode::CONFLICT,
    )
}

/// Validate an ordinary OCI candidate against its containing signed manifest.
/// Equality with an actual manifest candidate is checked separately at registration.
pub(crate) fn validate_candidate(manifest: &Value, definition: &Value) -> Result<()> {
    validate("SkillDefinition", definition)?;
    if !matches!(
        definition["target"]["kind"].as_str(),
        Some("capability" | "http")
    ) {
        return Err(Error::invalid(
            "Only ordinary OCI capability and signed HTTP Skill targets are supported",
        ));
    }
    let plugin = string(manifest, "plugin_id")?;
    if definition["target"]["plugin_id"] != plugin
        || !string(definition, "name")?.starts_with(&format!("{plugin}."))
    {
        return Err(conflict());
    }
    if definition["target"]["kind"] == "http" {
        if definition["mapping"] != "identity" {
            return Err(conflict());
        }
        for field in ["input_schema", "output_schema", "stream_item_schema"] {
            if field != "stream_item_schema" || !definition[field].is_null() {
                compile_business(&definition[field])?;
            }
        }
        definition_digest(definition)?;
        return Ok(());
    }
    let cap = manifest["capabilities"]
        .as_array()
        .and_then(|caps| {
            caps.iter()
                .find(|cap| cap["contract"] == definition["target"]["contract"])
        })
        .ok_or_else(conflict)?;
    for field in ["input_schema", "output_schema", "stream_item_schema"] {
        if definition[field] != cap[field] {
            return Err(conflict());
        }
        if field != "stream_item_schema" || !definition[field].is_null() {
            compile_business(&definition[field])?;
        }
    }
    definition_digest(definition)?;
    Ok(())
}

pub(crate) fn validate_candidates(manifest: &Value) -> Result<()> {
    let Some(candidates) = manifest.get("skills") else {
        return Ok(());
    };
    let candidates = candidates
        .as_array()
        .ok_or_else(|| Error::invalid("Skill candidates must be an array"))?;
    let mut versions = HashSet::new();
    for definition in candidates {
        validate_candidate(manifest, definition)?;
        if !versions.insert((string(definition, "name")?, string(definition, "version")?)) {
            return Err(conflict());
        }
    }
    Ok(())
}

/// The installation row was written only after image and original manifest
/// signature verification. Never accept a body-supplied candidate as provenance.
async fn installed_candidate(
    c: &(impl GenericClient + Sync),
    installation: Uuid,
    definition: &Value,
) -> Result<()> {
    let row = c.query_opt(
        "SELECT n.manifest FROM installations n JOIN publishers p ON p.id=n.publisher_id WHERE n.id=$1 AND n.state='installed' AND p.status='trusted' FOR SHARE OF n,p",
        &[&installation],
    ).await?.ok_or_else(|| Error::unavailable("Skill source installation is unavailable"))?;
    let manifest: Value = row.get(0);
    candidate_binding(c, installation, &manifest, definition).await
}

async fn candidate_binding(
    c: &(impl GenericClient + Sync),
    installation: Uuid,
    manifest: &Value,
    definition: &Value,
) -> Result<()> {
    validate_candidate(manifest, definition)?;
    if !manifest["skills"]
        .as_array()
        .is_some_and(|skills| skills.iter().any(|candidate| candidate == definition))
    {
        return Err(conflict());
    }
    if definition["target"]["kind"] == "http" {
        crate::http_contracts::load(c, installation)
            .await?
            .bind_skill(definition)?;
        return Ok(());
    }
    let contract = &definition["target"]["contract"];
    let row = c
        .query_opt(
            "SELECT schema_digest,spec FROM capability_contracts WHERE name=$1 AND version=$2",
            &[&string(contract, "name")?, &string(contract, "version")?],
        )
        .await?
        .ok_or_else(conflict)?;
    let cap: Value = row.get("spec");
    if row.get::<_, String>("schema_digest") != string(contract, "schema_digest")?
        || ["input_schema", "output_schema", "stream_item_schema"]
            .iter()
            .any(|field| cap[*field] != definition[*field])
    {
        return Err(conflict());
    }
    Ok(())
}

/// Validate persisted ordinary Skill identity before freezing or importing a
/// snapshot. Historical definitions remain data even when disabled, archived or
/// published by a now-revoked publisher. This does not restore live authority.
pub(crate) async fn validate_snapshot_bindings(c: &(impl GenericClient + Sync)) -> Result<()> {
    let mut after: Option<Uuid> = None;
    loop {
        let rows = c.query(
            "SELECT s.*,n.manifest AS source_manifest,n.plugin_id AS source_plugin,n.version AS source_version,n.publisher_id AS source_publisher,n.image_digest,n.manifest_digest FROM skills s LEFT JOIN installations n ON n.id=s.installation_id WHERE ($1::uuid IS NULL OR s.id>$1) ORDER BY s.id LIMIT 200",
            &[&after],
        ).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = Some(row.get("id"));
            if row.get::<_, String>("source_kind") != "oci"
                || [
                    "micro_version_id",
                    "micro_deployment_id",
                    "extension_version_id",
                    "extension_deployment_id",
                ]
                .iter()
                .any(|field| row.get::<_, Option<Uuid>>(*field).is_some())
                || row
                    .get::<_, Option<String>>("extension_host_chain_digest")
                    .is_some()
            {
                return Err(Error::conflict(
                    "Snapshot contains an unsupported Skill source",
                ));
            }
            let manifest = row
                .get::<_, Option<Value>>("source_manifest")
                .ok_or_else(conflict)?;
            let plugin = row
                .get::<_, Option<String>>("source_plugin")
                .ok_or_else(conflict)?;
            let version = row
                .get::<_, Option<String>>("source_version")
                .ok_or_else(conflict)?;
            let publisher = row
                .get::<_, Option<Uuid>>("source_publisher")
                .ok_or_else(conflict)?;
            if manifest["plugin_id"] != plugin
                || manifest["version"] != version
                || manifest["publisher_id"] != publisher.to_string()
                || ["image_digest", "manifest_digest"].iter().any(|field| {
                    !row.get::<_, Option<String>>(*field).is_some_and(|hash| {
                        hash.len() == 71
                            && hash.starts_with("sha256:")
                            && hash[7..]
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                })
            {
                return Err(conflict());
            }
            crate::artifact::validate_runtime_profile(&manifest)?;
            let definition: Value = row.get("definition");
            if definition["name"] != row.get::<_, String>("name")
                || definition["version"] != row.get::<_, String>("version")
                || definition_digest(&definition)? != row.get::<_, String>("definition_digest")
            {
                return Err(conflict());
            }
            candidate_binding(c, row.get("installation_id"), &manifest, &definition).await?;
        }
    }
    // Deployments can change installation after a historical call. Their
    // current installation is not evidence of that call's original provider.
    // The immutable Skill/call binding and the normal provider FKs survive.
    if c.query_one(
        "SELECT EXISTS(SELECT 1 FROM calls c LEFT JOIN skills s ON s.id=c.skill_id WHERE (c.skill_id IS NULL AND c.skill_definition_digest IS NOT NULL) OR (c.skill_id IS NOT NULL AND (s.id IS NULL OR c.skill_definition_digest IS DISTINCT FROM s.definition_digest OR c.contract IS DISTINCT FROM CASE WHEN s.definition->'target'->>'kind'='http' THEN jsonb_build_object('name',s.name,'version',s.version,'schema_digest',s.definition_digest) ELSE s.definition->'target'->'contract' END)))",
        &[],
    ).await?.get::<_,bool>(0) {
        return Err(Error::conflict("Snapshot Call does not match its immutable Skill"));
    }
    Ok(())
}

async fn access(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    skill: Uuid,
    action: &str,
) -> Result<()> {
    let row = c
        .query_opt("SELECT created_by FROM skills WHERE id=$1", &[&skill])
        .await?
        .ok_or_else(Error::not_found)?;
    auth::authorize(
        c,
        ctx,
        action,
        &Resource::new("skill", skill, Some(row.get(0))),
    )
    .await
}

pub async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
) -> Result<()> {
    let result = match name {
        "listSkills" => Ok(()), // individual objects are filtered on every page
        "registerSkill" => {
            auth::authorize(
                c,
                ctx,
                "skill.register",
                &Resource::new("skill", "new", Some(ctx.subject)),
            )
            .await?;
            let installation = id(body, "installation_id")?;
            let row = c
                .query_opt(
                    "SELECT plugin_id FROM installations WHERE id=$1",
                    &[&installation],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            auth::authorize(
                c,
                ctx,
                "plugin.install",
                &Resource::new("plugin", row.get::<_, String>(0), Some(ctx.subject)),
            )
            .await
        }
        "getSkill" | "setSkillEnabled" | "archiveSkill" => {
            access(
                c,
                ctx,
                path_id(params, "skill_id")?,
                match name {
                    "getSkill" => "skill.read",
                    "setSkillEnabled" => "skill.enable",
                    _ => "skill.archive",
                },
            )
            .await
        }
        _ => Err(Error::not_found()),
    };
    result.map_err(|e| {
        if name == "getSkill" && e.code == "PERMISSION_DENIED" {
            Error::not_found()
        } else {
            e
        }
    })
}

pub(crate) struct ResolvedSkill {
    pub id: Uuid,
    pub installation_id: Uuid,
    pub definition: Value,
    pub definition_digest: String,
    pub owner: Uuid,
}

/// Called inside the Broker transaction. Provider selection and target action
/// authorization remain Broker responsibilities and share its instance budget.
pub(crate) async fn resolve_for_invoke(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    skill: Uuid,
) -> Result<ResolvedSkill> {
    resolve_live(c, ctx, skill, "skill.invoke", None).await
}

pub(crate) async fn resolve_for_workflow(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    skill: Uuid,
) -> Result<ResolvedSkill> {
    resolve_live(c, ctx, skill, "skill.read", None)
        .await
        .map_err(|error| {
            if error.code == "PERMISSION_DENIED" {
                Error::not_found()
            } else {
                error
            }
        })
}

pub(crate) async fn resolve_http_for_invoke(
    c: &tokio_postgres::Transaction<'_>,
    ctx: &Context,
    skill: Uuid,
    authority: &auth::CurrentAuthority<'_, '_>,
) -> Result<ResolvedSkill> {
    authority.verify(c, ctx)?;
    resolve_live(c, ctx, skill, "skill.invoke", Some(authority)).await
}

async fn resolve_live(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    skill: Uuid,
    action: &str,
    authority: Option<&auth::CurrentAuthority<'_, '_>>,
) -> Result<ResolvedSkill> {
    let row = c
        .query_opt("SELECT * FROM skills WHERE id=$1 FOR SHARE", &[&skill])
        .await?
        .ok_or_else(Error::not_found)?;
    let owner = row.get("created_by");
    let resource = Resource::new("skill", skill, Some(owner));
    if let Some(authority) = authority {
        // The concrete transaction was verified by resolve_http_for_invoke.
        authority.require_context(ctx, action, &resource)?;
    } else {
        auth::authorize(c, ctx, action, &resource).await?;
    }
    if !row.get::<_, bool>("enabled")
        || row.get::<_, Option<DateTime<Utc>>>("archived_at").is_some()
    {
        return Err(Error::unavailable("Skill is disabled or archived"));
    }
    let definition: Value = row.get("definition");
    let installation_id = row.get("installation_id");
    let stored_digest: String = row.get("definition_digest");
    if definition_digest(&definition)? != stored_digest {
        return Err(conflict());
    }
    installed_candidate(c, installation_id, &definition).await?;
    Ok(ResolvedSkill {
        id: skill,
        installation_id,
        definition,
        definition_digest: stored_digest,
        owner,
    })
}

/// Data-only check for an already admitted HTTP Call. Its caller must separately
/// revalidate the original frozen Skill and business permission paths; this does
/// not grant authority or substitute a new permission alternative.
pub(crate) async fn check_admitted_http_binding(
    c: &(impl GenericClient + Sync),
    skill: Uuid,
    expected_digest: &str,
    installation: Uuid,
) -> Result<()> {
    let row=c.query_opt("SELECT definition,definition_digest,installation_id,enabled,archived_at FROM skills WHERE id=$1 FOR SHARE",&[&skill]).await?.ok_or_else(Error::not_found)?;
    let definition: Value = row.get("definition");
    if !row.get::<_, bool>("enabled")
        || row.get::<_, Option<DateTime<Utc>>>("archived_at").is_some()
    {
        return Err(Error::unavailable("HTTP Skill is disabled or archived"));
    }
    if row.get::<_, Uuid>("installation_id") != installation
        || row.get::<_, String>("definition_digest") != expected_digest
        || definition_digest(&definition)? != expected_digest
        || definition["target"]["kind"] != "http"
    {
        return Err(conflict());
    }
    installed_candidate(c, installation, &definition).await
}

// Metadata-only half of an already admitted capability Skill proof. Callers
// must separately require the exact original+current business/Skill sources.
pub(crate) async fn check_admitted_capability_binding(
    c: &(impl GenericClient + Sync),
    skill: Uuid,
    expected_digest: &str,
    installation: Uuid,
) -> Result<()> {
    let row=c.query_opt("SELECT definition,definition_digest,installation_id,enabled,archived_at FROM skills WHERE id=$1 FOR SHARE",&[&skill]).await?.ok_or_else(Error::not_found)?;
    let definition: Value = row.get("definition");
    if !row.get::<_, bool>("enabled")
        || row.get::<_, Option<DateTime<Utc>>>("archived_at").is_some()
    {
        return Err(Error::unavailable("Skill is disabled or archived"));
    }
    if row.get::<_, Uuid>("installation_id") != installation
        || row.get::<_, String>("definition_digest") != expected_digest
        || definition_digest(&definition)? != expected_digest
        || definition["target"]["kind"] != "capability"
    {
        return Err(conflict());
    }
    installed_candidate(c, installation, &definition).await
}

async fn row_value(c: &(impl GenericClient + Sync), row: &Row) -> Result<Value> {
    let mut value = db::stamp(row);
    let definition: Value = row.get("definition");
    let installation: Uuid = row.get("installation_id");
    let enabled: bool = row.get("enabled");
    let archived = row.get::<_, Option<DateTime<Utc>>>("archived_at").is_some();
    let source_valid = if enabled
        && !archived
        && definition_digest(&definition)? == row.get::<_, String>("definition_digest")
    {
        installed_candidate(c, installation, &definition)
            .await
            .is_ok()
    } else {
        false
    };
    let ready = if source_valid && definition["target"]["kind"] == "http" {
        c.query_one("SELECT EXISTS(SELECT 1 FROM instances i JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id WHERE n.id=$1 AND i.phase='ready' AND i.health='alive' AND i.last_heartbeat_at>now()-interval '1 millisecond'*((n.manifest->'health'->>'interval_ms')::bigint*(n.manifest->'health'->>'failure_threshold')::bigint+(n.manifest->'health'->>'timeout_ms')::bigint) AND d.spec->>'enabled'='true' AND d.archived_at IS NULL AND d.approval ? 'rules')",&[&installation]).await?.get(0)
    } else if source_valid {
        c.query_one(
            "SELECT EXISTS(SELECT 1 FROM provider_records p JOIN instances i ON i.id=p.instance_id JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id WHERE n.id=$1 AND p.name=$2 AND p.version=$3 AND p.availability='ready' AND p.observed_at>now()-interval '1 millisecond'*((n.manifest->'health'->>'interval_ms')::bigint*(n.manifest->'health'->>'failure_threshold')::bigint+(n.manifest->'health'->>'timeout_ms')::bigint) AND i.phase='ready' AND d.spec->>'enabled'='true' AND d.archived_at IS NULL)",
            &[&installation, &string(&definition["target"]["contract"], "name")?, &string(&definition["target"]["contract"], "version")?],
        ).await?.get::<_, bool>(0)
    } else {
        false
    };
    let (availability, reasons) = if archived {
        ("disabled", vec!["SKILL_ARCHIVED"])
    } else if !enabled {
        ("disabled", vec!["SKILL_DISABLED"])
    } else if !source_valid {
        ("unavailable", vec!["SOURCE_UNAVAILABLE"])
    } else if !ready {
        ("unavailable", vec!["PROVIDER_UNAVAILABLE"])
    } else {
        ("ready", vec![])
    };
    value["definition"] = definition;
    value["definition_digest"] = json!(row.get::<_, String>("definition_digest"));
    value["installation_id"] = json!(installation);
    value["enabled"] = json!(enabled);
    value["availability"] = json!(availability);
    value["reason_codes"] = json!(reasons);
    validate("Skill", &value)?;
    Ok(value)
}

pub(crate) async fn value(c: &(impl GenericClient + Sync), skill: Uuid) -> Result<Value> {
    let row = c
        .query_opt("SELECT * FROM skills WHERE id=$1", &[&skill])
        .await?
        .ok_or_else(Error::not_found)?;
    row_value(c, &row).await
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
    headers: &HeaderMap,
    query: &str,
) -> Result<(Value, u16)> {
    match name {
        "registerSkill" => {
            validate("CreateSkill", body)?;
            let definition = &body["definition"];
            let installation = id(body, "installation_id")?;
            installed_candidate(c, installation, definition).await?;
            let name = string(definition, "name")?;
            let version = string(definition, "version")?;
            let lock = format!("skill-version:{name}@{version}");
            c.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock],
            )
            .await?;
            let hash = definition_digest(definition)?;
            if let Some(row) = c
                .query_opt(
                    "SELECT * FROM skills WHERE name=$1 AND version=$2 FOR UPDATE",
                    &[&name, &version],
                )
                .await?
            {
                if row.get::<_, String>("definition_digest") != hash
                    || row.get::<_, Uuid>("installation_id") != installation
                    || row.get::<_, Value>("definition") != *definition
                {
                    return Err(conflict());
                }
                // Re-registration never changes enablement or resurrects archives.
                access(c, ctx, row.get("id"), "skill.read").await?;
                return Ok((row_value(c, &row).await?, 201));
            }
            let skill = Uuid::new_v4();
            let enabled = body["enabled"].as_bool().unwrap_or(false);
            if enabled {
                auth::authorize(
                    c,
                    ctx,
                    "skill.enable",
                    &Resource::new("skill", skill, Some(ctx.subject)),
                )
                .await?;
            }
            c.execute("INSERT INTO skills(id,name,version,installation_id,created_by,definition,definition_digest,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),now())", &[&skill, &name, &version, &installation, &ctx.subject, &definition, &hash, &enabled]).await?;
            Ok((value(c, skill).await?, 201))
        }
        "getSkill" => Ok((value(c, path_id(params, "skill_id")?).await?, 200)),
        "listSkills" => Ok((list(c, auth, ctx, query).await?, 200)),
        "setSkillEnabled" | "archiveSkill" => {
            let skill = path_id(params, "skill_id")?;
            let row = c
                .query_one("SELECT * FROM skills WHERE id=$1 FOR UPDATE", &[&skill])
                .await?;
            etag(headers, row.get("revision"))?;
            if name == "archiveSkill" {
                c.execute("UPDATE skills SET enabled=false,archived_at=coalesce(archived_at,now()),revision=revision+1,updated_at=now() WHERE id=$1", &[&skill]).await?;
                return Ok((Value::Null, 204));
            } else {
                if row.get::<_, Option<DateTime<Utc>>>("archived_at").is_some() {
                    return Err(Error::conflict("An archived Skill cannot be enabled"));
                }
                let enabled = body["enabled"]
                    .as_bool()
                    .ok_or_else(|| Error::invalid("Enabled flag is required"))?;
                if enabled {
                    installed_candidate(c, row.get("installation_id"), &row.get("definition"))
                        .await?;
                }
                c.execute(
                    "UPDATE skills SET enabled=$2,revision=revision+1,updated_at=now() WHERE id=$1",
                    &[&skill, &enabled],
                )
                .await?;
            }
            Ok((value(c, skill).await?, 200))
        }
        _ => Err(Error::not_found()),
    }
}

// A signed watermark cursor conveys position, never authority. Each page filters
// against current grants, ancestors and credential provenance through authorize.
async fn list(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    query: &str,
) -> Result<Value> {
    let mut args = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if args.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err(Error::invalid("Duplicate query parameter"));
        }
    }
    let limit = args
        .remove("limit")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|_| Error::invalid("Invalid page limit"))?
        .unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(Error::invalid("Invalid page limit"));
    }
    let cursor = args.remove("cursor");
    if !args.is_empty() {
        return Err(Error::invalid("Unsupported filter"));
    }
    let binding = json!({"subject":ctx.subject,"credential":ctx.credential,"operation":"listSkills","limit":limit});
    let mut watermark = Utc::now();
    let mut last_time = DateTime::<Utc>::UNIX_EPOCH;
    let mut last_id = String::new();
    if let Some(cursor) = cursor {
        let (raw, signature) = cursor
            .split_once('.')
            .ok_or_else(|| Error::invalid("Invalid cursor"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| Error::invalid("Invalid cursor"))?;
        if !auth.verify_mac(raw, &signature) {
            return Err(Error::invalid("Invalid cursor"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| Error::invalid("Invalid cursor"))?;
        let v: Value = serde_json::from_slice(&bytes)?;
        if v["binding"] != binding || crate::policy::timestamp(&v["expires_at"])? <= Utc::now() {
            return Err(Error::invalid("Cursor binding or expiry differs"));
        }
        watermark = crate::policy::timestamp(&v["watermark"])?;
        last_time = crate::policy::timestamp(&v["last_time"])?;
        last_id = string(&v, "last_id")?.to_owned();
    }
    let rows = c.query("SELECT * FROM skills WHERE created_at<=$1 AND (created_at,id::text)>($2,$3) ORDER BY created_at,id LIMIT 201", &[&watermark, &last_time, &last_id]).await?;
    let mut items = Vec::new();
    let mut processed = 0;
    for row in &rows {
        if processed == 200 || items.len() == limit {
            break;
        }
        processed += 1;
        let skill: Uuid = row.get("id");
        last_id = skill.to_string();
        last_time = row.get("created_at");
        match auth::authorize(
            c,
            ctx,
            "skill.read",
            &Resource::new("skill", skill, Some(row.get("created_by"))),
        )
        .await
        {
            Ok(()) => items.push(row_value(c, row).await?),
            Err(e) if e.code == "PERMISSION_DENIED" => (),
            Err(e) => return Err(e),
        }
    }
    let next = if processed < rows.len() {
        let raw = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"binding":binding,"watermark":watermark,"last_time":last_time,"last_id":last_id,"expires_at":watermark+chrono::Duration::minutes(15)}))?);
        Some(format!(
            "{raw}.{}",
            URL_SAFE_NO_PAD.encode(auth.token_digest(&raw))
        ))
    } else {
        None
    };
    Ok(json!({"items":items,"next_cursor":next}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Value, Value) {
        let mut manifest: Value =
            serde_json::from_str(include_str!("../tests/fixtures/secret-manifest.json")).unwrap();
        let cap = &manifest["capabilities"][0];
        let definition = json!({"name":"org.xelab.echo-python.echo","version":"1.0.0","description":"Echo a bounded message","input_schema":cap["input_schema"],"output_schema":cap["output_schema"],"stream_item_schema":null,"target":{"kind":"capability","plugin_id":manifest["plugin_id"],"contract":cap["contract"]},"mapping":"identity","maximum_timeout_ms":30000,"input_blobs":false,"tags":[]});
        manifest["skills"] = json!([definition]);
        (manifest, definition)
    }

    #[test]
    fn candidate_requires_namespace_exact_target_and_schemas() {
        let (manifest, definition) = fixture();
        validate_candidates(&manifest).unwrap();
        for pointer in [
            "/name",
            "/target/plugin_id",
            "/target/contract/schema_digest",
            "/input_schema",
            "/output_schema",
            "/stream_item_schema",
        ] {
            let mut wrong = definition.clone();
            *wrong.pointer_mut(pointer).unwrap() = match pointer {
                "/name" => json!("org.other.echo"),
                "/target/plugin_id" => json!("org.other.echo"),
                "/target/contract/schema_digest" => json!(digest(b"changed")),
                _ => json!({"type":"string"}),
            };
            assert!(validate_candidate(&manifest, &wrong).is_err(), "{pointer}");
        }
    }

    #[test]
    fn duplicate_versions_and_network_schema_refs_fail_closed() {
        let (mut manifest, definition) = fixture();
        manifest["skills"] = json!([definition, definition]);
        assert!(validate_candidates(&manifest).is_err());
        let (mut manifest, mut definition) = fixture();
        definition["input_schema"] = json!({"$ref":"https://example.invalid/schema.json"});
        manifest["capabilities"][0]["input_schema"] = definition["input_schema"].clone();
        assert!(validate_candidate(&manifest, &definition).is_err());
    }

    #[test]
    fn unimplemented_targets_cannot_be_smuggled_as_capabilities() {
        let (manifest, mut definition) = fixture();
        definition["target"]["kind"] = json!("http");
        assert!(validate_candidate(&manifest, &definition).is_err());
        let (_, mut definition) = fixture();
        definition["target"]["url"] = json!("http://127.0.0.1/admin");
        assert!(validate_candidate(&manifest, &definition).is_err());
    }

    #[test]
    fn jcs_digest_preserves_numbers_and_utf16_property_order() {
        let value: Value =
            serde_json::from_str(r#"{"\ue000":1,"😀":1.0,"a":-0.0,"b":1e30}"#).unwrap();
        let canonical = "{\"a\":0,\"b\":1e+30,\"😀\":1,\"\u{e000}\":1}";
        assert_eq!(
            definition_digest(&value).unwrap(),
            digest(canonical.as_bytes())
        );
        let changed: Value = serde_json::from_str(r#"{"\ue000":1,"😀":2,"a":0,"b":1e30}"#).unwrap();
        assert_ne!(
            definition_digest(&value).unwrap(),
            definition_digest(&changed).unwrap()
        );
        assert!(definition_digest(&json!({"maximum":9007199254740993_u64})).is_err());
    }

    // This exercises actual persisted registry state. OCI execution is covered
    // by the component suite; metadata fixtures do not claim signature testing.
    #[tokio::test]
    async fn actual_postgres_registry_disable_restore_conflict_and_archive() {
        let Some(f) = crate::backups::tests::Fixture::new().await else {
            return;
        };
        let mut c = f.app.db.connect().await.unwrap();
        let peer = "127.0.0.1".parse().unwrap();
        let (mut manifest, definition) = fixture();
        let publisher: Uuid = c
            .query_one("SELECT id FROM publishers LIMIT 1", &[])
            .await
            .unwrap()
            .get(0);
        manifest["publisher_id"] = json!(publisher);
        let installation = Uuid::new_v4();
        let hash = digest(&serde_json::to_vec(&manifest).unwrap());
        c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5,$6,'installed',now(),now())", &[&installation,&string(&manifest,"plugin_id").unwrap(),&string(&manifest,"version").unwrap(),&publisher,&hash,&manifest]).await.unwrap();
        let cap = &manifest["capabilities"][0];
        let contract = &cap["contract"];
        c.execute(
            "INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4)",
            &[
                &string(contract, "name").unwrap(),
                &string(contract, "version").unwrap(),
                &string(contract, "schema_digest").unwrap(),
                &cap,
            ],
        )
        .await
        .unwrap();
        let tx = c.transaction().await.unwrap();
        db::auth_lock(&tx, true).await.unwrap();
        let ctx = f
            .app
            .auth
            .authenticate(&tx, &f.token, peer, Uuid::new_v4())
            .await
            .unwrap();
        let body = json!({"definition":definition,"installation_id":installation});
        let empty = HashMap::new();
        let headers = HeaderMap::new();
        authorize(&tx, &ctx, "registerSkill", &empty, &body)
            .await
            .unwrap();
        let (registered, status) = execute(
            &tx,
            &f.app.auth,
            &ctx,
            "registerSkill",
            &empty,
            &body,
            &headers,
            "",
        )
        .await
        .unwrap();
        assert_eq!(status, 201);
        assert_eq!(registered["enabled"], false);
        assert_eq!(registered["availability"], "disabled");
        let skill = id(&registered, "id").unwrap();
        assert!(resolve_for_invoke(&tx, &ctx, skill).await.is_err());
        let params = HashMap::from([("skill_id".to_owned(), skill.to_string())]);
        let mut headers = HeaderMap::new();
        headers.insert("if-match", "\"rev-1\"".parse().unwrap());
        let (enabled, _) = execute(
            &tx,
            &f.app.auth,
            &ctx,
            "setSkillEnabled",
            &params,
            &json!({"enabled":true}),
            &headers,
            "",
        )
        .await
        .unwrap();
        assert_eq!(
            enabled["availability"], "unavailable",
            "No real provider exists in this registry fixture"
        );
        let fixed = resolve_for_invoke(&tx, &ctx, skill).await.unwrap();
        assert_eq!(fixed.installation_id, installation);
        assert_eq!(fixed.definition, definition);
        let (repeated, _) = execute(
            &tx,
            &f.app.auth,
            &ctx,
            "registerSkill",
            &empty,
            &body,
            &headers,
            "",
        )
        .await
        .unwrap();
        assert_eq!(repeated["id"], registered["id"]);
        assert_eq!(
            repeated["enabled"], true,
            "Duplicate registration cannot reset enablement"
        );
        let mut unsigned = body.clone();
        unsigned["definition"]["description"] = json!("Not covered by the installed manifest");
        assert_eq!(
            execute(
                &tx,
                &f.app.auth,
                &ctx,
                "registerSkill",
                &empty,
                &unsigned,
                &headers,
                ""
            )
            .await
            .unwrap_err()
            .code,
            "CONTRACT_CONFLICT"
        );
        headers.insert("if-match", "\"rev-2\"".parse().unwrap());
        execute(
            &tx,
            &f.app.auth,
            &ctx,
            "setSkillEnabled",
            &params,
            &json!({"enabled":false}),
            &headers,
            "",
        )
        .await
        .unwrap();
        assert!(resolve_for_invoke(&tx, &ctx, skill).await.is_err());
        headers.insert("if-match", "\"rev-3\"".parse().unwrap());
        execute(
            &tx,
            &f.app.auth,
            &ctx,
            "setSkillEnabled",
            &params,
            &json!({"enabled":true}),
            &headers,
            "",
        )
        .await
        .unwrap();
        resolve_for_invoke(&tx, &ctx, skill).await.unwrap();
        let mut changed = definition.clone();
        changed["description"] = json!("Changed immutable version");
        manifest["skills"] = json!([definition, changed]);
        tx.execute(
            "UPDATE installations SET manifest=$2 WHERE id=$1",
            &[&installation, &manifest],
        )
        .await
        .unwrap();
        let wrong = json!({"installation_id":installation,"definition":changed});
        assert_eq!(
            execute(
                &tx,
                &f.app.auth,
                &ctx,
                "registerSkill",
                &empty,
                &wrong,
                &headers,
                ""
            )
            .await
            .unwrap_err()
            .code,
            "CONTRACT_CONFLICT"
        );
        tx.execute(
            "UPDATE publishers SET status='revoked' WHERE id=$1",
            &[&publisher],
        )
        .await
        .unwrap();
        assert!(resolve_for_invoke(&tx, &ctx, skill).await.is_err());
        tx.execute(
            "UPDATE publishers SET status='trusted' WHERE id=$1",
            &[&publisher],
        )
        .await
        .unwrap();
        let (page, _) = execute(
            &tx,
            &f.app.auth,
            &ctx,
            "listSkills",
            &empty,
            &Value::Null,
            &headers,
            "limit=1",
        )
        .await
        .unwrap();
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert!(execute(
            &tx,
            &f.app.auth,
            &ctx,
            "listSkills",
            &empty,
            &Value::Null,
            &headers,
            "limit=1&limit=2"
        )
        .await
        .is_err());
        assert!(execute(
            &tx,
            &f.app.auth,
            &ctx,
            "listSkills",
            &empty,
            &Value::Null,
            &headers,
            "plugin_id=org.other"
        )
        .await
        .is_err());
        headers.insert("if-match", "\"rev-4\"".parse().unwrap());
        let (response, status) = execute(
            &tx,
            &f.app.auth,
            &ctx,
            "archiveSkill",
            &params,
            &Value::Null,
            &headers,
            "",
        )
        .await
        .unwrap();
        assert_eq!(status, 204);
        assert_eq!(response, Value::Null);
        assert_eq!(
            value(&tx, skill).await.unwrap()["reason_codes"],
            json!(["SKILL_ARCHIVED"])
        );
        assert!(resolve_for_invoke(&tx, &ctx, skill).await.is_err());
        headers.insert("if-match", "\"rev-5\"".parse().unwrap());
        assert!(execute(
            &tx,
            &f.app.auth,
            &ctx,
            "setSkillEnabled",
            &params,
            &json!({"enabled":true}),
            &headers,
            ""
        )
        .await
        .is_err());
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn actual_postgres_snapshot_preserves_history_and_rejects_changed_skill_bindings() {
        let Some(f) = crate::backups::tests::Fixture::new().await else {
            return;
        };
        let mut c = f.app.db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        let ctx = f
            .app
            .auth
            .authenticate(&tx, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
            .await
            .unwrap();
        let (mut manifest, definition) = fixture();
        let publisher: Uuid = tx
            .query_one("SELECT id FROM publishers LIMIT 1", &[])
            .await
            .unwrap()
            .get(0);
        manifest["publisher_id"] = json!(publisher);
        let installation = Uuid::new_v4();
        let installation_hash = digest(&serde_json::to_vec(&manifest).unwrap());
        tx.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5,$6,'installed',now(),now())",&[&installation,&string(&manifest,"plugin_id").unwrap(),&string(&manifest,"version").unwrap(),&publisher,&installation_hash,&manifest]).await.unwrap();
        let cap = &manifest["capabilities"][0];
        let contract = &cap["contract"];
        tx.execute(
            "INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4)",
            &[
                &string(contract, "name").unwrap(),
                &string(contract, "version").unwrap(),
                &string(contract, "schema_digest").unwrap(),
                &cap,
            ],
        )
        .await
        .unwrap();
        let skill = Uuid::new_v4();
        let hash = definition_digest(&definition).unwrap();
        tx.execute("INSERT INTO skills(id,name,version,installation_id,created_by,definition,definition_digest,enabled,archived_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,false,now(),now(),now())",&[&skill,&string(&definition,"name").unwrap(),&string(&definition,"version").unwrap(),&installation,&ctx.subject,&definition,&hash]).await.unwrap();
        tx.execute(
            "UPDATE publishers SET status='revoked' WHERE id=$1",
            &[&publisher],
        )
        .await
        .unwrap();
        validate_snapshot_bindings(&tx).await.unwrap();
        assert!(resolve_for_invoke(&tx, &ctx, skill).await.is_err());
        let other_installation: Uuid = tx
            .query_one(
                "SELECT id FROM installations WHERE id<>$1 LIMIT 1",
                &[&installation],
            )
            .await
            .unwrap()
            .get(0);
        for statement in [
            "UPDATE skills SET definition=jsonb_set(definition,'{description}','\"tampered description\"') WHERE id=$1",
            "UPDATE skills SET definition_digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=$1",
            "UPDATE skills SET name='org.other.skill' WHERE id=$1",
            "UPDATE skills SET version='9.0.0' WHERE id=$1",
            "UPDATE skills SET definition=jsonb_set(definition,'{target,kind}','\"http\"') WHERE id=$1",
        ] {
            tx.batch_execute("SAVEPOINT tamper").await.unwrap();
            tx.execute(statement,&[&skill]).await.unwrap();
            assert!(validate_snapshot_bindings(&tx).await.is_err(),"{statement}");
            tx.batch_execute("ROLLBACK TO SAVEPOINT tamper").await.unwrap();
        }
        tx.batch_execute("SAVEPOINT tamper").await.unwrap();
        tx.execute(
            "UPDATE skills SET installation_id=$2 WHERE id=$1",
            &[&skill, &other_installation],
        )
        .await
        .unwrap();
        assert!(validate_snapshot_bindings(&tx).await.is_err());
        tx.batch_execute("ROLLBACK TO SAVEPOINT tamper")
            .await
            .unwrap();
        tx.batch_execute("SAVEPOINT tamper").await.unwrap();
        tx.execute(
            "UPDATE capability_contracts SET schema_digest=$1 WHERE name=$2 AND version=$3",
            &[
                &digest(b"wrong target contract"),
                &string(contract, "name").unwrap(),
                &string(contract, "version").unwrap(),
            ],
        )
        .await
        .unwrap();
        assert!(validate_snapshot_bindings(&tx).await.is_err());
        tx.batch_execute("ROLLBACK TO SAVEPOINT tamper")
            .await
            .unwrap();
        // Unsupported source_kind cannot be represented in the published OCI
        // source constraint, even before the additional snapshot validation.
        tx.batch_execute("SAVEPOINT tamper").await.unwrap();
        assert!(tx
            .execute(
                "UPDATE skills SET source_kind='micro' WHERE id=$1",
                &[&skill]
            )
            .await
            .is_err());
        tx.batch_execute("ROLLBACK TO SAVEPOINT tamper")
            .await
            .unwrap();
        let call = Uuid::new_v4();
        tx.execute("INSERT INTO calls(id,owner_id,credential_id,skill_id,skill_definition_digest,contract,input_digest,state,deadline_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'unknown',now(),now())",&[&call,&ctx.subject,&ctx.credential,&skill,&hash,&contract,&digest(b"historical input")]).await.unwrap();
        validate_snapshot_bindings(&tx).await.unwrap();
        for statement in [
            "UPDATE calls SET skill_definition_digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=$1",
            "UPDATE calls SET contract=jsonb_set(contract,'{version}','\"9.0.0\"') WHERE id=$1",
            "UPDATE calls SET skill_id=NULL WHERE id=$1",
        ] {
            tx.batch_execute("SAVEPOINT tamper").await.unwrap();
            tx.execute(statement,&[&call]).await.unwrap();
            assert!(validate_snapshot_bindings(&tx).await.is_err(),"{statement}");
            tx.batch_execute("ROLLBACK TO SAVEPOINT tamper").await.unwrap();
        }
        validate_snapshot_bindings(&tx).await.unwrap();
        let kept = tx
            .query_one(
                "SELECT enabled,archived_at,definition,definition_digest FROM skills WHERE id=$1",
                &[&skill],
            )
            .await
            .unwrap();
        assert!(!kept.get::<_, bool>("enabled"));
        assert!(kept
            .get::<_, Option<DateTime<Utc>>>("archived_at")
            .is_some());
        assert_eq!(kept.get::<_, Value>("definition"), definition);
        assert_eq!(kept.get::<_, String>("definition_digest"), hash);
        tx.rollback().await.unwrap();
    }
}
