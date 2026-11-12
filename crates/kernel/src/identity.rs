//! M1 identity operations. Call inside the API transaction and authorization fence.
use crate::{
    api::{etag, path_id, read_object},
    auth::{self, Auth, Context, Resource},
    contracts::{id, openapi, string, unsigned, validate},
    db,
    error::{Error, Result},
    policy::{self, Policy},
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::{HeaderMap, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
};
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub fn handles(name: &str) -> bool {
    matches!(
        name,
        "listAccounts"
            | "getAccount"
            | "updateAccount"
            | "archiveAccount"
            | "createChildAccount"
            | "changePassword"
            | "updateInheritance"
            | "getEffectivePermissions"
            | "listRoles"
            | "listPermissions"
            | "listGroups"
            | "createGroup"
            | "getGroup"
            | "archiveGroup"
            | "publishGroupVersion"
            | "getGroupVersion"
            | "listGrants"
            | "createGrant"
            | "getGrant"
            | "revokeGrant"
            | "listApiKeys"
            | "createApiKey"
            | "getApiKey"
            | "revokeApiKey"
            | "rotateApiKey"
            | "getQuota"
            | "updateQuota"
            | "listSessions"
            | "revokeSession"
            | "listAuditEvents"
            | "checkAuthorization"
    )
}
pub fn sensitive(name: &str) -> bool {
    matches!(name, "createChildAccount" | "createApiKey" | "rotateApiKey")
}
/// Audit references contain identifiers only; never copy request/response secrets.
pub fn audit_resource(
    name: &str,
    p: &HashMap<String, String>,
    subject: Uuid,
    response: &Value,
) -> Value {
    let created = match name {
        "createChildAccount" => Some(("account", &response["account"]["id"])),
        "createApiKey" | "rotateApiKey" => Some(("credential", &response["credential"]["id"])),
        "createGroup" => Some(("group", &response["id"])),
        "createVolume" => Some(("volume", &response["resource_id"])),
        "createBackup" => Some(("backup", &response["resource_id"])),
        "createSecret" => Some(("secret", &response["id"])),
        "registerSkill" => Some(("skill", &response["id"])),
        "createWorkflow" => Some(("workflow", &response["id"])),
        "createTask" => Some(("task", &response["id"])),
        "createClient" => Some(("client", &response["id"])),
        "bindSecret" => Some(("secret", &response["spec"]["secret_id"])),
        _ => None,
    };
    if let Some((kind, id)) = created {
        if let Some(id) = id.as_str() {
            return Resource::new(kind, id, None).json();
        }
    }
    if name == "registerSkill" {
        return Resource::new("skill", "new", None).json();
    }
    if name == "createClient" {
        return Resource::new("client", "new", Some(subject)).json();
    }
    if name == "createWorkflow" {
        return Resource::new("workflow", "new", Some(subject)).json();
    }
    if name == "createTask" {
        return Resource::new("task", "new", Some(subject)).json();
    }
    if matches!(name, "getDefaultUi" | "setDefaultUi") {
        return Resource::new("platform", "node", None).json();
    }
    for (parameter, kind) in [
        ("skill_id", "skill"),
        ("workflow_id", "workflow"),
        ("task_id", "task"),
        ("client_id", "client"),
        ("call_id", "call"),
        ("credential_id", "credential"),
        ("session_id", "credential"),
        ("group_id", "group"),
        ("account_id", "account"),
        ("deployment_id", "deployment"),
        ("publisher_id", "publisher"),
        ("instance_id", "instance"),
        ("operation_id", "operation"),
        ("secret_id", "secret"),
        ("volume_id", "volume"),
        ("backup_id", "backup"),
    ] {
        if let Some(id) = p.get(parameter) {
            return Resource::new(kind, id, None).json();
        }
    }
    Resource::new("account", subject, Some(subject)).json()
}
fn denied_quota() -> Error {
    Error::new(
        "QUOTA_EXCEEDED",
        "Account tree quota would be exceeded",
        StatusCode::CONFLICT,
    )
}

async fn descendant(
    c: &impl GenericClient,
    parent: Uuid,
    child: Uuid,
    strict: bool,
) -> Result<bool> {
    Ok((!strict || parent != child)
        && c.query_opt(
            "SELECT 1 FROM account_closure WHERE ancestor_id=$1 AND descendant_id=$2",
            &[&parent, &child],
        )
        .await?
        .is_some())
}
async fn account_access(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    account: Uuid,
    action: &str,
) -> Result<()> {
    if c.query_opt("SELECT id FROM accounts WHERE id=$1", &[&account])
        .await?
        .is_none()
    {
        return Err(Error::not_found());
    }
    auth::authorize(
        c,
        ctx,
        action,
        &Resource::new("account", account, Some(account)),
    )
    .await
}

pub(crate) async fn authorize_management_snapshot(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    account: Uuid,
    rules: &Value,
) -> Result<()> {
    let resource = Resource::new("account", account, Some(account));
    if auth::rules_allow(rules, "account.manage", &resource, ctx.peer)
        || (descendant(c, ctx.subject, account, true).await?
            && auth::rules_allow(rules, "account.child.manage", &resource, ctx.peer))
    {
        Ok(())
    } else {
        Err(Error::denied())
    }
}

pub async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    p: &HashMap<String, String>,
    body: &Value,
) -> Result<()> {
    let result = match name {
        "listRoles" | "listPermissions" | "listAccounts" | "listGroups" | "listAuditEvents"
        | "checkAuthorization" => Ok(()), // collections filter each actual object
        "listSessions" => account_access(c, ctx, ctx.subject, "session.read").await,
        "getAccount" => {
            let account = path_id(p, "account_id")?;
            if account_access(c, ctx, account, "account.read")
                .await
                .is_ok()
            {
                Ok(())
            } else {
                account_access(c, ctx, account, "account.permissions.read").await
            }
        }
        "getEffectivePermissions" | "listGrants" => {
            account_access(
                c,
                ctx,
                path_id(p, "account_id")?,
                "account.permissions.read",
            )
            .await
        }
        "createChildAccount" => {
            account_access(c, ctx, path_id(p, "account_id")?, "account.child.create").await
        }
        "updateInheritance" => {
            let account = path_id(p, "account_id")?;
            if !descendant(c, ctx.subject, account, true).await? {
                Err(Error::denied())
            } else {
                account_access(c, ctx, account, "account.child.manage").await
            }
        }
        "updateAccount" | "archiveAccount" => {
            let account = path_id(p, "account_id")?;
            if name == "updateAccount"
                && body
                    .as_object()
                    .is_some_and(|b| b.len() == 1 && b.contains_key("display_name"))
                && account == ctx.subject
            {
                account_access(c, ctx, account, "account.profile.update").await
            } else if account_access(c, ctx, account, "account.manage")
                .await
                .is_ok()
            {
                Ok(())
            } else if descendant(c, ctx.subject, account, true).await? {
                account_access(c, ctx, account, "account.child.manage").await
            } else {
                Err(Error::denied())
            }
        }
        "changePassword" => {
            if path_id(p, "account_id")? != ctx.subject {
                return Err(Error::denied());
            }
            let kind: String = c
                .query_one(
                    "SELECT kind FROM credentials WHERE id=$1",
                    &[&ctx.credential],
                )
                .await?
                .get(0);
            if kind != "session" {
                Err(Error::denied())
            } else {
                Ok(())
            }
        }
        "createApiKey" | "listApiKeys" => {
            account_access(
                c,
                ctx,
                path_id(p, "account_id")?,
                if name == "createApiKey" {
                    "credential.api-key.create"
                } else {
                    "credential.api-key.read"
                },
            )
            .await
        }
        "getApiKey" | "revokeApiKey" | "rotateApiKey" | "revokeSession" => {
            let key = path_id(
                p,
                if name == "revokeSession" {
                    "session_id"
                } else {
                    "credential_id"
                },
            )?;
            let kind = if name == "revokeSession" {
                "session"
            } else {
                "api_key"
            };
            let row = c
                .query_opt(
                    "SELECT owner_id FROM credentials WHERE id=$1 AND kind=$2",
                    &[&key, &kind],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            let owner: Uuid = row.get(0);
            let action = match name {
                "getApiKey" => "credential.api-key.read",
                "revokeApiKey" => "credential.api-key.revoke",
                "rotateApiKey" => "credential.api-key.rotate",
                _ => "session.revoke",
            };
            auth::authorize(
                c,
                ctx,
                action,
                &Resource::new("credential", key, Some(owner)),
            )
            .await
        }
        "createGroup" => {
            let res = Resource::new("group", "new", Some(ctx.subject));
            auth::authorize(c, ctx, "group.create", &res).await?;
            if body["visibility"] == "public" {
                auth::authorize(c, ctx, "group.publish", &res).await?;
            }
            Ok(())
        }
        "getGroup" | "archiveGroup" | "publishGroupVersion" | "getGroupVersion" => {
            let group = path_id(p, "group_id")?;
            let row = c
                .query_opt(
                    "SELECT owner_id,visibility FROM permission_groups WHERE id=$1",
                    &[&group],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            let resource = Resource::new("group", group, Some(row.get(0)));
            let action = match name {
                "archiveGroup" => "group.archive",
                "publishGroupVersion" => "group.update",
                _ => "group.read",
            };
            // Public is template visibility, never an authority source.
            if action == "group.read" && row.get::<_, String>(1) == "public" {
                Ok(())
            } else {
                auth::authorize(c, ctx, action, &resource).await?;
                if action != "group.read" && row.get::<_, String>(1) == "public" {
                    auth::authorize(c, ctx, "group.publish", &resource).await?;
                }
                Ok(())
            }
        }
        "createGrant" => account_access(c, ctx, path_id(p, "account_id")?, "grant.create").await,
        "getGrant" | "revokeGrant" => {
            let grant = path_id(p, "grant_id")?;
            let account: Uuid = c
                .query_opt("SELECT subject_id FROM grants WHERE id=$1", &[&grant])
                .await?
                .ok_or_else(Error::not_found)?
                .get(0);
            account_access(
                c,
                ctx,
                account,
                if name == "getGrant" {
                    "account.permissions.read"
                } else {
                    "grant.revoke"
                },
            )
            .await
        }
        "getQuota" | "updateQuota" => {
            account_access(
                c,
                ctx,
                path_id(p, "account_id")?,
                if name == "getQuota" {
                    "quota.read"
                } else {
                    "quota.manage"
                },
            )
            .await
        }
        _ => Err(Error::not_found()),
    };
    result.map_err(|e| {
        if name.starts_with("get") && e.code == "PERMISSION_DENIED" {
            Error::not_found()
        } else {
            e
        }
    })
}

pub async fn account_value(c: &impl GenericClient, account: Uuid) -> Result<Value> {
    let row = c
        .query_opt(
            "SELECT to_jsonb(a) FROM accounts a WHERE id=$1",
            &[&account],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    let mut value: Value = row.get(0);
    value["inheritance"] = if let Some(row) = c
        .query_opt(
            "SELECT mode,maximum_rules FROM inheritance_grants WHERE account_id=$1",
            &[&account],
        )
        .await?
    {
        inheritance_value(
            &row.get::<_, String>(0),
            row.get::<_, Option<Value>>(1).as_ref(),
        )
    } else {
        Value::Null
    };
    project("Account", value)
}
fn inheritance_value(mode: &str, rules: Option<&Value>) -> Value {
    if mode == "selected" {
        json!({"mode":mode,"rules":rules.cloned().unwrap_or(json!([]))})
    } else {
        json!({"mode":mode})
    }
}
fn project(model: &str, raw: Value) -> Result<Value> {
    let mut value = json!({});
    for key in openapi()["components"]["schemas"][model]["required"]
        .as_array()
        .unwrap()
    {
        let key = key.as_str().unwrap();
        value[key] = raw[key].clone();
    }
    validate(model, &value)?;
    Ok(value)
}
pub async fn key_value(c: &impl GenericClient, key: Uuid) -> Result<Value> {
    let row = c
        .query_opt(
            "SELECT to_jsonb(k) FROM credentials k WHERE id=$1 AND kind='api_key'",
            &[&key],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    let mut v: Value = row.get(0);
    v["inheritance"] = inheritance_value(string(&v, "inheritance_mode")?, v.get("maximum_rules"));
    if v["status"] == "active" && policy::timestamp(&v["expires_at"])? <= Utc::now() {
        v["status"] = json!("expired");
    }
    project("ApiKey", v)
}
async fn grant_value(c: &impl GenericClient, grant: Uuid) -> Result<Value> {
    let mut v: Value = c
        .query_opt("SELECT to_jsonb(g) FROM grants g WHERE id=$1", &[&grant])
        .await?
        .ok_or_else(Error::not_found)?
        .get(0);
    let mut spec = json!({"scope":v["scope"]});
    if v["role_id"].is_null() {
        spec["source"] = json!("group");
        spec["group_version"] = json!({"group_id":v["group_id"],"version":v["group_version"]});
    } else {
        spec["source"] = json!("role");
        spec["role_id"] = v["role_id"].clone();
    }
    if !v["expires_at"].is_null() {
        spec["expires_at"] = v["expires_at"].clone();
    }
    v["spec"] = spec;
    project("Grant", v)
}

/// Recompute quota counts from the authoritative graph. Revoked/expired source
/// keys and disabled/archived accounts do not consume active-key quota.
pub async fn refresh_quotas(c: &impl GenericClient) -> Result<()> {
    c.execute("WITH RECURSIVE inactive(id) AS (SELECT id FROM credentials WHERE status<>'active' OR expires_at<=now() UNION SELECT k.id FROM credentials k JOIN inactive i ON k.issuer_credential_id=i.id) UPDATE quotas q SET descendants_used=(SELECT count(*) FROM account_closure t JOIN accounts a ON a.id=t.descendant_id WHERE t.ancestor_id=q.account_id AND t.depth>0 AND a.status<>'archived'),api_keys_used=(SELECT count(*) FROM credentials k JOIN account_closure t ON t.descendant_id=k.owner_id WHERE t.ancestor_id=q.account_id AND k.kind='api_key' AND k.status='active' AND k.expires_at>now() AND NOT EXISTS(SELECT 1 FROM inactive i WHERE i.id=k.id) AND NOT EXISTS(SELECT 1 FROM account_closure ac JOIN accounts a ON a.id=ac.ancestor_id WHERE ac.descendant_id=k.owner_id AND (a.status<>'active' OR a.expires_at<=now())) AND NOT EXISTS(SELECT 1 FROM account_closure ac JOIN inheritance_grants g ON g.account_id=ac.ancestor_id JOIN inactive i ON i.id=g.issuer_credential_id WHERE ac.descendant_id=k.owner_id))", &[]).await?;
    Ok(())
}
async fn lock_tree(c: &impl GenericClient, account: Uuid) -> Result<Vec<Uuid>> {
    let chain = auth::account_chain(c, account).await?;
    for id in &chain {
        c.query_one(
            "SELECT account_id FROM quotas WHERE account_id=$1 FOR UPDATE",
            &[id],
        )
        .await?;
    }
    Ok(chain)
}
async fn issuing_key(c: &impl GenericClient, ctx: &Context) -> Result<Option<Uuid>> {
    let kind: String = c
        .query_one(
            "SELECT kind FROM credentials WHERE id=$1",
            &[&ctx.credential],
        )
        .await?
        .get(0);
    Ok(matches!(kind.as_str(), "api_key" | "oauth_access").then_some(ctx.credential))
}
async fn bounded_expiry(
    c: &impl GenericClient,
    ctx: &Context,
    account: Uuid,
    expiry: Option<DateTime<Utc>>,
) -> Result<()> {
    if expiry.is_some_and(|e| e <= Utc::now()) {
        return Err(Error::invalid("Expiry must be in the future"));
    }
    let mut limits = Vec::new();
    for row in c.query("SELECT a.expires_at FROM accounts a JOIN account_closure t ON a.id=t.ancestor_id WHERE t.descendant_id=$1", &[&account]).await? {if let Some(e)=row.get::<_,Option<DateTime<Utc>>>(0){limits.push(e);}}
    for key in &ctx.chain {
        let row = c
            .query_one(
                "SELECT kind,expires_at FROM credentials WHERE id=$1",
                &[key],
            )
            .await?;
        if row.get::<_, String>(0) != "session" {
            limits.push(row.get(1));
        }
    }
    if limits
        .iter()
        .any(|limit| expiry.is_some_and(|e| e > *limit))
    {
        return Err(Error::denied());
    }
    Ok(())
}
pub(crate) async fn changed(c: &impl GenericClient, account: Uuid) -> Result<()> {
    c.execute("UPDATE accounts SET authz_revision=authz_revision+1 WHERE id IN(SELECT descendant_id FROM account_closure WHERE ancestor_id=$1)", &[&account]).await?;
    db::outbox(c, "identity.changed", account, &json!({})).await
}
async fn protect_owners(c: &(impl GenericClient + Sync)) -> Result<()> {
    let candidates=c.query("SELECT id FROM accounts WHERE independent_owner AND parent_id IS NULL AND status='active' AND (expires_at IS NULL OR expires_at>now())", &[]).await?;
    for row in candidates {
        let owner: Uuid = row.get(0);
        let paths = Policy::new(c, "127.0.0.1".parse().unwrap())
            .account(owner, 0)
            .await?;
        let mut unrestricted = true;
        for row in c
            .query(
                "SELECT action,resource_kinds FROM permission_definitions",
                &[],
            )
            .await?
        {
            let action: String = row.get(0);
            let kinds: Value = row.get(1);
            for kind in kinds.as_array().unwrap() {
                unrestricted &= paths.iter().any(|p| {
                    p.rule["action"] == action
                        && p.rule["resource"] == json!({"kind":kind,"match":"all"})
                        && p.rule.get("conditions").is_none_or(|v| v == &json!({}))
                });
            }
        }
        if unrestricted {
            return Ok(());
        }
    }
    Err(Error::conflict(
        "The last effective independent Owner must remain recoverable",
    ))
}

pub async fn activate(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    body: &Value,
    peer: IpAddr,
    request: Uuid,
) -> Result<Value> {
    let digest = auth.token_digest(string(body, "activation_token")?);
    let row=c.query_opt("SELECT id,parent_id FROM accounts WHERE activation_digest=$1 AND activation_expires_at>now() AND status='pending' AND kind='user' AND (expires_at IS NULL OR expires_at>now()) FOR UPDATE", &[&digest]).await?.ok_or_else(Error::credential)?;
    let account: Uuid = row.get(0);
    let recovered =
        crate::account_recovery::authorize_activation(c, auth, account, &digest).await?;
    let parent: Option<Uuid> = row.get(1);
    if let Some(parent) = parent {
        auth::validate_sources(c, None, Some(parent), peer).await?;
    } else if !recovered {
        return Err(Error::credential());
    }
    if !recovered {
        if let Some(key) = c
            .query_one(
                "SELECT issuer_credential_id FROM inheritance_grants WHERE account_id=$1",
                &[&account],
            )
            .await?
            .get::<_, Option<Uuid>>(0)
        {
            auth::validate_sources(c, Some(key), None, peer).await?;
        }
    }
    let password = string(body, "password")?.to_owned();
    let hash = auth::password_work(move || auth::password_hash(&password)).await?;
    c.execute("UPDATE accounts SET status='active',password_hash=$2,activation_digest=NULL,activation_expires_at=NULL,revision=revision+1,updated_at=now() WHERE id=$1", &[&account,&hash]).await?;
    changed(c, account).await?;
    crate::account_recovery::consume(c, account, &digest).await?;
    db::audit(
        c,
        account,
        None,
        request,
        "activateAccount",
        &Resource::new("account", account, Some(account)).json(),
        "succeeded",
        "ACCOUNT_ACTIVATED",
    )
    .await?;
    account_value(c, account).await
}

#[allow(clippy::too_many_arguments)] // Existing HTTP operation envelope; caller owns the transaction.
pub async fn execute(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    p: &HashMap<String, String>,
    body: &Value,
    headers: &HeaderMap,
    query: &str,
) -> Result<(Value, u16)> {
    match name {
        "getAccount" => Ok((account_value(c, path_id(p, "account_id")?).await?, 200)),
        "createChildAccount" => {
            let parent = path_id(p, "account_id")?;
            let chain = lock_tree(c, parent).await?;
            refresh_quotas(c).await?;
            for (level, ancestor) in chain.iter().enumerate() {
                let row = c
                    .query_one(
                        "SELECT spec,descendants_used FROM quotas WHERE account_id=$1",
                        &[ancestor],
                    )
                    .await?;
                let q: Value = row.get(0);
                if (chain.len() - level + 1) as i64 > q["maximum_depth"].as_i64().unwrap()
                    || row.get::<_, i64>(1) >= q["maximum_descendants"].as_i64().unwrap()
                {
                    return Err(denied_quota());
                }
            }
            let expiry = body.get("expires_at").map(policy::timestamp).transpose()?;
            bounded_expiry(c, ctx, parent, expiry).await?;
            let mut policy = Policy::for_context(c, ctx);
            let mut paths = policy.select(ctx, &body["inheritance"]).await?;
            let parent_paths = policy.account(parent, 0).await?;
            paths = policy.intersection(&paths, &parent_paths).await?;
            ensure_selection(&body["inheritance"], &paths)?;
            let account = Uuid::new_v4();
            let kind = body["kind"].as_str().unwrap_or("user");
            let mode = string(&body["inheritance"], "mode")?;
            let issuer = issuing_key(c, ctx).await?;
            let (activation, digest) = auth.random_token();
            let activation = if kind == "user" {
                Some(activation)
            } else {
                None
            };
            let digest = if kind == "user" { Some(digest) } else { None };
            let expires = activation
                .as_ref()
                .map(|_| Utc::now() + chrono::Duration::hours(24));
            let state = if kind == "user" { "pending" } else { "active" };
            c.execute("INSERT INTO accounts(id,parent_id,kind,status,display_name,activation_digest,activation_expires_at,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),now())", &[&account,&parent,&kind,&state,&string(body,"display_name")?,&digest,&expires,&expiry]).await?;
            c.execute("INSERT INTO account_closure(ancestor_id,descendant_id,depth) SELECT ancestor_id,$2::uuid,depth+1 FROM account_closure WHERE descendant_id=$1 UNION ALL SELECT $2::uuid,$2::uuid,0", &[&parent,&account]).await?;
            let maximum = if mode == "follow_parent" {
                None
            } else {
                Some(policy::rules(&paths))
            };
            c.execute("INSERT INTO inheritance_grants(account_id,parent_id,mode,maximum_rules,issuer_credential_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,now(),now())", &[&account,&parent,&mode,&maximum,&issuer]).await?;
            if mode != "follow_parent" {
                policy::save_sources(c, &paths, Some(account), None).await?;
            }
            let mut quota: Value = c
                .query_one("SELECT spec FROM quotas WHERE account_id=$1", &[&parent])
                .await?
                .get(0);
            quota["maximum_depth"] = json!(quota["maximum_depth"].as_i64().unwrap() - 1);
            c.execute("INSERT INTO quotas(account_id,spec,daily_bucket,created_at,updated_at) VALUES($1,$2,(now() AT TIME ZONE 'UTC')::date,now(),now())", &[&account,&quota]).await?;
            refresh_quotas(c).await?;
            changed(c, account).await?;
            Ok((
                json!({"account":account_value(c,account).await?,"activation_token":activation,"activation_expires_at":expires}),
                201,
            ))
        }
        "updateAccount" | "archiveAccount" => {
            let account = path_id(p, "account_id")?;
            let row = c
                .query_one("SELECT * FROM accounts WHERE id=$1 FOR UPDATE", &[&account])
                .await?;
            etag(headers, row.get("revision"))?;
            if row.get::<_, String>("status") == "archived" {
                return Err(Error::conflict("Archived accounts cannot be restored"));
            }
            let status = if name == "archiveAccount" {
                "archived"
            } else {
                body["status"].as_str().unwrap_or("")
            };
            if status == "active" && row.get::<_, String>("status") == "pending" {
                return Err(Error::conflict("Pending users require activation"));
            }
            if status == "active" {
                if let Some(parent) = row.get::<_, Option<Uuid>>("parent_id") {
                    auth::validate_sources(c, None, Some(parent), ctx.peer).await?;
                }
            }
            let expires = if let Some(v) = body.get("expires_at") {
                if v.is_null() {
                    None
                } else {
                    Some(policy::timestamp(v)?)
                }
            } else {
                row.get("expires_at")
            };
            if body.get("expires_at").is_some() {
                bounded_expiry(c, ctx, account, expires).await?;
            }
            let name = body["display_name"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or(row.get("display_name"));
            let status = if status.is_empty() {
                row.get::<_, String>("status")
            } else {
                status.into()
            };
            c.execute("UPDATE accounts SET display_name=$2,status=$3,expires_at=$4,revision=revision+1,updated_at=now() WHERE id=$1", &[&account,&name,&status,&expires]).await?;
            protect_owners(c).await?;
            if status != "active" {
                crate::oauth::revoke_account(c, account).await?;
            }
            changed(c, account).await?;
            refresh_quotas(c).await?;
            if status == "active" {
                check_all_quotas(c).await?;
            }
            if status == "archived" {
                Ok((Value::Null, 204))
            } else {
                Ok((account_value(c, account).await?, 200))
            }
        }
        "updateInheritance" => {
            let account = path_id(p, "account_id")?;
            let row = c
                .query_one(
                    "SELECT revision,parent_id FROM accounts WHERE id=$1 FOR UPDATE",
                    &[&account],
                )
                .await?;
            etag(headers, row.get(0))?;
            let parent: Uuid = row.get(1);
            let old = c
                .query_one(
                    "SELECT issuer_credential_id FROM inheritance_grants WHERE account_id=$1",
                    &[&account],
                )
                .await?;
            let original: Option<Uuid> = old.get(0);
            let caller = issuing_key(c, ctx).await?;
            // Updating a descendant cannot detach its original credential source.
            if caller.is_some() && original != caller {
                return Err(Error::denied());
            }
            let mut policy = Policy::for_context(c, ctx);
            let selected = policy.select(ctx, body).await?;
            let parent_paths = policy.account(parent, 0).await?;
            let mut paths = policy.intersection(&selected, &parent_paths).await?;
            if let Some(key) = original {
                let source = policy.credential(key, 0).await?;
                paths = policy.intersection(&paths, &source).await?;
            }
            ensure_selection(body, &paths)?;
            let mode = string(body, "mode")?;
            let maximum = if mode == "follow_parent" {
                None
            } else {
                Some(policy::rules(&paths))
            };
            c.execute("UPDATE inheritance_grants SET mode=$2,maximum_rules=$3,revision=revision+1,updated_at=now() WHERE account_id=$1", &[&account,&mode,&maximum]).await?;
            c.execute(
                "DELETE FROM grant_provenance WHERE derived_account_id=$1",
                &[&account],
            )
            .await?;
            if mode != "follow_parent" {
                policy::save_sources(c, &paths, Some(account), None).await?;
            }
            c.execute(
                "UPDATE accounts SET revision=revision+1,updated_at=now() WHERE id=$1",
                &[&account],
            )
            .await?;
            changed(c, account).await?;
            Ok((account_value(c, account).await?, 200))
        }
        "changePassword" => {
            let account = ctx.subject;
            let row = c
                .query_one(
                    "SELECT revision,password_hash,kind FROM accounts WHERE id=$1 FOR UPDATE",
                    &[&account],
                )
                .await?;
            etag(headers, row.get(0))?;
            if row.get::<_, String>(2) != "user" {
                return Err(Error::denied());
            }
            auth.check_login_budget(account, ctx.peer)?;
            let hash: String = row.get(1);
            let current = string(body, "current_password")?.to_owned();
            let next = string(body, "new_password")?.to_owned();
            let hash = auth::password_work(move || {
                let old = PasswordHash::new(&hash).map_err(|_| Error::credential())?;
                Argon2::default()
                    .verify_password(current.as_bytes(), &old)
                    .map_err(|_| Error::credential())?;
                auth::password_hash(&next)
            })
            .await?;
            auth.login_succeeded(account, ctx.peer)?;
            c.execute("UPDATE accounts SET password_hash=$2,revision=revision+1,updated_at=now() WHERE id=$1", &[&account,&hash]).await?;
            c.execute("UPDATE credentials SET status='revoked',revision=revision+1,updated_at=now() WHERE owner_id=$1 AND kind IN ('session','oauth_access','oauth_refresh') AND status='active'", &[&account]).await?;
            crate::oauth::revoke_account(c, account).await?;
            changed(c, account).await?;
            Ok((Value::Null, 204))
        }
        "createApiKey" | "rotateApiKey" => issue_key(c, auth, ctx, name, p, body, headers).await,
        "getApiKey" => Ok((key_value(c, path_id(p, "credential_id")?).await?, 200)),
        "revokeApiKey" | "revokeSession" => {
            let key = path_id(
                p,
                if name == "revokeSession" {
                    "session_id"
                } else {
                    "credential_id"
                },
            )?;
            let row = c
                .query_one(
                    "SELECT owner_id,revision FROM credentials WHERE id=$1 FOR UPDATE",
                    &[&key],
                )
                .await?;
            etag(headers, row.get(1))?;
            c.execute("UPDATE credentials SET status='revoked',revision=revision+1,updated_at=now() WHERE id=$1", &[&key]).await?;
            if name == "revokeSession" {
                crate::oauth::revoke_session(c, key).await?;
            }
            changed(c, row.get(0)).await?;
            refresh_quotas(c).await?;
            Ok((Value::Null, 204))
        }
        "createGroup" | "publishGroupVersion" => {
            let rules = body["rules"].as_array().unwrap();
            Policy::for_context(c, ctx)
                .require_subset(ctx, rules)
                .await?;
            let group;
            if name == "createGroup" {
                group = Uuid::new_v4();
                c.execute("INSERT INTO permission_groups(id,owner_id,name,visibility,latest_version,status,created_at,updated_at) VALUES($1,$2,$3,$4,1,'active',now(),now())", &[&group,&ctx.subject,&string(body,"name")?,&body["visibility"].as_str().unwrap_or("private")]).await?;
            } else {
                group = path_id(p, "group_id")?;
                let row = c
                    .query_one(
                        "SELECT revision,status FROM permission_groups WHERE id=$1 FOR UPDATE",
                        &[&group],
                    )
                    .await?;
                etag(headers, row.get(0))?;
                if row.get::<_, String>(1) != "active" {
                    return Err(Error::conflict("Group is archived"));
                }
                c.execute("UPDATE permission_groups SET latest_version=latest_version+1,revision=revision+1,updated_at=now() WHERE id=$1", &[&group]).await?;
            }
            let version: i64 = c
                .query_one(
                    "SELECT latest_version FROM permission_groups WHERE id=$1",
                    &[&group],
                )
                .await?
                .get(0);
            c.execute("INSERT INTO group_versions(group_id,version,rules,created_by,created_at) VALUES($1,$2,$3,$4,now())", &[&group,&version,&body["rules"],&ctx.subject]).await?;
            changed(c, ctx.subject).await?;
            if name == "createGroup" {
                Ok((
                    read_object(c, "permission_groups", group, "PermissionGroup").await?,
                    201,
                ))
            } else {
                Ok((group_version(c, group, version).await?, 201))
            }
        }
        "getGroup" => Ok((
            read_object(
                c,
                "permission_groups",
                path_id(p, "group_id")?,
                "PermissionGroup",
            )
            .await?,
            200,
        )),
        "getGroupVersion" => {
            let version = p
                .get("version_id")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::invalid("Invalid group version"))?;
            Ok((
                group_version(c, path_id(p, "group_id")?, version).await?,
                200,
            ))
        }
        "archiveGroup" => {
            let group = path_id(p, "group_id")?;
            let row = c
                .query_one(
                    "SELECT revision FROM permission_groups WHERE id=$1 FOR UPDATE",
                    &[&group],
                )
                .await?;
            etag(headers, row.get(0))?;
            c.execute("UPDATE permission_groups SET status='archived',revision=revision+1,updated_at=now() WHERE id=$1", &[&group]).await?;
            protect_owners(c).await?;
            invalidate_all(c, group).await?;
            Ok((Value::Null, 204))
        }
        "createGrant" => create_grant(c, ctx, p, body).await,
        "getGrant" => Ok((grant_value(c, path_id(p, "grant_id")?).await?, 200)),
        "revokeGrant" => {
            let grant = path_id(p, "grant_id")?;
            let row = c
                .query_one(
                    "SELECT revision FROM grants WHERE id=$1 FOR UPDATE",
                    &[&grant],
                )
                .await?;
            etag(headers, row.get(0))?;
            c.execute("UPDATE grants SET status='revoked',revision=revision+1,updated_at=now() WHERE id=$1", &[&grant]).await?;
            protect_owners(c).await?;
            invalidate_all(c, grant).await?;
            Ok((Value::Null, 204))
        }
        "getQuota" | "updateQuota" => {
            let account = path_id(p, "account_id")?;
            refresh_quotas(c).await?;
            if name == "updateQuota" {
                let row = c
                    .query_one(
                        "SELECT revision FROM quotas WHERE account_id=$1 FOR UPDATE",
                        &[&account],
                    )
                    .await?;
                etag(headers, row.get(0))?;
                refresh_quotas(c).await?;
                for row in c.query("SELECT q.spec,t.depth FROM quotas q JOIN account_closure t ON q.account_id=t.ancestor_id WHERE t.descendant_id=$1 AND t.depth>0 ORDER BY t.depth DESC", &[&account]).await?{let ancestor:Value=row.get(0);let depth:i32=row.get(1);for (key,value) in body.as_object().unwrap(){let allowance=ancestor[key].as_i64().unwrap()-if key=="maximum_depth"{i64::from(depth)}else{0};if value.as_i64().unwrap()>allowance{return Err(denied_quota());}}}
                c.execute("UPDATE quotas SET spec=$2,revision=revision+1,updated_at=now() WHERE account_id=$1", &[&account,&body]).await?;
                check_all_quotas(c).await?;
                changed(c, account).await?;
            }
            let mut value: Value = c
                .query_one(
                    "SELECT to_jsonb(q) FROM quotas q WHERE account_id=$1",
                    &[&account],
                )
                .await?
                .get(0);
            value["id"] = json!(account);
            Ok((project("Quota", value)?, 200))
        }
        "getEffectivePermissions" => {
            let account = path_id(p, "account_id")?;
            let revision: i64 = c
                .query_one(
                    "SELECT authz_revision FROM accounts WHERE id=$1",
                    &[&account],
                )
                .await?
                .get(0);
            let (rules, blocked) =
                match auth::validate_sources(c, None, Some(account), ctx.peer).await {
                    Ok(_) => (
                        policy::rules(&Policy::for_context(c, ctx).account(account, 0).await?),
                        json!([]),
                    ),
                    Err(e) if e.code == "INVALID_CREDENTIAL" => (json!([]), json!([account])),
                    Err(e) => return Err(e),
                };
            Ok((
                json!({"account_id":account,"authz_revision":revision,"rules":rules,"blocked_by":blocked}),
                200,
            ))
        }
        "checkAuthorization" => {
            let requested = json!({"action":body["action"],"resource":body["resource"]});
            let result = Policy::for_context(c, ctx)
                .covers_now(ctx, &requested)
                .await;
            let allowed = match result {
                Ok(allowed) => allowed,
                Err(e) if matches!(e.code, "PERMISSION_DENIED" | "INVALID_ARGUMENT") => false,
                Err(e) => return Err(e),
            };
            let rev: i64 = c
                .query_one(
                    "SELECT authz_revision FROM accounts WHERE id=$1",
                    &[&ctx.subject],
                )
                .await?
                .get(0);
            Ok((
                json!({"allowed":allowed,"code":if allowed{"ALLOW"}else{"NO_GRANT"},"authz_revision":rev}),
                200,
            ))
        }
        _ if name.starts_with("list") => Ok((list(c, auth, ctx, name, p, query).await?, 200)),
        _ => Err(Error::not_found()),
    }
}

fn ensure_selection(spec: &Value, paths: &[policy::Path]) -> Result<()> {
    if spec["mode"] == "selected" && paths.is_empty() {
        Err(Error::denied())
    } else {
        Ok(())
    }
}
async fn invalidate_all(c: &impl GenericClient, resource: Uuid) -> Result<()> {
    c.execute("UPDATE accounts SET authz_revision=authz_revision+1", &[])
        .await?;
    db::outbox(c, "identity.changed", resource, &json!({})).await
}
async fn group_version(c: &impl GenericClient, group: Uuid, version: i64) -> Result<Value> {
    let row = c
        .query_opt(
            "SELECT to_jsonb(v) FROM group_versions v WHERE group_id=$1 AND version=$2",
            &[&group, &version],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    project("GroupVersion", row.get(0))
}
async fn check_all_quotas(c: &impl GenericClient) -> Result<()> {
    let exceeds=c.query_one("SELECT EXISTS(SELECT 1 FROM quotas q WHERE q.descendants_used>(q.spec->>'maximum_descendants')::bigint OR q.api_keys_used>(q.spec->>'maximum_api_keys')::bigint OR q.concurrent_calls_used>(q.spec->>'maximum_concurrent_calls')::bigint OR (q.daily_bucket=(now() AT TIME ZONE 'UTC')::date AND q.daily_calls_used>(q.spec->>'daily_calls')::bigint)) OR EXISTS(SELECT 1 FROM account_closure t JOIN accounts a ON a.id=t.descendant_id JOIN quotas q ON q.account_id=t.ancestor_id WHERE a.status<>'archived' AND t.depth+1>(q.spec->>'maximum_depth')::bigint)", &[]).await?.get::<_,bool>(0);
    if exceeds {
        Err(denied_quota())
    } else {
        Ok(())
    }
}

/// Lifetime business calls charged to a key include key-derived credentials and
/// accounts. Revocation never deletes the journal, so the counter cannot reset.
pub async fn key_calls(c: &impl GenericClient, key: Uuid) -> Result<i64> {
    Ok(c.query_one("WITH RECURSIVE edges(source,target) AS (SELECT issuer_credential_id,id FROM credentials WHERE issuer_credential_id IS NOT NULL UNION ALL SELECT issuer_credential_id,account_id FROM inheritance_grants WHERE issuer_credential_id IS NOT NULL UNION ALL SELECT parent_id,id FROM accounts WHERE parent_id IS NOT NULL UNION ALL SELECT owner_id,id FROM credentials),derived(id) AS (SELECT $1::uuid UNION SELECT e.target FROM edges e JOIN derived d ON e.source=d.id) SELECT count(*) FROM calls WHERE credential_id IN(SELECT id FROM derived) OR id IN(SELECT call_id FROM call_credential_charges WHERE credential_id=$1)", &[&key]).await?.get(0))
}

/// Choose one live authorization alternative under the caller's call_lock.
/// All keys on that proof are conjunctive; unrelated alternatives are not billed.
pub async fn call_sources(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    resource: &Resource,
) -> Result<BTreeSet<Uuid>> {
    call_sources_for(c, ctx, "capability.invoke", resource).await
}

/// Keep proof-source charging identical for Skill and its underlying action.
pub(crate) async fn call_sources_for(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    action: &str,
    resource: &Resource,
) -> Result<BTreeSet<Uuid>> {
    let paths = Policy::for_context(c, ctx)
        .credential(ctx.credential, 0)
        .await?;
    call_sources_from_paths(c, ctx, action, resource, paths).await
}

pub(crate) async fn call_sources_from_paths(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    action: &str,
    resource: &Resource,
    paths: Vec<crate::policy::Path>,
) -> Result<BTreeSet<Uuid>> {
    if !ctx.proxy_allows(action, resource) {
        return Err(Error::denied());
    }
    let mut alternatives = Vec::new();
    'candidate: for path in paths {
        if !auth::rules_allow(&json!([path.rule]), action, resource, ctx.peer) {
            continue;
        }
        let mut keys: BTreeSet<_> = ctx.chain.iter().copied().collect();
        let sources: Vec<_> = path.sources.into_iter().collect();
        let issuers = c
            .query(
                "SELECT issuer_id,issuer_credential_id FROM grants WHERE id=ANY($1)",
                &[&sources],
            )
            .await?;
        if issuers.len() != sources.len() {
            return Err(Error::denied());
        }
        for row in issuers {
            match auth::validate_sources(c, row.get(1), Some(row.get(0)), ctx.peer).await {
                Ok(sources) => keys.extend(sources),
                // A prepared alternative may expire while admission waits for
                // the ledger. Other independent proofs remain eligible.
                Err(error) if error.code == "INVALID_CREDENTIAL" => continue 'candidate,
                Err(error) => return Err(error),
            }
        }
        alternatives.push(keys);
    }
    if alternatives.is_empty() {
        return Err(Error::denied());
    }
    alternatives.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    alternatives.dedup();
    let mut available = HashMap::new();
    for keys in alternatives {
        let mut allowed = true;
        for key in &keys {
            let remaining = if let Some(remaining) = available.get(key) {
                *remaining
            } else {
                let conditions: Value = c
                    .query_one("SELECT conditions FROM credentials WHERE id=$1", &[key])
                    .await?
                    .get(0);
                let remaining = match conditions.get("max_calls") {
                    Some(max) => {
                        let used = u64::try_from(key_calls(c, *key).await?)
                            .map_err(|_| Error::denied())?;
                        used < unsigned(max)?
                    }
                    None => true,
                };
                available.insert(*key, remaining);
                remaining
            };
            allowed &= remaining;
        }
        if allowed {
            return Ok(keys);
        }
    }
    Err(Error::new(
        "QUOTA_EXCEEDED",
        "Credential lifetime call budget is exhausted",
        StatusCode::CONFLICT,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn issue_key(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    p: &HashMap<String, String>,
    body: &Value,
    headers: &HeaderMap,
) -> Result<(Value, u16)> {
    let old = if name == "rotateApiKey" {
        Some(path_id(p, "credential_id")?)
    } else {
        None
    };
    let old_row = if let Some(old) = old {
        Some(
            c.query_one("SELECT * FROM credentials WHERE id=$1 FOR UPDATE", &[&old])
                .await?,
        )
    } else {
        None
    };
    let owner = if let Some(row) = &old_row {
        etag(headers, row.get("revision"))?;
        row.get("owner_id")
    } else {
        path_id(p, "account_id")?
    };
    if !descendant(c, ctx.subject, owner, false).await? {
        return Err(Error::denied());
    }
    lock_tree(c, owner).await?;
    let expiry = policy::timestamp(&body["conditions"]["expires_at"])?;
    if expiry > Utc::now() + chrono::Duration::days(365) {
        return Err(Error::invalid("API Key lifetime exceeds 365 days"));
    }
    policy::validate_conditions(&body["conditions"])?;
    bounded_expiry(c, ctx, owner, Some(expiry)).await?;
    let mode = string(&body["inheritance"], "mode")?;
    let mut policy = Policy::for_context(c, ctx);
    let selected = policy.select(ctx, &body["inheritance"]).await?;
    let owned = policy.account(owner, 0).await?;
    let mut paths = policy.intersection(&selected, &owned).await?;
    let mut issuer = issuing_key(c, ctx).await?;
    if let (Some(old), Some(row)) = (old, &old_row) {
        if row.get::<_, String>("status") != "active" {
            return Err(Error::conflict("Only an active key can be rotated"));
        }
        let limits = policy.credential(old, 0).await?;
        paths = policy.intersection(&paths, &limits).await?;
        if mode == "follow_parent"
            && row.get::<_, Option<String>>("inheritance_mode").as_deref() != Some("follow_parent")
        {
            return Err(Error::denied());
        }
        let old_conditions: Value = row.get("conditions");
        let combined = policy::intersect_conditions(&old_conditions, &body["conditions"])
            .ok_or_else(Error::denied)?;
        let mut proposed = body["conditions"].clone();
        proposed.as_object_mut().unwrap().remove("max_calls");
        if combined != proposed {
            return Err(Error::denied());
        }
        if let Some(max) = old_conditions.get("max_calls") {
            let used = u64::try_from(key_calls(c, old).await?).map_err(|_| Error::denied())?;
            let remaining = unsigned(max)?.saturating_sub(used);
            let requested = body["conditions"]
                .get("max_calls")
                .map(unsigned)
                .transpose()?;
            if requested.is_none_or(|max| max > remaining) {
                return Err(Error::denied());
            }
        }
        let original: Option<Uuid> = row.get("issuer_credential_id");
        if issuer == Some(old) || issuer.is_none() {
            issuer = original;
        } else if original.is_some_and(|k| !ctx.chain.contains(&k)) {
            return Err(Error::denied());
        }
    }
    ensure_selection(&body["inheritance"], &paths)?;
    let key = Uuid::new_v4();
    let (token, digest) = auth.random_token();
    let prefix = &token[..8];
    let maximum = if mode == "follow_parent" {
        None
    } else {
        Some(policy::rules(&paths))
    };
    c.execute("INSERT INTO credentials(id,owner_id,kind,name,prefix,hmac_key_id,verification_digest,issuer_credential_id,status,inheritance_mode,maximum_rules,conditions,expires_at,created_at,updated_at) VALUES($1,$2,'api_key',$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,now(),now())", &[&key,&owner,&string(body,"name")?,&prefix,&auth.key_id.as_str(),&digest,&issuer,&mode,&maximum,&body["conditions"],&expiry]).await?;
    if mode != "follow_parent" {
        policy::save_sources(c, &paths, None, Some(key)).await?;
    }
    if let Some(old) = old {
        c.execute("UPDATE credentials SET status='revoked',revision=revision+1,updated_at=now() WHERE id=$1", &[&old]).await?;
    }
    refresh_quotas(c).await?;
    check_all_quotas(c).await?;
    changed(c, owner).await?;
    Ok((
        json!({"credential":key_value(c,key).await?,"secret":token}),
        201,
    ))
}

async fn create_grant(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    p: &HashMap<String, String>,
    body: &Value,
) -> Result<(Value, u16)> {
    let account = path_id(p, "account_id")?;
    let scope = &body["scope"];
    let role = body["role_id"].as_str();
    let mut group = None;
    let mut version = None;
    let mut rules = Vec::new();
    if let Some(role) = role {
        let def: Value = c
            .query_one(
                "SELECT definition FROM role_definitions WHERE id=$1",
                &[&role],
            )
            .await?
            .get(0);
        for action in def["actions"].as_array().unwrap() {
            if policy::registered(c, action.as_str().unwrap(), string(scope, "kind")?).await? {
                rules.push(json!({"action":action,"resource":scope}));
            }
        }
        if role == "Member"
            && !matches!(
                scope["kind"].as_str(),
                Some("capability" | "skill" | "deployment")
            )
            && (scope["match"] != "owned_by" || scope["owner_id"] != account.to_string())
        {
            return Err(Error::denied());
        }
    } else {
        group = Some(id(&body["group_version"], "group_id")?);
        version = body["group_version"]["version"].as_i64();
        let row=c.query_opt("SELECT v.rules,g.owner_id,g.visibility FROM group_versions v JOIN permission_groups g ON g.id=v.group_id WHERE v.group_id=$1 AND v.version=$2 AND g.status='active'", &[&group,&version]).await?.ok_or_else(Error::not_found)?;
        if row.get::<_, Uuid>(1) != ctx.subject && row.get::<_, String>(2) != "public" {
            return Err(Error::not_found());
        }
        let raw: Value = row.get(0);
        let policy = Policy::for_context(c, ctx);
        for rule in raw.as_array().unwrap() {
            let left = policy::Path {
                rule: rule.clone(),
                sources: Default::default(),
            };
            let right = policy::Path {
                rule: json!({"action":rule["action"],"resource":scope}),
                sources: Default::default(),
            };
            rules.extend(
                policy
                    .intersection(&[left], &[right])
                    .await?
                    .into_iter()
                    .map(|p| p.rule),
            );
        }
    }
    if rules.is_empty() {
        return Err(Error::invalid(
            "Grant has no action for the selected resource kind",
        ));
    }
    let expires = body.get("expires_at").map(policy::timestamp).transpose()?;
    if let Some(expiry) = expires {
        if expiry <= Utc::now() {
            return Err(Error::invalid("Grant is already expired"));
        }
        for rule in &mut rules {
            rule["conditions"] = policy::intersect_conditions(
                rule.get("conditions").unwrap_or(&json!({})),
                &json!({"expires_at":expiry}),
            )
            .ok_or_else(Error::denied)?;
        }
    }
    Policy::for_context(c, ctx)
        .require_subset(ctx, &rules)
        .await?;
    let grant = Uuid::new_v4();
    let issuer = issuing_key(c, ctx).await?;
    c.execute("INSERT INTO grants(id,subject_id,issuer_id,issuer_credential_id,role_id,group_id,group_version,scope,expires_at,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',now(),now())", &[&grant,&account,&ctx.subject,&issuer,&role,&group,&version,&scope,&expires]).await?;
    invalidate_all(c, grant).await?;
    Ok((grant_value(c, grant).await?, 201))
}

// Signed cursors bind the actor, credential, operation, filters and creation
// watermark. Every page re-evaluates visibility; a cursor conveys no authority.
pub(crate) async fn list(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    p: &HashMap<String, String>,
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
    let mut sorted: Vec<_> = args.iter().collect();
    sorted.sort();
    let binding = json!({"subject":ctx.subject,"credential":ctx.credential,"operation":name,"params":p,"filters":sorted,"limit":limit});
    let mut watermark = Utc::now();
    let mut last_time = DateTime::<Utc>::UNIX_EPOCH;
    let mut last_id = String::new();
    if let Some(cursor) = cursor {
        let (raw, mac) = cursor
            .split_once('.')
            .ok_or_else(|| Error::invalid("Invalid cursor"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| Error::invalid("Invalid cursor"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(mac)
            .map_err(|_| Error::invalid("Invalid cursor"))?;
        if !auth.verify_mac(raw, &signature) {
            return Err(Error::invalid("Invalid cursor"));
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        if v["binding"] != binding || policy::timestamp(&v["expires_at"])? <= Utc::now() {
            return Err(Error::invalid("Cursor binding or expiry differs"));
        }
        watermark = policy::timestamp(&v["watermark"])?;
        last_time = policy::timestamp(&v["last_time"])?;
        last_id = string(&v, "last_id")?.into();
    }
    let (table, model, action, kind) = match name {
        "listAccounts" => ("accounts", "Account", "account.read", "account"),
        "listSessions" => ("credentials", "Session", "session.read", "account"),
        "listApiKeys" => (
            "credentials",
            "ApiKey",
            "credential.api-key.read",
            "credential",
        ),
        "listGroups" => (
            "permission_groups",
            "PermissionGroup",
            "group.read",
            "group",
        ),
        "listGrants" => ("grants", "Grant", "account.permissions.read", "account"),
        "listAuditEvents" => ("audit_events", "AuditEvent", "audit.read", "audit"),
        "listRoles" => ("role_definitions", "Role", "", ""),
        "listPermissions" => ("permission_definitions", "PermissionDefinition", "", ""),
        "listVolumes" => ("kernel_volumes", "Volume", "volume.read", "volume"),
        "listBackups" => ("backups", "Backup", "backup.read", "backup"),
        "listSecrets" => ("secrets", "Secret", "secret.metadata.read", "secret"),
        "listSecretBindings" => ("secret_bindings", "SecretBinding", "secret.bind", "secret"),
        _ => return Err(Error::not_found()),
    };
    if name == "listRoles" || name == "listPermissions" {
        if !args.is_empty() {
            return Err(Error::invalid("Unsupported filter"));
        }
        let key = if name == "listRoles" { "id" } else { "action" };
        let sql =
            format!("SELECT to_jsonb(t) FROM {table} t WHERE {key}>$1 ORDER BY {key} LIMIT $2");
        let rows = c.query(&sql, &[&last_id, &((limit + 1) as i64)]).await?;
        let has_more = rows.len() > limit;
        let mut items = Vec::new();
        for row in rows.into_iter().take(limit) {
            let mut v: Value = row.get(0);
            last_id = string(&v, key)?.into();
            if name == "listRoles" {
                v = json!({"id":v["id"],"actions":v["definition"]["actions"],"description":v["definition"]["description"]});
            }
            items.push(project(model, v)?);
        }
        return Ok(
            json!({"items":items,"next_cursor":if has_more{Some(encode_cursor(auth,&binding,watermark,last_time,&last_id)?)}else{None}}),
        );
    }
    let parent = args
        .remove("parent_id")
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| Error::invalid("Invalid parent filter"))?;
    let subject = args
        .remove("subject_id")
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| Error::invalid("Invalid subject filter"))?;
    let from = args
        .remove("from")
        .map(|s| policy::timestamp(&json!(s)))
        .transpose()?;
    let until = args
        .remove("until")
        .map(|s| policy::timestamp(&json!(s)))
        .transpose()?;
    if !args.is_empty()
        || (name != "listAccounts" && parent.is_some())
        || (name != "listAuditEvents" && (subject.is_some() || from.is_some() || until.is_some()))
    {
        return Err(Error::invalid("Unsupported filter"));
    }
    let sql=format!("SELECT to_jsonb(t) FROM {table} t WHERE created_at<=$1 AND (created_at,id::text)>($2,$3) ORDER BY created_at,id LIMIT 201");
    let rows = c.query(&sql, &[&watermark, &last_time, &last_id]).await?;
    let available = policy::rules(
        &Policy::for_context(c, ctx)
            .credential(ctx.credential, 0)
            .await?,
    );
    let mut items = Vec::new();
    let mut processed = 0;
    for row in &rows {
        if processed == 200 || items.len() == limit {
            break;
        }
        processed += 1;
        let mut v: Value = row.get(0);
        let object = id(&v, "id")?;
        last_id = object.to_string();
        last_time = policy::timestamp(&v["created_at"])?;
        if parent.is_some_and(|id| v["parent_id"] != id.to_string())
            || subject.is_some_and(|id| v["subject_id"] != id.to_string())
            || from.is_some_and(|t| last_time < t)
            || until.is_some_and(|t| last_time >= t)
        {
            continue;
        }
        let resource = match name {
            "listAccounts" => Resource::new(kind, object, Some(object)),
            "listSessions" => {
                if v["kind"] != "session" || v["owner_id"] != ctx.subject.to_string() {
                    continue;
                }
                Resource::new(kind, ctx.subject, Some(ctx.subject))
            }
            "listApiKeys" => {
                let account = path_id(p, "account_id")?;
                if v["kind"] != "api_key" || v["owner_id"] != account.to_string() {
                    continue;
                }
                Resource::new(kind, object, Some(account))
            }
            "listGrants" => {
                let account = path_id(p, "account_id")?;
                if v["subject_id"] != account.to_string() {
                    continue;
                }
                Resource::new(kind, account, Some(account))
            }
            "listAuditEvents" => Resource::new(
                kind,
                object,
                v["subject_id"].as_str().and_then(|v| v.parse().ok()),
            ),
            "listSecretBindings" => {
                let secret = id(&v, "secret_id")?;
                let row = c
                    .query_one("SELECT owner_id FROM secrets WHERE id=$1", &[&secret])
                    .await?;
                if crate::secrets::deployment_access(c, ctx, id(&v, "deployment_id")?)
                    .await
                    .is_err()
                {
                    continue;
                }
                Resource::new("secret", secret, Some(row.get(0)))
            }
            "listBackups" => Resource::new(kind, object, Some(id(&v, "created_by")?)),
            _ => Resource::new(kind, object, Some(id(&v, "owner_id")?)),
        };
        let visible = auth::rules_allow(&available, action, &resource, ctx.peer)
            || (name == "listAccounts"
                && auth::rules_allow(&available, "account.permissions.read", &resource, ctx.peer))
            || (name == "listGroups" && v["visibility"] == "public");
        if !visible {
            continue;
        }
        v = match name {
            "listAccounts" => account_value(c, object).await?,
            "listApiKeys" => key_value(c, object).await?,
            "listGrants" => grant_value(c, object).await?,
            "listSecretBindings" => crate::secrets::binding_value(c, object).await?,
            "listSecrets" => crate::secrets::metadata(c, object).await?,
            "listSessions" => {
                v["account_id"] = v["owner_id"].clone();
                v["last_seen_at"] = v["last_used_at"].clone();
                project(model, v)?
            }
            _ => project(model, v)?,
        };
        items.push(v);
    }
    let next = if processed < rows.len() {
        Some(encode_cursor(
            auth, &binding, watermark, last_time, &last_id,
        )?)
    } else {
        None
    };
    Ok(json!({"items":items,"next_cursor":next}))
}
fn encode_cursor(
    auth: &Auth,
    binding: &Value,
    watermark: DateTime<Utc>,
    last_time: DateTime<Utc>,
    last_id: &str,
) -> Result<String> {
    let raw=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"binding":binding,"watermark":watermark,"last_time":last_time,"last_id":last_id,"expires_at":watermark+chrono::Duration::minutes(15)}))?);
    Ok(format!(
        "{raw}.{}",
        URL_SAFE_NO_PAD.encode(auth.token_digest(&raw))
    ))
}
