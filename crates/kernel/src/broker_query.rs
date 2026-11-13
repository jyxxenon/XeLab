//! Query a previously admitted ordinary capability; never execute or retry it.
//! No authorization, ledger, or provider lock is retained across the RPC.
use crate::{
    api::App,
    auth::{self, Context, Resource},
    contracts::{digest, strict_json, unsigned, validate, validate_business},
    db,
    error::{Error, Result},
    rpc::{self, capability_service_client::CapabilityServiceClient},
};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::OnceLock, time::Duration};
use tokio::sync::Semaphore;
use tokio_postgres::Transaction;
use uuid::Uuid;

const QUERY_LIMIT: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct Binding {
    call: Uuid,
    subject: Uuid,
    credential: Uuid,
    instance: Uuid,
    generation: i64,
    deadline: DateTime<Utc>,
    key: String,
    contract: Value,
    capability: Value,
    skill: Option<(Uuid, String, Value)>,
}

enum Outcome {
    Completed(Value),
    Failed(Value),
}

async fn context(
    tx: &Transaction<'_>,
    app: &App,
    headers: &HeaderMap,
    peer: SocketAddr,
    request: Uuid,
) -> Result<Context> {
    crate::oauth_http::credential_context(
        tx,
        &app.auth,
        headers,
        peer,
        request,
        app.config.text("server", "public_origin"),
    )
    .await
}

/// Existing getCall read semantics, including source checks on delivered Skill
/// and HTTP results. Query authorization below is stricter than metadata reads.
async fn read(tx: &Transaction<'_>, app: &App, ctx: &Context, call: Uuid) -> Result<Value> {
    let row = tx.query_opt(
        "SELECT owner_id,credential_id,state,result,error,skill_id,http_binding FROM calls WHERE id=$1",
        &[&call],
    ).await?.ok_or_else(Error::not_found)?;
    auth::authorize(
        tx,
        ctx,
        "capability.call.read",
        &Resource::new("call", call, Some(row.get("owner_id"))),
    )
    .await
    .map_err(|error| {
        if error.code == "PERMISSION_DENIED" {
            Error::not_found()
        } else {
            error
        }
    })?;
    let effectful: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM calls c JOIN capability_contracts p ON p.name=c.contract->>'name' AND p.version=c.contract->>'version' AND p.schema_digest=c.contract->>'schema_digest' WHERE c.id=$1 AND c.state IN ('succeeded','failed') AND p.spec->>'side_effect' IN ('idempotent','queryable','non_repeatable'))", &[&call]).await?.get(0);
    if effectful {
        let origin: Option<String> = tx
            .query_opt(
                "SELECT browser_origin FROM host_rpc_contexts WHERE call_id=$1",
                &[&call],
            )
            .await?
            .ok_or_else(Error::denied)?
            .get(0);
        if row.get::<_, Uuid>("owner_id") != ctx.subject
            || row.get::<_, Option<Uuid>>("credential_id") != Some(ctx.credential)
            || origin != ctx.browser_origin
        {
            return Err(Error::denied());
        }
    }
    if effectful
        || (row.get::<_, Option<Value>>("result").is_some()
            && (row.get::<_, Option<Uuid>>("skill_id").is_some()
                || row.get::<_, Option<Value>>("http_binding").is_some()))
    {
        crate::broker::check_skill_authority(tx, ctx, call)
            .await
            .map_err(delivery_error)?;
        if row.get::<_, Option<Value>>("http_binding").is_some() {
            crate::broker::check_http_approval(tx, app, call)
                .await
                .map_err(delivery_error)?;
        }
    }
    Ok(
        json!({"call_id":call,"state":row.get::<_,String>("state"),"result":row.get::<_,Option<Value>>("result"),"error":row.get::<_,Option<Value>>("error")}),
    )
}

fn delivery_error(error: Error) -> Error {
    if matches!(
        error.code,
        "PERMISSION_DENIED" | "INVALID_CREDENTIAL" | "RESOURCE_NOT_FOUND" | "STATE_CONFLICT"
    ) {
        Error::denied()
    } else {
        error
    }
}

async fn reject(tx: Transaction<'_>, ctx: &Context, call: Uuid, error: Error) -> Result<Value> {
    db::audit(
        &tx,
        ctx.subject,
        Some(ctx.credential),
        ctx.request,
        "getCall",
        &Resource::new("call", call, None).json(),
        "denied",
        error.code,
    )
    .await?;
    tx.commit().await?;
    Err(error)
}

/// A query is admitted only with the original credential, source proof, exact
/// signed capability, physical instance generation and still-live data binding.
async fn resolve_binding(
    tx: &Transaction<'_>,
    ctx: &Context,
    call: Uuid,
) -> Result<Option<Binding>> {
    let row = tx.query_opt(
        "SELECT c.owner_id,c.credential_id,c.contract,c.idempotency_key,c.deadline_at,c.skill_id,c.skill_definition_digest,c.provider_instance_id,c.state,c.http_binding,i.generation,i.phase,d.installation_id,d.spec,d.archived_at,n.manifest,n.state AS installation_state,p.status AS publisher_status,r.generation AS original_generation,x.source_paths,x.browser_origin,
                EXISTS(SELECT 1 FROM attempts a WHERE a.broker_call_id=c.id AND a.dispatch_started IS FALSE) AS unsent
         FROM calls c LEFT JOIN instances i ON i.id=c.provider_instance_id LEFT JOIN deployments d ON d.id=i.deployment_id LEFT JOIN installations n ON n.id=d.installation_id LEFT JOIN publishers p ON p.id=n.publisher_id LEFT JOIN rpc_delegations r ON r.execution_delegation_id=c.delegation_id AND r.call_id=c.id AND r.instance_id=c.provider_instance_id AND r.subject_id=c.owner_id AND r.issuer_credential_id=c.credential_id LEFT JOIN host_rpc_contexts x ON x.call_id=c.id WHERE c.id=$1",
        &[&call],
    ).await?.ok_or_else(Error::not_found)?;
    if row.get::<_, String>("state") != "unknown"
        || row.get::<_, Option<Value>>("http_binding").is_some()
        || row.get::<_, bool>("unsent")
    {
        return Ok(None);
    }
    let contract: Value = row.get("contract");
    let Some(registered) = tx.query_opt(
        "SELECT spec FROM capability_contracts WHERE name=$1 AND version=$2 AND schema_digest=$3",
        &[&contract["name"].as_str().unwrap_or(""),&contract["version"].as_str().unwrap_or(""),&contract["schema_digest"].as_str().unwrap_or("")],
    ).await? else { return Ok(None) };
    let capability: Value = registered.get("spec");
    if capability["side_effect"] != "queryable" {
        return Ok(None);
    }
    if row.get::<_, Uuid>("owner_id") != ctx.subject
        || row.get::<_, Option<Uuid>>("credential_id") != Some(ctx.credential)
        || row.get::<_, Option<Value>>("source_paths").is_none()
        || row.get::<_, Option<String>>("browser_origin") != ctx.browser_origin
    {
        return Err(Error::denied());
    }
    crate::broker::check_skill_authority(tx, ctx, call).await?;
    let resource = Resource::new(
        "capability",
        format!(
            "{}@{}",
            contract["name"].as_str().unwrap_or(""),
            contract["version"].as_str().unwrap_or("")
        ),
        None,
    );
    auth::authorize(tx, ctx, "capability.invoke", &resource).await?;
    let deadline: DateTime<Utc> = row.get("deadline_at");
    let Some(generation) = row.get::<_, Option<i64>>("original_generation") else {
        return Ok(None);
    };
    if deadline <= Utc::now()
        || row.get::<_, Option<i64>>("generation") != Some(generation)
        || row.get::<_, Option<String>>("phase").as_deref() != Some("ready")
        || row.get::<_, Option<DateTime<Utc>>>("archived_at").is_some()
        || row
            .get::<_, Option<Value>>("spec")
            .is_none_or(|spec| spec["enabled"] != true)
        || row
            .get::<_, Option<String>>("installation_state")
            .as_deref()
            != Some("installed")
        || row.get::<_, Option<String>>("publisher_status").as_deref() != Some("trusted")
    {
        return Ok(None);
    }
    let manifest: Value = row
        .get::<_, Option<Value>>("manifest")
        .ok_or_else(Error::denied)?;
    if !manifest["capabilities"].as_array().is_some_and(|caps| {
        caps.iter()
            .any(|cap| cap == &capability && cap["contract"] == contract)
    }) {
        return Err(Error::denied());
    }
    let skill = if let Some(skill) = row.get::<_, Option<Uuid>>("skill_id") {
        let resolved = crate::skills::resolve_for_invoke(tx, ctx, skill).await?;
        let expected: String = row
            .get::<_, Option<String>>("skill_definition_digest")
            .ok_or_else(Error::denied)?;
        if resolved.definition_digest != expected
            || Some(resolved.installation_id) != row.get::<_, Option<Uuid>>("installation_id")
            || resolved.definition["target"]["contract"] != contract
        {
            return Err(Error::denied());
        }
        Some((skill, expected, resolved.definition))
    } else {
        None
    };
    let key = row
        .get::<_, Option<String>>("idempotency_key")
        .filter(|key| !key.is_empty())
        .ok_or_else(Error::denied)?;
    Ok(Some(Binding {
        call,
        subject: ctx.subject,
        credential: ctx.credential,
        instance: row
            .get::<_, Option<Uuid>>("provider_instance_id")
            .ok_or_else(Error::denied)?,
        generation,
        deadline,
        key,
        contract,
        capability,
        skill,
    }))
}

#[cfg(test)]
fn decode(binding: &Binding, response: rpc::QueryResultResponse) -> Result<Option<Outcome>> {
    decode_bounded(binding, response, usize::MAX)
}
fn decode_bounded(
    binding: &Binding,
    response: rpc::QueryResultResponse,
    maximum: usize,
) -> Result<Option<Outcome>> {
    use rpc::{query_result_response::Outcome as Wire, ExecutionState};
    match (ExecutionState::try_from(response.state), response.outcome) {
        (Ok(ExecutionState::Succeeded), Some(Wire::Completed(response))) => {
            if response.call_id != binding.call.to_string()
                || digest(&response.output_json) != response.output_digest
            {
                return Err(Error::conflict(
                    "QueryResult Call identity or digest differs",
                ));
            }
            let output = strict_json(
                &response.output_json,
                (unsigned(&binding.capability["maximum_output_bytes"])? as usize).min(maximum),
            )?;
            validate_business(&binding.capability["output_schema"], &output)?;
            if let Some((_, _, skill)) = &binding.skill {
                validate_business(&skill["output_schema"], &output)?;
            }
            let mut value = json!({"call_id":binding.call,"contract":binding.contract,"provider_instance_id":binding.instance,"output":output,"completed_at":Utc::now()});
            if let Some((skill, digest, _)) = &binding.skill {
                value["skill_id"] = json!(skill);
                value["skill_definition_digest"] = json!(digest);
            }
            validate("CallResult", &value)?;
            Ok(Some(Outcome::Completed(value)))
        }
        (Ok(ExecutionState::Failed), Some(Wire::Failed(error))) => {
            let violations: Vec<Value> = error
                .violations
                .into_iter()
                .map(|violation| json!({"path":violation.path,"reason":violation.reason}))
                .collect();
            let value = json!({"code":error.code,"message":error.message,"retryable":false,"violations":violations,"retry_after_ms":null,"resource_id":binding.call});
            validate("ErrorDetail", &value)?;
            Ok(Some(Outcome::Failed(value)))
        }
        (
            Ok(
                ExecutionState::Accepted
                | ExecutionState::Running
                | ExecutionState::Unknown
                | ExecutionState::Canceled,
            ),
            None,
        ) => Ok(None),
        _ => Err(Error::conflict("QueryResult state and outcome differ")),
    }
}

/// `getCall` is the only trigger: no background polling, Invoke retry, provider
/// fallback, new daily call charge, or authority inherited by the query plugin.
pub(crate) async fn get_call(
    app: &App,
    headers: &HeaderMap,
    peer: SocketAddr,
    request: Uuid,
    call: Uuid,
) -> Result<Value> {
    static QUERIES: OnceLock<Semaphore> = OnceLock::new();
    let _permit = QUERIES
        .get_or_init(|| Semaphore::new(32))
        .try_acquire()
        .map_err(|_| Error::exhausted())?;
    let started = tokio::time::Instant::now();
    let mut connection = app.db.connect_scoped(QUERY_LIMIT).await?;
    let tx = connection.transaction().await?;
    db::call_lock(&tx).await?;
    let ctx = context(&tx, app, headers, peer, request).await?;
    let previous = match read(&tx, app, &ctx, call).await {
        Ok(value) => value,
        Err(error) => return reject(tx, &ctx, call, error).await,
    };
    let candidate = match resolve_binding(&tx, &ctx, call).await {
        Ok(value) => value,
        Err(error) => return reject(tx, &ctx, call, error).await,
    };
    let Some(binding) = candidate else {
        tx.commit().await?;
        return Ok(previous);
    };
    if crate::skill_streams::ensure_active(app).is_err() {
        tx.commit().await?;
        return Ok(previous);
    }
    let until = binding
        .deadline
        .min(Utc::now() + chrono::Duration::seconds(2));
    let deadline = (started + QUERY_LIMIT)
        .min(tokio::time::Instant::now() + (until - Utc::now()).to_std().unwrap_or(Duration::ZERO));
    if deadline <= tokio::time::Instant::now() {
        tx.commit().await?;
        return Ok(previous);
    }
    // Empty query-only lease. It cannot replace the original execution binding
    // or authorize HostService, whose authority also requires a running Call.
    let execution = Uuid::new_v4();
    let rpc_id = Uuid::new_v4();
    let (token, hash) = app.auth.random_token();
    tx.execute("INSERT INTO execution_delegations(id,subject_id,issuer_credential_id,maximum_rules,run_as,expires_at,status,created_at) VALUES($1,$2,$3,'[]','user',$4,'active',now())", &[&execution,&ctx.subject,&ctx.credential,&until]).await?;
    tx.execute("INSERT INTO rpc_delegations(id,execution_delegation_id,subject_id,instance_id,generation,call_id,issuer_credential_id,hmac_key_id,verification_digest,expires_at,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active',now())", &[&rpc_id,&execution,&ctx.subject,&binding.instance,&binding.generation,&call,&ctx.credential,&app.auth.key_id.as_str(),&hash,&until]).await?;
    tx.commit().await?;
    drop(connection);
    let result = tokio::time::timeout_at(deadline, async {
        let address = app.runtime.address(binding.instance)?;
        let channel = crate::tls::channel_with_timeout(
            &app.config,
            binding.instance,
            binding.generation,
            &address,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
        let mut client = CapabilityServiceClient::new(channel)
            .max_decoding_message_size(app.config.rpc_limit(16_778_240));
        let mut rpc_context = crate::controller::context(Some(binding.subject));
        rpc_context.request_id = request.to_string();
        rpc_context.delegation_token = token;
        rpc_context.deadline_unix_ms = until.timestamp_millis();
        rpc_context.idempotency_key = binding.key.clone();
        let mut request = tonic::Request::new(rpc::QueryResultRequest {
            context: Some(rpc_context),
            call_id: call.to_string(),
            idempotency_key: binding.key.clone(),
        });
        request.set_timeout(deadline.saturating_duration_since(tokio::time::Instant::now()));
        decode_bounded(
            &binding,
            client.query_result(request).await?.into_inner(),
            app.config.json_limit(16_777_216),
        )
    })
    .await;
    let mut connection = app.db.connect_scoped(QUERY_LIMIT).await?;
    let tx = connection.transaction().await?;
    db::call_lock(&tx).await?;
    tx.execute(
        "UPDATE rpc_delegations SET status='revoked' WHERE id=$1",
        &[&rpc_id],
    )
    .await?;
    tx.execute(
        "UPDATE execution_delegations SET status='revoked' WHERE id=$1",
        &[&execution],
    )
    .await?;
    let ctx = match context(&tx, app, headers, peer, request).await {
        Ok(ctx) => ctx,
        Err(error) => {
            // Revocation may win while RPC is in flight. Persist only cleanup,
            // even though the revoked caller cannot authorize result delivery.
            tx.commit().await?;
            return Err(error);
        }
    };
    let current = match read(&tx, app, &ctx, call).await {
        Ok(value) => value,
        Err(error) => return reject(tx, &ctx, call, error).await,
    };
    let candidate = match resolve_binding(&tx, &ctx, call).await {
        Ok(value) => value,
        Err(error) => return reject(tx, &ctx, call, error).await,
    };
    if let Some(current_binding) = candidate {
        if current_binding.instance != binding.instance
            || current_binding.generation != binding.generation
            || current_binding.credential != binding.credential
            || current_binding.contract != binding.contract
            || current_binding.key != binding.key
            || current_binding.capability != binding.capability
            || current_binding.skill != binding.skill
        {
            return reject(tx, &ctx, call, Error::denied()).await;
        }
        if let Ok(Ok(Some(outcome))) = result {
            crate::skill_streams::ensure_active(app)?;
            let (state, value, error) = match outcome {
                Outcome::Completed(value) => ("succeeded", Some(value), None),
                Outcome::Failed(error) => ("failed", None, Some(error)),
            };
            let changed = tx.execute("UPDATE calls SET state=$2,result=$3,error=$4,completed_at=now() WHERE id=$1 AND state='unknown'", &[&call,&state,&value,&error]).await?;
            if changed == 1 {
                let released = tx.execute("UPDATE reservations SET status='released' WHERE id=$1 AND kind='call' AND status<>'released'", &[&call]).await?;
                if released == 1 {
                    for row in tx.query("SELECT ancestor_id FROM account_closure WHERE descendant_id=$1 ORDER BY depth DESC", &[&binding.subject]).await? {
                        tx.execute("UPDATE quotas SET concurrent_calls_used=greatest(0,concurrent_calls_used-1) WHERE account_id=$1", &[&row.get::<_,Uuid>(0)]).await?;
                    }
                }
                db::audit(
                    &tx,
                    ctx.subject,
                    Some(ctx.credential),
                    request,
                    "capability.call.read",
                    &Resource::new("call", call, Some(ctx.subject)).json(),
                    "succeeded",
                    "CALL_RESULT_QUERIED",
                )
                .await?;
            }
        }
    }
    let value = if current["state"] == "unknown" {
        read(&tx, app, &ctx, call).await?
    } else {
        current
    };
    tx.commit().await?;
    Ok(value)
}

#[cfg(test)]
#[path = "broker_query_tests.rs"]
mod tests;
