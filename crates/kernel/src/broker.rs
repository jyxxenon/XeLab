use crate::{
    api::App,
    auth::{account_chain, authorize, Resource},
    contracts::{digest, id, strict_json, string, unsigned, validate, validate_business},
    controller, db,
    error::{Error, Result},
    rpc::{self, capability_service_client::CapabilityServiceClient},
    task_engine::{self, Lease},
    tls,
};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use std::{net::IpAddr, time::Duration};
use uuid::Uuid;
#[path = "broker_http.rs"]
mod http;
pub(crate) use http::check_route_approval as check_http_approval;
pub use http::invoke as invoke_http;
pub(crate) use http::target_resource as business_target;

#[derive(Clone, Copy)]
enum CallRequest<'a> {
    Token {
        token: &'a str,
        peer: IpAddr,
        browser_origin: Option<&'a str>,
        input: &'a Value,
        skill: Option<Uuid>,
    },
    Task(&'a Lease),
}

impl<'a> CallRequest<'a> {
    fn source(self) -> CallSource<'a> {
        match self {
            Self::Token {
                token,
                peer,
                browser_origin,
                ..
            } => CallSource::Token {
                token,
                peer,
                browser_origin,
            },
            Self::Task(lease) => CallSource::Task(lease),
        }
    }
}

#[derive(Clone, Copy)]
enum CallSource<'a> {
    Token {
        token: &'a str,
        peer: IpAddr,
        browser_origin: Option<&'a str>,
    },
    Task(&'a Lease),
}

impl<'a> CallSource<'a> {
    fn token(self) -> Option<&'a str> {
        match self {
            Self::Token { token, .. } => Some(token),
            Self::Task(_) => None,
        }
    }

    async fn authenticate(
        self,
        tx: &tokio_postgres::Transaction<'_>,
        app: &App,
        request: Uuid,
        call: Option<Uuid>,
    ) -> Result<crate::auth::Context> {
        match self {
            Self::Token {
                token,
                peer,
                browser_origin,
                ..
            } => {
                let mut ctx =
                    crate::host_calls::authenticate(tx, app, token, peer, request).await?;
                ctx.browser_origin = browser_origin.map(str::to_owned);
                Ok(ctx)
            }
            Self::Task(lease) => {
                task_engine::authorize_broker_call(
                    tx,
                    &app.auth,
                    lease,
                    call.ok_or_else(Error::denied)?,
                )
                .await
            }
        }
    }
}

pub(crate) async fn invoke_task(app: &App, lease: &Lease) -> Result<Value> {
    crate::skill_streams::ensure_active(app)?;
    let until = tokio::time::Instant::now() + Duration::from_secs(300);
    let key = lease.execution_id.to_string();
    tokio::time::timeout_at(
        until,
        invoke_inner(
            app,
            CallRequest::Task(lease),
            lease.execution_id,
            &key,
            None,
            chrono::Utc::now(),
            until,
        ),
    )
    .await
    .unwrap_or_else(|_| {
        Err(Error::new(
            "DEADLINE_EXCEEDED",
            "Task call deadline elapsed; inspect its attempt journal",
            axum::http::StatusCode::GATEWAY_TIMEOUT,
        ))
    })
}

pub async fn invoke(
    app: &App,
    token: &str,
    peer: IpAddr,
    request_id: Uuid,
    input: &Value,
    key: &str,
) -> Result<Value> {
    invoke_bounded(app, token, peer, request_id, input, key, None, None, None).await
}

/// Skill identity comes from the path, never from caller-supplied route context.
#[allow(clippy::too_many_arguments)]
pub async fn invoke_skill(
    app: &App,
    token: &str,
    peer: IpAddr,
    request_id: Uuid,
    skill: Uuid,
    input: &Value,
    key: &str,
) -> Result<Value> {
    invoke_bounded(
        app,
        token,
        peer,
        request_id,
        input,
        key,
        Some(skill),
        None,
        None,
    )
    .await
}

/// Browser Origin is captured only after trusted Host/header classification.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn invoke_from_http(
    app: &App,
    token: &str,
    peer: IpAddr,
    request_id: Uuid,
    input: &Value,
    key: &str,
    skill: Option<Uuid>,
    browser_origin: Option<&str>,
) -> Result<Value> {
    invoke_bounded(
        app,
        token,
        peer,
        request_id,
        input,
        key,
        skill,
        None,
        browser_origin,
    )
    .await
}

/// Streaming shares the exact ordinary-call admission, journal and finalizer.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn stream_skill(
    app: &App,
    token: &str,
    peer: IpAddr,
    request_id: Uuid,
    skill: Uuid,
    input: &Value,
    key: &str,
    output: &crate::skill_streams::Output,
    browser_origin: Option<&str>,
) -> Result<Value> {
    invoke_bounded(
        app,
        token,
        peer,
        request_id,
        input,
        key,
        Some(skill),
        Some(output),
        browser_origin,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn invoke_bounded<'a>(
    app: &'a App,
    token: &'a str,
    peer: IpAddr,
    request_id: Uuid,
    input: &'a Value,
    key: &'a str,
    skill: Option<Uuid>,
    stream: Option<&'a crate::skill_streams::Output>,
    browser_origin: Option<&'a str>,
) -> BoxFuture<'a, Result<Value>> {
    Box::pin(async move {
        let started = tokio::time::Instant::now();
        let wall_started = chrono::Utc::now();
        let timeout = input
            .get("timeout_ms")
            .map(unsigned)
            .transpose()?
            .unwrap_or(if skill.is_some() { 120000 } else { 30000 })
            .min(300000);
        let expired = || {
            Error::new(
                "DEADLINE_EXCEEDED",
                "Call deadline elapsed; inspect any admitted call before retrying",
                axum::http::StatusCode::GATEWAY_TIMEOUT,
            )
        };
        let invocation = async {
            let mut effective = timeout;
            let mut http_target = false;
            if let Some(skill) = skill {
                // This read can only narrow the time budget. It conveys no authority;
                // full signed binding and current authorization are checked inside
                // admission. Read before waiting for the shared business call lock.
                let c = app
                    .db
                    .connect_scoped(
                        (started + Duration::from_millis(timeout))
                            .saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await?;
                if let Some(row) = c
                .query_opt(
                    "SELECT definition->'maximum_timeout_ms' AS maximum,definition->'target'->>'kind' AS target_kind FROM skills WHERE id=$1",
                    &[&skill],
                )
                .await?
            {
                http_target = row.get::<_,Option<String>>("target_kind").as_deref()==Some("http");
                let maximum: Option<Value> = row.get("maximum");
                if let Some(maximum) = maximum.and_then(|v| unsigned(&v).ok()) {
                    effective = effective.min(maximum);
                }
            }
            }
            if http_target {
                return tokio::time::timeout_at(
                    started + Duration::from_millis(effective),
                    http::execute_skill(
                        app,
                        token,
                        peer,
                        request_id,
                        skill.ok_or_else(Error::denied)?,
                        input,
                        key,
                        started,
                        started + Duration::from_millis(effective),
                        stream,
                        browser_origin,
                    ),
                )
                .await
                .unwrap_or_else(|_| Err(expired()));
            }
            tokio::time::timeout_at(
                started + Duration::from_millis(effective),
                invoke_inner(
                    app,
                    CallRequest::Token {
                        token,
                        peer,
                        browser_origin,
                        input,
                        skill,
                    },
                    request_id,
                    key,
                    stream,
                    wall_started,
                    started + Duration::from_millis(effective),
                ),
            )
            .await
            .unwrap_or_else(|_| Err(expired()))
        };
        // Also bound metadata lookup itself by the caller/default outer budget.
        // Dropping admission rolls back; admitted work retains its durable slot.
        let bounded = tokio::time::timeout_at(started + Duration::from_millis(timeout), invocation);
        let result = if let Some(stream) = stream {
            tokio::select! {
                biased;
                _ = stream.abandoned_before_admission() => {
                    return Err(Error::new("CANCELED", "Skill stream consumer disconnected before admission", axum::http::StatusCode::CONFLICT));
                }
                result = bounded => result,
            }
        } else {
            bounded.await
        };
        result.unwrap_or_else(|_| Err(expired()))
    })
}

fn invoke_inner<'a>(
    app: &'a App,
    request: CallRequest<'a>,
    request_id: Uuid,
    key: &'a str,
    stream: Option<&'a crate::skill_streams::Output>,
    started: chrono::DateTime<chrono::Utc>,
    deadline_bound: tokio::time::Instant,
) -> BoxFuture<'a, Result<Value>> {
    Box::pin(async move {
        if let CallRequest::Token { input, skill, .. } = request {
            validate(
                if skill.is_some() {
                    "SkillInvokeRequest"
                } else {
                    "InvokeRequest"
                },
                input,
            )?;
        }
        let origin = request.source();
        let mut c = app
            .db
            .connect_scoped(deadline_bound.saturating_duration_since(tokio::time::Instant::now()))
            .await?;
        let tx = c.transaction().await?;
        db::call_lock(&tx).await?;
        let task_input;
        let (ctx, input, skill_id, task_deadline) = match request {
            CallRequest::Token { input, skill, .. } => (
                origin.authenticate(&tx, app, request_id, None).await?,
                input,
                skill,
                None,
            ),
            CallRequest::Task(lease) => {
                let (invocation, ctx) = task_engine::begin_broker(&tx, &app.auth, lease).await?;
                let deadline = invocation
                    .deadline
                    .min(started + chrono::Duration::seconds(300));
                let now = chrono::Utc::now();
                if deadline <= now {
                    return Err(Error::new(
                        "DEADLINE_EXCEEDED",
                        "Task deadline elapsed before Broker admission",
                        axum::http::StatusCode::GATEWAY_TIMEOUT,
                    ));
                }
                // The public request schema has a minimum timeout. The actual
                // Task deadline still governs reservation and dispatch below.
                task_input = json!({"input":invocation.input,"provider_deployment_id":invocation.deployment_id,
                    "timeout_ms":(deadline - now).num_milliseconds().max(100),"idempotency_key":invocation.idempotency_key});
                validate("SkillInvokeRequest", &task_input)?;
                (ctx, &task_input, Some(invocation.skill_id), Some(deadline))
            }
        };
        // The replay scope and the plugin's stable business key are distinct.
        let business_key = input["idempotency_key"].as_str().unwrap_or(key);
        let skill = if let Some(id) = skill_id {
            match crate::skills::resolve_for_invoke(&tx, &ctx, id).await {
                Ok(skill) => Some(skill),
                Err(error) => {
                    if matches!(origin, CallSource::Task(_)) {
                        return Err(error);
                    }
                    db::audit(
                        &tx,
                        ctx.subject,
                        Some(ctx.credential),
                        request_id,
                        "skill.invoke",
                        &Resource::new("skill", id, None).json(),
                        "denied",
                        error.code,
                    )
                    .await?;
                    tx.commit().await?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let mut adapted;
        let original = input;
        let input = if let Some(skill) = &skill {
            let maximum = unsigned(&skill.definition["maximum_timeout_ms"])?;
            let timeout = input
                .get("timeout_ms")
                .map(unsigned)
                .transpose()?
                .unwrap_or(120000.min(maximum));
            if timeout > maximum {
                return Err(Error::invalid(
                    "Requested deadline exceeds the fixed Skill maximum",
                ));
            }
            validate_business(&skill.definition["input_schema"], &input["input"])?;
            adapted = json!({"contract":skill.definition["target"]["contract"],"input":input["input"],"timeout_ms":timeout});
            if let Some(deployment) = input.get("provider_deployment_id") {
                adapted["provider_deployment_id"] = deployment.clone();
            }
            &adapted
        } else {
            input
        };
        let contract = &input["contract"];
        let name = string(contract, "name")?;
        let version = string(contract, "version")?;
        let schema_digest = string(contract, "schema_digest")?;
        let authorization = authorize(
            &tx,
            &ctx,
            "capability.invoke",
            &Resource::new("capability", format!("{name}@{version}"), None),
        )
        .await;
        if let Err(e) = authorization {
            if matches!(origin, CallSource::Task(_)) {
                return Err(e);
            }
            db::audit(
                &tx,
                ctx.subject,
                Some(ctx.credential),
                request_id,
                "capability.invoke",
                &Resource::new("capability", format!("{name}@{version}"), None).json(),
                "denied",
                e.code,
            )
            .await?;
            tx.commit().await?;
            return Err(e);
        }
        let cap = tx
            .query_opt(
                "SELECT spec,schema_digest FROM capability_contracts WHERE name=$1 AND version=$2",
                &[&name, &version],
            )
            .await?
            .ok_or_else(Error::not_found)?;
        if cap.get::<_, String>("schema_digest") != schema_digest {
            return Err(Error::conflict("Capability digest differs"));
        }
        let definition: Value = cap.get("spec");
        if !matches!(
            definition["side_effect"].as_str(),
            Some("none" | "idempotent" | "queryable" | "non_repeatable")
        ) {
            return Err(Error::invalid(
                "Unsupported capability side-effect semantics",
            ));
        }
        if stream.is_some() && definition["stream_item_schema"].is_null() {
            return Err(Error::invalid(
                "Capability does not declare a streaming item schema",
            ));
        }
        let mut protected = skill.is_some()
            || definition["side_effect"] != "none"
            || origin
                .token()
                .is_some_and(|token| token.starts_with("host:"));
        let fingerprint = digest(&serde_json::to_vec(original)?);
        let path = if let CallSource::Task(lease) = origin {
            format!("/internal/task-attempts/{}/skill", lease.attempt_id)
        } else {
            skill_id.map_or_else(
                || "/api/platform/v1/calls".to_owned(),
                |id| {
                    format!(
                        "/api/platform/v1/skills/{id}/calls{}",
                        if stream.is_some() { ":stream" } else { "" }
                    )
                },
            )
        };
        let lock = format!("call:{}:{}:{path}:{key}", ctx.subject, ctx.credential);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&lock],
        )
        .await?;
        if let Some(r)=tx.query_opt("SELECT * FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method='POST' AND path=$4 AND key=$3 AND expires_at>now() FOR UPDATE",&[&ctx.subject,&ctx.credential,&key,&path]).await?{
        if matches!(origin, CallSource::Task(_)) { return Err(Error::conflict("Task attempt already has a Broker record")); }
        if r.get::<_,String>("fingerprint")!=fingerprint{return Err(Error::new("IDEMPOTENCY_CONFLICT","The key was already used for different input",axum::http::StatusCode::CONFLICT));}
        let call_id=r.get::<_,Option<String>>("resource_id").and_then(|s|s.parse::<Uuid>().ok()).ok_or_else(||Error::conflict("Missing prior call"))?;
        if stream.is_some() { return Err(Error::conflict("Generation streams cannot be replayed; inspect the admitted Call").with_resource(call_id)); }
        let row=tx.query_one("SELECT state,result FROM calls WHERE id=$1",&[&call_id]).await?;
        if row.get::<_,String>("state")=="succeeded"{let deployment:Uuid=tx.query_one("SELECT i.deployment_id FROM calls c JOIN instances i ON i.id=c.provider_instance_id WHERE c.id=$1", &[&call_id]).await?.get(0);crate::dependencies::check_ready(&tx,app,deployment).await?;if protected || tx.query_one("SELECT EXISTS(SELECT 1 FROM host_rpc_contexts WHERE call_id=$1)",&[&call_id]).await?.get::<_,bool>(0){check_skill_authority(&tx,&ctx,call_id).await?;}let value = row.get::<_,Option<Value>>("result").ok_or_else(||Error::conflict("Call result is unavailable"))?; return skill_result(skill.as_ref(), value);}
        return Err(Error::new("OUTCOME_UNKNOWN","Prior call is not a confirmed success; query its call ID",axum::http::StatusCode::CONFLICT).with_resource(call_id));
    }
        let bytes = serde_json::to_vec(&input["input"])?;
        if bytes.len()
            > app
                .config
                .json_limit(unsigned(&definition["maximum_input_bytes"])? as usize)
        {
            return Err(Error::invalid("Capability input exceeds its byte limit"));
        }
        validate_business(&definition["input_schema"], &input["input"])?;
        let fixed = input
            .get("provider_deployment_id")
            .map(|_| id(input, "provider_deployment_id"))
            .transpose()?;
        let installation = skill.as_ref().map(|s| s.installation_id);
        let task = matches!(origin, CallSource::Task(_));
        let providers = tx.query(
            "SELECT i.id,i.generation,d.id AS deployment_id,d.owner_id,n.manifest
             FROM provider_records p JOIN instances i ON i.id=p.instance_id
             JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id
             WHERE p.name=$1 AND p.version=$2 AND p.availability='ready'
               AND p.observed_at>now()-interval '1 millisecond'*
                   ((n.manifest->'health'->>'interval_ms')::bigint*
                    (n.manifest->'health'->>'failure_threshold')::bigint+
                    (n.manifest->'health'->>'timeout_ms')::bigint)
               AND i.phase='ready' AND d.spec->>'enabled'='true' AND d.archived_at IS NULL
               AND ($3::uuid IS NULL OR d.id=$3) AND ($4::uuid IS NULL OR n.id=$4)
               AND (NOT $5::boolean OR p.observed_generation=i.generation)
             ORDER BY i.id FOR UPDATE OF i",
            &[&name, &version, &fixed, &installation, &task],
        ).await?;
        let row = providers
            .first()
            .ok_or_else(|| Error::unavailable("No healthy fixed provider is available"))?;
        crate::dependencies::check_ready(&tx, app, row.get("deployment_id")).await?;
        let instance: Uuid = row.get("id");
        let generation: i64 = row.get("generation");
        let manifest: Value = row.get("manifest");
        if matches!(origin, CallSource::Task(_))
            && manifest["requested_rules"].as_array().is_some_and(|rules| {
                rules.iter().any(|rule| {
                    rule["required"] == true
                        && crate::host_blobs::proxy_action(
                            rule["rule"]["action"].as_str().unwrap_or(""),
                            rule["rule"]["resource"]["kind"].as_str().unwrap_or(""),
                        )
                })
            })
        {
            return Err(Error::invalid(
                "Task Skill requires HostService authority beyond its frozen targets",
            ));
        }
        protected |= manifest["dependencies"]
            .as_array()
            .is_some_and(|d| !d.is_empty());
        if definition["side_effect"] != "none" {
            crate::artifact::validate_runtime_profile(&manifest)?;
            if !manifest["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cap| {
                    cap["contract"] == *contract
                        && cap["side_effect"] == definition["side_effect"]
                        && [
                            "input_schema",
                            "output_schema",
                            "stream_item_schema",
                            "maximum_input_bytes",
                            "maximum_output_bytes",
                        ]
                        .iter()
                        .all(|field| cap[*field] == definition[*field])
                })
            {
                return Err(Error::invalid(
                    "Side-effecting execution requires its exact signed capability",
                ));
            }
        }
        if manifest["business_entry"] == "skill_required" && skill.is_none() {
            return Err(Error::denied());
        }
        protected |= manifest["requested_rules"].as_array().is_some_and(|rs| {
            rs.iter().any(|r| {
                crate::host_blobs::proxy_action(
                    r["rule"]["action"].as_str().unwrap_or(""),
                    r["rule"]["resource"]["kind"].as_str().unwrap_or(""),
                )
            })
        });
        let (accounts, charged) = reserve_business(
            &tx,
            &ctx,
            instance,
            &manifest,
            "capability.invoke",
            &Resource::new("capability", format!("{name}@{version}"), None),
            skill.as_ref(),
            None,
        )
        .await?;
        let call = if let Some(token) = origin.token() {
            crate::host_calls::new_call(&tx, app, token).await?
        } else {
            Uuid::new_v4()
        };
        let timeout = input
            .get("timeout_ms")
            .map(unsigned)
            .transpose()?
            .unwrap_or(30000);
        let deadline = if let Some(token) = origin.token() {
            crate::host_calls::bound_deadline(
                &tx,
                app,
                token,
                started + chrono::Duration::milliseconds(timeout as i64),
            )
            .await?
        } else {
            task_deadline.ok_or_else(Error::denied)?
        };
        if deadline <= chrono::Utc::now() {
            return Err(Error::new(
                "DEADLINE_EXCEEDED",
                "Call admission exceeded its deadline",
                axum::http::StatusCode::GATEWAY_TIMEOUT,
            ));
        }
        tx.execute("INSERT INTO calls(id,owner_id,credential_id,provider_instance_id,contract,input_digest,idempotency_key,state,deadline_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8,now())",&[&call,&ctx.subject,&ctx.credential,&instance,&contract,&digest(&bytes),&business_key,&deadline]).await?;
        if let Some(skill) = &skill {
            tx.execute(
                "UPDATE calls SET skill_id=$2,skill_definition_digest=$3 WHERE id=$1",
                &[&call, &skill.id, &skill.definition_digest],
            )
            .await?;
        }
        for credential in charged {
            tx.execute(
                "INSERT INTO call_credential_charges(call_id,credential_id) VALUES($1,$2)",
                &[&call, &credential],
            )
            .await?;
        }
        tx.execute("INSERT INTO reservations(id,account_id,kind,expires_at,status,created_at) VALUES($1,$2,'call',$3,'active',now())", &[&call,&ctx.subject,&deadline]).await?;
        if let Some(token) = origin.token() {
            crate::host_calls::bind_child(&tx, app, token, call, instance).await?;
        }
        let delegation = app
            .auth
            .issue_rpc(&tx, &ctx, call, instance, generation, deadline)
            .await?;
        crate::host_blobs::grant_skill_call(
            &tx,
            app,
            &ctx,
            call,
            row.get("deployment_id"),
            &manifest,
            &definition,
            &input["input"],
            skill
                .as_ref()
                .is_none_or(|s| s.definition["input_blobs"] == true),
        )
        .await?;
        if protected {
            crate::host_blobs::check_call_sources(&tx, &ctx, call).await?;
        }
        if let CallSource::Task(lease) = origin {
            task_engine::record_broker_call(&tx, lease, call).await?;
            crate::skill_streams::ensure_active(app)?;
        }
        tx.execute("DELETE FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method='POST' AND path=$4 AND key=$3 AND expires_at<=now()",&[&ctx.subject,&ctx.credential,&key,&path]).await?;
        tx.execute("INSERT INTO idempotency_records(subject_id,credential_id,method,path,key,fingerprint,resource_id,expires_at,created_at) VALUES($1,$2,'POST',$6,$3,$4,$5,now()+interval '24 hours',now())",&[&ctx.subject,&ctx.credential,&key,&fingerprint,&call.to_string(),&path]).await?;
        if let Some(stream) = stream {
            stream.ensure_open()?;
        }
        tx.commit().await?;
        drop(c);
        let remaining = || {
            Duration::from_millis((deadline - chrono::Utc::now()).num_milliseconds().max(0) as u64)
        };
        let result = async {
            if let Some(stream) = stream {
                if let Some(skill) = skill.as_ref() {
                    stream.bind(skill, call, deadline)?;
                } else {
                    let synthetic = crate::skills::ResolvedSkill {
                        id: Uuid::nil(),
                        installation_id: Uuid::nil(),
                        definition: json!({"version":version}),
                        definition_digest: schema_digest.into(),
                        owner: ctx.subject,
                    };
                    stream.bind(&synthetic, call, deadline)?;
                }
                stream.emit("accepted", json!({})).await?;
            }
            let address = app.runtime.address(instance)?;
            let channel = tls::channel(&app.config, instance, generation, &address).await?;
            let mut client = CapabilityServiceClient::new(channel).max_decoding_message_size(
                app.config
                    .rpc_limit(stream.map(|s| s.maximum_rpc_response()).unwrap_or(16778240)),
            );
            let mut context = controller::context(Some(ctx.subject));
            context.request_id = ctx.request.to_string();
            context.delegation_token = delegation;
            context.deadline_unix_ms = deadline.timestamp_millis();
            context.idempotency_key = business_key.to_owned();
            let mut request = tonic::Request::new(rpc::InvokeRequest {
                context: Some(context),
                call_id: call.to_string(),
                contract: Some(rpc::ContractRef {
                    name: name.to_owned(),
                    version: version.to_owned(),
                    schema_digest: schema_digest.to_owned(),
                }),
                input_digest: digest(&bytes),
                input_json: bytes,
                binding_id: String::new(),
            });
            if protected {
                check_live_call_for_source(
                    app, origin, request_id, call, instance, generation, deadline,
                )
                .await?;
            }
            if let Some(stream) = stream {
                stream.ensure_open()?;
            }
            request.set_timeout(remaining());
            let response = if let Some(output) = stream {
                let mut response_stream = client.invoke_stream(request).await?.into_inner();
                let mut sequence = 0_u64;
                let mut completed = None;
                while let Some(chunk) = response_stream.message().await? {
                    if chunk.call_id != call.to_string()
                        || chunk.sequence != sequence + 1
                        || completed.is_some()
                    {
                        return Err(Error::conflict(
                            "Plugin stream identity, sequence or terminal state differs",
                        ));
                    }
                    sequence = chunk.sequence;
                    match chunk.body {
                        Some(rpc::invoke_chunk::Body::ItemJson(bytes)) => {
                            let item = strict_json(&bytes, app.config.json_limit(1024 * 1024))?;
                            validate_business(&definition["stream_item_schema"], &item)?;
                            if let Some(skill) = skill.as_ref() {
                                validate_business(&skill.definition["stream_item_schema"], &item)?;
                            }
                            check_live_call_for_source(
                                app, origin, request_id, call, instance, generation, deadline,
                            )
                            .await?;
                            output.emit("item", item).await?;
                        }
                        Some(rpc::invoke_chunk::Body::Completed(response)) => {
                            completed = Some(response)
                        }
                        Some(rpc::invoke_chunk::Body::Failed(_)) => {
                            return Err(Error::unavailable(
                                "Plugin stream failed; inspect the Call",
                            ))
                        }
                        Some(rpc::invoke_chunk::Body::Canceled(_)) => {
                            return Err(Error::new(
                                "CANCELED",
                                "Plugin stream was canceled",
                                axum::http::StatusCode::CONFLICT,
                            ))
                        }
                        None => return Err(Error::conflict("Plugin stream chunk has no body")),
                    }
                }
                completed.ok_or_else(|| {
                    Error::conflict("Plugin stream ended without a terminal result")
                })?
            } else {
                client.invoke(request).await?.into_inner()
            };
            if response.call_id != call.to_string()
                || digest(&response.output_json) != response.output_digest
            {
                return Err(Error::conflict(
                    "Plugin returned a different call or output digest",
                ));
            }
            let output = strict_json(
                &response.output_json,
                app.config
                    .json_limit(unsigned(&definition["maximum_output_bytes"])? as usize),
            )?;
            validate_business(&definition["output_schema"], &output)?;
            if let Some(skill) = &skill {
                validate_business(&skill.definition["output_schema"], &output)?;
            }
            let mut out = json!({"call_id":call,"contract":contract,"provider_instance_id":instance,"output":output,"completed_at":chrono::Utc::now()});
            if let Some(skill) = &skill {
                out["skill_id"] = json!(skill.id);
                out["skill_definition_digest"] = json!(skill.definition_digest);
            }
            validate("CallResult", &out)?;
            if let Some(stream) = stream {
                stream.validate_completed(&out)?;
            }
            Ok(out)
        };
        let monitor = async {
            if !protected {
                std::future::pending::<()>().await;
            }
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                // Retain the physical slot until process fencing on failure, as
                // for RPC timeouts. This guard must be polled alongside execution:
                // execution may own a short shared authorization transaction when
                // a revocation writer queues ahead of this next reader.
                check_live_call_for_source(
                    app, origin, request_id, call, instance, generation, deadline,
                )
                .await?;
            }
        };
        let consumer = async {
            if let Some(stream) = stream {
                stream.closed().await
            } else {
                std::future::pending::<()>().await
            }
        };
        let monitored = race_live_call(result, monitor, consumer);
        let mut result = tokio::time::timeout(remaining(), monitored)
            .await
            .unwrap_or_else(|_| {
                Err(Error::new(
                    "DEADLINE_EXCEEDED",
                    "Call deadline elapsed; inspect the call record",
                    axum::http::StatusCode::GATEWAY_TIMEOUT,
                ))
            });
        if app.leader.is_closed() {
            return Err(Error::unavailable("Controller leadership is lost").with_resource(call));
        }
        let mut c = app
            .db
            .connect_scoped(deadline_bound.saturating_duration_since(tokio::time::Instant::now()))
            .await?;
        let tx = c.transaction().await?;
        db::call_lock(&tx).await?;
        let check = async {
            let current = origin
                .authenticate(&tx, app, request_id, Some(call))
                .await?;
            crate::dependencies::check_call(&tx, call).await?;
            crate::dependencies::check_ready(&tx, app, row.get("deployment_id")).await?;
            if protected {
                crate::host_blobs::check_call_sources(&tx, &current, call).await?;
            }
            if let Some(skill) = &skill {
                let resolved = crate::skills::resolve_for_invoke(&tx, &current, skill.id).await?;
                if resolved.definition_digest != skill.definition_digest
                    || resolved.installation_id != skill.installation_id
                {
                    return Err(Error::conflict("Fixed Skill binding changed"));
                }
            }
            authorize(
                &tx,
                &current,
                "capability.invoke",
                &Resource::new("capability", format!("{name}@{version}"), None),
            )
            .await
        };
        if let Err(e) = check.await {
            result = Err(e);
        }
        settle_business(
            &tx,
            &ctx,
            call,
            &accounts,
            if skill.is_some() {
                "skill.invoke"
            } else {
                "capability.invoke"
            },
            &result,
        )
        .await?;
        tx.commit().await?;
        skill_result(skill.as_ref(), result.map_err(|e| e.with_resource(call))?)
    })
}

async fn race_live_call<T>(
    execution: impl std::future::Future<Output = Result<T>>,
    monitor: impl std::future::Future<Output = Result<T>>,
    consumer: impl std::future::Future<Output = ()>,
) -> Result<T> {
    tokio::pin!(execution, monitor, consumer);
    tokio::select! {
        result = &mut execution => result,
        result = &mut monitor => result,
        _ = &mut consumer => Err(Error::new(
            "CANCELED",
            "Skill stream consumer disconnected",
            axum::http::StatusCode::CONFLICT,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn check_live_call(
    app: &App,
    token: &str,
    peer: IpAddr,
    request_id: Uuid,
    call: Uuid,
    instance: Uuid,
    generation: i64,
    deadline: chrono::DateTime<chrono::Utc>,
    browser_origin: Option<&str>,
) -> Result<()> {
    check_live_call_for_source(
        app,
        CallSource::Token {
            token,
            peer,
            browser_origin,
        },
        request_id,
        call,
        instance,
        generation,
        deadline,
    )
    .await
}

async fn check_live_call_for_source(
    app: &App,
    origin: CallSource<'_>,
    request_id: Uuid,
    call: Uuid,
    instance: Uuid,
    generation: i64,
    deadline: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    crate::skill_streams::ensure_active(app)?;
    let mut connection = app
        .db
        .connect_scoped(
            (deadline - chrono::Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO),
        )
        .await?;
    let check = connection.transaction().await?;
    if matches!(origin, CallSource::Task(_)) {
        db::call_lock(&check).await?;
    }
    let current = origin
        .authenticate(&check, app, request_id, Some(call))
        .await?;
    check_skill_authority(&check, &current, call).await?;
    http::check_route_approval(&check, app, call).await?;
    let status = check
        .query_one("SELECT state,error FROM calls WHERE id=$1", &[&call])
        .await?;
    if status
        .get::<_, Option<Value>>("error")
        .as_ref()
        .is_some_and(|error| error["code"] == "CANCELED")
    {
        return Err(Error::new(
            "CANCELED",
            "Call cancellation was requested; physical outcome remains unknown",
            axum::http::StatusCode::CONFLICT,
        ));
    }
    if status.get::<_, String>("state") != "running" {
        return Err(Error::conflict("Admitted call is no longer running"));
    }
    let live: bool = check.query_one("SELECT EXISTS(SELECT 1 FROM instances i JOIN deployments d ON d.id=i.deployment_id WHERE i.id=$1 AND i.generation=$2 AND i.phase='ready' AND d.archived_at IS NULL AND d.spec->>'enabled'='true')", &[&instance,&generation]).await?.get(0);
    if !live {
        return Err(Error::unavailable("Fixed Skill deployment is unavailable"));
    }
    let deployment: Uuid = check
        .query_one(
            "SELECT deployment_id FROM instances WHERE id=$1",
            &[&instance],
        )
        .await?
        .get(0);
    crate::dependencies::check_call(&check, call).await?;
    crate::dependencies::check_ready(&check, app, deployment).await?;
    check.commit().await?;
    crate::skill_streams::ensure_active(app)?;
    Ok(())
}

/// HostService reads authority from the admitted Call, not plugin JSON/headers.
pub(crate) async fn check_skill_binding(
    c: &(impl tokio_postgres::GenericClient + Sync),
    ctx: &crate::auth::Context,
    call: Uuid,
) -> Result<()> {
    http::check_binding(c, ctx, call).await?;
    let row = c.query_opt(
        "SELECT c.skill_id,c.skill_definition_digest,c.http_binding,d.installation_id FROM calls c LEFT JOIN instances i ON i.id=c.provider_instance_id LEFT JOIN deployments d ON d.id=i.deployment_id WHERE c.id=$1",
        &[&call],
    ).await?.ok_or_else(Error::denied)?;
    if let Some(skill) = row.get::<_, Option<Uuid>>("skill_id") {
        if row.get::<_, Option<Value>>("http_binding").is_some() {
            return crate::skills::check_admitted_http_binding(
                c,
                skill,
                &row.get::<_, Option<String>>("skill_definition_digest")
                    .ok_or_else(Error::denied)?,
                row.get::<_, Option<Uuid>>("installation_id")
                    .ok_or_else(Error::denied)?,
            )
            .await;
        }
        crate::skills::check_admitted_capability_binding(
            c,
            skill,
            &row.get::<_, Option<String>>("skill_definition_digest")
                .ok_or_else(Error::denied)?,
            row.get::<_, Option<Uuid>>("installation_id")
                .ok_or_else(Error::denied)?,
        )
        .await?;
    }
    Ok(())
}

fn skill_result(skill: Option<&crate::skills::ResolvedSkill>, call: Value) -> Result<Value> {
    if let Some(skill) = skill {
        let value = json!({"skill_id":skill.id,"skill_version":skill.definition["version"],"definition_digest":skill.definition_digest,"call":call});
        validate("SkillCallResult", &value)?;
        Ok(value)
    } else {
        Ok(call)
    }
}

#[cfg(test)]
#[path = "broker_schema_tests.rs"]
mod schema_tests;

/// One admission path for RPC and signed HTTP; all physical requests consume
/// the same instance count and ancestor/source credential accounting.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn reserve_business(
    tx: &tokio_postgres::Transaction<'_>,
    ctx: &crate::auth::Context,
    instance: Uuid,
    manifest: &Value,
    action: &str,
    resource: &Resource,
    skill: Option<&crate::skills::ResolvedSkill>,
    authority: Option<&crate::auth::CurrentAuthority<'_, '_>>,
) -> Result<(Vec<Uuid>, std::collections::BTreeSet<Uuid>)> {
    let active:i64=tx.query_one("SELECT (SELECT count(*) FROM calls c WHERE provider_instance_id=$1 AND (state IN ('accepted','running') OR EXISTS(SELECT 1 FROM reservations r WHERE r.id=c.id AND r.kind='call' AND r.status<>'released')))+(SELECT count(*) FROM plugin_http_requests WHERE instance_id=$1)",&[&instance]).await?.get(0);
    let max = manifest["concurrency"]["max_active_requests"]
        .as_i64()
        .unwrap_or(1);
    if active >= max {
        return Err(Error::exhausted());
    }
    let accounts = account_chain(tx, ctx.subject).await?;
    let today = chrono::Utc::now().date_naive();
    for account in &accounts {
        let quota = tx
            .query_one(
                "SELECT * FROM quotas WHERE account_id=$1 FOR UPDATE",
                &[account],
            )
            .await?;
        let q: Value = quota.get("spec");
        let daily = if quota.get::<_, chrono::NaiveDate>("daily_bucket") == today {
            quota.get::<_, i64>("daily_calls_used")
        } else {
            0
        };
        if quota.get::<_, i64>("concurrent_calls_used")
            >= q["maximum_concurrent_calls"].as_i64().unwrap()
            || daily >= q["daily_calls"].as_i64().unwrap()
        {
            return Err(Error::exhausted());
        }
        tx.execute("UPDATE quotas SET concurrent_calls_used=concurrent_calls_used+1,daily_calls_used=$2::bigint+1,daily_bucket=$3 WHERE account_id=$1", &[account,&daily,&today]).await?;
    }
    let mut charged = if let Some(authority) = authority {
        crate::identity::call_sources_from_paths(
            tx,
            ctx,
            action,
            resource,
            authority.paths(tx, ctx, resource)?.to_vec(),
        )
        .await?
    } else {
        crate::identity::call_sources_for(tx, ctx, action, resource).await?
    };
    if let Some(skill) = skill {
        let resource = Resource::new("skill", skill.id, Some(skill.owner));
        charged.extend(if let Some(authority) = authority {
            crate::identity::call_sources_from_paths(
                tx,
                ctx,
                "skill.invoke",
                &resource,
                authority.paths(tx, ctx, &resource)?.to_vec(),
            )
            .await?
        } else {
            crate::identity::call_sources_for(tx, ctx, "skill.invoke", &resource).await?
        });
    }
    Ok((accounts, charged))
}

/// A transport failure never proves physical completion. Only confirmed results
/// release the shared reservation; Controller recovery fences unknown work.
pub(crate) async fn settle_business(
    tx: &(impl tokio_postgres::GenericClient + Sync),
    ctx: &crate::auth::Context,
    call: Uuid,
    accounts: &[Uuid],
    action: &str,
    result: &Result<Value>,
) -> Result<()> {
    let (state, value, error) = match &result {
        Ok(v) => ("succeeded", Some(v.clone()), None),
        Err(e) => ("unknown", None, Some(e.detail())),
    };
    let changed = tx.execute("UPDATE calls SET state=$2,result=$3,error=$4,completed_at=CASE WHEN $2='succeeded' THEN now() ELSE NULL END WHERE id=$1 AND state='running'",&[&call,&state,&value,&error]).await?;
    if changed != 1 {
        let saved = tx
            .query_one("SELECT error FROM calls WHERE id=$1", &[&call])
            .await?
            .get::<_, Option<Value>>(0);
        if saved
            .as_ref()
            .is_some_and(|error| error["code"] == "CANCELED")
        {
            return Err(Error::new(
                "CANCELED",
                "Call cancellation was requested; physical outcome remains unknown",
                axum::http::StatusCode::CONFLICT,
            )
            .with_resource(call));
        }
        return Err(Error::new(
            "OUTCOME_UNKNOWN",
            "Call was fenced by recovery",
            axum::http::StatusCode::CONFLICT,
        )
        .with_resource(call));
    }
    // An error/timeout does not prove that the provider stopped executing.
    // Recovery fences its process before returning the reserved call slot.
    if result.is_ok() {
        tx.execute(
            "UPDATE reservations SET status='released' WHERE id=$1 AND kind='call'",
            &[&call],
        )
        .await?;
        for account in accounts {
            tx.execute("UPDATE quotas SET concurrent_calls_used=greatest(0,concurrent_calls_used-1) WHERE account_id=$1", &[account]).await?;
        }
    }
    tx.execute(
        "UPDATE rpc_delegations SET status='revoked' WHERE call_id=$1",
        &[&call],
    )
    .await?;
    tx.execute("UPDATE execution_delegations SET status='revoked' WHERE id IN(SELECT delegation_id FROM calls WHERE id=$1)", &[&call]).await?;
    db::audit(
        tx,
        ctx.subject,
        Some(ctx.credential),
        ctx.request,
        action,
        &Resource::new("call", call, Some(ctx.subject)).json(),
        if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        },
        if result.is_ok() {
            "CALL_COMPLETED"
        } else {
            "OUTCOME_UNKNOWN"
        },
    )
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "broker_http_tests.rs"]
mod http_component_tests;

/// Mandatory combined gate for admitted business delivery and HostService use.
/// Metadata-only checks are private; no HTTP caller can omit original/current
/// frozen proof validation, including calls with no Blob delegation context.
pub(crate) async fn check_skill_authority(
    c: &(impl tokio_postgres::GenericClient + Sync),
    ctx: &crate::auth::Context,
    call: Uuid,
) -> Result<()> {
    check_skill_binding(c, ctx, call).await?;
    crate::host_blobs::check_call_sources(c, ctx, call).await
}

#[cfg(test)]
#[path = "broker_monitor_tests.rs"]
mod monitor_tests;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn invoke_host(
    app: &App,
    token: &str,
    ctx: &crate::auth::Context,
    input: &Value,
    key: &str,
    skill: Option<Uuid>,
    stream: Option<&crate::skill_streams::Output>,
) -> Result<Value> {
    invoke_bounded(
        app,
        token,
        ctx.peer,
        ctx.request,
        input,
        key,
        skill,
        stream,
        ctx.browser_origin.as_deref(),
    )
    .await
}
