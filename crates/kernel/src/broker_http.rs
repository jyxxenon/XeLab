//! Signed HTTP is a Broker transport, with the same physical resource ledger,
//! current Authorizer, source proofs, cancellation and recovery as RPC calls.
use super::*;
use crate::{
    auth::{Context, Resource},
    plugin_http::transport::{Delegation, InstanceHttp},
    plugin_http::{self, Registry},
};
use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use futures_util::{Stream, StreamExt};
use std::{
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_postgres::GenericClient;

struct Input {
    method: Method,
    path: String,
    headers: HeaderMap,
    bytes: Vec<u8>,
    key: String,
    deployment: Option<Uuid>,
    skill: Option<Uuid>,
    skill_input: Option<Value>,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
}
impl Input {
    fn skill(started: tokio::time::Instant, deadline: tokio::time::Instant, key: String) -> Self {
        Self {
            method: Method::POST,
            path: String::new(),
            headers: HeaderMap::new(),
            bytes: Vec::new(),
            key,
            deployment: None,
            skill: None,
            skill_input: None,
            started,
            deadline,
        }
    }
}
struct Provider {
    instance: Uuid,
    generation: i64,
    deployment: Uuid,
    installation: Uuid,
    owner: Uuid,
    manifest: Value,
    registry: Arc<Registry>,
    path: String,
    method: Method,
}
impl Provider {
    fn operation(&self) -> Result<&plugin_http::Operation> {
        self.registry.resolve(&self.method, &self.path)
    }
}
#[allow(clippy::too_many_arguments)] // Preserve the authenticated request and monotonic deadline independently.
pub(super) async fn execute_skill(
    app: &App,
    token: &str,
    peer: IpAddr,
    request: Uuid,
    skill: Uuid,
    input: &Value,
    key: &str,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
    stream: Option<&crate::skill_streams::Output>,
    browser_origin: Option<&str>,
) -> Result<Value> {
    let mut value = Input::skill(started, deadline, key.into());
    value.deployment = input
        .get("provider_deployment_id")
        .map(|_| id(input, "provider_deployment_id"))
        .transpose()?;
    value.skill = Some(skill);
    value.skill_input = Some(input.clone());
    let source = CallSource::Token {
        token,
        peer,
        browser_origin,
    };
    let result = execute(app, source, request, value, None, stream).await?;
    Ok(result.0)
}

pub(super) async fn execute_task(app: &App, lease: &Lease) -> Result<Value> {
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(300);
    let input = Input::skill(started, deadline, lease.execution_id.to_string());
    let (value, _) = tokio::time::timeout_at(
        deadline,
        execute_inner(
            app,
            CallSource::Task(lease),
            lease.execution_id,
            input,
            None,
            None,
        ),
    )
    .await
    .map_err(|_| expired())??;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub async fn invoke(
    app: Arc<App>,
    token: &str,
    peer: IpAddr,
    request: Uuid,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    bytes: &[u8],
    key: Option<&str>,
    deployment: Option<Uuid>,
    started: tokio::time::Instant,
) -> Result<Response> {
    let permit = pool().try_acquire_owned().map_err(|_| Error::exhausted())?;
    let (sender, receiver) = mpsc::channel(1);
    let (head, head_rx) = oneshot::channel();
    let output = Arc::new(Output {
        sender,
        head: Mutex::new(Some(head)),
        identity: Arc::new(Mutex::new(None)),
        sequence: Mutex::new(0),
        stalled: std::sync::atomic::AtomicBool::new(false),
        terminal: std::sync::atomic::AtomicBool::new(false),
    });
    let input = Input {
        method: method.clone(),
        path: path.into(),
        headers: headers.clone(),
        bytes: bytes.to_vec(),
        key: key
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        deployment,
        skill: None,
        skill_input: None,
        started,
        deadline: started + Duration::from_millis(300000),
    };
    let browser_origin = crate::oauth_http::request_origin(headers)?.map(str::to_owned);
    let actor = app.clone();
    let actor_token = token.to_owned();
    let producer = output.clone();
    tokio::spawn(async move {
        let source = CallSource::Token {
            token: &actor_token,
            peer,
            browser_origin: browser_origin.as_deref(),
        };
        let result = tokio::select! {
            biased;
            _ = producer.abandoned_before_admission() => Err(Error::new("CANCELED","HTTP consumer disconnected before admission",StatusCode::CONFLICT)),
            result=tokio::time::timeout_at(input.deadline,execute(&actor,source,request,input,Some(&producer),None))=>result.unwrap_or_else(|_|Err(expired())),
        };
        match result {
            Ok((value, Some(response))) => producer.complete_json(value, response).await,
            Ok((value, None)) => producer.terminal("completed", value).await,
            Err(error) => producer.fail(error).await,
        }
    });
    let head = tokio::time::timeout_at(started + Duration::from_millis(300000), head_rx)
        .await
        .map_err(|_| expired())?
        .map_err(|_| Error::unavailable("HTTP call admission ended"))??;
    let consumer = output.identity.clone();
    let consumer_token = token.to_owned();
    let stream = futures_util::stream::unfold(
        (receiver, false, 0_u64),
        move |(mut receiver, ended, last_sequence)| {
            let app = app.clone();
            let token = consumer_token.clone();
            let identity = consumer.clone();
            async move {
                if ended {
                    return None;
                }
                let frame = receiver.recv().await?;
                let checked = if let Some(identity) = identity.lock().ok().and_then(|i| i.clone()) {
                    delivery(&app, &token, peer, request, &identity).await
                } else {
                    Err(Error::denied())
                };
                let frame = match checked {
                    Ok(()) => frame,
                    Err(error) => {
                        if head.2 {
                            match error_frame(&identity, error, last_sequence + 1) {
                                Ok(frame) => frame,
                                Err(_) => return None,
                            }
                        } else {
                            return Some((
                                Err(std::io::Error::other(
                                    "HTTP authority changed before body delivery",
                                )),
                                (receiver, true, last_sequence),
                            ));
                        }
                    }
                };
                let ended = frame.1;
                Some((
                    Ok::<_, std::io::Error>(frame.0),
                    (
                        receiver,
                        ended,
                        if frame.2 == 0 { last_sequence } else { frame.2 },
                    ),
                ))
            }
        },
    );
    let mut response = Response::new(retained_body(Body::from_stream(stream), permit));
    *response.status_mut() = head.0;
    *response.headers_mut() = head.1;
    response
        .headers_mut()
        .insert("x-request-id", request.to_string().parse().unwrap());
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(response)
}

async fn execute(
    app: &App,
    source: CallSource<'_>,
    request: Uuid,
    mut input: Input,
    output: Option<&Output>,
    stream: Option<&crate::skill_streams::Output>,
) -> Result<(Value, Option<plugin_http::transport::Response>)> {
    // This lookup conveys no authority. It only narrows the original request
    // clock before waiting on the shared admission lock, exactly as Skill RPC.
    let c = app
        .db
        .connect_scoped(
            input
                .deadline
                .saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
    let minimum: Option<i64> = if let Some(skill) = input.skill {
        // Budget-only metadata must neither select another route nor expose a
        // private installation's integrity/availability before authorization.
        // Authoritative errors are produced by resolve_http_for_invoke below.
        let exact_budget = async {
            let row = c
                .query_opt(
                    "SELECT definition,installation_id FROM skills WHERE id=$1",
                    &[&skill],
                )
                .await
                .ok()??;
            let registry = crate::http_contracts::load(&*c, row.get("installation_id"))
                .await
                .ok()?;
            let definition: Value = row.get("definition");
            registry
                .bind_skill(&definition)
                .ok()
                .map(|operation| operation.route.timeout.as_millis() as i64)
        };
        tokio::time::timeout_at(input.deadline, exact_budget)
            .await
            .map_err(|_| expired())?
    } else {
        plugin_http::canonical_path(&input.path)?;
        let plugin = input
            .path
            .strip_prefix("/plugins/")
            .and_then(|p| p.split_once('/'))
            .map(|(p, _)| p)
            .ok_or_else(Error::not_found)?;
        c.query_one("SELECT min((r->>'timeout_ms')::bigint) FROM installations n CROSS JOIN LATERAL jsonb_array_elements(n.manifest->'routes') r WHERE n.plugin_id=$1 AND n.state='installed' AND r->>'kind'='http' AND r->'methods' ? $2 AND left($3,length(r->>'path_prefix'))=r->>'path_prefix' AND ($4::uuid IS NULL OR EXISTS(SELECT 1 FROM deployments d WHERE d.id=$4 AND d.installation_id=n.id))",&[&plugin,&input.method.as_str(),&input.path,&input.deployment]).await?.get(0)
    };
    drop(c);
    if let Some(minimum) = minimum.filter(|v| *v >= 100 && *v <= 300000) {
        input.deadline = input
            .deadline
            .min(input.started + Duration::from_millis(minimum as u64));
    }
    if input.deadline <= tokio::time::Instant::now() {
        return Err(expired());
    }
    tokio::time::timeout_at(
        input.deadline,
        execute_inner(app, source, request, input, output, stream),
    )
    .await
    .unwrap_or_else(|_| Err(expired()))
}

async fn execute_inner(
    app: &App,
    source: CallSource<'_>,
    request: Uuid,
    mut input: Input,
    output: Option<&Output>,
    stream: Option<&crate::skill_streams::Output>,
) -> Result<(Value, Option<plugin_http::transport::Response>)> {
    crate::skill_streams::ensure_active(app)?;
    let mut c = app
        .db
        .connect_scoped(
            input
                .deadline
                .saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
    let tx = c.transaction().await?;
    let task = match source {
        CallSource::Task(lease) => Some(lease),
        CallSource::Token { .. } => None,
    };
    let (ctx, task_deadline) = if let Some(lease) = task {
        // Task preparation and its transaction-bound proof must share the
        // physical Call admission transaction and its lock order.
        db::call_lock(&tx).await?;
        let (invocation, ctx) = task_engine::prepare_broker(&tx, &app.auth, lease).await?;
        input.skill = Some(invocation.skill_id);
        input.deployment = Some(invocation.deployment_id);
        input.skill_input = Some(json!({
            "input":invocation.input,
            "provider_deployment_id":invocation.deployment_id,
            "idempotency_key":invocation.idempotency_key,
        }));
        let remaining = (invocation.deadline - chrono::Utc::now())
            .to_std()
            .map_err(|_| expired())?;
        input.deadline = input.deadline.min(tokio::time::Instant::now() + remaining);
        (ctx, Some(invocation.deadline))
    } else {
        (source.authenticate(&tx, app, request, None).await?, None)
    };
    let mut authority = crate::auth::CurrentAuthority::new(&tx, &ctx).await?;
    let skill = if let Some(skill) = input.skill {
        match crate::skills::resolve_http_for_invoke(&tx, &ctx, skill, &authority).await {
            Ok(skill) => Some(skill),
            Err(error) if task.is_some() => return Err(error),
            Err(error) => {
                db::audit(
                    &tx,
                    ctx.subject,
                    Some(ctx.credential),
                    request,
                    "skill.invoke",
                    &Resource::new("skill", skill, None).json(),
                    "denied",
                    error.code,
                )
                .await?;
                drop(authority);
                tx.commit().await?;
                return Err(error);
            }
        }
    } else {
        None
    };
    if let Some(skill) = &skill {
        let invocation = input.skill_input.as_ref().ok_or_else(Error::denied)?;
        validate("SkillInvokeRequest", invocation)?;
        validate_business(&skill.definition["input_schema"], &invocation["input"])?;
        if task.is_none() {
            let maximum = unsigned(&skill.definition["maximum_timeout_ms"])?;
            let requested = invocation
                .get("timeout_ms")
                .map(unsigned)
                .transpose()?
                .unwrap_or(maximum.min(120000));
            if requested > maximum {
                return Err(Error::invalid(
                    "Requested deadline exceeds HTTP Skill maximum",
                ));
            }
            input.deadline = input
                .deadline
                .min(input.started + Duration::from_millis(requested));
        }
    }
    // Expensive current-policy preparation can run concurrently under the
    // shared auth fence. The physical ledger, provider rows and mutable budget
    // choices remain serialized in the established order below.
    if task.is_none() {
        db::call_lock(&tx).await?;
        let current = source.authenticate(&tx, app, request, None).await?;
        authority.verify(&tx, &current)?;
    }
    let target = resolve(&tx, &input, skill.as_ref(), task.is_some()).await?;
    let op = target.operation()?;
    if let Some(skill) = &skill {
        let invocation = input.skill_input.as_ref().ok_or_else(Error::denied)?;
        if op.input.is_some() {
            input.bytes = serde_json::to_vec(&invocation["input"])?;
            input
                .headers
                .insert("content-type", "application/json".parse().unwrap());
        } else if !invocation["input"].is_null() {
            return Err(Error::invalid(
                "Bodyless HTTP Skill identity input must be null",
            ));
        }
        if stream.is_some() != !skill.definition["stream_item_schema"].is_null() {
            return Err(Error::invalid(
                "HTTP Skill invocation must use the endpoint matching its signed streaming declaration",
            ));
        }
    }
    input.deadline = input.deadline.min(input.started + op.route.timeout);
    let remaining = input
        .deadline
        .saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(expired());
    }
    let transport_deadline =
        chrono::Utc::now() + chrono::Duration::from_std(remaining).map_err(|_| expired())?;
    let wall_deadline = if let Some(token) = source.token() {
        crate::host_calls::bound_deadline(&tx, app, token, transport_deadline).await?
    } else {
        task_deadline
            .ok_or_else(Error::denied)?
            .min(transport_deadline)
    };
    input.deadline = input.deadline.min(
        tokio::time::Instant::now()
            + (wall_deadline - chrono::Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO),
    );
    if input.bytes.len() > app.config.json_limit(op.route.maximum_body_bytes) {
        return Err(plugin_http::too_large());
    }
    let headers = op.request(&input.headers, &input.bytes)?;
    if task.is_some() {
        check_task_manifest(&target.manifest)?;
        // Deployment approval retains its independent source proof, even
        // when the approver and the Task issuer use the same credential.
        crate::plugin_http_gateway::check_approval(&tx, app, target.deployment, &target.manifest)
            .await?;
    } else {
        crate::plugin_http_gateway::check_approval_prepared(
            &tx,
            app,
            target.deployment,
            &target.manifest,
            &ctx,
            &authority,
        )
        .await?;
    }
    if target.manifest["business_entry"] == "skill_required" && skill.is_none() {
        return Err(Error::denied());
    }
    let resource = Resource::new(
        "plugin",
        string(&target.manifest, "plugin_id")?,
        Some(target.owner),
    );
    authority.bind_plugin(&tx, &ctx, &resource)?;
    if let Err(error) = authority.require(&tx, &ctx, &op.route.action, &resource) {
        if task.is_some() {
            return Err(error);
        }
        db::audit(
            &tx,
            ctx.subject,
            Some(ctx.credential),
            request,
            &op.route.action,
            &resource.json(),
            "denied",
            error.code,
        )
        .await?;
        drop(authority);
        tx.commit().await?;
        return Err(error);
    }
    let binding = json!({"installation_id":target.installation,"deployment_id":target.deployment,"generation":target.generation,"http_contract_digest":op.contract_digest,"operation_id":op.id,"method":op.method.as_str(),"path":op.path,"required_action":op.route.action});
    let contract = if let Some(skill) = &skill {
        json!({"name":skill.definition["name"],"version":skill.definition["version"],"schema_digest":skill.definition_digest})
    } else {
        json!({"name":format!("{}.http",string(&target.manifest,"plugin_id")?),"version":target.manifest["version"],"schema_digest":op.contract_digest})
    };
    let key = &input.key;
    if key.is_empty() || key.len() > 128 {
        return Err(Error::invalid("HTTP idempotency key is invalid"));
    }
    let business_key = input
        .skill_input
        .as_ref()
        .and_then(|i| i["idempotency_key"].as_str())
        .unwrap_or(key);
    if business_key.is_empty() || business_key.chars().count() > 128 {
        return Err(Error::invalid("Business idempotency key is invalid"));
    }
    let header_fingerprint: std::collections::BTreeMap<_, _> = headers
        .iter()
        .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
        .collect();
    let body = if input.bytes.is_empty() {
        Value::Null
    } else {
        strict_json(
            &input.bytes,
            app.config.json_limit(op.route.maximum_body_bytes),
        )?
    };
    let fingerprint = crate::skills::definition_digest(
        &json!({"installation":target.installation,"deployment":target.deployment,"operation":op.id,"digest":op.contract_digest,"input":body,"headers":header_fingerprint,"skill_input":input.skill_input}),
    )?;
    let path = if let Some(lease) = task {
        task_call_path(lease)
    } else if let Some(skill) = &skill {
        format!(
            "/api/platform/v1/skills/{}/calls{}",
            skill.id,
            if stream.is_some() { ":stream" } else { "" }
        )
    } else {
        input.path.clone()
    };
    let method = if skill.is_some() {
        "POST"
    } else {
        input.method.as_str()
    };
    if let Some(prior)=tx.query_opt("SELECT fingerprint,resource_id,safe_response,response_status FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method=$3 AND path=$4 AND key=$5 AND expires_at>now() FOR UPDATE",&[&ctx.subject,&ctx.credential,&method,&path,&key]).await?{
        if task.is_some(){return Err(Error::conflict("Task attempt already has a Broker record"));}
        if prior.get::<_,String>("fingerprint")!=fingerprint{return Err(Error::new("IDEMPOTENCY_CONFLICT","HTTP key was already bound to different input",StatusCode::CONFLICT));}
        let call=prior.get::<_,Option<String>>("resource_id").and_then(|s|s.parse::<Uuid>().ok()).ok_or_else(Error::denied)?;
        check_skill_authority(&tx,&ctx,call).await?;
        if stream.is_some(){return Err(Error::conflict("Generation streams cannot be replayed; inspect the admitted Call").with_resource(call));}
        let saved=tx.query_one("SELECT state,result FROM calls WHERE id=$1",&[&call]).await?;
        if saved.get::<_,String>("state")!="succeeded"{return Err(Error::new("OUTCOME_UNKNOWN","Prior HTTP call is not a confirmed success",StatusCode::CONFLICT).with_resource(call));}
        let value:Value=saved.get::<_,Option<Value>>("result").ok_or_else(Error::denied)?;
        if skill.is_some(){return Ok((skill_result(skill.as_ref(),value)?,None));}
        let saved:Value=prior.get::<_,Option<Value>>("safe_response").ok_or_else(||Error::conflict("Generation streams cannot be replayed; inspect Call").with_resource(call))?;
        let status=StatusCode::from_u16(prior.get::<_,Option<i32>>("response_status").ok_or_else(Error::denied)? as u16).map_err(|_|Error::denied())?;
        let mut headers=HeaderMap::new();for (name,value) in saved["headers"].as_object().ok_or_else(Error::denied)?{headers.insert(axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_|Error::denied())?,string(&json!({"v":value}),"v")?.parse().map_err(|_|Error::denied())?);}
        if let Some(output)=output {output.bind_origin(call,wall_deadline,ctx.browser_origin.as_deref());}
        return Ok((value,Some(plugin_http::transport::Response{status,headers,bytes:serde_json::to_vec(&saved["body"])?})));
    }
    let (accounts, charged) = reserve_business(
        &tx,
        &ctx,
        target.instance,
        &target.manifest,
        &op.route.action,
        &resource,
        skill.as_ref(),
        Some(&authority),
    )
    .await?;
    let call = if let Some(token) = source.token() {
        crate::host_calls::new_call(&tx, app, token).await?
    } else {
        Uuid::new_v4()
    };
    tx.execute("INSERT INTO calls(id,owner_id,credential_id,provider_instance_id,contract,input_digest,idempotency_key,state,deadline_at,created_at,http_binding,skill_id,skill_definition_digest) VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8,now(),$9,$10,$11)",&[&call,&ctx.subject,&ctx.credential,&target.instance,&contract,&digest(&input.bytes),&business_key,&wall_deadline,&binding,&skill.as_ref().map(|s|s.id),&skill.as_ref().map(|s|s.definition_digest.as_str())]).await?;
    for credential in charged {
        tx.execute(
            "INSERT INTO call_credential_charges(call_id,credential_id) VALUES($1,$2)",
            &[&call, &credential],
        )
        .await?;
    }
    tx.execute("INSERT INTO reservations(id,account_id,kind,expires_at,status,created_at) VALUES($1,$2,'call',$3,'active',now())",&[&call,&ctx.subject,&wall_deadline]).await?;
    if let Some(token) = source.token() {
        crate::host_calls::bind_child(&tx, app, token, call, target.instance).await?;
    }
    let delegation = app
        .auth
        .issue_rpc(
            &tx,
            &ctx,
            call,
            target.instance,
            target.generation,
            wall_deadline,
        )
        .await?;
    let definition = json!({"input_schema":op.input.as_ref().map(|s|s.value()).unwrap_or(&Value::Null),"contract":contract});
    crate::host_blobs::grant_http_call(
        &tx,
        app,
        &ctx,
        call,
        target.deployment,
        &target.manifest,
        &definition,
        &body,
        skill
            .as_ref()
            .is_some_and(|s| s.definition["input_blobs"] == true),
        &authority,
    )
    .await?;
    if let Some(lease) = task {
        task_engine::record_broker_call(&tx, lease, call).await?;
        crate::skill_streams::ensure_active(app)?;
    }
    tx.execute("DELETE FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method=$3 AND path=$4 AND key=$5 AND expires_at<=now()",&[&ctx.subject,&ctx.credential,&method,&path,&key]).await?;
    tx.execute("INSERT INTO idempotency_records(subject_id,credential_id,method,path,key,fingerprint,resource_id,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '24 hours',now())",&[&ctx.subject,&ctx.credential,&method,&path,&key,&fingerprint,&call.to_string()]).await?;
    if let Some(output) = output {
        output.ensure_open()?;
        output.bind_origin(call, wall_deadline, ctx.browser_origin.as_deref());
    }
    if let Some(stream) = stream {
        stream.ensure_open()?;
    }
    drop(authority);
    tx.commit().await?;
    drop(c);
    let execution = async {
        if let Some(stream) = stream {
            stream.bind(
                skill.as_ref().ok_or_else(Error::denied)?,
                call,
                wall_deadline,
            )?;
            stream.ensure_open()?;
        }
        check_live_call_for_source(
            app,
            source,
            request,
            call,
            target.instance,
            target.generation,
            wall_deadline,
        )
        .await?;
        if let Some(output) = output {
            output.ensure_open()?;
        }
        let client = InstanceHttp::from_runtime(
            &app.config,
            &app.runtime,
            target.instance,
            target.generation,
        )?;
        if let Some(output) = output {
            output.ensure_open()?;
        }
        let response = client
            .open(
                op,
                &input.headers,
                &input.bytes,
                Delegation {
                    token: &delegation,
                    subject: ctx.subject,
                    call,
                    deadline_unix_ms: wall_deadline.timestamp_millis(),
                    idempotency_key: business_key,
                },
                input.deadline,
            )
            .await?;
        let status = response.status();
        let (_, safe_headers) = op.response_head(status, response.headers())?;
        let streaming =
            op.responses[&status.as_u16()].media_type.as_deref() == Some("text/event-stream");
        if streaming {
            if output.is_none() && stream.is_none() {
                return Err(Error::invalid(
                    "HTTP event stream requires a streaming invocation",
                ));
            }
            let terminal = read_events(
                app,
                source,
                request,
                call,
                &target,
                response,
                output,
                stream.zip(skill.as_ref()),
                (status, safe_headers),
                wall_deadline,
            )
            .await?;
            let value = terminal["payload"].clone();
            if value["call_id"] != call.to_string()
                || value["contract"]
                    != json!({"name":format!("{}.http",string(&target.manifest,"plugin_id")?),"version":target.manifest["version"],"schema_digest":op.contract_digest})
                || value["provider_instance_id"] != target.instance.to_string()
            {
                return Err(Error::conflict("HTTP completed stream target differs"));
            }
            if value.get("skill_id").is_some() || value.get("skill_definition_digest").is_some() {
                return Err(Error::conflict("Direct HTTP cannot claim a Skill result"));
            }
            validate("CallResult", &value)?;
            let mut value = json!({"call_id":call,"contract":contract,"provider_instance_id":target.instance,"output":value["output"],"completed_at":chrono::Utc::now()});
            if let Some(skill) = &skill {
                validate_business(&skill.definition["output_schema"], &value["output"])?;
                value["skill_id"] = json!(skill.id);
                value["skill_definition_digest"] = json!(skill.definition_digest);
            }
            validate("CallResult", &value)?;
            if let Some(stream) = stream {
                stream.validate_completed(&value)?;
            } else {
                let mut terminal = terminal;
                terminal["payload"] = value.clone();
                op.responses[&200]
                    .schema
                    .as_ref()
                    .ok_or_else(Error::denied)?
                    .check(&terminal)?;
            }
            return Ok((value, None));
        }
        let maximum_output_bytes = app.config.json_limit(if task.is_some() {
            task_engine::MAX_STEP_JSON_BYTES
        } else {
            plugin_http::MAXIMUM_RESPONSE_BYTES
        });
        let bytes = plugin_http::transport::collect(response, maximum_output_bytes)
            .await?
            .bytes;
        let safe_headers = op.response(status, &safe_headers, &bytes)?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            strict_json(&bytes, maximum_output_bytes)?
        };
        if task.is_some() {
            crate::contracts::reject_jsonb_nul(&body)?;
            if serde_json::to_vec(&body)?.len() > maximum_output_bytes {
                return Err(plugin_http::too_large());
            }
        }
        if let Some(skill) = &skill {
            if !status.is_success() {
                return Err(Error::unavailable(
                    "HTTP Skill operation did not return a declared success",
                ));
            }
            validate_business(&skill.definition["output_schema"], &body)?;
        }
        let mut value = json!({"call_id":call,"contract":contract,"provider_instance_id":target.instance,"output":body,"completed_at":chrono::Utc::now()});
        if let Some(skill) = &skill {
            value["skill_id"] = json!(skill.id);
            value["skill_definition_digest"] = json!(skill.definition_digest);
        }
        validate("CallResult", &value)?;
        Ok((
            value,
            Some(plugin_http::transport::Response {
                status,
                headers: safe_headers,
                bytes,
            }),
        ))
    };
    let monitored = async {
        // Authority monitoring must not stop polling the actual HTTP transport
        // while its database checks are in flight.
        let authority = async {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Err(error) = check_live_call_for_source(
                    app,
                    source,
                    request,
                    call,
                    target.instance,
                    target.generation,
                    wall_deadline,
                )
                .await
                {
                    return error;
                }
            }
        };
        tokio::select! {
            result=execution=>result,
            error=authority=>Err(error),
            _=async{if let Some(output)=output{output.sender.closed().await}else if let Some(stream)=stream{stream.closed().await}else{std::future::pending::<()>().await}}=>Err(Error::new("CANCELED","HTTP consumer disconnected",StatusCode::CONFLICT)),
        }
    };
    let result = tokio::time::timeout_at(input.deadline, monitored)
        .await
        .unwrap_or_else(|_| Err(expired()));
    crate::skill_streams::ensure_active(app)?;
    let mut c = app
        .db
        .connect_scoped(
            input
                .deadline
                .saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
    let tx = c.transaction().await?;
    db::call_lock(&tx).await?;
    let authority = async {
        let current = source.authenticate(&tx, app, request, Some(call)).await?;
        check_skill_authority(&tx, &current, call).await?;
        check_route_approval(&tx, app, call).await
    }
    .await;
    let mut result = result;
    if let Err(error) = authority {
        result = Err(error);
    }
    let settlement = match &result {
        Ok((value, _)) => super::CallSettlement::Completed(value),
        Err(error) => super::CallSettlement::Unknown(error),
    };
    settle_business(
        &tx,
        &ctx,
        call,
        &accounts,
        if skill.is_some() {
            "skill.invoke"
        } else {
            &op.route.action
        },
        settlement,
    )
    .await?;
    if let Ok((value, Some(response))) = &result {
        if skill.is_none() {
            let headers: std::collections::BTreeMap<_, _> = response
                .headers
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str(), v)))
                .collect();
            let safe = json!({"headers":headers,"body":value["output"]});
            tx.execute("UPDATE idempotency_records SET response_status=$2,safe_response=$3 WHERE subject_id=$4 AND credential_id=$5 AND method=$6 AND path=$7 AND key=$8 AND resource_id=$1",&[&call.to_string(),&(response.status.as_u16() as i32),&safe,&ctx.subject,&ctx.credential,&method,&path,&key]).await?;
        }
    }
    tx.commit().await?;
    let (value, response) = result.map_err(|e| e.with_resource(call))?;
    Ok((skill_result(skill.as_ref(), value)?, response))
}

async fn resolve(
    c: &(impl GenericClient + Sync),
    input: &Input,
    skill: Option<&crate::skills::ResolvedSkill>,
    task: bool,
) -> Result<Provider> {
    let plugin = if let Some(skill) = skill {
        string(&skill.definition["target"], "plugin_id")?
    } else {
        plugin_http::canonical_path(&input.path)?;
        input
            .path
            .strip_prefix("/plugins/")
            .and_then(|p| p.split_once('/'))
            .map(|(p, _)| p)
            .ok_or_else(Error::not_found)?
    };
    let installation = skill.map(|s| s.installation_id);
    let rows=c.query("SELECT i.id,i.generation,d.id AS deployment,d.owner_id,d.installation_id,n.manifest FROM instances i JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id JOIN publishers p ON p.id=n.publisher_id WHERE n.plugin_id=$1 AND n.state='installed' AND p.status='trusted' AND i.phase='ready' AND i.generation=d.observed_generation AND d.phase='ready' AND i.health='alive' AND i.last_heartbeat_at>(CASE WHEN $4 THEN clock_timestamp() ELSE now() END)-interval '1 millisecond'*((n.manifest->'health'->>'interval_ms')::bigint*(n.manifest->'health'->>'failure_threshold')::bigint+(n.manifest->'health'->>'timeout_ms')::bigint) AND d.spec->>'enabled'='true' AND d.archived_at IS NULL AND d.approval ? 'rules' AND ($2::uuid IS NULL OR n.id=$2) AND ($3::uuid IS NULL OR d.id=$3) ORDER BY i.id FOR UPDATE OF i",&[&plugin,&installation,&input.deployment,&task]).await?;
    if rows.len() > 1 {
        return Err(Error::conflict(
            "HTTP route has ambiguous approved deployment bindings",
        ));
    }
    let row = rows
        .first()
        .ok_or_else(|| Error::unavailable("No healthy fixed HTTP deployment"))?;
    let installation = row.get("installation_id");
    let registry = crate::http_contracts::load(c, installation).await?;
    let (method, path) = if let Some(skill) = skill {
        let op = registry.bind_skill(&skill.definition)?;
        (op.method.clone(), op.path.clone())
    } else {
        registry.resolve(&input.method, &input.path)?;
        (input.method.clone(), input.path.clone())
    };
    Ok(Provider {
        instance: row.get("id"),
        generation: row.get("generation"),
        deployment: row.get("deployment"),
        installation,
        owner: row.get("owner_id"),
        manifest: row.get("manifest"),
        registry,
        path,
        method,
    })
}

pub(crate) async fn target_resource(
    c: &(impl GenericClient + Sync),
    call: Uuid,
) -> Result<(String, Resource)> {
    let row = c
        .query_one(
            "SELECT contract,http_binding FROM calls WHERE id=$1",
            &[&call],
        )
        .await?;
    if let Some(binding) = row.get::<_, Option<Value>>("http_binding") {
        let installation = id(&binding, "installation_id")?;
        let deployment = id(&binding, "deployment_id")?;
        let row=c.query_one("SELECT n.plugin_id,d.owner_id FROM installations n JOIN deployments d ON d.id=$2 WHERE n.id=$1",&[&installation,&deployment]).await?;
        Ok((
            string(&binding, "required_action")?.into(),
            Resource::new(
                "plugin",
                row.get::<_, String>("plugin_id"),
                Some(row.get("owner_id")),
            ),
        ))
    } else {
        let contract: Value = row.get("contract");
        Ok((
            "capability.invoke".into(),
            Resource::new(
                "capability",
                format!(
                    "{}@{}",
                    string(&contract, "name")?,
                    string(&contract, "version")?
                ),
                None,
            ),
        ))
    }
}

pub(super) async fn check_binding(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    call: Uuid,
) -> Result<()> {
    let row=c.query_one("SELECT c.http_binding,d.installation_id,d.spec,d.archived_at,i.generation,n.manifest,n.state,p.status,d.id AS deployment,i.phase AS instance_phase,i.health,i.last_heartbeat_at,d.observed_generation,d.phase AS deployment_phase FROM calls c JOIN instances i ON i.id=c.provider_instance_id JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id JOIN publishers p ON p.id=n.publisher_id WHERE c.id=$1",&[&call]).await?;
    let Some(binding) = row.get::<_, Option<Value>>("http_binding") else {
        return Ok(());
    };
    let installation = id(&binding, "installation_id")?;
    let deployment = id(&binding, "deployment_id")?;
    if row.get::<_, Uuid>("installation_id") != installation
        || row.get::<_, Uuid>("deployment") != deployment
        || row.get::<_, i64>("generation") != unsigned(&binding["generation"])? as i64
        || row.get::<_, Value>("spec")["enabled"] != true
        || row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("archived_at")
            .is_some()
        || row.get::<_, String>("state") != "installed"
        || row.get::<_, String>("status") != "trusted"
    {
        return Err(Error::denied());
    }
    let manifest: Value = row.get("manifest");
    let freshness = unsigned(&manifest["health"]["interval_ms"])?
        * unsigned(&manifest["health"]["failure_threshold"])?
        + unsigned(&manifest["health"]["timeout_ms"])?;
    if row.get::<_, String>("instance_phase") != "ready"
        || row.get::<_, String>("deployment_phase") != "ready"
        || row.get::<_, String>("health") != "alive"
        || row.get::<_, i64>("generation") != row.get::<_, i64>("observed_generation")
        || row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("last_heartbeat_at")
            .is_none_or(|at| {
                at + chrono::Duration::milliseconds(freshness as i64) <= chrono::Utc::now()
            })
    {
        return Err(Error::unavailable("Fixed HTTP instance is no longer ready"));
    }
    let registry = crate::http_contracts::load(c, installation).await?;
    let method =
        Method::from_bytes(string(&binding, "method")?.as_bytes()).map_err(|_| Error::denied())?;
    let op = registry.resolve(&method, string(&binding, "path")?)?;
    if op.id != binding["operation_id"]
        || op.contract_digest != binding["http_contract_digest"]
        || op.route.action != binding["required_action"]
    {
        return Err(Error::denied());
    }
    let manifest: Value = row.get("manifest");
    crate::http_contracts::validate_actions(c, &manifest).await?;
    // Current + original target/Skill permissions are checked together by
    // host_blobs::check_call_sources in this same authority transaction.
    let _ = ctx;
    Ok(())
}

#[derive(Clone)]
struct Identity {
    call: Uuid,
    deadline: chrono::DateTime<chrono::Utc>,
    browser_origin: Option<String>,
}
type Head = (StatusCode, HeaderMap, bool);
struct Output {
    sender: mpsc::Sender<(Vec<u8>, bool, u64)>,
    head: Mutex<Option<oneshot::Sender<Result<Head>>>>,
    identity: Arc<Mutex<Option<Identity>>>,
    sequence: Mutex<u64>,
    stalled: std::sync::atomic::AtomicBool,
    terminal: std::sync::atomic::AtomicBool,
}
impl Output {
    #[cfg(test)]
    fn bind(&self, call: Uuid, deadline: chrono::DateTime<chrono::Utc>) {
        self.bind_origin(call, deadline, None);
    }
    fn bind_origin(
        &self,
        call: Uuid,
        deadline: chrono::DateTime<chrono::Utc>,
        browser_origin: Option<&str>,
    ) {
        if let Ok(mut i) = self.identity.lock() {
            *i = Some(Identity {
                call,
                deadline,
                browser_origin: browser_origin.map(str::to_owned),
            });
        }
    }
    fn ensure_open(&self) -> Result<()> {
        if self.sender.is_closed() {
            Err(Error::new(
                "CANCELED",
                "HTTP consumer disconnected",
                StatusCode::CONFLICT,
            ))
        } else {
            Ok(())
        }
    }
    fn begin(&self, status: StatusCode, headers: HeaderMap, streaming: bool) -> Result<()> {
        self.ensure_open()?;
        if let Some(head) = self
            .head
            .lock()
            .map_err(|_| Error::unavailable("HTTP response state unavailable"))?
            .take()
        {
            head.send(Ok((status, headers, streaming))).map_err(|_| {
                Error::new(
                    "CANCELED",
                    "HTTP consumer disconnected",
                    StatusCode::CONFLICT,
                )
            })?;
        }
        Ok(())
    }
    async fn emit(&self, value: &Value) -> Result<()> {
        if self.terminal.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::conflict("HTTP stream is already terminal"));
        }
        let sequence = unsigned(&value["sequence"])?;
        if sequence != *self.sequence.lock().map_err(|_| Error::denied())? + 1 {
            return Err(Error::conflict("HTTP stream sequence differs"));
        }
        let bytes = encode(value)?;
        self.send(bytes, value["terminal"] == true, sequence)
            .await?;
        *self.sequence.lock().map_err(|_| Error::denied())? = sequence;
        if value["terminal"] == true {
            self.terminal
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
    async fn send(&self, bytes: Vec<u8>, terminal: bool, sequence: u64) -> Result<()> {
        match tokio::time::timeout(
            Duration::from_secs(30),
            self.sender.send((bytes, terminal, sequence)),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Error::new(
                "CANCELED",
                "HTTP consumer disconnected",
                StatusCode::CONFLICT,
            )),
            Err(_) => {
                self.stalled
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Err(expired())
            }
        }
    }
    async fn complete_json(&self, _value: Value, response: plugin_http::transport::Response) {
        if self.begin(response.status, response.headers, false).is_ok() {
            let _ = self.send(response.bytes, true, 0).await;
        }
    }
    async fn terminal(&self, kind: &str, payload: Value) {
        let identity = self.identity.lock().ok().and_then(|i| i.clone());
        if let Some(identity) = identity {
            let sequence = self.sequence.lock().map(|s| *s + 1).unwrap_or(1);
            let value = json!({"call_id":identity.call,"sequence":sequence,"kind":kind,"payload":payload,"terminal":true});
            if self.stalled.load(std::sync::atomic::Ordering::SeqCst) {
                if let Ok(bytes) = encode(&value) {
                    let _ = self.sender.try_send((bytes, true, sequence));
                }
            } else {
                let _ = self.emit(&value).await;
            }
        }
    }
    async fn abandoned_before_admission(&self) {
        self.sender.closed().await;
        if self.identity.lock().map(|i| i.is_some()).unwrap_or(true) {
            std::future::pending::<()>().await;
        }
    }
    async fn fail(&self, error: Error) {
        if let Ok(mut head) = self.head.lock() {
            if let Some(head) = head.take() {
                let _ = head.send(Err(error));
                return;
            }
        }
        let (kind, payload) = terminal_error(&error);
        self.terminal(kind, payload).await;
    }
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    validate("StreamEvent", value)?;
    let raw = serde_json::to_string(value)?;
    let out = format!(
        "event: {}\nid: {}:{}\ndata: {}\n\n",
        string(value, "kind")?,
        string(value, "call_id")?,
        unsigned(&value["sequence"])?,
        raw
    )
    .into_bytes();
    if out.len() > 1048576 {
        return Err(plugin_http::too_large());
    }
    Ok(out)
}
fn pool() -> Arc<Semaphore> {
    static POOL: OnceLock<Arc<Semaphore>> = OnceLock::new();
    POOL.get_or_init(|| Arc::new(Semaphore::new(64))).clone()
}
fn retained_body(body: Body, permit: OwnedSemaphorePermit) -> Body {
    let mut source = body.into_data_stream();
    Body::from_stream(futures_util::stream::poll_fn(move |cx| {
        let _held = &permit;
        Pin::new(&mut source).poll_next(cx)
    }))
}
async fn delivery(
    app: &App,
    token: &str,
    peer: IpAddr,
    request: Uuid,
    identity: &Identity,
) -> Result<()> {
    crate::skill_streams::ensure_active(app)?;
    let remaining = (identity.deadline - chrono::Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return Err(expired());
    }
    let mut c = app.db.connect_scoped(remaining).await?;
    let tx = c.transaction().await?;
    let mut ctx = crate::host_calls::authenticate(&tx, app, token, peer, request).await?;
    ctx.browser_origin = identity.browser_origin.clone();
    let row = tx
        .query_one(
            "SELECT owner_id,credential_id,error FROM calls WHERE id=$1",
            &[&identity.call],
        )
        .await?;
    if row.get::<_, Uuid>("owner_id") != ctx.subject
        || row.get::<_, Option<Uuid>>("credential_id") != Some(ctx.credential)
    {
        return Err(Error::denied());
    }
    // A recorded cancellation is authoritative even if Controller has already
    // drained the physical instance; it never authorizes or delivers data.
    if row
        .get::<_, Option<Value>>("error")
        .is_some_and(|e| e["code"] == "CANCELED")
    {
        return Err(Error::new(
            "CANCELED",
            "HTTP call was canceled",
            StatusCode::CONFLICT,
        ));
    }
    check_skill_authority(&tx, &ctx, identity.call).await?;
    check_route_approval(&tx, app, identity.call).await?;
    tx.commit().await?;
    crate::skill_streams::ensure_active(app)
}
fn expired() -> Error {
    Error::new(
        "DEADLINE_EXCEEDED",
        "HTTP call deadline elapsed; inspect any admitted Call",
        StatusCode::GATEWAY_TIMEOUT,
    )
}

#[allow(clippy::too_many_arguments)]
async fn read_events(
    app: &App,
    call_source: CallSource<'_>,
    request: Uuid,
    call: Uuid,
    target: &Provider,
    response: reqwest::Response,
    output: Option<&Output>,
    stream: Option<(&crate::skill_streams::Output, &crate::skills::ResolvedSkill)>,
    head: (StatusCode, HeaderMap),
    deadline: chrono::DateTime<chrono::Utc>,
) -> Result<Value> {
    let mut pending_head = Some(head);
    let mut source = response.bytes_stream();
    let mut buffer = Vec::new();
    let mut sequence = 0;
    let mut completed = None;
    let maximum_frame = app.config.json_limit(1048576);
    while let Some(chunk) = source.next().await {
        let chunk = chunk.map_err(|error| {
            if error.is_timeout() {
                expired()
            } else {
                Error::unavailable("HTTP event stream ended early")
            }
        })?;
        if chunk.len() > maximum_frame {
            return Err(plugin_http::too_large());
        }
        buffer.extend_from_slice(&chunk);
        drop(chunk);
        loop {
            let split = buffer
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|i| (i, 2))
                .or_else(|| {
                    buffer
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|i| (i, 4))
                });
            let Some((end, separator)) = split else {
                break;
            };
            if end + separator > maximum_frame {
                return Err(plugin_http::too_large());
            }
            let bytes: Vec<_> = buffer.drain(..end + separator).collect();
            let frame = std::str::from_utf8(&bytes)
                .map_err(|_| Error::invalid("HTTP event stream is not UTF-8"))?
                .replace("\r\n", "\n");
            if frame.starts_with(':') {
                if frame.len() > 128 || !frame.trim_end().starts_with(": ping") {
                    return Err(Error::invalid("Unknown HTTP stream comment"));
                }
                continue;
            }
            if completed.is_some() {
                return Err(Error::conflict(
                    "HTTP event stream continued after terminal",
                ));
            }
            let mut fields = std::collections::BTreeMap::new();
            for line in frame.trim_end_matches('\n').split('\n') {
                let (key, value) = line
                    .split_once(':')
                    .ok_or_else(|| Error::invalid("Invalid SSE field"))?;
                if !["event", "id", "data"].contains(&key)
                    || fields
                        .insert(key, value.strip_prefix(' ').unwrap_or(value))
                        .is_some()
                {
                    return Err(Error::invalid("Duplicate or unknown SSE field"));
                }
            }
            if fields.len() != 3 {
                return Err(Error::invalid("SSE frame is incomplete"));
            }
            let value = strict_json(fields["data"].as_bytes(), maximum_frame)?;
            validate("StreamEvent", &value)?;
            target.operation()?.responses[&200]
                .schema
                .as_ref()
                .ok_or_else(Error::denied)?
                .check(&value)?;
            if value["call_id"] != call.to_string()
                || unsigned(&value["sequence"])? != sequence + 1
                || fields["id"] != format!("{call}:{}", sequence + 1)
                || fields["event"] != string(&value, "kind")?
                || (sequence == 0 && value["kind"] != "accepted")
                || (sequence > 0 && value["kind"] == "accepted")
            {
                return Err(Error::conflict("HTTP stream identity or sequence differs"));
            }
            sequence += 1;
            // Do not retain wire copies while awaiting authority/backpressure.
            drop(fields);
            drop(frame);
            drop(bytes);
            check_live_call_for_source(
                app,
                call_source,
                request,
                call,
                target.instance,
                target.generation,
                deadline,
            )
            .await?;
            // Do not commit SSE headers until a signed, authorized first
            // accepted frame is actually available. Earlier EOF/malformed
            // frames remain ordinary HTTP errors, never failed sequence1.
            if let Some((status, headers)) = pending_head.take() {
                if let Some(output) = output {
                    output.begin(status, headers, true)?;
                }
            }
            if value["terminal"] == true {
                if value["kind"] == "canceled" {
                    return Err(if value["payload"]["reason"] == "deadline" {
                        expired()
                    } else {
                        Error::new(
                            "CANCELED",
                            "HTTP plugin canceled the stream; physical outcome remains unknown",
                            StatusCode::CONFLICT,
                        )
                    });
                }
                if value["kind"] != "completed" {
                    return Err(Error::unavailable(
                        "HTTP plugin stream failed; inspect the fixed Call",
                    ));
                }
                completed = Some(value);
            } else if let Some((stream, skill)) = stream {
                let kind = match string(&value, "kind")? {
                    "accepted" => "accepted",
                    "item" => {
                        validate_business(
                            &skill.definition["stream_item_schema"],
                            &value["payload"],
                        )?;
                        "item"
                    }
                    _ => return Err(Error::conflict("Unexpected nonterminal HTTP event")),
                };
                stream.emit(kind, value["payload"].clone()).await?;
            } else if let Some(output) = output {
                output.emit(&value).await?;
            }
        }
        if buffer.len() > maximum_frame {
            return Err(plugin_http::too_large());
        }
    }
    if !buffer.is_empty() {
        return Err(Error::conflict(
            "HTTP stream ended with an incomplete frame",
        ));
    }
    completed.ok_or_else(|| Error::conflict("HTTP stream ended without a terminal"))
}

pub(crate) async fn check_route_approval(
    c: &(impl GenericClient + Sync),
    app: &App,
    call: Uuid,
) -> Result<()> {
    crate::dependencies::check_call(c, call).await?;
    let row=c.query_one("SELECT c.http_binding,n.manifest,d.id AS dependency_deployment FROM calls c JOIN instances i ON i.id=c.provider_instance_id JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id WHERE c.id=$1",&[&call]).await?;
    crate::dependencies::check_ready(c, app, row.get("dependency_deployment")).await?;
    if let Some(binding) = row.get::<_, Option<Value>>("http_binding") {
        crate::plugin_http_gateway::check_approval(
            c,
            app,
            id(&binding, "deployment_id")?,
            &row.get::<_, Value>("manifest"),
        )
        .await?;
    }
    Ok(())
}

fn error_frame(
    identity: &Mutex<Option<Identity>>,
    error: Error,
    sequence: u64,
) -> Result<(Vec<u8>, bool, u64)> {
    let identity = identity
        .lock()
        .map_err(|_| Error::denied())?
        .clone()
        .ok_or_else(Error::denied)?;
    let (kind, payload) = terminal_error(&error);
    Ok((
        encode(
            &json!({"call_id":identity.call,"sequence":sequence,"kind":kind,"payload":payload,"terminal":true}),
        )?,
        true,
        sequence,
    ))
}
fn terminal_error(error: &Error) -> (&'static str, Value) {
    match error.code {
        "CANCELED" => ("canceled", json!({"reason":"requested"})),
        "DEADLINE_EXCEEDED" => ("canceled", json!({"reason":"deadline"})),
        _ => ("failed", error.detail()),
    }
}

#[cfg(test)]
#[path = "broker_http_unit_tests.rs"]
mod tests;
