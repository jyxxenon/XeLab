//! Trusted HostService authority and private Broker admission handles.
use crate::host_blobs::{caps, saved};
use crate::{
    api::App,
    auth::{self, Context, Resource},
    contracts, db,
    error::{Error, Result},
    policy::{self, Policy},
    rpc,
};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use std::{net::IpAddr, sync::atomic::Ordering, time::Duration};
use tokio_postgres::GenericClient;
use uuid::Uuid;
#[derive(Clone, Copy)]
pub(crate) struct Workload {
    pub instance: Uuid,
    pub generation: i64,
}
pub(crate) struct Authority {
    pub ctx: Context,
    pub call: Uuid,
    pub deployment: Uuid,
    pub until_ms: i64,
}
pub(crate) async fn authority(
    c: &(impl GenericClient + Sync),
    app: &App,
    workload: Workload,
    context: &rpc::RpcContext,
    action: &str,
    resource: &Resource,
) -> Result<Authority> {
    let hash = app.auth.token_digest(&context.delegation_token);
    let authority = authority_digest(
        c,
        app,
        workload,
        context,
        &hash,
        0,
        &mut ProofCache::default(),
    )
    .await?;
    if !authority.ctx.proxy_allows(action, resource)
        || !auth::rules_allow(
            &policy::rules(
                authority
                    .ctx
                    .proxy_paths
                    .as_ref()
                    .ok_or_else(Error::denied)?,
            ),
            action,
            resource,
            authority.ctx.peer,
        )
    {
        return Err(Error::denied());
    }
    Ok(authority)
}
fn authority_digest<'a>(
    c: &'a (impl GenericClient + Sync),
    app: &'a App,
    workload: Workload,
    context: &'a rpc::RpcContext,
    hash: &'a [u8],
    depth: usize,
    cache: &'a mut ProofCache,
) -> BoxFuture<'a, Result<Authority>> {
    Box::pin(async move {
        let timing = std::time::Instant::now();
        if depth >= 16 {
            return Err(Error::conflict("HostService delegation depth limit"));
        }
        if app.leader.is_closed()
            || app.shutdown.load(Ordering::SeqCst)
            || !app.ready.load(Ordering::SeqCst)
        {
            return Err(Error::unavailable("Kernel is not ready"));
        }
        db::call_lock(c).await?;
        crate::dependencies::dependency_lock(c).await?;
        stage(timing, "locks");
        let request: Uuid = context
            .request_id
            .parse()
            .map_err(|_| Error::invalid("RPC request_id must be a UUID"))?;
        if context.deadline_unix_ms <= chrono::Utc::now().timestamp_millis() {
            return Err(Error::new(
                "DEADLINE_EXCEEDED",
                "Blob deadline exceeded",
                axum::http::StatusCode::GATEWAY_TIMEOUT,
            ));
        }
        if !context.actor_instance_id.is_empty()
            && context.actor_instance_id != workload.instance.to_string()
        {
            return Err(Error::denied());
        }
        // Match terminal-call and controller row ordering: call, deployment,
        // instance, then delegation records. A reverse order can deadlock against
        // completion (call -> delegation) or health publication (deployment -> instance).
        let target=c.query_opt("SELECT r.call_id,i.deployment_id FROM rpc_delegations r JOIN instances i ON i.id=r.instance_id WHERE r.hmac_key_id=$1 AND r.verification_digest=$2 AND r.instance_id=$3",&[&app.auth.key_id.as_str(),&hash,&workload.instance]).await?.ok_or_else(Error::denied)?;
        c.query_one(
            "SELECT id FROM calls WHERE id=$1 FOR SHARE",
            &[&target.get::<_, Uuid>("call_id")],
        )
        .await?;
        c.query_one(
            "SELECT id FROM deployments WHERE id=$1 FOR SHARE",
            &[&target.get::<_, Uuid>("deployment_id")],
        )
        .await?;
        c.query_one(
            "SELECT id FROM instances WHERE id=$1 FOR SHARE",
            &[&workload.instance],
        )
        .await?;
        let row=c.query_opt("SELECT LEAST(r.expires_at,e.expires_at,c.deadline_at) AS until,r.call_id,r.subject_id,r.issuer_credential_id,e.maximum_rules,c.contract,i.deployment_id,t.manifest,x.source_paths,x.proxy_source_paths,x.proxy_ceilings,x.read_blob_ids,x.browser_origin,host(x.peer) AS peer FROM rpc_delegations r JOIN execution_delegations e ON e.id=r.execution_delegation_id JOIN calls c ON c.id=r.call_id JOIN host_rpc_contexts x ON x.call_id=c.id JOIN instances i ON i.id=r.instance_id JOIN deployments d ON d.id=i.deployment_id JOIN installations t ON t.id=d.installation_id JOIN publishers p ON p.id=t.publisher_id WHERE r.hmac_key_id=$1 AND r.verification_digest=$2 AND r.instance_id=$3 AND r.generation=$4 AND r.status='active' AND r.expires_at>now() AND e.status='active' AND e.expires_at>now() AND e.subject_id=r.subject_id AND e.issuer_credential_id=r.issuer_credential_id AND c.state='running' AND c.deadline_at>now() AND c.provider_instance_id=i.id AND c.owner_id=r.subject_id AND c.credential_id=r.issuer_credential_id AND c.delegation_id=e.id AND i.generation=r.generation AND i.runtime_id=i.id::text AND i.phase IN ('ready','degraded') AND d.spec->>'enabled'='true' AND d.archived_at IS NULL AND t.state='installed' AND p.status='trusted' FOR SHARE OF r,e,t,p",&[&app.auth.key_id.as_str(),&hash,&workload.instance,&workload.generation]).await?.ok_or_else(Error::denied)?;
        let peer: IpAddr = row
            .get::<_, String>("peer")
            .parse()
            .map_err(|_| Error::denied())?;
        let mut ctx = app
            .auth
            .resume(c, row.get("issuer_credential_id"), peer, request)
            .await?;
        ctx.browser_origin = row.get("browser_origin");
        if ctx.subject != row.get::<_, Uuid>("subject_id")
            || (!context.subject_id.is_empty() && context.subject_id != ctx.subject.to_string())
        {
            return Err(Error::denied());
        }
        stage(timing, "resume");
        let (target_action, target) = crate::broker::business_target(c, row.get("call_id")).await?;
        let (_, business_live) = cache
            .revalidate(c, &ctx, Some(&target), &saved(row.get("source_paths"))?)
            .await?;
        stage(timing, "business_sources");
        let rules = policy::rules(&business_live);
        let mut business_required = vec![(target_action.clone(), target.clone())];
        let maximum: Value = row.get("maximum_rules");
        let blobs: Vec<Uuid> =
            serde_json::from_value(row.get("read_blob_ids")).map_err(|_| Error::denied())?;
        if blobs.len() > 256 {
            return Err(Error::denied());
        }
        for blob in blobs {
            let owner: Uuid = c
                .query_opt(
                    &format!(
                        "SELECT owner_id FROM blobs WHERE id=$1 AND {}",
                        crate::blobs::LIVE
                    ),
                    &[&blob],
                )
                .await?
                .ok_or_else(Error::denied)?
                .get(0);
            let resource = Resource::new("blob", blob, Some(owner));
            if !auth::rules_allow(&rules, "blob.read", &resource, peer)
                || !auth::rules_allow(&maximum, "blob.read", &resource, peer)
            {
                return Err(Error::denied());
            }
            business_required.push(("blob.read".to_owned(), resource));
        }

        crate::broker::check_skill_binding(c, &ctx, row.get("call_id")).await?;
        if let Some(skill) = c
        .query_opt(
            "SELECT s.id,s.created_by FROM calls c JOIN skills s ON s.id=c.skill_id WHERE c.id=$1",
            &[&row.get::<_, Uuid>("call_id")],
        )
        .await?
    {
        let resource = Resource::new(
            "skill",
            skill.get::<_, Uuid>("id"),
            Some(skill.get("created_by")),
        );
        if !auth::rules_allow(&rules, "skill.invoke", &resource, peer)
            || !auth::rules_allow(&maximum, "skill.invoke", &resource, peer)
        {
            return Err(Error::denied());
        }
        business_required.push(("skill.invoke".to_owned(), resource));
    }
        if !auth::rules_allow(&rules, &target_action, &target, peer)
            || !auth::rules_allow(&maximum, &target_action, &target, peer)
        {
            return Err(Error::denied());
        }
        stage(timing, "business_binding");
        let (_, mut live) = cache
            .revalidate(c, &ctx, None, &saved(row.get("proxy_source_paths"))?)
            .await?;
        stage(timing, "proxy_sources");
        let mut ceilings: Vec<Value> =
            serde_json::from_value(row.get("proxy_ceilings")).map_err(|_| Error::denied())?;
        crate::broker::check_http_approval(c, app, row.get("call_id")).await?;
        crate::dependencies::check_ready(c, app, row.get("deployment_id")).await?;
        crate::dependencies::check_call(c, row.get("call_id")).await?;
        let mut until_ms = row
            .get::<_, chrono::DateTime<chrono::Utc>>("until")
            .timestamp_millis()
            .min(context.deadline_unix_ms);
        if until_ms <= chrono::Utc::now().timestamp_millis() {
            return Err(Error::new(
                "DEADLINE_EXCEEDED",
                "Call deadline exceeded",
                axum::http::StatusCode::GATEWAY_TIMEOUT,
            ));
        }
        if let Some(parent)=c.query_opt("SELECT t.instance_id,t.generation,t.delegation_digest,t.rpc_context,t.bounds,t.expires_at,t.dependency_binding_id,t.expected_contract,t.provider_deployment_id,t.ceilings FROM host_child_calls l JOIN host_call_tickets t ON t.id=l.ticket_id WHERE l.child_call_id=$1",&[&row.get::<_,Uuid>("call_id")]).await? {
        let expiry=parent.get::<_,chrono::DateTime<chrono::Utc>>("expires_at").timestamp_millis();
        if expiry<=chrono::Utc::now().timestamp_millis(){return Err(Error::denied());}
        let original:Value=parent.get("rpc_context");
        let ancestor=rpc::RpcContext{request_id:context.request_id.clone(),deadline_unix_ms:original["deadline"].as_i64().ok_or_else(Error::denied)?,..Default::default()};
        let ancestor=Box::pin(authority_digest(c,app,Workload{instance:parent.get("instance_id"),generation:parent.get("generation")},&ancestor,&parent.get::<_,Vec<u8>>("delegation_digest"),depth+1,cache)).await?;
        if let Some(binding)=parent.get::<_,Option<Uuid>>("dependency_binding_id"){
            let provider=crate::dependencies::check_host(c,&ancestor.ctx,ancestor.deployment,ancestor.call,binding,&parent.get::<_,Option<Value>>("expected_contract").ok_or_else(Error::denied)?).await?;
            if Some(provider)!=parent.get::<_,Option<Uuid>>("provider_deployment_id"){return Err(Error::denied());}
        }
        if !proof_allows(&ancestor.ctx,&target_action,&target){return Err(Error::denied());}
        if let Some(skill)=c.query_opt("SELECT s.id,s.created_by FROM calls c JOIN skills s ON s.id=c.skill_id WHERE c.id=$1",&[&row.get::<_,Uuid>("call_id")]).await?{
            if !proof_allows(&ancestor.ctx,"skill.invoke",&Resource::new("skill",skill.get::<_,Uuid>("id"),Some(skill.get("created_by")))){return Err(Error::denied());}
        }
        let inputs:Vec<Uuid>=serde_json::from_value(row.get("read_blob_ids")).map_err(|_|Error::denied())?;
        for blob in inputs{
            let owner:Uuid=c.query_one("SELECT owner_id FROM blobs WHERE id=$1",&[&blob]).await?.get(0);
            if !proof_allows(&ancestor.ctx,"blob.read",&Resource::new("blob",blob,Some(owner))){return Err(Error::denied());}
        }
        until_ms=until_ms.min(ancestor.until_ms).min(expiry);
        let narrowing=Policy::for_context(c,&ctx);
        live=narrowing.intersection(&live,ancestor.ctx.proxy_paths.as_ref().ok_or_else(Error::denied)?).await?;
        live=narrowing.intersection(&live,&caps(&parent.get::<_,Value>("bounds"))?).await?;
        extend_ceilings(&mut ceilings,&ancestor.ctx.proxy_ceilings)?;
        extend_ceilings(&mut ceilings,&serde_json::from_value::<Vec<Value>>(parent.get("ceilings")).map_err(|_|Error::denied())?)?;
    }
        stage(timing, "ancestors");
        let (approval, approver, approved_peer) = crate::host_blobs::approval_sources_current(
            c,
            app,
            row.get("deployment_id"),
            &row.get("manifest"),
            Some(cache),
        )
        .await?;
        extend_ceilings(
            &mut ceilings,
            &[
                maximum,
                approval["rules"].clone(),
                scopes_at_peer(&approver, approved_peer),
            ],
        )?;
        auth::validate_sources(c, Some(ctx.credential), Some(ctx.subject), ctx.peer).await?;
        // Recursive ancestors and approval walks can cross a source's clock
        // boundary even while authorization mutations are fenced. Business-only
        // sources need this final check independently of the proxy action set.
        let business_live = Policy::for_context(c, &ctx)
            .live_proxy_sources(business_live)
            .await?;
        let business_rules = policy::rules(&business_live);
        if business_required
            .iter()
            .any(|(action, resource)| !auth::rules_allow(&business_rules, action, resource, peer))
        {
            return Err(Error::denied());
        }
        live = Policy::for_context(c, &ctx)
            .live_proxy_sources(live)
            .await?;
        if until_ms <= chrono::Utc::now().timestamp_millis() {
            return Err(Error::new(
                "DEADLINE_EXCEEDED",
                "Ancestor call deadline elapsed",
                axum::http::StatusCode::GATEWAY_TIMEOUT,
            ));
        }
        stage(timing, "approval");
        ctx.proxy_ceilings = ceilings;
        ctx.proxy_paths = Some(live);
        ctx.bind_proxy_proof(c).await?;
        Ok(Authority {
            ctx,
            deployment: row.get("deployment_id"),
            call: row.get("call_id"),
            until_ms,
        })
    })
}

/// Ordinary HTTP never enters this path: the private handle exists only inside
/// the authenticated HostService adapter and is never returned to a workload.
pub(crate) fn authenticate<'a>(
    c: &'a (impl GenericClient + Sync),
    app: &'a App,
    token: &'a str,
    peer: IpAddr,
    request: Uuid,
) -> BoxFuture<'a, Result<Context>> {
    Box::pin(async move {
        if !token.starts_with("host:") {
            return app.auth.authenticate(c, token, peer, request).await;
        }
        let hash = app.auth.token_digest(token);
        let row = c
            .query_opt(
                "SELECT * FROM host_call_tickets WHERE verification_digest=$1 AND expires_at>now()",
                &[&hash],
            )
            .await?
            .ok_or_else(Error::denied)?;
        let original: Value = row.get("rpc_context");
        let context = rpc::RpcContext {
            request_id: request.to_string(),
            deadline_unix_ms: original["deadline"].as_i64().ok_or_else(Error::denied)?,
            idempotency_key: String::new(),
            delegation_token: String::new(),
            subject_id: String::new(),
            actor_instance_id: String::new(),
        };
        let workload = Workload {
            instance: row.get("instance_id"),
            generation: row.get("generation"),
        };
        let mut authority = authority_digest(
            c,
            app,
            workload,
            &context,
            &row.get::<_, Vec<u8>>("delegation_digest"),
            0,
            &mut ProofCache::default(),
        )
        .await?;
        if authority.call != row.get::<_, Uuid>("parent_call_id") || authority.ctx.peer != peer {
            return Err(Error::denied());
        }
        if let Some(binding) = row.get::<_, Option<Uuid>>("dependency_binding_id") {
            let provider = crate::dependencies::check_host(
                c,
                &authority.ctx,
                authority.deployment,
                authority.call,
                binding,
                &row.get::<_, Option<Value>>("expected_contract")
                    .ok_or_else(Error::denied)?,
            )
            .await?;
            if Some(provider) != row.get::<_, Option<Uuid>>("provider_deployment_id") {
                return Err(Error::denied());
            }
        }
        let bounds: Value = row.get("bounds");
        let p = Policy::for_context(c, &authority.ctx);
        let paths = p
            .intersection(
                authority
                    .ctx
                    .proxy_paths
                    .as_ref()
                    .ok_or_else(Error::denied)?,
                &caps(&bounds)?,
            )
            .await?;
        extend_ceilings(
            &mut authority.ctx.proxy_ceilings,
            &serde_json::from_value::<Vec<Value>>(row.get("ceilings"))
                .map_err(|_| Error::denied())?,
        )?;
        authority.ctx.proxy_paths = Some(paths);
        Ok(authority.ctx)
    })
}

/// Persist ancestry in the same transaction as the child ledger and quota
/// reservations. A recursively invoked instance cannot reenter its own chain.
pub(crate) async fn bind_child(
    c: &(impl GenericClient + Sync),
    app: &App,
    token: &str,
    call: Uuid,
    instance: Uuid,
) -> Result<()> {
    if !token.starts_with("host:") {
        return Ok(());
    }
    let hash = app.auth.token_digest(token);
    let row=c.query_opt("SELECT id,parent_call_id,provider_deployment_id,expected_skill,expected_contract,input_digest FROM host_call_tickets WHERE verification_digest=$1 AND expires_at>now() FOR SHARE",&[&hash]).await?.ok_or_else(Error::denied)?;
    let actual = c
        .query_one(
            "SELECT contract,skill_id,input_digest FROM calls WHERE id=$1",
            &[&call],
        )
        .await?;
    if row.get::<_, Option<Uuid>>("expected_skill") != actual.get::<_, Option<Uuid>>("skill_id")
        || row.get::<_, String>("input_digest") != actual.get::<_, String>("input_digest")
        || row
            .get::<_, Option<Value>>("expected_contract")
            .is_some_and(|contract| contract != actual.get::<_, Value>("contract"))
    {
        return Err(Error::denied());
    }
    let parent: Uuid = row.get("parent_call_id");
    check_child_ancestry(c, parent, instance).await?;
    if let Some(provider) = row.get::<_, Option<Uuid>>("provider_deployment_id") {
        let actual: Uuid = c
            .query_one(
                "SELECT deployment_id FROM instances WHERE id=$1",
                &[&instance],
            )
            .await?
            .get(0);
        if provider != actual {
            return Err(Error::conflict("Fixed HostService binding changed"));
        }
    }
    c.execute(
        "INSERT INTO host_child_calls(child_call_id,parent_call_id,ticket_id) VALUES($1,$2,$3)",
        &[&call, &parent, &row.get::<_, Uuid>("id")],
    )
    .await?;
    Ok(())
}

pub(crate) async fn check_queued_child(
    c: &(impl GenericClient + Sync),
    app: &App,
    token: &str,
    instance: Uuid,
) -> Result<()> {
    if !token.starts_with("host:") {
        return Ok(());
    }
    let parent = c.query_opt(
        "SELECT parent_call_id FROM host_call_tickets WHERE verification_digest=$1 AND expires_at>clock_timestamp()",
        &[&app.auth.token_digest(token)],
    ).await?.ok_or_else(Error::denied)?.get(0);
    check_child_ancestry(c, parent, instance).await
}

async fn check_child_ancestry(
    c: &(impl GenericClient + Sync),
    parent: Uuid,
    instance: Uuid,
) -> Result<()> {
    let ancestors=c.query("WITH RECURSIVE chain(id,depth) AS (SELECT $1::uuid,0 UNION ALL SELECT l.parent_call_id,c.depth+1 FROM chain c JOIN host_child_calls l ON l.child_call_id=c.id WHERE c.depth<16) SELECT c.provider_instance_id FROM chain JOIN calls c ON c.id=chain.id",&[&parent]).await?;
    if ancestors.len() >= 16
        || ancestors
            .iter()
            .any(|r| r.get::<_, Option<Uuid>>(0) == Some(instance))
    {
        return Err(Error::conflict(
            "HostService child call cycle or depth limit",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn ticket(
    c: &(impl GenericClient + Sync),
    app: &App,
    workload: Workload,
    context: &rpc::RpcContext,
    authority: &Authority,
    bounds: Value,
    provider: Option<Uuid>,
    fingerprint: &str,
    skill: Option<Uuid>,
    expected_contract: Option<Value>,
    input_digest: &str,
    requested_call: Option<Uuid>,
    invocation: &mut Value,
    binding_id: Option<Uuid>,
) -> Result<String> {
    if context.idempotency_key.is_empty()
        || context.idempotency_key.len() > 128
        || !context
            .idempotency_key
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(Error::invalid("Stable child idempotency key is required"));
    }
    let scope = format!("host-child:{}:{}", authority.call, context.idempotency_key);
    c.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        &[&scope],
    )
    .await?;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let encode = |id: Uuid| {
        format!(
            "host:{}:{}",
            id,
            URL_SAFE_NO_PAD.encode(app.auth.token_digest(&format!("host-call-ticket:{id}")))
        )
    };
    if let Some(row)=c.query_opt("SELECT id,fingerprint,invocation FROM host_call_tickets WHERE parent_call_id=$1 AND idempotency_key=$2",&[&authority.call,&context.idempotency_key]).await?{
        if row.get::<_,String>("fingerprint")!=fingerprint{return Err(Error::conflict("Child idempotency fingerprint differs"));}
        let original:Value=row.get("invocation");
        invocation["timeout_ms"]=original["timeout_ms"].clone();
        return Ok(encode(row.get("id")));
    }
    let count: i64 = c
        .query_one(
            "SELECT count(*) FROM host_call_tickets WHERE parent_call_id=$1",
            &[&authority.call],
        )
        .await?
        .get(0);
    if count >= 256 {
        return Err(Error::exhausted());
    }
    if serde_json::to_vec(&bounds)?.len() > 1048576 {
        return Err(Error::exhausted());
    }
    let id = Uuid::new_v4();
    let token = encode(id);
    let expires =
        chrono::DateTime::from_timestamp_millis(authority.until_ms.min(context.deadline_unix_ms))
            .ok_or_else(Error::denied)?;
    c.execute("INSERT INTO host_call_tickets(id,parent_call_id,instance_id,generation,delegation_digest,verification_digest,rpc_context,bounds,provider_deployment_id,idempotency_key,fingerprint,expires_at,expected_skill,expected_contract,input_digest,requested_call_id,invocation,dependency_binding_id,ceilings) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",&[&id,&authority.call,&workload.instance,&workload.generation,&app.auth.token_digest(&context.delegation_token),&app.auth.token_digest(&token),&json!({"deadline":context.deadline_unix_ms}),&bounds,&provider,&context.idempotency_key,&fingerprint,&expires,&skill,&expected_contract,&input_digest,&requested_call,&json!({"timeout_ms":invocation["timeout_ms"]}),&binding_id,&json!(authority.ctx.proxy_ceilings)]).await?;
    Ok(token)
}
pub(crate) async fn new_call(
    c: &(impl GenericClient + Sync),
    app: &App,
    token: &str,
) -> Result<Uuid> {
    if !token.starts_with("host:") {
        return Ok(Uuid::new_v4());
    }
    let row = c
        .query_one(
            "SELECT requested_call_id FROM host_call_tickets WHERE verification_digest=$1",
            &[&app.auth.token_digest(token)],
        )
        .await?;
    let call = row.get::<_, Option<Uuid>>(0).unwrap_or_else(Uuid::new_v4);
    if c.query_opt("SELECT id FROM calls WHERE id=$1", &[&call])
        .await?
        .is_some()
    {
        return Err(Error::conflict("Child call ID was already used"));
    }
    Ok(call)
}
fn context(context: Option<&rpc::RpcContext>) -> Result<&rpc::RpcContext> {
    let context = context.ok_or_else(|| Error::invalid("RPC context is required"))?;
    if context.deadline_unix_ms <= chrono::Utc::now().timestamp_millis() {
        return Err(Error::new(
            "DEADLINE_EXCEEDED",
            "HostService deadline elapsed",
            axum::http::StatusCode::GATEWAY_TIMEOUT,
        ));
    }
    Ok(context)
}
fn uuid(value: &str) -> Result<Uuid> {
    let id: Uuid = value
        .parse()
        .map_err(|_| Error::invalid("Canonical UUID is required"))?;
    if id.to_string() != value {
        return Err(Error::invalid("Canonical UUID is required"));
    }
    Ok(id)
}
fn contract(value: &rpc::ContractRef) -> Value {
    json!({"name":value.name,"version":value.version,"schema_digest":value.schema_digest})
}
fn as_contract(value: &Value) -> Result<rpc::ContractRef> {
    Ok(rpc::ContractRef {
        name: contracts::string(value, "name")?.into(),
        version: contracts::string(value, "version")?.into(),
        schema_digest: contracts::string(value, "schema_digest")?.into(),
    })
}
fn call_key(parent: Uuid, key: &str) -> String {
    contracts::digest(format!("host-child:{parent}:{key}").as_bytes())
}
fn reasons(value: &Value) -> Vec<String> {
    value["reason_codes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}
async fn target(c: &(impl GenericClient + Sync), skill: Uuid) -> Result<(Value, Resource, String)> {
    let mut value = crate::skills::value(c, skill).await?;
    let definition = &value["definition"];
    if definition["target"]["kind"] == "capability" {
        let target = &definition["target"]["contract"];
        return Ok((
            value.clone(),
            Resource::new(
                "capability",
                format!(
                    "{}@{}",
                    contracts::string(target, "name")?,
                    contracts::string(target, "version")?
                ),
                None,
            ),
            "capability.invoke".into(),
        ));
    }
    if definition["target"]["kind"] != "http" {
        return Err(Error::invalid("Unsupported HostService Skill target"));
    }
    let installation = contracts::id(&value, "installation_id")?;
    let registry = crate::http_contracts::load(c, installation).await?;
    let op = registry.bind_skill(definition)?;
    let eligible=c.query("SELECT d.owner_id,d.id FROM instances i JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id JOIN publishers p ON p.id=n.publisher_id WHERE n.id=$1 AND n.state='installed' AND p.status='trusted' AND i.phase='ready' AND i.generation=d.observed_generation AND d.phase='ready' AND i.health='alive' AND i.last_heartbeat_at>now()-interval '1 millisecond'*((n.manifest->'health'->>'interval_ms')::bigint*(n.manifest->'health'->>'failure_threshold')::bigint+(n.manifest->'health'->>'timeout_ms')::bigint) AND d.spec->>'enabled'='true' AND d.archived_at IS NULL AND d.approval ? 'rules' ORDER BY i.id",&[&installation]).await?;
    let owner = if eligible.len() == 1 {
        Some(eligible[0].get::<_, Uuid>("owner_id"))
    } else {
        None
    };
    let plugin = contracts::string(&definition["target"], "plugin_id")?.to_owned();
    if eligible.len() != 1 {
        value["availability"] = json!("unavailable");
        value["reason_codes"] = json!([if eligible.is_empty() {
            "PROVIDER_UNAVAILABLE"
        } else {
            "PROVIDER_AMBIGUOUS"
        }]);
    } else {
        value["host_provider_deployment_id"] = json!(eligible[0].get::<_, Uuid>("id"));
    }
    Ok((
        value.clone(),
        Resource::new("plugin", plugin, owner),
        op.route.action.clone(),
    ))
}
pub(crate) async fn resolve_skill(
    app: &App,
    workload: Workload,
    request: rpc::ResolveSkillRequest,
) -> Result<rpc::ResolveSkillResponse> {
    let context = context(request.context.as_ref())?;
    let skill = uuid(&request.skill_id)?;
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    db::call_lock(&tx).await?;
    crate::dependencies::dependency_lock(&tx).await?;
    let value = crate::skills::value(&tx, skill).await?;
    let owner: Uuid = tx
        .query_one("SELECT created_by FROM skills WHERE id=$1", &[&skill])
        .await?
        .get(0);
    authority(
        &tx,
        app,
        workload,
        context,
        "skill.read",
        &Resource::new("skill", skill, Some(owner)),
    )
    .await?;
    if value["availability"] == "disabled" {
        return Err(Error::unavailable("Skill is disabled or archived"));
    }
    let bytes = serde_json::to_vec(&value["definition"])?;
    if bytes.len() > 1048576 {
        return Err(Error::invalid("Skill definition exceeds 1 MiB"));
    }
    let result = rpc::ResolveSkillResponse {
        skill_id: skill.to_string(),
        definition_digest: contracts::string(&value, "definition_digest")?.into(),
        definition_json: bytes,
        ready: value["availability"] == "ready",
        reason_codes: reasons(&value),
    };
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn check_skill_access(
    app: &App,
    workload: Workload,
    request: rpc::CheckSkillAccessRequest,
) -> Result<rpc::CheckSkillAccessResponse> {
    let context = context(request.context.as_ref())?;
    let skill = uuid(&request.skill_id)?;
    let hash = &request.expected_definition_digest;
    if hash.len() != 71
        || !hash.starts_with("sha256:")
        || !hash[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::invalid("Exact Skill definition digest is required"));
    }
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    db::call_lock(&tx).await?;
    crate::dependencies::dependency_lock(&tx).await?;
    let (value, resource, action) = target(&tx, skill).await?;
    let owner: Uuid = tx
        .query_one("SELECT created_by FROM skills WHERE id=$1", &[&skill])
        .await?
        .get(0);
    let base = authority(
        &tx,
        app,
        workload,
        context,
        "skill.invoke",
        &Resource::new("skill", skill, Some(owner)),
    )
    .await?;
    if !base.ctx.proxy_allows(&action, &resource)
        || !auth::rules_allow(
            &policy::rules(base.ctx.proxy_paths.as_ref().ok_or_else(Error::denied)?),
            &action,
            &resource,
            base.ctx.peer,
        )
    {
        return Err(Error::denied());
    }
    if value["definition_digest"] != request.expected_definition_digest {
        return Err(Error::new(
            "CONTRACT_CONFLICT",
            "Fixed Skill definition digest differs",
            axum::http::StatusCode::CONFLICT,
        ));
    }
    let result = rpc::CheckSkillAccessResponse {
        skill_id: skill.to_string(),
        definition_digest: request.expected_definition_digest,
        ready: value["availability"] == "ready",
        reason_codes: reasons(&value),
    };
    tx.commit().await?;
    Ok(result)
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Cursor {
    subject: Uuid,
    credential: Uuid,
    plugins: Vec<String>,
    names: Vec<String>,
    watermark: String,
    offset: usize,
    expires: i64,
}
pub(crate) async fn list_skill_candidates(
    app: &App,
    workload: Workload,
    request: rpc::ListSkillCandidatesRequest,
) -> Result<rpc::ListSkillCandidatesResponse> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    if request.cursor.len() > 8192 {
        return Err(Error::invalid("Candidate cursor exceeds bound"));
    }
    let context = context(request.context.as_ref())?;
    for values in [&request.plugin_ids, &request.capability_names] {
        if values.is_empty()
            || values.len() > 8
            || values.iter().any(|v| v.is_empty() || v.len() > 200)
            || values
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != values.len()
        {
            return Err(Error::invalid(
                "Exact unique plugin and capability filters (1..8) are required",
            ));
        }
    }
    let size = if request.page_size == 0 {
        50
    } else {
        request.page_size
    };
    if size > 200 {
        return Err(Error::invalid("Candidate page size exceeds 200"));
    }
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    let hash = app.auth.token_digest(&context.delegation_token);
    let mut cache = ProofCache::default();
    let base = authority_digest(&tx, app, workload, context, &hash, 0, &mut cache).await?;
    let rows=tx.query("SELECT s.id,s.definition_digest,s.installation_id,s.created_by,n.plugin_id,s.revision,n.state,p.status FROM skills s JOIN installations n ON n.id=s.installation_id JOIN publishers p ON p.id=n.publisher_id WHERE n.plugin_id=ANY($1) AND s.definition->'target'->>'kind'='capability' AND s.definition->'target'->'contract'->>'name'=ANY($2) AND s.archived_at IS NULL ORDER BY n.plugin_id,s.definition->>'name',s.definition->>'version',s.id LIMIT 10001",&[&request.plugin_ids,&request.capability_names]).await?;
    if rows.len() > 10000 {
        return Err(Error::exhausted());
    }
    let water: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!([
                r.get::<_, Uuid>("id"),
                r.get::<_, i64>("revision"),
                r.get::<_, String>("state"),
                r.get::<_, String>("status"),
                r.get::<_, String>("definition_digest")
            ])
        })
        .collect();
    let watermark = contracts::digest(&serde_json::to_vec(&water)?);
    let mut cursor = Cursor {
        subject: base.ctx.subject,
        credential: base.ctx.credential,
        plugins: request.plugin_ids.clone(),
        names: request.capability_names.clone(),
        watermark: watermark.clone(),
        offset: 0,
        expires: chrono::Utc::now().timestamp() + 900,
    };
    if !request.cursor.is_empty() {
        let (raw, signature) = request
            .cursor
            .split_once('.')
            .ok_or_else(|| Error::invalid("Invalid candidate cursor"))?;
        if URL_SAFE_NO_PAD.encode(app.auth.token_digest(raw)) != signature {
            return Err(Error::invalid("Invalid candidate cursor"));
        }
        let previous: Cursor = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|_| Error::invalid("Invalid candidate cursor"))?,
        )
        .map_err(|_| Error::invalid("Invalid candidate cursor"))?;
        if previous.subject != cursor.subject
            || previous.credential != cursor.credential
            || previous.plugins != cursor.plugins
            || previous.names != cursor.names
            || previous.watermark != watermark
            || previous.expires <= chrono::Utc::now().timestamp()
        {
            return Err(Error::conflict("Candidate cursor state changed"));
        }
        cursor = previous;
    }
    let mut items = Vec::new();
    let mut returned_resources = Vec::new();
    for row in rows.iter().skip(cursor.offset) {
        cursor.offset += 1;
        let skill: Uuid = row.get("id");
        let owner: Uuid = row.get("created_by");
        if !base
            .ctx
            .proxy_allows("skill.read", &Resource::new("skill", skill, Some(owner)))
            || !auth::rules_allow(
                &policy::rules(base.ctx.proxy_paths.as_ref().ok_or_else(Error::denied)?),
                "skill.read",
                &Resource::new("skill", skill, Some(owner)),
                base.ctx.peer,
            )
        {
            continue;
        }
        let value = crate::skills::value(&tx, skill).await?;
        if value["availability"] == "disabled"
            || row.get::<_, String>("state") != "installed"
            || row.get::<_, String>("status") != "trusted"
        {
            continue;
        }
        let definition = &value["definition"];
        returned_resources.push(Resource::new("skill", skill, Some(owner)));
        items.push(rpc::SkillCandidate {
            skill_id: skill.to_string(),
            name: contracts::string(definition, "name")?.into(),
            version: contracts::string(definition, "version")?.into(),
            definition_digest: row.get("definition_digest"),
            installation_id: row.get::<_, Uuid>("installation_id").to_string(),
            plugin_id: row.get("plugin_id"),
            target_contract: Some(as_contract(&definition["target"]["contract"])?),
            ready: value["availability"] == "ready",
            reason_codes: reasons(&value),
        });
        if items.len() >= size as usize {
            break;
        }
    }
    let next_cursor = if cursor.offset < rows.len() {
        let raw = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor)?);
        format!(
            "{}.{}",
            raw,
            URL_SAFE_NO_PAD.encode(app.auth.token_digest(&raw))
        )
    } else {
        String::new()
    };
    // Catalog/value queries can wait past a parent or source clock boundary
    // while authorization mutations remain fenced. Rebuild current authority
    // in the same transaction and require every returned object's original
    // skill.read proof and independent ceilings immediately before delivery.
    let current = authority_digest(&tx, app, workload, context, &hash, 0, &mut cache).await?;
    if returned_resources
        .iter()
        .any(|resource| !proof_allows(&current.ctx, "skill.read", resource))
    {
        return Err(Error::denied());
    }
    tx.commit().await?;
    Ok(rpc::ListSkillCandidatesResponse { items, next_cursor })
}
pub(crate) async fn resolve(
    app: &App,
    workload: Workload,
    request: rpc::ResolveRequest,
) -> Result<rpc::ResolveResponse> {
    let context = context(request.context.as_ref())?;
    let contract = contract(
        request
            .contract
            .as_ref()
            .ok_or_else(|| Error::invalid("Exact contract is required"))?,
    );
    contracts::validate("ContractRef", &contract)?;
    let resource = Resource::new(
        "capability",
        format!(
            "{}@{}",
            contracts::string(&contract, "name")?,
            contracts::string(&contract, "version")?
        ),
        None,
    );
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    let hash = app.auth.token_digest(&context.delegation_token);
    let mut cache = ProofCache::default();
    let auth = authority_digest(&tx, app, workload, context, &hash, 0, &mut cache).await?;
    if !proof_allows(&auth.ctx, "capability.discover", &resource) {
        return Err(Error::denied());
    }
    let binding = crate::dependencies::resolve_host(
        &tx,
        &auth.ctx,
        auth.deployment,
        auth.call,
        &request.binding_scope_id,
        &contract,
    )
    .await?;
    let result = rpc::ResolveResponse {
        binding_id: contracts::string(&binding, "binding_id")?.into(),
        provider_deployment_id: contracts::string(&binding, "provider_deployment_id")?.into(),
        contract: request.contract,
        expires_unix_ms: binding["expires_unix_ms"].as_i64().unwrap_or(auth.until_ms),
    };
    // Request binding creation can wait after its original authorization. Keep
    // the new binding and its opaque handle private until the actual parent,
    // original sources and discovery ceilings are all still current.
    let current = authority_digest(&tx, app, workload, context, &hash, 0, &mut cache).await?;
    if !proof_allows(&current.ctx, "capability.discover", &resource) {
        return Err(Error::denied());
    }
    tx.commit().await?;
    Ok(result)
}
struct Prepared {
    token: String,
    ctx: Context,
    input: Value,
    key: String,
    skill: Option<Uuid>,
    until_ms: i64,
}
async fn prepare_capability(
    app: &App,
    workload: Workload,
    request: &rpc::InvokeRequest,
    streaming: bool,
) -> Result<Prepared> {
    let context = context(request.context.as_ref())?;
    let call = uuid(&request.call_id)?;
    let contract = contract(
        request
            .contract
            .as_ref()
            .ok_or_else(|| Error::invalid("Exact contract is required"))?,
    );
    contracts::validate("ContractRef", &contract)?;
    let payload = contracts::strict_json(&request.input_json, app.config.json_limit(4194304))?;
    if contracts::digest(&request.input_json) != request.input_digest {
        return Err(Error::invalid("Input digest differs"));
    }
    let resource = Resource::new(
        "capability",
        format!(
            "{}@{}",
            contracts::string(&contract, "name")?,
            contracts::string(&contract, "version")?
        ),
        None,
    );
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    let auth = authority(&tx, app, workload, context, "capability.invoke", &resource).await?;
    let provider = crate::dependencies::check_host(
        &tx,
        &auth.ctx,
        auth.deployment,
        auth.call,
        uuid(&request.binding_id)?,
        &contract,
    )
    .await?;
    let timeout = (auth.until_ms.min(context.deadline_unix_ms)
        - chrono::Utc::now().timestamp_millis())
    .clamp(1, 300000) as u64;
    let mut input = json!({"contract":contract,"input":payload,"provider_deployment_id":provider,"timeout_ms":timeout,"idempotency_key":context.idempotency_key});
    let fingerprint = contracts::digest(&serde_json::to_vec(
        &json!({"contract":contract,"input_digest":request.input_digest,"provider":provider,"call_id":call,"binding":request.binding_id,"streaming":streaming}),
    )?);
    let bounds = policy::rules(auth.ctx.proxy_paths.as_ref().ok_or_else(Error::denied)?);
    let token = ticket(
        &tx,
        app,
        workload,
        context,
        &auth,
        bounds,
        Some(provider),
        &fingerprint,
        None,
        Some(contract),
        &contracts::digest(&serde_json::to_vec(&payload)?),
        Some(call),
        &mut input,
        Some(uuid(&request.binding_id)?),
    )
    .await?;
    let prepared = Prepared {
        token,
        ctx: auth.ctx,
        input,
        key: call_key(auth.call, &context.idempotency_key),
        skill: None,
        until_ms: auth.until_ms,
    };
    tx.commit().await?;
    Ok(prepared)
}
async fn prepare_skill(
    app: &App,
    workload: Workload,
    request: &rpc::SkillInvokeRequest,
    streaming: bool,
) -> Result<Prepared> {
    let context = context(request.context.as_ref())?;
    let skill = uuid(&request.skill_id)?;
    let requested_call = request
        .call_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(uuid)
        .transpose()?;
    let payload = contracts::strict_json(&request.input_json, app.config.json_limit(4194304))?;
    if contracts::digest(&request.input_json) != request.input_digest {
        return Err(Error::invalid("Input digest differs"));
    }
    let mut c = app.db.connect().await?;
    let tx = c.transaction().await?;
    let (value, resource, action) = target(&tx, skill).await?;
    let owner: Uuid = tx
        .query_one("SELECT created_by FROM skills WHERE id=$1", &[&skill])
        .await?
        .get(0);
    let auth = authority(
        &tx,
        app,
        workload,
        context,
        "skill.invoke",
        &Resource::new("skill", skill, Some(owner)),
    )
    .await?;
    if !auth.ctx.proxy_allows(&action, &resource)
        || !auth::rules_allow(
            &policy::rules(auth.ctx.proxy_paths.as_ref().ok_or_else(Error::denied)?),
            &action,
            &resource,
            auth.ctx.peer,
        )
    {
        return Err(Error::denied());
    }
    let maximum = value["definition"]["maximum_timeout_ms"]
        .as_u64()
        .ok_or_else(Error::denied)?;
    let timeout = (auth.until_ms.min(context.deadline_unix_ms)
        - chrono::Utc::now().timestamp_millis())
    .clamp(1, 300000) as u64;
    let mut input = json!({"input":payload,"timeout_ms":timeout.min(maximum),"idempotency_key":context.idempotency_key});
    if let Some(provider) = value.get("host_provider_deployment_id") {
        input["provider_deployment_id"] = provider.clone();
    }
    let fingerprint = contracts::digest(&serde_json::to_vec(
        &json!({"skill":skill,"definition_digest":value["definition_digest"],"input_digest":request.input_digest,"call_id":requested_call,"streaming":streaming}),
    )?);
    let expected = if value["definition"]["target"]["kind"] == "capability" {
        Some(value["definition"]["target"]["contract"].clone())
    } else {
        None
    };
    let input_digest = if value["definition"]["target"]["kind"] == "http"
        && crate::http_contracts::load(&tx, contracts::id(&value, "installation_id")?)
            .await?
            .bind_skill(&value["definition"])?
            .input
            .is_none()
    {
        contracts::digest(b"")
    } else {
        contracts::digest(&serde_json::to_vec(&payload)?)
    };
    let bounds = policy::rules(auth.ctx.proxy_paths.as_ref().ok_or_else(Error::denied)?);
    let token = ticket(
        &tx,
        app,
        workload,
        context,
        &auth,
        bounds,
        None,
        &fingerprint,
        Some(skill),
        expected,
        &input_digest,
        requested_call,
        &mut input,
        None,
    )
    .await?;
    let prepared = Prepared {
        token,
        ctx: auth.ctx,
        input,
        key: call_key(auth.call, &context.idempotency_key),
        skill: Some(skill),
        until_ms: auth.until_ms,
    };
    tx.commit().await?;
    Ok(prepared)
}
fn response(value: Value) -> Result<rpc::InvokeResponse> {
    let value = if value.get("call").is_some() {
        &value["call"]
    } else {
        &value
    };
    let output = serde_json::to_vec(&value["output"])?;
    Ok(rpc::InvokeResponse {
        call_id: contracts::string(value, "call_id")?.into(),
        output_digest: contracts::digest(&output),
        output_json: output,
    })
}
pub(crate) async fn invoke(
    app: &App,
    workload: Workload,
    request: rpc::InvokeRequest,
) -> Result<rpc::InvokeResponse> {
    let prepared = prepare_capability(app, workload, &request, false).await?;
    response(
        crate::broker::invoke_host(
            app,
            &prepared.token,
            &prepared.ctx,
            &prepared.input,
            &prepared.key,
            None,
            None,
        )
        .await?,
    )
}
pub(crate) async fn invoke_skill(
    app: &App,
    workload: Workload,
    request: rpc::SkillInvokeRequest,
) -> Result<rpc::InvokeResponse> {
    let prepared = prepare_skill(app, workload, &request, false).await?;
    let started = tokio::time::Instant::now();
    let result = crate::broker::invoke_host(
        app,
        &prepared.token,
        &prepared.ctx,
        &prepared.input,
        &prepared.key,
        prepared.skill,
        None,
    )
    .await;
    let maximum = prepared.input["timeout_ms"].as_u64().unwrap_or(30000);
    let result = visible_error(
        app,
        &prepared,
        result,
        started + Duration::from_millis(maximum),
    )
    .await;
    response(result?)
}
async fn visible_error(
    app: &App,
    prepared: &Prepared,
    mut result: Result<Value>,
    deadline: tokio::time::Instant,
) -> Result<Value> {
    if let Err(error) = &mut result {
        if let Some(id) = error.resource_id.as_deref() {
            let budget = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_secs(10));
            let check = async {
                let child = uuid(id)?;
                let mut c = app.db.connect_scoped(budget).await?;
                let tx = c.transaction().await?;
                db::call_lock(&tx).await?;
                let ctx = authenticate(
                    &tx,
                    app,
                    &prepared.token,
                    prepared.ctx.peer,
                    prepared.ctx.request,
                )
                .await?;
                crate::broker::check_skill_authority(&tx, &ctx, child).await?;
                tx.commit().await?;
                Ok::<(), Error>(())
            };
            let checked = tokio::time::timeout(budget, check).await;
            if !matches!(checked, Ok(Ok(()))) {
                #[cfg(test)]
                if std::env::var_os("XELAB_HOST_TIMING").is_some() {
                    eprintln!("HOST_ERROR_VISIBILITY {checked:?}");
                }
                error.resource_id = None;
            }
        }
    }
    result
}
pub(crate) type RpcStream = std::pin::Pin<
    Box<
        dyn tokio_stream::Stream<Item = std::result::Result<rpc::InvokeChunk, tonic::Status>>
            + Send,
    >,
>;
pub(crate) async fn invoke_stream(
    app: std::sync::Arc<App>,
    workload: Workload,
    request: rpc::InvokeRequest,
) -> Result<RpcStream> {
    let prepared = prepare_capability(&app, workload, &request, true).await?;
    stream(app, prepared).await
}
pub(crate) async fn invoke_skill_stream(
    app: std::sync::Arc<App>,
    workload: Workload,
    request: rpc::SkillInvokeRequest,
) -> Result<RpcStream> {
    let prepared = prepare_skill(&app, workload, &request, true).await?;
    stream(app, prepared).await
}
async fn stream(app: std::sync::Arc<App>, prepared: Prepared) -> Result<RpcStream> {
    let remaining = prepared
        .until_ms
        .saturating_sub(chrono::Utc::now().timestamp_millis())
        .max(0) as u64;
    let until = tokio::time::Instant::now()
        + Duration::from_millis(
            remaining.min(prepared.input["timeout_ms"].as_u64().unwrap_or(30000)),
        );
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let (output, source) = tokio::sync::mpsc::channel(2);
    let producer = std::sync::Arc::new(crate::skill_streams::Output::new_host(sender));
    let delivery_token = prepared.token.clone();
    let delivery_peer = prepared.ctx.peer;
    let delivery_request = prepared.ctx.request;
    let actor = producer.clone();
    drop(producer);
    let owner = app.clone();
    tokio::spawn(async move {
        let result = crate::broker::invoke_host(
            &owner,
            &prepared.token,
            &prepared.ctx,
            &prepared.input,
            &prepared.key,
            prepared.skill,
            Some(&actor),
        )
        .await;
        actor
            .finish(result.map(|value| {
                if value.get("call").is_some() {
                    value
                } else {
                    json!({"call":value})
                }
            }))
            .await;
    });
    let maximum_frame = app.config.rpc_limit(16777216 + 65536);
    tokio::spawn(async move {
        let mut sequence = 0;
        loop {
            let frame = tokio::select! {_ = output.closed()=>break,frame=receiver.recv()=>match frame{Some(frame)=>frame,None=>break}};
            let mapped = match frame {
                Err(error) => Err(status(error)),
                Ok(frame) => {
                    if frame.kind == "accepted" {
                        continue;
                    }
                    sequence += 1;
                    let parsed = contracts::strict_json(frame.data.as_bytes(), maximum_frame);
                    parsed
                        .and_then(|value| {
                            let event = &value["event"];
                            let call = contracts::string(event, "call_id")?.into();
                            let body = match frame.kind {
                                "item" => rpc::invoke_chunk::Body::ItemJson(serde_json::to_vec(
                                    &event["payload"],
                                )?),
                                "completed" => rpc::invoke_chunk::Body::Completed(response(
                                    event["payload"].clone(),
                                )?),
                                "canceled" => rpc::invoke_chunk::Body::Canceled(rpc::Ack {
                                    request_id: String::new(),
                                    accepted: true,
                                }),
                                _ => {
                                    return Err(Error::unavailable(
                                        "Downstream generation failed; inspect Call",
                                    ))
                                }
                            };
                            Ok(rpc::InvokeChunk {
                                call_id: call,
                                sequence,
                                body: Some(body),
                            })
                        })
                        .map_err(status)
                }
            };
            if tokio::time::timeout(Duration::from_secs(30), output.send(mapped))
                .await
                .is_err()
            {
                break;
            }
            if output.is_closed() {
                break;
            }
        }
    });
    let guarded = futures_util::stream::unfold(
        (source, app, delivery_token, false),
        move |(mut source, app, token, ended)| async move {
            if ended {
                return None;
            }
            let mut item = source.recv().await?;
            let mut stop = false;
            if let Ok(chunk) = item.as_ref() {
                let budget = until
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(Duration::from_secs(10));
                let check = async {
                    let mut c = app.db.connect_scoped(budget).await?;
                    let tx = c.transaction().await?;
                    db::call_lock(&tx).await?;
                    let ctx =
                        authenticate(&tx, &app, &token, delivery_peer, delivery_request).await?;
                    let child = uuid(&chunk.call_id)?;
                    crate::broker::check_skill_authority(&tx, &ctx, child).await?;
                    let deployment:Uuid=tx.query_one("SELECT i.deployment_id FROM calls c JOIN instances i ON i.id=c.provider_instance_id WHERE c.id=$1",&[&child]).await?.get(0);
                    crate::dependencies::check_ready(&tx, &app, deployment).await?;
                    crate::dependencies::check_call(&tx, child).await?;
                    tx.commit().await?;
                    Ok::<(), Error>(())
                };
                if let Err(error) = tokio::time::timeout(budget, check)
                    .await
                    .unwrap_or_else(|_| {
                        Err(Error::unavailable("Host delivery authorization deadline"))
                    })
                {
                    item = Err(status(error));
                    stop = true;
                }
            }
            Some((item, (source, app, token, stop)))
        },
    );
    Ok(with_deadline(Box::pin(guarded), until))
}

/// A single captured deadline covers waiting, proof work and queued delivery.
/// This wrapper is also applied to the original transport/context bound.
pub(crate) fn with_deadline(stream: RpcStream, until: tokio::time::Instant) -> RpcStream {
    use futures_util::StreamExt;
    Box::pin(futures_util::stream::unfold(
        Some(stream),
        move |stream| async move {
            let mut stream = stream?;
            let expired = || {
                status(Error::new(
                    "DEADLINE_EXCEEDED",
                    "Host stream deadline elapsed",
                    axum::http::StatusCode::GATEWAY_TIMEOUT,
                ))
            };
            if tokio::time::Instant::now() >= until {
                return Some((Err(expired()), None));
            }
            match tokio::time::timeout_at(until, stream.next()).await {
                Ok(Some(item)) if tokio::time::Instant::now() < until => {
                    let next = if item.is_err() { None } else { Some(stream) };
                    Some((item, next))
                }
                Ok(None) => None,
                _ => Some((Err(expired()), None)),
            }
        },
    ))
}

#[allow(clippy::result_large_err)]
pub(crate) fn status(error: Error) -> tonic::Status {
    use prost::Message;
    let detail = rpc::ErrorDetail {
        code: error.code.into(),
        message: error.message.to_owned(),
        retryable: false,
        retry_after_ms: 0,
        violations: Vec::new(),
        resource_id: if matches!(error.status.as_u16(), 401 | 403 | 404) {
            String::new()
        } else {
            error.resource_id.clone().unwrap_or_default()
        },
    };
    let mut status = crate::host_blobs::status(error);
    status.metadata_mut().insert_bin(
        "xelab-error-bin",
        tonic::metadata::MetadataValue::from_bytes(&detail.encode_to_vec()),
    );
    status
}

pub(crate) async fn bound_deadline(
    c: &(impl GenericClient + Sync),
    app: &App,
    token: &str,
    deadline: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>> {
    if !token.starts_with("host:") {
        return Ok(deadline);
    }
    let expiry: chrono::DateTime<chrono::Utc> = c
        .query_opt(
            "SELECT expires_at FROM host_call_tickets WHERE verification_digest=$1",
            &[&app.auth.token_digest(token)],
        )
        .await?
        .ok_or_else(Error::denied)?
        .get(0);
    let deadline = deadline.min(expiry);
    if deadline <= chrono::Utc::now() {
        return Err(Error::new(
            "DEADLINE_EXCEEDED",
            "Ancestor call deadline elapsed",
            axum::http::StatusCode::GATEWAY_TIMEOUT,
        ));
    }
    Ok(deadline)
}

// Approval provenance is evaluated at the approver's saved environment; its
// CIDR restriction must not be reinterpreted as the business caller's network.
fn scopes_at_peer(rules: &Value, peer: IpAddr) -> Value {
    json!(rules
        .as_array()
        .into_iter()
        .flatten()
        .filter(|rule| auth::conditions_match(
            rule.get("conditions").unwrap_or(&json!({})),
            peer,
            chrono::Utc::now()
        ))
        .map(|rule| {
            let mut rule = rule.clone();
            if let Some(conditions) = rule.get_mut("conditions").and_then(Value::as_object_mut) {
                conditions.remove("source_cidrs");
            }
            rule
        })
        .collect::<Vec<_>>())
}
#[cfg(test)]
mod proof_tests {
    use super::*;
    #[test]
    fn approver_environment_does_not_become_caller_cidr() {
        let rules = json!([{"action":"event.publish","resource":{"kind":"event","match":"all"},"conditions":{"source_cidrs":["203.0.113.0/24"]}}]);
        let scopes = scopes_at_peer(&rules, "203.0.113.9".parse().unwrap());
        assert!(auth::rules_allow(
            &scopes,
            "event.publish",
            &Resource::new("event", "org.xelab.test", None),
            "192.0.2.7".parse().unwrap()
        ));
        assert_eq!(
            scopes_at_peer(&rules, "192.0.2.7".parse().unwrap()),
            json!([])
        );
    }
}

pub(crate) fn extend_ceilings(ceilings: &mut Vec<Value>, additional: &[Value]) -> Result<()> {
    for ceiling in additional {
        if !ceiling.is_array() {
            return Err(Error::denied());
        }
        if !ceilings.contains(ceiling) {
            ceilings.push(ceiling.clone());
        }
    }
    if ceilings.len() > 128 || serde_json::to_vec(ceilings)?.len() > 1048576 {
        return Err(Error::exhausted());
    }
    Ok(())
}

fn proof_allows(ctx: &Context, action: &str, resource: &Resource) -> bool {
    ctx.proxy_allows(action, resource)
        && ctx.proxy_paths.as_ref().is_some_and(|paths| {
            auth::rules_allow(&policy::rules(paths), action, resource, ctx.peer)
        })
}

fn stage(start: std::time::Instant, name: &str) {
    #[cfg(test)]
    if std::env::var_os("XELAB_HOST_TIMING").is_some() {
        eprintln!("HOST_PROOF {name}: {}ms", start.elapsed().as_millis());
    }
    #[cfg(not(test))]
    let _ = (start, name);
}

/// One Host RPC's authority walks, including its original approvers, under one
/// shared authorization fence. Never retain across requests/transactions.
#[derive(Default)]
pub(crate) struct ProofCache {
    current: std::collections::HashMap<String, Vec<crate::policy::Path>>,
    paths: usize,
}
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestProofCache(ProofCache);
#[cfg(test)]
impl TestProofCache {
    pub(crate) async fn revalidate(
        &mut self,
        c: &(impl GenericClient + Sync),
        ctx: &Context,
        resource: Option<&Resource>,
        saved: &[crate::policy::Path],
    ) -> Result<Vec<crate::policy::Path>> {
        Ok(self.0.revalidate(c, ctx, resource, saved).await?.1)
    }
}
impl ProofCache {
    pub(crate) fn revalidate<'a>(
        &'a mut self,
        c: &'a (impl GenericClient + Sync),
        ctx: &'a Context,
        resource: Option<&'a Resource>,
        saved: &'a [crate::policy::Path],
    ) -> BoxFuture<'a, Result<(Vec<crate::policy::Path>, Vec<crate::policy::Path>)>> {
        Box::pin(async move {
            if saved.len() > 4096 {
                return Err(Error::exhausted());
            }
            auth::validate_sources(c, Some(ctx.credential), Some(ctx.subject), ctx.peer).await?;
            let current = self.current(c, ctx, resource).await?;
            // The cache is transaction-local, but clocks still advance. In
            // particular, external business issuers may not appear in proxy scopes.
            let current = Policy::for_context(c, ctx)
                .live_proxy_sources(current)
                .await?;
            let mut policy = Policy::for_context(c, ctx);
            if let Some(resource) = resource.filter(|r| r.kind == "plugin") {
                policy = policy.with_resource_owner(resource);
            }
            let mut live = Vec::new();
            let mut pending = Vec::new();
            for path in saved {
                let identical_sources: Vec<_> = current
                    .iter()
                    .filter(|p| p.sources == path.sources)
                    .cloned()
                    .collect();
                let proved = policy
                    .intersection(std::slice::from_ref(path), &identical_sources)
                    .await?;
                if proved.iter().any(|p| p.rule == path.rule) {
                    // The fresh proof has the exact original sources and covers
                    // the entire frozen rule under the same owner profile. Any
                    // narrower intersection with additional conjunctive sources
                    // is dominated by this already-proved original path.
                    live.push(path.clone());
                } else {
                    pending.push(path.clone());
                }
                if live.len() > 4096 {
                    return Err(Error::exhausted());
                }
            }
            live.extend(policy.revalidate_current(&pending, &current).await?);
            if live.len() > 4096 {
                return Err(Error::exhausted());
            }
            Ok((current, live))
        })
    }

    async fn current(
        &mut self,
        c: &(impl GenericClient + Sync),
        ctx: &Context,
        resource: Option<&Resource>,
    ) -> Result<Vec<crate::policy::Path>> {
        // Private to a single Host authority walk under its shared auth fence.
        // Contexts are freshly resumed; no body or prior request supplies proof.
        if ctx.proxy_paths.is_some() || !ctx.proxy_ceilings.is_empty() || ctx.proxy_proof.is_some()
        {
            return Err(Error::denied());
        }
        let owner = resource.filter(|r| r.kind == "plugin");
        let key = serde_json::to_string(&json!([
            ctx.credential,
            ctx.subject,
            ctx.peer.to_string(),
            ctx.browser_origin,
            owner.map(|r| (&r.kind, &r.id, r.owner))
        ]))?;
        if let Some(paths) = self.current.get(&key) {
            return Ok(paths.clone());
        }
        let mut policy = Policy::for_context(c, ctx);
        if let Some(resource) = owner {
            policy = policy.with_resource_owner(resource);
        }
        let paths = policy.credential(ctx.credential, 0).await?;
        if self.paths + paths.len() <= 8192 {
            self.paths += paths.len();
            self.current.insert(key, paths.clone());
        }
        Ok(paths)
    }
}
