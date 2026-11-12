use crate::{
    auth::{self, Auth, Context, Resource},
    contracts::{id, string},
    error::{Error, Result},
    policy::{self, Path, Policy},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(super) struct Prepared {
    pub(super) skill: Uuid,
    pub(super) deployment: Uuid,
    pub(super) installation: Uuid,
    pub(super) definition: Value,
    pub(super) is_http: bool,
    pub(super) http_bodyless: bool,
    pub(super) maximum_input_bytes: usize,
    pub(super) maximum_output_bytes: usize,
    pub(super) deadline: DateTime<Utc>,
    context: Context,
    business_paths: Vec<Path>,
}

impl Prepared {
    /// Expose only this step's live business proof to the Broker transaction.
    pub(super) async fn into_broker_context(self, tx: &Transaction<'_>) -> Result<Context> {
        let mut context = self.context;
        context
            .proxy_ceilings
            .push(policy::rules(&self.business_paths));
        context.proxy_paths = Some(self.business_paths);
        context.bind_proxy_proof(tx).await?;
        Ok(context)
    }
}

#[derive(Deserialize)]
struct Admission {
    version: u64,
    peer: IpAddr,
    browser_origin: Option<String>,
    credential_chain: Vec<Uuid>,
    workflow_paths: Vec<Path>,
    steps: Vec<StepAdmission>,
}

#[derive(Deserialize)]
struct StepAdmission {
    step_key: String,
    deployment_id: Option<Uuid>,
    installation_id: Option<Uuid>,
    binding: Value,
    targets: Vec<Target>,
}

#[derive(Deserialize)]
struct Target {
    action: String,
    resource: Value,
    owner_id: Option<Uuid>,
    paths: Vec<Path>,
}

/// Rebuild authority in the transaction that already holds the auth fence and
/// locks the Task and step. The returned binding is metadata, never a bearer.
pub(super) async fn prepare(
    tx: &Transaction<'_>,
    auth: &Auth,
    task: &Row,
    step_key: &str,
    request: Uuid,
) -> Result<Prepared> {
    let owner: Uuid = task.try_get("owner_id")?;
    if task.try_get::<_, Uuid>("delegation_subject")? != owner
        || task.try_get::<_, String>("delegation_status")? != "active"
        || task.try_get::<_, String>("delegation_run_as")? != "user"
    {
        return Err(Error::denied());
    }
    let deadline = task
        .try_get::<_, DateTime<Utc>>("deadline_at")?
        .min(task.try_get("delegation_expires_at")?);
    if deadline <= Utc::now() {
        return Err(Error::denied());
    }

    let admission: Admission = serde_json::from_value(
        task.try_get::<_, Option<Value>>("admission")?
            .ok_or_else(Error::denied)?,
    )
    .map_err(|_| Error::denied())?;
    if admission.version != 1 {
        return Err(Error::denied());
    }
    let mut matching_steps = admission
        .steps
        .iter()
        .filter(|step| step.step_key == step_key);
    let step = matching_steps.next().ok_or_else(Error::denied)?;
    if matching_steps.next().is_some() {
        return Err(Error::denied());
    }
    let is_http = match step.binding["kind"].as_str() {
        Some("skill_capability") => false,
        Some("skill_http") => true,
        _ => return Err(Error::unavailable("Task step requires a synchronous Skill")),
    };
    let skill_id = id(&step.binding, "skill_id").map_err(|_| Error::denied())?;
    let definition_digest =
        string(&step.binding, "definition_digest").map_err(|_| Error::denied())?;
    let deployment = step.deployment_id.ok_or_else(Error::denied)?;
    let installation = step.installation_id.ok_or_else(Error::denied)?;
    if task.try_get::<_, Option<Uuid>>("provider_deployment_id")? != Some(deployment) {
        return Err(Error::denied());
    }

    let issuer = task
        .try_get::<_, Option<Uuid>>("issuer_credential_id")?
        .ok_or_else(Error::denied)?;
    let mut ctx = auth.resume(tx, issuer, admission.peer, request).await?;
    if ctx.subject != owner || ctx.chain != admission.credential_chain {
        return Err(Error::denied());
    }
    ctx.browser_origin = admission.browser_origin;
    crate::oauth_http::validate_source_origins(tx, &[issuer], ctx.browser_origin.as_deref())
        .await?;

    let workflow: Uuid = task.try_get("workflow_id")?;
    let spec: Value = task.try_get("spec")?;
    let workflow_step = spec["steps"]
        .as_array()
        .ok_or_else(Error::denied)?
        .iter()
        .find(|step| step["id"] == step_key)
        .ok_or_else(Error::denied)?;
    if id(workflow_step, "skill_id").ok() != Some(skill_id) {
        return Err(Error::denied());
    }

    // The Skill resolver checks the live Skill and signed installation candidate.
    let skill = crate::skills::resolve_for_invoke(tx, &ctx, skill_id).await?;
    if skill.installation_id != installation || skill.definition_digest != definition_digest {
        return Err(Error::denied());
    }
    let (
        business_action,
        business_resource,
        maximum_input_bytes,
        maximum_output_bytes,
        http_bodyless,
    ) = if is_http {
        let (action, resource, input_bytes, bodyless) = check_http_provider(
            tx,
            deployment,
            installation,
            &step.binding,
            &skill.definition,
        )
        .await?;
        (
            action,
            resource,
            input_bytes,
            crate::plugin_http::MAXIMUM_RESPONSE_BYTES,
            bodyless,
        )
    } else {
        let contract = &step.binding["contract"];
        if skill.definition["target"]["kind"] != "capability"
            || skill.definition["target"]["contract"] != *contract
        {
            return Err(Error::denied());
        }
        let (input_bytes, output_bytes) =
            check_provider(tx, deployment, installation, contract).await?;
        let resource = Resource::new(
            "capability",
            format!(
                "{}@{}",
                string(contract, "name")?,
                string(contract, "version")?
            ),
            None,
        );
        (
            "capability.invoke".to_owned(),
            resource,
            input_bytes,
            output_bytes,
            false,
        )
    };

    let workflow_resource = Resource::new(
        "workflow",
        workflow,
        Some(task.try_get("workflow_owner_id")?),
    );
    let skill_resource = Resource::new("skill", skill_id, Some(skill.owner));
    if step.targets.len() != 2 {
        return Err(Error::denied());
    }
    let saved_targets = [
        (
            "workflow.read",
            &workflow_resource,
            admission.workflow_paths.as_slice(),
        ),
        (
            "skill.invoke",
            &skill_resource,
            saved_paths(step, "skill.invoke", &skill_resource)?,
        ),
        (
            business_action.as_str(),
            &business_resource,
            saved_paths(step, &business_action, &business_resource)?,
        ),
    ];
    let maximum: Value = task.try_get("maximum_rules")?;
    let ceiling = maximum.as_array().ok_or_else(Error::denied)?;
    let mut current_paths = Vec::with_capacity(saved_targets.len());
    for (action, resource, saved) in saved_targets {
        current_paths.push(revalidate_paths(tx, &ctx, action, resource, saved, ceiling).await?);
    }
    let deadline = live_deadline(tx, &ctx, &mut current_paths, deadline).await?;
    Ok(Prepared {
        skill: skill_id,
        deployment,
        installation,
        definition: skill.definition,
        is_http,
        http_bodyless,
        maximum_input_bytes,
        maximum_output_bytes,
        deadline,
        context: ctx,
        // Workflow visibility is required above, but it is not delegated to
        // the Broker as part of Skill or business authority.
        business_paths: current_paths.into_iter().skip(1).flatten().collect(),
    })
}

fn saved_paths<'a>(
    step: &'a StepAdmission,
    action: &str,
    resource: &Resource,
) -> Result<&'a [Path]> {
    let target = step
        .targets
        .iter()
        .find(|target| target.action == action)
        .ok_or_else(Error::denied)?;
    if target.resource != resource.json() || target.owner_id != resource.owner {
        return Err(Error::denied());
    }
    Ok(&target.paths)
}

async fn revalidate_paths(
    tx: &Transaction<'_>,
    ctx: &Context,
    action: &str,
    resource: &Resource,
    saved: &[Path],
    ceiling: &[Value],
) -> Result<Vec<Path>> {
    let selector = resource.json();
    if saved.is_empty()
        || saved.iter().any(|path| {
            path.rule["action"] != action
                || path.rule["resource"] != selector
                || !ceiling.contains(&path.rule)
        })
        || !policy::registered(tx, action, &resource.kind).await?
    {
        return Err(Error::denied());
    }
    Policy::for_context(tx, ctx)
        .with_resource_owner(resource)
        .revalidate(saved, ctx.credential)
        .await
}

async fn check_http_provider(
    tx: &Transaction<'_>,
    deployment: Uuid,
    installation: Uuid,
    binding: &Value,
    definition: &Value,
) -> Result<(String, Resource, usize, bool)> {
    let row = tx
        .query_opt(
            "SELECT owner_id FROM deployments
             WHERE id=$1 AND installation_id=$2 AND archived_at IS NULL AND spec->>'enabled'='true'
             FOR SHARE",
            &[&deployment, &installation],
        )
        .await?
        .ok_or_else(|| Error::unavailable("Task HTTP Skill deployment is no longer available"))?;
    let registry = crate::http_contracts::load(tx, installation).await?;
    let operation = registry.bind_skill(definition)?;
    if operation.id != binding["operation_id"]
        || operation.contract_digest != binding["http_contract_digest"]
        || operation.method.as_str() != binding["method"]
        || operation.path != binding["path"]
    {
        return Err(Error::denied());
    }
    if !definition["stream_item_schema"].is_null()
        || operation
            .responses
            .values()
            .any(|response| response.media_type.as_deref() == Some("text/event-stream"))
    {
        return Err(Error::unavailable("Task HTTP Skill must be synchronous"));
    }
    let resource = Resource::new(
        "plugin",
        string(&definition["target"], "plugin_id")?,
        Some(row.get("owner_id")),
    );
    Ok((
        operation.route.action.clone(),
        resource,
        operation.route.maximum_body_bytes,
        operation.input.is_none(),
    ))
}

async fn check_provider(
    tx: &Transaction<'_>,
    deployment: Uuid,
    installation: Uuid,
    contract: &Value,
) -> Result<(usize, usize)> {
    let row = tx
        .query_opt(
            "SELECT n.manifest FROM deployments d JOIN installations n ON n.id=d.installation_id
         WHERE d.id=$1 AND n.id=$2 AND d.archived_at IS NULL AND d.spec->>'enabled'='true'
         FOR SHARE OF d",
            &[&deployment, &installation],
        )
        .await?
        .ok_or_else(|| Error::unavailable("Task Skill deployment is no longer available"))?;
    let manifest: Value = row.get(0);
    let signed = manifest["capabilities"]
        .as_array()
        .and_then(|caps| caps.iter().find(|cap| cap["contract"] == *contract))
        .ok_or_else(|| {
            Error::conflict("Task Skill capability differs from the pinned installation")
        })?;
    let row = tx
        .query_opt(
            "SELECT schema_digest,spec FROM capability_contracts WHERE name=$1 AND version=$2",
            &[&string(contract, "name")?, &string(contract, "version")?],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    let registered: Value = row.get("spec");
    if row.get::<_, String>("schema_digest") != string(contract, "schema_digest")?
        || [
            "contract",
            "input_schema",
            "output_schema",
            "stream_item_schema",
            "side_effect",
            "maximum_input_bytes",
            "maximum_output_bytes",
        ]
        .iter()
        .any(|field| signed.get(field) != registered.get(field))
    {
        return Err(Error::conflict(
            "Task Skill capability differs from the registered contract",
        ));
    }
    let byte_limit = |field: &str| {
        registered[field]
            .as_u64()
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size > 0)
            .ok_or_else(|| Error::conflict("Task Skill capability has an invalid payload limit"))
    };
    Ok((
        byte_limit("maximum_input_bytes")?,
        byte_limit("maximum_output_bytes")?,
    ))
}

async fn live_deadline(
    tx: &Transaction<'_>,
    ctx: &Context,
    targets: &mut [Vec<Path>],
    deadline: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    let sources: Vec<_> = targets
        .iter()
        .flatten()
        .flat_map(|path| path.sources.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let chains = Policy::for_context(tx, ctx)
        .live_grant_issuer_chains(&sources)
        .await?;
    let chain =
        auth::validate_sources(tx, Some(ctx.credential), Some(ctx.subject), ctx.peer).await?;
    if chain != ctx.chain {
        return Err(Error::denied());
    }
    let credentials: Vec<_> = chain
        .iter()
        .copied()
        .chain(chains.values().flat_map(|chain| chain.iter().copied()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let expiries: HashMap<Uuid, DateTime<Utc>> = tx
        .query(
            "SELECT id,expires_at FROM credentials WHERE id=ANY($1::uuid[])",
            &[&credentials],
        )
        .await?
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    if expiries.len() != credentials.len() {
        return Err(Error::denied());
    }
    let grant_expiries: HashMap<_, _> = chains
        .into_iter()
        .map(|(source, chain)| {
            (
                source,
                chain
                    .iter()
                    .map(|credential| expiries[credential])
                    .min()
                    .unwrap_or(DateTime::<Utc>::MAX_UTC),
            )
        })
        .collect();
    let now: DateTime<Utc> = tx.query_one("SELECT clock_timestamp()", &[]).await?.get(0);
    let mut deadline = chain
        .iter()
        .map(|credential| expiries[credential])
        .fold(deadline, DateTime::min);
    for paths in targets {
        // Alternatives are independent. A target remains authorized until its
        // longest surviving original proof ends, subject to the global deadline.
        let mut longest = None;
        paths.retain_mut(|path| {
            let conditions = path.rule.get("conditions");
            if conditions
                .is_some_and(|conditions| !auth::conditions_match(conditions, ctx.peer, now))
            {
                return false;
            }
            let rule_expiry = conditions
                .and_then(|conditions| conditions.get("expires_at"))
                .and_then(Value::as_str)
                .and_then(|expiry| expiry.parse::<DateTime<Utc>>().ok())
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
            let Some(until) = path.sources.iter().try_fold(rule_expiry, |until, source| {
                Some(until.min(*grant_expiries.get(source)?))
            }) else {
                return false;
            };
            if until <= now {
                return false;
            }
            if until < rule_expiry {
                path.rule["conditions"]["expires_at"] = json!(until);
            }
            longest = Some(longest.map_or(until, |current: DateTime<Utc>| current.max(until)));
            true
        });
        deadline = deadline.min(longest.ok_or_else(Error::denied)?);
    }
    (deadline > now)
        .then_some(deadline)
        .ok_or_else(Error::denied)
}
