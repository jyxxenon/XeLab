//! Schedules persist the exact Task proofs they may use to admit future work.
use super::{
    authority, authorize_create, authorize_workflow_read, collect_live_rules, freeze_task_plan,
    insert_task, load_workflow, proposed_task, source_ids, targets, NewTask, DEFAULT_TIMEOUT_MS,
};
use crate::{
    auth::{Auth, Context, Resource},
    contracts::{digest, id},
    error::{Error, Result},
    plugin_catalog::reserve_authority_bytes,
    policy::{self, Path, Policy},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, net::IpAddr};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(crate) struct ScheduleAdmission {
    pub proof: Value,
    pub maximum_rules: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct ScheduleProof {
    version: u64,
    workflow_id: Uuid,
    input_digest: String,
    task_create_paths: Vec<Path>,
    task: TaskProof,
}

#[derive(Deserialize, Serialize)]
struct TaskProof {
    version: u64,
    peer: IpAddr,
    browser_origin: Option<String>,
    credential_chain: Vec<Uuid>,
    workflow_paths: Vec<Path>,
    steps: Vec<StepProof>,
}

#[derive(Deserialize, Serialize)]
struct StepProof {
    step_key: String,
    deployment_id: Uuid,
    installation_id: Uuid,
    binding: Value,
    targets: Vec<TargetProof>,
}

#[derive(Deserialize, Serialize)]
struct TargetProof {
    action: String,
    resource: Value,
    owner_id: Option<Uuid>,
    paths: Vec<Path>,
}

impl TargetProof {
    fn resource(&self) -> Result<Resource> {
        let ids = self.resource["ids"].as_array().ok_or_else(Error::denied)?;
        let [id] = ids.as_slice() else {
            return Err(Error::denied());
        };
        let kind = self.resource["kind"].as_str().ok_or_else(Error::denied)?;
        let resource = Resource::new(kind, id.as_str().ok_or_else(Error::denied)?, self.owner_id);
        if self.resource != resource.json() {
            return Err(Error::denied());
        }
        Ok(resource)
    }
}

/// Prepare the frozen execution authority before a Schedule row is written.
/// The HTTP mutation transaction holds the same auth fence as ordinary Task admission.
pub(crate) async fn admit_schedule(
    c: &Transaction<'_>,
    ctx: &Context,
    spec: &Value,
) -> Result<ScheduleAdmission> {
    let workflow = id(spec, "workflow_id")?;
    let input = &spec["input"];
    authorize_create(c, ctx).await?;
    authorize_workflow_read(c, ctx, workflow).await?;
    let (workflow_resource, workflow_spec) = load_workflow(c, workflow, input).await?;
    let steps = workflow_spec["steps"].as_array().unwrap();
    let mut plan = freeze_task_plan(c, ctx, &workflow_resource, steps, DEFAULT_TIMEOUT_MS).await?;
    if plan.steps.iter().any(|step| !step.synchronous_skill) {
        return Err(Error::unavailable(
            "Schedules require synchronous Skill steps",
        ));
    }
    // Freeze creation separately from the exact Workflow and per-step proofs:
    // each fire creates a new Task with the original owner's authority.
    let mut task_create_paths =
        authority::freeze(c, ctx, "task.create", &proposed_task(ctx)).await?;
    let grants = source_ids(plan.paths().chain(&task_create_paths));
    let source_expiries = authority::source_expiries(c, ctx, &grants).await?;
    let expires_at = authority::issuer_expiry(c, ctx).await?;
    let now: DateTime<Utc> = c.query_one("SELECT clock_timestamp()", &[]).await?.get(0);
    if expires_at <= now {
        return Err(Error::credential());
    }
    let mut rules = BTreeMap::new();
    plan.retain_live_rules(ctx, now, &source_expiries, &mut rules)?;
    collect_live_rules(
        &mut task_create_paths,
        ctx,
        now,
        &source_expiries,
        &mut rules,
    )?;
    // Bind the same PostgreSQL JSONB representation that the Schedule stores.
    // This does not round large JSON integers or rely on exponent formatting.
    let input_text: String = c
        .query_one("SELECT ($1::jsonb)::text", &[&input])
        .await?
        .get(0);
    let proof = json!({
        "version": 1,
        "workflow_id": workflow,
        "input_digest": digest(input_text.as_bytes()),
        "task_create_paths": task_create_paths,
        "task": plan.admission(ctx)?,
    });
    reserve_authority_bytes(&mut 0, serde_json::to_vec(&proof)?.len())?;
    Ok(ScheduleAdmission {
        proof,
        maximum_rules: Value::Array(rules.into_values().collect()),
        expires_at,
    })
}

/// Revalidate the original delegated proofs and create a separate Task
/// delegation. The caller holds the auth fence before locking the Schedule
/// and inserts the fire/Task link in this same transaction.
pub(crate) async fn enqueue_scheduled_task(
    c: &Transaction<'_>,
    auth: &Auth,
    schedule: &Row,
) -> Result<Uuid> {
    let schedule_id: Uuid = schedule.try_get("id")?;
    let owner: Uuid = schedule.try_get("owner_id")?;
    let delegation: Uuid = schedule.try_get("delegation_id")?;
    let spec: Value = schedule.try_get("spec")?;
    let proof: Value = schedule
        .try_get::<_, Option<Value>>("admission")?
        .ok_or_else(Error::denied)?;
    let mut saved: ScheduleProof = serde_json::from_value(proof).map_err(|_| Error::denied())?;
    let input = &spec["input"];
    let input_text: Option<String> = c
        .query_one(
            "SELECT (spec->'input')::text FROM schedules WHERE id=$1",
            &[&schedule_id],
        )
        .await?
        .get(0);
    if saved.version != 1
        || saved.task.version != 1
        || saved.workflow_id != id(&spec, "workflow_id").map_err(|_| Error::denied())?
        || input_text.is_none_or(|input| saved.input_digest != digest(input.as_bytes()))
    {
        return Err(Error::denied());
    }

    let delegation = c
        .query_opt(
            "SELECT subject_id,issuer_credential_id,maximum_rules,expires_at,status,run_as
         FROM execution_delegations WHERE id=$1 FOR SHARE",
            &[&delegation],
        )
        .await?
        .ok_or_else(Error::denied)?;
    let expires_at: DateTime<Utc> = delegation.get("expires_at");
    if owner != delegation.get::<_, Uuid>("subject_id")
        || delegation.get::<_, String>("status") != "active"
        || delegation.get::<_, String>("run_as") != "user"
        || expires_at <= Utc::now()
    {
        return Err(Error::denied());
    }
    let issuer: Uuid = delegation
        .get::<_, Option<Uuid>>("issuer_credential_id")
        .ok_or_else(Error::denied)?;
    let ceiling: Value = delegation.get("maximum_rules");
    let ceiling = ceiling.as_array().ok_or_else(Error::denied)?;
    let mut ctx = auth
        .resume(c, issuer, saved.task.peer, Uuid::new_v4())
        .await?;
    if ctx.subject != owner || ctx.chain != saved.task.credential_chain {
        return Err(Error::denied());
    }
    ctx.browser_origin = saved.task.browser_origin.clone();
    crate::oauth_http::validate_source_origins(c, &[issuer], ctx.browser_origin.as_deref()).await?;

    let (workflow_resource, workflow_spec) = load_workflow(c, saved.workflow_id, input).await?;
    let steps = workflow_spec["steps"].as_array().unwrap();
    if steps.len() != saved.task.steps.len() {
        return Err(Error::denied());
    }
    let submitted: DateTime<Utc> = c.query_one("SELECT clock_timestamp()", &[]).await?.get(0);
    saved.task_create_paths = revalidate(
        c,
        &ctx,
        "task.create",
        &proposed_task(&ctx),
        &saved.task_create_paths,
        ceiling,
    )
    .await?;
    saved.task.workflow_paths = revalidate(
        c,
        &ctx,
        "workflow.read",
        &workflow_resource,
        &saved.task.workflow_paths,
        ceiling,
    )
    .await?;

    // Verify the saved sources even if a provider is temporarily disabled.
    // Actual owner/target and binding identities are checked under the provider
    // locks before these narrowed proofs can be written to a Task.
    for step in &mut saved.task.steps {
        for target in &mut step.targets {
            target.paths = revalidate(
                c,
                &ctx,
                &target.action,
                &target.resource()?,
                &target.paths,
                ceiling,
            )
            .await?;
        }
    }
    for (step, frozen) in steps.iter().zip(&saved.task.steps) {
        check_pinned_step(c, &ctx, step, frozen).await?;
    }

    let grants = source_ids(
        saved
            .task
            .workflow_paths
            .iter()
            .chain(
                saved
                    .task
                    .steps
                    .iter()
                    .flat_map(|step| &step.targets)
                    .flat_map(|target| &target.paths),
            )
            .chain(&saved.task_create_paths),
    );
    let source_expiries = authority::source_expiries(c, &ctx, &grants).await?;
    let deadline = submitted + Duration::milliseconds(DEFAULT_TIMEOUT_MS as i64);
    let authority_expires = deadline
        .min(expires_at)
        .min(authority::issuer_expiry(c, &ctx).await?);
    let checked_at: DateTime<Utc> = c.query_one("SELECT clock_timestamp()", &[]).await?.get(0);
    if authority_expires <= checked_at {
        return Err(Error::denied());
    }
    // The schedule's task.create proof gates insertion, but is not authority
    // granted to a running Task. Persist only its Workflow and step proofs.
    collect_live_rules(
        &mut saved.task_create_paths,
        &ctx,
        checked_at,
        &source_expiries,
        &mut BTreeMap::new(),
    )?;
    let mut rules = BTreeMap::new();
    collect_live_rules(
        &mut saved.task.workflow_paths,
        &ctx,
        checked_at,
        &source_expiries,
        &mut rules,
    )?;
    for step in &mut saved.task.steps {
        for target in &mut step.targets {
            collect_live_rules(
                &mut target.paths,
                &ctx,
                checked_at,
                &source_expiries,
                &mut rules,
            )?;
        }
    }
    let admission = serde_json::to_value(saved.task)?;
    reserve_authority_bytes(&mut 0, serde_json::to_vec(&admission)?.len())?;
    insert_task(
        c,
        &ctx,
        NewTask {
            workflow: saved.workflow_id,
            input,
            steps,
            submitted,
            deadline,
            authority_expires,
            admission,
            maximum_rules: Value::Array(rules.into_values().collect()),
        },
    )
    .await
}

async fn revalidate(
    c: &Transaction<'_>,
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
        || !policy::registered(c, action, &resource.kind).await?
    {
        return Err(Error::denied());
    }
    let mut paths = Policy::for_context(c, ctx)
        .with_resource_owner(resource)
        .revalidate(saved, ctx.credential)
        .await?;
    authority::retain_live_paths(&mut paths, ctx, Utc::now())?;
    Ok(paths)
}

async fn check_pinned_step(
    c: &Transaction<'_>,
    ctx: &Context,
    step: &Value,
    saved: &StepProof,
) -> Result<()> {
    let current = targets::resolve_pinned(c, ctx, step, saved.deployment_id, saved.installation_id)
        .await
        .map_err(|error| {
            if error.code == "CONTRACT_CONFLICT" {
                Error::conflict("Scheduled Task binding changed")
            } else {
                error
            }
        })?;
    let binding = current.record();
    if !current.synchronous_skill
        || binding["step_key"] != saved.step_key
        || binding["binding"] != saved.binding
        || current.targets.len() != saved.targets.len()
        || current
            .targets
            .iter()
            .zip(&saved.targets)
            .any(|(target, original)| {
                target.action != original.action
                    || target.resource.json() != original.resource
                    || target.resource.owner != original.owner_id
            })
    {
        return Err(Error::conflict("Scheduled Task binding changed"));
    }
    Ok(())
}
