//! Task submission persists metadata and an authorization ceiling. Execution
//! must revalidate the original grants and provider binding before each step.
use crate::{
    auth::{self, Auth, Context, Resource},
    contracts::{id, reject_jsonb_nul, string, unsigned, validate, validate_business},
    error::{Error, Result},
    policy::Path,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tokio_postgres::GenericClient;
use uuid::Uuid;

mod authority;
mod reads;
#[cfg(test)]
mod restart_tests;
pub(crate) mod snapshot;
mod targets;

pub(crate) fn handles(name: &str) -> bool {
    matches!(
        name,
        "createTask" | "getTask" | "listTasks" | "listTaskSteps"
    )
}

pub(crate) fn validate_query(name: &str, query: &str) -> Result<()> {
    if matches!(name, "createTask" | "getTask") && !query.is_empty() {
        return Err(Error::invalid("Unexpected task query parameter"));
    }
    Ok(())
}

pub(crate) async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
) -> Result<()> {
    if name != "createTask" {
        return reads::authorize(c, ctx, name, params).await;
    }
    authorize_create(c, ctx).await?;
    let workflow = id(body, "workflow_id")?;
    let row = c
        .query_opt("SELECT owner_id FROM workflows WHERE id=$1", &[&workflow])
        .await?
        .ok_or_else(Error::not_found)?;
    let resource = Resource::new("workflow", workflow, Some(row.get(0)));
    if !crate::policy::allows(c, ctx, "workflow.read", &resource).await? {
        return Err(Error::not_found());
    }
    Ok(())
}

async fn authorize_create(c: &(impl GenericClient + Sync), ctx: &Context) -> Result<()> {
    auth::authorize(
        c,
        ctx,
        "task.create",
        &Resource::new("task", "new", Some(ctx.subject)),
    )
    .await
}

pub(crate) async fn execute(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
    query: &str,
) -> Result<(Value, u16)> {
    if name == "createTask" {
        return Ok((create(c, ctx, body).await?, 201));
    }
    reads::execute(c, auth, ctx, name, params, query).await
}

async fn create(c: &(impl GenericClient + Sync), ctx: &Context, body: &Value) -> Result<Value> {
    if body["run_as"] == "service" {
        // The contract requires a separate service approval. A workflow or a
        // task.create grant never substitutes for that approval.
        return Err(Error::denied());
    }
    if body.get("service_account_id").is_some() {
        return Err(Error::invalid(
            "A user task cannot specify a service account",
        ));
    }
    let workflow = id(body, "workflow_id")?;
    let row = c
        .query_opt(
            "SELECT owner_id,spec,status FROM workflows WHERE id=$1 FOR SHARE",
            &[&workflow],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, String>("status") != "active" {
        return Err(Error::conflict("Workflow version is archived"));
    }
    let spec: Value = row.get("spec");
    validate("WorkflowSpec", &spec)?;
    reject_jsonb_nul(&body["input"])?;
    validate_business(&spec["input_schema"], &body["input"])?;
    let timeout = body
        .get("timeout_ms")
        .map(unsigned)
        .transpose()?
        .unwrap_or(86_400_000);
    let submitted: DateTime<Utc> = c.query_one("SELECT clock_timestamp()", &[]).await?.get(0);
    let deadline = submitted + Duration::milliseconds(timeout as i64);
    let workflow_resource = Resource::new("workflow", workflow, Some(row.get("owner_id")));
    let steps = spec["steps"].as_array().unwrap();
    let mut admissions = Vec::with_capacity(steps.len());
    for step in steps {
        if unsigned(&step["timeout_ms"])? > timeout {
            return Err(Error::invalid("Workflow step exceeds the task deadline"));
        }
        admissions.push(targets::resolve(c, ctx, step).await?);
    }

    // Freeze authority after all provider locks, which can outlive grant conditions.
    let mut workflow_paths = authority::freeze(c, ctx, "workflow.read", &workflow_resource).await?;
    let mut budget = 0;
    crate::plugin_catalog::reserve_authority_bytes(
        &mut budget,
        serde_json::to_vec(&workflow_paths)?.len(),
    )?;
    for bound in &mut admissions {
        for target in &mut bound.targets {
            let paths = authority::freeze(c, ctx, &target.action, &target.resource).await?;
            crate::plugin_catalog::reserve_authority_bytes(
                &mut budget,
                serde_json::to_vec(&paths)?.len(),
            )?;
            target.paths = paths;
        }
    }

    let target_paths = admissions
        .iter()
        .flat_map(|bound| &bound.targets)
        .flat_map(|target| &target.paths);
    let grant_ids: Vec<_> = workflow_paths
        .iter()
        .chain(target_paths)
        .flat_map(|path| path.sources.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let source_expiries = authority::source_expiries(c, ctx, &grant_ids).await?;
    authorize_create(c, ctx).await?;
    let authority_expires = deadline.min(authority::issuer_expiry(c, ctx).await?);
    let checked_at: DateTime<Utc> = c.query_one("SELECT clock_timestamp()", &[]).await?.get(0);
    if authority_expires <= checked_at {
        return Err(Error::new(
            "DEADLINE_EXCEEDED",
            "Task admission exceeded its live deadline",
            axum::http::StatusCode::GATEWAY_TIMEOUT,
        ));
    }
    let mut rules = BTreeMap::new();
    collect_live_rules(
        &mut workflow_paths,
        ctx,
        checked_at,
        &source_expiries,
        &mut rules,
    )?;
    for bound in &mut admissions {
        for target in &mut bound.targets {
            collect_live_rules(
                &mut target.paths,
                ctx,
                checked_at,
                &source_expiries,
                &mut rules,
            )?;
        }
    }
    let admission = json!({
        "version": 1,
        "peer": ctx.peer,
        "browser_origin": ctx.browser_origin,
        "credential_chain": ctx.chain,
        "workflow_paths": workflow_paths,
        "steps": admissions.iter().map(targets::StepAdmission::record).collect::<Vec<_>>(),
    });
    // Cap the full persisted record, including non-rule metadata.
    crate::plugin_catalog::reserve_authority_bytes(&mut 0, serde_json::to_vec(&admission)?.len())?;
    // This union is only the overall ceiling. Execution must also require the
    // chosen step's own targets and original sources, never a sibling's paths.
    let maximum_rules = Value::Array(rules.into_values().collect());
    let task = Uuid::new_v4();
    let delegation = Uuid::new_v4();
    c.execute(
        "INSERT INTO execution_delegations(id,subject_id,issuer_credential_id,maximum_rules,run_as,expires_at,status,created_at)
         VALUES($1,$2,$3,$4,'user',$5,'active',$6)",
        &[&delegation, &ctx.subject, &ctx.credential, &maximum_rules, &authority_expires, &submitted],
    ).await?;
    c.execute(
        "INSERT INTO tasks(id,owner_id,workflow_id,delegation_id,input,deadline_at,state,created_at,updated_at,admission)
         VALUES($1,$2,$3,$4,$5,$6,'queued',$7,$7,$8)",
        &[&task, &ctx.subject, &workflow, &delegation, &body["input"], &deadline, &submitted, &admission],
    ).await?;
    for (step, binding) in steps.iter().zip(&admissions) {
        let state = if step["depends_on"].as_array().unwrap().is_empty() {
            "ready"
        } else {
            "pending"
        };
        c.execute(
            "INSERT INTO task_steps(id,task_id,step_key,provider_deployment_id,state,created_at,updated_at)
             VALUES($1,$2,$3,$4,$5,$6,$6)",
            &[&Uuid::new_v4(), &task, &string(step, "id")?, &binding.deployment_id(), &state, &submitted],
        ).await?;
    }
    crate::plugin_catalog::read_task(c, task, None)
        .await?
        .ok_or_else(Error::not_found)
}

fn collect_live_rules(
    paths: &mut Vec<Path>,
    ctx: &Context,
    checked_at: DateTime<Utc>,
    source_expiries: &HashMap<Uuid, DateTime<Utc>>,
    rules: &mut BTreeMap<String, Value>,
) -> Result<()> {
    paths.retain(|path| {
        path.sources.iter().all(|grant| {
            source_expiries
                .get(grant)
                .is_some_and(|expiry| *expiry > checked_at)
        })
    });
    authority::retain_live_paths(paths, ctx, checked_at)?;
    for path in paths {
        rules
            .entry(serde_json::to_string(&path.rule)?)
            .or_insert_with(|| path.rule.clone());
    }
    Ok(())
}

/// Controller restart revokes short call authority. A submitted Task retains
/// its original, time-bounded proof for later revalidation.
pub(crate) async fn revoke_transient_delegations(c: &(impl GenericClient + Sync)) -> Result<()> {
    c.execute(
        "UPDATE execution_delegations e SET status='revoked' WHERE e.status='active'
         AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.delegation_id=e.id AND t.admission IS NOT NULL)",
        &[],
    ).await?;
    Ok(())
}
