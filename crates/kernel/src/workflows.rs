//! Immutable workflow definitions and their publication lifecycle.
use crate::{
    api::{path_id, read_object},
    auth::{self, Auth, Context, Resource},
    contracts::{compile_business, id, string, unsigned},
    error::{Error, Result},
};
use axum::http::HeaderMap;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio_postgres::GenericClient;

mod store;

pub(crate) fn handles(name: &str) -> bool {
    matches!(
        name,
        "createWorkflow" | "getWorkflow" | "listWorkflows" | "archiveWorkflow"
    )
}

pub(crate) fn validate_query(name: &str, query: &str) -> Result<()> {
    if handles(name) && name != "listWorkflows" && !query.is_empty() {
        return Err(Error::invalid("Unexpected workflow query parameter"));
    }
    Ok(())
}

pub(crate) async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
) -> Result<()> {
    match name {
        "listWorkflows" => Ok(()), // The catalog filters each object by its current owner and policy.
        "createWorkflow" => {
            auth::authorize(
                c,
                ctx,
                "workflow.create",
                &Resource::new("workflow", "new", Some(ctx.subject)),
            )
            .await
        }
        "getWorkflow" | "archiveWorkflow" => {
            let workflow = path_id(params, "workflow_id")?;
            let owner = store::owner(c, workflow).await?;
            let reading = name == "getWorkflow";
            let resource = Resource::new("workflow", workflow, Some(owner));
            let result = auth::authorize(
                c,
                ctx,
                if reading {
                    "workflow.read"
                } else {
                    "workflow.archive"
                },
                &resource,
            )
            .await;
            if result
                .as_ref()
                .is_err_and(|error| error.code == "PERMISSION_DENIED")
                && (reading || !crate::policy::allows(c, ctx, "workflow.read", &resource).await?)
            {
                return Err(Error::not_found());
            }
            result
        }
        _ => Err(Error::not_found()),
    }
}

async fn validate_targets(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    spec: &Value,
) -> Result<()> {
    for step in spec["steps"].as_array().unwrap() {
        if step.get("skill_id").is_some() {
            let skill = crate::skills::resolve_for_workflow(c, ctx, id(step, "skill_id")?).await?;
            if unsigned(&step["timeout_ms"])? > unsigned(&skill.definition["maximum_timeout_ms"])? {
                return Err(Error::invalid("Workflow step exceeds the Skill timeout"));
            }
            let target = &skill.definition["target"];
            if target["kind"] == "capability" {
                validate_contract(c, &target["contract"]).await?;
            }
        } else {
            let contract = &step["contract"];
            validate_contract(c, contract).await?;
            let fixed = step
                .get("provider_deployment_id")
                .map(|_| id(step, "provider_deployment_id"))
                .transpose()?;
            let installation: Option<uuid::Uuid> = if let Some(deployment) = fixed {
                // Keep the validated installation attached through publication.
                let row = c.query_opt(
                    "SELECT installation_id,owner_id FROM deployments WHERE id=$1 AND archived_at IS NULL FOR SHARE",
                    &[&deployment],
                ).await?.ok_or_else(Error::not_found)?;
                if !crate::policy::allows(
                    c,
                    ctx,
                    "plugin.read",
                    &Resource::new("deployment", deployment, Some(row.get("owner_id"))),
                )
                .await?
                {
                    return Err(Error::not_found());
                }
                Some(row.get(0))
            } else {
                None
            };
            let capability = json!({"capabilities": [{"contract": contract}]});
            let direct: Option<bool> = c
                .query_one(
                    "SELECT bool_or(coalesce(i.manifest->>'business_entry','direct')='direct')
                 FROM installations i JOIN publishers p ON p.id=i.publisher_id
                 WHERE i.state='installed' AND p.status='trusted' AND i.manifest @> $1::jsonb
                   AND ($2::uuid IS NULL OR i.id=$2)",
                    &[&capability, &installation],
                )
                .await?
                .get(0);
            match direct {
                Some(true) => (),
                Some(false) => return Err(Error::denied()),
                None => return Err(Error::not_found()),
            }
        }
    }
    Ok(())
}

pub(crate) async fn validate_contract(
    c: &(impl GenericClient + Sync),
    contract: &Value,
) -> Result<()> {
    let name = string(contract, "name")?;
    let version = string(contract, "version")?;
    let row = c
        .query_opt(
            "SELECT schema_digest FROM capability_contracts WHERE name=$1 AND version=$2",
            &[&name, &version],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, String>(0) != string(contract, "schema_digest")? {
        return Err(Error::conflict("Capability digest differs"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Shared HTTP dispatch inputs.
pub(crate) async fn execute(
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
        "createWorkflow" => {
            compile_business(&body["input_schema"])?;
            validate_targets(c, ctx, body).await?;
            Ok((store::publish(c, ctx.subject, body).await?, 201))
        }
        "getWorkflow" => Ok((
            read_object(c, "workflows", path_id(params, "workflow_id")?, "Workflow").await?,
            200,
        )),
        "listWorkflows" => crate::plugin_catalog::execute(c, auth, ctx, name, query).await,
        "archiveWorkflow" => {
            store::archive(c, path_id(params, "workflow_id")?, headers).await?;
            Ok((Value::Null, 204))
        }
        _ => Err(Error::not_found()),
    }
}
