//! Check persisted relationships without reactivating historical Task authority.
use crate::{
    auth::Resource,
    contracts::{self, id, string},
    error::{Error, Result},
    policy::Path,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, net::IpAddr};
use tokio_postgres::{GenericClient, Row};
use uuid::Uuid;

#[derive(Deserialize)]
struct Admission {
    version: u64,
    #[serde(rename = "peer")]
    _peer: IpAddr,
    #[serde(rename = "browser_origin")]
    _browser_origin: Option<String>,
    credential_chain: Vec<Uuid>,
    workflow_paths: Vec<Path>,
    steps: Vec<Binding>,
}

#[derive(Deserialize)]
struct Binding {
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

fn invalid_task() -> Error {
    Error::conflict("Historical Task admission or execution records differ")
}

pub(crate) async fn validate(c: &(impl GenericClient + Sync)) -> Result<()> {
    let live_on_terminal: bool = c
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM attempts a JOIN task_steps s ON s.id=a.step_id
                 JOIN tasks t ON t.id=s.task_id
                 WHERE a.state IN ('leased','running') AND
                       (s.state IN ('succeeded','failed','canceled') OR
                        t.state IN ('succeeded','failed','canceled'))
             ) OR EXISTS (
                 SELECT 1 FROM skill_batch_items i JOIN skill_batches b ON b.id=i.batch_id
                 WHERE i.state='running' AND b.state IN ('succeeded','partially_succeeded','failed','canceled')
             )",
            &[],
        )
        .await?
        .get(0);
    if live_on_terminal {
        return Err(Error::conflict(
            "Task admission ledger has a live attempt on a terminal step or a live batch item on a terminal batch",
        ));
    }

    let mut after: Option<Uuid> = None;
    loop {
        let rows = c.query(
            "SELECT id,name,spec FROM workflows WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 16",
            &[&after],
        ).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = Some(row.get("id"));
            let spec: Value = row.get("spec");
            let invalid = || Error::conflict("Historical Workflow specification is invalid");
            contracts::validate("WorkflowSpec", &spec).map_err(|_| invalid())?;
            contracts::compile_business(&spec["input_schema"]).map_err(|_| invalid())?;
            if spec["name"] != row.get::<_, String>("name") {
                return Err(invalid());
            }
        }
    }

    let mut after: Option<Uuid> = None;
    loop {
        let rows = c.query(
            "SELECT t.id,t.owner_id,t.workflow_id,t.delegation_id,t.admission,t.input,
                    w.spec,e.subject_id,e.issuer_credential_id,e.run_as,e.maximum_rules
             FROM tasks t JOIN workflows w ON w.id=t.workflow_id
             JOIN execution_delegations e ON e.id=t.delegation_id
             WHERE t.admission IS NOT NULL AND ($1::uuid IS NULL OR t.id>$1) ORDER BY t.id LIMIT 16",
            &[&after],
        ).await?;
        if rows.is_empty() {
            return crate::task_engine::validate_resolution_history(c).await;
        }
        for row in rows {
            after = Some(row.get("id"));
            validate_task(c, &row).await?;
        }
    }
}

async fn validate_task(c: &(impl GenericClient + Sync), task: &Row) -> Result<()> {
    let task_id: Uuid = task.get("id");
    let admission: Admission =
        serde_json::from_value(task.get("admission")).map_err(|_| invalid_task())?;
    let maximum: Value = task.get("maximum_rules");
    let rules = maximum.as_array().ok_or_else(invalid_task)?;
    let issuer: Option<Uuid> = task.get("issuer_credential_id");
    let workflow = Resource::new("workflow", task.get::<_, Uuid>("workflow_id"), None);
    if admission.version != 1
        || task.get::<_, Uuid>("owner_id") != task.get::<_, Uuid>("subject_id")
        || task.get::<_, String>("run_as") != "user"
        || issuer.is_none_or(|issuer| !admission.credential_chain.contains(&issuer))
        || !paths_match(
            &admission.workflow_paths,
            "workflow.read",
            &workflow.json(),
            rules,
        )
    {
        return Err(invalid_task());
    }
    let spec: Value = task.get("spec");
    contracts::validate_business(&spec["input_schema"], &task.get("input"))
        .map_err(|_| invalid_task())?;
    let steps: HashMap<_, _> = spec["steps"]
        .as_array()
        .ok_or_else(invalid_task)?
        .iter()
        .map(|step| Ok((string(step, "id")?, step)))
        .collect::<Result<_>>()?;
    let count = admission.steps.len();
    let bindings: HashMap<_, _> = admission
        .steps
        .into_iter()
        .map(|step| (step.step_key.clone(), step))
        .collect();
    let stored = c
        .query(
            "SELECT id,step_key,provider_deployment_id,attempt_count,fence,state,output
         FROM task_steps WHERE task_id=$1 LIMIT 65",
            &[&task_id],
        )
        .await?;
    if stored.len() != steps.len() || bindings.len() != count || count != steps.len() {
        return Err(invalid_task());
    }
    if stored
        .iter()
        .filter(|step| step.get::<_, &str>("state") == "running")
        .count()
        > 1
    {
        return Err(invalid_task());
    }
    for step in stored {
        let key: &str = step.get("step_key");
        let original = steps.get(key).ok_or_else(invalid_task)?;
        let binding = bindings.get(key).ok_or_else(invalid_task)?;
        if step.get::<_, Option<Uuid>>("provider_deployment_id") != binding.deployment_id {
            return Err(invalid_task());
        }
        let contract = validate_binding(c, original, binding, rules).await?;
        validate_attempts(c, task, &step, original, binding, &contract).await?;
    }
    Ok(())
}

fn paths_match(paths: &[Path], action: &str, resource: &Value, maximum: &[Value]) -> bool {
    !paths.is_empty()
        && paths.iter().all(|path| {
            path.rule["action"] == action
                && path.rule["resource"] == *resource
                && maximum.contains(&path.rule)
        })
}

async fn validate_binding(
    c: &(impl GenericClient + Sync),
    original: &Value,
    saved: &Binding,
    rules: &[Value],
) -> Result<Value> {
    if saved.deployment_id.is_some() != saved.installation_id.is_some() {
        return Err(invalid_task());
    }
    let mut targets = Vec::new();
    let (expected, contract) = if original.get("skill_id").is_some() {
        let skill = id(original, "skill_id")?;
        let installation = saved.installation_id.ok_or_else(invalid_task)?;
        let row = c.query_opt(
            "SELECT created_by,definition,definition_digest FROM skills WHERE id=$1 AND installation_id=$2",
            &[&skill,&installation],
        ).await?.ok_or_else(invalid_task)?;
        let definition: Value = row.get("definition");
        let digest: String = row.get("definition_digest");
        if crate::skills::definition_digest(&definition)? != digest {
            return Err(invalid_task());
        }
        targets.push((
            "skill.invoke".to_owned(),
            Resource::new("skill", skill, Some(row.get("created_by"))),
        ));
        match definition["target"]["kind"].as_str() {
            Some("capability") => {
                let contract = &definition["target"]["contract"];
                targets.push(capability_target(contract)?);
                (
                    json!({"kind":"skill_capability","skill_id":skill,"definition_digest":digest,"contract":contract}),
                    contract.clone(),
                )
            }
            Some("http") => {
                let deployment = saved.deployment_id.ok_or_else(invalid_task)?;
                // The deployment's current installation can differ after an upgrade.
                let owner = c
                    .query_opt(
                        "SELECT owner_id FROM deployments WHERE id=$1",
                        &[&deployment],
                    )
                    .await?
                    .ok_or_else(invalid_task)?
                    .get(0);
                let registry = crate::http_contracts::load(c, installation).await?;
                let operation = registry.bind_skill(&definition)?;
                let plugin = string(&definition["target"], "plugin_id")?;
                targets.push((
                    operation.route.action.clone(),
                    Resource::new("plugin", plugin, Some(owner)),
                ));
                (
                    json!({"kind":"skill_http","skill_id":skill,"definition_digest":digest,
                    "operation_id":operation.id,"http_contract_digest":operation.contract_digest,
                    "method":operation.method.as_str(),"path":operation.path}),
                    json!({"name":definition["name"],"version":definition["version"],"schema_digest":digest}),
                )
            }
            _ => return Err(invalid_task()),
        }
    } else {
        let contract = &original["contract"];
        if original.get("provider_deployment_id").is_some()
            && Some(id(original, "provider_deployment_id")?) != saved.deployment_id
        {
            return Err(invalid_task());
        }
        targets.push(capability_target(contract)?);
        let routing = if saved.deployment_id.is_some() {
            "fixed"
        } else {
            "stateless_direct"
        };
        (
            json!({"kind":"capability","contract":contract,"routing":routing}),
            contract.clone(),
        )
    };
    if saved.binding != expected || saved.targets.len() != targets.len() {
        return Err(invalid_task());
    }
    for (action, resource) in targets {
        let resource_json = resource.json();
        if !saved.targets.iter().any(|target| {
            target.action == action
                && target.resource == resource_json
                && target.owner_id == resource.owner
                && paths_match(&target.paths, &action, &resource_json, rules)
        }) {
            return Err(invalid_task());
        }
    }
    Ok(contract)
}

fn capability_target(contract: &Value) -> Result<(String, Resource)> {
    let key = format!(
        "{}@{}",
        string(contract, "name")?,
        string(contract, "version")?
    );
    Ok((
        "capability.invoke".to_owned(),
        Resource::new("capability", key, None),
    ))
}

async fn validate_attempts(
    c: &(impl GenericClient + Sync),
    task: &Row,
    step: &Row,
    original: &Value,
    binding: &Binding,
    contract: &Value,
) -> Result<()> {
    let step_id: Uuid = step.get("id");
    let attempts = c.query(
        "SELECT a.number,a.fence,a.state,a.idempotency_key,a.broker_call_id,a.dispatch_started,c.state AS call_state,
                c.owner_id AS call_owner,c.credential_id,c.delegation_id,c.skill_id,c.skill_definition_digest,
                c.contract,c.provider_instance_id,c.idempotency_key AS call_key,c.http_binding,c.result,
                i.deployment_id,i.generation
         FROM attempts a LEFT JOIN calls c ON c.id=a.broker_call_id
         LEFT JOIN instances i ON i.id=c.provider_instance_id
         WHERE a.step_id=$1 ORDER BY a.number LIMIT 6",
        &[&step_id],
    ).await?;
    let count: i32 = step.get("attempt_count");
    let step_fence: i64 = step.get("fence");
    let running = step.get::<_, String>("state") == "running";
    if count < 0
        || attempts.len() != count as usize
        || i64::from(count) > original["maximum_attempts"].as_i64().unwrap_or(1)
    {
        return Err(invalid_task());
    }
    let mut active = false;
    let mut last_fence = 0;
    let key = format!("task-step:{step_id}");
    for (index, attempt) in attempts.iter().enumerate() {
        let fence: i64 = attempt.get("fence");
        let state: &str = attempt.get("state");
        if attempt.get::<_, i32>("number") != index as i32 + 1
            || fence <= last_fence
            || fence > step_fence
            || attempt.get::<_, String>("idempotency_key") != key
        {
            return Err(invalid_task());
        }
        last_fence = fence;
        if matches!(state, "leased" | "running") {
            if active || fence != step_fence {
                return Err(invalid_task());
            }
            active = true;
        }
        if let Some(call) = attempt.get("broker_call_id") {
            if attempt.get::<_, Option<bool>>("dispatch_started") == Some(false)
                && (!matches!(
                    attempt.get::<_, Option<&str>>("call_state"),
                    Some("accepted" | "running" | "unknown")
                ) || attempt.get::<_, Option<Value>>("result").is_some())
            {
                return Err(invalid_task());
            }
            validate_call(task, step, attempt, binding, call, &key, contract)?;
        }
    }
    if running != active || step_fence < 0 {
        return Err(invalid_task());
    }
    Ok(())
}

fn validate_call(
    task: &Row,
    step: &Row,
    attempt: &Row,
    binding: &Binding,
    call: Uuid,
    key: &str,
    contract: &Value,
) -> Result<()> {
    let call_delegation: Option<Uuid> = attempt.get("delegation_id");
    let skill = id(&binding.binding, "skill_id").map_err(|_| invalid_task())?;
    let digest = string(&binding.binding, "definition_digest")?;
    let provider: Option<Uuid> = attempt.get("provider_instance_id");
    if attempt.get::<_, Option<Uuid>>("call_owner") != Some(task.get("owner_id"))
        || attempt.get::<_, Option<Uuid>>("credential_id")
            != task.get::<_, Option<Uuid>>("issuer_credential_id")
        || call_delegation.is_none_or(|id| id == task.get::<_, Uuid>("delegation_id"))
        || attempt.get::<_, Option<Uuid>>("skill_id") != Some(skill)
        || attempt.get::<_, Option<&str>>("skill_definition_digest") != Some(digest)
        || attempt.get::<_, Option<Value>>("contract").as_ref() != Some(contract)
        || provider.is_none()
        || attempt.get::<_, Option<Uuid>>("deployment_id") != binding.deployment_id
        || attempt.get::<_, Option<&str>>("call_key") != Some(key)
    {
        return Err(invalid_task());
    }
    let http: Option<Value> = attempt.get("http_binding");
    match binding.binding["kind"].as_str() {
        Some("skill_capability") if http.is_none() => (),
        Some("skill_http") => {
            let target = binding
                .targets
                .iter()
                .find(|target| target.resource["kind"] == "plugin")
                .ok_or_else(invalid_task)?;
            let expected = json!({"installation_id":binding.installation_id,"deployment_id":binding.deployment_id,
                "generation":attempt.get::<_, Option<i64>>("generation"),"operation_id":binding.binding["operation_id"],
                "http_contract_digest":binding.binding["http_contract_digest"],"method":binding.binding["method"],
                "path":binding.binding["path"],"required_action":target.action});
            if http != Some(expected) {
                return Err(invalid_task());
            }
        }
        _ => return Err(invalid_task()),
    }
    let succeeded = attempt.get::<_, Option<&str>>("call_state") == Some("succeeded");
    let attempt_succeeded = attempt.get::<_, &str>("state") == "succeeded";
    if attempt_succeeded && !succeeded {
        return Err(invalid_task());
    }
    if succeeded {
        let result: Value = attempt
            .get::<_, Option<Value>>("result")
            .ok_or_else(invalid_task)?;
        contracts::validate("CallResult", &result).map_err(|_| invalid_task())?;
        if id(&result, "call_id")? != call
            || Some(id(&result, "provider_instance_id")?) != provider
            || id(&result, "skill_id")? != skill
            || result["skill_definition_digest"] != digest
            || result.get("contract") != Some(contract)
            || (attempt_succeeded
                && step.get::<_, Option<Value>>("output").as_ref() != result.get("output"))
        {
            return Err(invalid_task());
        }
    }
    Ok(())
}
