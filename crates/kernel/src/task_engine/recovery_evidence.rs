//! Match a settled Call to the evidence frozen at Task admission.
use super::MAX_STEP_JSON_BYTES;
use crate::{
    auth::Resource,
    contracts::{id, reject_jsonb_nul, string, unsigned, validate, validate_business},
    error::{Error, Result},
};
use serde_json::{json, Value};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(super) struct RecordedAttempt<'a> {
    pub(super) owner: Uuid,
    pub(super) issuer: Uuid,
    pub(super) task_delegation: Uuid,
    pub(super) deployment: Uuid,
    pub(super) step_key: &'a str,
    pub(super) admission: &'a Value,
    pub(super) idempotency_key: &'a str,
    pub(super) call: Uuid,
}

fn conflict() -> Error {
    Error::conflict("Linked Broker Call does not prove the requested Task outcome")
}

fn invalid_proof(error: Error) -> Error {
    match error.code {
        "INVALID_ARGUMENT" | "RESOURCE_NOT_FOUND" | "PERMISSION_DENIED" | "STATE_CONFLICT" => {
            conflict()
        }
        _ => error,
    }
}

pub(super) async fn verified_output(
    tx: &Transaction<'_>,
    attempt: RecordedAttempt<'_>,
) -> Result<Value> {
    let call = attempt.call;
    let proof = verified_call(tx, &attempt, true).await?;
    let mut result: Value = proof
        .row
        .get::<_, Option<Value>>("result")
        .ok_or_else(conflict)?;
    validate("CallResult", &result).map_err(invalid_proof)?;
    if id(&result, "call_id").map_err(invalid_proof)? != call
        || id(&result, "provider_instance_id").map_err(invalid_proof)?
            != proof.row.get::<_, Uuid>("provider_instance_id")
        || id(&result, "skill_id").map_err(invalid_proof)? != proof.row.get::<_, Uuid>("skill_id")
        || result["skill_definition_digest"] != proof.digest
        || result["contract"] != proof.contract
        || result.get("micro_plugin_id").is_some()
    {
        return Err(conflict());
    }
    let output = result
        .as_object_mut()
        .and_then(|result| result.remove("output"))
        .ok_or_else(conflict)?;
    if serde_json::to_vec(&output)?.len() > proof.maximum {
        return Err(conflict());
    }
    reject_jsonb_nul(&output).map_err(invalid_proof)?;
    validate_business(&proof.definition["output_schema"], &output).map_err(invalid_proof)?;
    Ok(output)
}

pub(super) async fn verified_nonexecution(
    tx: &Transaction<'_>,
    attempt: RecordedAttempt<'_>,
) -> Result<()> {
    verified_call(tx, &attempt, false).await?;
    Ok(())
}

struct VerifiedCall {
    row: Row,
    definition: Value,
    digest: String,
    contract: Value,
    maximum: usize,
}

async fn verified_call(
    tx: &Transaction<'_>,
    attempt: &RecordedAttempt<'_>,
    succeeded: bool,
) -> Result<VerifiedCall> {
    let frozen = frozen_step(attempt)?;
    let rows = tx.query(
        "SELECT c.contract,c.result,c.provider_instance_id,c.skill_id,c.http_binding,
                s.created_by AS skill_owner,s.definition,s.definition_digest,s.installation_id,
                n.manifest,d.owner_id AS deployment_owner,g.generation
         FROM calls c JOIN instances i ON i.id=c.provider_instance_id
         JOIN deployments d ON d.id=i.deployment_id
         JOIN skills s ON s.id=c.skill_id AND s.definition_digest=c.skill_definition_digest AND s.source_kind='oci'
         JOIN installations n ON n.id=s.installation_id
         JOIN execution_delegations e ON e.id=c.delegation_id
         JOIN rpc_delegations g ON g.execution_delegation_id=e.id AND g.call_id=c.id
           AND g.instance_id=i.id AND g.subject_id=c.owner_id AND g.issuer_credential_id=c.credential_id
           AND g.parent_rpc_delegation_id IS NULL
         JOIN reservations r ON r.id=c.id AND r.kind='call' AND r.account_id=c.owner_id
         JOIN attempts a ON a.broker_call_id=c.id
         WHERE c.id=$1 AND c.owner_id=$2 AND c.credential_id=$3 AND c.delegation_id<>$4
           AND d.id=$5 AND c.idempotency_key=$6 AND c.parent_call_id IS NULL
           AND c.micro_plugin_id IS NULL AND c.extension_plugin_id IS NULL
           AND e.subject_id=c.owner_id AND e.issuer_credential_id=c.credential_id AND e.run_as='user'
           AND r.status='released'
           AND (CASE WHEN $7::boolean THEN
                c.state='succeeded' AND c.completed_at IS NOT NULL AND c.error IS NULL
                  AND a.dispatch_started IS DISTINCT FROM FALSE
              ELSE c.state='unknown' AND c.result IS NULL AND c.completed_at IS NULL
                  AND a.dispatch_started IS FALSE
                  AND NOT EXISTS (
                    SELECT 1 FROM host_call_tickets ticket
                    JOIN host_child_calls child ON child.ticket_id=ticket.id
                    WHERE ticket.parent_call_id=c.id
                  )
              END)
         LIMIT 2",
        &[&attempt.call,&attempt.owner,&attempt.issuer,&attempt.task_delegation,
          &attempt.deployment,&attempt.idempotency_key,&succeeded],
    ).await?;
    let Ok([row]) = <[_; 1]>::try_from(rows) else {
        return Err(conflict());
    };

    let skill: Uuid = row.get("skill_id");
    let definition: Value = row.get("definition");
    let digest: String = row.get("definition_digest");
    let installation: Uuid = row.get("installation_id");
    let contract: Value = row.get("contract");
    let manifest: Value = row.get("manifest");
    if id(frozen, "installation_id").map_err(invalid_proof)? != installation
        || id(&frozen["binding"], "skill_id").map_err(invalid_proof)? != skill
        || frozen["binding"]["definition_digest"] != digest
        || crate::skills::definition_digest(&definition).map_err(invalid_proof)? != digest
        || frozen["targets"]
            .as_array()
            .is_none_or(|targets| targets.len() != 2)
        || !has_target(
            frozen,
            "skill.invoke",
            &Resource::new("skill", skill, Some(row.get("skill_owner"))),
        )
    {
        return Err(conflict());
    }

    let maximum = match definition["target"]["kind"].as_str() {
        Some("capability") => {
            crate::skills::candidate_binding(tx, installation, &manifest, &definition)
                .await
                .map_err(invalid_proof)?;
            capability_binding(&row, frozen, &definition, &manifest, &contract)?
        }
        Some("http") => {
            if !definition["stream_item_schema"].is_null()
                || !manifest["skills"]
                    .as_array()
                    .is_some_and(|skills| skills.contains(&definition))
            {
                return Err(conflict());
            }
            let registry = crate::http_contracts::load(tx, installation)
                .await
                .map_err(invalid_proof)?;
            let operation = registry.bind_skill(&definition).map_err(invalid_proof)?;
            http_binding(&row, frozen, &definition, &contract, &digest, operation)?;
            MAX_STEP_JSON_BYTES
        }
        _ => return Err(conflict()),
    };

    Ok(VerifiedCall {
        row,
        definition,
        digest,
        contract,
        maximum,
    })
}

fn frozen_step<'a>(attempt: &RecordedAttempt<'a>) -> Result<&'a Value> {
    let mut matches = attempt.admission["steps"]
        .as_array()
        .ok_or_else(conflict)?
        .iter()
        .filter(|step| step["step_key"] == attempt.step_key);
    let frozen = matches.next().ok_or_else(conflict)?;
    if attempt.admission["version"] != 1
        || matches.next().is_some()
        || id(frozen, "deployment_id").map_err(invalid_proof)? != attempt.deployment
    {
        return Err(conflict());
    }
    Ok(frozen)
}

fn has_target(frozen: &Value, action: &str, resource: &Resource) -> bool {
    frozen["targets"].as_array().is_some_and(|targets| {
        targets.iter().any(|target| {
            target["action"] == action
                && target["resource"] == resource.json()
                && target.get("owner_id") == Some(&json!(resource.owner))
        })
    })
}

fn capability_binding(
    row: &Row,
    frozen: &Value,
    definition: &Value,
    manifest: &Value,
    contract: &Value,
) -> Result<usize> {
    let frozen_binding = &frozen["binding"];
    if frozen_binding["kind"] != "skill_capability"
        || frozen_binding["contract"] != *contract
        || definition["target"]["contract"] != *contract
        || row.get::<_, Option<Value>>("http_binding").is_some()
    {
        return Err(conflict());
    }
    let name = string(contract, "name").map_err(invalid_proof)?;
    let version = string(contract, "version").map_err(invalid_proof)?;
    if !has_target(
        frozen,
        "capability.invoke",
        &Resource::new("capability", format!("{name}@{version}"), None),
    ) {
        return Err(conflict());
    }
    let signed = manifest["capabilities"]
        .as_array()
        .and_then(|caps| caps.iter().find(|cap| cap["contract"] == *contract))
        .ok_or_else(conflict)?;
    let limit = unsigned(&signed["maximum_output_bytes"]).map_err(invalid_proof)?;
    Ok(limit.min(MAX_STEP_JSON_BYTES as u64) as usize)
}

fn http_binding(
    row: &Row,
    frozen: &Value,
    definition: &Value,
    contract: &Value,
    digest: &str,
    operation: &crate::plugin_http::Operation,
) -> Result<()> {
    let binding = &frozen["binding"];
    let plugin = string(&definition["target"], "plugin_id").map_err(invalid_proof)?;
    if binding["kind"] != "skill_http"
        || binding["operation_id"] != operation.id
        || binding["http_contract_digest"] != operation.contract_digest
        || binding["method"] != operation.method.as_str()
        || binding["path"] != operation.path
        || !has_target(
            frozen,
            &operation.route.action,
            &Resource::new("plugin", plugin, Some(row.get("deployment_owner"))),
        )
        || *contract
            != json!({"name":definition["name"],"version":definition["version"],"schema_digest":digest})
    {
        return Err(conflict());
    }
    let expected = json!({
        "installation_id":frozen["installation_id"], "deployment_id":frozen["deployment_id"],
        "generation":row.get::<_,i64>("generation"), "required_action":operation.route.action,
        "operation_id":operation.id,"http_contract_digest":operation.contract_digest,
        "method":operation.method.as_str(),"path":operation.path,
    });
    if row.get::<_, Option<Value>>("http_binding").as_ref() != Some(&expected) {
        return Err(conflict());
    }
    Ok(())
}
