//! Explicit unary failure replies and their fixed provider binding.
use crate::{
    api::App,
    auth::Context,
    broker_queue::Instance,
    error::{Error, Result},
    rpc,
};
use serde_json::Value;
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(super) const VERSION: u32 = 1;

pub(super) struct Binding {
    pub installation: Uuid,
    pub manifest_digest: String,
    pub has_proxy: bool,
}

pub(super) fn signed_capability(manifest: &Value, contract: &Value, spec: &Value) -> bool {
    manifest["capabilities"].as_array().is_some_and(|caps| {
        caps.iter().any(|cap| {
            cap["contract"] == *contract
                && [
                    "side_effect",
                    "input_schema",
                    "output_schema",
                    "stream_item_schema",
                    "maximum_input_bytes",
                    "maximum_output_bytes",
                ]
                .iter()
                .all(|field| cap[*field] == spec[*field])
        })
    })
}

impl Binding {
    pub(super) async fn verify(
        &self,
        tx: &Transaction<'_>,
        app: &App,
        provider: Instance,
        deployment: Uuid,
        contract: &rpc::ContractRef,
        definition: &Value,
    ) -> Result<()> {
        // Health publication and HostService lock deployment before instance.
        tx.query_opt(
            "SELECT id FROM deployments WHERE id=$1 AND installation_id=$2
                AND spec->>'enabled'='true' AND archived_at IS NULL FOR SHARE",
            &[&deployment, &self.installation],
        )
        .await?
        .ok_or_else(binding_changed)?;
        tx.query_opt(
            "SELECT id FROM instances WHERE id=$1 AND deployment_id=$2 AND generation=$3
                AND phase='ready' AND health='alive' FOR SHARE",
            &[&provider.id, &deployment, &provider.generation],
        )
        .await?
        .ok_or_else(binding_changed)?;
        let row = tx
            .query_opt(
                "SELECT n.manifest,c.spec FROM installations n
                JOIN publishers p ON p.id=n.publisher_id
                JOIN capability_contracts c ON c.name=$3 AND c.version=$4 AND c.schema_digest=$5
             WHERE n.id=$1 AND n.manifest_digest=$2 AND n.state='installed' AND p.status='trusted'
             FOR SHARE OF n,p,c",
                &[
                    &self.installation,
                    &self.manifest_digest,
                    &contract.name,
                    &contract.version,
                    &contract.schema_digest,
                ],
            )
            .await?
            .ok_or_else(binding_changed)?;
        let manifest: Value = row.get("manifest");
        if &row.get::<_, Value>("spec") != definition
            || !signed_capability(&manifest, &definition["contract"], definition)
        {
            return Err(binding_changed());
        }
        if self.has_proxy {
            crate::host_blobs::check_approval(tx, app, deployment, &manifest).await?;
        }
        Ok(())
    }
}

fn binding_changed() -> Error {
    Error::unavailable("Fixed provider binding changed before Call settlement")
}

pub(super) fn business_error(code: &str) -> Option<Error> {
    Some(match code {
        "INVALID_ARGUMENT" => Error::invalid("Plugin rejected the business input"),
        "PERMISSION_DENIED" => Error::denied(),
        "RESOURCE_NOT_FOUND" => Error::not_found(),
        "STATE_CONFLICT" => Error::conflict("Plugin rejected the current business state"),
        "RESOURCE_EXHAUSTED" => Error::exhausted(),
        _ => return None,
    })
}

pub(super) fn decode(
    reply: &rpc::InvokeResponse,
    call: Uuid,
    contract: &rpc::ContractRef,
    version: u32,
) -> Result<Option<Error>> {
    let Some(failure) = &reply.terminal_failure else {
        return Ok(None);
    };
    let invalid = || Error::conflict("Plugin returned an invalid terminal failure");
    if version != VERSION
        || failure.version != version
        || reply.call_id != call.to_string()
        || failure.contract.as_ref() != Some(contract)
        || !reply.output_json.is_empty()
        || !reply.output_digest.is_empty()
    {
        return Err(invalid());
    }
    Ok(Some(
        business_error(&failure.code)
            .ok_or_else(invalid)?
            .with_resource(call),
    ))
}

pub(super) async fn record(
    tx: &Transaction<'_>,
    ctx: &Context,
    call: Uuid,
    path: &str,
    key: &str,
    error: &Error,
) -> Result<()> {
    // An HTTP status on this exact unary idempotency record marks the
    // sanitized terminal response. QueryResult's older failure rows lack it.
    let status = i32::from(error.status.as_u16());
    let changed = tx
        .execute(
            "UPDATE idempotency_records SET response_status=$6
          WHERE subject_id=$1 AND credential_id=$2 AND method='POST' AND path=$3 AND key=$4
            AND resource_id=$5",
            &[
                &ctx.subject,
                &ctx.credential,
                &path,
                &key,
                &call.to_string(),
                &status,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(Error::conflict("Missing Call idempotency record"));
    }
    Ok(())
}

pub(crate) fn replay(call: Uuid, detail: Option<Value>, status: i32) -> Result<Error> {
    let invalid = || Error::conflict("Saved terminal failure is unavailable").with_resource(call);
    let detail = detail.ok_or_else(invalid)?;
    let code = detail["code"].as_str().ok_or_else(invalid)?;
    let error = business_error(code)
        .ok_or_else(invalid)?
        .with_resource(call);
    if status != i32::from(error.status.as_u16()) || detail != error.detail() {
        return Err(invalid());
    }
    Ok(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_failure_must_match_the_negotiated_call_and_contract() {
        let call = Uuid::new_v4();
        let contract = rpc::ContractRef {
            name: "test.echo".into(),
            version: "1.0.0".into(),
            schema_digest: crate::contracts::digest(b"fixture"),
        };
        let failure = rpc::InvokeFailure {
            version: VERSION,
            contract: Some(contract.clone()),
            code: "RESOURCE_EXHAUSTED".into(),
        };
        let mut reply = rpc::InvokeResponse {
            call_id: call.to_string(),
            terminal_failure: Some(failure.clone()),
            ..Default::default()
        };
        let error = decode(&reply, call, &contract, VERSION).unwrap().unwrap();
        assert_eq!(error.code, "RESOURCE_EXHAUSTED");
        assert_eq!(error.resource_id, Some(call.to_string()));
        assert!(decode(&reply, call, &contract, 0).is_err());
        assert!(decode(&reply, Uuid::new_v4(), &contract, VERSION).is_err());
        let mut wrong_contract = contract.clone();
        wrong_contract.schema_digest = crate::contracts::digest(b"other fixture");
        assert!(decode(&reply, call, &wrong_contract, VERSION).is_err());

        reply.terminal_failure.as_mut().unwrap().version = VERSION + 1;
        assert!(decode(&reply, call, &contract, VERSION).is_err());
        reply.terminal_failure = Some(failure);
        reply.terminal_failure.as_mut().unwrap().code = "OUTCOME_UNKNOWN".into();
        assert!(decode(&reply, call, &contract, VERSION).is_err());
        reply.terminal_failure.as_mut().unwrap().code = "RESOURCE_EXHAUSTED".into();
        reply.output_digest = crate::contracts::digest(b"null");
        assert!(decode(&reply, call, &contract, VERSION).is_err());
        reply.terminal_failure = None;
        assert!(decode(&reply, call, &contract, VERSION).unwrap().is_none());
    }
}
