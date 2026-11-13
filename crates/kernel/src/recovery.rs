//! Authority reset for an offline, imported snapshot. Old passwords, sessions,
//! keys and source graphs must not become live merely by rewinding metadata.
use crate::{
    auth,
    config::require_host_admin,
    contracts::{string, validate},
    db,
    error::{Error, Result},
    identity,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Host-only entrypoint. The caller owns the exclusive host/database leases and
/// a transaction. An importing recovery gate is also required in the database.
pub async fn reset_restored_authority(
    c: &Transaction<'_>,
    owner: Uuid,
    password: &str,
    recovery: Uuid,
) -> Result<()> {
    require_host_admin()?;
    reset_rows(c, owner, password, recovery).await
}
pub(crate) async fn reset_rows(
    c: &Transaction<'_>,
    owner: Uuid,
    password: &str,
    recovery: Uuid,
) -> Result<()> {
    db::auth_lock(c, true).await?;
    let gate=c.query_opt("SELECT backup_id FROM platform_recovery_state WHERE recovery_id=$1 AND phase='importing' FOR UPDATE",&[&recovery]).await?.ok_or_else(||Error::conflict("No matching imported recovery session"))?;
    let backup: Uuid = gate.get(0);
    let account=c.query_opt("SELECT password_hash FROM accounts WHERE id=$1 AND kind='user' AND parent_id IS NULL AND independent_owner AND status<>'archived' FOR UPDATE",&[&owner]).await?.ok_or_else(||Error::invalid("Recovery Owner must be an existing independent root user"))?;
    let previous: Option<String> = account.get(0);
    let password = Zeroizing::new(password.to_owned());
    let hashed = auth::password_work(move || -> Result<String> {
        if previous
            .as_deref()
            .and_then(|p| PasswordHash::new(p).ok())
            .is_some_and(|old| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &old)
                    .is_ok()
            })
        {
            return Err(Error::invalid(
                "Recovery password must differ from the snapshot password",
            ));
        }
        auth::password_hash(&password)
    })
    .await?;
    c.execute(
        "UPDATE credentials SET status='revoked',revision=revision+1,updated_at=now()",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE grants SET status='revoked',revision=revision+1,updated_at=now()",
        &[],
    )
    .await?;
    c.execute("DELETE FROM recovery_owner_anchors", &[]).await?;
    c.execute("UPDATE recovered_account_activations SET state='revoked',updated_at=now() WHERE state='pending'", &[]).await?;
    c.execute("UPDATE accounts SET status=CASE WHEN status='archived' THEN status ELSE 'disabled' END,password_hash=NULL,activation_digest=NULL,activation_expires_at=NULL,authz_revision=authz_revision+1,revision=revision+1,updated_at=now()",&[]).await?;
    c.execute("UPDATE inheritance_grants SET mode='all_snapshot',maximum_rules='[]',issuer_credential_id=NULL,revision=revision+1,updated_at=now()",&[]).await?;
    c.execute("DELETE FROM grant_provenance", &[]).await?;
    // Route contracts survive; old approval authority does not. Restored HTTP
    // deployments require an explicit approval from the fresh source graph.
    c.execute("DELETE FROM plugin_http_approvals", &[]).await?;
    c.execute("DELETE FROM plugin_http_requests", &[]).await?;
    c.execute(
        "UPDATE execution_delegations SET status='revoked' WHERE status='active'",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE rpc_delegations SET status='revoked' WHERE status='active'",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE host_call_tickets SET expires_at=least(expires_at,clock_timestamp())",
        &[],
    )
    .await?;
    c.execute("UPDATE dependency_bindings SET expires_at=least(coalesce(expires_at,clock_timestamp()),clock_timestamp()) WHERE bound_call IS NOT NULL", &[]).await?;
    crate::oauth::reset_authority(c).await?;
    crate::events::snapshot::reset_authority(c).await?;
    c.execute(
        "UPDATE clients SET status='disabled',revision=revision+1,updated_at=now()",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE authorization_requests SET status='denied' WHERE status IN ('pending','approved')",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE secrets SET status='revoked',revision=revision+1,updated_at=now()",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE secret_bindings SET status='revoked',revision=revision+1,updated_at=now()",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE secret_leases SET expires_at=least(expires_at,now())",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE publishers SET status='revoked',revision=revision+1,updated_at=now()",
        &[],
    )
    .await?;
    c.execute("UPDATE deployments SET spec=jsonb_set(spec,'{enabled}','false'),phase='disabled',revision=revision+1,updated_at=now()",&[]).await?;
    c.execute("UPDATE instances SET phase='stopped',runtime_id=NULL,health='unknown',revision=revision+1,updated_at=now()",&[]).await?;
    c.execute(
        "UPDATE provider_records SET availability='unavailable'",
        &[],
    )
    .await?;
    c.execute("DELETE FROM volume_attachments", &[]).await?;
    c.execute("DELETE FROM volume_mount_approvals", &[]).await?;
    c.execute("DELETE FROM host_proxy_approvals", &[]).await?;
    c.execute("UPDATE volumes SET writer_instance_id=NULL,write_fence=write_fence+1,state=CASE WHEN state IN ('full','deleting','deleted') THEN state ELSE 'available' END,revision=revision+1,updated_at=now()",&[]).await?;
    let unknown = Error::conflict("Recovered snapshot cannot replay unfinished work").detail();
    c.execute(
        "UPDATE calls SET state='unknown',error=$1 WHERE state IN ('accepted','running')",
        &[&unknown],
    )
    .await?;
    crate::task_engine::reconcile_stopped(c).await?;
    let paused = Error::new(
        "PERMISSION_DENIED",
        "Task execution authority was revoked during platform recovery",
        axum::http::StatusCode::FORBIDDEN,
    )
    .detail();
    c.execute(
        "UPDATE tasks SET state='paused_authorization',error=$1,revision=revision+1,
                updated_at=clock_timestamp() WHERE state IN ('queued','running','waiting_dependency')",
        &[&paused],
    )
    .await?;
    c.execute("UPDATE operations SET state='failed',error=$1,revision=revision+1,updated_at=now() WHERE state IN ('pending','running','cancel_requested')",&[&unknown]).await?;
    c.execute("UPDATE reservations SET status='released'", &[])
        .await?;
    crate::task_engine::finish_stopped_cancellations(c).await?;
    c.execute("UPDATE node_budget SET admission_enabled=false,reserved_cpu_millis=0,reserved_memory_bytes=0,revision=revision+1,updated_at=now()",&[]).await?;
    c.execute("UPDATE quotas SET concurrent_calls_used=0,api_keys_used=0,revision=revision+1,updated_at=now()",&[]).await?;
    c.execute("DELETE FROM idempotency_records", &[]).await?;
    c.execute("UPDATE storage_recovery_jobs SET state='failed',failure=coalesce(failure,$1),updated_at=now() WHERE state NOT IN ('succeeded','failed')",&[&unknown]).await?;
    c.execute("UPDATE deployment_upgrade_jobs SET state='failed',failure=coalesce(failure,$1),updated_at=now() WHERE state NOT IN ('succeeded','failed')",&[&unknown]).await?;
    c.execute("UPDATE volume_schema_jobs SET state='failed',failure=coalesce(failure,$1),updated_at=now() WHERE state NOT IN ('verified','failed')",&[&unknown]).await?;
    c.execute("UPDATE backups SET state='failed',revision=revision+1,updated_at=now() WHERE state='creating'",&[]).await?;
    c.execute("DELETE FROM volume_holds", &[]).await?;
    c.execute("DELETE FROM deployment_storage_holds", &[])
        .await?;
    // Permission definitions are code-owned, never authority imported from a
    // historical/tampered table. Groups remain data but all old grants are inert.
    let definitions: Value =
        serde_json::from_str(include_str!("../../../docs/contracts/permissions.json"))?;
    c.execute("DELETE FROM permission_definitions", &[]).await?;
    let mut kinds = BTreeSet::new();
    for (action, spec) in definitions["definitions"]
        .as_object()
        .ok_or_else(|| Error::unavailable("Permission definitions are invalid"))?
    {
        c.execute("INSERT INTO permission_definitions(action,resource_kinds,description,self_service) VALUES($1,$2,$3,$4) ON CONFLICT(action) DO UPDATE SET resource_kinds=$2,description=$3,self_service=$4",&[action,&spec["resource_kinds"],&string(spec,"description")?,&spec["self_service"].as_bool().unwrap_or(false)]).await?;
        for kind in spec["resource_kinds"]
            .as_array()
            .ok_or_else(|| Error::unavailable("Permission kinds are invalid"))?
        {
            kinds.insert(
                kind.as_str()
                    .ok_or_else(|| Error::unavailable("Permission kind is invalid"))?
                    .to_owned(),
            );
        }
    }
    auth::seed_roles(c).await?;
    c.execute("UPDATE accounts SET status='active',password_hash=$2,expires_at=NULL,revision=revision+1,updated_at=now() WHERE id=$1",&[&owner,&hashed]).await?;
    for kind in kinds {
        let grant = Uuid::new_v4();
        let scope = json!({"kind":kind,"match":"all"});
        validate("ResourceSelector", &scope)?;
        c.execute("INSERT INTO grants(id,subject_id,issuer_id,role_id,scope,status,created_at,updated_at) VALUES($1,$2,$2,'Owner',$3,'active',now(),now())",&[&grant,&owner,&scope]).await?;
        c.execute(
            "INSERT INTO recovery_owner_anchors(grant_id,account_id,recovery_id) VALUES($1,$2,$3)",
            &[&grant, &owner, &recovery],
        )
        .await?;
    }
    identity::refresh_quotas(c).await?;
    c.execute("UPDATE platform_recovery_state SET phase='rebuilding',recovery_owner_id=$2,updated_at=now() WHERE recovery_id=$1",&[&recovery,&owner]).await?;
    db::audit(
        c,
        owner,
        None,
        recovery,
        "backup.restore",
        &auth::Resource::new("backup", backup, None).json(),
        "succeeded",
        "OFFLINE_AUTHORITY_RESET",
    )
    .await?;
    Ok(())
}

/// Offline recovery never carries private Broker tickets or transient routing
/// handles into a fresh host. Historical rows remain available for audit.
pub(crate) async fn ensure_m4_authority_reset(c: &(impl GenericClient + Sync)) -> Result<()> {
    let unsafe_state: bool = c.query_one("SELECT EXISTS(SELECT 1 FROM host_call_tickets WHERE expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM dependency_bindings WHERE bound_call IS NOT NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()))", &[]).await?.get(0);
    if unsafe_state {
        return Err(Error::conflict(
            "Historical Host ticket or request binding survived recovery",
        ));
    }
    Ok(())
}

pub(crate) async fn ensure_task_authority_reset(c: &(impl GenericClient + Sync)) -> Result<()> {
    let active: bool = c
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM attempts WHERE state IN ('leased','running'))
               OR EXISTS(SELECT 1 FROM tasks WHERE state IN ('queued','running','waiting_dependency','cancel_requested'))
               OR EXISTS(SELECT 1 FROM tasks t JOIN execution_delegations e ON e.id=t.delegation_id
                         WHERE e.status='active')",
            &[],
        )
        .await?
        .get(0);
    if active {
        return Err(Error::conflict(
            "Historical Task execution survived recovery",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
