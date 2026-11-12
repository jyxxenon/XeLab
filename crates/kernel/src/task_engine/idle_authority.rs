//! Reconcile idle Task authority independently of provider availability.
use super::{authority, IDLE_TASK};
use crate::{auth::Auth, db, error::Result};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) async fn pause_idle_unauthorized(
    tx: &Transaction<'_>,
    auth: &Auth,
    cursor: &mut Option<Uuid>,
) -> Result<u64> {
    db::auth_lock(tx, false).await?;
    let select = format!(
        "SELECT t.id,t.owner_id,t.workflow_id,t.admission,t.deadline_at,
                w.owner_id AS workflow_owner_id,e.issuer_credential_id,e.maximum_rules,
                e.subject_id AS delegation_subject,e.status AS delegation_status,
                e.expires_at AS delegation_expires_at,e.run_as AS delegation_run_as
         FROM tasks t JOIN workflows w ON w.id=t.workflow_id
         JOIN execution_delegations e ON e.id=t.delegation_id
         WHERE {IDLE_TASK} AND t.deadline_at>statement_timestamp()
           AND ($1::uuid IS NULL OR t.id>$1)
         ORDER BY t.id LIMIT 1 FOR UPDATE OF t SKIP LOCKED"
    );
    let Some(row) = tx.query_opt(&select, &[&*cursor]).await? else {
        *cursor = None;
        return Ok(0);
    };
    let task = row.get("id");
    // Move past a slow or unavailable proof even if its transaction must
    // roll back. The next sweep revisits it after the cursor wraps.
    *cursor = Some(task);
    let error = match authority::check_idle(tx, auth, &row).await {
        Ok(()) => return Ok(0),
        Err(error) if matches!(error.code, "PERMISSION_DENIED" | "INVALID_CREDENTIAL") => error,
        Err(error) => return Err(error),
    };
    // A Step may have changed between statement snapshot and row lock
    // acquisition. Time may also pass during proof evaluation.
    let update = format!(
        "UPDATE tasks t SET state='paused_authorization',error=$2,
                revision=revision+1,updated_at=clock_timestamp()
         WHERE t.id=$1 AND {IDLE_TASK} AND t.deadline_at>clock_timestamp()"
    );
    Ok(tx.execute(&update, &[&task, &error.detail()]).await?)
}
