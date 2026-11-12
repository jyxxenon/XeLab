//! Task cancellation fences dispatch and waits for the Broker's physical ledger.
use super::{clock, recovery_evidence, set_attempt, set_step, step_event};
use crate::{
    auth::{Context, Resource},
    contracts::reject_jsonb_nul,
    db,
    error::{Error, Result},
};
use axum::http::{HeaderMap, StatusCode};
use serde_json::{json, Value};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

// Start from every journaled Attempt, including completed predecessors. A
// successful parent Call can still have a child whose reservation is active.
const CALL_TREE: &str = "WITH RECURSIVE tree(id) AS (
    SELECT a.broker_call_id FROM task_steps s JOIN attempts a ON a.step_id=s.id
    WHERE s.task_id=t.id AND a.broker_call_id IS NOT NULL
    UNION
    SELECT child.child_call_id FROM tree
    JOIN host_call_tickets ticket ON ticket.parent_call_id=tree.id
    JOIN host_child_calls child ON child.ticket_id=ticket.id AND child.parent_call_id=tree.id
)";
const CALL_UNSETTLED: &str =
    "c.state IN ('accepted','running') OR r.status IS DISTINCT FROM 'released'";
const CANCELLATION_BATCH: i64 = 16;

pub(crate) async fn cancel_task(
    tx: &Transaction<'_>,
    ctx: &Context,
    task_id: Uuid,
    body: &Value,
    headers: &HeaderMap,
) -> Result<Value> {
    db::call_lock(tx).await?;
    let task = tx
        .query_opt(
            "SELECT t.owner_id,t.state,t.revision,t.error,t.admission,t.delegation_id,e.issuer_credential_id
             FROM tasks t
             JOIN execution_delegations e ON e.id=t.delegation_id
             WHERE t.id=$1 FOR UPDATE OF t",
            &[&task_id],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    let resource = Resource::new("task", task_id, Some(task.get("owner_id")));
    crate::tasks::authorize_cancellation(tx, ctx, &resource).await?;
    crate::api::etag(headers, task.get("revision"))?;
    reject_jsonb_nul(body)?;
    match task.get::<_, &str>("state") {
        "cancel_requested" | "canceled" => {
            return crate::api::read_object(tx, "tasks", task_id, "Task").await;
        }
        "succeeded" | "failed" => return Err(Error::conflict("Task is already terminal")),
        _ => {}
    }
    let active = tx
        .query(
            "SELECT a.id,a.state,a.broker_call_id,a.idempotency_key,a.fence,a.number,
                    s.id AS step_id,s.step_key,s.state AS step_state,s.fence AS step_fence,
                    s.attempt_count,s.provider_deployment_id
             FROM task_steps s JOIN attempts a ON a.step_id=s.id
             WHERE s.task_id=$1 AND a.state IN ('leased','running')
             ORDER BY s.id LIMIT 2 FOR UPDATE OF s,a",
            &[&task_id],
        )
        .await?;
    let (attempt, output) = match active.as_slice() {
        [] => (None, None),
        [row] => {
            let step_id: Uuid = row.get("step_id");
            if row.get::<_, &str>("step_state") != "running"
                || row.get::<_, i64>("fence") != row.get::<_, i64>("step_fence")
                || row.get::<_, i32>("number") != row.get::<_, i32>("attempt_count")
                || row.get::<_, &str>("idempotency_key") != format!("task-step:{step_id}")
            {
                return Err(Error::conflict("Active attempt differs from its Task step"));
            }
            (Some(row), committed_output(tx, &task, row).await?)
        }
        _ => return Err(Error::conflict("Task has multiple active attempts")),
    };
    let select_calls = format!(
        "SELECT call.id FROM tasks t CROSS JOIN LATERAL ({CALL_TREE} SELECT id FROM tree) call WHERE t.id=$1"
    );
    let calls: Vec<Uuid> = tx
        .query(&select_calls, &[&task_id])
        .await?
        .into_iter()
        .map(|row| row.get(0))
        .collect();

    crate::tasks::authorize_cancellation(tx, ctx, &resource).await?;
    let mut error = Error::new(
        "CANCELED",
        "Task cancellation was requested",
        StatusCode::CONFLICT,
    );
    if let Some(row) = attempt {
        let attempt_id = row.get("id");
        let step = row.get("step_id");
        let call: Option<Uuid> = row.get("broker_call_id");
        let (attempt_state, step_state) = if output.is_some() {
            ("succeeded", "succeeded")
        } else if row.get::<_, &str>("state") == "leased" && call.is_none() {
            ("expired", "canceled")
        } else {
            if let Some(call) = call {
                error = error.with_resource(call);
            }
            ("unknown", "unknown")
        };
        let now = clock(tx).await?;
        set_attempt(tx, attempt_id, attempt_state, now).await?;
        set_step(tx, step, step_state, output, now).await?;
        step_event(tx, task_id, step, attempt_id, step_state).await?;
    }
    if error.resource_id.is_none() && task.get::<_, &str>("state") == "unknown" {
        let previous: Option<Value> = task.get("error");
        if let Some(call) = previous
            .as_ref()
            .and_then(|value| value["resource_id"].as_str())
        {
            error = error.with_resource(call);
        }
    }
    tx.execute(
        "UPDATE task_steps SET state='canceled',revision=revision+1,updated_at=clock_timestamp()
         WHERE task_id=$1 AND state IN ('pending','ready')",
        &[&task_id],
    )
    .await?;
    tx.execute(
        "UPDATE tasks SET state='cancel_requested',error=$2,revision=revision+1,updated_at=clock_timestamp()
         WHERE id=$1",
        &[&task_id, &error.detail()],
    )
    .await?;
    db::outbox(
        tx,
        "task.cancel.requested",
        task_id,
        &json!({"task_id":task_id,"request_id":ctx.request,"reason":body.get("reason")}),
    )
    .await?;
    if !calls.is_empty() {
        crate::broker::request_cancellation(tx, &calls).await?;
    }
    finish_ready(tx, Some(task_id)).await?;
    crate::api::read_object(tx, "tasks", task_id, "Task").await
}

async fn committed_output(
    tx: &Transaction<'_>,
    task: &Row,
    attempt: &Row,
) -> Result<Option<Value>> {
    let (Some(call), Some(issuer), Some(deployment), Some(admission)) = (
        attempt.get::<_, Option<Uuid>>("broker_call_id"),
        task.get::<_, Option<Uuid>>("issuer_credential_id"),
        attempt.get::<_, Option<Uuid>>("provider_deployment_id"),
        task.get::<_, Option<Value>>("admission"),
    ) else {
        return Ok(None);
    };
    match recovery_evidence::verified_output(
        tx,
        recovery_evidence::RecordedAttempt {
            owner: task.get("owner_id"),
            issuer,
            task_delegation: task.get("delegation_id"),
            deployment,
            step_key: attempt.get("step_key"),
            admission: &admission,
            idempotency_key: attempt.get("idempotency_key"),
            call,
        },
    )
    .await
    {
        Ok(output) => Ok(Some(output)),
        Err(error) if error.code == "STATE_CONFLICT" => Ok(None),
        Err(error) => Err(error),
    }
}

/// Independently of dispatch, finish a bounded batch after physical release.
pub(crate) async fn finish_cancellations(tx: &Transaction<'_>) -> Result<u64> {
    let pending: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM tasks WHERE state='cancel_requested')",
            &[],
        )
        .await?
        .get(0);
    if !pending {
        return Ok(0);
    }
    db::call_lock(tx).await?;
    finish_ready(tx, None).await
}

/// Startup or offline recovery has released physical reservations after
/// global stop or on the isolated restore target.
pub(crate) async fn finish_stopped_cancellations(tx: &Transaction<'_>) -> Result<()> {
    while finish_ready(tx, None).await? > 0 {}
    Ok(())
}

async fn finish_ready(tx: &Transaction<'_>, task: Option<Uuid>) -> Result<u64> {
    let sql = format!(
        "WITH finished AS (
            SELECT t.id FROM tasks t
            WHERE t.state='cancel_requested' AND ($1::uuid IS NULL OR t.id=$1)
              AND NOT EXISTS(SELECT 1 FROM task_steps s WHERE s.task_id=t.id AND s.state='running')
              AND NOT EXISTS(
                SELECT 1 FROM task_steps s JOIN attempts a ON a.step_id=s.id
                WHERE s.task_id=t.id AND a.state IN ('leased','running')
              )
              AND NOT EXISTS(
                {CALL_TREE}
                SELECT 1 FROM tree JOIN calls c ON c.id=tree.id
                LEFT JOIN reservations r ON r.id=c.id AND r.kind='call'
                WHERE {CALL_UNSETTLED}
              )
            ORDER BY t.id LIMIT $2 FOR UPDATE OF t SKIP LOCKED
         )
         UPDATE tasks t SET state='canceled',revision=revision+1,updated_at=clock_timestamp()
         FROM finished WHERE t.id=finished.id RETURNING t.id"
    );
    let rows = tx.query(&sql, &[&task, &CANCELLATION_BATCH]).await?;
    for row in &rows {
        let task_id: Uuid = row.get(0);
        db::outbox(tx, "task.canceled", task_id, &json!({"task_id":task_id})).await?;
    }
    Ok(rows.len() as u64)
}
