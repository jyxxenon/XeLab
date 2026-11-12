//! Historical resolution of an unknown step using the durable Broker ledger.
use super::{clock, promote_dependents, recovery_evidence, set_task};
use crate::{
    auth::{Context, Resource},
    contracts::{digest, reject_jsonb_nul, string},
    db,
    error::{Error, Result},
};
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::{GenericClient, Row, Transaction};
use uuid::Uuid;

pub(crate) async fn resolve_unknown(
    tx: &Transaction<'_>,
    ctx: &Context,
    step_id: Uuid,
    body: &Value,
    headers: &HeaderMap,
) -> Result<Value> {
    db::call_lock(tx).await?;
    let task = tx
        .query_opt(
            "SELECT t.id,t.owner_id,t.state,t.deadline_at,t.admission,t.delegation_id,w.spec,
                    e.issuer_credential_id,e.status AS delegation_status,e.expires_at AS delegation_expires_at
             FROM task_steps s JOIN tasks t ON t.id=s.task_id JOIN workflows w ON w.id=t.workflow_id
             JOIN execution_delegations e ON e.id=t.delegation_id WHERE s.id=$1 FOR UPDATE OF t",
            &[&step_id],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    let task_id: Uuid = task.get("id");
    let owner: Uuid = task.get("owner_id");
    let resource = Resource::new("task", task_id, Some(owner));
    let step = tx
        .query_one(
            "SELECT step_key,state,revision,fence,attempt_count,provider_deployment_id FROM task_steps
             WHERE id=$1 AND task_id=$2 FOR UPDATE",
            &[&step_id, &task_id],
        )
        .await?;
    crate::tasks::authorize_resolution(tx, ctx, &resource).await?;
    crate::api::etag(headers, step.get("revision"))?;
    if step.get::<_, &str>("state") != "unknown"
        || !matches!(
            task.get::<_, &str>("state"),
            "unknown" | "canceled" | "cancel_requested" | "failed"
        )
    {
        return Err(Error::conflict("Task step has no unresolved attempt"));
    }

    let evidence = string(body, "evidence")?;
    if evidence.trim().is_empty() || evidence.contains('\0') {
        return Err(Error::invalid(
            "A nonempty resolution evidence description is required",
        ));
    }
    let resolution = string(body, "resolution")?;
    let submitted = match (resolution, body.get("output")) {
        ("confirmed_succeeded", Some(output)) => {
            reject_jsonb_nul(output)?;
            Some(output)
        }
        ("confirmed_succeeded", None) => {
            return Err(Error::invalid(
                "Confirmed success requires an explicit output",
            ));
        }
        ("confirmed_not_executed", Some(_)) => {
            return Err(Error::invalid(
                "Nonexecution confirmation cannot include output",
            ));
        }
        ("confirmed_not_executed", None) => None,
        _ => return Err(Error::invalid("Unknown Task resolution")),
    };

    let attempt = tx
        .query_opt(
            "SELECT id,number,fence,state,idempotency_key,broker_call_id FROM attempts
         WHERE step_id=$1 ORDER BY number DESC LIMIT 1 FOR UPDATE",
            &[&step_id],
        )
        .await?
        .ok_or_else(|| Error::conflict("Task step has no recorded attempt"))?;
    let fence: i64 = step.get("fence");
    let key: &str = attempt.get("idempotency_key");
    if attempt.get::<_, &str>("state") != "unknown"
        || attempt.get::<_, i64>("fence") != fence
        || attempt.get::<_, i32>("number") != step.get::<_, i32>("attempt_count")
        || key != format!("task-step:{step_id}")
    {
        return Err(Error::conflict(
            "Task step fence no longer identifies the unresolved attempt",
        ));
    }
    let next_fence = fence
        .checked_add(1)
        .ok_or_else(|| Error::conflict("Task step fence exhausted"))?;
    let call = attempt
        .get::<_, Option<Uuid>>("broker_call_id")
        .ok_or_else(|| Error::conflict("Task attempt has no verified Call evidence"))?;
    let admission = task
        .get::<_, Option<Value>>("admission")
        .ok_or_else(|| Error::conflict("Task has no frozen admission record"))?;
    let issuer = task
        .get::<_, Option<Uuid>>("issuer_credential_id")
        .ok_or_else(|| Error::conflict("Task has no recorded issuer"))?;
    let deployment = step
        .get::<_, Option<Uuid>>("provider_deployment_id")
        .ok_or_else(|| Error::conflict("Task step has no fixed deployment"))?;
    let recorded = recovery_evidence::RecordedAttempt {
        owner,
        issuer,
        task_delegation: task.get("delegation_id"),
        deployment,
        step_key: step.get("step_key"),
        admission: &admission,
        idempotency_key: key,
        call,
    };
    let (state, output) = if let Some(submitted) = submitted {
        let output = recovery_evidence::verified_output(tx, recorded).await?;
        if &output != submitted {
            return Err(Error::conflict(
                "Submitted output differs from the linked Broker Call",
            ));
        }
        ("succeeded", Some(output))
    } else {
        recovery_evidence::verified_nonexecution(tx, recorded).await?;
        ("failed", None)
    };

    // Historical evidence grants no execution rights. Time-bound operator
    // permissions are rechecked after waiting for locks and inspecting proof.
    crate::tasks::authorize_resolution(tx, ctx, &resource).await?;
    let attempt_id: Uuid = attempt.get("id");
    let now = clock(tx).await?;
    let output_digest = output
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()?
        .map(|bytes| digest(&bytes));
    tx.execute(
        "INSERT INTO task_step_resolutions(attempt_id,call_id,actor_subject_id,actor_credential_id,
                  request_id,resolution,evidence,output_digest,created_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[
            &attempt_id,
            &call,
            &ctx.subject,
            &ctx.credential,
            &ctx.request,
            &resolution,
            &evidence,
            &output_digest,
            &now,
        ],
    )
    .await?;
    tx.execute(
        "UPDATE task_steps SET state=$2,output=$3,fence=$4,revision=revision+1,updated_at=$5 WHERE id=$1",
        &[&step_id,&state,&output,&next_fence,&now],
    ).await?;
    settle_parent(tx, &task, task_id, now).await?;
    db::outbox(
        tx,
        "task.step.resolved",
        step_id,
        &json!({"task_id":task_id,"step_id":step_id,"attempt_id":attempt_id,
                "call_id":call,"resolution":resolution}),
    )
    .await?;
    crate::api::read_object(tx, "task_steps", step_id, "TaskStep").await
}

async fn settle_parent(
    tx: &Transaction<'_>,
    task: &Row,
    task_id: Uuid,
    now: DateTime<Utc>,
) -> Result<()> {
    if task.get::<_, &str>("state") != "unknown" {
        // Cancellation and other terminal outcomes retain their parent state.
        tx.execute(
            "UPDATE tasks SET revision=revision+1,updated_at=$2 WHERE id=$1",
            &[&task_id, &now],
        )
        .await?;
        return Ok(());
    }
    let states = tx.query_one(
        "SELECT NOT EXISTS(SELECT 1 FROM task_steps WHERE task_id=$1 AND state<>'succeeded'),
                EXISTS(SELECT 1 FROM task_steps WHERE task_id=$1 AND state='unknown'),
                EXISTS(SELECT 1 FROM task_steps WHERE task_id=$1 AND state IN ('failed','canceled'))",
        &[&task_id],
    ).await?;
    if states.get::<_, bool>(0) {
        return promote_dependents(tx, task_id, &task.get("spec"), now).await;
    }
    let (state, error) = if states.get::<_, bool>(1) {
        (
            "unknown",
            Error::new(
                "OUTCOME_UNKNOWN",
                "Task has another unresolved step",
                StatusCode::CONFLICT,
            ),
        )
    } else if states.get::<_, bool>(2) {
        (
            "failed",
            Error::conflict("Task has an incomplete terminal step"),
        )
    } else if task.get::<_, DateTime<Utc>>("deadline_at") <= now {
        (
            "failed",
            Error::new(
                "DEADLINE_EXCEEDED",
                "Task deadline elapsed before remaining steps could run",
                StatusCode::GATEWAY_TIMEOUT,
            ),
        )
    } else if task.get::<_, &str>("delegation_status") != "active"
        || task.get::<_, DateTime<Utc>>("delegation_expires_at") <= now
    {
        ("paused_authorization", Error::denied())
    } else {
        set_task(tx, task_id, "running", None, None).await?;
        return promote_dependents(tx, task_id, &task.get("spec"), now).await;
    };
    set_task(tx, task_id, state, None, Some(error.detail())).await
}

pub(crate) async fn validate_resolution_history(c: &(impl GenericClient + Sync)) -> Result<()> {
    let mut after: Option<Uuid> = None;
    loop {
        let rows = c
            .query(
                "SELECT r.attempt_id,r.output_digest,c.result->'output' AS output,
                    a.broker_call_id IS NOT DISTINCT FROM r.call_id AND a.state='unknown'
                      AND s.fence>a.fence AND k.owner_id=r.actor_subject_id
                      AND (CASE r.resolution WHEN 'confirmed_succeeded' THEN
                            s.state='succeeded' AND s.output=(c.result->'output')
                              AND c.state='succeeded' AND a.dispatch_started IS DISTINCT FROM FALSE
                           WHEN 'confirmed_not_executed' THEN
                            a.dispatch_started IS FALSE AND c.state='unknown'
                              AND c.result IS NULL AND c.completed_at IS NULL AND EXISTS (
                                SELECT 1 FROM reservations q WHERE q.id=c.id AND q.kind='call'
                                  AND q.account_id=c.owner_id AND q.status='released'
                              ) AND NOT EXISTS (
                                SELECT 1 FROM host_call_tickets ticket
                                JOIN host_child_calls child ON child.ticket_id=ticket.id
                                WHERE ticket.parent_call_id=c.id
                              )
                              AND (s.state IN ('failed','ready','canceled') OR EXISTS (
                                SELECT 1 FROM attempts later WHERE later.step_id=a.step_id AND later.number>a.number
                              ))
                           ELSE false END) AS valid
             FROM task_step_resolutions r JOIN attempts a ON a.id=r.attempt_id
             JOIN task_steps s ON s.id=a.step_id JOIN calls c ON c.id=r.call_id
             JOIN credentials k ON k.id=r.actor_credential_id
             WHERE ($1::uuid IS NULL OR r.attempt_id>$1) ORDER BY r.attempt_id LIMIT 16",
                &[&after],
            )
            .await?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            after = Some(row.get("attempt_id"));
            let output = row.get::<_, Option<Value>>("output");
            let actual = output
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()?
                .map(|bytes| digest(&bytes));
            if row.get::<_, Option<bool>>("valid") != Some(true)
                || actual.as_deref() != row.get::<_, Option<&str>>("output_digest")
            {
                return Err(Error::conflict(
                    "Historical Task resolution differs from its Call evidence",
                ));
            }
        }
    }
}
