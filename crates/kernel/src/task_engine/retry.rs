//! Explicit requeue of failed steps with a provably safe Attempt history.
use super::{
    authority, clock, maximum_attempts,
    recovery_evidence::{self, RecordedAttempt},
    step_spec, STEP_QUERY,
};
use crate::{
    auth::{Auth, Context, Resource},
    db,
    error::{Error, Result},
};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(crate) async fn retry_task(
    tx: &Transaction<'_>,
    auth: &Auth,
    ctx: &Context,
    task_id: Uuid,
    headers: &HeaderMap,
) -> Result<Value> {
    db::call_lock(tx).await?;
    let task = tx
        .query_opt(
            "SELECT owner_id,state,revision,deadline_at FROM tasks WHERE id=$1 FOR UPDATE",
            &[&task_id],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    let resource = Resource::new("task", task_id, Some(task.get("owner_id")));
    crate::tasks::authorize_retry(tx, ctx, &resource).await?;
    crate::api::etag(headers, task.get("revision"))?;
    if task.get::<_, &str>("state") != "failed" {
        return Err(Error::conflict("Only a failed Task can be retried"));
    }
    let task_deadline: DateTime<Utc> = task.get("deadline_at");
    if task_deadline <= clock(tx).await? {
        return Err(deadline_elapsed());
    }

    let blocked: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM task_steps s WHERE s.task_id=$1 AND (
                s.state IN ('unknown','canceled','running') OR EXISTS (
                    SELECT 1 FROM attempts a WHERE a.step_id=s.id AND a.state IN ('leased','running')
                )
            ))",
            &[&task_id],
        )
        .await?
        .get(0);
    if blocked {
        return Err(Error::conflict("Task has unsettled or canceled steps"));
    }

    let select =
        format!("{STEP_QUERY} WHERE t.id=$1 AND s.state='failed' ORDER BY s.id FOR UPDATE OF s");
    let steps = tx.query(&select, &[&task_id]).await?;
    if steps.is_empty() {
        return Err(Error::conflict("Task has no failed steps to retry"));
    }
    let mut step_ids = Vec::with_capacity(steps.len());
    let mut execution_deadline = task_deadline;
    for step in &steps {
        let key: &str = step.get("step_key");
        let spec = step_spec(step, key)?;
        verify_history(tx, step, &spec).await?;
        let dependencies_complete: bool = tx
            .query_one(
                "SELECT NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements_text($2::jsonb->'depends_on') AS dep(key)
                    WHERE NOT EXISTS (SELECT 1 FROM task_steps s
                        WHERE s.task_id=$1 AND s.step_key=dep.key AND s.state='succeeded')
                )",
                &[&task_id, &spec],
            )
            .await?
            .get(0);
        if !dependencies_complete {
            return Err(Error::conflict("Task step dependencies are incomplete"));
        }
        let prepared = authority::prepare(tx, auth, step, key, ctx.request).await?;
        execution_deadline = execution_deadline.min(prepared.deadline);
        step_ids.push(step.get::<_, Uuid>("step_id"));
    }

    crate::tasks::authorize_retry(tx, ctx, &resource).await?;
    // Preserve the original ceiling, lifetime, attempt counts and fences. The
    // next worker claim allocates a new Attempt using the same business key.
    let changed = tx
        .execute(
            "WITH requeued AS (
                UPDATE tasks SET state='running',error=NULL,output=NULL,
                    revision=revision+1,updated_at=clock_timestamp()
                WHERE id=$1 AND state='failed' AND $2::timestamptz>clock_timestamp()
                RETURNING id
             )
             UPDATE task_steps s SET state='ready',output=NULL,revision=revision+1,updated_at=clock_timestamp()
             FROM requeued t WHERE s.task_id=t.id AND s.id=ANY($3::uuid[]) AND s.state='failed'",
            &[&task_id, &execution_deadline, &step_ids],
        )
        .await?;
    if changed != step_ids.len() as u64 {
        let now = clock(tx).await?;
        return Err(if task_deadline <= now {
            deadline_elapsed()
        } else if execution_deadline <= now {
            Error::denied()
        } else {
            Error::conflict("Task step state changed before retry")
        });
    }
    db::outbox(
        tx,
        "task.retried",
        task_id,
        &json!({"task_id":task_id,"step_ids":step_ids,"request_id":ctx.request}),
    )
    .await?;
    crate::api::read_object(tx, "tasks", task_id, "Task").await
}

fn deadline_elapsed() -> Error {
    Error::conflict("Task deadline elapsed before retry")
}

fn unproven() -> Error {
    Error::conflict("Task step history does not prove a safe retry")
}

async fn verify_history(tx: &Transaction<'_>, step: &Row, spec: &Value) -> Result<()> {
    let step_id: Uuid = step.get("step_id");
    let count: i32 = step.get("attempt_count");
    let step_fence: i64 = step.get("step_fence");
    if count < 1 || step_fence < 1 {
        return Err(unproven());
    }
    if count >= maximum_attempts(spec) || step_fence.checked_add(1).is_none() {
        return Err(Error::conflict("Task step attempt budget is exhausted"));
    }
    let owner: Uuid = step.get("owner_id");
    let issuer: Option<Uuid> = step.get("issuer_credential_id");
    let deployment: Option<Uuid> = step.get("provider_deployment_id");
    let admission: Option<Value> = step.get("admission");
    let key = format!("task-step:{step_id}");
    let attempts = tx
        .query(
            "SELECT a.number,a.fence,a.state,a.idempotency_key,a.broker_call_id,
                    a.pre_dispatch_failure,a.dispatch_started,EXISTS (
                    SELECT 1 FROM task_step_resolutions resolution
                    WHERE resolution.attempt_id=a.id AND resolution.call_id=a.broker_call_id
                      AND resolution.resolution='confirmed_not_executed' AND resolution.output_digest IS NULL
                ) AS confirmed_not_executed
             FROM attempts a WHERE a.step_id=$1 ORDER BY a.number LIMIT 6 FOR UPDATE OF a",
            &[&step_id],
        )
        .await?;
    if attempts.len() != count as usize {
        return Err(unproven());
    }

    let mut previous_fence = 0;
    let mut settled_calls = Vec::new();
    for (index, attempt) in attempts.iter().enumerate() {
        let fence: i64 = attempt.get("fence");
        if attempt.get::<_, i32>("number") != index as i32 + 1
            || attempt.get::<_, &str>("idempotency_key") != key
            || fence <= previous_fence
            || fence > step_fence
        {
            return Err(unproven());
        }
        let state: &str = attempt.get("state");
        let failed_before_dispatch: bool = attempt.get("pre_dispatch_failure");
        let dispatch_started: Option<bool> = attempt.get("dispatch_started");
        let call: Option<Uuid> = attempt.get("broker_call_id");
        let last = index + 1 == attempts.len();
        previous_fence = fence;
        match (state, failed_before_dispatch, dispatch_started, call) {
            ("expired", false, None, None) if !last => (),
            ("failed", true, None, None) if !last || fence == step_fence => (),
            ("unknown", false, Some(false), Some(call))
                if attempt.get::<_, bool>("confirmed_not_executed") =>
            {
                previous_fence = fence.checked_add(1).ok_or_else(unproven)?;
                if previous_fence > step_fence {
                    return Err(unproven());
                }
                recovery_evidence::verified_nonexecution(
                    tx,
                    RecordedAttempt {
                        owner,
                        issuer: issuer.ok_or_else(unproven)?,
                        task_delegation: step.get("delegation_id"),
                        deployment: deployment.ok_or_else(unproven)?,
                        step_key: step.get("step_key"),
                        admission: admission.as_ref().ok_or_else(unproven)?,
                        idempotency_key: &key,
                        call,
                    },
                )
                .await?;
                settled_calls.push(call);
            }
            _ => return Err(unproven()),
        }
    }
    let other_call: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM calls WHERE owner_id=$1 AND idempotency_key=$2
                AND NOT (id=ANY($3::uuid[])))",
            &[&owner, &key, &settled_calls],
        )
        .await?
        .get(0);
    if other_call {
        return Err(unproven());
    }
    Ok(())
}
