//! Controller-owned worker for synchronous Task steps.
use crate::{
    api::App,
    broker,
    error::{Error, Result},
    task_engine::{self, Lease, Outcome, WorkerCall},
};
use axum::http::StatusCode;
use serde_json::Value;
use std::{
    future::Future,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::time::{self, Instant, MissedTickBehavior};
use uuid::Uuid;

const IDLE_DELAY: Duration = Duration::from_secs(1);
const HEARTBEAT: Duration = Duration::from_secs(10);
const METADATA_BUDGET: Duration = Duration::from_secs(5);
const AUTHORITY_CHECKS_PER_TICK: usize = 4;

pub(crate) async fn run(app: Arc<App>) {
    tokio::join!(reconcile(&app), reconcile_authority(&app), dispatch(&app));
}

async fn reconcile(app: &App) {
    while !stopping(app) {
        if let Err(error) = bounded(reconcile_once(app)).await {
            tracing::warn!(reason_code = error.code, "Task reconciliation failed");
        }
        if let Err(error) = bounded(reconcile_cancellations_once(app)).await {
            tracing::warn!(
                reason_code = error.code,
                "Task cancellation reconciliation failed"
            );
        }
        time::sleep(IDLE_DELAY).await;
    }
}

async fn reconcile_authority(app: &App) {
    let mut cursor = None;
    while !stopping(app) {
        for _ in 0..AUTHORITY_CHECKS_PER_TICK {
            if let Err(error) = bounded(reconcile_authority_once(app, &mut cursor)).await {
                tracing::warn!(
                    reason_code = error.code,
                    "Idle Task authorization reconciliation failed"
                );
            }
            if cursor.is_none() || !ready(app) {
                break;
            }
        }
        time::sleep(IDLE_DELAY).await;
    }
}

async fn dispatch(app: &App) {
    while !stopping(app) {
        match dispatch_once(app).await {
            Ok(true) => continue,
            Ok(false) => (),
            Err(error) => tracing::warn!(reason_code = error.code, "Task worker iteration failed"),
        }
        time::sleep(IDLE_DELAY).await;
    }
}

#[cfg(test)]
pub(crate) async fn run_once(app: &App) -> Result<bool> {
    bounded(reconcile_once(app)).await?;
    bounded(reconcile_cancellations_once(app)).await?;
    let mut cursor = None;
    bounded(reconcile_authority_once(app, &mut cursor)).await?;
    dispatch_once(app).await
}

async fn dispatch_once(app: &App) -> Result<bool> {
    if !ready(app) {
        return Ok(false);
    }
    let Some(lease) = bounded(next_lease(app)).await? else {
        return Ok(false);
    };
    if !ready(app) {
        return Ok(false);
    }

    let result = tokio::select! {
        result = broker::invoke_task(app, &lease) => result,
        () = heartbeat(app, &lease) => return Ok(false),
    };
    if stopping(app) {
        return Ok(false);
    }
    bounded(finish(app, &lease, result)).await?;
    Ok(true)
}

fn stopping(app: &App) -> bool {
    app.shutdown.load(Ordering::SeqCst) || app.leader.is_closed()
}

fn ready(app: &App) -> bool {
    app.ready.load(Ordering::SeqCst) && !stopping(app)
}

async fn bounded<T>(operation: impl Future<Output = Result<T>>) -> Result<T> {
    time::timeout(METADATA_BUDGET, operation)
        .await
        .map_err(|_| Error::unavailable("Task metadata operation timed out"))?
}

async fn next_lease(app: &App) -> Result<Option<Lease>> {
    let mut connection = app.db.connect_scoped(METADATA_BUDGET).await?;
    let tx = connection.transaction().await?;
    if !ready(app) {
        return Ok(None);
    }
    let lease = task_engine::claim_broker(&tx, &app.auth).await?;
    if !ready(app) {
        return Ok(None);
    }
    tx.commit().await?;
    Ok(lease)
}

async fn reconcile_once(app: &App) -> Result<()> {
    if !ready(app) {
        return Ok(());
    }
    let mut connection = app.db.connect_scoped(METADATA_BUDGET).await?;
    let tx = connection.transaction().await?;
    if !ready(app) {
        return Ok(());
    }
    task_engine::expire(&tx).await?;
    task_engine::expire_idle(&tx).await?;
    if !ready(app) {
        return Ok(());
    }
    tx.commit().await?;
    Ok(())
}

async fn reconcile_cancellations_once(app: &App) -> Result<()> {
    if !ready(app) {
        return Ok(());
    }
    let mut connection = app.db.connect_scoped(METADATA_BUDGET).await?;
    let tx = connection.transaction().await?;
    task_engine::finish_cancellations(&tx).await?;
    if !ready(app) {
        return Ok(());
    }
    tx.commit().await?;
    Ok(())
}

async fn reconcile_authority_once(app: &App, cursor: &mut Option<Uuid>) -> Result<()> {
    if !ready(app) {
        return Ok(());
    }
    let mut connection = app.db.connect_scoped(METADATA_BUDGET).await?;
    let tx = connection.transaction().await?;
    if !ready(app) {
        return Ok(());
    }
    task_engine::pause_idle_unauthorized(&tx, &app.auth, cursor).await?;
    if ready(app) {
        tx.commit().await?;
    }
    Ok(())
}

async fn heartbeat(app: &App, lease: &Lease) {
    let mut interval = time::interval_at(Instant::now() + HEARTBEAT, HEARTBEAT);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if stopping(app) {
            return;
        }
        if let Err(error) = bounded(renew(app, lease)).await {
            // The Broker independently verifies the current lease. Let it
            // finish its Call settlement if renewal was fenced or unavailable.
            tracing::warn!(
                task_id = %lease.task_id,
                attempt_id = %lease.attempt_id,
                reason_code = error.code,
                "Task lease renewal failed"
            );
        }
    }
}

async fn renew(app: &App, lease: &Lease) -> Result<()> {
    let mut connection = app.db.connect_scoped(METADATA_BUDGET).await?;
    let tx = connection.transaction().await?;
    task_engine::renew(&tx, &app.auth, lease).await?;
    if stopping(app) {
        return Ok(());
    }
    tx.commit().await?;
    Ok(())
}

async fn finish(app: &App, lease: &Lease, invocation: Result<Value>) -> Result<()> {
    let mut connection = app.db.connect_scoped(METADATA_BUDGET).await?;
    let tx = connection.transaction().await?;
    if stopping(app) {
        return Ok(());
    }
    let outcome = match task_engine::broker_call(&tx, lease).await? {
        WorkerCall::Canceled => return Ok(()),
        WorkerCall::Linked(call, state, result) => {
            Some(match durable_output(call, &state, result) {
                Some(output) => Outcome::Succeeded(output),
                None => Outcome::Unknown(
                    Error::new(
                        "OUTCOME_UNKNOWN",
                        "Task Call has no confirmed result",
                        StatusCode::CONFLICT,
                    )
                    .with_resource(call),
                ),
            })
        }
        WorkerCall::Unlinked => match invocation {
            // Transient admission failures leave an undispatched lease for
            // expiry to reconcile under the Task's existing attempt budget.
            Err(error)
                if matches!(
                    error.code,
                    "NOT_READY" | "RESOURCE_EXHAUSTED" | "DEADLINE_EXCEEDED"
                ) =>
            {
                return Ok(());
            }
            Err(error) if matches!(error.code, "PERMISSION_DENIED" | "INVALID_CREDENTIAL") => {
                task_engine::pause_undispatched(&tx, lease, &error).await?;
                None
            }
            Err(error) => Some(Outcome::Failed(error)),
            Ok(_) => return Err(Error::conflict("Task Call journal is missing")),
        },
    };
    if stopping(app) {
        return Ok(());
    }
    if let Some(outcome) = outcome {
        task_engine::complete(&tx, &app.auth, lease, outcome).await?;
    }
    if stopping(app) {
        return Ok(());
    }
    tx.commit().await?;
    Ok(())
}

fn durable_output(call: Uuid, state: &str, result: Option<Value>) -> Option<Value> {
    let mut result = result?;
    if state != "succeeded"
        || result.get("call_id").and_then(Value::as_str)?.parse().ok() != Some(call)
    {
        return None;
    }
    result.as_object_mut()?.remove("output")
}
