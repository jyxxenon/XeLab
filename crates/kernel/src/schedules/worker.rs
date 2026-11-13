//! Durable cron dispatch. A Schedule row serializes changes to its fire ledger.
use super::cron::Cron;
use crate::{
    api::App,
    auth::{Auth, Resource},
    db,
    error::{Error, Result},
    tasks,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::time;
use tokio_postgres::Transaction;
use uuid::Uuid;

const METADATA_BUDGET: Duration = Duration::from_secs(5);
const POLL_DELAY: Duration = Duration::from_secs(1);
const SCHEDULES_PER_POLL: usize = 4;
const CATCH_UP_WINDOW: TimeDelta = TimeDelta::hours(24);

const ACTIVE_TASK: &str = "SELECT 1 FROM schedule_fires f JOIN tasks t ON t.id=f.task_id
    WHERE f.schedule_id=$1 AND t.state NOT IN ('succeeded','failed','canceled')";

#[derive(Clone, Copy)]
pub(crate) struct PendingFire {
    schedule: Uuid,
    at: DateTime<Utc>,
}

enum Scan {
    Empty,
    Recorded,
    Pending(PendingFire),
}

pub(crate) async fn run(app: Arc<App>) {
    let mut startup_cutoff = None;
    let mut cursor = None;
    while !stopping(&app) {
        if !ready(&app) {
            startup_cutoff = None;
            cursor = None;
        } else {
            for _ in 0..SCHEDULES_PER_POLL {
                match time::timeout(
                    METADATA_BUDGET,
                    run_one(&app, &mut startup_cutoff, &mut cursor),
                )
                .await
                {
                    Ok(Ok(true)) => (),
                    Ok(Ok(false)) => break,
                    Ok(Err(error)) => {
                        tracing::warn!(reason_code = error.code, "Schedule reconciliation failed");
                        break;
                    }
                    Err(_) => {
                        tracing::warn!(
                            reason_code = "NOT_READY",
                            "Schedule metadata operation timed out"
                        );
                        break;
                    }
                }
                if !ready(&app) {
                    break;
                }
            }
        }
        time::sleep(POLL_DELAY).await;
    }
}

fn stopping(app: &App) -> bool {
    app.shutdown.load(Ordering::SeqCst) || app.leader.is_closed()
}

fn ready(app: &App) -> bool {
    app.ready.load(Ordering::SeqCst) && !stopping(app)
}

async fn run_one(
    app: &App,
    startup_cutoff: &mut Option<DateTime<Utc>>,
    cursor: &mut Option<Uuid>,
) -> Result<bool> {
    let mut connection = app.db.connect_scoped(METADATA_BUDGET).await?;
    let tx = connection.transaction().await?;
    if !ready(app) {
        return Ok(false);
    }
    db::auth_lock(&tx, false).await?;
    let now: DateTime<Utc> = tx.query_one("SELECT clock_timestamp()", &[]).await?.get(0);
    let cutoff = *startup_cutoff.get_or_insert(now);
    let scan = stage_after(&tx, now, cutoff, cursor).await?;
    if !ready(app) {
        return Ok(false);
    }
    tx.commit().await?;

    // The fire is durable before Task admission, including if the deadline
    // cancels this attempt or the connection disappears during admission.
    match scan {
        Scan::Empty => Ok(false),
        Scan::Recorded => Ok(true),
        Scan::Pending(fire) => {
            let tx = connection.transaction().await?;
            db::auth_lock(&tx, false).await?;
            if !ready(app) {
                return Ok(false);
            }
            dispatch_pending(&tx, &app.auth, fire).await?;
            if !ready(app) {
                return Ok(false);
            }
            tx.commit().await?;
            Ok(true)
        }
    }
}

#[cfg(test)]
pub(crate) async fn tick(
    tx: &Transaction<'_>,
    auth: &Auth,
    now: DateTime<Utc>,
    startup_cutoff: DateTime<Utc>,
) -> Result<bool> {
    db::auth_lock(tx, false).await?;
    match stage_after(tx, now, startup_cutoff, &mut None).await? {
        Scan::Empty => Ok(false),
        Scan::Recorded => Ok(true),
        Scan::Pending(fire) => {
            dispatch_pending(tx, auth, fire).await?;
            Ok(true)
        }
    }
}

#[cfg(test)]
pub(crate) async fn stage_tick(
    tx: &Transaction<'_>,
    now: DateTime<Utc>,
    startup_cutoff: DateTime<Utc>,
) -> Result<Option<PendingFire>> {
    db::auth_lock(tx, false).await?;
    match stage_after(tx, now, startup_cutoff, &mut None).await? {
        Scan::Pending(fire) => Ok(Some(fire)),
        Scan::Empty | Scan::Recorded => Ok(None),
    }
}

#[cfg(test)]
pub(crate) async fn dispatch_tick(
    tx: &Transaction<'_>,
    auth: &Auth,
    fire: PendingFire,
) -> Result<()> {
    db::auth_lock(tx, false).await?;
    dispatch_pending(tx, auth, fire).await
}

async fn stage_after(
    tx: &Transaction<'_>,
    now: DateTime<Utc>,
    startup_cutoff: DateTime<Utc>,
    cursor: &mut Option<Uuid>,
) -> Result<Scan> {
    let schedule = tx
        .query_opt(
            "SELECT s.* FROM schedules s
             WHERE s.deleted_at IS NULL AND s.admission IS NOT NULL AND s.next_fire_at IS NOT NULL
               AND s.spec->>'enabled'='true'
               AND ($2::uuid IS NULL OR s.id>$2)
               AND (s.next_fire_at<=$1 OR EXISTS (
                    SELECT 1 FROM schedule_fires f WHERE f.schedule_id=s.id AND f.outcome='pending'
                      AND (f.task_id IS NOT NULL OR (f.scheduled_at<=$1 AND NOT EXISTS (
                          SELECT 1 FROM schedule_fires a JOIN tasks t ON t.id=a.task_id
                          WHERE a.schedule_id=s.id AND t.state NOT IN ('succeeded','failed','canceled')
                      )))
               ))
             ORDER BY s.id LIMIT 1 FOR UPDATE OF s SKIP LOCKED",
            &[&now, &*cursor],
        )
        .await?;
    let Some(schedule) = schedule else {
        *cursor = None;
        return Ok(Scan::Empty);
    };
    let id: Uuid = schedule.try_get("id")?;
    // Advance before any expensive work. A temporary failure on one Schedule
    // must not prevent other Schedules from being visited on this pass.
    *cursor = Some(id);
    let spec: Value = schedule.try_get("spec")?;
    let previous_next: DateTime<Utc> = schedule.try_get("next_fire_at")?;
    let mut next = Some(previous_next);

    // A known linked Task wins over the pending marker before making any
    // misfire or overlap decision. The primary key protects other historical
    // outcomes even when a cursor is replayed.
    tx.execute(
        "UPDATE schedule_fires SET outcome='created'
         WHERE schedule_id=$1 AND outcome='pending' AND task_id IS NOT NULL",
        &[&id],
    )
    .await?;
    let active = has_active_task(tx, id).await?;
    let queue_one = spec["overlap"] == "queue_one";
    if previous_next <= now {
        let cron = Cron::parse(
            crate::contracts::string(&spec, "cron")?,
            spec["timezone"].as_str().unwrap_or("Asia/Shanghai"),
        )?;
        let due = due_fires(
            &cron,
            previous_next,
            now,
            startup_cutoff,
            spec["misfire"] == "run_once",
        );
        if let Some(skipped) = due.skipped {
            record_fire(tx, id, skipped, "skipped").await?;
        }
        if let Some(at) = due.pending {
            let outcome = if active && !queue_one {
                "skipped"
            } else {
                "pending"
            };
            record_fire(tx, id, at, outcome).await?;
        }
        next = cron.next_after(now);
    }

    let pending: Option<DateTime<Utc>> = tx
        .query_opt(
            "SELECT scheduled_at FROM schedule_fires WHERE schedule_id=$1
               AND outcome='pending' AND task_id IS NULL AND scheduled_at<=$2
             ORDER BY scheduled_at DESC LIMIT 1",
            &[&id, &now],
        )
        .await?
        .map(|row| row.get(0));
    let mut scan = Scan::Recorded;
    if let Some(at) = pending {
        tx.execute(
            "UPDATE schedule_fires SET outcome='skipped' WHERE schedule_id=$1
               AND outcome='pending' AND task_id IS NULL AND (scheduled_at<$2 OR ($3 AND scheduled_at=$2))",
            &[&id, &at, &(active && !queue_one)],
        )
        .await?;
        if !active {
            scan = Scan::Pending(PendingFire { schedule: id, at });
        }
    }
    if next != Some(previous_next) {
        tx.execute(
            "UPDATE schedules SET next_fire_at=$2,revision=revision+1,updated_at=$3 WHERE id=$1",
            &[&id, &next, &now],
        )
        .await?;
    }
    Ok(scan)
}

async fn has_active_task(tx: &Transaction<'_>, schedule: Uuid) -> Result<bool> {
    Ok(tx
        .query_one(&format!("SELECT EXISTS({ACTIVE_TASK})"), &[&schedule])
        .await?
        .get(0))
}

async fn dispatch_pending(tx: &Transaction<'_>, auth: &Auth, fire: PendingFire) -> Result<()> {
    let id = fire.schedule;
    let at = fire.at;
    let Some(schedule) = tx
        .query_opt(
            "SELECT s.* FROM schedules s WHERE id=$1 AND deleted_at IS NULL
               AND admission IS NOT NULL AND next_fire_at IS NOT NULL AND spec->>'enabled'='true'
             FOR UPDATE OF s SKIP LOCKED",
            &[&id],
        )
        .await?
    else {
        return Ok(());
    };
    // Take a fresh snapshot after acquiring the Schedule lock. A concurrent
    // scan, update, or dispatcher may already have settled this exact fire.
    let pending = tx
        .query_opt(
            "SELECT 1 FROM schedule_fires WHERE schedule_id=$1 AND scheduled_at=$2
               AND outcome='pending' AND task_id IS NULL",
            &[&id, &at],
        )
        .await?;
    if pending.is_none() {
        return Ok(());
    }
    if has_active_task(tx, id).await? {
        let spec: Value = schedule.try_get("spec")?;
        if spec["overlap"] != "queue_one" {
            settle_unlinked(tx, fire, "skipped").await?;
        }
        return Ok(());
    }
    match tasks::enqueue_scheduled_task(tx, auth, &schedule).await {
        Ok(task) => {
            let linked = tx
                .execute(
                    "UPDATE schedule_fires SET task_id=$3,outcome='created'
                     WHERE schedule_id=$1 AND scheduled_at=$2 AND outcome='pending' AND task_id IS NULL",
                    &[&id, &at, &task],
                )
                .await?;
            if linked != 1 {
                return Err(Error::conflict("Schedule fire changed before Task linkage"));
            }
        }
        // Enqueue checks definitive authority and pinned identities before
        // inserting any Task rows. Other errors roll back only this attempt.
        Err(error) => {
            let Some(outcome) = pause_outcome(&error) else {
                return Err(error);
            };
            settle_unlinked(tx, fire, "paused").await?;
            tx.execute(
                "UPDATE schedules SET next_fire_at=NULL,revision=revision+1,updated_at=clock_timestamp()
                 WHERE id=$1",
                &[&id],
            )
            .await?;
            let owner: Uuid = schedule.try_get("owner_id")?;
            let delegation: Uuid = schedule.try_get("delegation_id")?;
            let issuer = tx
                .query_opt(
                    "SELECT issuer_credential_id FROM execution_delegations WHERE id=$1",
                    &[&delegation],
                )
                .await?
                .and_then(|row| row.get::<_, Option<Uuid>>(0));
            db::audit(
                tx,
                owner,
                issuer,
                Uuid::new_v4(),
                "schedule.fire",
                &Resource::new("schedule", id, Some(owner)).json(),
                outcome,
                error.code,
            )
            .await?;
        }
    }
    Ok(())
}

async fn settle_unlinked(tx: &Transaction<'_>, fire: PendingFire, outcome: &str) -> Result<()> {
    tx.execute(
        "UPDATE schedule_fires SET outcome=$3 WHERE schedule_id=$1 AND scheduled_at=$2
           AND outcome='pending' AND task_id IS NULL",
        &[&fire.schedule, &fire.at, &outcome],
    )
    .await?;
    Ok(())
}

fn pause_outcome(error: &Error) -> Option<&'static str> {
    match error.code {
        "PERMISSION_DENIED" | "INVALID_CREDENTIAL" => Some("denied"),
        "RESOURCE_NOT_FOUND" | "STATE_CONFLICT" => Some("failed"),
        _ => None,
    }
}

async fn record_fire(
    tx: &Transaction<'_>,
    id: Uuid,
    scheduled_at: DateTime<Utc>,
    outcome: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO schedule_fires(schedule_id,scheduled_at,outcome) VALUES($1,$2,$3)
         ON CONFLICT (schedule_id,scheduled_at) DO NOTHING",
        &[&id, &scheduled_at, &outcome],
    )
    .await?;
    Ok(())
}

#[derive(Default)]
struct DueFires {
    skipped: Option<DateTime<Utc>>,
    pending: Option<DateTime<Utc>>,
}

fn due_fires(
    cron: &Cron,
    next: DateTime<Utc>,
    now: DateTime<Utc>,
    startup_cutoff: DateTime<Utc>,
    run_once: bool,
) -> DueFires {
    let Some(latest) = cron
        .previous_at_or_before(now)
        .filter(|latest| *latest >= next)
    else {
        return DueFires::default();
    };
    let delay = now.signed_duration_since(latest);
    let missed = latest <= startup_cutoff || delay >= TimeDelta::minutes(1);
    if missed && (!run_once || delay > CATCH_UP_WINDOW) {
        return DueFires {
            skipped: Some(latest),
            pending: None,
        };
    }

    // One skipped record represents the coalesced earlier occurrences. Never
    // walk or materialize an unbounded history after a long interruption.
    let skipped = latest
        .checked_sub_signed(TimeDelta::seconds(1))
        .and_then(|before| cron.previous_at_or_before(before))
        .filter(|earlier| *earlier >= next);
    DueFires {
        skipped,
        pending: Some(latest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(instant: &str) -> DateTime<Utc> {
        instant.parse().unwrap()
    }

    #[test]
    fn skip_coalesces_missed_slots_and_preserves_the_live_minute() {
        let cron = Cron::parse("* * * * *", "UTC").unwrap();
        let next = utc("2026-11-12T10:00:00Z");
        let now = utc("2026-11-12T10:05:15Z");
        let latest = utc("2026-11-12T10:05:00Z");

        let startup = due_fires(&cron, next, now, now, false);
        assert_eq!(startup.skipped, Some(latest));
        assert_eq!(startup.pending, None);

        let live = due_fires(&cron, next, now, next, false);
        assert_eq!(live.skipped, Some(utc("2026-11-12T10:04:00Z")));
        assert_eq!(live.pending, Some(latest));
    }

    #[test]
    fn run_once_recovers_only_the_latest_slot_within_twenty_four_hours() {
        let cron = Cron::parse("0 12 * * 1", "UTC").unwrap();
        let next = utc("2026-11-02T12:00:00Z");
        let latest = utc("2026-11-09T12:00:00Z");
        let now = utc("2026-11-10T12:00:00Z");

        let recoverable = due_fires(&cron, next, now, now, true);
        assert_eq!(recoverable.skipped, Some(next));
        assert_eq!(recoverable.pending, Some(latest));

        let after_window = now + TimeDelta::seconds(1);
        let expired = due_fires(&cron, next, after_window, after_window, true);
        assert_eq!(expired.skipped, Some(latest));
        assert_eq!(expired.pending, None);
    }
}
