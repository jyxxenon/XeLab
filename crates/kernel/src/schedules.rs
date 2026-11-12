//! Schedule management. The worker owns durable fire-to-Task transitions.
use crate::{
    api::{etag, object_value, path_id},
    auth::{self, Auth, Context, Resource},
    contracts::{id, reject_jsonb_nul, string},
    error::{Error, Result},
    tasks::{admit_schedule, ScheduleAdmission},
};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio_postgres::{GenericClient, Row, Transaction};
use uuid::Uuid;

mod cron;
mod worker;
pub(crate) use worker::run;
#[cfg(test)]
pub(crate) use worker::tick;

pub(crate) fn handles(name: &str) -> bool {
    matches!(
        name,
        "createSchedule" | "getSchedule" | "listSchedules" | "updateSchedule" | "deleteSchedule"
    )
}

pub(crate) fn validate_query(name: &str, query: &str) -> Result<()> {
    if handles(name) && name != "listSchedules" && !query.is_empty() {
        return Err(Error::invalid("Unexpected Schedule query parameter"));
    }
    Ok(())
}

pub(crate) async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
) -> Result<()> {
    match name {
        "listSchedules" => Ok(()), // The catalog checks current policy per object.
        "createSchedule" => {
            authorize_create(c, ctx).await?;
            let workflow = id(body, "workflow_id")?;
            let row = c
                .query_opt("SELECT owner_id FROM workflows WHERE id=$1", &[&workflow])
                .await?
                .ok_or_else(Error::not_found)?;
            let resource = Resource::new("workflow", workflow, Some(row.get(0)));
            if !crate::policy::allows(c, ctx, "workflow.read", &resource).await? {
                return Err(Error::not_found());
            }
            Ok(())
        }
        "getSchedule" | "updateSchedule" | "deleteSchedule" => {
            let schedule = path_id(params, "schedule_id")?;
            // Keep tombstone ownership available for authorized idempotency replays.
            let row = c
                .query_opt(
                    "SELECT owner_id FROM schedules WHERE id=$1 AND admission IS NOT NULL
                 AND (NOT $2::boolean OR deleted_at IS NULL)",
                    &[&schedule, &(name == "getSchedule")],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            let action = match name {
                "updateSchedule" => "schedule.update",
                "deleteSchedule" => "schedule.delete",
                _ => "schedule.read",
            };
            authorize_existing(c, ctx, schedule, row.get(0), action).await
        }
        _ => Err(Error::not_found()),
    }
}

async fn authorize_create(c: &(impl GenericClient + Sync), ctx: &Context) -> Result<()> {
    auth::authorize(
        c,
        ctx,
        "schedule.create",
        &Resource::new("schedule", "new", Some(ctx.subject)),
    )
    .await
}

async fn authorize_existing(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    schedule: Uuid,
    owner: Uuid,
    action: &str,
) -> Result<()> {
    let resource = Resource::new("schedule", schedule, Some(owner));
    if !crate::policy::allows(c, ctx, "schedule.read", &resource).await? {
        return Err(Error::not_found());
    }
    if action != "schedule.read" {
        auth::authorize(c, ctx, action, &resource).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Shared HTTP dispatch inputs.
pub(crate) async fn execute(
    c: &Transaction<'_>,
    auth: &Auth,
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
    headers: &HeaderMap,
    query: &str,
) -> Result<(Value, u16)> {
    match name {
        "listSchedules" => crate::plugin_catalog::execute(c, auth, ctx, name, query).await,
        "getSchedule" => Ok((view(c, path_id(params, "schedule_id")?).await?, 200)),
        "createSchedule" => Ok((create(c, ctx, body).await?, 201)),
        "updateSchedule" => Ok((
            update(c, ctx, path_id(params, "schedule_id")?, body, headers).await?,
            200,
        )),
        "deleteSchedule" => {
            delete(c, ctx, path_id(params, "schedule_id")?, headers).await?;
            Ok((Value::Null, 204))
        }
        _ => Err(Error::not_found()),
    }
}

pub(crate) async fn read(c: &(impl GenericClient + Sync), schedule: Uuid) -> Result<Option<Value>> {
    let row = c
        .query_opt(
            "SELECT to_jsonb(s) FROM (
             SELECT id,revision,created_at,updated_at,owner_id,spec,delegation_id,next_fire_at
             FROM schedules WHERE id=$1 AND admission IS NOT NULL AND deleted_at IS NULL
         ) s",
            &[&schedule],
        )
        .await?;
    row.map(|row| object_value(&row.get(0), "Schedule"))
        .transpose()
}

async fn view(c: &(impl GenericClient + Sync), schedule: Uuid) -> Result<Value> {
    read(c, schedule).await?.ok_or_else(Error::not_found)
}

fn normalize(body: &Value) -> Result<(Value, cron::Cron)> {
    reject_jsonb_nul(body)?;
    let mut spec = body.clone();
    let fields = spec
        .as_object_mut()
        .ok_or_else(|| Error::invalid("Expected a Schedule spec"))?;
    for (name, default) in [
        ("timezone", json!("Asia/Shanghai")),
        ("enabled", json!(true)),
        ("misfire", json!("skip")),
        ("overlap", json!("skip")),
    ] {
        fields.entry(name).or_insert(default);
    }
    let cron = cron::Cron::parse(string(&spec, "cron")?, string(&spec, "timezone")?)?;
    Ok((spec, cron))
}

async fn clock(c: &Transaction<'_>) -> Result<DateTime<Utc>> {
    Ok(c.query_one("SELECT clock_timestamp()", &[]).await?.get(0))
}

fn next_fire(cron: &cron::Cron, spec: &Value, now: DateTime<Utc>) -> Result<Option<DateTime<Utc>>> {
    let next = cron
        .next_after(now)
        .ok_or_else(|| Error::invalid("Schedule has no future occurrence"))?;
    Ok((spec["enabled"] == true).then_some(next))
}

async fn store_delegation(
    c: &Transaction<'_>,
    ctx: &Context,
    admission: &ScheduleAdmission,
    now: DateTime<Utc>,
) -> Result<Uuid> {
    if admission.expires_at <= now {
        return Err(Error::credential());
    }
    let delegation = Uuid::new_v4();
    c.execute(
        "INSERT INTO execution_delegations
             (id,subject_id,issuer_credential_id,maximum_rules,run_as,expires_at,status,created_at)
         VALUES($1,$2,$3,$4,'user',$5,'active',$6)",
        &[
            &delegation,
            &ctx.subject,
            &ctx.credential,
            &admission.maximum_rules,
            &admission.expires_at,
            &now,
        ],
    )
    .await?;
    Ok(delegation)
}

async fn create(c: &Transaction<'_>, ctx: &Context, body: &Value) -> Result<Value> {
    let (spec, cron) = normalize(body)?;
    let admission = admit_schedule(c, ctx, &spec).await?;
    authorize_create(c, ctx).await?;
    let now = clock(c).await?;
    let next = next_fire(&cron, &spec, now)?;
    let delegation = store_delegation(c, ctx, &admission, now).await?;
    let schedule = Uuid::new_v4();
    c.execute(
        "INSERT INTO schedules(id,owner_id,spec,delegation_id,admission,next_fire_at,created_at,updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$7)",
        &[&schedule, &ctx.subject, &spec, &delegation, &admission.proof, &next, &now],
    ).await?;
    view(c, schedule).await
}

async fn lock(c: &Transaction<'_>, schedule: Uuid) -> Result<Row> {
    c.query_opt(
        "SELECT owner_id,spec,revision,delegation_id,admission,next_fire_at
         FROM schedules WHERE id=$1 AND admission IS NOT NULL AND deleted_at IS NULL FOR UPDATE",
        &[&schedule],
    )
    .await?
    .ok_or_else(Error::not_found)
}

async fn skip_pending(c: &Transaction<'_>, schedule: Uuid) -> Result<()> {
    c.execute(
        "UPDATE schedule_fires SET outcome='skipped'
         WHERE schedule_id=$1 AND outcome='pending' AND task_id IS NULL",
        &[&schedule],
    )
    .await?;
    Ok(())
}

async fn revoke(c: &Transaction<'_>, delegation: Uuid) -> Result<()> {
    c.execute(
        "UPDATE execution_delegations SET status='revoked' WHERE id=$1 AND status='active'",
        &[&delegation],
    )
    .await?;
    Ok(())
}

async fn update(
    c: &Transaction<'_>,
    ctx: &Context,
    schedule: Uuid,
    body: &Value,
    headers: &HeaderMap,
) -> Result<Value> {
    let (spec, cron) = normalize(body)?;
    let row = lock(c, schedule).await?;
    let owner = row.get("owner_id");
    authorize_existing(c, ctx, schedule, owner, "schedule.update").await?;
    etag(headers, row.get("revision"))?;
    let saved: Value = row.get("spec");
    let changes_task =
        spec["workflow_id"] != saved["workflow_id"] || spec["input"] != saved["input"];
    if changes_task && ctx.subject != owner {
        return Err(Error::denied());
    }
    let rearm = spec["enabled"] == true
        && row
            .get::<_, Option<DateTime<Utc>>>("next_fire_at")
            .is_none();
    let new_admission = if changes_task || (rearm && ctx.subject == owner) {
        Some(admit_schedule(c, ctx, &spec).await?)
    } else {
        None
    };
    authorize_existing(c, ctx, schedule, owner, "schedule.update").await?;
    let now = clock(c).await?;
    let next = next_fire(&cron, &spec, now)?;
    let previous = row.get("delegation_id");
    let (delegation, proof) = if let Some(admission) = new_admission {
        let delegation = store_delegation(c, ctx, &admission, now).await?;
        revoke(c, previous).await?;
        (delegation, admission.proof)
    } else {
        (previous, row.get("admission"))
    };
    skip_pending(c, schedule).await?;
    c.execute(
        "UPDATE schedules SET spec=$2,delegation_id=$3,admission=$4,next_fire_at=$5,
             revision=revision+1,updated_at=$6 WHERE id=$1",
        &[&schedule, &spec, &delegation, &proof, &next, &now],
    )
    .await?;
    view(c, schedule).await
}

async fn delete(
    c: &Transaction<'_>,
    ctx: &Context,
    schedule: Uuid,
    headers: &HeaderMap,
) -> Result<()> {
    let row = lock(c, schedule).await?;
    authorize_existing(c, ctx, schedule, row.get("owner_id"), "schedule.delete").await?;
    etag(headers, row.get("revision"))?;
    revoke(c, row.get("delegation_id")).await?;
    skip_pending(c, schedule).await?;
    c.execute(
        "UPDATE schedules SET deleted_at=clock_timestamp(),next_fire_at=NULL,
             revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        &[&schedule],
    )
    .await?;
    Ok(())
}
