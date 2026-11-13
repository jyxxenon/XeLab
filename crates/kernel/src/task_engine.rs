//! Transactional state for synchronous Workflow attempts. The in-process
//! caller must commit a lease before preparing it for Broker dispatch.
use crate::{
    auth::{Auth, Context},
    contracts::{reject_jsonb_nul, unsigned, validate, validate_business},
    db,
    error::{Error, Result},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

mod authority;
mod input;

const LEASE: Duration = Duration::seconds(30);
pub(crate) const MAX_STEP_JSON_BYTES: usize = 4 * 1024 * 1024;
const STEP_QUERY: &str = "SELECT t.*,w.spec,w.owner_id AS workflow_owner_id,
    s.id AS step_id,s.step_key,s.state AS step_state,s.fence AS step_fence,s.attempt_count,s.provider_deployment_id,
    e.issuer_credential_id,e.subject_id AS delegation_subject,e.status AS delegation_status,
    e.expires_at AS delegation_expires_at,e.run_as AS delegation_run_as,e.maximum_rules
    FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN workflows w ON w.id=t.workflow_id
    JOIN execution_delegations e ON e.id=t.delegation_id";
const IDLE_DEADLINE_DUE: &str = "t.admission IS NOT NULL
    AND t.state IN ('queued','running','waiting_dependency') AND t.deadline_at<=statement_timestamp()
    AND NOT EXISTS (
        SELECT 1 FROM task_steps s WHERE s.task_id=t.id AND (
            s.state IN ('running','unknown') OR EXISTS (
                SELECT 1 FROM attempts a WHERE a.step_id=s.id AND a.state IN ('leased','running')
            )
        )
    )";
const ACTIVE_ATTEMPTS: &str = "SELECT t.id,t.state,t.deadline_at,w.spec,s.id AS step_id,s.step_key,
    s.attempt_count,s.state AS step_state,s.fence AS step_fence,a.fence AS attempt_fence,
    a.id AS attempt_id,a.state AS attempt_state,a.lease_expires_at,a.broker_call_id
    FROM attempts a JOIN task_steps s ON s.id=a.step_id JOIN tasks t ON t.id=s.task_id
    JOIN workflows w ON w.id=t.workflow_id WHERE a.state IN ('leased','running')";

#[derive(Debug, Clone)]
pub struct Lease {
    pub task_id: Uuid,
    pub step_id: Uuid,
    pub attempt_id: Uuid,
    pub execution_id: Uuid,
    pub fence: i64,
    pub idempotency_key: String,
    http: bool,
}

impl Lease {
    pub(crate) fn is_http(&self) -> bool {
        self.http
    }
}

pub struct Invocation {
    pub skill_id: Uuid,
    pub deployment_id: Uuid,
    pub installation_id: Uuid,
    pub input: Value,
    pub deadline: DateTime<Utc>,
    pub idempotency_key: String,
}

pub enum Outcome {
    Succeeded(Value),
    Failed(Error),
    Unknown(Error),
}

pub async fn claim(tx: &Transaction<'_>, auth: &Auth) -> Result<Option<Lease>> {
    claim_with_readiness(tx, auth, false).await
}

pub(crate) async fn claim_broker(tx: &Transaction<'_>, auth: &Auth) -> Result<Option<Lease>> {
    claim_with_readiness(tx, auth, true).await
}

async fn claim_with_readiness(
    tx: &Transaction<'_>,
    auth: &Auth,
    require_provider: bool,
) -> Result<Option<Lease>> {
    db::auth_lock(tx, false).await?;
    let query = format!(
        "{STEP_QUERY}
        WHERE t.state IN ('queued','running') AND s.state='ready' AND t.deadline_at>clock_timestamp()
          AND EXISTS (
              SELECT 1 FROM deployments d JOIN installations n ON n.id=d.installation_id
              JOIN publishers p ON p.id=n.publisher_id JOIN skills k ON k.installation_id=n.id
              WHERE d.id=s.provider_deployment_id AND d.archived_at IS NULL AND d.spec->>'enabled'='true'
                AND n.state='installed' AND p.status='trusted' AND k.enabled AND k.archived_at IS NULL
                AND k.definition->'target'->>'kind' IN ('capability','http')
                AND (k.definition->'target'->>'kind'='capability'
                     OR k.definition->>'stream_item_schema' IS NULL)
                AND t.admission @> jsonb_build_object('version',1,'steps',jsonb_build_array(
                    jsonb_build_object('step_key',s.step_key,'deployment_id',d.id,'installation_id',n.id,
                      'binding',jsonb_build_object('kind','skill_' || (k.definition->'target'->>'kind'),'skill_id',k.id,
                                                 'definition_digest',k.definition_digest))))
                AND (NOT $1::boolean OR EXISTS (
                    SELECT 1 FROM instances i WHERE i.deployment_id=d.id AND i.phase='ready'
                      AND (
                        (k.definition->'target'->>'kind'='http' AND d.phase='ready'
                         AND i.health='alive' AND i.generation=d.observed_generation
                         AND d.approval ? 'rules'
                         AND i.last_heartbeat_at>clock_timestamp()-interval '1 millisecond' *
                             ((n.manifest->'health'->>'interval_ms')::bigint *
                              (n.manifest->'health'->>'failure_threshold')::bigint +
                              (n.manifest->'health'->>'timeout_ms')::bigint))
                        OR (k.definition->'target'->>'kind'='capability' AND EXISTS (
                            SELECT 1 FROM provider_records p WHERE p.instance_id=i.id
                              AND p.availability='ready' AND p.observed_generation=i.generation
                              AND p.observed_at>clock_timestamp()-interval '1 millisecond' *
                                  ((n.manifest->'health'->>'interval_ms')::bigint *
                                   (n.manifest->'health'->>'failure_threshold')::bigint +
                                   (n.manifest->'health'->>'timeout_ms')::bigint)
                              AND t.admission @> jsonb_build_object('steps',jsonb_build_array(
                                jsonb_build_object('step_key',s.step_key,'installation_id',n.id,'binding',
                                  jsonb_build_object('contract',jsonb_build_object('name',p.name,'version',p.version)))))
                        ))
                      )
                ))
          )
          AND (NOT $1::boolean OR NOT EXISTS (
              SELECT 1 FROM task_steps other WHERE other.task_id=t.id AND NOT EXISTS (
                  SELECT 1 FROM skills k
                  WHERE other.provider_deployment_id IS NOT NULL
                    AND k.definition->'target'->>'kind' IN ('capability','http')
                    AND (k.definition->'target'->>'kind'='capability'
                         OR k.definition->>'stream_item_schema' IS NULL)
                    AND t.admission @> jsonb_build_object('steps',jsonb_build_array(jsonb_build_object(
                      'step_key',other.step_key,'deployment_id',other.provider_deployment_id,
                      'installation_id',k.installation_id,'binding',jsonb_build_object(
                        'kind','skill_' || (k.definition->'target'->>'kind'),'skill_id',k.id,
                        'definition_digest',k.definition_digest))))
              )
          ))
          AND NOT EXISTS (SELECT 1 FROM task_steps active WHERE active.task_id=t.id AND active.state='running')
        ORDER BY s.created_at,s.id LIMIT 1 FOR UPDATE OF t,s SKIP LOCKED"
    );
    let Some(row) = tx.query_opt(&query, &[&require_provider]).await? else {
        return Ok(None);
    };
    let task_id = row.get("id");
    let step_id = row.get("step_id");
    // The selection statement can have taken its snapshot before a sibling
    // claim committed. Check again while this transaction holds the Task lock.
    let idle: bool = tx
        .query_one(
            "SELECT NOT EXISTS (SELECT 1 FROM task_steps WHERE task_id=$1 AND state='running')",
            &[&task_id],
        )
        .await?
        .get(0);
    if !idle {
        return Ok(None);
    }
    let step_key: String = row.get("step_key");
    let step = step_spec(&row, &step_key)?;
    let count: i32 = row.get("attempt_count");
    let number = count
        .checked_add(1)
        .filter(|number| *number <= maximum_attempts(&step))
        .ok_or_else(|| Error::conflict("Task step attempt limit reached"))?;
    let fence = row
        .get::<_, i64>("step_fence")
        .checked_add(1)
        .ok_or_else(|| Error::conflict("Task step fence limit reached"))?;
    let attempt_id = Uuid::new_v4();
    let prepared = match authority::prepare(tx, auth, &row, &step_key, attempt_id).await {
        Ok(prepared) => prepared,
        Err(error) if matches!(error.code, "PERMISSION_DENIED" | "INVALID_CREDENTIAL") => {
            set_task(
                tx,
                task_id,
                "paused_authorization",
                None,
                Some(error.detail()),
            )
            .await?;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let now = clock(tx).await?;
    let end = prepared
        .deadline
        .min(now + step_timeout(&step)?)
        .min(now + LEASE);
    require_future(end, now)?;
    let execution_id = Uuid::new_v4();
    let idempotency_key = format!("task-step:{step_id}");
    tx.execute(
        "INSERT INTO attempts(id,step_id,number,execution_id,idempotency_key,fence,lease_expires_at,state,created_at,updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,'leased',$8,$8)",
        &[&attempt_id, &step_id, &number, &execution_id, &idempotency_key, &fence, &end, &now],
    ).await?;
    tx.execute(
        "UPDATE task_steps SET state='running',attempt_count=$2,fence=$3,revision=revision+1,updated_at=$4 WHERE id=$1",
        &[&step_id, &number, &fence, &now],
    ).await?;
    // Update the parent on every claim so a repeatable-read claimant using an
    // older snapshot cannot silently retain the preceding Task version.
    set_task(tx, task_id, "running", None, None).await?;
    Ok(Some(Lease {
        task_id,
        step_id,
        attempt_id,
        execution_id,
        fence,
        idempotency_key,
        http: prepared.is_http,
    }))
}

/// Persist dispatch intent before transferring a validated invocation. Until
/// the Broker journals an admitted Call, loss after this boundary is unknown.
pub async fn begin(tx: &Transaction<'_>, auth: &Auth, lease: &Lease) -> Result<Invocation> {
    let (invocation, _, now) = prepare_begin(tx, auth, lease).await?;
    set_live_attempt(tx, lease.attempt_id, "running", now, invocation.deadline).await?;
    Ok(invocation)
}

/// Prepare a Task invocation with a proof bound to this transaction.
pub(crate) async fn prepare_broker(
    tx: &Transaction<'_>,
    auth: &Auth,
    lease: &Lease,
) -> Result<(Invocation, Context)> {
    let (invocation, prepared, _) = prepare_begin(tx, auth, lease).await?;
    let context = prepared.into_broker_context(tx).await?;
    Ok((invocation, context))
}

async fn prepare_begin(
    tx: &Transaction<'_>,
    auth: &Auth,
    lease: &Lease,
) -> Result<(Invocation, authority::Prepared, DateTime<Utc>)> {
    let active = load(tx, lease).await?;
    active.require_running_step()?;
    if active.state != "leased" || active.broker_call_id.is_some() {
        return Err(Error::conflict(
            "Attempt has already crossed the dispatch boundary",
        ));
    }
    let prepared = active.prepare(tx, auth, lease).await?;
    let input = step_input(tx, &active, lease.task_id, &prepared).await?;
    validate_business(&prepared.definition["input_schema"], &input)?;
    let deadline = active.deadline(&prepared)?;
    let now = clock(tx).await?;
    require_future(active.lease_until.min(deadline), now)?;
    let invocation = Invocation {
        skill_id: prepared.skill,
        deployment_id: prepared.deployment,
        installation_id: prepared.installation,
        input,
        deadline,
        idempotency_key: lease.idempotency_key.clone(),
    };
    Ok((invocation, prepared, now))
}

/// Cross the dispatch boundary together with the admitted Call.
pub(crate) async fn record_broker_call(
    tx: &Transaction<'_>,
    lease: &Lease,
    call: Uuid,
) -> Result<()> {
    let active = load(tx, lease).await?;
    active.require_running_step()?;
    if active.state != "leased" || active.broker_call_id.is_some() {
        return Err(Error::conflict(
            "Task attempt no longer accepts a Broker Call",
        ));
    }
    let updated = tx.execute(
        "UPDATE attempts a SET state='running',broker_call_id=c.id,revision=a.revision+1,updated_at=clock_timestamp()
         FROM calls c JOIN instances i ON i.id=c.provider_instance_id
         JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id
         JOIN task_steps s ON s.provider_deployment_id=d.id
         JOIN tasks t ON t.id=s.task_id JOIN execution_delegations e ON e.id=t.delegation_id
         WHERE a.id=$1 AND c.id=$2 AND s.id=a.step_id AND a.state='leased'
           AND a.broker_call_id IS NULL AND c.state='running'
           AND LEAST(a.lease_expires_at,c.deadline_at,t.deadline_at,e.expires_at)>clock_timestamp()
           AND c.owner_id=t.owner_id AND c.credential_id=e.issuer_credential_id
           AND c.delegation_id<>t.delegation_id AND c.idempotency_key=a.idempotency_key
           AND (CASE WHEN $3::boolean THEN
               c.http_binding @> jsonb_build_object('installation_id',n.id,'deployment_id',d.id,'generation',i.generation)
               AND t.admission @> jsonb_build_object('version',1,'steps',jsonb_build_array(jsonb_build_object(
                   'step_key',s.step_key,'deployment_id',d.id,'installation_id',n.id,
                   'binding',jsonb_build_object('kind','skill_http','skill_id',c.skill_id,
                       'definition_digest',c.skill_definition_digest,
                       'operation_id',c.http_binding->'operation_id',
                       'http_contract_digest',c.http_binding->'http_contract_digest',
                       'method',c.http_binding->'method','path',c.http_binding->'path'),
                   'targets',jsonb_build_array(jsonb_build_object('action',c.http_binding->'required_action',
                       'owner_id',d.owner_id,'resource',jsonb_build_object('kind','plugin','match','ids',
                                                                        'ids',jsonb_build_array(n.plugin_id)))))))
             ELSE
               c.http_binding IS NULL
               AND t.admission @> jsonb_build_object('version',1,'steps',jsonb_build_array(jsonb_build_object(
                   'step_key',s.step_key,'deployment_id',d.id,'installation_id',n.id,
                   'binding',jsonb_build_object('kind','skill_capability','skill_id',c.skill_id,
                       'definition_digest',c.skill_definition_digest,'contract',c.contract))))
             END)",
        &[&lease.attempt_id, &call, &lease.is_http()],
    ).await?;
    if updated != 1 {
        return Err(Error::conflict(
            "Broker Call does not match the live Task attempt",
        ));
    }
    Ok(())
}

/// Recreate exact Task authority for one transaction on an admitted Call.
pub(crate) async fn authorize_broker_call(
    tx: &Transaction<'_>,
    auth: &Auth,
    lease: &Lease,
    call: Uuid,
) -> Result<Context> {
    let active = load(tx, lease).await?;
    active.require_running_step()?;
    if active.state != "running" || active.broker_call_id != Some(call) {
        return Err(Error::conflict(
            "Broker Call is not linked to this Task attempt",
        ));
    }
    let prepared = active.prepare(tx, auth, lease).await?;
    let deadline = active.deadline(&prepared)?;
    let context = prepared.into_broker_context(tx).await?;
    require_future(active.lease_until.min(deadline), clock(tx).await?)?;
    Ok(context)
}

/// Inspect durable settlement even if the dispatch future lost its response.
pub(crate) async fn broker_outcome(tx: &Transaction<'_>, lease: &Lease) -> Result<Option<Outcome>> {
    let active = load(tx, lease).await?;
    let Some(call) = active.broker_call_id else {
        return Ok(None);
    };
    linked_outcome(tx, lease, call).await.map(Some)
}

async fn linked_outcome(tx: &Transaction<'_>, lease: &Lease, call: Uuid) -> Result<Outcome> {
    let path = crate::broker::task_call_path(lease);
    let key = lease.execution_id.to_string();
    let row = tx
        .query_one(
            "SELECT c.state,c.result,c.error,(
                SELECT r.response_status FROM idempotency_records r
                WHERE r.subject_id=c.owner_id AND r.credential_id=c.credential_id
                  AND r.method='POST' AND r.path=$2 AND r.key=$3 AND r.resource_id=c.id::text
                  AND c.http_binding IS NULL
             ) AS terminal_status FROM calls c WHERE c.id=$1",
            &[&call, &path, &key],
        )
        .await?;
    match row.get::<_, &str>("state") {
        "succeeded" => {
            let result: Option<Value> = row.get("result");
            let output = result
                .filter(|value| {
                    value["call_id"].as_str().and_then(|id| id.parse().ok()) == Some(call)
                })
                .and_then(|mut value| value.as_object_mut()?.remove("output"))
                .ok_or_else(|| Error::conflict("Saved Task Call result is unavailable"))?;
            return Ok(Outcome::Succeeded(output));
        }
        "failed" => {
            if let Some(status) = row.get("terminal_status") {
                let error = crate::broker::replay_terminal_failure(call, row.get("error"), status)?;
                return Ok(Outcome::Failed(error));
            }
        }
        _ => {}
    }
    Ok(Outcome::Unknown(
        Error::new(
            "OUTCOME_UNKNOWN",
            "Task Call has no confirmed result",
            axum::http::StatusCode::CONFLICT,
        )
        .with_resource(call),
    ))
}

/// A revoked or expired credential can close a lease that never admitted a Call.
pub(crate) async fn pause_undispatched(
    tx: &Transaction<'_>,
    lease: &Lease,
    error: &Error,
) -> Result<()> {
    if !matches!(error.code, "PERMISSION_DENIED" | "INVALID_CREDENTIAL") {
        return Err(Error::invalid(
            "Task authorization pause requires an authority error",
        ));
    }
    let active = load(tx, lease).await?;
    active.require_running_step()?;
    if active.state != "leased" || active.broker_call_id.is_some() {
        return Err(Error::conflict(
            "Only an undispatched lease can pause authorization",
        ));
    }
    let now = clock(tx).await?;
    set_live_attempt(
        tx,
        lease.attempt_id,
        "expired",
        now,
        active.row.get("deadline_at"),
    )
    .await?;
    set_step(tx, lease.step_id, "ready", None, now).await?;
    set_task(
        tx,
        lease.task_id,
        "paused_authorization",
        None,
        Some(error.detail()),
    )
    .await
}

pub async fn renew(tx: &Transaction<'_>, auth: &Auth, lease: &Lease) -> Result<DateTime<Utc>> {
    let active = load(tx, lease).await?;
    active.require_running_step()?;
    let prepared = active.prepare(tx, auth, lease).await?;
    let now = clock(tx).await?;
    let deadline = active.deadline(&prepared)?;
    require_future(active.lease_until.min(deadline), now)?;
    let until = deadline.min(now + LEASE);
    let updated = tx
        .execute(
            "UPDATE attempts SET lease_expires_at=$2,revision=revision+1,updated_at=$3
         WHERE id=$1 AND LEAST(lease_expires_at,$4::timestamptz)>clock_timestamp()",
            &[&lease.attempt_id, &until, &now, &deadline],
        )
        .await?;
    if updated != 1 {
        return Err(Error::conflict("Task attempt lease or deadline expired"));
    }
    Ok(until)
}

struct Active {
    row: Row,
    step: Value,
    state: String,
    lease_until: DateTime<Utc>,
    created_at: DateTime<Utc>,
    broker_call_id: Option<Uuid>,
}

impl Active {
    fn require_running_step(&self) -> Result<()> {
        if self.row.get::<_, String>("state") == "running"
            && self.row.get::<_, String>("step_state") == "running"
            && matches!(self.state.as_str(), "leased" | "running")
        {
            Ok(())
        } else {
            Err(Error::conflict("Task step is no longer active"))
        }
    }

    fn deadline(&self, prepared: &authority::Prepared) -> Result<DateTime<Utc>> {
        Ok(prepared
            .deadline
            .min(self.created_at + step_timeout(&self.step)?))
    }

    async fn prepare(
        &self,
        tx: &Transaction<'_>,
        auth: &Auth,
        lease: &Lease,
    ) -> Result<authority::Prepared> {
        let prepared = authority::prepare(
            tx,
            auth,
            &self.row,
            self.row.get::<_, String>("step_key").as_str(),
            lease.attempt_id,
        )
        .await?;
        if prepared.is_http != lease.is_http() {
            return Err(Error::denied());
        }
        Ok(prepared)
    }
}

async fn load(tx: &Transaction<'_>, lease: &Lease) -> Result<Active> {
    db::auth_lock(tx, false).await?;
    let query = format!("{STEP_QUERY} WHERE t.id=$1 AND s.id=$2 FOR UPDATE OF t,s");
    let row = tx
        .query_opt(&query, &[&lease.task_id, &lease.step_id])
        .await?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, i64>("step_fence") != lease.fence {
        return Err(Error::conflict("Task step fence changed"));
    }
    let attempt = tx.query_opt(
        "SELECT state,lease_expires_at,created_at,broker_call_id FROM attempts
         WHERE id=$1 AND step_id=$2 AND execution_id=$3 AND fence=$4 AND idempotency_key=$5 FOR UPDATE",
        &[&lease.attempt_id, &lease.step_id, &lease.execution_id, &lease.fence, &lease.idempotency_key],
    ).await?.ok_or_else(|| Error::conflict("Attempt identity changed"))?;
    let step = step_spec(&row, &row.get::<_, String>("step_key"))?;
    Ok(Active {
        row,
        step,
        state: attempt.get("state"),
        lease_until: attempt.get("lease_expires_at"),
        created_at: attempt.get("created_at"),
        broker_call_id: attempt.get("broker_call_id"),
    })
}

fn step_spec(row: &Row, key: &str) -> Result<Value> {
    let spec: Value = row.get("spec");
    validate("WorkflowSpec", &spec)?;
    spec["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == key)
        .cloned()
        .ok_or_else(|| Error::conflict("Task step is missing from its workflow"))
}

fn maximum_attempts(step: &Value) -> i32 {
    step["maximum_attempts"].as_i64().unwrap_or(1) as i32
}

fn step_timeout(step: &Value) -> Result<Duration> {
    Ok(Duration::milliseconds(unsigned(&step["timeout_ms"])? as i64))
}

async fn clock(tx: &Transaction<'_>) -> Result<DateTime<Utc>> {
    Ok(tx.query_one("SELECT clock_timestamp()", &[]).await?.get(0))
}

fn require_future(until: DateTime<Utc>, now: DateTime<Utc>) -> Result<()> {
    if until > now {
        Ok(())
    } else {
        Err(Error::conflict("Task attempt lease or deadline expired"))
    }
}

async fn step_input(
    tx: &Transaction<'_>,
    active: &Active,
    task: Uuid,
    prepared: &authority::Prepared,
) -> Result<Value> {
    let dependencies = active.step["depends_on"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect::<Vec<_>>();
    let complete: i64 = tx.query_one(
        "SELECT count(*) FROM task_steps WHERE task_id=$1 AND step_key=ANY($2::text[]) AND state='succeeded'",
        &[&task, &dependencies],
    ).await?.get(0);
    // Repeated dependency edges are legal and require one successful step.
    let unique: std::collections::HashSet<_> = dependencies.into_iter().collect();
    if complete != unique.len() as i64 {
        return Err(Error::conflict("Task step dependencies are incomplete"));
    }
    if prepared.http_bodyless {
        if active.step["input_mapping"]
            .as_object()
            .is_none_or(|mapping| !mapping.is_empty())
        {
            return Err(Error::invalid(
                "Bodyless HTTP Skill requires an empty Workflow input mapping",
            ));
        }
        return Ok(Value::Null);
    }
    let upstream_ids: Vec<_> = active.step["input_mapping"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|leaf| leaf["step_output"]["step"].as_str())
        .collect();
    let rows = tx.query(
        "SELECT step_key,output FROM task_steps WHERE task_id=$1 AND step_key=ANY($2::text[]) AND state='succeeded'",
        &[&task, &upstream_ids],
    ).await?;
    let upstream: HashMap<_, _> = rows
        .into_iter()
        .filter_map(|row| {
            let output: Option<Value> = row.get("output");
            output.map(|value| (row.get("step_key"), value))
        })
        .collect();
    input::materialize(
        &active.step,
        &active.row.get("input"),
        &upstream,
        prepared.maximum_input_bytes.min(MAX_STEP_JSON_BYTES),
    )
}

pub async fn complete(
    tx: &Transaction<'_>,
    auth: &Auth,
    lease: &Lease,
    outcome: Outcome,
) -> Result<Value> {
    let active = load(tx, lease).await?;
    let prepared = active.prepare(tx, auth, lease).await?;
    if let Some(call) = active.broker_call_id {
        let matches = match (&outcome, linked_outcome(tx, lease, call).await?) {
            (Outcome::Succeeded(value), Outcome::Succeeded(saved)) => value == &saved,
            (Outcome::Failed(error), Outcome::Failed(saved)) => error.detail() == saved.detail(),
            (Outcome::Unknown(_), Outcome::Unknown(_)) => true,
            _ => false,
        };
        if !matches {
            return Err(Error::conflict(
                "Task outcome does not match the linked Broker Call",
            ));
        }
    }
    let (state, output, error) = match outcome {
        Outcome::Succeeded(value) => ("succeeded", Some(value), None),
        Outcome::Failed(error) => ("failed", None, Some(error.detail())),
        Outcome::Unknown(error) => ("unknown", None, Some(error.detail())),
    };
    if active.state == state && active.row.get::<_, String>("step_state") == state {
        let matches = if let Some(output) = &output {
            let saved: Option<Value> = tx
                .query_one(
                    "SELECT output FROM task_steps WHERE id=$1",
                    &[&lease.step_id],
                )
                .await?
                .get(0);
            saved.as_ref() == Some(output)
        } else {
            active.row.get::<_, Option<Value>>("error") == error
        };
        if !matches {
            return Err(Error::conflict(
                "Attempt already has a different terminal result",
            ));
        }
        return crate::api::read_object(tx, "task_steps", lease.step_id, "TaskStep").await;
    }
    active.require_running_step()?;
    if active.state != "running" && state != "failed" {
        return Err(Error::conflict(
            "Attempt has not crossed the dispatch boundary",
        ));
    }
    if let Some(output) = &output {
        reject_jsonb_nul(output)?;
        if serde_json::to_vec(output)?.len()
            > prepared.maximum_output_bytes.min(MAX_STEP_JSON_BYTES)
        {
            return Err(Error::invalid("Task step output exceeds its byte limit"));
        }
        validate_business(&prepared.definition["output_schema"], output)?;
    }
    let now = clock(tx).await?;
    let deadline = active.deadline(&prepared)?;
    require_future(active.lease_until.min(deadline), now)?;
    set_live_attempt(tx, lease.attempt_id, state, now, deadline).await?;
    set_step(tx, lease.step_id, state, output, now).await?;
    if state == "succeeded" {
        promote_dependents(tx, lease.task_id, &active.row.get("spec"), now).await?;
    } else {
        set_task(tx, lease.task_id, state, None, error).await?;
    }
    step_event(tx, lease.task_id, lease.step_id, lease.attempt_id, state).await?;
    crate::api::read_object(tx, "task_steps", lease.step_id, "TaskStep").await
}

async fn promote_dependents(
    tx: &Transaction<'_>,
    task: Uuid,
    spec: &Value,
    now: DateTime<Utc>,
) -> Result<()> {
    tx.execute(
        "UPDATE task_steps s SET state='ready',revision=revision+1,updated_at=$3
         WHERE s.task_id=$1 AND s.state='pending' AND EXISTS (
             SELECT 1 FROM jsonb_array_elements($2::jsonb->'steps') AS node
             WHERE node->>'id'=s.step_key AND NOT EXISTS (
                 SELECT 1 FROM jsonb_array_elements_text(node->'depends_on') AS dependency(key)
                 WHERE NOT EXISTS (SELECT 1 FROM task_steps d
                     WHERE d.task_id=$1 AND d.step_key=dependency.key AND d.state='succeeded')
             )
         )",
        &[&task, &spec, &now],
    )
    .await?;
    tx.execute(
        "UPDATE tasks t SET state='succeeded',error=NULL,revision=revision+1,updated_at=$2,
                output=(SELECT jsonb_object_agg(step_key,output) FROM task_steps WHERE task_id=t.id)
         WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM task_steps WHERE task_id=t.id AND state<>'succeeded')",
        &[&task, &now],
    ).await?;
    Ok(())
}

/// Reconcile one expired attempt. Only work that never crossed `begin` can
/// return to ready; an admitted dispatch must never be automatically replayed.
pub async fn expire(tx: &Transaction<'_>) -> Result<bool> {
    db::auth_lock(tx, false).await?;
    let query = format!(
        "{ACTIVE_ATTEMPTS} AND a.lease_expires_at<=statement_timestamp()
           AND s.state='running' AND s.fence=a.fence
         ORDER BY a.lease_expires_at,a.id LIMIT 1 FOR UPDATE OF t,s,a SKIP LOCKED"
    );
    let Some(row) = tx.query_opt(&query, &[]).await? else {
        return Ok(false);
    };
    let now = clock(tx).await?;
    if row.get::<_, DateTime<Utc>>("lease_expires_at") > now {
        return Ok(false);
    }
    settle_inactive_attempt(tx, &row, now).await?;
    Ok(true)
}

/// Close old attempts after positive runtime stop or on the isolated restore
/// target. The caller holds the offline and exclusive authorization fences.
pub(crate) async fn reconcile_stopped(tx: &Transaction<'_>) -> Result<()> {
    let query = format!("{ACTIVE_ATTEMPTS} ORDER BY t.id,s.id,a.id LIMIT 64 FOR UPDATE OF t,s,a");
    let mut previous_task = None;
    loop {
        let rows = tx.query(&query, &[]).await?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            let task: Uuid = row.get("id");
            if previous_task.replace(task) == Some(task) {
                return Err(Error::conflict("Task has multiple active steps"));
            }
            if row.get::<_, String>("step_state") != "running"
                || row.get::<_, i64>("step_fence") != row.get::<_, i64>("attempt_fence")
            {
                return Err(Error::conflict(
                    "Active Task attempt does not match its step fence",
                ));
            }
            settle_inactive_attempt(tx, &row, clock(tx).await?).await?;
        }
    }
}

async fn settle_inactive_attempt(
    tx: &Transaction<'_>,
    row: &Row,
    now: DateTime<Utc>,
) -> Result<()> {
    let task = row.get("id");
    let step = row.get("step_id");
    let attempt = row.get("attempt_id");
    let call: Option<Uuid> = row.get("broker_call_id");
    if row.get::<_, String>("attempt_state") == "running" || call.is_some() {
        set_attempt(tx, attempt, "unknown", now).await?;
        set_step(tx, step, "unknown", None, now).await?;
        let reason = Error::new(
            "OUTCOME_UNKNOWN",
            "Task attempt ended without a committed outcome",
            axum::http::StatusCode::CONFLICT,
        );
        let reason = if let Some(call) = call {
            reason.with_resource(call)
        } else {
            reason
        };
        if !matches!(
            row.get::<_, String>("state").as_str(),
            "succeeded" | "failed" | "canceled"
        ) {
            set_task(tx, task, "unknown", None, Some(reason.detail())).await?;
        }
        step_event(tx, task, step, attempt, "unknown").await?;
    } else {
        let spec = step_spec(row, &row.get::<_, String>("step_key"))?;
        set_attempt(tx, attempt, "expired", now).await?;
        let task_state: String = row.get("state");
        if task_state == "running"
            && row.get::<_, DateTime<Utc>>("deadline_at") > now
            && row.get::<_, i32>("attempt_count") < maximum_attempts(&spec)
        {
            set_step(tx, step, "ready", None, now).await?;
        } else {
            set_step(tx, step, "failed", None, now).await?;
            let reason = Error::new(
                "DEADLINE_EXCEEDED",
                "Task attempt ended before dispatch",
                axum::http::StatusCode::GATEWAY_TIMEOUT,
            );
            if task_state == "running" {
                set_task(tx, task, "failed", None, Some(reason.detail())).await?;
            }
            step_event(tx, task, step, attempt, "failed").await?;
        }
    }
    Ok(())
}

/// Close a bounded batch of Tasks whose deadline elapsed without active or
/// uncertain work. The existing step results and Broker ledger stay intact.
pub async fn expire_idle(tx: &Transaction<'_>) -> Result<u64> {
    db::auth_lock(tx, false).await?;
    let select = format!(
        "SELECT t.id FROM tasks t WHERE {IDLE_DEADLINE_DUE}
         ORDER BY t.deadline_at,t.id LIMIT 16 FOR UPDATE OF t SKIP LOCKED"
    );
    let tasks: Vec<Uuid> = tx
        .query(&select, &[])
        .await?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    if tasks.is_empty() {
        return Ok(0);
    }

    // A claim or completion may have committed after selection took its
    // snapshot. Recheck the Task and its steps under the acquired Task locks.
    let update = format!(
        "UPDATE tasks t SET state='failed',error=$2,revision=revision+1,updated_at=clock_timestamp()
         WHERE t.id=ANY($1) AND {IDLE_DEADLINE_DUE}"
    );
    let error = Error::new(
        "DEADLINE_EXCEEDED",
        "Task deadline elapsed with no active step",
        axum::http::StatusCode::GATEWAY_TIMEOUT,
    );
    Ok(tx.execute(&update, &[&tasks, &error.detail()]).await?)
}

async fn set_attempt(
    tx: &Transaction<'_>,
    attempt: Uuid,
    state: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    tx.execute(
        "UPDATE attempts SET state=$2,revision=revision+1,updated_at=$3 WHERE id=$1",
        &[&attempt, &state, &now],
    )
    .await?;
    Ok(())
}

async fn set_step(
    tx: &Transaction<'_>,
    step: Uuid,
    state: &str,
    output: Option<Value>,
    now: DateTime<Utc>,
) -> Result<()> {
    tx.execute(
        "UPDATE task_steps SET state=$2,output=$3,revision=revision+1,updated_at=$4 WHERE id=$1",
        &[&step, &state, &output, &now],
    )
    .await?;
    Ok(())
}

async fn set_live_attempt(
    tx: &Transaction<'_>,
    attempt: Uuid,
    state: &str,
    now: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Result<()> {
    let updated = tx
        .execute(
            "UPDATE attempts SET state=$2,revision=revision+1,updated_at=$3
         WHERE id=$1 AND LEAST(lease_expires_at,$4::timestamptz)>clock_timestamp()",
            &[&attempt, &state, &now, &deadline],
        )
        .await?;
    if updated != 1 {
        return Err(Error::conflict("Task attempt lease or deadline expired"));
    }
    Ok(())
}

async fn set_task(
    tx: &Transaction<'_>,
    task: Uuid,
    state: &str,
    output: Option<Value>,
    error: Option<Value>,
) -> Result<()> {
    tx.execute("UPDATE tasks SET state=$2,output=$3,error=$4,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1", &[&task, &state, &output, &error]).await?;
    Ok(())
}

async fn step_event(
    tx: &Transaction<'_>,
    task: Uuid,
    step: Uuid,
    attempt: Uuid,
    state: &str,
) -> Result<()> {
    db::outbox(
        tx,
        "task.step.completed",
        step,
        &json!({"task_id":task,"step_id":step,"attempt_id":attempt,"state":state}),
    )
    .await
}
