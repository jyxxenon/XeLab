//! Authorization and the active-slot transaction for Capability RPCs.
use super::{
    business_slot_available, check_task_manifest, reserve_call_quota, skill_result, CallRequest,
    CallSource,
};
use crate::{
    api::App,
    auth::{authorize, Context, CurrentAuthority, Resource},
    broker_queue::{self, Instance, Ticket},
    contracts::{digest, id, string, unsigned, validate, validate_business},
    db,
    error::{Error, Result},
    host_blobs, host_calls,
    policy::Path,
    skills::ResolvedSkill,
    task_engine,
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::{borrow::Cow, time::Duration};
use tokio::time::{timeout_at, Instant};
use tokio_postgres::{GenericClient, Row, Transaction};
use uuid::Uuid;

pub(super) struct Request<'a> {
    pub app: &'a App,
    pub request: CallRequest<'a>,
    pub request_id: Uuid,
    pub key: &'a str,
    pub stream: Option<&'a crate::skill_streams::Output>,
    pub started: DateTime<Utc>,
    pub deadline_bound: Instant,
}

pub(super) enum Admission {
    Replay(Value),
    Dispatch(Box<Call>),
}

pub(super) struct Call {
    pub ctx: Context,
    pub skill: Option<ResolvedSkill>,
    pub instance: Instance,
    pub deployment: Uuid,
    pub contract: Value,
    pub definition: Value,
    pub bytes: Vec<u8>,
    pub deadline: DateTime<Utc>,
    pub protected: bool,
    pub id: Uuid,
    pub delegation: String,
    pub accounts: Vec<Uuid>,
    pub business_key: String,
}

struct WaitingCall {
    ticket: Ticket,
    subject: Uuid,
    credential: Uuid,
    skill_digest: String,
    installation: Uuid,
    deployment: Uuid,
    sources: Vec<Path>,
}

struct Candidate<'tx, 'db> {
    ctx: Context,
    skill: Option<ResolvedSkill>,
    instance: Instance,
    deployment: Uuid,
    manifest: Value,
    contract: Value,
    definition: Value,
    capability: Resource,
    deadline: DateTime<Utc>,
    protected: bool,
    authority: Option<CurrentAuthority<'tx, 'db>>,
    input: Cow<'db, Value>,
    business_key: String,
    path: String,
    fingerprint: String,
}

enum Decision<'tx, 'db> {
    Replay(Value),
    Rejected(Error),
    Retry,
    Enqueue,
    Wait,
    Ready(Box<Candidate<'tx, 'db>>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Attempt {
    Initial,
    Preview,
    Admit,
}

impl Request<'_> {
    pub(super) async fn admit(&self) -> Result<Admission> {
        let token_input = if let CallRequest::Token { input, skill, .. } = self.request {
            validate(
                if skill.is_some() {
                    "SkillInvokeRequest"
                } else {
                    "InvokeRequest"
                },
                input,
            )?;
            let path = skill.map_or_else(
                || "/api/platform/v1/calls".to_owned(),
                |id| {
                    format!(
                        "/api/platform/v1/skills/{id}/calls{}",
                        if self.stream.is_some() { ":stream" } else { "" }
                    )
                },
            );
            Some((
                path,
                digest(&serde_json::to_vec(input)?),
                serde_json::to_vec(&input["input"])?.len(),
            ))
        } else {
            None
        };
        let mut waiting: Option<WaitingCall> = None;
        let mut inspect_queue = self.can_enqueue_without_ledger();
        let mut enqueue = false;
        loop {
            let background = if let Some(waiter) = waiting.as_ref() {
                waiter.ticket.background_permit().await?
            } else {
                None
            };
            let until = waiting
                .as_ref()
                .map_or(self.deadline_bound, |waiter| waiter.ticket.deadline);
            let expired = if waiting.is_some() {
                broker_queue::expired
            } else {
                call_expired
            };
            let now = Instant::now();
            if now >= until {
                return Err(expired());
            }
            let mut c = timeout_at(until, self.app.db.connect_scoped(until - now))
                .await
                .map_err(|_| expired())??;
            let initial = std::mem::take(&mut inspect_queue);
            let attempt = if std::mem::take(&mut enqueue)
                || initial
                    && timeout_at(until, self.queue_busy(&*c))
                        .await
                        .map_err(|_| expired())?
                        .unwrap_or(false)
            {
                Attempt::Preview
            } else if initial {
                Attempt::Initial
            } else {
                Attempt::Admit
            };
            let tx = timeout_at(until, c.transaction())
                .await
                .map_err(|_| expired())??;
            let decision = timeout_at(
                until,
                self.prepare(&tx, &mut waiting, attempt, token_input.as_ref()),
            )
            .await
            .map_err(|_| expired())??;
            let candidate = match decision {
                Decision::Replay(result) => return Ok(Admission::Replay(result)),
                Decision::Rejected(error) => {
                    tx.commit().await?;
                    return Err(error);
                }
                Decision::Retry | Decision::Enqueue => {
                    enqueue = matches!(decision, Decision::Enqueue);
                    tx.rollback().await?;
                    continue;
                }
                Decision::Wait => {
                    tx.rollback().await?;
                    drop(c);
                    drop(background);
                    waiting
                        .as_ref()
                        .expect("registered waiter")
                        .ticket
                        .wait()
                        .await;
                    continue;
                }
                Decision::Ready(candidate) => candidate,
            };

            // Keep the signed wait deadline through staging. A timed-out
            // transaction rolls back without a Call or any quota charge.
            let call = timeout_at(until, self.record(&tx, *candidate))
                .await
                .map_err(|_| expired())??;
            if waiting.is_some() {
                crate::skill_streams::ensure_active(self.app)?;
            }
            if Instant::now() >= until {
                return Err(expired());
            }
            tx.commit().await?;
            return Ok(Admission::Dispatch(Box::new(call)));
        }
    }

    fn can_enqueue_without_ledger(&self) -> bool {
        self.stream.is_none()
            && match self.request {
                CallRequest::Task(_) => true,
                CallRequest::Token { token, skill, .. } => {
                    skill.is_some() && !token.starts_with("host:")
                }
            }
    }

    /// This lookup only chooses the read-only waiting path. All selections and
    /// permissions are checked in the following authorization transaction.
    async fn queue_busy(&self, c: &(impl GenericClient + Sync)) -> Result<bool> {
        let CallRequest::Token { input, skill, .. } = self.request else {
            return Ok(false);
        };
        let row = c.query_opt(
            "SELECT s.definition,s.installation_id,n.manifest->'concurrency'->'max_queue_requests' AS queue_limit
               FROM skills s JOIN installations n ON n.id=s.installation_id WHERE s.id=$1",
            &[&skill],
        ).await?;
        let Some(row) = row else { return Ok(false) };
        if row
            .get::<_, Option<Value>>("queue_limit")
            .and_then(|limit| limit.as_u64())
            .unwrap_or(0)
            == 0
        {
            return Ok(false);
        }
        let definition: Value = row.get("definition");
        let contract = &definition["target"]["contract"];
        let fixed = input
            .get("provider_deployment_id")
            .map(|_| id(input, "provider_deployment_id"))
            .transpose()?;
        let row = provider(
            c,
            string(contract, "name")?,
            string(contract, "version")?,
            fixed,
            Some(row.get("installation_id")),
            None,
            false,
            false,
        )
        .await?;
        let instance = Instance {
            id: row.get("id"),
            generation: row.get("generation"),
        };
        Ok(self.app.runtime.business_queue.has_waiters(instance)
            || !business_slot_available(c, instance.id, &row.get("manifest")).await?)
    }

    async fn record(&self, tx: &Transaction<'_>, candidate: Candidate<'_, '_>) -> Result<Call> {
        let Candidate {
            ctx,
            skill,
            instance,
            deployment,
            manifest,
            contract,
            definition,
            capability,
            deadline,
            protected,
            authority,
            input,
            business_key,
            path,
            fingerprint,
        } = candidate;
        let source = self.request.source();
        let (accounts, charged) = reserve_call_quota(
            tx,
            &ctx,
            "capability.invoke",
            &capability,
            skill.as_ref(),
            authority.as_ref(),
        )
        .await?;
        let call = match source.token() {
            Some(token) => host_calls::new_call(tx, self.app, token).await?,
            None => Uuid::new_v4(),
        };
        if deadline <= Utc::now() {
            return Err(call_expired());
        }
        let bytes = serde_json::to_vec(input.as_ref())?;
        tx.execute("INSERT INTO calls(id,owner_id,credential_id,provider_instance_id,contract,input_digest,idempotency_key,state,deadline_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8,now())",&[&call,&ctx.subject,&ctx.credential,&instance.id,&contract,&digest(&bytes),&business_key,&deadline]).await?;
        if let Some(skill) = &skill {
            tx.execute(
                "UPDATE calls SET skill_id=$2,skill_definition_digest=$3 WHERE id=$1",
                &[&call, &skill.id, &skill.definition_digest],
            )
            .await?;
        }
        for credential in charged {
            tx.execute(
                "INSERT INTO call_credential_charges(call_id,credential_id) VALUES($1,$2)",
                &[&call, &credential],
            )
            .await?;
        }
        tx.execute("INSERT INTO reservations(id,account_id,kind,expires_at,status,created_at) VALUES($1,$2,'call',$3,'active',now())", &[&call,&ctx.subject,&deadline]).await?;
        if let Some(token) = source.token() {
            host_calls::bind_child(tx, self.app, token, call, instance.id).await?;
        }
        let delegation = self
            .app
            .auth
            .issue_rpc(tx, &ctx, call, instance.id, instance.generation, deadline)
            .await?;
        host_blobs::grant_skill_call(
            tx,
            self.app,
            &ctx,
            call,
            deployment,
            &manifest,
            &definition,
            &input,
            skill
                .as_ref()
                .is_none_or(|s| s.definition["input_blobs"] == true),
        )
        .await?;
        if protected {
            host_blobs::check_call_sources(tx, &ctx, call).await?;
        }
        if let CallSource::Task(lease) = source {
            task_engine::record_broker_call(tx, lease, call).await?;
            crate::skill_streams::ensure_active(self.app)?;
        }
        tx.execute("DELETE FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method='POST' AND path=$4 AND key=$3 AND expires_at<=now()",&[&ctx.subject,&ctx.credential,&self.key,&path]).await?;
        tx.execute("INSERT INTO idempotency_records(subject_id,credential_id,method,path,key,fingerprint,resource_id,expires_at,created_at) VALUES($1,$2,'POST',$6,$3,$4,$5,now()+interval '24 hours',now())",&[&ctx.subject,&ctx.credential,&self.key,&fingerprint,&call.to_string(),&path]).await?;
        if let Some(stream) = self.stream {
            stream.ensure_open()?;
        }
        Ok(Call {
            ctx,
            skill,
            instance,
            deployment,
            contract,
            definition,
            bytes,
            deadline,
            protected,
            id: call,
            delegation,
            accounts,
            business_key,
        })
    }

    async fn prepare<'tx, 'db>(
        &'db self,
        tx: &'tx Transaction<'db>,
        waiting: &mut Option<WaitingCall>,
        attempt: Attempt,
        token_input: Option<&(String, String, usize)>,
    ) -> Result<Decision<'tx, 'db>> {
        let app = self.app;
        if waiting.is_some() {
            crate::skill_streams::ensure_active(app)?;
        }
        let front = waiting
            .as_ref()
            .is_none_or(|waiter| waiter.ticket.is_head());
        let preview = attempt == Attempt::Preview;
        let can_admit = front && !preview;
        if can_admit {
            db::call_lock(tx).await?;
            if attempt == Attempt::Initial && self.queue_busy(tx).await.unwrap_or(false) {
                // Another admission may have filled the last slot while this
                // request waited for the ledger. Authorize its wait in a new
                // transaction so active Calls can settle in the meantime.
                return Ok(Decision::Enqueue);
            }
        } else {
            // Waiting-only work checks live binding and authority without
            // serializing behind the durable Call ledger.
            db::auth_lock(tx, false).await?;
        }
        let origin = self.request.source();
        let (ctx, body, skill_id, task_deadline, path, fingerprint, input_bytes) = match self
            .request
        {
            CallRequest::Token { input, skill, .. } => {
                let (path, fingerprint, input_bytes) = token_input.expect("validated token call");
                (
                    origin.authenticate(tx, app, self.request_id, None).await?,
                    Cow::Borrowed(input),
                    skill,
                    None,
                    path.clone(),
                    fingerprint.clone(),
                    *input_bytes,
                )
            }
            CallRequest::Task(lease) => {
                let (invocation, ctx) = task_engine::prepare_broker(tx, &app.auth, lease).await?;
                let body = json!({
                    "input":invocation.input,
                    "provider_deployment_id":invocation.deployment_id,
                    "idempotency_key":invocation.idempotency_key,
                });
                validate("SkillInvokeRequest", &body)?;
                let fingerprint = digest(&serde_json::to_vec(&body)?);
                let input_bytes = serde_json::to_vec(&body["input"])?.len();
                (
                    ctx,
                    Cow::Owned(body),
                    Some(invocation.skill_id),
                    Some(
                        invocation
                            .deadline
                            .min(self.started + chrono::Duration::seconds(300)),
                    ),
                    super::task_call_path(lease),
                    fingerprint,
                    input_bytes,
                )
            }
        };
        let task = task_deadline.is_some();
        let skill = if let Some(id) = skill_id {
            match crate::skills::resolve_for_invoke(tx, &ctx, id).await {
                Ok(skill) => Some(skill),
                Err(error) if task => return Err(error),
                Err(error) => {
                    db::audit(
                        tx,
                        ctx.subject,
                        Some(ctx.credential),
                        self.request_id,
                        "skill.invoke",
                        &Resource::new("skill", id, None).json(),
                        "denied",
                        error.code,
                    )
                    .await?;
                    return Ok(Decision::Rejected(error));
                }
            }
        } else {
            None
        };
        let input = &body["input"];
        let timeout = body.get("timeout_ms").map(unsigned).transpose()?;
        let (contract, timeout) = if let Some(skill) = &skill {
            let maximum = unsigned(&skill.definition["maximum_timeout_ms"])?;
            let timeout = timeout.unwrap_or(120000.min(maximum));
            if timeout > maximum {
                return Err(Error::invalid(
                    "Requested deadline exceeds the fixed Skill maximum",
                ));
            }
            if front {
                validate_business(&skill.definition["input_schema"], input)?;
            }
            (&skill.definition["target"]["contract"], timeout)
        } else {
            (&body["contract"], timeout.unwrap_or(30000))
        };
        let name = string(contract, "name")?;
        let version = string(contract, "version")?;
        let schema_digest = string(contract, "schema_digest")?;
        let capability = Resource::new("capability", format!("{name}@{version}"), None);
        if let Err(error) = authorize(tx, &ctx, "capability.invoke", &capability).await {
            if task {
                return Err(error);
            }
            db::audit(
                tx,
                ctx.subject,
                Some(ctx.credential),
                self.request_id,
                "capability.invoke",
                &capability.json(),
                "denied",
                error.code,
            )
            .await?;
            return Ok(Decision::Rejected(error));
        }
        let cap = tx
            .query_opt(
                "SELECT spec,schema_digest FROM capability_contracts WHERE name=$1 AND version=$2",
                &[&name, &version],
            )
            .await?
            .ok_or_else(Error::not_found)?;
        if cap.get::<_, String>("schema_digest") != schema_digest {
            return Err(Error::conflict("Capability digest differs"));
        }
        let definition: Value = cap.get("spec");
        if !matches!(
            definition["side_effect"].as_str(),
            Some("none" | "idempotent" | "queryable" | "non_repeatable")
        ) {
            return Err(Error::invalid(
                "Unsupported capability side-effect semantics",
            ));
        }
        if self.stream.is_some() && definition["stream_item_schema"].is_null() {
            return Err(Error::invalid(
                "Capability does not declare a streaming item schema",
            ));
        }
        let mut protected = skill.is_some()
            || definition["side_effect"] != "none"
            || origin
                .token()
                .is_some_and(|token| token.starts_with("host:"));
        let fixed = body
            .get("provider_deployment_id")
            .map(|_| id(&body, "provider_deployment_id"))
            .transpose()?;
        let installation = skill.as_ref().map(|s| s.installation_id);

        let mut authority = None;
        let mut pinned = None;
        if let Some(waiter) = waiting.as_ref() {
            let skill = skill.as_ref().ok_or_else(Error::denied)?;
            if ctx.subject != waiter.subject
                || ctx.credential != waiter.credential
                || skill.definition_digest != waiter.skill_digest
                || skill.installation_id != waiter.installation
            {
                return Err(Error::denied());
            }
            let proof = CurrentAuthority::new(tx, &ctx)
                .await?
                .restrict_to(tx, &ctx, &waiter.sources)
                .await?;
            proof.require(tx, &ctx, "skill.invoke", &skill_resource(skill))?;
            proof.require(tx, &ctx, "capability.invoke", &capability)?;
            if front {
                // Disable/upgrade locks the deployment before its instances.
                tx.query_opt(
                    "SELECT id FROM deployments WHERE id=$1 AND spec->>'enabled'='true' AND archived_at IS NULL FOR SHARE",
                    &[&waiter.deployment],
                ).await?.ok_or_else(|| Error::unavailable("Queued deployment is no longer enabled"))?;
            }
            let row = provider(
                tx,
                name,
                version,
                Some(waiter.deployment),
                installation,
                Some(waiter.ticket.instance),
                front,
                task,
            )
            .await?;
            crate::dependencies::check_ready(tx, app, row.get("deployment_id")).await?;
            pinned = Some(row);
            authority = Some(proof);
        }

        let prior = if can_admit {
            let lock = format!(
                "call:{}:{}:{path}:{}",
                ctx.subject, ctx.credential, self.key
            );
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock],
            )
            .await?;
            tx.query_opt("SELECT * FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method='POST' AND path=$4 AND key=$3 AND expires_at>now() FOR UPDATE", &[&ctx.subject,&ctx.credential,&self.key,&path]).await?
        } else if preview && tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method='POST' AND path=$4 AND key=$3 AND expires_at>now())",
            &[&ctx.subject,&ctx.credential,&self.key,&path],
        ).await?.get(0) {
            return Ok(Decision::Retry);
        } else {
            None
        };
        if let Some(r) = prior {
            if task {
                return Err(Error::conflict("Task attempt already has a Broker record"));
            }
            if r.get::<_, String>("fingerprint") != fingerprint {
                return Err(Error::new(
                    "IDEMPOTENCY_CONFLICT",
                    "The key was already used for different input",
                    axum::http::StatusCode::CONFLICT,
                ));
            }
            let call = r
                .get::<_, Option<String>>("resource_id")
                .and_then(|s| s.parse::<Uuid>().ok())
                .ok_or_else(|| Error::conflict("Missing prior call"))?;
            if self.stream.is_some() {
                return Err(Error::conflict(
                    "Generation streams cannot be replayed; inspect the admitted Call",
                )
                .with_resource(call));
            }
            let row = tx
                .query_one("SELECT state,result FROM calls WHERE id=$1", &[&call])
                .await?;
            if row.get::<_, String>("state") == "succeeded" {
                let deployment: Uuid = tx.query_one(
                    "SELECT i.deployment_id FROM calls c JOIN instances i ON i.id=c.provider_instance_id WHERE c.id=$1",
                    &[&call],
                ).await?.get(0);
                crate::dependencies::check_ready(tx, app, deployment).await?;
                if protected
                    || tx
                        .query_one(
                            "SELECT EXISTS(SELECT 1 FROM host_rpc_contexts WHERE call_id=$1)",
                            &[&call],
                        )
                        .await?
                        .get::<_, bool>(0)
                {
                    super::check_skill_authority(tx, &ctx, call).await?;
                }
                let value = row
                    .get::<_, Option<Value>>("result")
                    .ok_or_else(|| Error::conflict("Call result is unavailable"))?;
                return skill_result(skill.as_ref(), value).map(Decision::Replay);
            }
            return Err(Error::new(
                "OUTCOME_UNKNOWN",
                "Prior call is not a confirmed success; query its call ID",
                axum::http::StatusCode::CONFLICT,
            )
            .with_resource(call));
        }
        if input_bytes
            > app
                .config
                .json_limit(unsigned(&definition["maximum_input_bytes"])? as usize)
        {
            return Err(Error::invalid("Capability input exceeds its byte limit"));
        }
        if front {
            validate_business(&definition["input_schema"], input)?;
        }
        let row = if let Some(row) = pinned {
            row
        } else {
            let row = provider(
                tx,
                name,
                version,
                fixed,
                installation,
                None,
                can_admit,
                task,
            )
            .await?;
            crate::dependencies::check_ready(tx, app, row.get("deployment_id")).await?;
            row
        };
        let instance = Instance {
            id: row.get("id"),
            generation: row.get("generation"),
        };
        let deployment = row.get("deployment_id");
        let manifest: Value = row.get("manifest");
        if task {
            check_task_manifest(&manifest)?;
        }
        protected |= manifest["dependencies"]
            .as_array()
            .is_some_and(|d| !d.is_empty());
        if front && definition["side_effect"] != "none" {
            crate::artifact::validate_runtime_profile(&manifest)?;
            if !manifest["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cap| {
                    cap["contract"] == *contract
                        && cap["side_effect"] == definition["side_effect"]
                        && [
                            "input_schema",
                            "output_schema",
                            "stream_item_schema",
                            "maximum_input_bytes",
                            "maximum_output_bytes",
                        ]
                        .iter()
                        .all(|field| cap[*field] == definition[*field])
                })
            {
                return Err(Error::invalid(
                    "Side-effecting execution requires its exact signed capability",
                ));
            }
        }
        if manifest["business_entry"] == "skill_required" && skill.is_none() {
            return Err(Error::denied());
        }
        let has_proxy = manifest["requested_rules"].as_array().is_some_and(|rules| {
            rules.iter().any(|request| {
                host_blobs::proxy_action(
                    request["rule"]["action"].as_str().unwrap_or(""),
                    request["rule"]["resource"]["kind"].as_str().unwrap_or(""),
                )
            })
        });
        protected |= has_proxy;
        let deadline = match origin.token() {
            Some(token) => {
                host_calls::bound_deadline(
                    tx,
                    app,
                    token,
                    self.started + chrono::Duration::milliseconds(timeout as i64),
                )
                .await?
            }
            None => task_deadline.ok_or_else(Error::denied)?,
        };
        if deadline <= Utc::now() {
            return Err(call_expired());
        }
        let queue = &app.runtime.business_queue;
        let turn = waiting
            .as_ref()
            .map_or_else(|| !queue.has_waiters(instance), |_| front);
        if !turn || !business_slot_available(tx, instance.id, &manifest).await? {
            let limit = manifest["concurrency"]["max_queue_requests"]
                .as_u64()
                .unwrap_or(0);
            let skill = skill
                .as_ref()
                .filter(|_| {
                    limit > 0 && self.stream.is_none() && broker_queue::supports_manifest(&manifest)
                })
                .ok_or_else(Error::exhausted)?;
            if waiting.is_none() && !preview && self.can_enqueue_without_ledger() {
                // The provider became busy after the optimistic lookup. Let
                // Call finalizers through before expanding the queued proof.
                return Ok(Decision::Enqueue);
            }
            if has_proxy {
                let inputs = host_blobs::authorize_skill_blob_inputs(
                    tx,
                    app,
                    &ctx,
                    deployment,
                    &manifest,
                    &definition,
                    input,
                    skill.definition["input_blobs"] == true,
                )
                .await?;
                // Each authorized input already checked the current signed
                // approval. Without an input, check approval independently.
                if inputs.is_empty() {
                    host_blobs::check_approval(tx, app, deployment, &manifest).await?;
                }
            }
            if waiting.is_none() {
                let maximum =
                    Duration::from_millis(unsigned(&manifest["concurrency"]["queue_timeout_ms"])?);
                if let Some(token) = origin.token() {
                    host_calls::check_queued_child(tx, app, token, instance.id).await?;
                }
                let proof = CurrentAuthority::new(tx, &ctx).await?;
                let skill_resource = skill_resource(skill);
                let sources = proof
                    .paths(tx, &ctx, &capability)?
                    .iter()
                    .filter_map(|path| {
                        let rules = json!([&path.rule]);
                        let resource = if crate::auth::rules_allow(
                            &rules,
                            "capability.invoke",
                            &capability,
                            ctx.peer,
                        ) {
                            &capability
                        } else if crate::auth::rules_allow(
                            &rules,
                            "skill.invoke",
                            &skill_resource,
                            ctx.peer,
                        ) {
                            &skill_resource
                        } else {
                            return None;
                        };
                        let mut path = path.clone();
                        path.rule["resource"] = resource.json();
                        Some(path)
                    })
                    .collect();
                let remaining = (deadline - Utc::now())
                    .to_std()
                    .map_err(|_| call_expired())?;
                let deadline = self
                    .deadline_bound
                    .min(Instant::now() + maximum.min(remaining));
                let ticket = queue.enqueue(instance, limit as usize, deadline)?;
                *waiting = Some(WaitingCall {
                    ticket,
                    subject: ctx.subject,
                    credential: ctx.credential,
                    skill_digest: skill.definition_digest.clone(),
                    installation: skill.installation_id,
                    deployment,
                    sources,
                });
            }
            return Ok(Decision::Wait);
        }
        if preview {
            return Ok(Decision::Retry);
        }
        let contract = contract.clone();
        let business_key = body["idempotency_key"]
            .as_str()
            .unwrap_or(self.key)
            .to_owned();
        let input = match body {
            Cow::Borrowed(body) => Cow::Borrowed(&body["input"]),
            Cow::Owned(mut body) => Cow::Owned(body["input"].take()),
        };
        Ok(Decision::Ready(Box::new(Candidate {
            contract,
            ctx,
            skill,
            instance,
            deployment,
            manifest,
            definition,
            capability,
            deadline,
            protected,
            authority,
            input,
            business_key,
            path,
            fingerprint,
        })))
    }
}

fn skill_resource(skill: &ResolvedSkill) -> Resource {
    Resource::new("skill", skill.id, Some(skill.owner))
}

async fn provider(
    c: &(impl GenericClient + Sync),
    name: &str,
    version: &str,
    fixed: Option<Uuid>,
    installation: Option<Uuid>,
    pinned: Option<Instance>,
    lock_instance: bool,
    require_generation: bool,
) -> Result<Row> {
    let instance = pinned.map(|instance| instance.id);
    let generation = pinned.map(|instance| instance.generation);
    let lock = if lock_instance {
        " FOR UPDATE OF i"
    } else {
        ""
    };
    let statement = format!(
        "SELECT i.id,i.generation,d.id AS deployment_id,n.manifest
           FROM provider_records p JOIN instances i ON i.id=p.instance_id
           JOIN deployments d ON d.id=i.deployment_id JOIN installations n ON n.id=d.installation_id
          WHERE p.name=$1 AND p.version=$2 AND p.availability='ready'
            AND p.observed_at>clock_timestamp()-interval '1 millisecond'*
                ((n.manifest->'health'->>'interval_ms')::bigint*(n.manifest->'health'->>'failure_threshold')::bigint
                +(n.manifest->'health'->>'timeout_ms')::bigint)
            AND i.phase='ready' AND d.spec->>'enabled'='true' AND d.archived_at IS NULL
            AND ($3::uuid IS NULL OR d.id=$3) AND ($4::uuid IS NULL OR n.id=$4)
            AND ($5::uuid IS NULL OR (i.id=$5 AND i.generation=$6 AND p.observed_generation=$6))
            AND (NOT $7::boolean OR p.observed_generation=i.generation)
          ORDER BY i.id LIMIT 1{lock}",
    );
    c.query_opt(
        &statement,
        &[
            &name,
            &version,
            &fixed,
            &installation,
            &instance,
            &generation,
            &require_generation,
        ],
    )
    .await?
    .ok_or_else(|| Error::unavailable("No healthy fixed provider is available"))
}

fn call_expired() -> Error {
    Error::new(
        "DEADLINE_EXCEEDED",
        "Call admission exceeded its deadline",
        axum::http::StatusCode::GATEWAY_TIMEOUT,
    )
}
