use crate::{
    auth::{Context, Resource},
    contracts::{id, string, unsigned},
    error::{Error, Result},
    policy::Path,
    skills::ResolvedSkill,
};
use serde_json::{json, Value};
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub(super) struct Target {
    pub(super) action: String,
    pub(super) resource: Resource,
    pub(super) paths: Vec<Path>,
}

impl Target {
    fn new(action: impl Into<String>, resource: Resource) -> Self {
        Self {
            action: action.into(),
            resource,
            paths: Vec::new(),
        }
    }

    fn record(&self) -> Value {
        json!({"action": self.action, "resource": self.resource.json(),
            "owner_id": self.resource.owner, "paths": self.paths})
    }
}

struct Provider {
    deployment: Uuid,
    installation: Uuid,
}

pub(super) struct StepAdmission {
    step_key: String,
    provider: Option<Provider>,
    binding: Value,
    pub(super) synchronous_skill: bool,
    pub(super) targets: Vec<Target>,
}

impl StepAdmission {
    pub(super) fn deployment_id(&self) -> Option<Uuid> {
        self.provider.as_ref().map(|p| p.deployment)
    }

    pub(super) fn record(&self) -> Value {
        json!({
            "step_key": self.step_key,
            "deployment_id": self.deployment_id(),
            "installation_id": self.provider.as_ref().map(|p| p.installation),
            "binding": self.binding,
            "targets": self.targets.iter().map(Target::record).collect::<Vec<_>>(),
        })
    }
}

pub(super) async fn resolve(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    step: &Value,
) -> Result<StepAdmission> {
    resolve_selected(c, ctx, step, None).await
}

pub(super) async fn resolve_pinned(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    step: &Value,
    deployment: Uuid,
    installation: Uuid,
) -> Result<StepAdmission> {
    resolve_selected(c, ctx, step, Some((deployment, installation))).await
}

async fn resolve_selected(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    step: &Value,
    pin: Option<(Uuid, Uuid)>,
) -> Result<StepAdmission> {
    let mut targets = Vec::new();
    let step_key = string(step, "id")?.to_owned();
    let skill = if step.get("skill_id").is_some() {
        let skill_id = id(step, "skill_id")?;
        if let Some((_, installation)) = pin {
            let row = c
                .query_opt(
                    "SELECT installation_id,archived_at IS NOT NULL AS archived
                 FROM skills WHERE id=$1 FOR SHARE",
                    &[&skill_id],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            if row.get::<_, bool>("archived")
                || row.get::<_, Uuid>("installation_id") != installation
            {
                return Err(Error::conflict("Scheduled Skill binding changed"));
            }
        }
        let skill = crate::skills::resolve_for_invoke(c, ctx, skill_id).await?;
        if unsigned(&step["timeout_ms"])? > unsigned(&skill.definition["maximum_timeout_ms"])? {
            return Err(Error::invalid("Workflow step exceeds the Skill timeout"));
        }
        targets.push(Target::new(
            "skill.invoke",
            Resource::new("skill", skill.id, Some(skill.owner)),
        ));
        Some(skill)
    } else {
        None
    };

    if let Some((deployment, installation)) = pin {
        let row = c
            .query_opt(
                "SELECT installation_id,archived_at IS NOT NULL AS archived,
                    coalesce(spec->>'enabled'='true',false) AS enabled
             FROM deployments WHERE id=$1 FOR SHARE",
                &[&deployment],
            )
            .await?
            .ok_or_else(Error::not_found)?;
        if row.get::<_, bool>("archived") || row.get::<_, Uuid>("installation_id") != installation {
            return Err(Error::conflict("Scheduled deployment binding changed"));
        }
        if !row.get::<_, bool>("enabled") {
            return Err(Error::unavailable("Scheduled deployment is disabled"));
        }
    }

    if let Some(skill) = skill
        .as_ref()
        .filter(|skill| skill.definition["target"]["kind"] == "http")
    {
        let (provider, binding, target, synchronous_skill) =
            http_provider(c, ctx, skill, pin.map(|(deployment, _)| deployment)).await?;
        targets.push(target);
        return Ok(StepAdmission {
            step_key,
            provider: Some(provider),
            binding,
            synchronous_skill,
            targets,
        });
    }

    let contract = skill.as_ref().map_or(&step["contract"], |skill| {
        &skill.definition["target"]["contract"]
    });
    let resource = Resource::new(
        "capability",
        format!(
            "{}@{}",
            string(contract, "name")?,
            string(contract, "version")?
        ),
        None,
    );
    crate::auth::authorize(c, ctx, "capability.invoke", &resource).await?;
    crate::workflows::validate_contract(c, contract).await?;
    targets.push(Target::new("capability.invoke", resource));
    let fixed = step
        .get("provider_deployment_id")
        .map(|_| id(step, "provider_deployment_id"))
        .transpose()?;
    let provider = capability_provider(
        c,
        contract,
        pin.map(|(deployment, _)| deployment).or(fixed),
        skill.as_ref().map(|s| s.installation_id),
    )
    .await?;
    let binding = match skill.as_ref() {
        Some(skill) => json!({"kind":"skill_capability", "contract":contract,
            "skill_id":skill.id, "definition_digest":skill.definition_digest}),
        None => json!({"kind":"capability", "contract":contract,
            "routing": if provider.is_some() { "fixed" } else { "stateless_direct" }}),
    };
    let synchronous_skill = skill.is_some() && provider.is_some();
    Ok(StepAdmission {
        step_key,
        provider,
        binding,
        synchronous_skill,
        targets,
    })
}

async fn capability_provider(
    c: &(impl GenericClient + Sync),
    contract: &Value,
    deployment: Option<Uuid>,
    skill_installation: Option<Uuid>,
) -> Result<Option<Provider>> {
    let manifest_filter = json!({"capabilities":[{"contract":contract}]});
    if deployment.is_none()
        && skill_installation.is_none()
        && c.query_one(
            "SELECT EXISTS(SELECT 1 FROM installations n JOIN publishers p ON p.id=n.publisher_id
             WHERE n.state='installed' AND p.status='trusted' AND n.manifest @> $1::jsonb
               AND coalesce(n.manifest->>'business_entry','direct')='direct'
               AND n.manifest->>'data_schema_version'='none')",
            &[&manifest_filter],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Ok(None);
    }
    let rows = c.query(
        "SELECT d.id,n.id FROM deployments d JOIN installations n ON n.id=d.installation_id
         JOIN publishers p ON p.id=n.publisher_id
         WHERE d.archived_at IS NULL AND n.state='installed' AND p.status='trusted' AND n.manifest @> $1::jsonb
           AND ($2::uuid IS NULL OR d.id=$2)
           AND (($3::uuid IS NULL AND coalesce(n.manifest->>'business_entry','direct')='direct') OR n.id=$3)
         ORDER BY d.id LIMIT 2 FOR SHARE OF d,n,p",
        &[&manifest_filter, &deployment, &skill_installation],
    ).await?;
    match rows.as_slice() {
        [row] => Ok(Some(Provider {
            deployment: row.get(0),
            installation: row.get(1),
        })),
        [] => Err(Error::unavailable(
            "No eligible workflow deployment is available",
        )),
        _ => Err(Error::conflict(
            "Workflow target has multiple eligible deployments",
        )),
    }
}

async fn http_provider(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    skill: &ResolvedSkill,
    pinned_deployment: Option<Uuid>,
) -> Result<(Provider, Value, Target, bool)> {
    let registry = crate::http_contracts::load(c, skill.installation_id).await?;
    let operation = registry.bind_skill(&skill.definition)?;
    let plugin = string(&skill.definition["target"], "plugin_id")?;
    let rows = c
        .query(
            "SELECT id,owner_id FROM deployments WHERE installation_id=$1 AND archived_at IS NULL
         AND ($2::uuid IS NULL OR id=$2)
         ORDER BY id LIMIT 129 FOR SHARE",
            &[&skill.installation_id, &pinned_deployment],
        )
        .await?;
    if rows.is_empty() {
        return Err(Error::unavailable(
            "No eligible HTTP Skill deployment is available",
        ));
    }
    if rows.len() > 128 {
        return Err(Error::exhausted());
    }
    let mut selected = None;
    for row in rows {
        let resource = Resource::new("plugin", plugin, Some(row.get("owner_id")));
        match super::authority::freeze(c, ctx, &operation.route.action, &resource).await {
            Ok(_) if selected.is_some() => {
                return Err(Error::conflict(
                    "Workflow HTTP Skill has multiple eligible deployments",
                ))
            }
            Ok(_) => {
                selected = Some((
                    row.get("id"),
                    Target::new(&operation.route.action, resource),
                ))
            }
            Err(error) if error.code == "PERMISSION_DENIED" => (),
            Err(error) => return Err(error),
        }
    }
    let (deployment, target) = selected.ok_or_else(Error::denied)?;
    let binding = json!({
        "kind":"skill_http", "skill_id":skill.id, "definition_digest":skill.definition_digest,
        "operation_id":operation.id, "http_contract_digest":operation.contract_digest,
        "method":operation.method.as_str(), "path":operation.path,
    });
    let synchronous_skill = skill.definition["stream_item_schema"].is_null()
        && !operation
            .responses
            .values()
            .any(|response| response.media_type.as_deref() == Some("text/event-stream"));
    Ok((
        Provider {
            deployment,
            installation: skill.installation_id,
        },
        binding,
        target,
        synchronous_skill,
    ))
}
