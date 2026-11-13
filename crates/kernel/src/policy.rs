//! Bounded, uncached policy evaluation. Sources in one path are conjunctive;
//! separate paths are alternatives. Snapshots freeze rules AND source paths.
use crate::{
    auth::{conditions_match, rules_allow, Context, Resource},
    contracts::{id, string, validate},
    error::{Error, Result},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tokio_postgres::{GenericClient, Row};
use uuid::Uuid;

const MAX_PATHS: usize = 4096;

// Fetch grant metadata and its catalog rows together. The Rust expansion still
// evaluates every issuer, expiry and source path at the point of authorization.
const GRANT_ROWS: &str = "
    SELECT g.id,g.subject_id,g.issuer_id,g.issuer_credential_id,g.role_id,g.scope,g.expires_at,
           role.definition AS role_definition,version.rules AS group_rules,
           ARRAY(SELECT p.action FROM permission_definitions p
                 WHERE p.resource_kinds ? (g.scope->>'kind') ORDER BY p.action) AS supported_actions,
           COALESCE(a.independent_owner AND a.parent_id IS NULL AND g.role_id='Owner'
                    AND g.issuer_id=a.id AND g.issuer_credential_id IS NULL
                    AND (g.created_at=a.created_at OR EXISTS(
                        SELECT 1 FROM recovery_owner_anchors r WHERE r.grant_id=g.id AND r.account_id=a.id
                    )),false) AS bootstrap
      FROM grants g JOIN accounts a ON a.id=g.subject_id
      LEFT JOIN role_definitions role ON role.id=g.role_id
      LEFT JOIN permission_groups grp ON grp.id=g.group_id AND grp.status='active'
      LEFT JOIN group_versions version ON version.group_id=grp.id AND version.version=g.group_version
     WHERE g.status='active' AND (g.expires_at IS NULL OR g.expires_at>now())";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Path {
    pub rule: Value,
    pub sources: BTreeSet<Uuid>,
}
/// An observation of unresolved intersections, never an authorization result.
/// Only UI SQL candidate selection uses it, then evaluates each fixed owner
/// again through the ordinary policy and rechecks every resulting deployment.
#[derive(Default)]
pub(crate) struct PluginOwnerCandidates(Mutex<BTreeSet<(String, Uuid)>>);
impl PluginOwnerCandidates {
    fn record(&self, plugin: &str, owner: Uuid) -> Result<()> {
        let mut pairs = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Policy candidate collector failed"))?;
        let pair = (plugin.to_owned(), owner);
        if !pairs.contains(&pair) && pairs.len() >= MAX_PATHS {
            return Err(Error::exhausted());
        }
        pairs.insert(pair);
        Ok(())
    }
    pub(crate) fn pairs(&self) -> Result<Vec<(String, Uuid)>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Policy candidate collector failed"))?
            .iter()
            .cloned()
            .collect())
    }
}

pub struct Policy<'a, C> {
    c: &'a C,
    peer: IpAddr,
    browser_origin: Option<String>,
    proxy_paths: Option<Vec<Path>>,
    proxy_proof: Option<(Uuid, String, bool)>,
    evaluating_grants: HashSet<Uuid>,
    proving_self_grants: HashSet<Uuid>,
    resource_owner: Option<(String, String, Uuid)>,
    plugin_owner_candidates: Option<&'a PluginOwnerCandidates>,
}
impl<'a, C: GenericClient + Sync> Policy<'a, C> {
    pub fn new(c: &'a C, peer: IpAddr) -> Self {
        Self {
            c,
            peer,
            browser_origin: None,
            proxy_paths: None,
            proxy_proof: None,
            evaluating_grants: HashSet::new(),
            proving_self_grants: HashSet::new(),
            resource_owner: None,
            plugin_owner_candidates: None,
        }
    }

    pub(crate) fn with_plugin_owner_candidates(
        mut self,
        candidates: &'a PluginOwnerCandidates,
    ) -> Self {
        self.plugin_owner_candidates = Some(candidates);
        self
    }

    pub fn for_context(c: &'a C, ctx: &Context) -> Self {
        {
            let mut policy = Self::with_browser_origin(c, ctx.peer, ctx.browser_origin.as_deref());
            policy.proxy_paths = ctx.proxy_paths.clone();
            policy.proxy_proof = ctx
                .proxy_proof
                .as_ref()
                .map(|proof| (ctx.credential, proof.nonce().to_owned(), proof.matches(ctx)));
            policy
        }
    }

    pub fn with_browser_origin(c: &'a C, peer: IpAddr, origin: Option<&str>) -> Self {
        let mut policy = Self::new(c, peer);
        policy.browser_origin = origin.map(str::to_owned);
        policy
    }

    /// A stable plugin ID can have deployments owned by different accounts.
    /// Only a trusted, fixed deployment/Call may supply its actual resource owner;
    /// generic grant issuance and global resource ownership remain unchanged.
    pub(crate) fn with_resource_owner(mut self, resource: &Resource) -> Self {
        if resource.kind == "plugin" {
            self.resource_owner = resource
                .owner
                .map(|owner| (resource.kind.clone(), resource.id.clone(), owner));
        }
        self
    }

    pub async fn account(&mut self, account: Uuid, depth: usize) -> Result<Vec<Path>> {
        if depth > 64 {
            return Err(Error::denied());
        }
        let chain = crate::auth::account_chain(self.c, account).await?;
        let mut paths = Vec::new();
        let direct_grants = format!(
            "SELECT * FROM ({GRANT_ROWS}) AS live WHERE subject_id=$1
             AND (NOT $2 OR issuer_id<>subject_id OR bootstrap) ORDER BY id"
        );
        for (level, subject) in chain.iter().enumerate() {
            let mut direct = Vec::new();
            for row in self
                .c
                .query(
                    &direct_grants,
                    &[subject, &self.proving_self_grants.contains(subject)],
                )
                .await?
            {
                direct.extend(Box::pin(self.expand_grant(&row, depth + 1)).await?);
                bounded(&direct)?;
            }
            if level == 0 {
                paths = direct;
            } else {
                let row = self
                    .c
                    .query_opt(
                        "SELECT * FROM inheritance_grants WHERE account_id=$1",
                        &[subject],
                    )
                    .await?
                    .ok_or_else(Error::credential)?;
                if row.get::<_, Uuid>("parent_id") != chain[level - 1] {
                    return Err(Error::credential());
                }
                if let Some(issuer) = row.get::<_, Option<Uuid>>("issuer_credential_id") {
                    let limits = Box::pin(self.credential(issuer, depth + 1)).await?;
                    paths = self.intersection(&paths, &limits).await?;
                }
                // Inherited and direct grants are alternative sources. Both
                // must obey the current parent and original credential ceiling.
                direct = self.intersection(&direct, &paths).await?;
                if row.get::<_, String>("mode") != "follow_parent" {
                    let maximum: Value = row
                        .get::<_, Option<Value>>("maximum_rules")
                        .ok_or_else(Error::denied)?;
                    let caps: Vec<Path> = maximum
                        .as_array()
                        .ok_or_else(Error::denied)?
                        .iter()
                        .map(|rule| Path {
                            rule: rule.clone(),
                            sources: BTreeSet::new(),
                        })
                        .collect();
                    direct = self.intersection(&direct, &caps).await?;
                    paths = self.freeze(paths, &maximum, Some(*subject), None).await?;
                }
                // Only the inherited branch uses its frozen issuance sources.
                // An explicit direct grant has its own live provenance; it
                // cannot widen maximum_rules or revive a previously issued Key.
                paths.extend(direct);
                bounded(&paths)?;
            }
        }
        // Identity self-service is a fixed system source, scoped to this user.
        // It is added after business inheritance, but never after credential limits.
        let row = self
            .c
            .query_one("SELECT kind FROM accounts WHERE id=$1", &[&account])
            .await?;
        if row.get::<_, String>(0) == "user" {
            paths.extend(self.self_service(account).await?);
        }
        bounded(&paths)?;
        Ok(paths)
    }

    async fn self_service(&self, account: Uuid) -> Result<Vec<Path>> {
        let descendants: Vec<Value> = self.c.query("SELECT descendant_id FROM account_closure WHERE ancestor_id=$1 ORDER BY depth,descendant_id", &[&account]).await?.iter().map(|r| json!(r.get::<_,Uuid>(0))).collect();
        let mut paths = Vec::new();
        for r in self.c.query("SELECT action,resource_kinds FROM permission_definitions WHERE self_service ORDER BY action", &[]).await? {
            let action:String=r.get(0);
            let kinds:Value=r.get(1);
            for kind in kinds.as_array().ok_or_else(Error::denied)? {
                if kind == "account" {
                    let ids=if matches!(action.as_str(),"account.child.create"|"account.child.manage"|"account.permissions.read"|"credential.api-key.create"|"credential.api-key.read") { descendants.clone() } else { vec![json!(account)] };
                    for chunk in ids.chunks(256) { paths.push(Path{rule:json!({"action":action,"resource":{"kind":kind,"match":"ids","ids":chunk}}),sources:BTreeSet::new()}); }
                } else {
                    paths.push(Path{rule:json!({"action":action,"resource":{"kind":kind,"match":"owned_by","owner_id":account}}),sources:BTreeSet::new()});
                }
            }
        }
        Ok(paths)
    }

    pub async fn credential(&mut self, credential: Uuid, depth: usize) -> Result<Vec<Path>> {
        if depth == 0 {
            if let Some((scope, nonce, identity_matches)) = self.proxy_proof.as_ref() {
                if !identity_matches || *scope != credential {
                    return Err(Error::denied());
                }
                let current: Option<String> = self
                    .c
                    .query_one("SELECT current_setting('xelab.host_proof_nonce',true)", &[])
                    .await?
                    .get(0);
                if current.as_deref() != Some(nonce.as_str()) {
                    return Err(Error::denied());
                }
                crate::auth::validate_sources(self.c, Some(credential), None, self.peer).await?;
                return self
                    .live_proxy_sources(self.proxy_paths.clone().ok_or_else(Error::denied)?)
                    .await;
            }
        }
        if depth > 64 {
            return Err(Error::denied());
        }
        let row = self
            .c
            .query_opt("SELECT * FROM credentials WHERE id=$1", &[&credential])
            .await?
            .ok_or_else(Error::credential)?;
        if row.get::<_, String>("status") != "active"
            || row.get::<_, DateTime<Utc>>("expires_at") <= Utc::now()
            || !conditions_match(&row.get::<_, Value>("conditions"), self.peer, Utc::now())
        {
            return Err(Error::credential());
        }
        let binding = if row.get::<_, String>("kind") == "oauth_access" {
            let binding = crate::oauth::binding(self.c, credential).await?;
            // An origin-restricted grant is one authority alternative. Do not
            // reject independent alternatives belonging to the same account.
            if self
                .browser_origin
                .as_ref()
                .is_some_and(|origin| *origin != binding.origin)
            {
                return Ok(Vec::new());
            }
            Some(binding)
        } else {
            None
        };
        let mut paths = Box::pin(self.account(row.get("owner_id"), depth + 1)).await?;
        if let Some(issuer) = row.get::<_, Option<Uuid>>("issuer_credential_id") {
            let limits = Box::pin(self.credential(issuer, depth + 1)).await?;
            paths = self.intersection(&paths, &limits).await?;
        }
        match row.get::<_, String>("kind").as_str() {
            "session" => {}
            "oauth_access" => {
                let binding = binding.ok_or_else(Error::credential)?;
                paths = self
                    .freeze(
                        paths,
                        row.get::<_, Option<Value>>("maximum_rules")
                            .as_ref()
                            .ok_or_else(Error::credential)?,
                        None,
                        Some(credential),
                    )
                    .await?;
                for ceiling in [&binding.maximum_rules, &binding.client_maximum_rules] {
                    let caps: Vec<Path> = ceiling
                        .as_array()
                        .ok_or_else(Error::credential)?
                        .iter()
                        .map(|rule| Path {
                            rule: rule.clone(),
                            sources: BTreeSet::new(),
                        })
                        .collect();
                    paths = self.intersection(&paths, &caps).await?;
                }
            }
            "api_key" => match row.get::<_, Option<String>>("inheritance_mode").as_deref() {
                Some("follow_parent") => {}
                Some("selected" | "all_snapshot") => {
                    paths = self
                        .freeze(
                            paths,
                            row.get::<_, Option<Value>>("maximum_rules")
                                .as_ref()
                                .ok_or_else(Error::denied)?,
                            None,
                            Some(credential),
                        )
                        .await?
                }
                _ => return Err(Error::credential()),
            },
            _ => return Err(Error::credential()),
        }
        // Carry non-action restrictions into newly issued snapshots/templates too.
        let mut conditions: Value = row.get("conditions");
        conditions
            .as_object_mut()
            .ok_or_else(Error::credential)?
            .remove("max_calls");
        for path in &mut paths {
            let Some(condition) = intersect_conditions(
                path.rule.get("conditions").unwrap_or(&json!({})),
                &conditions,
            ) else {
                return Ok(Vec::new());
            };
            path.rule["conditions"] = condition;
        }
        if depth == 0 {
            if let Some(ceiling) = self.proxy_paths.clone() {
                paths = self.intersection(&paths, &ceiling).await?;
            }
        }
        Ok(paths)
    }

    // Grant/account mutations are excluded while the Host proof's auth fence
    // is held. Time-based source-credential expiry is checked again at leaves;
    // expired alternatives are removed rather than reviving them from new grants.
    pub(crate) async fn live_proxy_sources(&self, paths: Vec<Path>) -> Result<Vec<Path>> {
        let sources: Vec<Uuid> = paths
            .iter()
            .flat_map(|p| p.sources.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let valid = self.live_grant_issuer_chains(&sources).await?;
        Ok(paths
            .into_iter()
            .filter(|p| p.sources.iter().all(|id| valid.contains_key(id)))
            .collect())
    }

    /// Return the validated credential chain for each live original grant issuer.
    pub(crate) async fn live_grant_issuer_chains(
        &self,
        sources: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Arc<[Uuid]>>> {
        let rows = self
            .c
            .query(
                "SELECT id,issuer_id,issuer_credential_id FROM grants WHERE id=ANY($1)",
                &[&sources],
            )
            .await?;
        if rows.len() != sources.len() {
            return Err(Error::denied());
        }
        let mut valid = std::collections::HashMap::new();
        let mut issuers: std::collections::HashMap<_, Option<Arc<[Uuid]>>> = Default::default();
        for row in rows {
            let issuer: Option<Uuid> = row.get("issuer_credential_id");
            let owner: Uuid = row.get("issuer_id");
            let chain = if let Some(chain) = issuers.get(&(issuer, owner)) {
                chain.clone()
            } else {
                let chain =
                    match crate::auth::validate_sources(self.c, issuer, Some(owner), self.peer)
                        .await
                    {
                        Ok(credentials) => Some(Arc::from(credentials)),
                        Err(e) if e.code == "INVALID_CREDENTIAL" => None,
                        Err(e) => return Err(e),
                    };
                issuers.insert((issuer, owner), chain.clone());
                chain
            };
            if let Some(chain) = chain {
                valid.insert(row.get::<_, Uuid>("id"), chain);
            }
        }
        Ok(valid)
    }

    async fn grant(&mut self, grant: Uuid, depth: usize) -> Result<Vec<Path>> {
        let Some(row) = self
            .c
            .query_opt(
                &format!("SELECT * FROM ({GRANT_ROWS}) AS live WHERE id=$1"),
                &[&grant],
            )
            .await?
        else {
            return Ok(Vec::new());
        };
        self.expand_grant(&row, depth).await
    }

    async fn expand_grant(&mut self, row: &Row, depth: usize) -> Result<Vec<Path>> {
        let grant = row.get("id");
        // A grant cannot prove its own issuing authority. Other independent paths
        // remain available while evaluating a delegated grant on the same subject.
        if !self.evaluating_grants.insert(grant) {
            return Ok(Vec::new());
        }
        // Self-issued bindings cannot add authority to their own issuer: each
        // is an intersection with authority that must exist independently.
        // Remove ALL such edges while proving one, instead of enumerating every
        // permutation of the other self-issued bindings. Keep the bootstrap
        // Owner anchor and external/inherited paths, and retain the direct
        // binding's provenance in the outer evaluation.
        let subject: Uuid = row.get("subject_id");
        let issuer: Uuid = row.get("issuer_id");
        let inserted = subject == issuer && self.proving_self_grants.insert(subject);
        let result = self.grant_inner(row, grant, issuer, depth).await;
        if inserted {
            self.proving_self_grants.remove(&subject);
        }
        self.evaluating_grants.remove(&grant);
        result
    }
    async fn grant_inner(
        &mut self,
        row: &Row,
        grant: Uuid,
        issuer: Uuid,
        depth: usize,
    ) -> Result<Vec<Path>> {
        let scope: Value = row.get("scope");
        let mut rules = Vec::new();
        if row.get::<_, Option<String>>("role_id").is_some() {
            string(&scope, "kind")?;
            let def: Value = row
                .get::<_, Option<Value>>("role_definition")
                .ok_or_else(Error::denied)?;
            let actions = def["actions"].as_array().ok_or_else(Error::denied)?;
            for action in row.get::<_, Vec<String>>("supported_actions") {
                if actions.iter().any(|allowed| allowed == &action) {
                    rules.push(json!({"action":action,"resource":scope}));
                }
            }
        } else {
            let Some(group) = row.get::<_, Option<Value>>("group_rules") else {
                return Ok(Vec::new());
            };
            for r in group.as_array().ok_or_else(Error::denied)? {
                if let Some(resource) = self.selector_intersection(&r["resource"], &scope).await? {
                    let mut rule = r.clone();
                    rule["resource"] = resource;
                    rules.push(rule);
                }
            }
        }
        let expiry: Option<DateTime<Utc>> = row.get("expires_at");
        let mut paths = Vec::new();
        for mut rule in rules {
            if let Some(expiry) = expiry {
                let Some(conditions) = intersect_conditions(
                    rule.get("conditions").unwrap_or(&json!({})),
                    &json!({"expires_at":expiry}),
                ) else {
                    continue;
                };
                rule["conditions"] = conditions;
            }
            paths.push(Path {
                rule,
                sources: BTreeSet::from([grant]),
            });
        }
        if let Some(issuer) = row.get::<_, Option<Uuid>>("issuer_credential_id") {
            // Invalid delegated source withdraws this alternative, not all grants.
            match Box::pin(self.credential(issuer, depth + 1)).await {
                Ok(limits) => paths = self.intersection(&paths, &limits).await?,
                Err(e) if matches!(e.code, "INVALID_CREDENTIAL" | "PERMISSION_DENIED") => {
                    return Ok(Vec::new())
                }
                Err(e) => return Err(e),
            }
        } else if !row.get::<_, bool>("bootstrap") {
            match Box::pin(self.account(issuer, depth + 1)).await {
                Ok(limits) => paths = self.intersection(&paths, &limits).await?,
                Err(e) if matches!(e.code, "INVALID_CREDENTIAL" | "PERMISSION_DENIED") => {
                    return Ok(Vec::new())
                }
                Err(e) => return Err(e),
            }
        }
        Ok(paths)
    }

    async fn freeze(
        &mut self,
        paths: Vec<Path>,
        ceiling: &Value,
        account: Option<Uuid>,
        credential: Option<Uuid>,
    ) -> Result<Vec<Path>> {
        let caps: Vec<Path> = ceiling
            .as_array()
            .ok_or_else(Error::denied)?
            .iter()
            .map(|r| Path {
                rule: r.clone(),
                sources: BTreeSet::new(),
            })
            .collect();
        let paths = self.intersection(&paths, &caps).await?;
        let mut saved = Vec::new();
        let mut seen = HashSet::new();
        for row in self.c.query("SELECT source_rules FROM grant_provenance WHERE derived_account_id=$1 OR derived_credential_id=$2", &[&account,&credential]).await? {
            let v:Value=row.get(0);
            if v["version"]!=1 {return Err(Error::denied());}
            let p:Path=serde_json::from_value(v["path"].clone()).map_err(|_|Error::denied())?;
            if seen.insert(serde_json::to_string(&p)?) {
                let mut current=vec![p.clone()];
                for source in &p.sources {
                    let rule_paths=Box::pin(self.grant(*source,1)).await?;
                    // Retain each source's current selectors and conditions.
                    // A mere nonempty overlap could resurrect a withdrawn part
                    // through an unrelated grant acquired after the snapshot.
                    current=self.intersection(&current,&rule_paths).await?;
                    if current.is_empty(){break;}
                }
                saved.extend(current);
                bounded(&saved)?;
            }
        }
        // Source-less paths can only originate from fixed user self-service;
        // they are still intersected with the exact frozen selector and conditions.
        saved.extend(paths.iter().filter(|p| p.sources.is_empty()).cloned());
        self.intersection(&paths, &saved).await
    }

    /// Re-evaluate every original grant alternative before intersecting current
    /// credential rights. Newly acquired grants cannot revive a withdrawn part.
    pub async fn revalidate(&mut self, saved: &[Path], credential: Uuid) -> Result<Vec<Path>> {
        let current = self.credential(credential, 0).await?;
        self.revalidate_current(saved, &current).await
    }

    /// Current rights may be supplied only by the transaction-bound authority
    /// proof. Every original source is still walked before their intersection.
    pub(crate) async fn revalidate_current(
        &mut self,
        saved: &[Path],
        current: &[Path],
    ) -> Result<Vec<Path>> {
        bounded(saved)?;
        bounded(current)?;
        let mut live = Vec::new();
        // A source is immutable under this transaction's authorization fence.
        // Reuse its current expansion only within this one proof evaluation.
        let mut sources: std::collections::HashMap<Uuid, Vec<Path>> = Default::default();
        let mut cached_paths = 0;
        for path in saved {
            let mut current = vec![path.clone()];
            for source in &path.sources {
                let grants = if let Some(paths) = sources.get(source) {
                    paths.clone()
                } else {
                    let paths = self.grant(*source, 1).await?;
                    if cached_paths + paths.len() <= MAX_PATHS {
                        cached_paths += paths.len();
                        sources.insert(*source, paths.clone());
                    }
                    paths
                };
                current = self.intersection(&current, &grants).await?;
                if current.is_empty() {
                    break;
                }
            }
            live.extend(current);
            bounded(&live)?;
        }
        self.intersection(&live, current).await
    }

    pub async fn intersection(&self, left: &[Path], right: &[Path]) -> Result<Vec<Path>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for a in left {
            for b in right {
                if a.rule["action"] != b.rule["action"] {
                    continue;
                }
                let Some(resource) = self
                    .selector_intersection(&a.rule["resource"], &b.rule["resource"])
                    .await?
                else {
                    continue;
                };
                let Some(conditions) = intersect_conditions(
                    a.rule.get("conditions").unwrap_or(&json!({})),
                    b.rule.get("conditions").unwrap_or(&json!({})),
                ) else {
                    continue;
                };
                let rule =
                    json!({"action":a.rule["action"],"resource":resource,"conditions":conditions});
                let sources = a.sources.union(&b.sources).copied().collect();
                let path = Path { rule, sources };
                if seen.insert(serde_json::to_string(&path)?) {
                    out.push(path);
                    bounded(&out)?;
                }
            }
        }
        Ok(out)
    }

    async fn selector_intersection(&self, a: &Value, b: &Value) -> Result<Option<Value>> {
        if a["kind"] != b["kind"] {
            return Ok(None);
        }
        if a["match"] == "all" {
            return Ok(Some(b.clone()));
        }
        if b["match"] == "all" || a == b {
            return Ok(Some(a.clone()));
        }
        if a["match"] == "owned_by" && b["match"] == "owned_by" {
            return Ok(None);
        }
        let (ids, other) = if a["match"] == "ids" { (a, b) } else { (b, a) };
        let mut kept = Vec::new();
        for value in ids["ids"].as_array().ok_or_else(Error::denied)? {
            let matches = if other["match"] == "ids" {
                other["ids"].as_array().is_some_and(|a| a.contains(value))
            } else {
                let kind = string(ids, "kind")?;
                let id = value.as_str().ok_or_else(Error::denied)?;
                if kind == "plugin" && self.resource_owner.is_none() && other["match"] == "owned_by"
                {
                    if let Some(candidates) = self.plugin_owner_candidates {
                        candidates.record(id, crate::contracts::id(other, "owner_id")?)?;
                    }
                }
                let owner = if let Some((fixed_kind, fixed_id, owner)) = &self.resource_owner {
                    if fixed_kind == kind && fixed_id == id {
                        Some(*owner)
                    } else {
                        resource_owner(self.c, kind, id).await?
                    }
                } else {
                    resource_owner(self.c, kind, id).await?
                };
                owner.is_some_and(|owner| other["owner_id"] == owner.to_string())
            };
            if matches {
                kept.push(value.clone());
            }
        }
        Ok((!kept.is_empty()).then(|| json!({"kind":a["kind"],"match":"ids","ids":kept})))
    }

    pub async fn covers_now(&mut self, ctx: &Context, rule: &Value) -> Result<bool> {
        self.validate_rules(std::slice::from_ref(rule)).await?;
        let mut available = self.credential(ctx.credential, 0).await?;
        available.retain(|p| {
            p.rule
                .get("conditions")
                .is_none_or(|v| conditions_match(v, self.peer, Utc::now()))
        });
        for p in &mut available {
            p.rule["conditions"] = json!({});
        }
        for part in split_ids(rule) {
            let wanted = Path {
                rule: part.clone(),
                sources: BTreeSet::new(),
            };
            let intersections = self.intersection(&[wanted], &available).await?;
            if !intersections.iter().any(|p| same_rule(&p.rule, &part)) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub async fn select(&mut self, ctx: &Context, spec: &Value) -> Result<Vec<Path>> {
        validate("InheritanceSpec", spec)?;
        let effective = self.credential(ctx.credential, 0).await?;
        if spec["mode"] != "selected" {
            return Ok(effective);
        }
        let mut rules = spec
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(groups) = spec.get("group_versions").and_then(Value::as_array) {
            for group in groups {
                let row=self.c.query_opt("SELECT v.rules,g.owner_id,g.visibility FROM group_versions v JOIN permission_groups g ON g.id=v.group_id WHERE v.group_id=$1 AND v.version=$2 AND g.status='active'", &[&id(group,"group_id")?,&group["version"].as_i64().ok_or_else(Error::denied)?]).await?.ok_or_else(Error::not_found)?;
                if row.get::<_, Uuid>("owner_id") != ctx.subject
                    && row.get::<_, String>("visibility") != "public"
                {
                    return Err(Error::not_found());
                }
                rules.extend(
                    row.get::<_, Value>("rules")
                        .as_array()
                        .ok_or_else(Error::denied)?
                        .iter()
                        .cloned(),
                );
            }
        }
        self.validate_rules(&rules).await?;
        let requested: Vec<Path> = rules
            .into_iter()
            .map(|rule| Path {
                rule,
                sources: BTreeSet::new(),
            })
            .collect();
        // Selected is a ceiling, not an authority source. Intersect at issuance;
        // the exact resulting rules are persisted, never the group template alone.
        self.intersection(&effective, &requested).await
    }

    pub async fn validate_rules(&self, rules: &[Value]) -> Result<()> {
        for rule in rules {
            validate("PermissionRule", rule)?;
            if !registered(
                self.c,
                string(rule, "action")?,
                string(&rule["resource"], "kind")?,
            )
            .await?
            {
                return Err(Error::invalid(
                    "Unknown action or incompatible resource kind",
                ));
            }
            if let Some(conditions) = rule.get("conditions") {
                validate_conditions(conditions)?;
            }
        }
        Ok(())
    }
    pub async fn require_subset(&mut self, ctx: &Context, rules: &[Value]) -> Result<()> {
        self.validate_rules(rules).await?;
        let available = self.credential(ctx.credential, 0).await?;
        for rule in rules {
            // Require a covering alternative, including ALL non-action conditions.
            // Disjoint ID alternatives are checked independently.
            let parts = split_ids(rule);
            for part in parts {
                let wanted = Path {
                    rule: part.clone(),
                    sources: BTreeSet::new(),
                };
                let intersections = self
                    .intersection(std::slice::from_ref(&wanted), &available)
                    .await?;
                if !intersections.iter().any(|p| same_rule(&p.rule, &part)) {
                    return Err(Error::denied());
                }
            }
        }
        Ok(())
    }
}

fn split_ids(rule: &Value) -> Vec<Value> {
    if rule["resource"]["match"] != "ids" {
        return vec![rule.clone()];
    }
    rule["resource"]["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| {
            let mut r = rule.clone();
            r["resource"]["ids"] = json!([id]);
            r
        })
        .collect()
}
fn same_rule(a: &Value, b: &Value) -> bool {
    if a["action"] != b["action"] || a["resource"] != b["resource"] {
        return false;
    }
    let empty = json!({});
    let left = a.get("conditions").unwrap_or(&empty);
    let right = b.get("conditions").unwrap_or(&empty);
    // Compare normalized instants, not their RFC3339 spelling (+00:00 vs Z).
    matches!(
        (
            intersect_conditions(left, left),
            intersect_conditions(right, right)
        ),
        (Some(left), Some(right)) if left == right
    )
}
fn bounded(paths: &[Path]) -> Result<()> {
    if paths.len() > MAX_PATHS {
        Err(Error::invalid("Policy expansion exceeds 4096 paths"))
    } else {
        Ok(())
    }
}
pub fn rules(paths: &[Path]) -> Value {
    let mut out = Vec::new();
    for p in paths {
        if !out.contains(&p.rule) {
            out.push(p.rule.clone());
        }
    }
    json!(out)
}

pub async fn save_sources(
    c: &(impl GenericClient + Sync),
    paths: &[Path],
    account: Option<Uuid>,
    credential: Option<Uuid>,
) -> Result<()> {
    for path in paths {
        for source in &path.sources {
            c.execute("INSERT INTO grant_provenance(id,derived_account_id,derived_credential_id,source_grant_id,source_rules) VALUES($1,$2,$3,$4,$5)", &[&Uuid::new_v4(),&account,&credential,&source,&json!({"version":1,"path":path})]).await?;
        }
    }
    Ok(())
}
pub async fn registered(c: &impl GenericClient, action: &str, kind: &str) -> Result<bool> {
    Ok(c.query_opt(
        "SELECT resource_kinds FROM permission_definitions WHERE action=$1",
        &[&action],
    )
    .await?
    .is_some_and(|r| {
        r.get::<_, Value>(0)
            .as_array()
            .is_some_and(|k| k.iter().any(|v| v == kind))
    }))
}
pub async fn allows(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    action: &str,
    resource: &Resource,
) -> Result<bool> {
    if !ctx.proxy_allows(action, resource) || !registered(c, action, &resource.kind).await? {
        return Ok(false);
    }
    let paths = Policy::for_context(c, ctx)
        .credential(ctx.credential, 0)
        .await?;
    Ok(rules_allow(&rules(&paths), action, resource, ctx.peer))
}

pub async fn resource_owner(c: &impl GenericClient, kind: &str, id: &str) -> Result<Option<Uuid>> {
    let sql=match kind {
        "account"=>"SELECT id FROM accounts WHERE id::text=$1",
        "group"=>"SELECT owner_id FROM permission_groups WHERE id::text=$1",
        "client"=>"SELECT created_by FROM clients WHERE id::text=$1",
        "credential"=>"SELECT owner_id FROM credentials WHERE id::text=$1",
        "deployment"=>"SELECT owner_id FROM deployments WHERE id::text=$1",
        "instance"=>"SELECT d.owner_id FROM instances i JOIN deployments d ON d.id=i.deployment_id WHERE i.id::text=$1",
        "operation"=>"SELECT owner_id FROM operations WHERE id::text=$1",
        "call"=>"SELECT owner_id FROM calls WHERE id::text=$1",
        "skill"=>"SELECT created_by FROM skills WHERE id::text=$1",
        "task"=>"SELECT owner_id FROM tasks WHERE id::text=$1",
        "workflow"=>"SELECT owner_id FROM workflows WHERE id::text=$1",
        "schedule"=>"SELECT owner_id FROM schedules WHERE id::text=$1",
        "volume"=>"SELECT owner_id FROM volumes WHERE id::text=$1",
        "blob"=>"SELECT owner_id FROM blobs WHERE id::text=$1",
        "secret"=>"SELECT owner_id FROM secrets WHERE id::text=$1",
        _=>return Ok(None),
    };
    Ok(c.query_opt(sql, &[&id])
        .await?
        .and_then(|r| r.get::<_, Option<Uuid>>(0)))
}

pub fn validate_conditions(v: &Value) -> Result<()> {
    if let Some(cidrs) = v.get("source_cidrs").and_then(Value::as_array) {
        for cidr in cidrs {
            cidr.as_str()
                .ok_or_else(Error::denied)?
                .parse::<ipnet::IpNet>()
                .map_err(|_| Error::invalid("Invalid source CIDR"))?;
        }
    }
    if let (Some(start), Some(end)) = (v.get("not_before"), v.get("expires_at")) {
        if timestamp(start)? >= timestamp(end)? {
            return Err(Error::invalid("Empty validity interval"));
        }
    }
    Ok(())
}
pub fn timestamp(v: &Value) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(
        v.as_str()
            .ok_or_else(|| Error::invalid("Expected timestamp"))?,
    )
    .map(|t| t.with_timezone(&Utc))
    .map_err(|_| Error::invalid("Invalid timestamp"))
}
pub fn intersect_conditions(a: &Value, b: &Value) -> Option<Value> {
    let mut out = json!({});
    for (key, latest) in [("not_before", true), ("expires_at", false)] {
        let t = match (a.get(key), b.get(key)) {
            (Some(x), Some(y)) => {
                let x = timestamp(x).ok()?;
                let y = timestamp(y).ok()?;
                Some(if latest { x.max(y) } else { x.min(y) })
            }
            (Some(v), None) | (None, Some(v)) => Some(timestamp(v).ok()?),
            _ => None,
        };
        if let Some(t) = t {
            out[key] = json!(t);
        }
    }
    for key in ["audiences", "source_cidrs"] {
        match (a.get(key), b.get(key)) {
            (Some(a), Some(b)) => {
                let mut values = Vec::new();
                for x in a.as_array()? {
                    for y in b.as_array()? {
                        let v = if key == "source_cidrs" {
                            let x = x.as_str()?.parse::<ipnet::IpNet>().ok()?;
                            let y = y.as_str()?.parse::<ipnet::IpNet>().ok()?;
                            if x.contains(&y) {
                                Some(json!(y.to_string()))
                            } else if y.contains(&x) {
                                Some(json!(x.to_string()))
                            } else {
                                None
                            }
                        } else if x == y {
                            Some(x.clone())
                        } else {
                            None
                        };
                        if let Some(v) = v {
                            if !values.contains(&v) {
                                values.push(v);
                            }
                        }
                    }
                }
                if values.is_empty() {
                    return None;
                }
                out[key] = json!(values);
            }
            (Some(v), None) | (None, Some(v)) => out[key] = v.clone(),
            _ => {}
        }
    }
    if let (Some(a), Some(b)) = (out.get("not_before"), out.get("expires_at")) {
        if timestamp(a).ok()? >= timestamp(b).ok()? {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn condition_intersection_never_widens() {
        let a = json!({"source_cidrs":["10.0.0.0/8"],"audiences":["xelab.platform","other"],"expires_at":"2030-01-01T00:00:00Z"});
        let b = json!({"source_cidrs":["10.1.0.0/16"],"audiences":["xelab.platform"],"expires_at":"2029-01-01T00:00:00Z"});
        assert_eq!(intersect_conditions(&a, &b), Some(b));
        assert!(intersect_conditions(&a, &json!({"source_cidrs":["192.0.2.0/24"]})).is_none());
        assert!(intersect_conditions(&a, &json!({"not_before":"2031-01-01T00:00:00Z"})).is_none());
        let utc = json!({"action":"platform.read","resource":{"kind":"platform","match":"all"},"conditions":{"expires_at":"2030-01-01T00:00:00Z"}});
        let mut offset = utc.clone();
        offset["conditions"]["expires_at"] = json!("2030-01-01T01:00:00+01:00");
        assert!(same_rule(&utc, &offset));
        offset["conditions"]["expires_at"] = json!("2030-01-02T00:00:00Z");
        assert!(!same_rule(&utc, &offset));
    }
}

#[cfg(test)]
mod owner_candidate_tests {
    use super::*;
    #[test]
    fn owner_candidates_deduplicate_and_enforce_the_existing_path_bound() {
        let candidates = PluginOwnerCandidates::default();
        for index in 0..MAX_PATHS {
            candidates
                .record("org.xelab.fixture", Uuid::from_u128(index as u128))
                .unwrap();
        }
        candidates.record("org.xelab.fixture", Uuid::nil()).unwrap();
        assert_eq!(candidates.pairs().unwrap().len(), MAX_PATHS);
        assert_eq!(
            candidates
                .record("org.xelab.other", Uuid::nil())
                .unwrap_err()
                .code,
            "RESOURCE_EXHAUSTED"
        );
        assert_eq!(candidates.pairs().unwrap().len(), MAX_PATHS);
    }
}
