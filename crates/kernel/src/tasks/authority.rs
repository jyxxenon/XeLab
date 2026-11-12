use crate::{
    auth::{self, Context, Resource},
    error::{Error, Result},
    policy::{self, Path, Policy},
};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use tokio_postgres::GenericClient;
use uuid::Uuid;

/// Freeze only alternatives that currently authorize this exact target. Keeping
/// their source grants lets later admission reject a replacement grant.
pub(super) async fn freeze(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    action: &str,
    resource: &Resource,
) -> Result<Vec<Path>> {
    if !ctx.proxy_allows(action, resource) || !policy::registered(c, action, &resource.kind).await?
    {
        return Err(Error::denied());
    }
    let mut policy = Policy::for_context(c, ctx).with_resource_owner(resource);
    let current = policy.credential(ctx.credential, 0).await?;
    let ceiling = Path {
        rule: json!({"action": action, "resource": resource.json()}),
        sources: Default::default(),
    };
    let mut frozen = policy.intersection(&current, &[ceiling]).await?;
    retain_live_paths(&mut frozen, ctx, Utc::now())?;
    Ok(frozen)
}

pub(super) fn retain_live_paths(
    paths: &mut Vec<Path>,
    ctx: &Context,
    now: DateTime<Utc>,
) -> Result<()> {
    paths.retain(|path| {
        path.rule
            .get("conditions")
            .is_none_or(|conditions| auth::conditions_match(conditions, ctx.peer, now))
    });
    if paths.is_empty() {
        return Err(Error::denied());
    }
    Ok(())
}

/// Check all original grant issuers after policy expansion. Physical credential
/// expiry is separate from conditions carried by a rule and from the submitter's
/// own credential chain.
pub(super) async fn source_expiries(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    sources: &[Uuid],
) -> Result<HashMap<Uuid, DateTime<Utc>>> {
    let chains = Policy::for_context(c, ctx)
        .live_grant_issuer_chains(sources)
        .await?;
    let credentials: Vec<_> = chains
        .values()
        .flat_map(|chain| chain.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let expiries: HashMap<_, _> = c
        .query(
            "SELECT id,expires_at FROM credentials WHERE id=ANY($1::uuid[])",
            &[&credentials],
        )
        .await?
        .into_iter()
        .map(|row| (row.get::<_, Uuid>(0), row.get::<_, DateTime<Utc>>(1)))
        .collect();
    if expiries.len() != credentials.len() {
        return Err(Error::denied());
    }
    Ok(chains
        .into_iter()
        .map(|(grant, chain)| {
            let expiry = chain
                .iter()
                .map(|id| expiries[id])
                .min()
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
            (grant, expiry)
        })
        .collect())
}

/// The caller must hold the authorization fence on the admission transaction.
/// Revalidate after metadata waits and never extend the issuer's lifetime.
pub(super) async fn issuer_expiry(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
) -> Result<DateTime<Utc>> {
    let chain =
        auth::validate_sources(c, Some(ctx.credential), Some(ctx.subject), ctx.peer).await?;
    if chain != ctx.chain {
        return Err(Error::credential());
    }
    crate::oauth_http::validate_source_origins(c, &[ctx.credential], ctx.browser_origin.as_deref())
        .await?;
    let expiry: Option<DateTime<Utc>> = c
        .query_one(
            "SELECT min(expires_at) FROM credentials WHERE id=ANY($1::uuid[])",
            &[&chain],
        )
        .await?
        .get(0);
    expiry
        .filter(|expiry| *expiry > Utc::now())
        .ok_or_else(Error::credential)
}
