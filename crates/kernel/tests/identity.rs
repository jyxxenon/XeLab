//! Real PostgreSQL + HTTP acceptance. Each test owns a separate database.
#[path = "support/http_host.rs"]
mod http_host;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::Request,
    Router,
};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc},
};
use tower::ServiceExt;
use uuid::Uuid;
use xelab_kernel::{
    api::{router, App},
    auth::{self, Auth},
    config::Config,
    contracts,
    db::Db,
    runtime::Runtime,
};

const PASSWORD: &str = "correct horse acceptance password";

#[tokio::test]
async fn publisher_retrust_preserves_identity_and_requires_existing_object_authority() {
    use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
    let Some(f) = Fixture::new().await else {
        return;
    };
    let pem = SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    let body = json!({"name":"reviewed publisher","key_id":"reviewed-key","public_key_pem":pem});
    // A creation-only selector grants a proposed owner, not an unowned existing
    // publisher. A cached 201 still checks the original creation permission.
    let creation_key = f.key(f.owner, &f.token, json!({"mode":"selected","rules":[{"action":"publisher.trust","resource":{"kind":"publisher","match":"owned_by","owner_id":f.owner}}]})).await;
    let creation_token = creation_key["secret"].as_str().unwrap();
    let created = api(
        &f.router,
        "trustPublisher",
        &[],
        Some(creation_token),
        body.clone(),
        "create-publisher",
        None,
        "",
    )
    .await;
    assert_eq!(created.0, 201, "{}", created.1);
    let publisher = contracts::id(&created.1, "id").unwrap();
    let replay = api(
        &f.router,
        "trustPublisher",
        &[],
        Some(creation_token),
        body.clone(),
        "create-publisher",
        None,
        "",
    )
    .await;
    assert_eq!(replay.0, 201, "{}", replay.1);
    assert_eq!(replay.1, created.1);
    assert_eq!(
        f.call("trustPublisher", &[], creation_token, body.clone(), None)
            .await
            .0,
        403
    );
    let c = f.db.connect().await.unwrap();
    let installation = Uuid::new_v4();
    let deployment = Uuid::new_v4();
    c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,'org.xelab.trust-fixture','1.0.0',$2,'fixture','fixture','{}','installed',now(),now())", &[&installation,&publisher]).await.unwrap();
    c.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,'{\"enabled\":false}','disabled',now(),now())", &[&deployment,&f.owner,&installation]).await.unwrap();
    let revoked = f
        .call(
            "revokePublisher",
            &[("publisher_id", publisher.to_string())],
            &f.token,
            Value::Null,
            Some(1),
        )
        .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let historical = api(
        &f.router,
        "trustPublisher",
        &[],
        Some(creation_token),
        body.clone(),
        "create-publisher",
        None,
        "",
    )
    .await;
    assert_eq!(historical.0, 201, "{}", historical.1);
    assert_eq!(
        c.query_one("SELECT status FROM publishers WHERE id=$1", &[&publisher])
            .await
            .unwrap()
            .get::<_, String>(0),
        "revoked",
        "replaying creation returns its old response and must not revive trust"
    );
    let scoped = f.key(f.owner, &f.token, json!({"mode":"selected","rules":[{"action":"publisher.trust","resource":{"kind":"publisher","match":"ids","ids":[publisher]}}]})).await;
    let token = scoped["secret"].as_str().unwrap();
    for field in ["public_key_pem", "name"] {
        let mut different = body.clone();
        different[field] = if field == "name" {
            json!("changed identity")
        } else {
            json!(SigningKey::from_bytes(&[8; 32])
                .verifying_key()
                .to_public_key_pem(Default::default())
                .unwrap())
        };
        let refused = f.call("trustPublisher", &[], token, different, None).await;
        assert_eq!(refused.0, 409, "{}", refused.1);
    }
    let restored = api(
        &f.router,
        "trustPublisher",
        &[],
        Some(token),
        body.clone(),
        "explicit-retrust",
        None,
        "",
    )
    .await;
    assert_eq!(restored.0, 200, "{}", restored.1);
    assert_eq!(restored.1["id"], created.1["id"]);
    assert_eq!(restored.1["created_at"], created.1["created_at"]);
    assert_eq!(restored.1["revision"], 3);
    assert_eq!(restored.1["status"], "trusted");
    let repeated = api(
        &f.router,
        "trustPublisher",
        &[],
        Some(token),
        body.clone(),
        "explicit-retrust",
        None,
        "",
    )
    .await;
    assert_eq!(repeated.0, 200, "{}", repeated.1);
    assert_eq!(repeated.1, restored.1);
    let state = c.query_one("SELECT i.publisher_id,d.spec,d.phase,(SELECT count(*) FROM publishers) AS n FROM installations i JOIN deployments d ON d.installation_id=i.id WHERE i.id=$1", &[&installation]).await.unwrap();
    assert_eq!(state.get::<_, Uuid>("publisher_id"), publisher);
    assert_eq!(state.get::<_, i64>("n"), 1);
    assert_eq!(state.get::<_, Value>("spec")["enabled"], false);
    assert_eq!(state.get::<_, String>("phase"), "disabled");
    c.execute(
        "UPDATE credentials SET status='revoked' WHERE id=$1",
        &[&contracts::id(&scoped["credential"], "id").unwrap()],
    )
    .await
    .unwrap();
    assert_eq!(
        api(
            &f.router,
            "trustPublisher",
            &[],
            Some(token),
            body,
            "explicit-retrust",
            None,
            ""
        )
        .await
        .0,
        401
    );
}

struct Fixture {
    db: Db,
    router: Router,
    owner: Uuid,
    token: String,
}
impl Fixture {
    async fn new() -> Option<Self> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            eprintln!("Skipping real identity database tests: XELAB_TEST_DATABASE_URL is not set");
            return None;
        };
        let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
        let database = format!("identity_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .await
            .unwrap();
        let db = Db::new(format!("{base} dbname={database}")).unwrap();
        db.migrate().await.unwrap();
        let value: toml::Value =
            toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
        let config = Config::from_value(serde_json::to_value(value).unwrap()).unwrap();
        let mut c = db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        let owner = auth::bootstrap(&tx, "Owner", PASSWORD, &config.value["quota_defaults"])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let app = Arc::new(App {
            runtime: Runtime::new(config.clone()),
            config,
            db: db.clone(),
            auth: Auth::new(vec![72; 32]).unwrap(),
            leader: Arc::new(db.leader().await.unwrap()),
            ready: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            blob_uploads: tokio::sync::Semaphore::new(4),
        });
        let router = router(app);
        let result = api(
            &router,
            "login",
            &[],
            None,
            json!({"account_id":owner,"password":PASSWORD}),
            "login",
            None,
            "",
        )
        .await;
        assert_eq!(result.0, 200, "{}", result.1);
        Some(Self {
            db,
            router,
            owner,
            token: result.1["access_token"].as_str().unwrap().into(),
        })
    }
    async fn call(
        &self,
        op: &str,
        params: &[(&str, String)],
        token: &str,
        body: Value,
        revision: Option<i64>,
    ) -> (u16, Value) {
        api(
            &self.router,
            op,
            params,
            Some(token),
            body,
            &Uuid::new_v4().to_string(),
            revision,
            "",
        )
        .await
    }
    async fn child(&self, parent: Uuid, token: &str, inheritance: Value) -> (Uuid, String) {
        let out = self
            .call(
                "createChildAccount",
                &[("account_id", parent.to_string())],
                token,
                json!({"display_name":"child","inheritance":inheritance}),
                None,
            )
            .await;
        assert_eq!(out.0, 201, "{}", out.1);
        let account = contracts::id(&out.1["account"], "id").unwrap();
        let activate = json!({"activation_token":out.1["activation_token"],"password":PASSWORD});
        let activated = api(
            &self.router,
            "activateAccount",
            &[],
            None,
            activate.clone(),
            "activate",
            None,
            "",
        )
        .await;
        assert_eq!(activated.0, 200, "{}", activated.1);
        assert_eq!(
            api(
                &self.router,
                "activateAccount",
                &[],
                None,
                activate,
                "activate",
                None,
                ""
            )
            .await
            .0,
            401
        );
        let session = api(
            &self.router,
            "login",
            &[],
            None,
            json!({"account_id":account,"password":PASSWORD}),
            "login",
            None,
            "",
        )
        .await;
        assert_eq!(session.0, 200, "{}", session.1);
        (account, session.1["access_token"].as_str().unwrap().into())
    }
    async fn key(&self, account: Uuid, token: &str, inheritance: Value) -> Value {
        let out = self
            .call(
                "createApiKey",
                &[("account_id", account.to_string())],
                token,
                key_body(inheritance),
                None,
            )
            .await;
        assert_eq!(out.0, 201, "{}", out.1);
        out.1
    }
    async fn check(&self, token: &str, action: &str, resource: Value) -> bool {
        let out = self
            .call(
                "checkAuthorization",
                &[],
                token,
                json!({"action":action,"resource":resource}),
                None,
            )
            .await;
        assert_eq!(out.0, 200, "{}", out.1);
        out.1["allowed"].as_bool().unwrap()
    }
    async fn root_guest(&self) -> (Uuid, String) {
        // Trusted host fixture, deliberately no management API for creating roots.
        let id = Uuid::new_v4();
        let hash = auth::password_hash(PASSWORD).unwrap();
        let c = self.db.connect().await.unwrap();
        c.execute("INSERT INTO accounts(id,kind,status,display_name,password_hash,created_at,updated_at) VALUES($1,'user','active','Guest',$2,now(),now())", &[&id,&hash]).await.unwrap();
        c.execute("INSERT INTO account_closure VALUES($1,$1,0)", &[&id])
            .await
            .unwrap();
        c.execute("INSERT INTO quotas(account_id,spec,daily_bucket,created_at,updated_at) SELECT $1,spec,current_date,now(),now() FROM quotas WHERE account_id=$2", &[&id,&self.owner]).await.unwrap();
        let grant = self
            .call(
                "createGrant",
                &[("account_id", id.to_string())],
                &self.token,
                json!({"source":"role","role_id":"Guest","scope":cap()}),
                None,
            )
            .await;
        assert_eq!(grant.0, 201, "{}", grant.1);
        let session = api(
            &self.router,
            "login",
            &[],
            None,
            json!({"account_id":id,"password":PASSWORD}),
            "guest-login",
            None,
            "",
        )
        .await;
        assert_eq!(session.0, 200, "{}", session.1);
        (id, session.1["access_token"].as_str().unwrap().into())
    }
}
fn cap() -> Value {
    json!({"kind":"capability","match":"ids","ids":["org.xelab.echo@1.0.0"]})
}
fn selected() -> Value {
    json!({"mode":"selected","rules":[{"action":"capability.invoke","resource":cap()}]})
}
fn key_body(inheritance: Value) -> Value {
    json!({"name":"acceptance key","inheritance":inheritance,"conditions":{"expires_at":(chrono::Utc::now()+chrono::Duration::days(30)).date_naive().and_hms_opt(0,0,0).unwrap().and_utc()}})
}

#[tokio::test]
async fn key_issued_grant_and_child_account_use_the_persisted_expiry() {
    use chrono::{Duration, Timelike, Utc};

    let Some(f) = Fixture::new().await else {
        return;
    };
    let requested = (Utc::now() + Duration::hours(1))
        .with_nanosecond(123_456_789)
        .unwrap();
    let expected = requested.with_nanosecond(123_456_000).unwrap();
    let owner = [("account_id", f.owner.to_string())];
    let mut body = key_body(json!({"mode":"all_snapshot"}));
    body["conditions"]["expires_at"] = json!(requested);
    let issuer = f.call("createApiKey", &owner, &f.token, body, None).await;
    assert_eq!(issuer.0, 201, "{}", issuer.1["error"]);
    let secret = issuer.1["secret"].as_str().unwrap();
    let child = |expiry| {
        json!({"display_name":"expiry child","inheritance":{"mode":"all_snapshot"},
               "expires_at":expiry})
    };
    let grant =
        |expiry| json!({"source":"role","role_id":"Guest","scope":cap(),"expires_at":expiry});
    let later = expected + Duration::microseconds(1);
    let denied = f
        .call("createChildAccount", &owner, secret, child(later), None)
        .await;
    assert_eq!(denied.0, 403, "{}", denied.1["error"]);
    let child = f
        .call("createChildAccount", &owner, secret, child(requested), None)
        .await;
    assert_eq!(child.0, 201, "{}", child.1["error"]);
    let child_id = contracts::id(&child.1["account"], "id").unwrap();
    let account = [("account_id", child_id.to_string())];
    let revision = child.1["account"]["revision"].as_i64();
    for (operation, exact, excessive, revision, accepted_status) in [
        ("createGrant", grant(requested), grant(later), None, 201),
        (
            "updateAccount",
            json!({"expires_at":requested}),
            json!({"expires_at":later}),
            revision,
            200,
        ),
    ] {
        let denied = f
            .call(operation, &account, secret, excessive, revision)
            .await;
        assert_eq!(denied.0, 403, "{operation}: {}", denied.1["error"]);
        let accepted = f.call(operation, &account, secret, exact, revision).await;
        assert_eq!(
            accepted.0, accepted_status,
            "{operation}: {}",
            accepted.1["error"]
        );
    }
    let c = f.db.connect().await.unwrap();
    for table in ["accounts", "grants"] {
        let selector = if table == "accounts" {
            "id"
        } else {
            "subject_id"
        };
        let stored: chrono::DateTime<Utc> = c
            .query_one(
                &format!("SELECT expires_at FROM {table} WHERE {selector}=$1"),
                &[&child_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(stored, expected);
    }
}

#[tokio::test]
async fn api_key_expiry_matches_postgres_for_derivation_and_rotation() {
    use chrono::Timelike;

    let Some(f) = Fixture::new().await else {
        return;
    };
    let requested = (chrono::Utc::now() + chrono::Duration::hours(1))
        .with_nanosecond(123_456_789)
        .unwrap();
    let expected = requested.with_nanosecond(123_456_000).unwrap();
    let account = [("account_id", f.owner.to_string())];
    let mut request = key_body(json!({"mode":"all_snapshot"}));
    request["conditions"]["expires_at"] = json!(requested);
    let issuer = f
        .call("createApiKey", &account, &f.token, request.clone(), None)
        .await;
    assert_eq!(issuer.0, 201, "{}", issuer.1["error"]);
    assert_eq!(
        issuer.1["credential"]["conditions"]["expires_at"],
        json!(expected)
    );
    let issuer_id = contracts::id(&issuer.1["credential"], "id").unwrap();
    let c = f.db.connect().await.unwrap();
    let row = c
        .query_one(
            "SELECT expires_at,conditions FROM credentials WHERE id=$1",
            &[&issuer_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, chrono::DateTime<chrono::Utc>>(0), expected);
    assert_eq!(row.get::<_, Value>(1)["expires_at"], json!(expected));

    // Older keys retain the untruncated request in JSON and the effective
    // expiry in the indexed column.
    c.execute(
        "UPDATE credentials SET conditions=$2 WHERE id=$1",
        &[&issuer_id, &request["conditions"]],
    )
    .await
    .unwrap();
    let credential = [("credential_id", issuer_id.to_string())];
    let inspected = f
        .call("getApiKey", &credential, &f.token, Value::Null, None)
        .await;
    assert_eq!(inspected.0, 200, "{}", inspected.1["error"]);
    assert_eq!(inspected.1["conditions"]["expires_at"], json!(expected));

    let mut later = request.clone();
    later["conditions"]["expires_at"] = json!(expected + chrono::Duration::microseconds(1));
    let issuer_secret = issuer.1["secret"].as_str().unwrap();
    for (operation, path, token, revision) in [
        ("createApiKey", &account, issuer_secret, None),
        ("rotateApiKey", &credential, f.token.as_str(), Some(1)),
    ] {
        let denied = f
            .call(operation, path, token, later.clone(), revision)
            .await;
        assert_eq!(denied.0, 403, "{operation}: {}", denied.1["error"]);
        assert_eq!(denied.1["error"]["code"], "PERMISSION_DENIED");
        let accepted = f
            .call(operation, path, token, request.clone(), revision)
            .await;
        assert_eq!(accepted.0, 201, "{operation}: {}", accepted.1["error"]);
        assert_eq!(
            accepted.1["credential"]["conditions"]["expires_at"],
            json!(expected)
        );
    }
}

async fn grant_guest(f: &Fixture, account: Uuid, scope: Value) -> Uuid {
    let granted = f
        .call(
            "createGrant",
            &[("account_id", account.to_string())],
            &f.token,
            json!({"source":"role","role_id":"Guest","scope":scope}),
            None,
        )
        .await;
    assert_eq!(granted.0, 201, "{}", granted.1);
    contracts::id(&granted.1, "id").unwrap()
}

async fn revoke_grant(f: &Fixture, grant: Uuid) {
    let revoked = f
        .call(
            "revokeGrant",
            &[("grant_id", grant.to_string())],
            &f.token,
            Value::Null,
            Some(1),
        )
        .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
}

async fn assert_child_capability(
    f: &Fixture,
    account: Uuid,
    token: &str,
    scope: Value,
    expected: bool,
) {
    let effective = f
        .call(
            "getEffectivePermissions",
            &[("account_id", account.to_string())],
            &f.token,
            Value::Null,
            None,
        )
        .await;
    assert_eq!(effective.0, 200, "{}", effective.1);
    let resource = auth::Resource::new("capability", scope["ids"][0].as_str().unwrap(), None);
    assert_eq!(
        auth::rules_allow(
            &effective.1["rules"],
            "capability.invoke",
            &resource,
            "127.0.0.1".parse().unwrap(),
        ),
        expected,
        "effective account rules: {}",
        effective.1
    );
    assert_eq!(f.check(token, "capability.invoke", scope).await, expected);
}

async fn child_direct_grant_sources(mode: &str) {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (parent, parent_token) = f.root_guest().await;
    let c = f.db.connect().await.unwrap();
    let original: Uuid = c
        .query_one("SELECT id FROM grants WHERE subject_id=$1", &[&parent])
        .await
        .unwrap()
        .get(0);
    let inheritance = if mode == "selected" {
        selected()
    } else {
        json!({"mode":mode})
    };
    let (child, token) = f.child(parent, &parent_token, inheritance).await;
    let (grandchild, grandchild_token) = f
        .child(child, &token, json!({"mode":"follow_parent"}))
        .await;
    let old_key = f.key(child, &token, json!({"mode":"all_snapshot"})).await;
    let direct = grant_guest(&f, child, cap()).await;
    assert_child_capability(&f, child, &token, cap(), true).await;
    let paths = xelab_kernel::policy::Policy::new(&c, "127.0.0.1".parse().unwrap())
        .account(child, 0)
        .await
        .unwrap();
    assert!(
        paths.iter().any(|p| p.sources.contains(&direct)),
        "a successful child Grant must participate in live provenance"
    );
    let issued = f.key(child, &token, json!({"mode":"all_snapshot"})).await;
    let issued_id = contracts::id(&issued["credential"], "id").unwrap();
    let count: i64 = c
        .query_one(
            "SELECT count(*) FROM grant_provenance WHERE derived_credential_id=$1 AND source_grant_id=$2",
            &[&issued_id, &direct],
        )
        .await
        .unwrap()
        .get(0);
    assert!(count > 0, "derived Keys retain the child Grant source");

    // A direct binding cannot exceed the parent or a selected/snapshot ceiling.
    let other = json!({"kind":"capability","match":"ids","ids":["org.xelab.other@1.0.0"]});
    grant_guest(&f, child, other.clone()).await;
    assert_child_capability(&f, child, &token, other.clone(), false).await;
    grant_guest(&f, parent, other.clone()).await;
    assert_child_capability(&f, child, &token, other, mode == "follow_parent").await;

    revoke_grant(&f, original).await;
    assert_child_capability(&f, child, &token, cap(), false).await;
    assert_child_capability(&f, grandchild, &grandchild_token, cap(), false).await;
    grant_guest(&f, parent, cap()).await;
    // Fixed-mode inheritance lost its original source. The explicit direct
    // grant remains independently valid, within the unchanged fixed selector.
    assert_child_capability(&f, child, &token, cap(), true).await;
    assert_child_capability(&f, grandchild, &grandchild_token, cap(), true).await;
    for key in [&old_key, &issued] {
        assert!(
            !f.check(key["secret"].as_str().unwrap(), "capability.invoke", cap())
                .await,
            "new parent/direct sources cannot revive an old Key snapshot"
        );
    }

    // A second, group-backed direct grant is an OR alternative to the role.
    let group = f
        .call(
            "createGroup",
            &[],
            &f.token,
            json!({"name":"child alternative","rules":[{"action":"capability.invoke","resource":cap(),"conditions":{"source_cidrs":["127.0.0.1/32"]}}]}),
            None,
        )
        .await;
    assert_eq!(group.0, 201, "{}", group.1);
    let alternate = f
        .call(
            "createGrant",
            &[("account_id", child.to_string())],
            &f.token,
            json!({"source":"group","group_version":{"group_id":group.1["id"],"version":1},"scope":cap()}),
            None,
        )
        .await;
    assert_eq!(alternate.0, 201, "{}", alternate.1);
    let alternate = contracts::id(&alternate.1, "id").unwrap();
    let current_key = f.key(child, &token, json!({"mode":"all_snapshot"})).await;
    revoke_grant(&f, direct).await;
    assert_child_capability(&f, child, &token, cap(), true).await;
    assert!(
        f.check(
            current_key["secret"].as_str().unwrap(),
            "capability.invoke",
            cap()
        )
        .await
    );
    revoke_grant(&f, alternate).await;
    let inherited = mode == "follow_parent";
    assert_child_capability(&f, child, &token, cap(), inherited).await;
    assert_child_capability(&f, grandchild, &grandchild_token, cap(), inherited).await;
    assert_eq!(
        f.check(
            current_key["secret"].as_str().unwrap(),
            "capability.invoke",
            cap()
        )
        .await,
        inherited
    );
    let paths = xelab_kernel::policy::Policy::new(&c, "127.0.0.1".parse().unwrap())
        .account(child, 0)
        .await
        .unwrap();
    assert!(paths
        .iter()
        .all(|p| !p.sources.contains(&direct) && !p.sources.contains(&alternate)));
    grant_guest(&f, child, cap()).await;
    assert_child_capability(&f, child, &token, cap(), true).await;
    assert_eq!(
        f.check(
            current_key["secret"].as_str().unwrap(),
            "capability.invoke",
            cap()
        )
        .await,
        inherited,
        "a replacement child Grant does not revive withdrawn Key sources"
    );
}

#[tokio::test]
async fn child_direct_grants_obey_selected_sources_and_ceiling() {
    child_direct_grant_sources("selected").await;
}

#[tokio::test]
async fn self_issued_grants_have_linear_proofs_and_live_revocation() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let c = f.db.connect().await.unwrap();
    let mut grants = Vec::new();
    for count in 1..=16 {
        let grant = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            grant_guest(&f, f.owner, cap()),
        )
        .await
        .expect("self-grant issuance must not expand permutations");
        grants.push(grant);
        if ![2, 8, 16].contains(&count) {
            continue;
        }
        let started = std::time::Instant::now();
        let paths = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            xelab_kernel::policy::Policy::new(&c, "127.0.0.1".parse().unwrap())
                .account(f.owner, 0)
                .await
                .unwrap()
        })
        .await
        .expect("self-grant evaluation must remain bounded");
        eprintln!(
            "self grants={count} paths={} elapsed={:?}",
            paths.len(),
            started.elapsed()
        );
        let invoke: Vec<_> = paths
            .iter()
            .filter(|p| {
                p.rule["action"] == "capability.invoke"
                    && p.rule["resource"]["kind"] == "capability"
            })
            .collect();
        assert_eq!(invoke.len(), count + 1);
        for grant in &grants {
            assert!(invoke.iter().any(|p| p.sources.contains(grant)));
        }
        assert_child_capability(&f, f.owner, &f.token, cap(), true).await;
    }
    let anchor: Uuid = c.query_one("SELECT g.id FROM grants g JOIN accounts a ON a.id=g.subject_id WHERE a.id=$1 AND g.role_id='Owner' AND g.created_at=a.created_at AND g.scope->>'kind'='capability'", &[&f.owner]).await.unwrap().get(0);
    c.execute("UPDATE grants SET status='revoked' WHERE id=$1", &[&anchor])
        .await
        .unwrap();
    // Sixteen self-issued bindings must not sustain one another after the
    // independent authority disappears; a fresh request must observe revocation.
    assert_child_capability(&f, f.owner, &f.token, cap(), false).await;
}

#[tokio::test]
async fn child_direct_grants_obey_snapshot_sources_and_ceiling() {
    child_direct_grant_sources("all_snapshot").await;
}

#[tokio::test]
async fn child_direct_grants_preserve_follow_parent_alternatives() {
    child_direct_grant_sources("follow_parent").await;
}

#[tokio::test]
async fn child_direct_grants_remain_bounded_by_issuer_key() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (parent, parent_token) = f.root_guest().await;
    let issuer = f
        .key(
            parent,
            &parent_token,
            json!({"mode":"selected","rules":[{"action":"capability.invoke","resource":cap()},{"action":"account.child.create","resource":{"kind":"account","match":"ids","ids":[parent]}}]}),
        )
        .await;
    let (child, token) = f
        .child(
            parent,
            issuer["secret"].as_str().unwrap(),
            json!({"mode":"follow_parent"}),
        )
        .await;
    grant_guest(&f, child, cap()).await;
    let other = json!({"kind":"capability","match":"ids","ids":["org.xelab.other@1.0.0"]});
    grant_guest(&f, parent, other.clone()).await;
    grant_guest(&f, child, other.clone()).await;
    assert_child_capability(&f, child, &token, cap(), true).await;
    assert_child_capability(&f, child, &token, other, false).await;
    let revoked = f
        .call(
            "revokeApiKey",
            &[(
                "credential_id",
                issuer["credential"]["id"].as_str().unwrap().into(),
            )],
            &parent_token,
            Value::Null,
            Some(1),
        )
        .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let denied = f
        .call(
            "checkAuthorization",
            &[],
            &token,
            json!({"action":"capability.invoke","resource":cap()}),
            None,
        )
        .await;
    assert_eq!(denied.0, 401, "{}", denied.1);
}

#[allow(clippy::too_many_arguments)]
async fn api(
    router: &Router,
    operation: &str,
    params: &[(&str, String)],
    token: Option<&str>,
    body: Value,
    key: &str,
    revision: Option<i64>,
    query: &str,
) -> (u16, Value) {
    let mut selected = None;
    for (path, methods) in contracts::openapi()["paths"].as_object().unwrap() {
        for (method, spec) in methods.as_object().unwrap() {
            if spec["operationId"] == operation {
                selected = Some((path.clone(), method.to_uppercase()));
            }
        }
    }
    let (mut path, method) = selected.unwrap();
    for (name, value) in params {
        path = path.replace(&format!("{{{name}}}"), value);
    }
    if !query.is_empty() {
        path.push('?');
        path.push_str(query);
    }
    let mut req = Request::builder()
        .header("host", http_host::authority(None))
        .method(method.as_str())
        .uri(path)
        .header("idempotency-key", key);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(revision) = revision {
        req = req.header("if-match", format!("\"rev-{revision}\""));
    }
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        req = req.header("content-type", "application/json");
        serde_json::to_vec(&body).unwrap()
    };
    let mut req = req.body(Body::from(bytes)).unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
    ));
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 16777216).await.unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}

#[tokio::test]
async fn auth_01_02_guest_self_service_and_group_cannot_escape_parent() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (guest, token) = f.root_guest().await;
    assert_eq!(
        f.call("getNode", &[], &token, Value::Null, None).await.0,
        404
    );
    let (child, child_token) = f.child(guest, &token, selected()).await;
    assert!(f.check(&child_token, "capability.invoke", cap()).await);
    let key = f.key(child, &child_token, selected()).await;
    assert!(
        !f.check(
            key["secret"].as_str().unwrap(),
            "credential.api-key.create",
            json!({"kind":"account","match":"ids","ids":[child]})
        )
        .await,
        "a Key does not gain fixed self-service"
    );
    let group = f
        .call(
            "createGroup",
            &[],
            &child_token,
            json!({"name":"echo only","rules":[{"action":"capability.invoke","resource":cap()}]}),
            None,
        )
        .await;
    assert_eq!(group.0, 201, "{}", group.1);
    let broader=f.call("createGroup",&[],&child_token,json!({"name":"escalation","rules":[{"action":"platform.read","resource":{"kind":"platform","match":"all"}}]}),None).await;
    assert_eq!(broader.0, 403, "{}", broader.1);
    let bind = f
        .call(
            "createGrant",
            &[("account_id", child.to_string())],
            &f.token,
            json!({"source":"role","role_id":"Owner","scope":{"kind":"platform","match":"all"}}),
            None,
        )
        .await;
    assert_eq!(bind.0, 201, "{}", bind.1);
    assert!(
        !f.check(
            &child_token,
            "platform.read",
            json!({"kind":"platform","match":"ids","ids":["node"]})
        )
        .await
    );
    let c = f.db.connect().await.unwrap();
    let raw: Value = c
        .query_one("SELECT to_jsonb(a) FROM accounts a WHERE id=$1", &[&child])
        .await
        .unwrap()
        .get(0);
    assert_eq!(raw["parent_id"], guest.to_string());
    assert_eq!(raw["independent_owner"], false);
    assert!(raw["activation_digest"].is_null());
}

#[tokio::test]
async fn auth_03_snapshot_follow_and_independent_provenance() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (guest, token) = f.root_guest().await;
    let fixed = f.key(guest, &token, json!({"mode":"all_snapshot"})).await;
    let follow = f.key(guest, &token, json!({"mode":"follow_parent"})).await;
    let grant = f
        .call(
            "createGrant",
            &[("account_id", guest.to_string())],
            &f.token,
            json!({"source":"role","role_id":"Auditor","scope":{"kind":"platform","match":"all"}}),
            None,
        )
        .await;
    assert_eq!(grant.0, 201, "{}", grant.1);
    let resource = json!({"kind":"platform","match":"ids","ids":["node"]});
    assert!(
        !f.check(
            fixed["secret"].as_str().unwrap(),
            "platform.read",
            resource.clone()
        )
        .await
    );
    assert!(
        f.check(
            follow["secret"].as_str().unwrap(),
            "platform.read",
            resource
        )
        .await
    );
    // Two independent live grant paths support the same frozen capability.
    let extra = f
        .call(
            "createGrant",
            &[("account_id", guest.to_string())],
            &f.token,
            json!({"source":"role","role_id":"Guest","scope":cap()}),
            None,
        )
        .await;
    assert_eq!(extra.0, 201, "{}", extra.1);
    let both = f.key(guest, &token, selected()).await;
    let all = f
        .call(
            "listGrants",
            &[("account_id", guest.to_string())],
            &token,
            Value::Null,
            None,
        )
        .await;
    assert_eq!(all.0, 200, "{}", all.1);
    let grants: Vec<Value> = all.1["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["spec"]["role_id"] == "Guest")
        .cloned()
        .collect();
    assert_eq!(grants.len(), 2);
    let revoked = f
        .call(
            "revokeGrant",
            &[("grant_id", grants[0]["id"].as_str().unwrap().into())],
            &f.token,
            Value::Null,
            Some(1),
        )
        .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    assert!(
        f.check(both["secret"].as_str().unwrap(), "capability.invoke", cap())
            .await
    );
    assert_eq!(
        f.call(
            "revokeGrant",
            &[("grant_id", grants[1]["id"].as_str().unwrap().into())],
            &f.token,
            Value::Null,
            Some(1)
        )
        .await
        .0,
        204
    );
    assert!(
        !f.check(both["secret"].as_str().unwrap(), "capability.invoke", cap())
            .await
    );
    let replacement = f
        .call(
            "createGrant",
            &[("account_id", guest.to_string())],
            &f.token,
            json!({"source":"role","role_id":"Guest","scope":cap()}),
            None,
        )
        .await;
    assert_eq!(replacement.0, 201, "{}", replacement.1);
    assert!(
        !f.check(both["secret"].as_str().unwrap(), "capability.invoke", cap())
            .await,
        "a new grant cannot revive a withdrawn snapshot source"
    );
    assert!(
        f.check(
            follow["secret"].as_str().unwrap(),
            "capability.invoke",
            cap()
        )
        .await
    );
}

#[tokio::test]
async fn snapshot_tracks_partial_source_withdrawal_without_borrowing_new_grants() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (issuer, issuer_token) = f
        .child(f.owner, &f.token, json!({"mode":"all_snapshot"}))
        .await;
    let (guest, token) = f.root_guest().await;
    let both = json!({"kind":"capability","match":"ids","ids":["org.xelab.alpha@1.0.0","org.xelab.beta@1.0.0"]});
    let alpha = json!({"kind":"capability","match":"ids","ids":["org.xelab.alpha@1.0.0"]});
    let beta = json!({"kind":"capability","match":"ids","ids":["org.xelab.beta@1.0.0"]});
    let grant = f
        .call(
            "createGrant",
            &[("account_id", guest.to_string())],
            &issuer_token,
            json!({"source":"role","role_id":"Guest","scope":both}),
            None,
        )
        .await;
    assert_eq!(grant.0, 201, "{}", grant.1);
    let frozen = f
        .key(
            guest,
            &token,
            json!({"mode":"selected","rules":[{"action":"capability.invoke","resource":both}]}),
        )
        .await;
    let account = f
        .call(
            "getAccount",
            &[("account_id", issuer.to_string())],
            &f.token,
            Value::Null,
            None,
        )
        .await;
    let narrowed = f
        .call(
            "updateInheritance",
            &[("account_id", issuer.to_string())],
            &f.token,
            json!({"mode":"selected","rules":[{"action":"capability.invoke","resource":alpha}]}),
            account.1["revision"].as_i64(),
        )
        .await;
    assert_eq!(narrowed.0, 200, "{}", narrowed.1);
    let replacement = f
        .call(
            "createGrant",
            &[("account_id", guest.to_string())],
            &f.token,
            json!({"source":"role","role_id":"Guest","scope":beta}),
            None,
        )
        .await;
    assert_eq!(replacement.0, 201, "{}", replacement.1);
    assert!(f.check(&token, "capability.invoke", beta.clone()).await);
    assert!(
        f.check(
            frozen["secret"].as_str().unwrap(),
            "capability.invoke",
            alpha
        )
        .await
    );
    assert!(
        !f.check(
            frozen["secret"].as_str().unwrap(),
            "capability.invoke",
            beta
        )
        .await,
        "the old source now covers only alpha; a new beta grant cannot fill its gap"
    );
}

#[tokio::test]
async fn auth_04_05_06_source_revocation_idempotency_and_secret_storage() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (guest, token) = f.root_guest().await;
    let k1 = f.key(guest, &token, json!({"mode":"all_snapshot"})).await;
    let k2 = f
        .key(guest, k1["secret"].as_str().unwrap(), selected())
        .await;
    let independent = f.key(guest, &token, selected()).await;
    let (child, child_token) = f
        .child(guest, k1["secret"].as_str().unwrap(), selected())
        .await;
    let params = [("account_id", guest.to_string())];
    let body = key_body(selected());
    let first = api(
        &f.router,
        "createApiKey",
        &params,
        Some(&token),
        body.clone(),
        "same-one-time-key",
        None,
        "",
    )
    .await;
    assert_eq!(first.0, 201, "{}", first.1);
    let replay = api(
        &f.router,
        "createApiKey",
        &params,
        Some(&token),
        body,
        "same-one-time-key",
        None,
        "",
    )
    .await;
    assert_eq!(replay.0, 409, "{}", replay.1);
    assert_eq!(replay.1["error"]["code"], "ONE_TIME_RESPONSE_UNAVAILABLE");
    assert_eq!(
        replay.1["error"]["resource_id"],
        first.1["credential"]["id"]
    );
    let c = f.db.connect().await.unwrap();
    let record = c
        .query_one(
            "SELECT sensitive,safe_response FROM idempotency_records WHERE key='same-one-time-key'",
            &[],
        )
        .await
        .unwrap();
    assert!(record.get::<_, bool>(0));
    assert!(record.get::<_, Option<Value>>(1).is_none());
    let persisted: String = c
        .query_one(
            "SELECT string_agg(to_jsonb(k)::text,'') FROM credentials k",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!persisted.contains(first.1["secret"].as_str().unwrap()));
    let issued_id = first.1["credential"]["id"].as_str().unwrap();
    let audit:Value=c.query_one("SELECT to_jsonb(a) FROM audit_events a WHERE action='createApiKey' AND resource->'ids' @> $1 ORDER BY created_at DESC LIMIT 1", &[&json!([issued_id])]).await.unwrap().get(0);
    assert_eq!(audit["resource"]["kind"], "credential");
    assert!(!audit
        .to_string()
        .contains(first.1["secret"].as_str().unwrap()));
    let revoke = f
        .call(
            "revokeApiKey",
            &[(
                "credential_id",
                k1["credential"]["id"].as_str().unwrap().into(),
            )],
            &token,
            Value::Null,
            Some(1),
        )
        .await;
    assert_eq!(revoke.0, 204, "{}", revoke.1);
    for secret in [
        k1["secret"].as_str().unwrap(),
        k2["secret"].as_str().unwrap(),
        &child_token,
    ] {
        assert_eq!(
            f.call(
                "checkAuthorization",
                &[],
                secret,
                json!({"action":"capability.invoke","resource":cap()}),
                None
            )
            .await
            .0,
            401
        );
    }
    assert!(
        f.check(
            independent["secret"].as_str().unwrap(),
            "capability.invoke",
            cap()
        )
        .await
    );
    // Archiving retains the original parent and source; no orphan promotion.
    let value = f
        .call(
            "getAccount",
            &[("account_id", child.to_string())],
            &f.token,
            Value::Null,
            None,
        )
        .await;
    let archive = f
        .call(
            "archiveAccount",
            &[("account_id", child.to_string())],
            &f.token,
            Value::Null,
            value.1["revision"].as_i64(),
        )
        .await;
    assert_eq!(archive.0, 204, "{}", archive.1);
    assert_eq!(
        c.query_one("SELECT parent_id FROM accounts WHERE id=$1", &[&child])
            .await
            .unwrap()
            .get::<_, Uuid>(0),
        guest
    );
}

#[tokio::test]
async fn auth_07_08_object_visibility_last_owner_and_stale_etag() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (_, guest) = f.root_guest().await;
    let secret = f.key(f.owner, &f.token, selected()).await;
    assert_eq!(
        f.call(
            "getApiKey",
            &[(
                "credential_id",
                secret["credential"]["id"].as_str().unwrap().into()
            )],
            &guest,
            Value::Null,
            None
        )
        .await
        .0,
        404
    );
    let p = [("account_id", f.owner.to_string())];
    assert_eq!(
        f.call(
            "updateAccount",
            &p,
            &f.token,
            json!({"status":"disabled"}),
            Some(1)
        )
        .await
        .0,
        409
    );
    assert_eq!(
        f.call("archiveAccount", &p, &f.token, Value::Null, Some(1))
            .await
            .0,
        409
    );
    let ok = f
        .call(
            "updateAccount",
            &p,
            &f.token,
            json!({"display_name":"renamed"}),
            Some(1),
        )
        .await;
    assert_eq!(ok.0, 200, "{}", ok.1);
    assert_eq!(
        f.call(
            "updateAccount",
            &p,
            &f.token,
            json!({"display_name":"stale"}),
            Some(1)
        )
        .await
        .0,
        412
    );
    let page = api(
        &f.router,
        "listAccounts",
        &[],
        Some(&f.token),
        Value::Null,
        "list",
        None,
        "limit=1",
    )
    .await;
    assert_eq!(page.0, 200, "{}", page.1);
    let cursor = page.1["next_cursor"].as_str().unwrap();
    let query = format!("limit=1&cursor={cursor}");
    assert_eq!(
        api(
            &f.router,
            "listAccounts",
            &[],
            Some(&guest),
            Value::Null,
            "list",
            None,
            &query
        )
        .await
        .0,
        400
    );
    let next = api(
        &f.router,
        "listAccounts",
        &[],
        Some(&f.token),
        Value::Null,
        "list",
        None,
        &query,
    )
    .await;
    assert_eq!(next.0, 200, "{}", next.1);
    assert_ne!(page.1["items"][0]["id"], next.1["items"][0]["id"]);
}

#[tokio::test]
async fn auth_09_concurrent_tree_and_key_quotas_are_atomic() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let p = [("account_id", f.owner.to_string())];
    let quota = json!({"maximum_depth":4,"maximum_descendants":1,"maximum_api_keys":1,"maximum_concurrent_calls":16,"daily_calls":10000});
    let out = f.call("updateQuota", &p, &f.token, quota, Some(1)).await;
    assert_eq!(out.0, 200, "{}", out.1);
    let body = json!({"display_name":"racer","kind":"service","inheritance":selected()});
    let (a, b) = tokio::join!(
        f.call("createChildAccount", &p, &f.token, body.clone(), None),
        f.call("createChildAccount", &p, &f.token, body, None)
    );
    let mut statuses = vec![a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, vec![201, 409], "{a:?} {b:?}");
    let body = key_body(selected());
    let (a, b) = tokio::join!(
        f.call("createApiKey", &p, &f.token, body.clone(), None),
        f.call("createApiKey", &p, &f.token, body, None)
    );
    let mut statuses = vec![a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, vec![201, 409], "{a:?} {b:?}");
    let c = f.db.connect().await.unwrap();
    let q = c
        .query_one(
            "SELECT descendants_used,api_keys_used FROM quotas WHERE account_id=$1",
            &[&f.owner],
        )
        .await
        .unwrap();
    assert_eq!((q.get::<_, i64>(0), q.get::<_, i64>(1)), (1, 1));
}

#[tokio::test]
async fn key_rotation_password_and_parent_disable_preserve_boundaries() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (guest, token) = f.root_guest().await;
    let (child, child_token) = f.child(guest, &token, selected()).await;
    let old = f.key(child, &child_token, selected()).await;
    let body = key_body(selected());
    let rotate = f
        .call(
            "rotateApiKey",
            &[(
                "credential_id",
                old["credential"]["id"].as_str().unwrap().into(),
            )],
            &child_token,
            body,
            Some(1),
        )
        .await;
    assert_eq!(rotate.0, 201, "{}", rotate.1);
    assert!(
        f.check(
            rotate.1["secret"].as_str().unwrap(),
            "capability.invoke",
            cap()
        )
        .await
    );
    assert_eq!(
        f.call(
            "checkAuthorization",
            &[],
            old["secret"].as_str().unwrap(),
            json!({"action":"capability.invoke","resource":cap()}),
            None
        )
        .await
        .0,
        401
    );
    let row = f
        .call(
            "getAccount",
            &[("account_id", guest.to_string())],
            &f.token,
            Value::Null,
            None,
        )
        .await;
    let disabled = f
        .call(
            "updateAccount",
            &[("account_id", guest.to_string())],
            &f.token,
            json!({"status":"disabled"}),
            row.1["revision"].as_i64(),
        )
        .await;
    assert_eq!(disabled.0, 200, "{}", disabled.1);
    assert_eq!(
        f.call(
            "getAccount",
            &[("account_id", child.to_string())],
            &child_token,
            Value::Null,
            None
        )
        .await
        .0,
        401
    );
    assert_eq!(
        f.call(
            "updateAccount",
            &[("account_id", guest.to_string())],
            &f.token,
            json!({"status":"active"}),
            disabled.1["revision"].as_i64()
        )
        .await
        .0,
        200
    );
    let row = f
        .call(
            "getAccount",
            &[("account_id", child.to_string())],
            &child_token,
            Value::Null,
            None,
        )
        .await;
    let changed = f
        .call(
            "changePassword",
            &[("account_id", child.to_string())],
            &child_token,
            json!({"current_password":PASSWORD,"new_password":"changed acceptance password"}),
            row.1["revision"].as_i64(),
        )
        .await;
    assert_eq!(changed.0, 204, "{}", changed.1);
    assert!(
        f.check(
            rotate.1["secret"].as_str().unwrap(),
            "capability.invoke",
            cap()
        )
        .await,
        "password/session revocation does not revoke independently issued keys"
    );
    assert_eq!(
        f.call(
            "getAccount",
            &[("account_id", child.to_string())],
            &child_token,
            Value::Null,
            None
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn immutable_group_templates_do_not_become_authority_sources() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (guest, token) = f.root_guest().await;
    let rules = json!([{"action":"capability.invoke","resource":cap()}]);
    let group = f
        .call(
            "createGroup",
            &[],
            &f.token,
            json!({"name":"public echo template","visibility":"public","rules":rules}),
            None,
        )
        .await;
    assert_eq!(group.0, 201, "{}", group.1);
    let group_id = group.1["id"].as_str().unwrap();
    let key = f
        .key(
            guest,
            &token,
            json!({"mode":"selected","group_versions":[{"group_id":group_id,"version":1}]}),
        )
        .await;
    let version=f.call("publishGroupVersion",&[("group_id",group_id.into())],&f.token,json!({"rules":[{"action":"platform.read","resource":{"kind":"platform","match":"all"}}]}),Some(1)).await;
    assert_eq!(version.0, 201, "{}", version.1);
    assert_eq!(version.1["version"], 2);
    let v1 = f
        .call(
            "getGroupVersion",
            &[("group_id", group_id.into()), ("version_id", "1".into())],
            &token,
            Value::Null,
            None,
        )
        .await;
    assert_eq!(v1.0, 200, "{}", v1.1);
    assert_eq!(v1.1["rules"], rules);
    let escalation = f
        .call(
            "createApiKey",
            &[("account_id", guest.to_string())],
            &token,
            key_body(
                json!({"mode":"selected","group_versions":[{"group_id":group_id,"version":2}]}),
            ),
            None,
        )
        .await;
    assert_eq!(
        escalation.0, 403,
        "a readable group is not a grant: {}",
        escalation.1
    );
    let archived = f
        .call(
            "archiveGroup",
            &[("group_id", group_id.into())],
            &f.token,
            Value::Null,
            Some(2),
        )
        .await;
    assert_eq!(archived.0, 204, "{}", archived.1);
    assert!(
        f.check(key["secret"].as_str().unwrap(), "capability.invoke", cap())
            .await,
        "the snapshot traces the actual Guest grant, not the selected template"
    );
    for rule in [
        json!({"action":"unregistered.action","resource":cap()}),
        json!({"action":"capability.invoke","resource":cap(),"conditions":{"source_cidrs":["not-a-cidr"]}}),
    ] {
        assert_eq!(
            f.call(
                "createGroup",
                &[],
                &f.token,
                json!({"name":"invalid","rules":[rule]}),
                None
            )
            .await
            .0,
            400
        );
    }
    let mut restricted = key_body(selected());
    restricted["conditions"]["source_cidrs"] = json!(["192.0.2.0/24"]);
    let issued = f
        .call(
            "createApiKey",
            &[("account_id", guest.to_string())],
            &token,
            restricted,
            None,
        )
        .await;
    assert_eq!(issued.0, 201, "{}", issued.1);
    assert_eq!(
        f.call(
            "checkAuthorization",
            &[],
            issued.1["secret"].as_str().unwrap(),
            json!({"action":"capability.invoke","resource":cap()}),
            None
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn browser_session_cookie_requires_same_origin_for_mutation() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut login = Request::builder()
        .header("host", http_host::authority(None))
        .method("POST")
        .uri("/api/platform/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"account_id":f.owner,"password":PASSWORD})).unwrap(),
        ))
        .unwrap();
    login.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
    ));
    let response = f.router.clone().oneshot(login).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let set_cookie = response.headers()["set-cookie"].to_str().unwrap();
    for flag in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(set_cookie.contains(flag));
    }
    assert!(!set_cookie.contains("Domain="));
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    let csrf = response.headers()["x-csrf-token"]
        .to_str()
        .unwrap()
        .to_owned();
    let config: toml::Value =
        toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
    for (origin, status) in [
        (None, 403),
        (Some("https://attacker.invalid"), 403),
        (config["server"]["public_origin"].as_str(), 200),
    ] {
        let mut request = Request::builder()
            .header("host", http_host::authority(None))
            .method("PATCH")
            .uri(format!("/api/platform/v1/accounts/{}", f.owner))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .header("content-type", "application/json")
            .header("if-match", "\"rev-1\"")
            .header("idempotency-key", Uuid::new_v4().to_string());
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let mut request = request
            .body(Body::from("{\"display_name\":\"browser\"}"))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
        ));
        let response = f.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
    }
}
