//! Workflow control-plane tests through the main router and PostgreSQL.
//! The installed capability is a metadata fixture; no plugin process is used.

#[path = "support/http_host.rs"]
mod http_host;
#[path = "support/task_admission.rs"]
mod task_admission;
#[path = "support/workflow_authority_wait.rs"]
mod workflow_authority_wait;

use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Method, Request},
    Router,
};
use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc},
};
use tower::ServiceExt;
use uuid::Uuid;
use xelab_kernel::{
    api::{router, App},
    artifact,
    auth::{self, Auth},
    config::Config,
    contracts,
    db::Db,
    runtime::Runtime,
};

const WORKFLOWS: &str = "/api/platform/v1/workflows";
const PASSWORD: &str = "correct horse Workflow acceptance password";

struct Reply {
    status: u16,
    etag: Option<String>,
    body: Value,
}

impl Reply {
    fn expect(self, status: u16) -> Self {
        assert_eq!(self.status, status, "{}", self.body);
        self
    }
}

async fn request(
    router: &Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<&Value>,
    headers: &[(&str, &str)],
) -> Reply {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, http_host::authority(None));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = if let Some(value) = body {
        request = request.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(value).unwrap())
    } else {
        Body::empty()
    };
    let mut request = request.body(body).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
    ));
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let etag = response
        .headers()
        .get(header::ETAG)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    Reply { status, etag, body }
}

struct Fixture {
    db: Db,
    router: Router,
    owner: Uuid,
    token: String,
    installation: Uuid,
    contract: Value,
    skill_definition: Value,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: Workflow API regression requires PostgreSQL");
            return None;
        };
        let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
        let name = format!("workflows_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let db = Db::new(format!("{base} dbname={name}")).unwrap();
        db.migrate().await.unwrap();
        let source: toml::Value =
            toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
        let config = Config::from_value(serde_json::to_value(source).unwrap()).unwrap();
        let mut conn = db.connect().await.unwrap();
        let tx = conn.transaction().await.unwrap();
        let owner = auth::bootstrap(&tx, "Owner", PASSWORD, &config.value["quota_defaults"])
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let publisher = Uuid::new_v4();
        let pem = SigningKey::from_bytes(&[13; 32])
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        conn.execute(
            "INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'Workflow fixture','workflow-fixture',$2,'trusted',now(),now())",
            &[&publisher, &pem],
        ).await.unwrap();
        let mut manifest: Value =
            serde_json::from_str(include_str!("fixtures/secret-manifest.json")).unwrap();
        manifest["publisher_id"] = json!(publisher);
        manifest["requested_rules"] = json!([]);
        let capability = manifest["capabilities"][0].clone();
        let contract = &capability["contract"];
        let skill_definition = json!({
            "name":format!("{}.echo", manifest["plugin_id"].as_str().unwrap()),
            "version":"1.0.0",
            "description":"Workflow fixture Skill",
            "input_schema":capability["input_schema"],
            "output_schema":capability["output_schema"],
            "stream_item_schema":null,
            "target":{"kind":"capability","plugin_id":manifest["plugin_id"],"contract":contract},
            "mapping":"identity",
            "maximum_timeout_ms":10000,
            "input_blobs":false,
            "tags":[]
        });
        manifest["skills"] = json!([skill_definition]);
        artifact::validate_profile(&manifest).unwrap();
        let installation = Uuid::new_v4();
        let digest = contracts::digest(&serde_json::to_vec(&manifest).unwrap());
        conn.execute(
            "INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,'1.0.0',$3,$4,$4,$5,'installed',now(),now())",
            &[&installation, &manifest["plugin_id"].as_str().unwrap(), &publisher, &digest, &manifest],
        ).await.unwrap();
        conn.execute(
            "INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4)",
            &[
                &contract["name"].as_str().unwrap(),
                &contract["version"].as_str().unwrap(),
                &contract["schema_digest"].as_str().unwrap(),
                &capability,
            ],
        )
        .await
        .unwrap();
        let router = router(Arc::new(App {
            runtime: Runtime::new(config.clone()),
            config,
            db: db.clone(),
            auth: Auth::new(vec![55; 32]).unwrap(),
            leader: Arc::new(db.leader().await.unwrap()),
            ready: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
            blob_uploads: tokio::sync::Semaphore::new(4),
        }));
        let token = login(&router, owner).await;
        Some(Self {
            db,
            router,
            owner,
            token,
            installation,
            contract: contract.clone(),
            skill_definition,
        })
    }

    fn spec(&self, message: &str) -> Value {
        json!({
            "name": "echo-workflow",
            "input_schema": {"type":"object"},
            "steps": [{
                "id": "echo",
                "contract": self.contract,
                "depends_on": [],
                "input_mapping": {"message": {"literal": message}},
                "timeout_ms": 1000
            }]
        })
    }

    async fn publish(&self, token: &str, spec: &Value, key: &str) -> Reply {
        request(
            &self.router,
            Method::POST,
            WORKFLOWS,
            Some(token),
            Some(spec),
            &[("idempotency-key", key)],
        )
        .await
    }

    async fn read(&self, token: &str, uri: &str) -> Reply {
        request(&self.router, Method::GET, uri, Some(token), None, &[]).await
    }

    async fn archive(&self, uri: &str, key: &str, etag: Option<&str>) -> Reply {
        let mut headers = vec![("idempotency-key", key)];
        if let Some(etag) = etag {
            headers.push(("if-match", etag));
        }
        request(
            &self.router,
            Method::DELETE,
            uri,
            Some(&self.token),
            None,
            &headers,
        )
        .await
    }

    async fn child(&self) -> (Uuid, String) {
        let child = request(
            &self.router,
            Method::POST,
            &format!("/api/platform/v1/accounts/{}/children", self.owner),
            Some(&self.token),
            Some(&json!({"display_name":"Child","inheritance":{"mode":"follow_parent"}})),
            &[("idempotency-key", "child")],
        )
        .await
        .expect(201)
        .body;
        request(
            &self.router,
            Method::POST,
            "/api/platform/v1/auth/activate",
            None,
            Some(&json!({"activation_token":child["activation_token"],"password":PASSWORD})),
            &[],
        )
        .await
        .expect(200);
        let owner = contracts::id(&child["account"], "id").unwrap();
        (owner, login(&self.router, owner).await)
    }

    async fn workflow_key(&self, owner: Uuid, token: &str, action: &str) -> String {
        let key = request(
            &self.router,
            Method::POST,
            &format!("/api/platform/v1/accounts/{owner}/api-keys"),
            Some(token),
            Some(&json!({
                "name":action,
                "inheritance":{"mode":"selected","rules":[{
                    "action":action,
                    "resource":{"kind":"workflow","match":"owned_by","owner_id":owner}
                }]},
                "conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}
            })),
            &[("idempotency-key", action)],
        )
        .await
        .expect(201)
        .body;
        key["secret"].as_str().unwrap().to_owned()
    }
}

async fn login(router: &Router, owner: Uuid) -> String {
    request(
        router,
        Method::POST,
        "/api/platform/v1/auth/login",
        None,
        Some(&json!({"account_id":owner,"password":PASSWORD})),
        &[],
    )
    .await
    .expect(200)
    .body["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn workflow_versions_are_immutable_and_archive_uses_etag_and_idempotency() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let first_spec = f.spec("first");
    let first = f
        .publish(&f.token, &first_spec, "publish-1")
        .await
        .expect(201);
    assert_eq!(first.body["version"], 1);
    assert_eq!(first.body["owner_id"], json!(f.owner));
    assert_eq!(first.body["spec"], first_spec);
    assert_eq!(first.etag.as_deref(), Some("\"rev-1\""));
    let first_id = first.body["id"].as_str().unwrap();
    let first_uri = format!("{WORKFLOWS}/{first_id}");

    let replay = f
        .publish(&f.token, &first_spec, "publish-1")
        .await
        .expect(201);
    assert_eq!(first.body, replay.body);
    let second_spec = f.spec("second");
    let conflict = f
        .publish(&f.token, &second_spec, "publish-1")
        .await
        .expect(409);
    assert_eq!(conflict.body["error"]["code"], "IDEMPOTENCY_CONFLICT");

    let third_spec = f.spec("third");
    let (second, third) = tokio::join!(
        f.publish(&f.token, &second_spec, "publish-2"),
        f.publish(&f.token, &third_spec, "publish-3"),
    );
    let second = second.expect(201).body;
    let third = third.expect(201).body;
    let mut versions = [
        second["version"].as_i64().unwrap(),
        third["version"].as_i64().unwrap(),
    ];
    versions.sort_unstable();
    assert_eq!(versions, [2, 3]);
    assert_ne!(second["id"], third["id"]);
    assert_eq!(second["spec"], second_spec);
    assert_eq!(third["spec"], third_spec);
    assert_eq!(
        f.read(&f.token, &first_uri).await.expect(200).body,
        first.body
    );

    f.archive(&first_uri, "archive-1", None).await.expect(428);
    let archived = f
        .archive(&first_uri, "archive-1", first.etag.as_deref())
        .await
        .expect(204);
    assert!(archived.body.is_null());
    f.archive(&first_uri, "archive-1", first.etag.as_deref())
        .await
        .expect(204);
    f.archive(&first_uri, "archive-stale", first.etag.as_deref())
        .await
        .expect(412);

    let history = f.read(&f.token, &first_uri).await.expect(200);
    assert_eq!(history.etag.as_deref(), Some("\"rev-2\""));
    assert_eq!(history.body["status"], "archived");
    for field in ["id", "version", "spec", "created_at", "owner_id"] {
        assert_eq!(history.body[field], first.body[field]);
    }
    let fourth = f
        .publish(&f.token, &f.spec("fourth"), "publish-4")
        .await
        .expect(201);
    assert_eq!(fourth.body["version"], 4);
    let list = f.read(&f.token, WORKFLOWS).await.expect(200).body;
    assert_eq!(list["items"].as_array().unwrap().len(), 4);
    assert!(list["items"].as_array().unwrap().contains(&history.body));

    let conn = f.db.connect().await.unwrap();
    let clean: bool = conn.query_one(
        "SELECT NOT EXISTS(SELECT FROM tasks) AND NOT EXISTS(SELECT FROM attempts) AND NOT EXISTS(SELECT FROM calls)",
        &[],
    ).await.unwrap().get(0);
    assert!(clean, "workflow publication must only mutate metadata");
}

#[tokio::test]
async fn workflow_reads_filter_current_authority_and_bind_cursors() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let owner_workflow = f
        .publish(&f.token, &f.spec("owner"), "owner-workflow")
        .await
        .expect(201)
        .body;
    let (child, child_token) = f.child().await;
    let child_workflow = f
        .publish(&child_token, &f.spec("child"), "child-workflow")
        .await
        .expect(201)
        .body;
    assert_eq!(child_workflow["owner_id"], json!(child));
    assert_eq!(child_workflow["version"], 1);
    let reader = f.workflow_key(child, &child_token, "workflow.read").await;
    let owner_uri = format!("{WORKFLOWS}/{}", owner_workflow["id"].as_str().unwrap());
    let child_uri = format!("{WORKFLOWS}/{}", child_workflow["id"].as_str().unwrap());
    f.read(&reader, &owner_uri).await.expect(404);
    assert_eq!(
        f.read(&reader, &child_uri).await.expect(200).body,
        child_workflow
    );
    let restricted = f.read(&reader, WORKFLOWS).await.expect(200).body;
    assert_eq!(restricted["items"], json!([child_workflow]));

    let page = f
        .read(&f.token, &format!("{WORKFLOWS}?limit=1"))
        .await
        .expect(200)
        .body;
    let cursor = page["next_cursor"].as_str().unwrap();
    let next_uri = format!("{WORKFLOWS}?limit=1&cursor={cursor}");
    f.read(&reader, &next_uri).await.expect(400);
    f.read(&f.token, &format!("{WORKFLOWS}?limit=2&cursor={cursor}"))
        .await
        .expect(400);
    let next = f.read(&f.token, &next_uri).await.expect(200).body;
    assert_ne!(page["items"][0]["id"], next["items"][0]["id"]);
    assert!(next["next_cursor"].is_null());
}

#[tokio::test]
async fn workflow_publication_rejects_invalid_and_skill_only_contracts() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let spec = f.spec("validated");
    let mut wrong_digest = spec.clone();
    wrong_digest["steps"][0]["contract"]["schema_digest"] =
        json!(format!("sha256:{}", "0".repeat(64)));
    f.publish(&f.token, &wrong_digest, "wrong-digest")
        .await
        .expect(409);

    let mut cycle = spec.clone();
    cycle["steps"][0]["depends_on"] = json!(["echo"]);
    f.publish(&f.token, &cycle, "cycle").await.expect(400);

    let publisher = f.workflow_key(f.owner, &f.token, "workflow.create").await;
    let first = f
        .publish(&publisher, &spec, "initial-publish")
        .await
        .expect(201);
    assert_eq!(first.body["version"], 1);

    let conn = f.db.connect().await.unwrap();
    conn.execute(
        "UPDATE installations SET manifest=jsonb_set(manifest,'{business_entry}',to_jsonb('skill_required'::text)) WHERE id=$1",
        &[&f.installation],
    ).await.unwrap();
    f.publish(&publisher, &spec, "skill-only").await.expect(403);
    assert_eq!(
        f.publish(&publisher, &spec, "initial-publish")
            .await
            .expect(201)
            .body,
        first.body
    );
    let count: i64 = conn
        .query_one("SELECT count(*) FROM workflows", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
}

#[tokio::test]
async fn fixed_workflow_provider_must_be_visible_without_a_live_instance() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let conn = f.db.connect().await.unwrap();
    let deployment = Uuid::new_v4();
    conn.execute(
        "INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at)
         SELECT $1,$2,id,jsonb_build_object('installation_id',id,'enabled',false,'limits',manifest->'minimum_resources'),'disabled',now(),now()
         FROM installations WHERE id=$3",
        &[&deployment, &f.owner, &f.installation],
    ).await.unwrap();

    let mut spec = f.spec("fixed provider");
    spec["steps"][0]["provider_deployment_id"] = json!(deployment);
    let publisher = f.workflow_key(f.owner, &f.token, "workflow.create").await;
    let invisible = f
        .publish(&publisher, &spec, "invisible-provider")
        .await
        .expect(404);
    assert_eq!(invisible.body["error"]["code"], "RESOURCE_NOT_FOUND");
    let published = f
        .publish(&f.token, &spec, "visible-provider")
        .await
        .expect(201);
    assert_eq!(published.body["spec"], spec);
    let instance_exists: bool = conn
        .query_one(
            "SELECT EXISTS(SELECT FROM instances WHERE deployment_id=$1)",
            &[&deployment],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!instance_exists);
}

#[tokio::test]
async fn workflow_skill_must_be_visible_and_within_its_timeout() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let skill = request(
        &f.router,
        Method::POST,
        "/api/platform/v1/skills",
        Some(&f.token),
        Some(&json!({
            "installation_id":f.installation,
            "definition":f.skill_definition,
            "enabled":true
        })),
        &[("idempotency-key", "register-skill")],
    )
    .await
    .expect(201)
    .body;
    let mut spec = f.spec("signed Skill");
    let step = spec["steps"][0].as_object_mut().unwrap();
    step.remove("contract");
    step.insert("skill_id".to_owned(), skill["id"].clone());

    let publisher = f.workflow_key(f.owner, &f.token, "workflow.create").await;
    f.publish(&publisher, &spec, "invisible-skill")
        .await
        .expect(404);
    let published = f
        .publish(&f.token, &spec, "visible-skill")
        .await
        .expect(201);
    assert_eq!(published.body["spec"], spec);

    spec["steps"][0]["timeout_ms"] = json!(10001);
    f.publish(&f.token, &spec, "skill-timeout")
        .await
        .expect(400);
}
