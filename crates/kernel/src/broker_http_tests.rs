//! Actual API + PostgreSQL + independent Python HTTPS component execution.
//! Installation/runtime metadata is a fixture: this is not signed OCI, host
//! admission, Controller process fencing, or production acceptance evidence.
use crate::{
    api::{self, App},
    backups::tests::Fixture,
    config::Config,
    contracts::{self, digest},
    runtime::Runtime,
    tls,
};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use futures_util::StreamExt;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use serde_json::{json, Value};
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

const CORE: &str = "kernel.example.org:8443";
const ECHO: &str = "/plugins/org.xelab.http-echo/echo";
const HOLD: &str = "/plugins/org.xelab.http-echo/hold";
const EVENTS: &str = "/plugins/org.xelab.http-echo/events";
const PAGE: &str = "/ui/org.xelab.http-echo/index.html";
static COMPONENT_PROCESS: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

#[path = "oauth_http_selector_tests.rs"]
mod selectors;

#[path = "broker_http_skill_stream_tests.rs"]
mod skill_streams;

#[path = "broker_http_task_tests.rs"]
mod task_engine;

async fn raw(
    router: &Router,
    method: &str,
    host: &str,
    path: &str,
    token: Option<&str>,
    bytes: Vec<u8>,
    headers: &[(&str, String)],
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let mut request = request.body(Body::from(bytes)).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
    ));
    router.clone().oneshot(request).await.unwrap()
}
use tower::ServiceExt;

async fn json_response(response: Response) -> (u16, Value) {
    let code = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 16777216).await.unwrap();
    (
        code,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("Non-JSON HTTP status {code}"))
        },
    )
}

#[allow(clippy::too_many_arguments)]
async fn management(
    router: &Router,
    operation: &str,
    params: &[(&str, String)],
    token: &str,
    body: Value,
    key: &str,
    revision: Option<i64>,
) -> (u16, Value) {
    let (mut path, method) = contracts::openapi()["paths"]
        .as_object()
        .unwrap()
        .iter()
        .find_map(|(path, methods)| {
            methods
                .as_object()
                .unwrap()
                .iter()
                .find(|(_, op)| op["operationId"] == operation)
                .map(|(method, _)| (path.clone(), method.to_ascii_uppercase()))
        })
        .unwrap();
    for (name, value) in params {
        path = path.replace(&format!("{{{name}}}"), value);
    }
    let mut headers = vec![("idempotency-key", key.to_owned())];
    if let Some(revision) = revision {
        headers.push(("if-match", format!("\"rev-{revision}\"")));
    }
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        headers.push(("content-type", "application/json".into()));
        serde_json::to_vec(&body).unwrap()
    };
    json_response(raw(router, &method, CORE, &path, Some(token), bytes, &headers).await).await
}

struct Component {
    _base: Fixture,
    _artifact: tempfile::TempDir,
    app: Arc<App>,
    router: Router,
    token: String,
    owner: Uuid,
    deployment: Uuid,
    installation: Uuid,
    manifest: Value,
    server: tokio::process::Child,
    heartbeat: tokio::task::JoinHandle<()>,
    _process_lock: tokio::sync::OwnedMutexGuard<()>,
}
impl Drop for Component {
    fn drop(&mut self) {
        self.heartbeat.abort();
        let _ = self.server.start_kill();
    }
}
impl Component {
    async fn new() -> Option<Self> {
        Self::with_exact_route_budget(false).await
    }
    async fn with_exact_route_budget(split: bool) -> Option<Self> {
        let process_lock = COMPONENT_PROCESS
            .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let base = Fixture::new().await?;
        let root = base.app.config.root();
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["broker-http-component-ca".into()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "broker-http-component-ca");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        fs::write(root.join("ca.crt"), ca.pem()).unwrap();
        fs::write(root.join("ca.key"), ca_key.serialize_pem()).unwrap();
        fs::set_permissions(root.join("ca.key"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut value = base.app.config.value.clone();
        value["security"]["workload_ca_cert_file"] = json!(root.join("ca.crt"));
        value["security"]["workload_ca_key_file"] = json!(root.join("ca.key"));
        value["runtime"]["network_cidr"] = json!("127.21.0.0/16");
        value["server"]["host_rpc_listen"] = json!("127.21.0.1:7443");
        value["ui_gateway"] = json!({"base_domain":"component-http.example.org","public_port":8443,"shell_origins":["https://desktop.example.org"]});
        let config = Config::from_value(value).unwrap();
        tls::issue(&config, None, &root.join("kernel-identity")).unwrap();
        let app = Arc::new(App {
            config: config.clone(),
            db: base.app.db.clone(),
            auth: base.app.auth.clone(),
            runtime: Runtime::new(config),
            leader: base.app.leader.clone(),
            ready: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
            blob_uploads: tokio::sync::Semaphore::new(4),
        });
        let c = app.db.connect().await.unwrap();
        let token = base.token.clone();
        let ctx = app
            .auth
            .authenticate(&c, &token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
            .await
            .unwrap();
        let owner = ctx.subject;
        let publisher = Uuid::new_v4();
        let (artifact, mut manifest, openapi) =
            crate::http_contracts::tests::fixture_manifest(publisher);
        manifest["concurrency"]["max_active_requests"] = json!(2);
        if split {
            let doc: Value = serde_json::from_slice(&openapi).unwrap();
            let template = manifest["routes"][0].clone();
            let mut routes = vec![manifest["routes"][1].clone()];
            for (path, operations) in doc["paths"].as_object().unwrap() {
                let mut route = template.clone();
                route["path_prefix"] = json!(path);
                route["methods"] = json!(operations
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(|method| method.to_ascii_uppercase())
                    .collect::<Vec<_>>());
                if path.ends_with("/echo") {
                    route["timeout_ms"] = json!(100);
                }
                routes.push(route);
            }
            manifest["routes"] = json!(routes);
        }
        fs::write(
            artifact.path().join("xelab/plugin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let installation = Uuid::new_v4();
        let deployment = Uuid::new_v4();
        let instance = Uuid::new_v4();
        c.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'HTTP transport component',$2,'fixture-only','trusted',now(),now())",&[&publisher,&publisher.to_string()]).await.unwrap();
        let manifest_raw = fs::read(artifact.path().join("xelab/plugin.json")).unwrap();
        c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,'1.0.0',$3,$4,$5,$6,'installed',now(),now())",&[&installation,&"org.xelab.http-echo",&publisher,&digest(b"component-metadata-image"),&digest(&manifest_raw),&manifest]).await.unwrap();
        crate::http_contracts::store(&c, installation, &manifest, Some(&openapi))
            .await
            .unwrap();
        let limits =
            json!({"cpu_millis":500,"memory_bytes":134217728,"ephemeral_bytes":1048576,"pids":64});
        let spec = json!({"installation_id":installation,"display_name":"component HTTP","enabled":false,"limits":limits,"config":{},"volume_ids":[],"replicas":1});
        c.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,$4,'disabled',now(),now())",&[&deployment,&owner,&installation,&spec]).await.unwrap();
        let router = api::router(app.clone());
        let approved = management(
            &router,
            "approvePlugin",
            &[("deployment_id", deployment.to_string())],
            &token,
            json!({"rules":[],"egress":[]}),
            "component-approve",
            Some(1),
        )
        .await;
        assert_eq!(approved.0, 200, "{}", approved.1);
        // This is the explicit runtime observation fixture. No OCI process is
        // created or presented as verified; live HTTP still uses actual mTLS.
        c.execute("UPDATE deployments SET spec=jsonb_set(spec,'{enabled}','true'),phase='ready',observed_generation=1 WHERE id=$1",&[&deployment]).await.unwrap();
        c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,last_heartbeat_at,created_at,updated_at) VALUES($1,$2,1,0,'ready','alive',$3,now(),now(),now())",&[&instance,&deployment,&limits]).await.unwrap();
        let runtime = root.join("runtime").join(instance.to_string());
        let identity = runtime.join("identity");
        fs::create_dir_all(&identity).unwrap();
        fs::write(
            runtime.join("network.json"),
            serde_json::to_vec(&json!({"instance":instance,"peer":"127.21.0.2"})).unwrap(),
        )
        .unwrap();
        let key = KeyPair::generate().unwrap();
        let name = format!("i-{instance}-g-1.xelab.local");
        let mut params = CertificateParams::new(vec![name.clone()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names.push(SanType::URI(
            format!("spiffe://xelab.local/instance/{instance}/generation/1")
                .try_into()
                .unwrap(),
        ));
        let certificate = params.signed_by(&key, &ca, &ca_key).unwrap();
        fs::write(identity.join("tls.crt"), certificate.pem()).unwrap();
        fs::write(identity.join("tls.key"), key.serialize_pem()).unwrap();
        fs::write(identity.join("ca.crt"), ca.pem()).unwrap();
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/http");
        let script = r#"import sys
sys.path.insert(0,sys.argv[1])
from http_server import State,KernelHTTPServer,Handler,encoded
original=Handler.reply
def reply(self,status,body=b'',content_type='application/json',extra=()):
 if body==encoded({'message':'fault:bad-output'}):body=encoded({'message':42})
 return original(self,status,body,content_type,extra)
Handler.reply=reply
original_events=Handler.events
original_encoded=encoded
def encoded(value):
 if isinstance(value,dict) and value.get('kind')=='item' and value.get('payload',{}).get('message')=='fault:skill-item':
  value={**value,'payload':{'message':42,'index':0}}
 if isinstance(value,dict) and value.get('kind')=='completed' and value.get('payload',{}).get('output',{}).get('message')=='fault:skill-output':
  value={**value,'payload':{**value['payload'],'output':{'message':42}}}
 return original_encoded(value)
import http_server
http_server.encoded=encoded
def events(self,value,call_id,deadline):
 if value['message'] not in ('fault:empty-sse','fault:first-item'):
  return original_events(self,value,call_id,deadline)
 self.send_response(200)
 self.send_header('Content-Type','text/event-stream')
 self.send_header('Cache-Control','no-store')
 self.send_header('Transfer-Encoding','chunked')
 self.send_header('Connection','close')
 self.end_headers()
 self.close_connection=True
 if value['message']=='fault:first-item':
  event={'call_id':call_id,'sequence':1,'kind':'item','payload':{'message':value['message'],'index':0},'terminal':False}
  raw=b'event: item\nid: '+call_id.encode()+b':1\ndata: '+encoded(event)+b'\n\n'
  self.wfile.write(f'{len(raw):x}\r\n'.encode()+raw+b'\r\n')
 self.wfile.write(b'0\r\n\r\n')
 self.wfile.flush()
Handler.events=events
s=State();s.initialize()
h=KernelHTTPServer(('127.21.0.2',8080),s,sys.argv[2])
print('READY',flush=True)
h.serve_forever()
"#;
        let mut server = tokio::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(examples)
            .arg(&identity)
            .env("XELAB_INSTANCE_ID", instance.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(server.stdout.take().unwrap()).lines();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                .await
                .unwrap()
                .unwrap()
                .as_deref(),
            Some("READY")
        );
        let db = app.db.clone();
        let heartbeat = tokio::spawn(async move {
            loop {
                let c = db.connect().await.unwrap();
                c.execute(
                    "UPDATE instances SET last_heartbeat_at=now() WHERE id=$1",
                    &[&instance],
                )
                .await
                .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        Some(Self {
            _base: base,
            _artifact: artifact,
            app,
            router,
            token,
            owner,
            deployment,
            installation,
            manifest,
            server,
            heartbeat,
            _process_lock: process_lock,
        })
    }
    async fn stop(&mut self) {
        self.heartbeat.abort();
        self.server.kill().await.unwrap();
        let status = self.server.wait().await.unwrap();
        assert!(
            !status.success(),
            "The explicitly stopped component unexpectedly exited normally"
        );
    }
    fn host(&self) -> String {
        format!(
            "d-{}.component-http.example.org:8443",
            self.deployment.simple()
        )
    }
    async fn direct(&self, path: &str, input: Value, key: &str) -> (u16, Value) {
        json_response(
            raw(
                &self.router,
                "POST",
                &self.host(),
                path,
                Some(&self.token),
                serde_json::to_vec(&input).unwrap(),
                &[
                    ("content-type", "application/json".into()),
                    ("idempotency-key", key.into()),
                ],
            )
            .await,
        )
        .await
    }
    async fn active(&self) -> i64 {
        self.app
            .db
            .connect()
            .await
            .unwrap()
            .query_one(
                "SELECT count(*) FROM reservations WHERE kind='call' AND status<>'released'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
}

async fn abandoned_before_admission(f: &Component) {
    let mut holder = f.app.db.connect().await.unwrap();
    let lock = holder.transaction().await.unwrap();
    crate::db::call_lock(&lock).await.unwrap();
    let router = f.router.clone();
    let token = f.token.clone();
    let host = f.host();
    let handling = tokio::spawn(async move {
        raw(
            &router,
            "POST",
            &host,
            ECHO,
            Some(&token),
            br#"{"message":"never admitted"}"#.to_vec(),
            &[
                ("content-type", "application/json".into()),
                ("idempotency-key", "abandoned-HTTP-admission".into()),
            ],
        )
        .await
    });
    let observer = f.app.db.connect().await.unwrap();
    let waiting:i32=tokio::time::timeout(Duration::from_secs(3),async {loop{if let Some(row)=observer.query_opt("SELECT pid FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted ORDER BY pid LIMIT 1",&[]).await.unwrap(){return row.get(0);}tokio::time::sleep(Duration::from_millis(10)).await;}}).await.expect("HTTP actor did not reach held admission lock");
    assert!(!handling.is_finished());
    handling.abort();
    assert!(handling.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let exists: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                    &[&waiting],
                )
                .await
                .unwrap()
                .get(0);
            if !exists {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Abandoned HTTP admission backend survived until lock release");
    lock.rollback().await.unwrap();
    let finished = holder.transaction().await.unwrap();
    crate::db::call_lock(&finished).await.unwrap();
    assert_eq!(
        finished
            .query_one("SELECT count(*) FROM calls", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        finished
            .query_one("SELECT count(*) FROM reservations WHERE kind='call'", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let quota = finished
        .query_one(
            "SELECT concurrent_calls_used,daily_calls_used FROM quotas WHERE account_id=$1",
            &[&f.owner],
        )
        .await
        .unwrap();
    assert_eq!(quota.get::<_, i64>(0), 0);
    assert_eq!(quota.get::<_, i64>(1), 0);
    finished.rollback().await.unwrap();
}

async fn owner_scoped_deployments_cannot_reuse_frozen_authority(f: &Component) {
    let c = f.app.db.connect().await.unwrap();
    let child = management(
        &f.router,
        "createChildAccount",
        &[("account_id", f.owner.to_string())],
        &f.token,
        json!({"display_name":"HTTP owner B","inheritance":{"mode":"all_snapshot"}}),
        "component-owner-B",
        None,
    )
    .await;
    assert_eq!(child.0, 201, "{}", child.1);
    let other_owner = contracts::id(&child.1["account"], "id").unwrap();
    let activated=json_response(raw(&f.router,"POST",CORE,"/api/platform/v1/auth/activate",None,serde_json::to_vec(&json!({"activation_token":child.1["activation_token"],"password":"other HTTP owner password"})).unwrap(),&[("content-type","application/json".into())]).await).await;
    assert_eq!(activated.0, 200, "{}", activated.1);
    let other_deployment = Uuid::new_v4();
    let other_instance = Uuid::new_v4();
    let spec: Value = c
        .query_one("SELECT spec FROM deployments WHERE id=$1", &[&f.deployment])
        .await
        .unwrap()
        .get(0);
    let mut disabled = spec.clone();
    disabled["enabled"] = json!(false);
    c.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,$4,'disabled',now(),now())",&[&other_deployment,&other_owner,&f.installation,&disabled]).await.unwrap();
    let approved = management(
        &f.router,
        "approvePlugin",
        &[("deployment_id", other_deployment.to_string())],
        &f.token,
        json!({"rules":[],"egress":[]}),
        "component-approve-B",
        Some(1),
    )
    .await;
    assert_eq!(approved.0, 200, "{}", approved.1);
    c.execute("UPDATE deployments SET spec=jsonb_set(spec,'{enabled}','true'),phase='ready',observed_generation=1 WHERE id=$1",&[&other_deployment]).await.unwrap();
    c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,last_heartbeat_at,created_at,updated_at) VALUES($1,$2,1,0,'ready','alive',$3,now(),now(),now())",&[&other_instance,&other_deployment,&spec["limits"]]).await.unwrap();
    let network = f
        .app
        .config
        .root()
        .join("runtime")
        .join(other_instance.to_string());
    fs::create_dir_all(&network).unwrap();
    fs::write(
        network.join("network.json"),
        serde_json::to_vec(&json!({"instance":other_instance,"peer":"127.21.0.2"})).unwrap(),
    )
    .unwrap();
    let key=management(&f.router,"createApiKey",&[("account_id",f.owner.to_string())],&f.token,json!({"name":"only deployment owner A","inheritance":{"mode":"selected","rules":[{"action":"plugin.http.invoke","resource":{"kind":"plugin","match":"owned_by","owner_id":f.owner}}]},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),"component-owner-scope-key",None).await;
    assert_eq!(key.0, 201, "{}", key.1);
    let token = key.1["secret"].as_str().unwrap();
    let headers = [
        ("content-type", "application/json".into()),
        ("idempotency-key", "owner-A-call".into()),
    ];
    let owned = json_response(
        raw(
            &f.router,
            "POST",
            &f.host(),
            ECHO,
            Some(token),
            br#"{"message":"owner A only"}"#.to_vec(),
            &headers,
        )
        .await,
    )
    .await;
    assert_eq!(
        owned.0, 200,
        "Owner-scoped fixed deployment A rejected: {}",
        owned.1
    );
    let other_host = format!(
        "d-{}.component-http.example.org:8443",
        other_deployment.simple()
    );
    let denied = json_response(
        raw(
            &f.router,
            "POST",
            &other_host,
            ECHO,
            Some(token),
            br#"{"message":"owner A only"}"#.to_vec(),
            &[
                ("content-type", "application/json".into()),
                ("idempotency-key", "owner-B-forged-context".into()),
                ("x-xelab-subject", f.owner.to_string()),
                ("x-xelab-deployment-id", f.deployment.to_string()),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(
        denied.0, 403,
        "Deployment B reused owner A context: {}",
        denied.1
    );
    let credential = contracts::id(&key.1["credential"], "id").unwrap();
    let frozen:Value=c.query_one("SELECT x.source_paths FROM host_rpc_contexts x JOIN calls c ON c.id=x.call_id WHERE c.credential_id=$1 ORDER BY c.created_at DESC LIMIT 1",&[&credential]).await.unwrap().get(0);
    let frozen: Vec<crate::policy::Path> = serde_json::from_value(frozen).unwrap();
    let target = crate::auth::Resource::new("plugin", "org.xelab.http-echo", Some(other_owner));
    let revalidated = crate::policy::Policy::new(&c, "127.0.0.1".parse().unwrap())
        .with_resource_owner(&target)
        .revalidate(&frozen, credential)
        .await;
    if let Ok(paths) = revalidated {
        assert!(
            !crate::auth::rules_allow(
                &crate::policy::rules(&paths),
                "plugin.http.invoke",
                &target,
                "127.0.0.1".parse().unwrap()
            ),
            "Copied frozen paths amplified authority to another owner"
        );
    }
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM calls WHERE http_binding->>'deployment_id'=$1",
            &[&other_deployment.to_string()]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(f.active().await, 0);
}

async fn missing_no_blob_context_cannot_be_replaced_on_replay(f: &Component) {
    assert!(f.manifest["requested_rules"].as_array().unwrap().is_empty());
    let message = format!("minimal-context-{}", Uuid::new_v4());
    let input = json!({"message":message});
    assert_eq!(
        f.direct(ECHO, input.clone(), "component-missing-context")
            .await,
        (200, input.clone())
    );
    let c = f.app.db.connect().await.unwrap();
    let request_digest = digest(&serde_json::to_vec(&input).unwrap());
    let row=c.query_one("SELECT c.id,x.read_blob_ids FROM calls c JOIN host_rpc_contexts x ON x.call_id=c.id WHERE c.input_digest=$1 ORDER BY c.created_at DESC LIMIT 1",&[&request_digest]).await.unwrap();
    let call: Uuid = row.get(0);
    assert_eq!(row.get::<_, Value>(1), json!([]));
    let calls: i64 = c
        .query_one("SELECT count(*) FROM calls", &[])
        .await
        .unwrap()
        .get(0);
    let daily: i64 = c
        .query_one(
            "SELECT daily_calls_used FROM quotas WHERE account_id=$1",
            &[&f.owner],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        c.execute("DELETE FROM host_rpc_contexts WHERE call_id=$1", &[&call])
            .await
            .unwrap(),
        1
    );
    let replay = f.direct(ECHO, input, "component-missing-context").await;
    assert_eq!(
        replay.0, 403,
        "Replay manufactured replacement authority without original frozen context: {}",
        replay.1
    );
    assert_eq!(
        c.query_one("SELECT count(*) FROM calls", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        calls
    );
    assert_eq!(
        c.query_one(
            "SELECT daily_calls_used FROM quotas WHERE account_id=$1",
            &[&f.owner]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        daily
    );
}

async fn integral_float_call_cap_is_enforced_and_cannot_be_rotated_away(f: &Component) {
    // Preserve the JSON number representation on the actual API wire. JSON
    // Schema integer includes 1.0; serde_json::Value::as_i64 does not.
    let mut request: Value = serde_json::from_str(
        r#"{"name":"one integral-float HTTP call","inheritance":{"mode":"selected","rules":[{"action":"plugin.http.invoke","resource":{"kind":"plugin","match":"ids","ids":["org.xelab.http-echo"]}}]},"conditions":{"max_calls":1.0}}"#,
    )
    .unwrap();
    assert!(request["conditions"]["max_calls"].is_f64());
    let expiry = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis() + 86_400_000,
    )
    .unwrap();
    request["conditions"]["expires_at"] = json!(expiry);
    let created = management(
        &f.router,
        "createApiKey",
        &[("account_id", f.owner.to_string())],
        &f.token,
        request.clone(),
        "component-integral-float-key",
        None,
    )
    .await;
    assert_eq!(created.0, 201, "{}", created.1);
    let credential = contracts::id(&created.1["credential"], "id").unwrap();
    let revision = created.1["credential"]["revision"].as_i64().unwrap();
    let token = created.1["secret"].as_str().unwrap();
    // Use the kernel-returned timestamp/conditions for exact non-action bounds.
    request["conditions"] = created.1["credential"]["conditions"].clone();
    let params = [("credential_id", credential.to_string())];
    for (suffix, cap) in [
        ("remove", None),
        (
            "increase",
            Some(serde_json::from_str::<Value>("2.0").unwrap()),
        ),
    ] {
        let mut rotation = request.clone();
        rotation["conditions"]
            .as_object_mut()
            .unwrap()
            .remove("max_calls");
        if let Some(cap) = cap {
            rotation["conditions"]["max_calls"] = cap;
        }
        let denied = management(
            &f.router,
            "rotateApiKey",
            &params,
            &f.token,
            rotation,
            &format!("component-integral-float-{suffix}-rotation"),
            Some(revision),
        )
        .await;
        assert_eq!(denied.0, 403, "A rotation widened max_calls: {}", denied.1);
        assert_eq!(denied.1["error"]["code"], "PERMISSION_DENIED");
    }
    let c = f.app.db.connect().await.unwrap();
    let persisted: Value = c
        .query_one(
            "SELECT conditions FROM credentials WHERE id=$1",
            &[&credential],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        persisted["max_calls"].as_i64().is_none(),
        "The regression lost its integral-float JSONB representation"
    );
    assert_eq!(persisted["max_calls"].as_f64(), Some(1.0));
    let before = c.query_one("SELECT (SELECT count(*) FROM calls),(SELECT count(*) FROM call_credential_charges),daily_calls_used FROM quotas WHERE account_id=$1", &[&f.owner]).await.unwrap();
    let calls_before: i64 = before.get(0);
    let charges_before: i64 = before.get(1);
    let daily_before: i64 = before.get(2);
    let first = json_response(
        raw(
            &f.router,
            "POST",
            &f.host(),
            ECHO,
            Some(token),
            br#"{"message":"one permitted real HTTP call"}"#.to_vec(),
            &[
                ("content-type", "application/json".into()),
                ("idempotency-key", "component-integral-float-first".into()),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(
        first,
        (200, json!({"message":"one permitted real HTTP call"}))
    );
    assert_eq!(f.active().await, 0);
    let exhausted = json_response(
        raw(
            &f.router,
            "POST",
            &f.host(),
            ECHO,
            Some(token),
            br#"{"message":"a distinct call must be refused"}"#.to_vec(),
            &[
                ("content-type", "application/json".into()),
                ("idempotency-key", "component-integral-float-second".into()),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(exhausted.0, 409, "{}", exhausted.1);
    assert_eq!(exhausted.1["error"]["code"], "QUOTA_EXCEEDED");
    request["conditions"]["max_calls"] = serde_json::from_str("1.0").unwrap();
    let spent_rotation = management(
        &f.router,
        "rotateApiKey",
        &params,
        &f.token,
        request,
        "component-integral-float-spent-rotation",
        Some(revision),
    )
    .await;
    assert_eq!(
        spent_rotation.0, 403,
        "A spent cap was reset by rotation: {}",
        spent_rotation.1
    );
    assert_eq!(spent_rotation.1["error"]["code"], "PERMISSION_DENIED");
    let after = c.query_one("SELECT (SELECT count(*) FROM calls),(SELECT count(*) FROM call_credential_charges),concurrent_calls_used,daily_calls_used FROM quotas WHERE account_id=$1", &[&f.owner]).await.unwrap();
    assert_eq!(after.get::<_, i64>(0), calls_before + 1);
    assert_eq!(after.get::<_, i64>(1), charges_before + 1);
    assert_eq!(after.get::<_, i64>(2), 0);
    assert_eq!(after.get::<_, i64>(3), daily_before + 1);
    let original = c
        .query_one(
            "SELECT status,revision FROM credentials WHERE id=$1",
            &[&credential],
        )
        .await
        .unwrap();
    assert_eq!(original.get::<_, String>(0), "active");
    assert_eq!(original.get::<_, i64>(1), revision);
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM calls WHERE credential_id=$1 AND state='succeeded'",
            &[&credential]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM call_credential_charges WHERE credential_id=$1",
            &[&credential]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(f.active().await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_gateway_postgres_and_independent_mtls_plugin_close_the_http_component_loop() {
    let Some(mut f) = Component::new().await else {
        return;
    };
    abandoned_before_admission(&f).await;
    assert_eq!(
        f.direct(ECHO, json!({"message":"kernel HTTP"}), "component-direct")
            .await,
        (200, json!({"message":"kernel HTTP"}))
    );
    assert_eq!(f.active().await, 0);
    let wrong = raw(
        &f.router,
        "POST",
        &f.host(),
        ECHO,
        Some(&f.token),
        br#"{"message":42}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "invalid-input".into()),
        ],
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert_eq!(f.active().await, 0);
    let page = raw(&f.router, "GET", &f.host(), PAGE, None, Vec::new(), &[]).await;
    if page.status() != StatusCode::OK {
        let (status, error) = json_response(page).await;
        panic!("Allocated static page failed: {status} {error}");
    }
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("worker-src 'none'"));
    assert!(!to_bytes(page.into_body(), 16777216)
        .await
        .unwrap()
        .is_empty());
    assert!(raw(
        &f.router,
        "GET",
        &f.host(),
        "/api/platform/v1/node",
        Some(&f.token),
        Vec::new(),
        &[]
    )
    .await
    .status()
    .is_client_error());
    let registered = management(
        &f.router,
        "registerSkill",
        &[],
        &f.token,
        json!({"installation_id":f.installation,"definition":f.manifest["skills"][0]}),
        "component-register",
        None,
    )
    .await;
    assert_eq!(registered.0, 201, "{}", registered.1);
    let skill = registered.1["id"].as_str().unwrap().to_owned();
    let params = [("skill_id", skill.clone())];
    assert_eq!(
        management(
            &f.router,
            "setSkillEnabled",
            &params,
            &f.token,
            json!({"enabled":true}),
            "component-enable",
            Some(1)
        )
        .await
        .0,
        200
    );
    selectors::fixed_http_skill_deployment_selector(&f, &skill).await;
    let input =
        json!({"input":{"message":"real HTTP Skill"},"timeout_ms":5000,"idempotency_key":"业务🔑"});
    let skill_rule =
        json!({"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[skill]}});
    let plugin_rule = json!({"action":"plugin.http.invoke","resource":{"kind":"plugin","match":"ids","ids":["org.xelab.http-echo"]}});
    for (index, rules) in [json!([skill_rule]), json!([plugin_rule])]
        .into_iter()
        .enumerate()
    {
        let key=management(&f.router,"createApiKey",&[("account_id",f.owner.to_string())],&f.token,json!({"name":"one HTTP permission layer","inheritance":{"mode":"selected","rules":rules},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),&format!("component-one-layer-{index}"),None).await;
        assert_eq!(key.0, 201, "{}", key.1);
        let refused = management(
            &f.router,
            "invokeSkill",
            &params,
            key.1["secret"].as_str().unwrap(),
            input.clone(),
            &format!("component-one-layer-call-{index}"),
            None,
        )
        .await;
        assert_eq!(
            refused.0, 403,
            "One HTTP Skill permission layer reached the plugin: {}",
            refused.1
        );
        assert_eq!(f.active().await, 0);
    }
    let called = management(
        &f.router,
        "invokeSkill",
        &params,
        &f.token,
        input.clone(),
        "component-skill-call",
        None,
    )
    .await;
    assert_eq!(called.0, 200, "{}", called.1);
    assert_eq!(
        called.1["call"]["output"],
        json!({"message":"real HTTP Skill"})
    );
    assert_eq!(
        management(
            &f.router,
            "invokeSkill",
            &params,
            &f.token,
            input,
            "component-skill-call",
            None
        )
        .await
        .1,
        called.1
    );
    let events = raw(
        &f.router,
        "POST",
        &f.host(),
        EVENTS,
        Some(&f.token),
        br#"{"message":"real stream","items":2,"interval_ms":10}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "component-events".into()),
        ],
    )
    .await;
    assert_eq!(events.status(), StatusCode::OK);
    let events = String::from_utf8(
        to_bytes(events.into_body(), 4194304)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        events.contains("event: completed"),
        "HTTP SSE lacked completed terminal: {events}"
    );
    assert_eq!(events.matches("event: item").count(), 2);
    assert_eq!(f.active().await, 0);
    // The core pool must reject before dispatch: a backend-only refusal is429,
    // whereas Broker admission returns RESOURCE_EXHAUSTED503.
    let mut held = Vec::new();
    for index in 0..2 {
        let router = f.router.clone();
        let host = f.host();
        let token = f.token.clone();
        held.push(tokio::spawn(async move {
            let response = json_response(
                raw(
                    &router,
                    "POST",
                    &host,
                    HOLD,
                    Some(&token),
                    br#"{"message":"held","delay_ms":2000}"#.to_vec(),
                    &[
                        ("content-type", "application/json".into()),
                        ("idempotency-key", format!("component-held-{index}")),
                    ],
                )
                .await,
            )
            .await;
            if response.0 != 200 {
                eprintln!(
                    "held HTTP request {index} failed: status={} error={}",
                    response.0, response.1["error"]
                );
            }
            response
        }));
    }
    // This metadata component declares two physical slots; the independent
    // upstream has four. A third503 therefore proves core shared admission.
    // The privileged OCI suite separately exercises the signed mixed4-slot image.
    let observer = f.app.db.connect().await.unwrap();
    let observation =
        tokio::time::timeout(Duration::from_secs(7), async {
            loop {
                let active: i64 = observer.query_one(
                "SELECT count(*) FROM reservations WHERE kind='call' AND status<>'released'", &[],
            ).await.unwrap().get(0);
                if active == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
    if observation.is_err() {
        let active = f.active().await;
        for (index, task) in held.into_iter().enumerate() {
            if task.is_finished() {
                match task.await {
                    Ok((status,body))=>eprintln!("held HTTP request {index} finished before observation: status={status} error={}",body["error"]),
                    Err(error)=>eprintln!("held HTTP request {index} task failed: {error}"),
                }
            } else {
                eprintln!("held HTTP request {index} remains pending");
                task.abort();
            }
        }
        let c = f.app.db.connect().await.unwrap();
        for row in c.query("SELECT coalesce(http_binding->>'operation_id','rpc'),state,count(*) FROM calls GROUP BY 1,2 ORDER BY 1,2",&[]).await.unwrap() {
            eprintln!("durable calls: operation={} state={} count={}",row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,i64>(2));
        }
        for row in c.query("SELECT state,coalesce(wait_event_type,'CPU'),coalesce(wait_event,''),count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() GROUP BY 1,2,3 ORDER BY 1,2,3",&[]).await.unwrap() {
            eprintln!("PostgreSQL activity: state={} wait_type={} wait_event={} count={}",row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,String>(2),row.get::<_,i64>(3));
        }
        panic!("Two real HTTP requests were not concurrently admitted within the signed route deadline; active={active}");
    }
    assert_eq!(f.active().await, 2);
    assert_eq!(observer.query_one(
        "SELECT count(*) FROM calls WHERE state='running' AND http_binding->>'operation_id'='holdMessage'", &[],
    ).await.unwrap().get::<_, i64>(0),2);
    let charged_before: i64 = observer
        .query_one(
            "SELECT daily_calls_used FROM quotas WHERE account_id=$1",
            &[&f.owner],
        )
        .await
        .unwrap()
        .get(0);
    let calls_before: i64 = observer
        .query_one("SELECT count(*) FROM calls", &[])
        .await
        .unwrap()
        .get(0);
    let exhausted = f
        .direct(ECHO, json!({"message":"third"}), "component-third")
        .await;
    assert_eq!(exhausted.0, 503, "{}", exhausted.1);
    assert_eq!(exhausted.1["error"]["code"], "RESOURCE_EXHAUSTED");
    assert_eq!(
        observer
            .query_one("SELECT count(*) FROM calls", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        calls_before
    );
    assert_eq!(
        observer
            .query_one(
                "SELECT daily_calls_used FROM quotas WHERE account_id=$1",
                &[&f.owner]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        charged_before
    );
    for task in held {
        assert_eq!(task.await.unwrap().0, 200);
    }
    assert_eq!(f.active().await, 0);
    owner_scoped_deployments_cannot_reuse_frozen_authority(&f).await;
    missing_no_blob_context_cannot_be_replaced_on_replay(&f).await;
    integral_float_call_cap_is_enforced_and_cannot_be_rotated_away(&f).await;
    // Fault injection is in this independent server process only. The core must
    // validate actual mTLS response bytes against the signed output schema.
    let bad = f
        .direct(
            ECHO,
            json!({"message":"fault:bad-output"}),
            "component-output-fault",
        )
        .await;
    assert!(bad.0 >= 400, "Invalid provider output reached the caller");
    assert_eq!(
        f.active().await,
        1,
        "An unknown dispatched outcome released physical capacity without fencing"
    );
    let key=management(&f.router,"createApiKey",&[("account_id",f.owner.to_string())],&f.token,json!({"name":"live HTTP source","inheritance":{"mode":"selected","rules":[{"action":"plugin.http.invoke","resource":{"kind":"plugin","match":"ids","ids":["org.xelab.http-echo"]}}]},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),"component-source-key",None).await;
    assert_eq!(key.0, 201, "{}", key.1);
    let response = raw(
        &f.router,
        "POST",
        &f.host(),
        EVENTS,
        Some(key.1["secret"].as_str().unwrap()),
        br#"{"message":"revoked stream","items":64,"interval_ms":100}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "component-revoked-events".into()),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    assert!(stream.next().await.unwrap().is_ok());
    let revoked = management(
        &f.router,
        "revokeApiKey",
        &[(
            "credential_id",
            key.1["credential"]["id"].as_str().unwrap().into(),
        )],
        &f.token,
        Value::Null,
        "component-revoke",
        key.1["credential"]["revision"].as_i64(),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let tail = tokio::time::timeout(Duration::from_secs(5), async {
        let mut output = String::new();
        while let Some(frame) = stream.next().await {
            output.push_str(std::str::from_utf8(&frame.unwrap()).unwrap());
        }
        output
    })
    .await
    .unwrap();
    assert!(!tail.contains("event: completed"));
    let frames: Vec<Value> = tail
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    assert_eq!(
        frames.len(),
        1,
        "Revoked HTTP stream delivered queued data: {tail}"
    );
    assert_eq!(frames[0]["kind"], "failed", "{tail}");
    assert_eq!(frames[0]["sequence"], 2, "{tail}");
    assert_eq!(frames[0]["payload"]["code"], "INVALID_CREDENTIAL", "{tail}");
    // The OCI suite proves the subsequent Controller fence. This component has
    // no runtime and deliberately does not clear those durable reservations.
    assert!(f.active().await >= 1);
    f.app.shutdown.store(true, Ordering::SeqCst);
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_mtls_sse_without_an_accepted_first_frame_returns_an_http_error() {
    let Some(mut f) = Component::new().await else {
        return;
    };
    for (index, message) in ["fault:empty-sse", "fault:first-item"]
        .into_iter()
        .enumerate()
    {
        let response = raw(
            &f.router,
            "POST",
            &f.host(),
            EVENTS,
            Some(&f.token),
            serde_json::to_vec(&json!({"message":message,"items":1,"interval_ms":0})).unwrap(),
            &[
                ("content-type", "application/json".into()),
                ("idempotency-key", format!("component-first-frame-{index}")),
            ],
        )
        .await;
        assert!(
            response.status().is_client_error() || response.status().is_server_error(),
            "An invalid first SSE frame committed success: {}",
            response.status()
        );
        assert!(!response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream")));
        let bytes = to_bytes(response.into_body(), 1048576).await.unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains("event: failed"),
            "An invalid first frame fabricated an SSE failure: {text}"
        );
        assert!(
            !text.contains("\"sequence\":1"),
            "An invalid first frame fabricated a sequence: {text}"
        );
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            body["error"]["code"].is_string(),
            "Expected a normal HTTP error: {body}"
        );
        assert_eq!(
            f.active().await,
            index as i64 + 1,
            "Unknown dispatched SSE work released physical capacity without fencing"
        );
    }
    let c = f.app.db.connect().await.unwrap();
    assert_eq!(
        c.query_one("SELECT count(*) FROM calls WHERE state='unknown'", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        c.query_one("SELECT count(*) FROM call_credential_charges", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    let quota = c
        .query_one(
            "SELECT concurrent_calls_used,daily_calls_used FROM quotas WHERE account_id=$1",
            &[&f.owner],
        )
        .await
        .unwrap();
    assert_eq!(quota.get::<_, i64>(0), 2);
    assert_eq!(quota.get::<_, i64>(1), 2);
    // Explicitly reap this independent TLS process before the serial guard is
    // released. Durable unknown reservations are left intact for real fencing.
    f.app.shutdown.store(true, Ordering::SeqCst);
    f.stop().await;
}
