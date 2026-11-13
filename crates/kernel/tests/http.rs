//! Signed HTTP-only and mixed HTTP/RPC plugins on the disposable OCI CI host.
//! This component sweep does not certify production capacity or AWS recovery.
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use futures_util::{Stream, StreamExt};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use serde_json::{json, Value};
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;
use xelab_kernel::{
    admission,
    api::{router, App},
    artifact,
    auth::{self, Auth},
    config::Config,
    contracts, controller,
    db::Db,
    runtime::Runtime,
    tls,
};

#[path = "support/oci_task.rs"]
mod oci_task;
#[path = "http_skill_profiles/mod.rs"]
mod skill_profiles;

const CORE_HOST: &str = "kernel.example.org:8443";
const ECHO: &str = "/plugins/org.xelab.http-echo/echo";
const HOLD: &str = "/plugins/org.xelab.http-echo/hold";
const EVENTS: &str = "/plugins/org.xelab.http-echo/events";
const PAGE: &str = "/ui/org.xelab.http-echo/index.html";

async fn request(
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

async fn json_response(response: Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 16777216).await.unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                panic!(
                    "Non-JSON status {status}: {}",
                    String::from_utf8_lossy(&bytes)
                )
            })
        },
    )
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
                .find(|(_, spec)| spec["operationId"] == operation)
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
    json_response(request(router, &method, CORE_HOST, &path, token, bytes, &headers).await).await
}

async fn operation(router: &Router, id: &str, token: &str) -> Value {
    for _ in 0..160 {
        let response = api(
            router,
            "getOperation",
            &[("operation_id", id.into())],
            Some(token),
            Value::Null,
            "poll",
            None,
        )
        .await;
        assert_eq!(response.0, 200, "{}", response.1);
        if response.1["state"] == "succeeded" {
            return response.1["result"].clone();
        }
        assert_ne!(response.1["state"], "failed", "{}", response.1);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("Operation {id} did not converge");
}

async fn enabled(router: &Router, deployment: &str, token: &str, value: bool, key: &str) {
    let params = [("deployment_id", deployment.into())];
    for _ in 0..12 {
        let current = api(
            router,
            "getDeployment",
            &params,
            Some(token),
            Value::Null,
            "read-intent",
            None,
        )
        .await;
        assert_eq!(current.0, 200, "{}", current.1);
        let changed = api(
            router,
            "setDeploymentEnabled",
            &params,
            Some(token),
            json!({"enabled":value}),
            key,
            current.1["revision"].as_i64(),
        )
        .await;
        if changed.0 == 412 {
            continue;
        }
        assert_eq!(changed.0, 202, "{}", changed.1);
        operation(router, changed.1["id"].as_str().unwrap(), token).await;
        return;
    }
    panic!("Deployment observations did not settle");
}

async fn install(
    router: &Router,
    token: &str,
    signing: &SigningKey,
    raw_path: &str,
    image_var: &str,
    key: &str,
    config: Value,
) -> (Value, Value, String) {
    let raw = fs::read(raw_path).unwrap();
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    let image = std::env::var(image_var).unwrap();
    let envelope =
        artifact::signature_envelope(&manifest, artifact::image_ref(&image).unwrap(), &raw)
            .unwrap();
    let installed=api(router,"installPlugin",&[],Some(token),json!({"publisher_id":manifest["publisher_id"],"image":image,"signature":STANDARD.encode(signing.sign(envelope.as_bytes()).to_bytes())}),&format!("{key}-install"),None).await;
    assert_eq!(installed.0, 202, "{}", installed.1);
    let installed = operation(router, installed.1["id"].as_str().unwrap(), token).await;
    let created=api(router,"createDeployment",&[],Some(token),json!({"installation_id":installed["installation_id"],"display_name":key,"enabled":false,"limits":{"cpu_millis":500,"memory_bytes":134217728,"ephemeral_bytes":1048576,"pids":64},"config":config,"volume_ids":[]}),&format!("{key}-deploy"),None).await;
    assert_eq!(created.0, 202, "{}", created.1);
    let deployment = operation(router, created.1["id"].as_str().unwrap(), token).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let approved = api(
        router,
        "approvePlugin",
        &[("deployment_id", deployment.clone())],
        Some(token),
        json!({"rules":[],"egress":[]}),
        &format!("{key}-approve"),
        Some(1),
    )
    .await;
    assert_eq!(approved.0, 200, "{}", approved.1);
    enabled(router, &deployment, token, true, &format!("{key}-enable")).await;
    (manifest, installed, deployment)
}

fn plugin_host(deployment: &str) -> String {
    format!("d-{}.http-ui.example.org:8443", deployment.replace('-', ""))
}

async fn direct(
    router: &Router,
    host: &str,
    token: &str,
    path: &str,
    input: Value,
    key: &str,
) -> (u16, Value) {
    json_response(
        request(
            router,
            "POST",
            host,
            path,
            Some(token),
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

async fn wait_active(db: &Db, count: i64) {
    let c = db.connect().await.unwrap();
    for _ in 0..500 {
        let active: i64 = c
            .query_one(
                "SELECT count(*) FROM reservations WHERE kind='call' AND status<>'released'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        if active == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("Call reservations did not converge to {count}");
}

async fn wait_ready(db: &Db, deployment: &str) {
    let c = db.connect().await.unwrap();
    let deployment: Uuid = deployment.parse().unwrap();
    for _ in 0..240 {
        let ready: bool = c
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM instances WHERE deployment_id=$1 AND phase='ready')",
                &[&deployment],
            )
            .await
            .unwrap()
            .get(0);
        if ready {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("HTTP deployment did not become ready after fencing");
}

async fn process_identity(app: &App, instance: Uuid) -> (u32, String) {
    let tasks = app
        .runtime
        .ctr(&["tasks".into(), "list".into()])
        .await
        .unwrap();
    let tasks = std::str::from_utf8(&tasks).unwrap();
    let expected = instance.to_string();
    let pid = tasks
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            match fields.as_slice() {
                [id, pid, "RUNNING", ..] if *id == expected => pid.parse::<u32>().ok(),
                _ => None,
            }
        })
        .expect("Live HTTP instance task missing");
    (
        pid,
        process_start(pid).expect("Live HTTP instance PID missing"),
    )
}

fn process_start(pid: u32) -> Option<String> {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => Some(
            stat.rsplit_once(") ")
                .unwrap()
                .1
                .split_whitespace()
                .nth(19)
                .unwrap()
                .to_owned(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("Cannot read HTTP instance PID {pid}: {error}"),
    }
}

struct OpenedEvents {
    call: Uuid,
    data: String,
    body: Pin<Box<dyn Stream<Item = Result<Bytes, axum::Error>> + Send>>,
}
impl OpenedEvents {
    async fn open(router: &Router, host: &str, token: &str, key: &str) -> Self {
        let response = request(
            router,
            "POST",
            host,
            EVENTS,
            Some(token),
            br#"{"message":"controlled stream","items":64,"interval_ms":100}"#.to_vec(),
            &[
                ("content-type", "application/json".into()),
                ("idempotency-key", key.into()),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = Box::pin(response.into_body().into_data_stream());
        let first = tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let data = String::from_utf8(first.to_vec()).unwrap();
        let accepted: Value = serde_json::from_str(
            data.lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted["kind"], "accepted");
        let call = contracts::id(&accepted, "call_id").unwrap();
        Self { call, data, body }
    }
    async fn terminal(mut self) -> String {
        tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(chunk) = self.body.next().await {
                self.data
                    .push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
            }
        })
        .await
        .unwrap();
        assert!(
            !self.data.contains("event: completed"),
            "Revoked/disabled/canceled stream completed: {}",
            self.data
        );
        assert!(
            self.data.contains("event: failed") || self.data.contains("event: canceled"),
            "Accepted stream ended without terminal: {}",
            self.data
        );
        self.data
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires root, containerd, nftables, cgroups v2 and signed HTTP fixture images"]
async fn signed_http_and_static_gateway_use_real_oci_and_shared_broker() {
    assert_eq!(std::env::var("XELAB_HTTP_OCI_TEST").as_deref(), Ok("1"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    xelab_kernel::init_crypto();
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let base = std::env::var("XELAB_TEST_DATABASE_URL").unwrap();
    let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
    admin
        .batch_execute("CREATE DATABASE xelab_http_oci")
        .await
        .unwrap();
    let db = Db::new(format!("{base} dbname=xelab_http_oci")).unwrap();
    db.migrate().await.unwrap();
    let directory = tempfile::Builder::new()
        .prefix("xelab-http-oci-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/mnt")
        .unwrap()
        .keep();
    let root = directory.as_path();
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["http-oci-test-ca".into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap();
    fs::write(root.join("ca.crt"), ca.pem()).unwrap();
    fs::write(root.join("ca.key"), ca_key.serialize_pem()).unwrap();
    fs::set_permissions(root.join("ca.key"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.join("master.key"), [42; 32]).unwrap();
    fs::set_permissions(root.join("master.key"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut value = serde_json::to_value(
        toml::from_str::<toml::Value>(include_str!("../../../docs/contracts/examples/kernel.toml"))
            .unwrap(),
    )
    .unwrap();
    value["storage"]["root_path"] = json!(root.join("state"));
    value["security"]["master_key_file"] = json!(root.join("master.key"));
    value["security"]["workload_ca_cert_file"] = json!(root.join("ca.crt"));
    value["security"]["workload_ca_key_file"] = json!(root.join("ca.key"));
    value["runtime"]["namespace"] = json!("xelab-ci");
    value["runtime"]["network_cidr"] = json!("172.29.240.0/24");
    value["server"]["host_rpc_listen"] = json!("172.29.240.1:7443");
    value["ui_gateway"] = json!({"base_domain":"http-ui.example.org","public_port":8443,"shell_origins":["https://desktop.example.org"]});
    let config = Config::from_value(value).unwrap();
    // Hosted component CI does not meet production admission. The unchanged
    // 4C16G kernel reserve still rejects this machine; only metadata capacity is
    // synthetic, while each actual plugin's cgroups are enforced below.
    assert!(admission::pool(&config.value["resources"], 4000, 17179869184).is_err());
    fs::create_dir_all("/sys/fs/cgroup/xelab/plugins").unwrap();
    for path in [
        "/sys/fs/cgroup/cgroup.subtree_control",
        "/sys/fs/cgroup/xelab/cgroup.subtree_control",
        "/sys/fs/cgroup/xelab/plugins/cgroup.subtree_control",
    ] {
        fs::write(path, "+cpu +memory +pids").unwrap();
    }
    fs::write("/sys/fs/cgroup/xelab/plugins/memory.max", "1073741824").unwrap();
    fs::write("/sys/fs/cgroup/xelab/plugins/cpu.max", "200000 100000").unwrap();
    fs::create_dir_all(config.root()).unwrap();
    fs::set_permissions(config.root(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = Runtime::new(config.clone());
    runtime.prepare_host_service_network().await.unwrap();
    tls::issue(&config, None, &config.root().join("kernel-identity")).unwrap();
    let mut c = db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let owner = auth::bootstrap(
        &tx,
        "HTTP owner",
        "correct HTTP owner password",
        &config.value["quota_defaults"],
    )
    .await
    .unwrap();
    admission::initialize(&tx, &config.value["resources"], 8000, 34359738368)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // A fixed fixture trust root matches the independently prebuilt signed OCI
    // input. All installation, approval, deployment and calls use public APIs.
    let signing = SigningKey::from_bytes(&[7; 32]);
    let publisher: Uuid = "00000000-0000-4000-8000-000000000001".parse().unwrap();
    let pem = signing
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    c.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'HTTP fixture','HTTP fixture',$2,'trusted',now(),now())",&[&publisher,&pem]).await.unwrap();
    let app = Arc::new(App {
        config,
        db: db.clone(),
        auth: Auth::new(vec![42; 32]).unwrap(),
        runtime,
        leader: Arc::new(db.leader().await.unwrap()),
        ready: AtomicBool::new(false),
        shutdown: AtomicBool::new(false),
        blob_uploads: tokio::sync::Semaphore::new(4),
    });
    let mut worker = tokio::spawn(controller::run(app.clone()));
    let router = router(app.clone());
    let session = api(
        &router,
        "login",
        &[],
        None,
        json!({"account_id":owner,"password":"correct HTTP owner password"}),
        "http-login",
        None,
    )
    .await;
    assert_eq!(session.0, 200, "{}", session.1);
    let token = session.1["access_token"].as_str().unwrap().to_owned();
    let (manifest, installed, deployment) = install(
        &router,
        &token,
        &signing,
        "examples/http/generated/xelab/plugin.json",
        "XELAB_TEST_HTTP_IMAGE",
        "http-only",
        json!({}),
    )
    .await;
    assert!(manifest["capabilities"].as_array().unwrap().is_empty());
    let deployment_id: Uuid = deployment.parse().unwrap();
    let providers:i64=c.query_one("SELECT count(*) FROM provider_records p JOIN instances i ON i.id=p.instance_id WHERE i.deployment_id=$1",&[&deployment_id]).await.unwrap().get(0);
    assert_eq!(
        providers, 0,
        "HTTP readiness must not fabricate a capability provider"
    );
    let host = plugin_host(&deployment);
    let direct_result = direct(
        &router,
        CORE_HOST,
        &token,
        ECHO,
        json!({"message":"real declarative HTTP"}),
        "http-direct",
    )
    .await;
    assert_eq!(
        direct_result,
        (200, json!({"message":"real declarative HTTP"}))
    );
    let forged = request(
        &router,
        "POST",
        &host,
        ECHO,
        Some(&token),
        br#"{"message":"reconstructed context"}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "forged-context".into()),
            ("x-xelab-delegation", "external-forged".into()),
            ("x-xelab-subject", "external-forged".into()),
            ("x-xelab-call-id", "external-forged".into()),
            ("x-xelab-deadline-unix-ms", "1".into()),
            ("x-xelab-idempotency-key", "external-forged".into()),
            ("x-user-id", "external-forged".into()),
        ],
    )
    .await;
    assert_eq!(
        json_response(forged).await,
        (200, json!({"message":"reconstructed context"}))
    );
    let misplaced_login = request(
        &router,
        "POST",
        &host,
        "/api/platform/v1/auth/login",
        None,
        serde_json::to_vec(&json!({"account_id":owner,"password":"correct HTTP owner password"}))
            .unwrap(),
        &[("content-type", "application/json".into())],
    )
    .await;
    assert!(
        misplaced_login.status().is_client_error(),
        "Plugin Host reached the trusted login endpoint"
    );
    assert!(!misplaced_login.headers().contains_key("set-cookie"));
    let browser_login = request(
        &router,
        "POST",
        CORE_HOST,
        "/api/platform/v1/auth/login",
        None,
        serde_json::to_vec(&json!({"account_id":owner,"password":"correct HTTP owner password"}))
            .unwrap(),
        &[
            ("content-type", "application/json".into()),
            ("origin", "https://kernel.example.org:8443".into()),
        ],
    )
    .await;
    assert_eq!(browser_login.status(), StatusCode::OK);
    let csrf = browser_login.headers()["x-csrf-token"]
        .to_str()
        .unwrap()
        .to_owned();
    let browser_login = json_response(browser_login).await;
    let browser_cookie = format!(
        "__Host-xelab_auth={}",
        browser_login.1["access_token"].as_str().unwrap()
    );
    for (index, (origin, proof)) in [
        (None, None),
        (Some("https://kernel.example.org:8443"), None),
        (Some("https://forged.example.org"), Some(csrf.as_str())),
    ]
    .into_iter()
    .enumerate()
    {
        let mut headers = vec![
            ("content-type", "application/json".into()),
            ("idempotency-key", format!("cookie-refused-{index}")),
            ("cookie", browser_cookie.clone()),
        ];
        if let Some(origin) = origin {
            headers.push(("origin", origin.into()));
        }
        if let Some(proof) = proof {
            headers.push(("x-csrf-token", proof.into()));
        }
        assert_eq!(
            request(
                &router,
                "POST",
                CORE_HOST,
                ECHO,
                None,
                br#"{"message":"browser"}"#.to_vec(),
                &headers
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    let browser_call = request(
        &router,
        "POST",
        CORE_HOST,
        ECHO,
        None,
        br#"{"message":"browser"}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "cookie-authorized".into()),
            ("cookie", browser_cookie),
            ("origin", "https://kernel.example.org:8443".into()),
            ("x-csrf-token", csrf),
        ],
    )
    .await;
    assert_eq!(
        json_response(browser_call).await,
        (200, json!({"message":"browser"}))
    );
    let page = request(&router, "GET", &host, PAGE, None, Vec::new(), &[]).await;
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("worker-src 'none'"));
    assert!(!page.headers().contains_key("set-cookie"));
    let etag = page.headers()["etag"].to_str().unwrap().to_owned();
    assert!(!to_bytes(page.into_body(), 16777216)
        .await
        .unwrap()
        .is_empty());
    let head = request(&router, "HEAD", &host, PAGE, None, Vec::new(), &[]).await;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(to_bytes(head.into_body(), 16777216)
        .await
        .unwrap()
        .is_empty());
    let cached = request(
        &router,
        "GET",
        &host,
        PAGE,
        None,
        Vec::new(),
        &[("if-none-match", etag)],
    )
    .await;
    assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);
    for (method, path, headers) in [
        ("GET", "/api/platform/v1/node", Vec::new()),
        ("POST", "/api/platform/v1/auth/login", Vec::new()),
        ("GET", "/oauth/authorize", Vec::new()),
        ("GET", "/health/live", Vec::new()),
        (
            "GET",
            "/ui/org.xelab.http-echo/%2e%2e/plugin.json",
            Vec::new(),
        ),
        (
            "POST",
            "/plugins/org.xelab.http-echo/undeclared",
            Vec::new(),
        ),
        ("GET", ECHO, Vec::new()),
        ("GET", PAGE, vec![("upgrade", "websocket".into())]),
    ] {
        let denied = request(
            &router,
            method,
            &host,
            path,
            Some(&token),
            Vec::new(),
            &headers,
        )
        .await;
        assert!(
            denied.status().is_client_error(),
            "{method} {path}: {}",
            denied.status()
        );
        assert!(!denied.headers().contains_key("set-cookie"));
    }
    assert!(request(
        &router,
        "GET",
        "unregistered.example.org:8443",
        "/health/live",
        None,
        Vec::new(),
        &[]
    )
    .await
    .status()
    .is_client_error());
    let duplicate = request(
        &router,
        "POST",
        &host,
        ECHO,
        Some(&token),
        br#"{"message":"one","message":"two"}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "duplicate-json".into()),
        ],
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let registered = api(
        &router,
        "registerSkill",
        &[],
        Some(&token),
        json!({"installation_id":installed["installation_id"],"definition":manifest["skills"][0]}),
        "http-skill-register",
        None,
    )
    .await;
    assert_eq!(registered.0, 201, "{}", registered.1);
    let skill = registered.1["id"].as_str().unwrap().to_owned();
    let streamed_skill = skill_profiles::fixed_methods_and_stream(
        &router,
        &app,
        &token,
        &manifest,
        &installed,
        &deployment,
    )
    .await;

    let skill_params = [("skill_id", skill.clone())];
    let input =
        json!({"input":{"message":"HTTP Skill"},"timeout_ms":10000,"idempotency_key":"业务🔑"});
    assert_eq!(
        api(
            &router,
            "invokeSkill",
            &skill_params,
            Some(&token),
            input.clone(),
            "http-skill-disabled",
            None
        )
        .await
        .0,
        503
    );
    assert_eq!(
        api(
            &router,
            "setSkillEnabled",
            &skill_params,
            Some(&token),
            json!({"enabled":true}),
            "http-skill-enable",
            Some(1)
        )
        .await
        .0,
        200
    );
    let skill_rule =
        json!({"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[skill]}});
    let plugin_rule = json!({"action":"plugin.http.invoke","resource":{"kind":"plugin","match":"ids","ids":["org.xelab.http-echo"]}});
    for (index, rules) in [json!([skill_rule]), json!([plugin_rule])]
        .into_iter()
        .enumerate()
    {
        let key=api(&router,"createApiKey",&[("account_id",owner.to_string())],Some(&token),json!({"name":"one HTTP Skill permission layer","inheritance":{"mode":"selected","rules":rules},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),&format!("http-layer-{index}"),None).await;
        assert_eq!(key.0, 201, "{}", key.1);
        assert_eq!(
            api(
                &router,
                "invokeSkill",
                &skill_params,
                Some(key.1["secret"].as_str().unwrap()),
                input.clone(),
                "http-one-layer",
                None
            )
            .await
            .0,
            403
        );
    }
    let key=api(&router,"createApiKey",&[("account_id",owner.to_string())],Some(&token),json!({"name":"HTTP Skill caller","inheritance":{"mode":"selected","rules":[skill_rule,plugin_rule]},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),"http-caller",None).await;
    assert_eq!(key.0, 201, "{}", key.1);
    let caller = key.1["secret"].as_str().unwrap();
    let called = api(
        &router,
        "invokeSkill",
        &skill_params,
        Some(caller),
        input.clone(),
        "http-skill-call",
        None,
    )
    .await;
    assert_eq!(called.0, 200, "{}", called.1);
    contracts::validate("SkillCallResult", &called.1).unwrap();
    let call_id = contracts::id(&called.1["call"], "call_id").unwrap();
    let stored = c
        .query_one(
            "SELECT idempotency_key,http_binding FROM calls WHERE id=$1",
            &[&call_id],
        )
        .await
        .unwrap();
    assert_eq!(stored.get::<_, String>(0), "业务🔑");
    let binding: Value = stored.get(1);
    assert_eq!(binding["installation_id"], installed["installation_id"]);
    assert_eq!(binding["operation_id"], "echoMessage");
    assert_eq!(called.1["call"]["output"], json!({"message":"HTTP Skill"}));
    assert_eq!(
        called.1["call"]["contract"]["name"],
        manifest["skills"][0]["name"]
    );
    assert_eq!(
        called.1["call"]["contract"]["schema_digest"],
        called.1["definition_digest"]
    );
    let replay = api(
        &router,
        "invokeSkill",
        &skill_params,
        Some(caller),
        input.clone(),
        "http-skill-call",
        None,
    )
    .await;
    assert_eq!(replay.1, called.1);
    let revoked = api(
        &router,
        "revokeApiKey",
        &[(
            "credential_id",
            key.1["credential"]["id"].as_str().unwrap().into(),
        )],
        Some(&token),
        Value::Null,
        "http-revoke",
        key.1["credential"]["revision"].as_i64(),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    assert_eq!(
        api(
            &router,
            "invokeSkill",
            &skill_params,
            Some(caller),
            input.clone(),
            "http-skill-call",
            None
        )
        .await
        .0,
        401
    );
    // Streaming business frames traverse the actual plugin's HTTPS endpoint.
    let stream = request(
        &router,
        "POST",
        &host,
        EVENTS,
        Some(&token),
        br#"{"message":"HTTP events","items":2,"interval_ms":10}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "http-events".into()),
            ("accept", "text/event-stream".into()),
        ],
    )
    .await;
    assert_eq!(stream.status(), StatusCode::OK);
    let events = String::from_utf8(
        to_bytes(stream.into_body(), 4194304)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(events.contains("event: accepted"));
    assert!(events.contains("event: completed"));
    assert_eq!(events.matches("event: item").count(), 2);
    wait_active(&db, 0).await;
    let live_key=api(&router,"createApiKey",&[("account_id",owner.to_string())],Some(&token),json!({"name":"HTTP live revocation","inheritance":{"mode":"selected","rules":[plugin_rule]},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),"http-live-key",None).await;
    assert_eq!(live_key.0, 201, "{}", live_key.1);
    let live = OpenedEvents::open(
        &router,
        &host,
        live_key.1["secret"].as_str().unwrap(),
        "http-live-revoke",
    )
    .await;
    let revoked = api(
        &router,
        "revokeApiKey",
        &[(
            "credential_id",
            live_key.1["credential"]["id"].as_str().unwrap().into(),
        )],
        Some(&token),
        Value::Null,
        "http-live-revoke-key",
        live_key.1["credential"]["revision"].as_i64(),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let revoked_events = live.terminal().await;
    let revoked_frames: Vec<Value> = revoked_events
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    assert_eq!(
        revoked_frames.len(),
        2,
        "Revoked HTTP stream delivered queued data: {revoked_events}"
    );
    assert_eq!(revoked_frames[1]["kind"], "failed");
    assert_eq!(revoked_frames[1]["sequence"], 2);
    assert_eq!(revoked_frames[1]["payload"]["code"], "INVALID_CREDENTIAL");
    wait_active(&db, 0).await;
    wait_ready(&db, &deployment).await;
    let disabled_stream = OpenedEvents::open(&router, &host, &token, "http-live-disable").await;
    let disable_task = {
        let router = router.clone();
        let deployment = deployment.clone();
        let token = token.clone();
        tokio::spawn(
            async move { enabled(&router, &deployment, &token, false, "http-disable").await },
        )
    };
    disabled_stream.terminal().await;
    disable_task.await.unwrap();
    assert!(
        direct(
            &router,
            &host,
            &token,
            ECHO,
            json!({"message":"disabled"}),
            "http-while-disabled"
        )
        .await
        .0 >= 400
    );
    enabled(&router, &deployment, &token, true, "http-restore").await;
    assert_eq!(
        direct(
            &router,
            &host,
            &token,
            ECHO,
            json!({"message":"restored"}),
            "http-after-enable"
        )
        .await
        .0,
        200
    );
    let canceled_stream = OpenedEvents::open(&router, &host, &token, "http-live-cancel").await;
    let canceled = api(
        &router,
        "cancelCall",
        &[("call_id", canceled_stream.call.to_string())],
        Some(&token),
        Value::Null,
        "http-cancel",
        None,
    )
    .await;
    assert_eq!(canceled.0, 204, "{}", canceled.1);
    assert!(canceled_stream.terminal().await.contains("event: canceled"));
    wait_active(&db, 0).await;
    wait_ready(&db, &deployment).await;
    worker.abort();
    let _ = worker.await;
    app.ready.store(false, Ordering::SeqCst);
    worker = tokio::spawn(controller::run(app.clone()));
    for _ in 0..120 {
        if app.ready.load(Ordering::SeqCst)
            && direct(
                &router,
                &host,
                &token,
                ECHO,
                json!({"message":"restart"}),
                "http-restart",
            )
            .await
            .0 == 200
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let after_restart = api(
        &router,
        "invokeSkill",
        &skill_params,
        Some(&token),
        input,
        "http-skill-restart",
        None,
    )
    .await;
    assert_eq!(after_restart.0, 200, "{}", after_restart.1);
    assert_eq!(after_restart.1["skill_id"], skill);
    skill_profiles::after_restart_and_live_revoke(
        &router,
        &db,
        &token,
        owner,
        &streamed_skill,
        &deployment,
    )
    .await;
    enabled(&router, &deployment, &token, false, "http-finish-only").await;
    let (mixed, mixed_installed, mixed_deployment) = install(
        &router,
        &token,
        &signing,
        "examples/http/generated-mixed/xelab/plugin.json",
        "XELAB_TEST_HTTP_MIXED_IMAGE",
        "http-rpc-mixed",
        json!({"test_hold_receipt":true}),
    )
    .await;
    let mixed_host = plugin_host(&mixed_deployment);
    let unavailable_fixed = api(
        &router,
        "invokeSkill",
        &skill_params,
        Some(&token),
        json!({"input":{"message":"do not drift to version two"},"timeout_ms":10000}),
        "http-no-latest-fallback",
        None,
    )
    .await;
    assert_eq!(
        unavailable_fixed.0, 503,
        "Disabled source installation must not be replaced by the healthy newer plugin: {}",
        unavailable_fixed.1
    );
    enabled(
        &router,
        &deployment,
        &token,
        true,
        "http-version-binding-check",
    )
    .await;
    let fixed = api(
        &router,
        "invokeSkill",
        &skill_params,
        Some(&token),
        json!({"input":{"message":"fixed version one"},"timeout_ms":10000}),
        "http-fixed-installation",
        None,
    )
    .await;
    assert_eq!(fixed.0, 200, "{}", fixed.1);
    let fixed_instance = contracts::id(&fixed.1["call"], "provider_instance_id").unwrap();
    let actual_deployment: Uuid = c
        .query_one(
            "SELECT deployment_id FROM instances WHERE id=$1",
            &[&fixed_instance],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(actual_deployment.to_string(), deployment);
    assert!(
        direct(
            &router,
            CORE_HOST,
            &token,
            ECHO,
            json!({"message":"ambiguous versions"}),
            "http-ambiguous-core-route"
        )
        .await
        .0 >= 400,
        "Core namespace silently selected one active plugin version"
    );
    assert_eq!(
        direct(
            &router,
            &mixed_host,
            &token,
            ECHO,
            json!({"message":"fixed deployment host"}),
            "http-fixed-deployment-host"
        )
        .await
        .0,
        200
    );
    enabled(
        &router,
        &deployment,
        &token,
        false,
        "http-finish-version-binding",
    )
    .await;
    let mut held = Vec::new();
    for index in 0..2 {
        let router = router.clone();
        let host = mixed_host.clone();
        let token = token.clone();
        held.push(tokio::spawn(async move {
            direct(
                &router,
                &host,
                &token,
                HOLD,
                json!({"message":"HTTP held","delay_ms":5000}),
                &format!("mixed-http-{index}"),
            )
            .await
            .0
        }));
    }
    for index in 0..2 {
        let router = router.clone();
        let token = token.clone();
        let contract = mixed["capabilities"][0]["contract"].clone();
        let deployment = mixed_deployment.clone();
        held.push(tokio::spawn(async move {api(&router,"invokeCapability",&[],Some(&token),json!({"contract":contract,"input":{"message":"RPC held","delay_ms":5000},"provider_deployment_id":deployment,"timeout_ms":10000}),&format!("mixed-rpc-{index}"),None).await.0}));
    }
    wait_active(&db, 4).await;
    let refused = direct(
        &router,
        &mixed_host,
        &token,
        ECHO,
        json!({"message":"fifth mixed call"}),
        "mixed-fifth",
    )
    .await;
    assert_eq!(refused.0, 503, "{}", refused.1);
    assert_eq!(refused.1["error"]["code"], "RESOURCE_EXHAUSTED");
    let static_refused = request(&router, "GET", &mixed_host, PAGE, None, Vec::new(), &[]).await;
    assert_eq!(
        static_refused.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "Static GET bypassed shared physical slots"
    );
    for task in held {
        assert_eq!(task.await.unwrap(), 200);
    }
    wait_active(&db, 0).await;
    // Pause reconciliation so the exact intermediate state can be observed:
    // dropping the nonstream gateway handler marks an admitted call unknown,
    // while its physical reservation remains until the Controller fences it.
    let disconnected_input =
        json!({"message":format!("handler-drop-{}",Uuid::new_v4()),"delay_ms":5000});
    let disconnected_digest = contracts::digest(&serde_json::to_vec(&disconnected_input).unwrap());
    let held_handler = {
        let router = router.clone();
        let host = mixed_host.clone();
        let token = token.clone();
        tokio::spawn(async move {
            direct(
                &router,
                &host,
                &token,
                HOLD,
                disconnected_input,
                "http-nonstream-handler-drop",
            )
            .await
        })
    };
    let mut admitted = None;
    for _ in 0..150 {
        if let Some(row)=c.query_opt("SELECT c.id,c.provider_instance_id FROM calls c WHERE c.input_digest=$1 AND c.state='running'",&[&disconnected_digest]).await.unwrap(){admitted=Some((row.get::<_,Uuid>(0),row.get::<_,Uuid>(1)));break;}
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (dropped_call, dropped_instance) = admitted.expect("HTTP hold was not durably admitted");
    let previous_process = process_identity(&app, dropped_instance).await;
    worker.abort();
    let _ = worker.await;
    held_handler.abort();
    let _ = held_handler.await;
    let mut unknown = false;
    for _ in 0..100 {
        let row=c.query_one("SELECT c.state,r.status FROM calls c JOIN reservations r ON r.id=c.id WHERE c.id=$1",&[&dropped_call]).await.unwrap();
        if row.get::<_, String>(0) == "unknown" {
            assert_ne!(row.get::<_, String>(1), "released");
            unknown = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        unknown,
        "Dropped handler did not retain an unknown physical call"
    );
    assert!(app.runtime.running(dropped_instance).await.unwrap());
    app.ready.store(false, Ordering::SeqCst);
    worker = tokio::spawn(controller::run(app.clone()));
    wait_active(&db, 0).await;
    wait_ready(&db, &mixed_deployment).await;
    assert_ne!(
        process_identity(&app, dropped_instance).await,
        previous_process,
        "Recovery did not fence the old process before releasing physical capacity"
    );
    // Client disconnect must eventually release/fence durable physical work.
    let response = request(
        &router,
        "POST",
        &mixed_host,
        EVENTS,
        Some(&token),
        br#"{"message":"disconnect","items":64,"interval_ms":100}"#.to_vec(),
        &[
            ("content-type", "application/json".into()),
            ("idempotency-key", "http-stream-disconnect".into()),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    assert!(body.next().await.unwrap().is_ok());
    drop(body);
    wait_active(&db, 0).await;
    wait_ready(&db, &mixed_deployment).await;
    skill_profiles::cancel_hold_task(
        &router,
        &app,
        &token,
        &mixed,
        &mixed_installed,
        &mixed_deployment,
    )
    .await;
    enabled(
        &router,
        &mixed_deployment,
        &token,
        false,
        "http-finish-mixed",
    )
    .await;
    assert_eq!(
        c.query_one("SELECT reserved_cpu_millis FROM node_budget", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    app.shutdown.store(true, Ordering::SeqCst);
    worker.abort();
    let _ = worker.await;
    println!("HTTP-OCI: signed HTTP-only readiness, fixed GET/PUT/PATCH/DELETE Skill, JSON/streaming Skill, direct HTTP, static origin, SSE, original-authority revocation, restart, Task cancellation and mixed physical slots passed");
}
