//! Privileged, disposable-host component test. It never lowers daemon preflight limits.
#[path = "support/http_host.rs"]
mod http_host;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::Request,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use futures_util::StreamExt;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use serde_json::{json, Value};
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
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
#[path = "support/platform_source.rs"]
mod platform_source;
#[path = "support/platform_versioned.rs"]
mod platform_versioned;

#[path = "support/m4.rs"]
mod m4;
#[path = "support/ordinary_effects.rs"]
mod ordinary_effects;
#[path = "support/upgrades.rs"]
mod upgrade_acceptance;

#[test]
fn m4_signed_consumer_fixture_matches_actual_kernel_profile_and_contracts() {
    let directory = tempfile::tempdir().unwrap();
    let platform = if cfg!(target_arch = "aarch64") {
        "linux/arm64"
    } else {
        "linux/amd64"
    };
    let generated = std::process::Command::new("python3")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/m4-consumer/build_artifact.py"),
        )
        .args([
            "--publisher-id",
            "00000000-0000-4000-8000-000000000001",
            "--platform",
            platform,
            "--output",
        ])
        .arg(directory.path())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let raw = fs::read(directory.path().join("xelab/plugin.json")).unwrap();
    let manifest = contracts::strict_json(&raw, 1048576).unwrap();
    artifact::validate_profile(&manifest).unwrap();
    let capability = &manifest["capabilities"][0];
    assert_eq!(capability["side_effect"], "non_repeatable");
    let name = capability["contract"]["name"].as_str().unwrap();
    let mut checks = String::new();
    for file in [
        "input.schema.json",
        "output.schema.json",
        "stream.schema.json",
        "semantics.json",
    ] {
        let bytes = fs::read(
            directory
                .path()
                .join("xelab/contracts")
                .join(name)
                .join("1.0.0")
                .join(file),
        )
        .unwrap();
        checks.push_str(&format!("{file} {}\n", &contracts::digest(&bytes)[7..]));
    }
    assert_eq!(
        capability["contract"]["schema_digest"],
        contracts::digest(checks.as_bytes())
    );
}

#[allow(clippy::too_many_arguments)] // Test request envelope.
async fn api(
    router: &Router,
    operation: &str,
    params: &[(&str, String)],
    token: Option<&str>,
    body: Value,
    key: &str,
    revision: Option<i64>,
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

async fn operation(router: &Router, id: &str, token: &str) -> Value {
    for _ in 0..120 {
        let (status, value) = api(
            router,
            "getOperation",
            &[("operation_id", id.into())],
            Some(token),
            Value::Null,
            "poll",
            None,
        )
        .await;
        assert_eq!(status, 200, "{value}");
        if value["state"] == "succeeded" {
            if matches!(
                value["kind"].as_str(),
                Some("createDeployment" | "setDeploymentEnabled")
            ) {
                contracts::validate("Deployment", &value["result"]).unwrap();
                assert_eq!(value["result"]["id"], value["resource_id"]);
            }
            return value["result"].clone();
        }
        assert_ne!(value["state"], "failed", "{value}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("operation {id} did not finish");
}

// Controlled process restarts can change observation revisions between GET and
// PUT. Retry only a confirmed precondition rejection with unchanged intent;
// never replay an accepted or uncertain mutation with a new fingerprint.
async fn disable_after_observation(
    router: &Router,
    params: &[(&str, String)],
    token: &str,
    key: &str,
) -> (u16, Value) {
    let mut expected = None;
    for _ in 0..10 {
        let current = api(
            router,
            "getDeployment",
            params,
            Some(token),
            Value::Null,
            "read-before-disable",
            None,
        )
        .await;
        assert_eq!(current.0, 200, "{}", current.1);
        match &expected {
            Some(spec) => assert_eq!(
                spec, &current.1["spec"],
                "do not retry over a changed deployment intent"
            ),
            None => expected = Some(current.1["spec"].clone()),
        }
        let response = api(
            router,
            "setDeploymentEnabled",
            params,
            Some(token),
            json!({"enabled":false}),
            key,
            current.1["revision"].as_i64(),
        )
        .await;
        if response.0 == 412 && response.1["error"]["code"] == "ETAG_MISMATCH" {
            continue;
        }
        return response;
    }
    panic!("observation revisions did not settle for a fenced disable request");
}

async fn configure_stopped_deployment(
    app: &App,
    router: &Router,
    params: &[(&str, String)],
    token: &str,
    instance: Uuid,
) {
    let c = app.db.connect().await.unwrap();
    let row = c
        .query_one(
            "SELECT phase,runtime_id FROM instances WHERE id=$1",
            &[&instance],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("phase"), "stopped");
    assert!(
        row.get::<_, Option<String>>("runtime_id").is_none(),
        "the disable operation must clear the runtime identity after confirming stop"
    );
    assert!(!app.runtime.inventory().await.unwrap().contains(&instance));

    // Restore the historical metadata left by a prior version, after the
    // actual container has stopped. The next inactive sweep must repair it.
    assert_eq!(
        c.execute(
            "UPDATE instances SET runtime_id=$2 WHERE id=$1 AND phase='stopped'",
            &[&instance, &instance.to_string()],
        )
        .await
        .unwrap(),
        1
    );
    let deployment: Uuid = params[0].1.parse().unwrap();
    let fence = format!("xelab/deployment-runtime/{deployment}");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let settled: bool = c
                .query_one(
                    "SELECT runtime_id IS NULL FROM instances WHERE id=$1",
                    &[&instance],
                )
                .await
                .unwrap()
                .get(0);
            if settled {
                // Wait for the same sweep to finish publishing the disabled
                // deployment before issuing a configuration request.
                let mut fence_connection = app.db.connect().await.unwrap();
                let tx = fence_connection.transaction().await.unwrap();
                tx.query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    &[&fence],
                )
                .await
                .unwrap();
                tx.rollback().await.unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("inactive reconciliation must recover the historical runtime marker");
    let current = api(
        router,
        "getDeployment",
        params,
        Some(token),
        Value::Null,
        "read-stopped-config",
        None,
    )
    .await;
    assert_eq!(current.0, 200, "{}", current.1);
    assert_eq!(current.1["phase"], "disabled");
    let mut spec = current.1["spec"].clone();
    spec["display_name"] = json!("Echo reconfigured after disable");
    let updated = api(
        router,
        "updateDeployment",
        params,
        Some(token),
        json!({"spec":spec}),
        "configure-after-runtime-stop",
        current.1["revision"].as_i64(),
    )
    .await;
    assert_eq!(updated.0, 202, "{}", updated.1);
    assert_eq!(updated.1["state"], "succeeded");
    assert_eq!(updated.1["result"]["spec"], spec);
    println!("Confirmed stopped OCI instance cleared its runtime identity, recovered an old marker and allowed disabled configuration");
}

#[tokio::test]
#[ignore = "requires root, containerd, nftables and a disposable Linux host; see README"]
async fn signed_oci_plugin_runs_through_the_management_api_and_recovers() {
    assert_eq!(std::env::var("XELAB_OCI_TEST").as_deref(), Ok("1"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        std::env::var("XELAB_M4_OCI_REQUIRED").as_deref(),
        Ok("1"),
        "the full OCI gate must explicitly require M4"
    );
    let m4_image =
        std::env::var("XELAB_TEST_M4_CONSUMER_IMAGE").expect("required M4 image is missing");
    artifact::image_ref(&m4_image).expect("M4 image must use its imported immutable digest");
    assert!(
        std::path::Path::new("examples/generated-m4-consumer/xelab/plugin.json").is_file(),
        "required signed M4 artifact is missing"
    );

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    xelab_kernel::init_crypto();
    let base = std::env::var("XELAB_TEST_DATABASE_URL").unwrap();
    let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
    admin
        .batch_execute("CREATE DATABASE xelab_oci")
        .await
        .unwrap();
    let db = Db::new(format!("{base} dbname=xelab_oci")).unwrap();
    db.migrate().await.unwrap();
    let directory = tempfile::Builder::new()
        .prefix("xelab-oci-source-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/mnt")
        .unwrap()
        .keep();
    let root = directory.as_path();
    let key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec!["xelab-test-ca".into()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = ca.self_signed(&key).unwrap();
    fs::write(root.join("ca.crt"), cert.pem()).unwrap();
    fs::write(root.join("ca.key"), key.serialize_pem()).unwrap();
    fs::set_permissions(root.join("ca.key"), fs::Permissions::from_mode(0o600)).unwrap();
    let t: toml::Value =
        toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
    let mut value = serde_json::to_value(t).unwrap();
    value["storage"]["root_path"] = json!(root.join("state"));
    value["security"]["workload_ca_cert_file"] = json!(root.join("ca.crt"));
    value["security"]["workload_ca_key_file"] = json!(root.join("ca.key"));
    value["security"]["master_key_file"] = json!(root.join("master.key"));
    fs::write(root.join("master.key"), [42; 32]).unwrap();
    fs::set_permissions(root.join("master.key"), fs::Permissions::from_mode(0o600)).unwrap();
    value["runtime"]["namespace"] = json!("xelab-ci");
    value["runtime"]["network_cidr"] = json!("172.29.240.0/24");
    value["server"]["host_rpc_listen"] = json!("172.29.240.1:7443");
    let config = Config::from_value(value).unwrap();
    let runtime = Runtime::new(config.clone());
    // Hosted CI is smaller than the production 4 CPU + 16 GiB kernel reservation.
    // Exercise real per-instance cgroups separately, with a synthetic metadata pool.
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
    runtime.prepare_host_service_network().await.unwrap();
    tls::issue(&config, None, &config.root().join("kernel-identity")).unwrap();
    let mut c = db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let owner = auth::bootstrap(
        &tx,
        "OCI test owner",
        "correct horse test password",
        &config.value["quota_defaults"],
    )
    .await
    .unwrap();
    admission::initialize(&tx, &config.value["resources"], 8000, 34359738368)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let publisher: Uuid = "00000000-0000-4000-8000-000000000001".parse().unwrap();
    let signing = SigningKey::from_bytes(&[7; 32]);
    let pem = signing
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    c.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'fixture','fixture',$2,'trusted',now(),now())",&[&publisher,&pem]).await.unwrap();
    let raw = fs::read("examples/generated/xelab/plugin.json").unwrap();
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    let image = std::env::var("XELAB_TEST_IMAGE").unwrap();
    let envelope =
        artifact::signature_envelope(&manifest, artifact::image_ref(&image).unwrap(), &raw)
            .unwrap();
    let install = json!({"publisher_id":publisher,"image":image,"signature":STANDARD.encode(signing.sign(envelope.as_bytes()).to_bytes())});
    let mut bad = install.clone();
    bad["signature"] = json!(STANDARD.encode([0; 64]));
    assert!(artifact::Artifact::inspect(&runtime, &bad, &pem)
        .await
        .is_err());
    let app = Arc::new(App {
        config: config.clone(),
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
    let (status, session) = api(
        &router,
        "login",
        &[],
        None,
        json!({"account_id":owner,"password":"correct horse test password"}),
        "login",
        None,
    )
    .await;
    assert_eq!(status, 200, "{session}");
    let token = session["access_token"].as_str().unwrap();
    let (status, installed) = api(
        &router,
        "installPlugin",
        &[],
        Some(token),
        install.clone(),
        "install-1",
        None,
    )
    .await;
    assert_eq!(status, 202, "{installed}");
    let replay = api(
        &router,
        "installPlugin",
        &[],
        Some(token),
        install,
        "install-1",
        None,
    )
    .await;
    assert_eq!(replay.1["id"], installed["id"]);
    let installed = operation(&router, installed["id"].as_str().unwrap(), token).await;
    // Later Python installation fixtures deliberately shadow `installed`.
    // Preserve the original signed Rust origin used by the fixed Skill.
    let rust_installation = contracts::id(&installed, "installation_id").unwrap();
    let limits =
        json!({"cpu_millis":500,"memory_bytes":134217728,"ephemeral_bytes":1048576,"pids":64});
    let (status,created)=api(&router,"createDeployment",&[],Some(token),json!({"installation_id":installed["installation_id"],"display_name":"echo","enabled":false,"limits":limits,"config":{},"volume_ids":[]}),"deploy-1",None).await;
    assert_eq!(status, 202, "{created}");
    let deployment = operation(&router, created["id"].as_str().unwrap(), token).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let params = [("deployment_id", deployment.clone())];
    let approved = api(
        &router,
        "approvePlugin",
        &params,
        Some(token),
        json!({"rules":[],"egress":[]}),
        "approve-1",
        Some(1),
    )
    .await;
    assert_eq!(approved.0, 200, "{}", approved.1);
    let stale = api(
        &router,
        "setDeploymentEnabled",
        &params,
        Some(token),
        json!({"enabled":true}),
        "stale-enable",
        Some(1),
    )
    .await;
    assert_eq!(stale.0, 412, "{}", stale.1);
    // RUN-01: interrupt reconciliation before persisting the enable intent.
    worker.abort();
    let _ = worker.await;
    app.ready.store(false, Ordering::SeqCst);
    let enabled = api(
        &router,
        "setDeploymentEnabled",
        &params,
        Some(token),
        json!({"enabled":true}),
        "enable-1",
        Some(2),
    )
    .await;
    assert_eq!(enabled.0, 202, "{}", enabled.1);
    let intended: Uuid = c
        .query_one(
            "SELECT id FROM instances WHERE deployment_id=$1",
            &[&deployment.parse::<Uuid>().unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!app.runtime.inventory().await.unwrap().contains(&intended));
    worker = tokio::spawn(controller::run(app.clone()));
    operation(&router, enabled.1["id"].as_str().unwrap(), token).await;
    let input = json!({"contract":manifest["capabilities"][0]["contract"],"input":{"message":"hello OCI"},"provider_deployment_id":deployment,"timeout_ms":10000});
    let called = api(
        &router,
        "invokeCapability",
        &[],
        Some(token),
        input.clone(),
        "invoke-1",
        None,
    )
    .await;
    assert_eq!(called.0, 200, "{}", called.1);
    assert_eq!(called.1["output"]["message"], "hello OCI");
    let replay = api(
        &router,
        "invokeCapability",
        &[],
        Some(token),
        input.clone(),
        "invoke-1",
        None,
    )
    .await;
    assert_eq!(replay.1, called.1);
    let mut different = input.clone();
    different["input"]["message"] = json!("different");
    assert_eq!(
        api(
            &router,
            "invokeCapability",
            &[],
            Some(token),
            different,
            "invoke-1",
            None
        )
        .await
        .0,
        409
    );
    let skill = ordinary_skill_lifecycle(
        &router,
        &db,
        owner,
        token,
        &installed["installation_id"],
        &manifest,
        &called.1,
        &deployment,
    )
    .await;
    let registered_skill = api(
        &router,
        "getSkill",
        &[("skill_id", skill.clone())],
        Some(token),
        Value::Null,
        "read-registered-skill",
        None,
    )
    .await;
    assert_eq!(registered_skill.0, 200, "{}", registered_skill.1);
    let call_id = called.1["call_id"].as_str().unwrap();
    assert_eq!(
        api(
            &router,
            "getCall",
            &[("call_id", call_id.into())],
            Some(token),
            Value::Null,
            "read",
            None
        )
        .await
        .1["state"],
        "succeeded"
    );
    let instance: Uuid = called.1["provider_instance_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        instance, intended,
        "restart must reuse the committed instance intent"
    );
    // Expected generation is part of the server certificate name; a different one fails closed.
    let instance_row = c
        .query_one("SELECT generation FROM instances WHERE id=$1", &[&instance])
        .await
        .unwrap();
    assert!(tls::channel(
        &config,
        instance,
        instance_row.get::<_, i64>(0) + 1,
        &app.runtime.address(instance).unwrap()
    )
    .await
    .is_err());
    let identity = config
        .root()
        .join("runtime")
        .join(instance.to_string())
        .join("identity");
    let before = fs::read(identity.join("tls.key")).unwrap();
    tls::issue(&config, Some((instance, instance_row.get(0))), &identity).unwrap();
    assert_eq!(fs::read(identity.join("tls.key")).unwrap(), before);
    // Fault cases can require a public disable/enable after the unchanged
    // restart budget is exhausted. Keep the original intent/TLS checks above;
    // later liveness/isolation checks must follow the current live generation.
    let mut instance = ordinary_skill_stream_lifecycle(
        &app,
        &router,
        &db,
        token,
        &installed["installation_id"],
        &manifest,
    )
    .await;
    let mut effects = ordinary_effects::successful(
        &router,
        &db,
        owner,
        token,
        &installed["installation_id"],
        &manifest,
        &deployment,
    )
    .await;
    instance = effects
        .interrupted(&app, &router, &db, owner, token, instance, &deployment)
        .await;
    // The Controller was running during all side-effect/query/fencing checks.
    // Now independently verify durable results and accounting after its restart.
    worker.abort();
    let _ = worker.await;
    app.ready.store(false, Ordering::SeqCst);
    worker = tokio::spawn(controller::run(app.clone()));
    for _ in 0..100 {
        if app.ready.load(Ordering::SeqCst)
            && api(
                &router,
                "invokeCapability",
                &[],
                Some(token),
                input.clone(),
                "after-restart",
                None,
            )
            .await
            .0 == 200
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        api(
            &router,
            "invokeCapability",
            &[],
            Some(token),
            input,
            "after-restart",
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        c.query_one("SELECT reserved_cpu_millis FROM node_budget", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        500
    );
    effects
        .after_restart(&app, &router, &db, owner, token, instance)
        .await;
    let after_restart = api(
        &router,
        "invokeSkill",
        &[("skill_id", skill.clone())],
        Some(token),
        json!({"input":{"message":"fixed Skill after controller restart"},"timeout_ms":10000}),
        "skill-after-restart",
        None,
    )
    .await;
    assert_eq!(after_restart.0, 200, "{}", after_restart.1);
    assert_eq!(after_restart.1["skill_id"], skill);
    assert_eq!(
        after_restart.1["call"]["output"]["message"],
        "fixed Skill after controller restart"
    );
    // A second independently implemented language/runtime reuses the same contract.
    let python_raw = fs::read("examples/generated-python/xelab/plugin.json").unwrap();
    let python_manifest: Value = serde_json::from_slice(&python_raw).unwrap();
    assert_eq!(
        manifest["capabilities"][0],
        python_manifest["capabilities"][0]
    );
    let rust_capabilities = manifest["capabilities"].as_array().unwrap();
    assert_eq!(rust_capabilities.len(), 6);
    let health_query = rust_capabilities.last().unwrap();
    assert_eq!(health_query["contract"]["name"], "org.xelab.echo.queryable");
    assert_eq!(health_query["contract"]["version"], "1.0.1");
    assert_eq!(health_query["side_effect"], "queryable");
    assert_eq!(python_manifest["capabilities"].as_array().unwrap().len(), 1);
    assert_ne!(manifest["plugin_id"], python_manifest["plugin_id"]);
    let python_image = std::env::var("XELAB_TEST_PYTHON_IMAGE").unwrap();
    let python_digest = artifact::image_ref(&python_image).unwrap();
    let envelope =
        artifact::signature_envelope(&python_manifest, python_digest, &python_raw).unwrap();
    let install = json!({"publisher_id":publisher,"image":python_image,"signature":STANDARD.encode(signing.sign(envelope.as_bytes()).to_bytes())});
    let installed = api(
        &router,
        "installPlugin",
        &[],
        Some(token),
        install,
        "install-python",
        None,
    )
    .await;
    assert_eq!(installed.0, 202, "{}", installed.1);
    let installed = operation(&router, installed.1["id"].as_str().unwrap(), token).await;
    let created=api(&router,"createDeployment",&[],Some(token),json!({"installation_id":installed["installation_id"],"display_name":"independent Python","enabled":false,"limits":limits,"config":{},"volume_ids":[]}),"deploy-python",None).await;
    assert_eq!(created.0, 202, "{}", created.1);
    let python_deployment: Uuid = operation(&router, created.1["id"].as_str().unwrap(), token)
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let python_params = [("deployment_id", python_deployment.to_string())];
    let approved = api(
        &router,
        "approvePlugin",
        &python_params,
        Some(token),
        json!({"rules":[],"egress":[]}),
        "approve-python",
        Some(1),
    )
    .await;
    assert_eq!(approved.0, 200, "{}", approved.1);
    worker.abort();
    let _ = worker.await;
    app.ready.store(false, Ordering::SeqCst);
    let enabled = api(
        &router,
        "setDeploymentEnabled",
        &python_params,
        Some(token),
        json!({"enabled":true}),
        "enable-python",
        Some(2),
    )
    .await;
    assert_eq!(enabled.0, 202, "{}", enabled.1);
    let row = c
        .query_one(
            "SELECT id,generation FROM instances WHERE deployment_id=$1",
            &[&python_deployment],
        )
        .await
        .unwrap();
    let python_instance: Uuid = row.get(0);
    let python_generation: i64 = row.get(1);
    let tx = c.transaction().await.unwrap();
    admission::reserve(&tx, python_instance).await.unwrap();
    tx.commit().await.unwrap();
    // RUN-02: OCI has been created, but observation was never committed.
    app.runtime
        .ensure(
            python_instance,
            python_deployment,
            python_generation,
            &python_manifest,
            &python_image,
            python_digest,
            &limits,
            &[],
        )
        .await
        .unwrap();
    assert!(app.runtime.running(python_instance).await.unwrap());
    let mut described = false;
    for _ in 0..30 {
        if let Ok(channel) = tls::channel(
            &config,
            python_instance,
            python_generation,
            &app.runtime.address(python_instance).unwrap(),
        )
        .await
        {
            let mut client =
                xelab_kernel::rpc::plugin_lifecycle_client::PluginLifecycleClient::new(channel);
            let description = client
                .describe(xelab_kernel::rpc::DescribeRequest {
                    context: Some(controller::context(None)),
                })
                .await;
            assert!(description.is_ok(), "independent Describe: {description:?}");
            assert_eq!(description.unwrap().into_inner().manifest_json, python_raw);
            described = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(described, "independent plugin TLS listener did not start");
    // A CA-trusted workload is still not the kernel: identity authorization
    // must reject it after mTLS, not merely trust every certificate from the CA.
    let imposter = root.join("imposter-identity");
    tls::issue(&config, Some((Uuid::new_v4(), 1)), &imposter).unwrap();
    let imposter_tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(
            fs::read(root.join("ca.crt")).unwrap(),
        ))
        .identity(tonic::transport::Identity::from_pem(
            fs::read(imposter.join("tls.crt")).unwrap(),
            fs::read(imposter.join("tls.key")).unwrap(),
        ))
        .domain_name(format!(
            "i-{python_instance}-g-{python_generation}.xelab.local"
        ));
    let imposter_channel = tonic::transport::Endpoint::from_shared(format!(
        "https://{}:7000",
        app.runtime.address(python_instance).unwrap()
    ))
    .unwrap()
    .tls_config(imposter_tls)
    .unwrap()
    .timeout(Duration::from_secs(3))
    .connect()
    .await
    .unwrap();
    let denied =
        xelab_kernel::rpc::plugin_lifecycle_client::PluginLifecycleClient::new(imposter_channel)
            .describe(xelab_kernel::rpc::DescribeRequest {
                context: Some(controller::context(None)),
            })
            .await
            .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    assert!(c
        .query_one(
            "SELECT runtime_id FROM instances WHERE id=$1",
            &[&python_instance]
        )
        .await
        .unwrap()
        .get::<_, Option<String>>(0)
        .is_none());
    worker = tokio::spawn(controller::run(app.clone()));
    operation(&router, enabled.1["id"].as_str().unwrap(), token).await;
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM instances WHERE deployment_id=$1",
            &[&python_deployment]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM reservations WHERE instance_id=$1 AND status<>'released'",
            &[&python_instance]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(app.runtime.inventory().await.unwrap().len(), 2);
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM provider_records WHERE availability='ready'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        (manifest["capabilities"].as_array().unwrap().len()
            + python_manifest["capabilities"].as_array().unwrap().len()) as i64
    );
    let fixed_skill = api(
        &router, "invokeSkill", &[("skill_id",skill.clone())], Some(token),
        json!({"input":{"message":"fixed despite another healthy implementation"},"timeout_ms":10000}),
        "skill-no-provider-drift", None,
    ).await;
    assert_eq!(fixed_skill.0, 200, "{}", fixed_skill.1);
    assert_eq!(
        fixed_skill.1["call"]["provider_instance_id"],
        instance.to_string()
    );
    assert_ne!(
        fixed_skill.1["call"]["provider_instance_id"],
        python_instance.to_string()
    );
    let python_input = json!({"contract":manifest["capabilities"][0]["contract"],"input":{"message":"hello OCI"},"provider_deployment_id":python_deployment,"timeout_ms":10000});
    let python_result = api(
        &router,
        "invokeCapability",
        &[],
        Some(token),
        python_input.clone(),
        "invoke-python",
        None,
    )
    .await;
    assert_eq!(python_result.0, 200, "{}", python_result.1);
    assert_eq!(python_result.1["output"], called.1["output"]);
    assert_eq!(
        python_result.1["provider_instance_id"],
        python_instance.to_string()
    );
    // Real plugin -> HostService mTLS path, with a signed requested secret.use
    // rule, approved binding, rotation, and immediate binding revocation.
    let host_worker = tokio::spawn(xelab_kernel::host::serve(app.clone()));
    let secret = api(
        &router,
        "createSecret",
        &[],
        Some(token),
        json!({"name":"oci-provider","value_base64":STANDARD.encode(b"oci-initial-secret")}),
        "oci-secret",
        None,
    )
    .await;
    assert_eq!(secret.0, 201, "{}", secret.1);
    let secret_id = secret.1["id"].as_str().unwrap();
    let bound = api(
        &router,
        "bindSecret",
        &[],
        Some(token),
        json!({"secret_id":secret_id,"deployment_id":python_deployment,"maximum_lease_seconds":60}),
        "oci-bind-secret",
        None,
    )
    .await;
    assert_eq!(bound.0, 201, "{}", bound.1);
    let binding = bound.1["id"].as_str().unwrap();
    let probe = |expected: String, version: &str| {
        vec![
            "tasks".into(),
            "exec".into(),
            "--exec-id".into(),
            format!("secret-{}", Uuid::new_v4()),
            python_instance.to_string(),
            "/usr/bin/python3".into(),
            "/opt/plugin/lease_probe.py".into(),
            binding.to_string(),
            expected,
            version.to_string(),
        ]
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let initial = app
        .runtime
        .ctr(&probe(
            contracts::digest(b"oci-initial-secret")[7..].to_string(),
            "1",
        ))
        .await
        .unwrap();
    assert_eq!(initial, b"lease-verified\n");
    let rotated = api(
        &router,
        "rotateSecret",
        &[("secret_id", secret_id.to_string())],
        Some(token),
        json!({"name":"oci-provider","value_base64":STANDARD.encode(b"oci-rotated-secret")}),
        "oci-rotate-secret",
        Some(1),
    )
    .await;
    assert_eq!(rotated.0, 200, "{}", rotated.1);
    let rotation = app
        .runtime
        .ctr(&probe(
            contracts::digest(b"oci-rotated-secret")[7..].to_string(),
            "2",
        ))
        .await
        .unwrap();
    assert_eq!(rotation, b"lease-verified\n");
    let revoked = api(
        &router,
        "revokeSecretBinding",
        &[("binding_id", binding.to_string())],
        Some(token),
        Value::Null,
        "oci-revoke-binding",
        Some(1),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    assert_eq!(
        app.runtime.ctr(&probe("denied".into(), "2")).await.unwrap(),
        b"lease-denied\n"
    );
    host_worker.abort();
    let _ = host_worker.await;
    // Real per-key lifetime accounting, including replay without another charge.
    let key_body = json!({"name":"one call","inheritance":{"mode":"selected","rules":[{"action":"capability.invoke","resource":{"kind":"capability","match":"ids","ids":["org.xelab.echo@1.0.0"]}}]},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::hours(1),"max_calls":1}});
    let issued = api(
        &router,
        "createApiKey",
        &[("account_id", owner.to_string())],
        Some(token),
        key_body,
        "issue-one-call",
        None,
    )
    .await;
    assert_eq!(issued.0, 201, "{}", issued.1);
    let limited = issued.1["secret"].as_str().unwrap();
    assert_eq!(
        api(
            &router,
            "invokeCapability",
            &[],
            Some(limited),
            python_input.clone(),
            "limited-call",
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        api(
            &router,
            "invokeCapability",
            &[],
            Some(limited),
            python_input.clone(),
            "limited-call",
            None
        )
        .await
        .0,
        200
    );
    let exhausted = api(
        &router,
        "invokeCapability",
        &[],
        Some(limited),
        python_input.clone(),
        "limited-again",
        None,
    )
    .await;
    assert_eq!(exhausted.0, 409, "{}", exhausted.1);
    assert_eq!(exhausted.1["error"]["code"], "QUOTA_EXCEEDED");
    grant_source_budget(&router, &db, owner, token, &python_input).await;
    // RUN-03: exercise the cgroup, not just serialized OCI configuration.
    let cg = std::path::Path::new("/sys/fs/cgroup/xelab/plugins").join(python_instance.to_string());
    assert_eq!(
        fs::read_to_string(cg.join("memory.max")).unwrap().trim(),
        "134217728"
    );
    assert_eq!(
        fs::read_to_string(cg.join("cpu.max")).unwrap().trim(),
        "50000 100000"
    );
    assert_eq!(
        fs::read_to_string(cg.join("pids.max")).unwrap().trim(),
        "64"
    );
    let before = counter(&cg.join("cpu.stat"), "nr_throttled");
    let stress = exec_python(
        python_instance,
        "import time\nend=time.monotonic()+2\nwhile time.monotonic()<end: pass",
    )
    .await;
    assert!(
        stress.status.success(),
        "{}",
        String::from_utf8_lossy(&stress.stderr)
    );
    assert!(counter(&cg.join("cpu.stat"), "nr_throttled") > before);
    let before = counter(&cg.join("memory.events"), "oom_kill");
    let oom = exec_python(python_instance, "a=bytearray(256*1024*1024)").await;
    assert!(!oom.status.success());
    assert!(counter(&cg.join("memory.events"), "oom_kill") > before);
    assert!(
        app.runtime.running(instance).await.unwrap(),
        "another plugin survives the OOM"
    );
    let isolation=exec_python(python_instance,"import socket\ntry:\n open('/xelab/forbidden','w')\n raise AssertionError('rootfs writable')\nexcept OSError: pass\ns=socket.socket();s.settimeout(1)\ntry:\n s.connect(('1.1.1.1',443))\n raise AssertionError('egress allowed')\nexcept OSError: pass").await;
    assert!(
        isolation.status.success(),
        "{}",
        String::from_utf8_lossy(&isolation.stderr)
    );
    // A dropped HTTP task can leave a durable running call without a finalizer.
    // Recovery must fence the old process before returning its slot, then restart.
    // Keep an unsettled disabled backlog larger than the old 1000-row page.
    // Recovery and health work must proceed before this cleanup sweep finishes.
    c.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) SELECT gen_random_uuid(),owner_id,installation_id,'{\"enabled\":false}'::jsonb,'reconciling',created_at-interval '1 day',now() FROM deployments CROSS JOIN generate_series(1,1200) WHERE id=$1", &[&deployment.parse::<Uuid>().unwrap()]).await.unwrap();
    let recovery_started = tokio::time::Instant::now();
    let abandoned = Uuid::new_v4();
    let prior: Uuid = called.1["call_id"].as_str().unwrap().parse().unwrap();
    let tx = c.transaction().await.unwrap();
    xelab_kernel::db::call_lock(&tx).await.unwrap();
    tx.execute("INSERT INTO calls(id,owner_id,credential_id,provider_instance_id,contract,input_digest,idempotency_key,state,deadline_at,created_at) SELECT $1,owner_id,credential_id,$2,contract,input_digest,'abandoned-fixture','running',now()-interval '10 seconds',now() FROM calls WHERE id=$3", &[&abandoned,&python_instance,&prior]).await.unwrap();
    tx.execute("INSERT INTO reservations(id,account_id,kind,expires_at,status,created_at) VALUES($1,$2,'call',now()-interval '10 seconds','active',now())", &[&abandoned,&owner]).await.unwrap();
    tx.execute(
        "UPDATE quotas SET concurrent_calls_used=concurrent_calls_used+1 WHERE account_id=$1",
        &[&owner],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut recovered = false;
    for _ in 0..120 {
        let state=c.query_one("SELECT c.state,r.status,q.concurrent_calls_used FROM calls c JOIN reservations r ON r.id=c.id JOIN quotas q ON q.account_id=c.owner_id WHERE c.id=$1", &[&abandoned]).await.unwrap();
        let ready:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM provider_records WHERE instance_id=$1 AND availability='ready')", &[&python_instance]).await.unwrap().get(0);
        if state.get::<_, String>(0) == "unknown"
            && state.get::<_, String>(1) == "released"
            && state.get::<_, i64>(2) == 0
            && ready
        {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        recovered,
        "abandoned call slot is reclaimed and stable provider recovers"
    );
    assert!(recovery_started.elapsed() < Duration::from_secs(60));
    let backlog: i64 = c.query_one("SELECT count(*) FROM deployments WHERE spec->'enabled'='false'::jsonb AND phase='reconciling'", &[]).await.unwrap().get(0);
    assert!(
        backlog > 0,
        "call recovery must not wait for the disabled sweep"
    );
    // Clean just the fixture rows (they have no instances/operations) so the
    // subsequent explicit disable operations retain their own latency budget.
    c.execute(
        "DELETE FROM deployments WHERE spec=$1",
        &[&json!({"enabled":false})],
    )
    .await
    .unwrap();
    // RUN-07: execute the shipped CLI over HTTPS against the same API, without WebUI.
    let leaf = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .signed_by(&leaf, &cert, &key)
        .unwrap();
    let server_tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        server_cert.pem().into_bytes(),
        leaf.serialize_pem().into_bytes(),
    )
    .await
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    // This real TLS listener has its own explicit trusted origin; the ordinary
    // in-process fixture above continues to use the checked-in core origin.
    let mut cli_value = app.config.value.clone();
    cli_value["server"]["public_origin"] = json!(format!("https://{address}"));
    cli_value["server"]["listen"] = json!(address.to_string());
    let cli_config = Config::from_value(cli_value).unwrap();
    let cli_app = Arc::new(App {
        runtime: Runtime::new(cli_config.clone()),
        config: cli_config,
        db: app.db.clone(),
        auth: app.auth.clone(),
        leader: app.leader.clone(),
        ready: AtomicBool::new(app.ready.load(Ordering::SeqCst)),
        shutdown: AtomicBool::new(false),
        blob_uploads: tokio::sync::Semaphore::new(4),
    });
    let cli_router = xelab_kernel::api::router(cli_app);
    let serve = tokio::spawn(
        axum_server::from_tcp_rustls(listener, server_tls)
            .serve(cli_router.into_make_service_with_connect_info::<SocketAddr>()),
    );
    let token_file = root.join("cli-token");
    fs::write(&token_file, token).unwrap();
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();
    let input_file = root.join("invoke.json");
    fs::write(&input_file, serde_json::to_vec(&python_input).unwrap()).unwrap();
    let cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_xelabctl"))
        .args([
            "api",
            "invokeCapability",
            "--endpoint",
            &format!("https://{address}"),
            "--token-file",
            token_file.to_str().unwrap(),
            "--ca-file",
            root.join("ca.crt").to_str().unwrap(),
            "--body-file",
            input_file.to_str().unwrap(),
            "--idempotency-key",
            "cli-independent-python",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_value: Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(cli_value["output"], called.1["output"]);
    serve.abort();
    // Component-only: verify the actual RUN-03 exec gate / cgroup cleanup on
    // the disposable CI plugin. This does not satisfy production host admission.
    let component = tokio::process::Command::new("python3")
        .args([
            "tools/acceptance/oci_stress_component.py",
            &python_instance.to_string(),
        ])
        .output()
        .await
        .unwrap();
    assert!(
        component.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&component.stdout),
        String::from_utf8_lossy(&component.stderr)
    );
    println!("{}", String::from_utf8_lossy(&component.stdout));
    let disabled =
        disable_after_observation(&router, &python_params, token, "disable-python").await;
    assert_eq!(disabled.0, 202, "{}", disabled.1);
    operation(&router, disabled.1["id"].as_str().unwrap(), token).await;
    let disabled = disable_after_observation(&router, &params, token, "disable-1").await;
    assert_eq!(disabled.0, 202, "{}", disabled.1);
    operation(&router, disabled.1["id"].as_str().unwrap(), token).await;
    assert!(!app.runtime.running(instance).await.unwrap());
    host_blob_component(&app, &router, token, publisher, &signing).await;
    Box::pin(m4::run(
        &app,
        &router,
        token,
        publisher,
        &signing,
        rust_installation,
        skill.parse().unwrap(),
    ))
    .await;
    assert_eq!(
        c.query_one("SELECT reserved_cpu_millis FROM node_budget", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    configure_stopped_deployment(&app, &router, &params, token, instance).await;
    // Leave one real signed, initialized workload running for the host-admin
    // offline freeze after the normal controller has relinquished leadership.
    let current = api(
        &router,
        "getDeployment",
        &params,
        Some(token),
        Value::Null,
        "offline-source-current",
        None,
    )
    .await;
    let enable = api(
        &router,
        "setDeploymentEnabled",
        &params,
        Some(token),
        json!({"enabled":true}),
        "offline-source-enable",
        current.1["revision"].as_i64(),
    )
    .await;
    assert_eq!(enable.0, 202, "{}", enable.1);
    operation(&router, enable.1["id"].as_str().unwrap(), token).await;
    upgrade_acceptance::exercise(&app, &router, token, publisher, &signing, &deployment).await;
    let source_volume = platform_source::SourceVolume::create(
        root,
        &app.config.root(),
        &db,
        owner,
        session["session"]["id"].as_str().unwrap().parse().unwrap(),
    )
    .await;
    let versioned_worker = tokio::spawn(xelab_kernel::schema_jobs::run(app.clone()));
    let mut versioned_sources = Vec::new();
    for schema in ["1", "2"] {
        versioned_sources.push(
            platform_versioned::create(&app, &router, token, publisher, &signing, schema).await,
        );
    }
    let source_deployments: std::collections::BTreeSet<Uuid> =
        std::iter::once(deployment.parse().unwrap())
            .chain(versioned_sources.iter().map(|source| source.deployment))
            .collect();
    let source_processes = offline_source_processes(&app, &source_deployments).await;
    // Withdraw the approval credential only after reconciliation has completed
    // its current mutation and stopped. Otherwise its live volume-approval
    // check must stop these writers, which cannot attest a consistent drain.
    // Do not abort a Controller between Runtime::stop and durable bookkeeping.
    app.shutdown.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(180), worker)
        .await
        .expect("source Controller did not relinquish reconciliation")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), versioned_worker)
        .await
        .expect("source schema supervisor did not stop")
        .unwrap();
    let revoke = api(
        &router,
        "revokeSession",
        &[(
            "session_id",
            session["session"]["id"].as_str().unwrap().into(),
        )],
        Some(token),
        Value::Null,
        "revoke-1",
        Some(1),
    )
    .await;
    assert_eq!(revoke.0, 204, "{}", revoke.1);
    assert_eq!(
        api(
            &router,
            "getNode",
            &[],
            Some(token),
            Value::Null,
            "read",
            None
        )
        .await
        .0,
        401
    );
    assert_eq!(
        offline_source_processes(&app, &source_deployments).await,
        source_processes,
        "offline handoff must retain the exact healthy source generations and processes"
    );
    eprintln!("Offline source handoff: Controller exited normally before approval credential revocation; all {} real ready source tasks retained exact instances, generations, PIDs and process start times after revoked-token rejection", source_processes.len());
    // The test's API App is deliberately still held by Router clones. Terminate
    // its old leader only after stopping the controller, then exercise normal
    // offline host/database lease acquisition with root-private credentials.
    let pid: i32 = app
        .leader
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    c.query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap();
    let mut offline_value = app.config.value.clone();
    for (section, key, name, bytes) in [
        (
            "database",
            "dsn_file",
            "offline.dsn",
            format!("{base} dbname=xelab_oci").into_bytes(),
        ),
        (
            "security",
            "token_hmac_key_file",
            "offline.hmac",
            vec![42; 32],
        ),
        (
            "server",
            "tls_key_file",
            "offline-server.key",
            leaf.serialize_pem().into_bytes(),
        ),
    ] {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        offline_value[section][key] = json!(path);
    }
    let offline_config = Config::from_value(offline_value).unwrap();
    match xelab_kernel::offline::Session::open(offline_config.clone(), false).await {
        Err(error) => assert_eq!(error.status.as_u16(), 400),
        Ok(_) => panic!("offline session accepted missing downtime authorization"),
    }
    assert!(
        !app.runtime.inventory().await.unwrap().is_empty(),
        "a rejected maintenance request must leave the live source alone"
    );
    let offline = Arc::new(
        xelab_kernel::offline::Session::open(offline_config, true)
            .await
            .unwrap(),
    );
    assert!(
        db.leader().await.is_err(),
        "offline session owns the database"
    );
    let frozen = offline.freeze_source().await.unwrap();
    assert!(!frozen.images().is_empty());
    assert!(!frozen.stopped_lsn().is_empty());
    let frozen_sources = frozen.volume_sources().await.unwrap();
    let expected = std::iter::once(source_volume.volume)
        .chain(versioned_sources.iter().map(|s| s.volume))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        frozen_sources
            .iter()
            .map(|s| s.id)
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    for source in &versioned_sources {
        assert_eq!(
            frozen_sources
                .iter()
                .find(|s| s.id == source.volume)
                .unwrap()
                .data_schema_version
                .as_deref(),
            Some(source.schema.as_str())
        );
    }
    assert!(matches!(
        frozen_sources
            .iter()
            .find(|s| s.id == source_volume.volume)
            .unwrap()
            .data_schema_version
            .as_deref(),
        None | Some("none")
    ));
    assert!(app.runtime.inventory().await.unwrap().is_empty());
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM instances WHERE phase<>'stopped' OR runtime_id IS NOT NULL",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let mut metadata = Vec::new();
    let summary = frozen.export_metadata(&mut metadata).await.unwrap();
    assert_eq!(summary.bytes, metadata.len() as u64);
    assert!(summary.rows > 0);
    println!("Offline source: real signed OCI Drain/stop, exclusive leases, image-index verification and consistent metadata export passed (not off-host acceptance)");
    drop(frozen);
    // Exercise the complete capture driver against the CI's real local S3
    // fixture. Its evidence remains false; no production endpoint override.
    use xelab_kernel::{
        backup_repository::Repository,
        storage::{
            backup_transfer::{self, raw},
            metadata_snapshot, s3,
        },
    };
    let endpoint =
        std::env::var("XELAB_TEST_S3_ENDPOINT").expect("real isolated test object store");
    let bucket = format!("xelab-platform-capture-{}", Uuid::new_v4().simple());
    let location = s3::Location::aws(&format!("s3://{bucket}/source/"), "us-east-1")
        .unwrap()
        .compatible(&endpoint)
        .unwrap();
    let credentials = root.join("offline-s3.json");
    fs::write(
        &credentials,
        b"{\"access_key_id\":\"xelab-test\",\"secret_access_key\":\"test-only-backup-password\"}",
    )
    .unwrap();
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600)).unwrap();
    let client =
        Arc::new(s3::Client::new(location, s3::Credentials::load(&credentials).unwrap()).unwrap());
    client.create_bucket().await.unwrap();
    let repository = Uuid::new_v4();
    let uri = format!("s3://{bucket}/source/");
    c.execute("INSERT INTO backup_repositories(id,location,region,state) VALUES($1,$2,'us-east-1','ready')",&[&repository,&uri]).await.unwrap();
    client
        .put(
            "xelab-repository.identity",
            serde_json::to_vec(&json!({"format":1,"repository_id":repository})).unwrap(),
        )
        .await
        .unwrap();
    let objects = Arc::new(
        client
            .scoped(&format!("repositories/{repository}"))
            .unwrap(),
    );
    let repo = Repository {
        id: repository,
        objects: objects.clone(),
    };
    let receipt = xelab_kernel::offline::backup::capture(
        offline.clone(),
        repo,
        zeroize::Zeroizing::new([42; 32]),
    )
    .await
    .unwrap();
    assert!(!receipt.off_host);
    let report =
        std::env::var("XELAB_PLATFORM_SOURCE_RECEIPT").expect("private source report path");
    fs::write(&report,serde_json::to_vec(&json!({"receipt":receipt,"owner_id":owner,"location":uri,"volume_id":source_volume.volume,"source_filesystem":source_volume.filesystem,"versioned_sources":versioned_sources.iter().map(|s|s.report()).collect::<Vec<_>>()})).unwrap()).unwrap();
    fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
    source_volume.destroy();
    let repo = Repository {
        id: receipt.repository_id,
        objects: objects.clone(),
    };
    let value = repo
        .read_manifest(
            receipt.backup_id,
            receipt.manifest_object,
            &[42; 32],
            &receipt.manifest_digest,
        )
        .await
        .unwrap();
    let manifest: xelab_kernel::offline::backup::Manifest = serde_json::from_value(value).unwrap();
    assert_eq!(
        manifest.metadata_summary.schema_version,
        xelab_kernel::db::SCHEMA_VERSION
    );
    assert!(manifest.metadata_summary.rows > 0);
    assert!(!manifest.installations.is_empty());
    assert!(manifest.images.is_some());
    assert!(!manifest.off_host);
    assert_eq!(manifest.volumes.len(), 3);
    for source in &versioned_sources {
        assert!(manifest
            .volumes
            .iter()
            .any(|v| v.object.volume == source.volume
                && v.data_schema_version.as_deref() == Some(source.schema.as_str())
                && v.format_binding.is_some()));
    }
    assert!(manifest.blob_count > 0);
    // Verify the actual encrypted native stream again on a fresh private file.
    let private = tempfile::NamedTempFile::new_in(root).unwrap();
    let target = raw::Target::new(private.reopen().unwrap()).unwrap();
    let pool = backup_transfer::Pool::default().raw(None);
    let restored = pool
        .download_file(
            objects.clone(),
            target,
            raw::Object {
                backup: receipt.backup_id,
                object: manifest.metadata.object,
                maximum_bytes: manifest.metadata.plaintext.bytes,
            },
            zeroize::Zeroizing::new([42; 32]),
            raw::Expected {
                plaintext: manifest.metadata.plaintext.clone(),
                ciphertext: manifest.metadata.ciphertext.clone(),
            },
            Duration::from_secs(300),
        )
        .unwrap()
        .wait()
        .await
        .unwrap();
    assert!(!restored.verified.off_host);
    admin
        .batch_execute("CREATE DATABASE xelab_oci_metadata_readback")
        .await
        .unwrap();
    let recovered = Db::new(format!("{base} dbname=xelab_oci_metadata_readback")).unwrap();
    recovered.migrate().await.unwrap();
    let mut restored_client = recovered.connect().await.unwrap();
    let recovery = Uuid::new_v4();
    restored_client.execute("INSERT INTO platform_recovery_state(recovery_id,backup_id,phase) VALUES($1,$2,'importing')",&[&recovery,&receipt.backup_id]).await.unwrap();
    let mut metadata_file = tokio::fs::File::from_std(restored.file);
    metadata_snapshot::import(
        &mut restored_client,
        &mut metadata_file,
        &manifest.metadata_summary,
        recovery,
        owner,
        "new offline recovery acceptance password",
    )
    .await
    .unwrap();
    let recovered_skill=restored_client.query_one("SELECT s.id,s.definition,s.definition_digest,s.installation_id,s.enabled,n.state,p.status FROM skills s JOIN installations n ON n.id=s.installation_id JOIN publishers p ON p.id=n.publisher_id WHERE s.id=$1", &[&skill.parse::<Uuid>().unwrap()]).await.unwrap();
    assert_eq!(recovered_skill.get::<_, Uuid>("id").to_string(), skill);
    assert_eq!(
        recovered_skill.get::<_, Value>("definition"),
        registered_skill.1["definition"]
    );
    assert_eq!(
        recovered_skill.get::<_, String>("definition_digest"),
        registered_skill.1["definition_digest"].as_str().unwrap()
    );
    assert_eq!(
        recovered_skill
            .get::<_, Uuid>("installation_id")
            .to_string(),
        registered_skill.1["installation_id"].as_str().unwrap()
    );
    assert!(
        recovered_skill.get::<_, bool>("enabled"),
        "saved Skill intent is history, not authority"
    );
    assert_eq!(
        recovered_skill.get::<_, String>("status"),
        "revoked",
        "restored Skill must not revive publisher trust"
    );
    let recovered_auth = Auth::new(vec![42; 32]).unwrap();
    assert!(
        recovered_auth
            .authenticate(
                &restored_client,
                token,
                "127.0.0.1".parse().unwrap(),
                Uuid::new_v4()
            )
            .await
            .is_err(),
        "restored Skill cannot revive old credentials"
    );
    assert_eq!(
        restored_client
            .query_one(
                "SELECT count(*) FROM deployments WHERE spec->>'enabled'='true'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(
        recovered.check().await.is_err(),
        "physical recovery is still incomplete; metadata import must not open the gate"
    );
    let rows = restored_client
        .query("SELECT id,size_bytes,digest FROM blobs ORDER BY id", &[])
        .await
        .unwrap();
    assert_eq!(rows.len() as u64, manifest.blob_count);
    for row in rows {
        let id: Uuid = row.get("id");
        let bytes: i64 = row.get("size_bytes");
        let digest: String = row.get("digest");
        let private = tempfile::NamedTempFile::new_in(root).unwrap();
        let restored = pool
            .download_file(
                objects.clone(),
                raw::Target::new(private.reopen().unwrap()).unwrap(),
                raw::Object {
                    backup: receipt.backup_id,
                    object: id,
                    maximum_bytes: bytes as u64,
                },
                zeroize::Zeroizing::new([42; 32]),
                raw::Expected {
                    plaintext: xelab_kernel::storage::backup_crypto::Summary {
                        bytes: bytes as u64,
                        digest,
                    },
                    ciphertext: None,
                },
                Duration::from_secs(300),
            )
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert!(!restored.verified.off_host);
    }
    println!("Platform source capture: native metadata, actual OCI and exact Blob objects uploaded and remotely verified; compatible fixture off_host=false (not whole-host restore acceptance)");
}

fn counter(path: &std::path::Path, name: &str) -> u64 {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == name).then(|| value.parse().unwrap())
        })
        .unwrap()
}
async fn exec_python(instance: Uuid, script: &str) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("/usr/bin/ctr")
            .args([
                "--namespace",
                "xelab-ci",
                "tasks",
                "exec",
                "--exec-id",
                &Uuid::new_v4().to_string(),
                &instance.to_string(),
                "/usr/bin/python3",
                "-c",
                script,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn grant_source_budget(router: &Router, db: &Db, owner: Uuid, token: &str, input: &Value) {
    let c = db.connect().await.unwrap();
    let parent = Uuid::new_v4();
    let password = "grant budget acceptance password";
    let hash = auth::password_hash(password).unwrap();
    // Trusted fixture root with one replaceable grant, not another Owner.
    c.execute("INSERT INTO accounts(id,kind,status,display_name,password_hash,created_at,updated_at) VALUES($1,'user','active','budget parent',$2,now(),now())", &[&parent,&hash]).await.unwrap();
    c.execute("INSERT INTO account_closure VALUES($1,$1,0)", &[&parent])
        .await
        .unwrap();
    c.execute("INSERT INTO quotas(account_id,spec,daily_bucket,created_at,updated_at) SELECT $1,spec,current_date,now(),now() FROM quotas WHERE account_id=$2", &[&parent,&owner]).await.unwrap();
    let scope = json!({"kind":"capability","match":"ids","ids":["org.xelab.echo@1.0.0"]});
    let grant_body = json!({"source":"role","role_id":"Guest","scope":scope});
    let old = api(
        router,
        "createGrant",
        &[("account_id", parent.to_string())],
        Some(token),
        grant_body.clone(),
        "parent-old",
        None,
    )
    .await;
    assert_eq!(old.0, 201, "{}", old.1);
    let login = api(
        router,
        "login",
        &[],
        None,
        json!({"account_id":parent,"password":password}),
        "parent-login",
        None,
    )
    .await;
    assert_eq!(login.0, 200, "{}", login.1);
    let parent_token = login.1["access_token"].as_str().unwrap();
    let child = api(
        router,
        "createChildAccount",
        &[("account_id", parent.to_string())],
        Some(parent_token),
        json!({"display_name":"budget child","inheritance":{"mode":"all_snapshot"}}),
        "budget-child",
        None,
    )
    .await;
    assert_eq!(child.0, 201, "{}", child.1);
    let child_id = contracts::id(&child.1["account"], "id").unwrap();
    let activated = api(
        router,
        "activateAccount",
        &[],
        None,
        json!({"activation_token":child.1["activation_token"],"password":password}),
        "child-activate",
        None,
    )
    .await;
    assert_eq!(activated.0, 200, "{}", activated.1);
    let login = api(
        router,
        "login",
        &[],
        None,
        json!({"account_id":child_id,"password":password}),
        "child-login",
        None,
    )
    .await;
    assert_eq!(login.0, 200, "{}", login.1);
    let session = login.1["access_token"].as_str().unwrap();
    let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
    let key = api(router,"createApiKey",&[("account_id",owner.to_string())],Some(token),json!({"name":"grant issuer one call","inheritance":{"mode":"all_snapshot"},"conditions":{"expires_at":expiry,"max_calls":1}}),"grant-key",None).await;
    assert_eq!(key.0, 201, "{}", key.1);
    let key_id = contracts::id(&key.1["credential"], "id").unwrap();
    let mut delegated = grant_body.clone();
    delegated["expires_at"] = json!(expiry);
    let grant = api(
        router,
        "createGrant",
        &[("account_id", child_id.to_string())],
        Some(key.1["secret"].as_str().unwrap()),
        delegated,
        "limited-grant",
        None,
    )
    .await;
    assert_eq!(grant.0, 201, "{}", grant.1);
    // Withdraw the frozen inherited source, then restore the parent's ceiling
    // with an independent replacement. Only the child's direct grant survives.
    let revoked = api(
        router,
        "revokeGrant",
        &[("grant_id", old.1["id"].as_str().unwrap().into())],
        Some(token),
        Value::Null,
        "old-revoke",
        Some(1),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let replacement = api(
        router,
        "createGrant",
        &[("account_id", parent.to_string())],
        Some(token),
        grant_body.clone(),
        "parent-new",
        None,
    )
    .await;
    assert_eq!(replacement.0, 201, "{}", replacement.1);
    let first = api(
        router,
        "invokeCapability",
        &[],
        Some(session),
        input.clone(),
        "grant-call",
        None,
    )
    .await;
    assert_eq!(first.0, 200, "{}", first.1);
    let replay = api(
        router,
        "invokeCapability",
        &[],
        Some(session),
        input.clone(),
        "grant-call",
        None,
    )
    .await;
    assert_eq!(replay.0, 200, "{}", replay.1);
    assert_eq!(first.1["call_id"], replay.1["call_id"]);
    let second = api(
        router,
        "invokeCapability",
        &[],
        Some(session),
        input.clone(),
        "grant-call-again",
        None,
    )
    .await;
    assert_eq!(second.0, 409, "{}", second.1);
    assert_eq!(second.1["error"]["code"], "QUOTA_EXCEEDED");
    assert_eq!(
        xelab_kernel::identity::key_calls(&c, key_id).await.unwrap(),
        1
    );
    // An exhausted alternative cannot block or charge an independent grant.
    let independent = api(
        router,
        "createGrant",
        &[("account_id", child_id.to_string())],
        Some(token),
        grant_body,
        "independent-grant",
        None,
    )
    .await;
    assert_eq!(independent.0, 201, "{}", independent.1);
    let allowed = api(
        router,
        "invokeCapability",
        &[],
        Some(session),
        input.clone(),
        "independent-call",
        None,
    )
    .await;
    assert_eq!(allowed.0, 200, "{}", allowed.1);
    assert_eq!(
        xelab_kernel::identity::key_calls(&c, key_id).await.unwrap(),
        1
    );
    let revoke = api(
        router,
        "revokeGrant",
        &[("grant_id", independent.1["id"].as_str().unwrap().into())],
        Some(token),
        Value::Null,
        "independent-revoke",
        Some(1),
    )
    .await;
    assert_eq!(revoke.0, 204, "{}", revoke.1);
    let revoke = api(
        router,
        "revokeApiKey",
        &[("credential_id", key_id.to_string())],
        Some(token),
        Value::Null,
        "source-key-revoke",
        Some(1),
    )
    .await;
    assert_eq!(revoke.0, 204, "{}", revoke.1);
    let denied = api(
        router,
        "invokeCapability",
        &[],
        Some(session),
        input.clone(),
        "grant-call",
        None,
    )
    .await;
    assert_eq!(denied.0, 403, "{}", denied.1);
    assert_eq!(
        xelab_kernel::identity::key_calls(&c, key_id).await.unwrap(),
        1,
        "revocation never refunds used budget"
    );
}

async fn blob_http(
    router: &Router,
    operation: &str,
    token: &str,
    id: Option<&str>,
    data: &[u8],
) -> (u16, Vec<u8>) {
    let (mut path, method) = contracts::openapi()["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(p, ms)| ms.as_object().unwrap().iter().map(move |(m, s)| (p, m, s)))
        .find(|(_, _, s)| s["operationId"] == operation)
        .map(|(p, m, _)| (p.clone(), m.to_uppercase()))
        .unwrap();
    if let Some(id) = id {
        path = path.replace("{blob_id}", id);
    }
    let mut request = Request::builder()
        .header("host", http_host::authority(None))
        .method(method.as_str())
        .header("authorization", format!("Bearer {token}"));
    if operation == "uploadBlob" {
        path.push_str("?content_type=application%2Foctet-stream");
        request = request
            .header("content-type", "application/octet-stream")
            .header("content-length", data.len())
            .header("x-content-sha256", contracts::digest(data))
            .header("idempotency-key", Uuid::new_v4().to_string());
    }
    let mut request = request.uri(path).body(Body::from(data.to_vec())).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:30000".parse::<SocketAddr>().unwrap(),
    ));
    let response = router.clone().oneshot(request).await.unwrap();
    (
        response.status().as_u16(),
        to_bytes(response.into_body(), 67108865)
            .await
            .unwrap()
            .to_vec(),
    )
}
async fn host_blob_component(
    app: &Arc<App>,
    router: &Router,
    token: &str,
    publisher: Uuid,
    signing: &SigningKey,
) {
    let raw = fs::read("examples/generated-host-blob/xelab/plugin.json").unwrap();
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    let image = std::env::var("XELAB_TEST_HOST_BLOB_IMAGE").unwrap();
    let envelope =
        artifact::signature_envelope(&manifest, artifact::image_ref(&image).unwrap(), &raw)
            .unwrap();
    let install=api(router,"installPlugin",&[],Some(token),json!({"publisher_id":publisher,"image":image,"signature":STANDARD.encode(signing.sign(envelope.as_bytes()).to_bytes())}),"host-blob-install",None).await;
    assert_eq!(install.0, 202, "{}", install.1);
    let installed = operation(router, install.1["id"].as_str().unwrap(), token).await;
    let created=api(router,"createDeployment",&[],Some(token),json!({"installation_id":installed["installation_id"],"display_name":"Host Blob component","enabled":false,"limits":{"cpu_millis":100,"memory_bytes":67108864,"ephemeral_bytes":1048576,"pids":64},"config":{},"volume_ids":[]}),"host-blob-deploy",None).await;
    assert_eq!(created.0, 202, "{}", created.1);
    let deployment = operation(router, created.1["id"].as_str().unwrap(), token).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let params = [("deployment_id", deployment.clone())];
    let approval = json!({"rules":[{"action":"blob.read","resource":{"kind":"blob","match":"all"}},{"action":"blob.create","resource":{"kind":"blob","match":"all"}}],"egress":[]});
    let approved = api(
        router,
        "approvePlugin",
        &params,
        Some(token),
        approval,
        "host-blob-approve",
        Some(1),
    )
    .await;
    assert_eq!(approved.0, 200, "{}", approved.1);
    let enabled = api(
        router,
        "setDeploymentEnabled",
        &params,
        Some(token),
        json!({"enabled":true}),
        "host-blob-enable",
        Some(2),
    )
    .await;
    assert_eq!(enabled.0, 202, "{}", enabled.1);
    operation(router, enabled.1["id"].as_str().unwrap(), token).await;
    let source = b"source bytes for the actual OCI Blob proxy";
    let uploaded = blob_http(router, "uploadBlob", token, None, source).await;
    assert_eq!(uploaded.0, 201, "{}", String::from_utf8_lossy(&uploaded.1));
    let source_meta: Value = serde_json::from_slice(&uploaded.1).unwrap();
    let host = tokio::spawn(xelab_kernel::host::serve(app.clone()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let input = json!({"contract":manifest["capabilities"][0]["contract"],"input":{"message":"OCI-created Blob","blob_id":source_meta["id"],"export":true},"provider_deployment_id":deployment,"timeout_ms":10000});
    let invoked = api(
        router,
        "invokeCapability",
        &[],
        Some(token),
        input.clone(),
        "host-blob-invoke",
        None,
    )
    .await;
    assert_eq!(invoked.0, 200, "{}", invoked.1);
    let output = &invoked.1["output"];
    assert_eq!(output["source_digest"], contracts::digest(source));
    assert_eq!(
        output["blob"]["digest"],
        contracts::digest(b"OCI-created Blob")
    );
    let downloaded = blob_http(
        router,
        "downloadBlob",
        token,
        output["blob"]["blob_id"].as_str(),
        b"",
    )
    .await;
    assert_eq!(downloaded.0, 200);
    assert_eq!(downloaded.1, b"OCI-created Blob");
    let replay = api(
        router,
        "invokeCapability",
        &[],
        Some(token),
        input,
        "host-blob-invoke",
        None,
    )
    .await;
    assert_eq!(replay.1, invoked.1);
    let c = app.db.connect().await.unwrap();
    let call: Uuid = invoked.1["call_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM host_blob_outputs WHERE call_id=$1",
            &[&call]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    host.abort();
    let _ = host.await;
    let current = api(
        router,
        "getDeployment",
        &params,
        Some(token),
        Value::Null,
        "host-blob-read",
        None,
    )
    .await;
    let disabled = api(
        router,
        "setDeploymentEnabled",
        &params,
        Some(token),
        json!({"enabled":false}),
        "host-blob-disable",
        current.1["revision"].as_i64(),
    )
    .await;
    assert_eq!(disabled.0, 202, "{}", disabled.1);
    operation(router, disabled.1["id"].as_str().unwrap(), token).await;
    println!("Host Blob: actual signed OCI -> delegated ReadBlob/WriteBlob -> verified HTTP download and call replay passed");
}

// This helper exercises the new registry/router with the signed artifact already
// verified and actually running above. It deliberately uses the public API for
// registration, permissions, enable/disable, replay and credential revocation.
#[allow(clippy::too_many_arguments)]
async fn ordinary_skill_lifecycle(
    router: &Router,
    db: &Db,
    owner: Uuid,
    token: &str,
    installation: &Value,
    manifest: &Value,
    prior_capability_call: &Value,
    deployment: &str,
) -> String {
    let register = json!({"installation_id":installation,"definition":manifest["skills"][0]});
    let mut unsigned = register.clone();
    unsigned["definition"]["description"] = json!("not covered by the original signed image");
    let unsigned = api(
        router,
        "registerSkill",
        &[],
        Some(token),
        unsigned,
        "skill-unsigned-candidate",
        None,
    )
    .await;
    assert_eq!(unsigned.0, 409, "{}", unsigned.1);
    assert_eq!(unsigned.1["error"]["code"], "CONTRACT_CONFLICT");
    let created = api(
        router,
        "registerSkill",
        &[],
        Some(token),
        register.clone(),
        "skill-register",
        None,
    )
    .await;
    assert_eq!(created.0, 201, "{}", created.1);
    contracts::validate("Skill", &created.1).unwrap();
    let skill = created.1["id"].as_str().unwrap().to_owned();
    let params = [("skill_id", skill.clone())];
    let request = json!({"input":{"message":"real Skill over OCI"},"timeout_ms":10000,"idempotency_key":"stable-skill-business-key"});
    let disabled = api(
        router,
        "invokeSkill",
        &params,
        Some(token),
        request.clone(),
        "skill-disabled",
        None,
    )
    .await;
    assert_eq!(disabled.0, 503, "{}", disabled.1);
    let enabled = api(
        router,
        "setSkillEnabled",
        &params,
        Some(token),
        json!({"enabled":true}),
        "skill-enable",
        Some(1),
    )
    .await;
    assert_eq!(enabled.0, 200, "{}", enabled.1);
    let skill_rule =
        json!({"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[skill]}});
    let cap = &manifest["capabilities"][0]["contract"];
    let capability_rule = json!({"action":"capability.invoke","resource":{"kind":"capability","match":"ids","ids":[format!("{}@{}",cap["name"].as_str().unwrap(),cap["version"].as_str().unwrap())]}});
    for (index, rules) in [json!([skill_rule]), json!([capability_rule])]
        .into_iter()
        .enumerate()
    {
        let key=api(router,"createApiKey",&[("account_id",owner.to_string())],Some(token),json!({"name":"one Skill permission layer","inheritance":{"mode":"selected","rules":rules},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),&format!("skill-one-layer-{index}"),None).await;
        assert_eq!(key.0, 201, "{}", key.1);
        let refused = api(
            router,
            "invokeSkill",
            &params,
            Some(key.1["secret"].as_str().unwrap()),
            request.clone(),
            "one-layer-call",
            None,
        )
        .await;
        assert_eq!(refused.0, 403, "{}", refused.1);
    }
    let key=api(router,"createApiKey",&[("account_id",owner.to_string())],Some(token),json!({"name":"fixed Skill caller","inheritance":{"mode":"selected","rules":[skill_rule,capability_rule]},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),"skill-caller-key",None).await;
    assert_eq!(key.0, 201, "{}", key.1);
    let caller = key.1["secret"].as_str().unwrap();
    // The same HTTP key used by the earlier bare capability call cannot collide
    // with this Skill-specific endpoint's idempotency namespace.
    let called = api(
        router,
        "invokeSkill",
        &params,
        Some(token),
        request.clone(),
        "invoke-1",
        None,
    )
    .await;
    assert_eq!(called.0, 200, "{}", called.1);
    contracts::validate("SkillCallResult", &called.1).unwrap();
    assert_eq!(called.1["call"]["skill_id"], called.1["skill_id"]);
    assert_eq!(
        called.1["call"]["skill_definition_digest"],
        called.1["definition_digest"]
    );
    let recorded = api(
        router,
        "getCall",
        &[(
            "call_id",
            called.1["call"]["call_id"].as_str().unwrap().to_owned(),
        )],
        Some(token),
        Value::Null,
        "read-skill-call",
        None,
    )
    .await;
    assert_eq!(recorded.0, 200, "{}", recorded.1);
    assert_eq!(recorded.1["result"], called.1["call"]);
    assert_ne!(
        called.1["call"]["call_id"],
        prior_capability_call["call_id"]
    );
    assert_eq!(
        called.1["call"]["provider_instance_id"],
        prior_capability_call["provider_instance_id"]
    );
    assert_eq!(called.1["call"]["output"]["message"], "real Skill over OCI");
    let replay = api(
        router,
        "invokeSkill",
        &params,
        Some(token),
        request.clone(),
        "invoke-1",
        None,
    )
    .await;
    assert_eq!(replay, called);
    let mut changed = request.clone();
    changed["input"]["message"] = json!("different");
    let conflict = api(
        router,
        "invokeSkill",
        &params,
        Some(token),
        changed,
        "invoke-1",
        None,
    )
    .await;
    assert_eq!(conflict.0, 409, "{}", conflict.1);
    let scoped = api(
        router,
        "invokeSkill",
        &params,
        Some(caller),
        request.clone(),
        "scoped-skill-call",
        None,
    )
    .await;
    assert_eq!(scoped.0, 200, "{}", scoped.1);
    let c = db.connect().await.unwrap();
    let journal=c.query_one("SELECT c.skill_id,c.skill_definition_digest,d.installation_id,c.idempotency_key FROM calls c JOIN instances i ON i.id=c.provider_instance_id JOIN deployments d ON d.id=i.deployment_id WHERE c.id=$1",&[&scoped.1["call"]["call_id"].as_str().unwrap().parse::<Uuid>().unwrap()]).await.unwrap();
    assert_eq!(journal.get::<_, String>(3), "stable-skill-business-key");
    assert_eq!(journal.get::<_, Uuid>(0).to_string(), skill);
    assert_eq!(
        journal.get::<_, String>(1),
        created.1["definition_digest"].as_str().unwrap()
    );
    assert_eq!(
        journal.get::<_, Uuid>(2).to_string(),
        installation.as_str().unwrap()
    );
    let before = c
        .query_one(
            "SELECT concurrent_calls_used,daily_calls_used,spec FROM quotas WHERE account_id=$1",
            &[&owner],
        )
        .await
        .unwrap();
    let mut exhausted: Value = before.get(2);
    exhausted["maximum_concurrent_calls"] = json!(0);
    c.execute(
        "UPDATE quotas SET spec=$2 WHERE account_id=$1",
        &[&owner, &exhausted],
    )
    .await
    .unwrap();
    let denied = api(
        router,
        "invokeSkill",
        &params,
        Some(token),
        request.clone(),
        "skill-quota-exhausted",
        None,
    )
    .await;
    assert_eq!(denied.0, 503, "{}", denied.1);
    assert_eq!(denied.1["error"]["code"], "RESOURCE_EXHAUSTED");
    let after = c
        .query_one(
            "SELECT concurrent_calls_used,daily_calls_used FROM quotas WHERE account_id=$1",
            &[&owner],
        )
        .await
        .unwrap();
    assert_eq!(after.get::<_, i64>(0), before.get::<_, i64>(0));
    assert_eq!(after.get::<_, i64>(1), before.get::<_, i64>(1));
    c.execute(
        "UPDATE quotas SET spec=$2 WHERE account_id=$1",
        &[&owner, &before.get::<_, Value>(2)],
    )
    .await
    .unwrap();
    let off = api(
        router,
        "setSkillEnabled",
        &params,
        Some(token),
        json!({"enabled":false}),
        "skill-disable",
        enabled.1["revision"].as_i64(),
    )
    .await;
    assert_eq!(off.0, 200, "{}", off.1);
    let denied = api(
        router,
        "invokeSkill",
        &params,
        Some(caller),
        request.clone(),
        "skill-after-disable",
        None,
    )
    .await;
    assert_eq!(denied.0, 503, "{}", denied.1);
    let on = api(
        router,
        "setSkillEnabled",
        &params,
        Some(token),
        json!({"enabled":true}),
        "skill-reenable",
        off.1["revision"].as_i64(),
    )
    .await;
    assert_eq!(on.0, 200, "{}", on.1);
    let restored = api(
        router,
        "invokeSkill",
        &params,
        Some(caller),
        request.clone(),
        "skill-restored",
        None,
    )
    .await;
    assert_eq!(restored.0, 200, "{}", restored.1);
    let revoked = api(
        router,
        "revokeApiKey",
        &[(
            "credential_id",
            key.1["credential"]["id"].as_str().unwrap().into(),
        )],
        Some(token),
        Value::Null,
        "skill-revoke-key",
        key.1["credential"]["revision"].as_i64(),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let denied = api(
        router,
        "invokeSkill",
        &params,
        Some(caller),
        request,
        "skill-restored",
        None,
    )
    .await;
    assert_eq!(
        denied.0, 401,
        "replay must reauthenticate revoked callers: {}",
        denied.1
    );
    // Keep the registration enabled so the caller tests it after controller
    // restart, while all routes retain this exact installation binding.
    assert!(!deployment.is_empty());
    skill
}

// Capture the actual task PID and start time so a released ledger row alone
// cannot be mistaken for proof that the previous OCI process stopped.
async fn stream_process(app: &App, instance: Uuid) -> (u32, String) {
    let tasks = String::from_utf8(
        app.runtime
            .ctr(&["tasks".into(), "list".into()])
            .await
            .unwrap(),
    )
    .unwrap();
    let pid = tasks
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 3 && fields[0] == instance.to_string() && fields[2] == "RUNNING")
                .then(|| fields[1].parse::<u32>().unwrap())
        })
        .expect("a healthy provider must have a real running OCI task");
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let started = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_owned();
    (pid, started)
}

// This is an observation of real tasks, never a provider/heartbeat fixture.
// Include every live SQL identity so a stale draining historical instance
// cannot be silently omitted from the offline source's consistency boundary.
#[derive(Debug, PartialEq, Eq)]
struct OfflineSourceProcess {
    deployment: Uuid,
    generation: i64,
    process: (u32, String),
}

async fn offline_source_processes(
    app: &App,
    expected_deployments: &std::collections::BTreeSet<Uuid>,
) -> std::collections::BTreeMap<Uuid, OfflineSourceProcess> {
    let c = app.db.connect().await.unwrap();
    let rows = c.query("SELECT id,deployment_id,generation,phase FROM instances i WHERE phase<>'stopped' OR EXISTS(SELECT 1 FROM volume_attachments a WHERE a.instance_id=i.id) ORDER BY id", &[]).await.unwrap();
    let mut processes = std::collections::BTreeMap::new();
    let mut deployments = std::collections::BTreeSet::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let deployment: Uuid = row.get("deployment_id");
        let generation: i64 = row.get("generation");
        let phase: String = row.get("phase");
        assert_eq!(phase, "ready", "offline source instance {id} deployment {deployment} generation {generation} must be healthy");
        if !app.runtime.running(id).await.unwrap() {
            let tasks = app.runtime.ctr(&["tasks".into(), "list".into()]).await;
            let summary = tasks.as_ref().map(|bytes| {
                String::from_utf8_lossy(bytes)
                    .chars()
                    .take(4096)
                    .collect::<String>()
            });
            panic!("offline source instance {id} deployment {deployment} generation {generation} exited before handoff; bounded task inventory: {summary:?}");
        }
        assert!(
            deployments.insert(deployment),
            "offline source has multiple current instances for deployment {deployment}"
        );
        processes.insert(
            id,
            OfflineSourceProcess {
                deployment,
                generation,
                process: stream_process(app, id).await,
            },
        );
    }
    assert_eq!(&deployments, expected_deployments);
    let actual: std::collections::BTreeSet<_> =
        app.runtime.inventory().await.unwrap().into_iter().collect();
    assert_eq!(actual, processes.keys().copied().collect());
    processes
}

fn stream_process_exited(process: &(u32, String)) -> bool {
    match fs::read_to_string(format!("/proc/{}/stat", process.0)) {
        Ok(stat) => {
            stat.rsplit_once(") ")
                .unwrap()
                .1
                .split_whitespace()
                .nth(19)
                .unwrap()
                != process.1
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => panic!("cannot verify the old OCI process: {error}"),
    }
}
struct StreamRecovery<'a> {
    app: &'a App,
    router: &'a Router,
    db: &'a Db,
    token: &'a str,
    skill: &'a str,
}
impl StreamRecovery<'_> {
    async fn fence_and_ready(
        &self,
        calls: &[Uuid],
        instance: Uuid,
        old_process: &(u32, String),
        key: &str,
    ) -> (Uuid, bool) {
        let c = self.db.connect().await.unwrap();
        let origin = c.query_one("SELECT i.deployment_id,i.generation,d.installation_id,c.owner_id FROM calls c JOIN instances i ON i.id=c.provider_instance_id JOIN deployments d ON d.id=i.deployment_id WHERE c.id=$1 AND i.id=$2", &[&calls[0], &instance]).await.unwrap();
        let deployment: Uuid = origin.get("deployment_id");
        let owner: Uuid = origin.get("owner_id");
        let mut released = false;
        for _ in 0..120 {
            let count: i64 = c.query_one("SELECT count(*) FROM calls c JOIN reservations r ON r.id=c.id WHERE c.id=ANY($1) AND c.provider_instance_id=$2 AND c.state='unknown' AND r.status='released' AND NOT EXISTS(SELECT 1 FROM rpc_delegations d WHERE d.call_id=c.id AND d.status='active') AND NOT EXISTS(SELECT 1 FROM execution_delegations e WHERE e.id=c.delegation_id AND e.status='active')", &[&calls, &instance]).await.unwrap().get(0);
            if count == calls.len() as i64 && stream_process_exited(old_process) {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(released, "{key}: unknown calls must release only after the old OCI process exits and delegation is revoked");
        assert_eq!(
            c.query_one(
                "SELECT concurrent_calls_used FROM quotas WHERE account_id=$1",
                &[&owner]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0,
            "{key}: fenced calls cannot leak concurrent quota"
        );
        let mut exhausted = false;
        let mut settled = false;
        for _ in 0..120 {
            let row = c.query_one("SELECT i.phase,i.restart_count,EXISTS(SELECT 1 FROM provider_records p WHERE p.instance_id=i.id AND p.availability='ready') AS ready FROM instances i WHERE i.id=$1", &[&instance]).await.unwrap();
            if row.get::<_, String>("phase") == "ready" && row.get::<_, bool>("ready") {
                settled = true;
                break;
            }
            if row.get::<_, String>("phase") == "failed" && row.get::<_, i32>("restart_count") >= 5
            {
                settled = true;
                exhausted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(settled, "{key}: the provider must become ready or explicitly refuse its exhausted restart budget");
        if !exhausted {
            return (instance, false);
        }
        assert!(!self.app.runtime.running(instance).await.unwrap());
        assert_eq!(c.query_one("SELECT count(*) FROM provider_records WHERE instance_id=$1 AND availability='ready'", &[&instance]).await.unwrap().get::<_, i64>(0), 0);
        let before = c.query_one("SELECT (SELECT count(*) FROM calls) AS calls,daily_calls_used FROM quotas WHERE account_id=$1", &[&owner]).await.unwrap();
        let refused = stream_skill_request(self.router, self.token, self.skill, &json!({"input":{"message":"restart budget must remain closed","count":1},"timeout_ms":10000}), &format!("{key}-budget-refused"), false).await;
        assert_eq!(
            refused.status(),
            503,
            "restart budget cannot admit new work"
        );
        let refused: Value =
            serde_json::from_slice(&to_bytes(refused.into_body(), 1048576).await.unwrap()).unwrap();
        assert_eq!(refused["error"]["code"], "NOT_READY");
        let after = c.query_one("SELECT (SELECT count(*) FROM calls) AS calls,daily_calls_used FROM quotas WHERE account_id=$1", &[&owner]).await.unwrap();
        assert_eq!(before.get::<_, i64>("calls"), after.get::<_, i64>("calls"));
        assert_eq!(
            before.get::<_, i64>("daily_calls_used"),
            after.get::<_, i64>("daily_calls_used")
        );
        let params = [("deployment_id", deployment.to_string())];
        let disabled = disable_after_observation(
            self.router,
            &params,
            self.token,
            &format!("{key}-budget-disable"),
        )
        .await;
        assert_eq!(disabled.0, 202, "{}", disabled.1);
        operation(self.router, disabled.1["id"].as_str().unwrap(), self.token).await;
        let current = api(
            self.router,
            "getDeployment",
            &params,
            Some(self.token),
            Value::Null,
            &format!("{key}-budget-current"),
            None,
        )
        .await;
        assert_eq!(current.0, 200, "{}", current.1);
        assert_eq!(current.1["phase"], "disabled");
        let enabled = api(
            self.router,
            "setDeploymentEnabled",
            &params,
            Some(self.token),
            json!({"enabled":true}),
            &format!("{key}-budget-enable"),
            current.1["revision"].as_i64(),
        )
        .await;
        assert_eq!(enabled.0, 202, "{}", enabled.1);
        operation(self.router, enabled.1["id"].as_str().unwrap(), self.token).await;
        let fresh = c.query_one("SELECT i.id,i.generation,d.installation_id FROM instances i JOIN deployments d ON d.id=i.deployment_id WHERE i.deployment_id=$1 AND i.phase='ready' AND EXISTS(SELECT 1 FROM provider_records p WHERE p.instance_id=i.id AND p.availability='ready')", &[&deployment]).await.unwrap();
        let fresh_id: Uuid = fresh.get("id");
        assert_ne!(fresh_id, instance);
        assert!(fresh.get::<_, i64>("generation") > origin.get::<_, i64>("generation"));
        assert_eq!(
            fresh.get::<_, Uuid>("installation_id"),
            origin.get::<_, Uuid>("installation_id")
        );
        assert_eq!(
            c.query_one("SELECT phase FROM instances WHERE id=$1", &[&instance])
                .await
                .unwrap()
                .get::<_, String>(0),
            "stopped"
        );
        assert_eq!(
            c.query_one(
                "SELECT count(*) FROM instances WHERE deployment_id=$1 AND phase<>'stopped'",
                &[&deployment]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        stream_process(self.app, fresh_id).await;
        println!("{key}: restart budget refused new work without charge; public disable/enable created fresh signed generation");
        (fresh_id, true)
    }
}

// A real signed OCI stream crosses the public API, core Skill router and mTLS
// CapabilityService; this helper does not synthesize plugin responses.
async fn ordinary_skill_stream_lifecycle(
    app: &App,
    router: &Router,
    db: &Db,
    token: &str,
    installation: &Value,
    manifest: &Value,
) -> Uuid {
    let created = api(
        router,
        "registerSkill",
        &[],
        Some(token),
        json!({"installation_id":installation,"definition":manifest["skills"][1],"enabled":true}),
        "stream-skill-register",
        None,
    )
    .await;
    assert_eq!(created.0, 201, "{}", created.1);
    let skill = created.1["id"].as_str().unwrap();
    let request = json!({"input":{"message":"stream over real OCI","count":3},"timeout_ms":10000});
    let response = stream_skill_request(router, token, skill, &request, "real-stream", false).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let events = collect_skill_events(response.into_body()).await;
    assert_eq!(events.len(), 5);
    assert_eq!(events[0]["skill_id"], skill);
    assert_eq!(events[0]["skill_version"], manifest["skills"][1]["version"]);
    assert_eq!(
        events[0]["definition_digest"],
        created.1["definition_digest"]
    );
    assert_eq!(events[0]["event"]["kind"], "accepted");
    for index in 0..3 {
        assert_eq!(events[index + 1]["event"]["kind"], "item");
        assert_eq!(events[index + 1]["event"]["payload"]["index"], index);
    }
    assert_eq!(events[4]["event"]["kind"], "completed");
    assert_eq!(
        events[4]["event"]["payload"]["output"],
        json!({"message":"stream over real OCI"})
    );
    assert_eq!(events[4]["event"]["payload"]["skill_id"], skill);
    assert_eq!(
        events[4]["event"]["payload"]["skill_definition_digest"],
        created.1["definition_digest"]
    );
    let call = events[0]["event"]["call_id"].as_str().unwrap();
    let replay = stream_skill_request(router, token, skill, &request, "real-stream", false).await;
    assert_eq!(
        replay.status(),
        409,
        "streams cannot regenerate items on HTTP replay"
    );
    let replay: Value =
        serde_json::from_slice(&to_bytes(replay.into_body(), 1048576).await.unwrap()).unwrap();
    assert_eq!(replay["error"]["resource_id"], call);
    let resumed =
        stream_skill_request(router, token, skill, &request, "last-event-refused", true).await;
    assert_eq!(resumed.status(), 400);
    let record = api(
        router,
        "getCall",
        &[("call_id", call.into())],
        Some(token),
        Value::Null,
        "stream-get-result",
        None,
    )
    .await;
    assert_eq!(record.0, 200);
    assert_eq!(record.1["state"], "succeeded");
    let recovery = StreamRecovery {
        app,
        router,
        db,
        token,
        skill,
    };
    let mut live_instance = record.1["result"]["provider_instance_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let mut budget_recoveries = 0;
    let c = db.connect().await.unwrap();
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM calls WHERE skill_id=$1",
            &[&skill.parse::<Uuid>().unwrap()]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    for (index, fault, items) in [
        (0, "call-id", 0),
        (1, "item", 0),
        (2, "sequence", 1),
        (3, "digest", 3),
        (4, "output", 3),
        (5, "missing-terminal", 3),
        (6, "after-terminal", 3),
    ] {
        let old_process = stream_process(app, live_instance).await;
        let response=stream_skill_request(router,token,skill,&json!({"input":{"message":"untrusted output","count":3,"fault":fault},"timeout_ms":10000}),&format!("stream-fault-{index}"),false).await;
        assert_eq!(response.status(), 200, "fault follows accepted");
        let events = collect_skill_events(response.into_body()).await;
        assert_eq!(events[0]["event"]["kind"], "accepted");
        assert_eq!(events.last().unwrap()["event"]["kind"], "failed");
        let delivered: Vec<_> = events
            .iter()
            .filter(|event| event["event"]["kind"] == "item")
            .collect();
        assert!(delivered.len() <= items, "malformed item reached caller");
        // Recovery can fence the instance before the already verified prefix
        // drains; every item that is delivered must retain its signed schema.
        for (index, event) in delivered.iter().enumerate() {
            assert_eq!(
                event["event"]["payload"],
                json!({"index":index,"message":"untrusted output"})
            );
        }
        assert!(events
            .iter()
            .all(|event| event["event"]["kind"] != "completed"));
        let call = events[0]["event"]["call_id"]
            .as_str()
            .unwrap()
            .parse::<Uuid>()
            .unwrap();
        let row = c
            .query_one(
                "SELECT state,provider_instance_id FROM calls WHERE id=$1",
                &[&call],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "unknown");
        assert_eq!(row.get::<_, Uuid>(1), live_instance);
        let (ready, reset) = recovery
            .fence_and_ready(
                &[call],
                live_instance,
                &old_process,
                &format!("stream-fault-{index}"),
            )
            .await;
        live_instance = ready;
        budget_recoveries += usize::from(reset);
    }
    assert!(
        budget_recoveries > 0,
        "fault sweep must prove restart-budget refusal and public recovery"
    );
    let old_process = stream_process(app, live_instance).await;
    let response=stream_skill_request(router,token,skill,&json!({"input":{"message":"cancel actual stream","count":64,"delay_ms":1000},"timeout_ms":10000}),"stream-explicit-cancel",false).await;
    assert_eq!(response.status(), 200);
    let mut stream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = std::str::from_utf8(&first).unwrap();
    let accepted: Value = serde_json::from_str(
        text.lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    contracts::validate("SkillStreamEvent", &accepted).unwrap();
    assert_eq!(accepted["event"]["kind"], "accepted");
    let canceled_call = accepted["event"]["call_id"].as_str().unwrap();
    let cancel = api(
        router,
        "cancelCall",
        &[("call_id", canceled_call.into())],
        Some(token),
        Value::Null,
        "cancel-real-stream",
        None,
    )
    .await;
    assert_eq!(cancel.0, 204, "{}", cancel.1);
    let mut response_bytes = first.to_vec();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(chunk) = stream.next().await {
            response_bytes.extend_from_slice(&chunk.unwrap());
        }
    })
    .await
    .unwrap();
    let events = parse_skill_events(std::str::from_utf8(&response_bytes).unwrap());
    assert!(events[1..events.len() - 1]
        .iter()
        .all(|event| event["event"]["kind"] == "item"));
    assert_eq!(events.last().unwrap()["event"]["kind"], "canceled");
    assert_eq!(
        events.last().unwrap()["event"]["payload"],
        json!({"reason":"requested"})
    );
    let canceled_id = canceled_call.parse::<Uuid>().unwrap();
    let row = c
        .query_one(
            "SELECT state,error,provider_instance_id FROM calls WHERE id=$1",
            &[&canceled_id],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        "unknown",
        "cancel is intent, not rollback proof"
    );
    assert_eq!(row.get::<_, Value>(1)["code"], "CANCELED");
    assert_eq!(row.get::<_, Uuid>(2), live_instance);
    live_instance = recovery
        .fence_and_ready(
            &[canceled_id],
            live_instance,
            &old_process,
            "stream-explicit-cancel",
        )
        .await
        .0;
    let owner: Uuid = c
        .query_one("SELECT owner_id FROM calls WHERE id=$1", &[&canceled_id])
        .await
        .unwrap()
        .get(0);
    let quota_before: i64 = c
        .query_one(
            "SELECT concurrent_calls_used FROM quotas WHERE account_id=$1",
            &[&owner],
        )
        .await
        .unwrap()
        .get(0);
    let capability = &manifest["capabilities"][1]["contract"];
    let rules = json!([
        {"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[skill]}},
        {"action":"capability.invoke","resource":{"kind":"capability","match":"ids","ids":[format!("{}@{}",capability["name"].as_str().unwrap(),capability["version"].as_str().unwrap())]}}
    ]);
    let key=api(router,"createApiKey",&[("account_id",owner.to_string())],Some(token),json!({"name":"live stream revocation","inheritance":{"mode":"selected","rules":rules},"conditions":{"expires_at":chrono::Utc::now()+chrono::Duration::days(1)}}),"stream-source-key",None).await;
    assert_eq!(key.0, 201, "{}", key.1);
    let caller = key.1["secret"].as_str().unwrap();
    // This scenario proves revocation, not deadline expiry. Keep the request
    // inside the signed Skill maximum while leaving enough time for the
    // actual management transaction and the unchanged 10s delivery bound.
    let revocation_budget_ms = 90000_u64;
    assert!(
        revocation_budget_ms
            <= manifest["skills"][1]["maximum_timeout_ms"]
                .as_u64()
                .unwrap(),
        "the revocation fixture cannot exceed the signed Skill maximum"
    );
    let revoked_input = json!({"input":{"message":"revoke actual stream","count":64,"delay_ms":1000},"timeout_ms":revocation_budget_ms});
    let old_process = stream_process(app, live_instance).await;
    let revocation_started = std::time::Instant::now();
    let response = stream_skill_request(
        router,
        caller,
        skill,
        &revoked_input,
        "stream-live-revoke",
        false,
    )
    .await;
    assert_eq!(response.status(), 200);
    let mut stream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let accepted: Value = serde_json::from_str(
        std::str::from_utf8(&first)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(accepted["event"]["kind"], "accepted");
    let revoked_call = accepted["event"]["call_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let accepted_elapsed = revocation_started.elapsed();
    let call_deadline: chrono::DateTime<chrono::Utc> = c
        .query_one(
            "SELECT deadline_at FROM calls WHERE id=$1",
            &[&revoked_call],
        )
        .await
        .unwrap()
        .get(0);
    let revoked = api(
        router,
        "revokeApiKey",
        &[(
            "credential_id",
            key.1["credential"]["id"].as_str().unwrap().into(),
        )],
        Some(token),
        Value::Null,
        "stream-revoke-source",
        key.1["credential"]["revision"].as_i64(),
    )
    .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    let revocation_committed_at = chrono::Utc::now();
    let remaining_ms = (call_deadline - revocation_committed_at).num_milliseconds();
    println!(
        "Skill revocation timing: elapsed_ms={} accepted_ms={} revoke_committed_at={} call_deadline={} remaining_ms={}",
        revocation_started.elapsed().as_millis(),
        accepted_elapsed.as_millis(),
        revocation_committed_at,
        call_deadline,
        remaining_ms
    );
    assert!(
        remaining_ms > 30000,
        "revocation must leave more than 30s before the Call deadline for the 10s delivery check; elapsed={:?}, deadline={call_deadline}, revoked_at={revocation_committed_at}",
        revocation_started.elapsed()
    );
    let mut response_bytes = first.to_vec();
    let delivery = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(chunk) = stream.next().await {
            response_bytes.extend_from_slice(&chunk.unwrap());
        }
    })
    .await;
    let events = parse_skill_events(std::str::from_utf8(&response_bytes).unwrap());
    let observed = c
        .query_one(
            "SELECT state,error FROM calls WHERE id=$1",
            &[&revoked_call],
        )
        .await
        .unwrap();
    let diagnostic = format!(
        "events={events:?}; stored_state={}; stored_error={:?}; elapsed={:?}; deadline={call_deadline}; revoked_at={revocation_committed_at}",
        observed.get::<_, String>("state"),
        observed.get::<_, Option<Value>>("error"),
        revocation_started.elapsed()
    );
    assert!(
        delivery.is_ok(),
        "revocation delivery exceeded 10s: {diagnostic}"
    );
    assert_eq!(
        events.len(),
        2,
        "revocation rejects queued business output: {diagnostic}"
    );
    assert_eq!(events[1]["event"]["kind"], "failed", "{diagnostic}");
    assert_eq!(
        events[1]["event"]["payload"]["code"], "INVALID_CREDENTIAL",
        "{diagnostic}"
    );
    live_instance = recovery
        .fence_and_ready(
            &[revoked_call],
            live_instance,
            &old_process,
            "stream-live-revoke",
        )
        .await
        .0;
    assert_eq!(
        c.query_one(
            "SELECT concurrent_calls_used FROM quotas WHERE account_id=$1",
            &[&owner]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        quota_before,
        "revocation and fencing cannot leak concurrent quota"
    );
    let refused = stream_skill_request(
        router,
        caller,
        skill,
        &revoked_input,
        "stream-live-revoke",
        false,
    )
    .await;
    assert_eq!(
        refused.status(),
        401,
        "revoked stream replay reauthenticates"
    );
    let maximum = manifest["concurrency"]["max_active_requests"]
        .as_u64()
        .unwrap();
    assert!((1..=4).contains(&maximum), "bounded reference pool");
    let before_pool = c
        .query_one(
            "SELECT concurrent_calls_used,daily_calls_used FROM quotas WHERE account_id=$1",
            &[&owner],
        )
        .await
        .unwrap();
    let pool_input = json!({"input":{"message":"shared stream pool","count":64,"delay_ms":1000},"timeout_ms":10000});
    let old_process = stream_process(app, live_instance).await;
    let mut active_streams = Vec::new();
    let mut active_calls = Vec::new();
    for index in 0..maximum {
        let response = stream_skill_request(
            router,
            token,
            skill,
            &pool_input,
            &format!("stream-pool-{index}"),
            false,
        )
        .await;
        assert_eq!(response.status(), 200, "reference pool admission {index}");
        let mut stream = response.into_body().into_data_stream();
        let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let accepted: Value = serde_json::from_str(
            std::str::from_utf8(&first)
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap(),
        )
        .unwrap();
        contracts::validate("SkillStreamEvent", &accepted).unwrap();
        assert_eq!(accepted["event"]["kind"], "accepted");
        active_calls.push(
            accepted["event"]["call_id"]
                .as_str()
                .unwrap()
                .parse::<Uuid>()
                .unwrap(),
        );
        active_streams.push(stream);
    }
    let charged = c
        .query_one(
            "SELECT concurrent_calls_used,daily_calls_used FROM quotas WHERE account_id=$1",
            &[&owner],
        )
        .await
        .unwrap();
    assert_eq!(
        charged.get::<_, i64>(0),
        before_pool.get::<_, i64>(0) + maximum as i64
    );
    assert_eq!(
        charged.get::<_, i64>(1),
        before_pool.get::<_, i64>(1) + maximum as i64
    );
    let full = stream_skill_request(
        router,
        token,
        skill,
        &pool_input,
        "stream-pool-exhausted",
        false,
    )
    .await;
    assert_eq!(full.status(), 503);
    let full: Value =
        serde_json::from_slice(&to_bytes(full.into_body(), 1048576).await.unwrap()).unwrap();
    assert_eq!(full["error"]["code"], "RESOURCE_EXHAUSTED");
    let unary = api(
        router,
        "invokeSkill",
        &[("skill_id", skill.into())],
        Some(token),
        pool_input,
        "unary-shares-stream-pool",
        None,
    )
    .await;
    assert_eq!(unary.0, 503, "{}", unary.1);
    assert_eq!(unary.1["error"]["code"], "RESOURCE_EXHAUSTED");
    let unchanged = c
        .query_one(
            "SELECT concurrent_calls_used,daily_calls_used FROM quotas WHERE account_id=$1",
            &[&owner],
        )
        .await
        .unwrap();
    assert_eq!(unchanged.get::<_, i64>(0), charged.get::<_, i64>(0));
    assert_eq!(unchanged.get::<_, i64>(1), charged.get::<_, i64>(1));
    drop(active_streams);
    live_instance = recovery
        .fence_and_ready(
            &active_calls,
            live_instance,
            &old_process,
            "stream-pool-disconnected",
        )
        .await
        .0;
    assert_eq!(
        c.query_one(
            "SELECT concurrent_calls_used FROM quotas WHERE account_id=$1",
            &[&owner]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        before_pool.get::<_, i64>(0)
    );
    let restored = stream_skill_request(
        router,
        token,
        skill,
        &json!({"input":{"message":"stream after fenced revocation","count":1.0},"timeout_ms":10000}),
        "stream-after-source-revoke",
        false,
    )
    .await;
    assert_eq!(restored.status(), 200);
    let restored = collect_skill_events(restored.into_body()).await;
    assert_eq!(restored.len(), 3);
    assert_eq!(restored.last().unwrap()["event"]["kind"], "completed");
    assert_eq!(
        restored.last().unwrap()["event"]["payload"]["provider_instance_id"],
        live_instance.to_string()
    );
    println!("Skill SSE: actual signed OCI accepted/items/completion, no regeneration replay, malformed identity/sequence/schema/digest/EOF rejection, explicit cancel, live credential revocation, shared unary/stream pool exhaustion, consumer disconnect, no quota leak, restart-budget refusal and public fresh-generation recovery passed");
    live_instance
}

async fn stream_skill_request(
    router: &Router,
    token: &str,
    skill: &str,
    input: &Value,
    key: &str,
    last_event: bool,
) -> axum::response::Response {
    let mut request = Request::builder()
        .header("host", http_host::authority(None))
        .method("POST")
        .uri(format!("/api/platform/v1/skills/{skill}/calls:stream"))
        .header("authorization", format!("Bearer {token}"))
        .header("idempotency-key", key)
        .header("content-type", "application/json");
    if last_event {
        request = request.header("last-event-id", "replay-forbidden:1");
    }
    let mut request = request
        .body(Body::from(serde_json::to_vec(input).unwrap()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
    ));
    router.clone().oneshot(request).await.unwrap()
}

async fn collect_skill_events(body: Body) -> Vec<Value> {
    let bytes = tokio::time::timeout(Duration::from_secs(20), to_bytes(body, 4194304))
        .await
        .unwrap()
        .unwrap();
    parse_skill_events(std::str::from_utf8(&bytes).unwrap())
}

fn parse_skill_events(text: &str) -> Vec<Value> {
    let mut events = Vec::new();
    for frame in text.split("\n\n") {
        let data = frame.lines().find_map(|line| line.strip_prefix("data: "));
        let Some(data) = data else {
            continue;
        };
        let event: Value = serde_json::from_str(data).unwrap();
        contracts::validate("SkillStreamEvent", &event).unwrap();
        let inner = &event["event"];
        assert_eq!(inner["sequence"].as_u64().unwrap(), events.len() as u64 + 1);
        assert_eq!(
            frame
                .lines()
                .find_map(|line| line.strip_prefix("event: "))
                .unwrap(),
            inner["kind"].as_str().unwrap()
        );
        assert_eq!(
            frame
                .lines()
                .find_map(|line| line.strip_prefix("id: "))
                .unwrap(),
            format!(
                "{}:{}",
                inner["call_id"].as_str().unwrap(),
                inner["sequence"].as_u64().unwrap()
            )
        );
        if let Some(prior) = events.first() {
            let prior: &Value = prior;
            assert_eq!(event["skill_id"], prior["skill_id"]);
            assert_eq!(inner["call_id"], prior["event"]["call_id"]);
        }
        assert!(events
            .last()
            .is_none_or(|prior: &Value| prior["event"]["terminal"] != true));
        events.push(event);
    }
    assert!(!events.is_empty(), "empty SSE response: {text}");
    assert_eq!(events.last().unwrap()["event"]["terminal"], true);
    events
}
