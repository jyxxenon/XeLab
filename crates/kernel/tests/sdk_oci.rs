//! Signed C++ Echo acceptance using containerd on a disposable Linux host.
#[path = "support/http_host.rs"]
mod http_host;
#[path = "support/oci.rs"]
mod oci;

use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use oci::{
    api, collect_skill_events, disable_after_observation, finished_operation, operation,
    stream_skill_request,
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_postgres::Client;
use uuid::Uuid;
use xelab_kernel::{
    admission,
    api::{router, App},
    artifact,
    auth::{self, Auth},
    contracts, controller,
    db::Db,
};

const NAMESPACE: &str = "xelab-sdk-oci";
const PUBLISHER: &str = "00000000-0000-4000-8000-000000000001";
const PASSWORD: &str = "signed C++ Echo test password";
const CPU_MILLIS: i64 = 500;
const MEMORY_BYTES: i64 = 134217728;

#[tokio::test]
#[ignore = "requires root, containerd, nftables and a disposable Linux host"]
async fn signed_cpp_echo_runs_as_an_oci_plugin() {
    assert_eq!(std::env::var("XELAB_CPP_OCI_TEST").as_deref(), Ok("1"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let image = std::env::var("XELAB_TEST_CPP_IMAGE").expect("import the C++ image first");
    let digest = artifact::image_ref(&image).expect("use the imported immutable manifest digest");
    let raw = fs::read("examples/echo-cpp/generated/xelab/plugin.json").unwrap();
    let manifest = contracts::strict_json(&raw, 1048576).unwrap();
    assert_eq!(manifest["publisher_id"], PUBLISHER);
    assert_eq!(manifest["plugin_id"], "org.xelab.echo-cpp");

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    xelab_kernel::init_crypto();
    let base = std::env::var("XELAB_TEST_DATABASE_URL").unwrap();
    let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
    admin
        .batch_execute("CREATE DATABASE xelab_sdk_oci")
        .await
        .unwrap();
    let db = Db::new(format!("{base} dbname=xelab_sdk_oci")).unwrap();
    db.migrate().await.unwrap();
    let root = tempfile::Builder::new()
        .prefix("xelab-sdk-oci-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/mnt")
        .unwrap();
    let (cert, key) = oci::workload_ca();
    let (config, runtime) = oci::prepare_runtime(root.path(), NAMESPACE, &cert, &key).await;
    let mut c = db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let owner = auth::bootstrap(
        &tx,
        "C++ Echo OCI owner",
        PASSWORD,
        &config.value["quota_defaults"],
    )
    .await
    .unwrap();
    admission::initialize(&tx, &config.value["resources"], 8000, 34359738368)
        .await
        .unwrap();
    // The fixture image is built before the test runs, with this publisher UUID.
    let publisher: Uuid = PUBLISHER.parse().unwrap();
    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let pem = signing
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    tx.execute(
        "INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at)
         VALUES($1,'C++ Echo OCI fixture','cpp-oci-test',$2,'trusted',now(),now())",
        &[&publisher, &pem],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

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
    assert!(app.runtime.inventory().await.unwrap().is_empty());
    let worker = tokio::spawn(controller::run(app.clone()));
    let router = router(app.clone());
    let (status, session) = api(
        &router,
        "login",
        &[],
        None,
        json!({"account_id":owner,"password":PASSWORD}),
        "login",
        None,
    )
    .await;
    assert_eq!(status, 200, "{session}");
    let token = session["access_token"].as_str().unwrap();

    let signed_request = |signed_digest| {
        let envelope = artifact::signature_envelope(&manifest, signed_digest, &raw).unwrap();
        json!({
            "publisher_id": publisher,
            "image": image,
            "signature": STANDARD.encode(signing.sign(envelope.as_bytes()).to_bytes())
        })
    };
    let other_digest = format!("sha256:{}", "0".repeat(64));
    assert_ne!(other_digest, digest);
    let (status, rejected) = api(
        &router,
        "installPlugin",
        &[],
        Some(token),
        signed_request(&other_digest),
        "install-wrong-digest",
        None,
    )
    .await;
    assert_eq!(status, 202, "{rejected}");
    let failure = finished_operation(&router, rejected["id"].as_str().unwrap(), token).await;
    assert_eq!(failure["state"], "failed", "{failure}");
    assert_eq!(failure["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        failure["error"]["message"],
        "Artifact signature verification failed"
    );
    assert_eq!(
        c.query_one("SELECT count(*) FROM installations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );

    let (status, queued) = api(
        &router,
        "installPlugin",
        &[],
        Some(token),
        signed_request(digest),
        "install-signed",
        None,
    )
    .await;
    assert_eq!(status, 202, "{queued}");
    let installed = operation(&router, queued["id"].as_str().unwrap(), token).await;
    let installation = installed["installation_id"].as_str().unwrap();
    let (status, record) = api(
        &router,
        "getInstallation",
        &[("installation_id", installation.into())],
        Some(token),
        Value::Null,
        "get-installation",
        None,
    )
    .await;
    assert_eq!(status, 200, "{record}");
    assert_eq!(record["image_digest"], digest);
    assert_eq!(record["manifest"], manifest);
    assert_eq!(record["state"], "installed");
    println!("Verified signature bound to the imported image manifest: {image}");

    let (status, queued) = api(
        &router,
        "createDeployment",
        &[],
        Some(token),
        json!({
            "installation_id": installation, "display_name": "C++ Echo", "enabled": false,
            "limits": {
                "cpu_millis": CPU_MILLIS, "memory_bytes": MEMORY_BYTES,
                "ephemeral_bytes": 1048576, "pids": 64
            },
            "config": {}, "volume_ids": []
        }),
        "create-deployment",
        None,
    )
    .await;
    assert_eq!(status, 202, "{queued}");
    let deployment = operation(&router, queued["id"].as_str().unwrap(), token).await;
    assert_eq!(deployment["phase"], "disabled");
    let deployment_id = deployment["id"].as_str().unwrap();
    let params = [("deployment_id", deployment_id.into())];
    let (status, approved) = api(
        &router,
        "approvePlugin",
        &params,
        Some(token),
        json!({"rules":[],"egress":[]}),
        "approve-deployment",
        Some(deployment["revision"].as_i64().unwrap()),
    )
    .await;
    assert_eq!(status, 200, "{approved}");
    let (status, current) = api(
        &router,
        "getDeployment",
        &params,
        Some(token),
        Value::Null,
        "get-approved-deployment",
        None,
    )
    .await;
    assert_eq!(status, 200, "{current}");
    let (status, queued) = api(
        &router,
        "setDeploymentEnabled",
        &params,
        Some(token),
        json!({"enabled":true}),
        "enable-deployment",
        Some(current["revision"].as_i64().unwrap()),
    )
    .await;
    assert_eq!(status, 202, "{queued}");
    let ready = operation(&router, queued["id"].as_str().unwrap(), token).await;
    assert_eq!(ready["phase"], "ready");
    assert_eq!(reserved(&c).await, (CPU_MILLIS, MEMORY_BYTES));

    let message = "Hello from signed C++ Echo";
    let (status, called) = api(
        &router,
        "invokeCapability",
        &[],
        Some(token),
        json!({
            "contract": manifest["capabilities"][0]["contract"],
            "input": {"message": message},
            "provider_deployment_id": deployment_id,
            "timeout_ms": 10000
        }),
        "unary",
        None,
    )
    .await;
    assert_eq!(status, 200, "{called}");
    assert_eq!(called["output"], json!({"message":message}));
    let instance = contracts::id(&called, "provider_instance_id").unwrap();
    assert_eq!(app.runtime.inventory().await.unwrap(), vec![instance]);
    assert!(app.runtime.running(instance).await.unwrap());
    assert_call(&router, token, &called["call_id"], instance).await;
    assert_stream(
        &router,
        token,
        installation,
        &manifest["skills"][1],
        instance,
    )
    .await;
    println!("Ran unary and SSE streaming calls against the C++ Echo container");

    let (status, queued) = disable_after_observation(&router, &params, token, "disable").await;
    assert_eq!(status, 202, "{queued}");
    let disabled = operation(&router, queued["id"].as_str().unwrap(), token).await;
    assert_eq!(disabled["phase"], "disabled");
    assert!(!app.runtime.running(instance).await.unwrap());
    assert!(app.runtime.inventory().await.unwrap().is_empty());
    assert_eq!(reserved(&c).await, (0, 0));
    app.shutdown.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(10), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(
        std::process::Command::new("umount")
            .arg(app.config.root().join("images").join(&digest[7..]))
            .status()
            .unwrap()
            .success(),
        "fixture image view must be unmounted before removing its directory"
    );
    root.close().unwrap();
    println!("Disabled the deployment, removed the container and released its CPU and memory");
}

async fn reserved(c: &Client) -> (i64, i64) {
    let row = c
        .query_one(
            "SELECT reserved_cpu_millis, reserved_memory_bytes FROM node_budget",
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

async fn assert_call(router: &Router, token: &str, call: &Value, instance: Uuid) {
    let (status, record) = api(
        router,
        "getCall",
        &[("call_id", call.as_str().unwrap().into())],
        Some(token),
        Value::Null,
        "get-call",
        None,
    )
    .await;
    assert_eq!(status, 200, "{record}");
    assert_eq!(record["state"], "succeeded");
    assert_eq!(
        contracts::id(&record["result"], "provider_instance_id").unwrap(),
        instance
    );
}

async fn assert_stream(
    router: &Router,
    token: &str,
    installation: &str,
    definition: &Value,
    instance: Uuid,
) {
    let (status, registered) = api(
        router,
        "registerSkill",
        &[],
        Some(token),
        json!({"installation_id":installation,"definition":definition,"enabled":true}),
        "register-stream",
        None,
    )
    .await;
    assert_eq!(status, 201, "{registered}");
    let skill = registered["id"].as_str().unwrap();
    let message = "Streaming from signed C++ Echo";
    let request = json!({"input":{"message":message,"count":3},"timeout_ms":10000});
    let response = stream_skill_request(router, token, skill, &request, "stream", false).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let events = collect_skill_events(response.into_body()).await;
    assert_eq!(events.len(), 5, "{events:?}");
    assert_eq!(events[0]["event"]["kind"], "accepted");
    assert_eq!(events[0]["skill_id"], skill);
    for (index, event) in events[1..4].iter().enumerate() {
        assert_eq!(event["event"]["kind"], "item");
        assert_eq!(
            event["event"]["payload"],
            json!({"index":index,"message":message})
        );
    }
    let terminal = &events[4]["event"];
    assert_eq!(terminal["kind"], "completed");
    assert_eq!(terminal["payload"]["output"], json!({"message":message}));
    assert_call(router, token, &terminal["call_id"], instance).await;
}
