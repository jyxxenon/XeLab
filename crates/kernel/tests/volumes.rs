//! Real metadata/HTTP tests. The ignored acceptance also needs a newly created,
//! dedicated XFS mount; tools/test-xfs.sh owns its complete disposable lifecycle.
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
    fs,
    io::Write,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;
use xelab_kernel::{
    admission,
    api::{router, App},
    auth::{self, Auth},
    config::Config,
    contracts,
    db::Db,
    runtime::Runtime,
    storage::xfs::{Limits, ProjectStore},
    volumes,
};
#[path = "support/aws_format_transitions.rs"]
mod aws_format_transitions;
#[path = "support/kernel_process_death.rs"]
mod kernel_process_death;
#[path = "support/object_storage_kernel.rs"]
mod object_storage_kernel;
#[path = "support/schema_bootstrap.rs"]
mod schema_bootstrap;
#[path = "support/schema_same_format.rs"]
mod schema_same_format;
#[path = "support/volume_upgrades.rs"]
mod volume_upgrades;
struct Fixture {
    app: Arc<App>,
    router: Router,
    token: String,
    owner: Uuid,
    _root: tempfile::TempDir,
}
impl Fixture {
    async fn new(real: bool) -> Option<Self> {
        Self::new_with_capacity(real, None).await
    }
    async fn new_with_capacity(real: bool, capacity: Option<(i64, i64)>) -> Option<Self> {
        xelab_kernel::init_crypto();
        let Ok(base) = std::env::var("XELAB_TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: volume metadata tests need PostgreSQL");
            return None;
        };
        let admin = Db::new(base.clone()).unwrap().connect().await.unwrap();
        let name = format!("volume_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let db = Db::new(format!("{base} dbname={name}")).unwrap();
        db.migrate().await.unwrap();
        db.migrate().await.unwrap();
        db.check().await.unwrap();
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .unwrap();
        let t: toml::Value =
            toml::from_str(include_str!("../../../docs/contracts/examples/kernel.toml")).unwrap();
        let mut value = serde_json::to_value(t).unwrap();
        value["storage"]["root_path"] = if real {
            json!(std::env::var("XELAB_VOLUME_TEST_ROOT").unwrap())
        } else {
            json!(root.path())
        };
        if real {
            value["runtime"]["namespace"] = json!("xelab-ci");
            value["runtime"]["network_cidr"] = json!("172.29.240.0/24");
            value["server"]["host_rpc_listen"] = json!("172.29.240.1:7443");
            value["security"]["workload_ca_cert_file"] = json!(root.path().join("ca.crt"));
            value["security"]["workload_ca_key_file"] = json!(root.path().join("ca.key"));
        }
        value["security"]["workload_ca_cert_file"] = json!(root.path().join("ca.crt"));
        value["security"]["workload_ca_key_file"] = json!(root.path().join("ca.key"));
        value["security"]["master_key_file"] = json!(root.path().join("master.key"));
        fs::write(root.path().join("master.key"), [31; 32]).unwrap();
        fs::set_permissions(
            root.path().join("master.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["volume-test-ca".into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        fs::write(root.path().join("ca.crt"), ca.pem()).unwrap();
        fs::write(root.path().join("ca.key"), ca_key.serialize_pem()).unwrap();
        fs::set_permissions(
            root.path().join("ca.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let config = Config::from_value(value).unwrap();
        xelab_kernel::tls::issue(&config, None, &config.root().join("kernel-identity")).unwrap();
        let mut c = db.connect().await.unwrap();
        let tx = c.transaction().await.unwrap();
        let owner = auth::bootstrap(
            &tx,
            "Volume owner",
            "correct horse volume test password",
            &config.value["quota_defaults"],
        )
        .await
        .unwrap();
        // Ordinary components use a synthetic pool; the explicit AWS drill
        // supplies measured host capacity without changing production floors.
        let (cpu, memory) = capacity.unwrap_or((8000, 34359738368));
        admission::initialize(&tx, &config.value["resources"], cpu, memory)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let auth = Auth::new(vec![82; 32]).unwrap();
        let token = auth
            .login(
                &c,
                owner,
                "correct horse volume test password".into(),
                "127.0.0.1".parse().unwrap(),
                Uuid::new_v4(),
            )
            .await
            .unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let app = Arc::new(App {
            runtime: Runtime::new(config.clone()),
            config,
            db: db.clone(),
            auth,
            leader: Arc::new(db.leader().await.unwrap()),
            ready: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
            blob_uploads: tokio::sync::Semaphore::new(4),
        });
        Some(Self {
            router: router(app.clone()),
            app,
            token,
            owner,
            _root: root,
        })
    }
    async fn api(
        &self,
        op: &str,
        id: Option<Uuid>,
        body: Value,
        key: &str,
        revision: Option<i64>,
        query: Option<&str>,
    ) -> (u16, Value) {
        let (mut path, method) = contracts::openapi()["paths"]
            .as_object()
            .unwrap()
            .iter()
            .flat_map(|(p, ms)| ms.as_object().unwrap().iter().map(move |(m, s)| (p, m, s)))
            .find(|(_, _, s)| s["operationId"] == op)
            .map(|(p, m, _)| (p.clone(), m.to_uppercase()))
            .unwrap();
        if let Some(id) = id {
            for p in [
                "volume_id",
                "deployment_id",
                "operation_id",
                "account_id",
                "backup_id",
                "skill_id",
                "call_id",
                "blob_id",
            ] {
                path = path.replace(&format!("{{{p}}}"), &id.to_string());
            }
        }
        if let Some(q) = query {
            path.push('?');
            path.push_str(q);
        }
        let mut req = Request::builder()
            .header(
                "host",
                http_host::authority(Some(self.app.config.text("server", "public_origin"))),
            )
            .method(method.as_str())
            .uri(path)
            .header("authorization", format!("Bearer {}", self.token))
            .header("idempotency-key", key);
        if let Some(rev) = revision {
            req = req.header("if-match", format!("\"rev-{rev}\""));
        }
        let bytes = if body.is_null() {
            Vec::new()
        } else {
            req = req.header("content-type", "application/json");
            serde_json::to_vec(&body).unwrap()
        };
        let mut req = req.body(Body::from(bytes)).unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:30000".parse::<SocketAddr>().unwrap(),
        ));
        let response = self.router.clone().oneshot(req).await.unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 4194304).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn finish(&self, op: &Value) {
        for _ in 0..50 {
            volumes::tick(&self.app).await.unwrap();
            let value = xelab_kernel::db::operation_value(
                &self.app.db.connect().await.unwrap(),
                op["id"].as_str().unwrap().parse().unwrap(),
            )
            .await
            .unwrap();
            if value["state"] == "succeeded" {
                return;
            }
            assert_ne!(value["state"], "failed", "{value}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("volume operation did not converge: {op}");
    }
}
fn spec() -> Value {
    json!({"name":"data","capacity_bytes":4194304,"access":"single_writer","scope":"deployment"})
}
#[tokio::test]
async fn unsupported_storage_never_publishes_a_volume_or_allocation() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let (status, value) = f
        .api("createVolume", None, spec(), "unsupported", None, None)
        .await;
    assert_eq!(status, 503, "{value}");
    let c = f.app.db.connect().await.unwrap();
    for table in [
        "volumes",
        "volume_allocations",
        "volume_storage_root",
        "operations",
    ] {
        assert_eq!(
            c.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    let id = Uuid::new_v4();
    for query in [
        None,
        Some("confirm_volume_id=wrong"),
        Some("confirm_volume_id=00000000-0000-4000-8000-000000000001&extra=1"),
    ] {
        let result = f
            .api(
                "deleteVolume",
                Some(id),
                Value::Null,
                "bad-confirm",
                Some(1),
                query,
            )
            .await;
        assert_eq!(result.0, 400, "{}", result.1);
    }
    let listed = f
        .api("listVolumes", None, Value::Null, "list", None, None)
        .await;
    assert_eq!(listed.0, 200, "{}", listed.1);
    assert_eq!(listed.1["items"], json!([]));
}

#[tokio::test]
#[ignore = "requires explicit real AWS credentials, disposable privileged host and tools/test-aws-format.sh"]
async fn actual_aws_backed_format_upgrade_unknown_apply_and_incompatible_rollback() {
    aws_format_transitions::exercise().await;
}

#[tokio::test]
#[ignore = "requires actual kernel process abort/restart, root and dedicated XFS; tools/test-xfs.sh"]
async fn actual_kernel_process_death_resumes_initializing_checkpoint() {
    kernel_process_death::exercise().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the signed object-storage fixture and dedicated XFS/containerd runner"]
async fn actual_object_storage_kernel_round_trip() {
    object_storage_kernel::exercise().await;
}

#[tokio::test]
#[ignore = "requires a dedicated real XFS mount and root; tools/test-xfs.sh"]
async fn actual_volume_operations_recover_enforce_capacity_and_fence_writers() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(std::env::var("XELAB_XFS_TEST").unwrap(), "1");
    let f = Fixture::new(true).await.unwrap();
    f.app.runtime.retain_daemon_host_lease().unwrap();
    assert!(
        f.app.runtime.clone().host_lease().is_err(),
        "the daemon lease survives local runtime values until this isolated test process exits"
    );
    let c = f.app.db.connect().await.unwrap();
    let created = f
        .api("createVolume", None, spec(), "create", None, None)
        .await;
    assert_eq!(created.0, 202, "{}", created.1);
    let id: Uuid = created.1["resource_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        f.api("getVolume", Some(id), Value::Null, "get", None, None)
            .await
            .0,
        404
    );
    let replay = f
        .api("createVolume", None, spec(), "create", None, None)
        .await;
    assert_eq!(replay.1, created.1);
    // Power loss after the quota/directory side effect but before publication.
    let a = c
        .query_one(
            "SELECT project_id,inode_limit FROM volume_allocations WHERE volume_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    let project = a.get::<_, i32>(0) as u32;
    let path = f.app.config.root().join("volumes");
    let mut store = ProjectStore::open(&path).unwrap();
    store
        .recover_create(
            id,
            project,
            Limits {
                capacity_bytes: 4194304,
                inodes: a.get::<_, i64>(1) as u64,
            },
        )
        .unwrap();
    store.prepare_data(id, project).unwrap();
    let data = store.data_path(id, project).unwrap();
    fs::write(data.join("survives"), b"persistent bytes").unwrap();
    drop(store);
    f.finish(&created.1).await;
    assert_eq!(
        fs::read(data.join("survives")).unwrap(),
        b"persistent bytes"
    );
    let mut file = fs::File::create(data.join("full")).unwrap();
    let bytes = [5u8; 65536];
    let mut written = 0;
    loop {
        assert!(written < 8388608);
        match file.write_all(&bytes).and_then(|_| file.sync_all()) {
            Ok(()) => written += 65536,
            Err(e) => {
                assert!(matches!(
                    e.raw_os_error(),
                    Some(libc::EDQUOT | libc::ENOSPC)
                ));
                break;
            }
        }
    }
    // XFS delayed-allocation reservations can reject a large write before its
    // committed block counter equals the limit. Retain that actual EDQUOT check
    // above, then drive the independent inode hard quota to its exact counter
    // boundary for the metadata full-state/outbox assertion.
    file.set_len(0).unwrap();
    file.sync_all().unwrap();
    let inode_failure = loop {
        let n = fs::read_dir(&data).unwrap().count();
        assert!(n < 2048, "inode quota was bypassed");
        match fs::File::create(data.join(format!("inode-{n}"))) {
            Ok(_) => (),
            Err(error) => break error,
        }
    };
    assert!(matches!(
        inode_failure.raw_os_error(),
        Some(libc::EDQUOT | libc::ENOSPC)
    ));
    let full = f
        .api("getVolume", Some(id), Value::Null, "get-full", None, None)
        .await;
    assert_eq!(full.0, 200, "{}", full.1);
    assert_eq!(full.1["state"], "full", "{0}", full.1);
    assert!(full.1["used_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM outbox WHERE topic='volume_full' AND aggregate_id=$1",
            &[&id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let rev = full.1["revision"].as_i64().unwrap();
    let stale = f
        .api(
            "resizeVolume",
            Some(id),
            json!({"capacity_bytes":8388608}),
            "stale",
            Some(rev - 1),
            None,
        )
        .await;
    assert_eq!(stale.0, 412, "{}", stale.1);
    let resize = f
        .api(
            "resizeVolume",
            Some(id),
            json!({"capacity_bytes":8388608}),
            "resize",
            Some(rev),
            None,
        )
        .await;
    assert_eq!(resize.0, 202, "{}", resize.1);
    f.finish(&resize.1).await;
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let grown = f
        .api("getVolume", Some(id), Value::Null, "get-grown", None, None)
        .await;
    assert_eq!(grown.1["spec"]["capacity_bytes"], 8388608);
    assert_eq!(grown.1["state"], "available");
    let marker = path.join(".xelab-volume-root");
    fs::rename(&marker, path.join(".held-marker")).unwrap();
    assert_eq!(
        f.api("getVolume", Some(id), Value::Null, "missing", None, None)
            .await
            .0,
        503
    );
    assert_eq!(
        f.api("createVolume", None, spec(), "missing-create", None, None)
            .await
            .0,
        503
    );
    fs::rename(path.join(".held-marker"), &marker).unwrap();
    // Verify the actual signed volume image; this fixture inserts the verified
    // installation metadata so attachment and runtime effects remain explicit.
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
    use xelab_kernel::{artifact, tls};
    let manifest_bytes = fs::read("examples/generated-volume/xelab/plugin.json").unwrap();
    let declared: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let image = std::env::var("XELAB_TEST_VOLUME_IMAGE").unwrap();
    let signing = SigningKey::from_bytes(&[7; 32]);
    let pem = signing
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    let envelope = artifact::signature_envelope(
        &declared,
        artifact::image_ref(&image).unwrap(),
        &manifest_bytes,
    )
    .unwrap();
    let publisher: Uuid = declared["publisher_id"].as_str().unwrap().parse().unwrap();
    let artifact=artifact::Artifact::inspect(&f.app.runtime,&json!({"publisher_id":publisher,"image":image,"signature":STANDARD.encode(signing.sign(envelope.as_bytes()).to_bytes())}),&pem).await.unwrap();
    let manifest = artifact.manifest;
    let installation = Uuid::new_v4();
    c.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'fixture','fixture',$2,'trusted',now(),now())",&[&publisher,&pem]).await.unwrap();
    c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,'org.xelab.echo-python','1.0.0',$2,$3,$4,$5,'installed',now(),now())",&[&installation,&publisher,&artifact.image_digest,&artifact.manifest_digest,&manifest]).await.unwrap();
    f.app.runtime.prepare_host_service_network().await.unwrap();
    tls::issue(
        &f.app.config,
        None,
        &f.app.config.root().join("kernel-identity"),
    )
    .unwrap();
    let deployspec = json!({"installation_id":installation,"display_name":"volume fixture","config":{},"limits":{"cpu_millis":100,"memory_bytes":134217728,"ephemeral_bytes":1048576,"pids":64},"replicas":1,"enabled":false,"volume_ids":[id]});
    let child = f
        .api(
            "createChildAccount",
            Some(f.owner),
            json!({"display_name":"other volume owner","inheritance":{"mode":"follow_parent"}}),
            "other-owner",
            None,
            None,
        )
        .await;
    assert_eq!(child.0, 201, "{}", child.1);
    let other: Uuid = child.1["account"]["id"].as_str().unwrap().parse().unwrap();
    c.execute("UPDATE volumes SET owner_id=$2 WHERE id=$1", &[&id, &other])
        .await
        .unwrap();
    assert_eq!(
        f.api("getVolume", Some(id), Value::Null, "other-read", None, None)
            .await
            .0,
        200
    );
    let forbidden = f
        .api(
            "createDeployment",
            None,
            deployspec.clone(),
            "cross-owner",
            None,
            None,
        )
        .await;
    assert_eq!(
        forbidden.0, 403,
        "metadata visibility must not confer another owner's writes: {}",
        forbidden.1
    );
    c.execute(
        "UPDATE volumes SET owner_id=$2 WHERE id=$1",
        &[&id, &f.owner],
    )
    .await
    .unwrap();
    let mut deployments = Vec::new();
    for n in 0..2 {
        let created = f
            .api(
                "createDeployment",
                None,
                deployspec.clone(),
                &format!("dep{n}"),
                None,
                None,
            )
            .await;
        assert_eq!(created.0, 202, "{}", created.1);
        let d: Uuid = created.1["resource_id"].as_str().unwrap().parse().unwrap();
        let approved = f
            .api(
                "approvePlugin",
                Some(d),
                json!({"rules":[],"egress":[]}),
                &format!("approve{n}"),
                Some(1),
                None,
            )
            .await;
        assert_eq!(approved.0, 200, "{}", approved.1);
        let enabled = f
            .api(
                "setDeploymentEnabled",
                Some(d),
                json!({"enabled":true}),
                &format!("enable{n}"),
                Some(2),
                None,
            )
            .await;
        assert_eq!(enabled.0, 202, "{}", enabled.1);
        let instance = c
            .query_one(
                "SELECT id,generation FROM instances WHERE deployment_id=$1",
                &[&d],
            )
            .await
            .unwrap();
        deployments.push((d, instance.get::<_, Uuid>(0), instance.get::<_, i64>(1)));
    }
    let (d, i, g) = deployments[0];
    let mounts = volumes::mounts(&f.app, d, i, g, &manifest).await.unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].source, data);
    assert_eq!(
        volumes::mounts(&f.app, d, i, g, &manifest).await.unwrap()[0].fence,
        mounts[0].fence
    );
    fs::remove_file(data.join("full")).unwrap();
    let limits = deployspec["limits"].clone();
    f.app
        .runtime
        .ensure(
            i,
            d,
            g,
            &manifest,
            &image,
            &artifact.image_digest,
            &limits,
            &mounts,
        )
        .await
        .unwrap();
    probe(&f, i, "fill").await;
    f.app.runtime.stop(i).await.unwrap();
    f.app.runtime.stop(i).await.unwrap(); // Confirm cleanup is idempotent before releasing the attachment.
    let mut dbc = f.app.db.connect().await.unwrap();
    let tx = dbc.transaction().await.unwrap();
    volumes::release_stopped(&tx, Some(i)).await.unwrap();
    tx.commit().await.unwrap();
    let restarted = volumes::mounts(&f.app, d, i, g, &manifest).await.unwrap();
    assert!(restarted[0].fence > mounts[0].fence);
    f.app
        .runtime
        .ensure(
            i,
            d,
            g,
            &manifest,
            &image,
            &artifact.image_digest,
            &limits,
            &restarted,
        )
        .await
        .unwrap();
    probe(&f, i, "read").await;
    f.app.runtime.stop(i).await.unwrap();
    let mut readonly = restarted.clone();
    readonly[0].access = "ro".into();
    f.app
        .runtime
        .ensure(
            i,
            d,
            g,
            &manifest,
            &image,
            &artifact.image_digest,
            &limits,
            &readonly,
        )
        .await
        .unwrap();
    probe(&f, i, "ro").await;
    f.app.runtime.stop(i).await.unwrap();
    assert!(volumes::mounts(&f.app, d, i, g + 1, &manifest)
        .await
        .is_err());
    let (d2, i2, g2) = deployments[1];
    assert!(volumes::mounts(&f.app, d2, i2, g2, &manifest)
        .await
        .is_err());
    let mounted = f
        .api("getVolume", Some(id), Value::Null, "mounted", None, None)
        .await;
    let confirm = format!("confirm_volume_id={id}");
    assert_eq!(
        f.api(
            "deleteVolume",
            Some(id),
            Value::Null,
            "mounted-delete",
            mounted.1["revision"].as_i64(),
            Some(&confirm)
        )
        .await
        .0,
        409
    );
    // Stop removed the actual task and container; only now transfer the writer.
    assert!(!f.app.runtime.inventory().await.unwrap().contains(&i));
    // Actual signed workload lifecycle, not a simulated Drain response. Keep
    // cloud placement outside this owned-host component test.
    f.app
        .runtime
        .ensure(
            i,
            d,
            g,
            &manifest,
            &image,
            &artifact.image_digest,
            &limits,
            &readonly,
        )
        .await
        .unwrap();
    backup_freeze_phase(&f, d, i, g, id, installation, &data).await;
    let mut dbc = f.app.db.connect().await.unwrap();
    let tx = dbc.transaction().await.unwrap();
    volumes::release_stopped(&tx, Some(i)).await.unwrap();
    tx.commit().await.unwrap();
    let newer = volumes::mounts(&f.app, d2, i2, g2, &manifest)
        .await
        .unwrap();
    assert!(newer[0].fence > mounts[0].fence);
    let tx = dbc.transaction().await.unwrap();
    volumes::release_stopped(&tx, Some(i2)).await.unwrap();
    tx.commit().await.unwrap();
    let current = f
        .api("getVolume", Some(id), Value::Null, "current", None, None)
        .await;
    let delete = f
        .api(
            "deleteVolume",
            Some(id),
            Value::Null,
            "delete",
            current.1["revision"].as_i64(),
            Some(&confirm),
        )
        .await;
    assert_eq!(delete.0, 202, "{}", delete.1);
    f.finish(&delete.1).await;
    assert!(!data.exists());
    let deleted = f
        .api("getVolume", Some(id), Value::Null, "deleted", None, None)
        .await;
    assert_eq!(deleted.1["state"], "deleted");
    let wrong = f
        .api(
            "deleteVolume",
            Some(id),
            Value::Null,
            "delete",
            current.1["revision"].as_i64(),
            Some("confirm_volume_id=wrong"),
        )
        .await;
    assert_eq!(wrong.0, 400, "confirmation must precede replay");
    assert_eq!(
        c.query_one("SELECT reserved_bytes FROM volume_storage_root", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        65536
    );
    let next = f
        .api("createVolume", None, spec(), "next", None, None)
        .await;
    assert_eq!(next.0, 202, "{}", next.1);
    f.finish(&next.1).await;
    assert!(
        c.query_one("SELECT max(project_id) FROM volume_allocations", &[])
            .await
            .unwrap()
            .get::<_, i32>(0)
            > project as i32
    );
    assert_eq!(
        c.query_one("SELECT owner_id FROM volumes WHERE id=$1", &[&id])
            .await
            .unwrap()
            .get::<_, Uuid>(0),
        f.owner
    );
    // The previous attachment fixtures have positive stop proofs. Isolate the
    // new real controller sweep from their deliberately deleted selections.
    c.execute("UPDATE deployments SET spec=jsonb_set(spec,'{enabled}','false'),phase='disabled' WHERE id=ANY($1)", &[&vec![d,d2]]).await.unwrap();
    xelab_kernel::tls::atomic_file(
        &f.app
            .config
            .root()
            .join("images")
            .join(&artifact.image_digest[7..])
            .with_extension("reference"),
        image.as_bytes(),
        0o600,
    )
    .unwrap();
    volume_upgrades::exercise(&f, installation, publisher, &next.1).await;
    schema_bootstrap::exercise(&f, publisher).await;
}

async fn probe(f: &Fixture, instance: Uuid, mode: &str) {
    let out = f
        .app
        .runtime
        .ctr(&[
            "tasks".into(),
            "exec".into(),
            "--exec-id".into(),
            Uuid::new_v4().to_string(),
            "--user".into(),
            "65532:65532".into(),
            instance.to_string(),
            "/usr/bin/python3".into(),
            "/opt/plugin/volume_probe.py".into(),
            mode.into(),
        ])
        .await
        .unwrap();
    assert!(String::from_utf8(out)
        .unwrap()
        .contains(&format!("volume-{mode}-verified")));
}

async fn backup_freeze_phase(
    f: &Fixture,
    deployment: Uuid,
    instance: Uuid,
    generation: i64,
    volume: Uuid,
    installation: Uuid,
    data: &std::path::Path,
) {
    use xelab_kernel::{
        backups, controller,
        policy::Policy,
        rpc::{self, plugin_lifecycle_client::PluginLifecycleClient},
        tls,
    };
    let mut channel = None;
    for _ in 0..40 {
        if let Ok(value) = tls::channel(
            &f.app.config,
            instance,
            generation,
            &f.app.runtime.address(instance).unwrap(),
        )
        .await
        {
            channel = Some(value);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut client =
        PluginLifecycleClient::new(channel.expect("real volume workload TLS listener"));
    let described = client
        .describe(rpc::DescribeRequest {
            context: Some(controller::context(None)),
        })
        .await
        .unwrap()
        .into_inner();
    let mut c = f.app.db.connect().await.unwrap();
    let installed = c
        .query_one(
            "SELECT image_digest,manifest_digest,manifest FROM installations WHERE id=$1",
            &[&installation],
        )
        .await
        .unwrap();
    assert_eq!(
        described.manifest_digest,
        installed.get::<_, String>("manifest_digest")
    );
    let config = b"{}".to_vec();
    let initialized = client
        .initialize(rpc::InitializeRequest {
            context: Some(controller::context(None)),
            deployment_id: deployment.to_string(),
            instance_id: instance.to_string(),
            generation: generation as u64,
            config_json: config.clone(),
            config_digest: contracts::digest(&config),
            approval_revision: 3,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(initialized.initialized);
    assert_eq!(initialized.observed_generation, generation as u64);
    let health = client
        .get_health(rpc::HealthRequest {
            context: Some(controller::context(None)),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(health.alive && health.capabilities.iter().all(|v| v.ready));
    let before = fs::read(data.join("sentinel")).unwrap();
    let tx = c.transaction().await.unwrap();
    let credential: Uuid = tx
        .query_one(
            "SELECT id FROM credentials WHERE owner_id=$1 AND kind='session' AND status='active'",
            &[&f.owner],
        )
        .await
        .unwrap()
        .get(0);
    f.app
        .auth
        .authenticate(&tx, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap();
    let paths = Policy::new(&tx, "127.0.0.1".parse().unwrap())
        .credential(credential, 0)
        .await
        .unwrap();
    let spec: Value = tx
        .query_one(
            "SELECT spec FROM deployments WHERE id=$1 FOR UPDATE",
            &[&deployment],
        )
        .await
        .unwrap()
        .get(0);
    tx.execute(
        "UPDATE instances SET phase='ready',health='healthy' WHERE id=$1",
        &[&instance],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE deployments SET phase='ready',observed_generation=$2 WHERE id=$1",
        &[&deployment, &generation],
    )
    .await
    .unwrap();
    let repository = Uuid::new_v4();
    tx.execute("INSERT INTO backup_repositories(id,location,region,state) VALUES($1,'s3://test-only-freeze/node/','us-east-1','preparing')",&[&repository]).await.unwrap();
    let backup = Uuid::new_v4();
    let operation =
        xelab_kernel::db::operation(&tx, f.owner, "createBackup", Some(backup.to_string()))
            .await
            .unwrap();
    tx.execute("INSERT INTO backups(id,deployment_id,created_by,volume_ids,state,off_host,created_at,updated_at) VALUES($1,$2,$3,$4,'creating',false,now(),now())",&[&backup,&deployment,&f.owner,&json!([volume])]).await.unwrap();
    let metadata = json!({"id":installation,"image_digest":installed.get::<_,String>("image_digest"),"manifest_digest":installed.get::<_,String>("manifest_digest"),"manifest":installed.get::<_,Value>("manifest")});
    tx.execute("INSERT INTO storage_recovery_jobs(operation_id,kind,backup_id,deployment_id,repository_id,credential_id,subject_id,peer,authority,state,original_spec,installation_digest,installation_metadata,instances,manifest_object_id,master_key_id) VALUES($1,'backup',$2,$3,$4,$5,$6,'127.0.0.1',$7,'freezing',$8,$9,$10,$11,$12,$13)",&[&operation,&backup,&deployment,&repository,&credential,&f.owner,&serde_json::to_value(paths).unwrap(),&spec,&installed.get::<_,String>("image_digest"),&metadata,&json!([{"id":instance,"generation":generation}]),&Uuid::new_v4(),&contracts::digest(&[31;32])]).await.unwrap();
    tx.execute(
        "INSERT INTO deployment_storage_holds(deployment_id,operation_id) VALUES($1,$2)",
        &[&deployment, &operation],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO volume_holds(volume_id,operation_id,kind) VALUES($1,$2,'backup')",
        &[&volume, &operation],
    )
    .await
    .unwrap();
    let v = tx
        .query_one(
            "SELECT spec,capacity_bytes FROM volumes WHERE id=$1",
            &[&volume],
        )
        .await
        .unwrap();
    tx.execute("INSERT INTO backup_job_volumes(operation_id,source_volume_id,object_id,state,volume_spec,capacity_bytes) VALUES($1,$2,$3,'pending',$4,$5)",&[&operation,&volume,&Uuid::new_v4(),&v.get::<_,Value>(0),&v.get::<_,i64>(1)]).await.unwrap();
    let mut disabled = spec;
    disabled["enabled"] = json!(false);
    tx.execute(
        "UPDATE deployments SET spec=$2,phase='draining' WHERE id=$1",
        &[&deployment, &disabled],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let worker = tokio::spawn(backups::run(f.app.clone()));
    let mut terminal = false;
    for _ in 0..120 {
        let row = c
            .query_one(
                "SELECT state,stopped_at FROM storage_recovery_jobs WHERE operation_id=$1",
                &[&operation],
            )
            .await
            .unwrap();
        if row.get::<_, String>("state") == "failed" {
            assert!(row.get::<_,Option<chrono::DateTime<chrono::Utc>>>("stopped_at").is_some(),"signed Drain/stop/sync phase must precede the intentionally unconfigured off-host backend");
            terminal = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    worker.abort();
    let _ = worker.await;
    assert!(terminal, "backup freeze phase did not settle");
    assert!(!f.app.runtime.inventory().await.unwrap().contains(&instance));
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM volume_attachments WHERE instance_id=$1",
            &[&instance]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(fs::read(data.join("sentinel")).unwrap(), before);
    let b = c
        .query_one("SELECT state,off_host FROM backups WHERE id=$1", &[&backup])
        .await
        .unwrap();
    assert_eq!(b.get::<_, String>(0), "failed");
    assert!(!b.get::<_, bool>(1));
    println!("signed volume Drain, stop proof, sync and durable backup intent verified; off-host backend intentionally unavailable");
}
