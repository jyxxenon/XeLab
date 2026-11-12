//! Real kernel integration for the signed release image.
use super::*;
use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
use std::{collections::BTreeMap, path::Path, sync::atomic::Ordering};
use xelab_kernel::{broker, controller, host, schema_jobs};

async fn blob(f: &Fixture, id: Option<Uuid>, data: &[u8]) -> (u16, Vec<u8>) {
    let request = Request::builder()
        .header("host", http_host::authority(None))
        .header("authorization", format!("Bearer {}", f.token));
    let request = if let Some(id) = id {
        request
            .method("GET")
            .uri(format!("/api/platform/v1/blobs/{id}/content"))
    } else {
        request
            .method("POST")
            .uri("/api/platform/v1/blobs?content_type=application%2Foctet-stream")
            .header("content-type", "application/octet-stream")
            .header("content-length", data.len())
            .header("x-content-sha256", contracts::digest(data))
            .header("idempotency-key", "object-source-blob")
    };
    let mut request = request.body(Body::from(data.to_vec())).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:30000".parse::<SocketAddr>().unwrap(),
    ));
    let response = f.router.clone().oneshot(request).await.unwrap();
    (
        response.status().as_u16(),
        to_bytes(response.into_body(), 1048576)
            .await
            .unwrap()
            .to_vec(),
    )
}

async fn skill(f: &Fixture, id: Uuid, input: Value, key: &str) -> Value {
    let result = f
        .api(
            "invokeSkill",
            Some(id),
            json!({"input":input,"timeout_ms":15000}),
            key,
            None,
            None,
        )
        .await;
    assert_eq!(result.0, 200, "{key}: {}", result.1);
    assert_eq!(result.1["skill_id"], id.to_string());
    result.1["call"].clone()
}

async fn other_subject(f: &Fixture, list: Uuid, put: Uuid, input: &Value) {
    let created = f
        .api(
            "createChildAccount",
            Some(f.owner),
            json!({
                "display_name":"Object caller without Blob access",
                "inheritance":{"mode":"selected","rules":[
                    {"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[list,put]}},
                    {"action":"capability.invoke","resource":{"kind":"capability","match":"ids","ids":["data.object.list@1.0.0","data.object.put@1.0.0"]}}
                ]}
            }),
            "object-child",
            None,
            None,
        )
        .await;
    assert_eq!(created.0, 201, "{}", created.1);
    let password = "isolated object caller test password";
    let activated = f
        .api(
            "activateAccount",
            None,
            json!({"activation_token":created.1["activation_token"],"password":password}),
            "object-child-activate",
            None,
            None,
        )
        .await;
    assert_eq!(activated.0, 200);
    let login = f
        .api(
            "login",
            None,
            json!({"account_id":created.1["account"]["id"],"password":password}),
            "object-child-login",
            None,
            None,
        )
        .await;
    assert_eq!(login.0, 200);
    let token = login.1["access_token"].as_str().unwrap();
    let peer = "127.0.0.1".parse().unwrap();
    let listed = broker::invoke_skill(
        &f.app,
        token,
        peer,
        Uuid::new_v4(),
        list,
        &json!({"input":{},"timeout_ms":15000}),
        "child-list",
    )
    .await
    .unwrap();
    assert_eq!(listed["call"]["output"]["items"], json!([]));
    let denied = broker::invoke_skill(
        &f.app,
        token,
        peer,
        Uuid::new_v4(),
        put,
        &json!({"input":input,"timeout_ms":15000}),
        "child-foreign-source",
    )
    .await
    .unwrap_err();
    assert_eq!(denied.code, "PERMISSION_DENIED");
    assert!(denied.resource_id.is_none(), "denial must precede dispatch");
}

async fn disable(f: &Fixture, deployment: Uuid, key: &str) {
    let before = schema_bootstrap::current(f, deployment).await;
    let disabled = f
        .api(
            "setDeploymentEnabled",
            Some(deployment),
            json!({"enabled":false}),
            key,
            before["revision"].as_i64(),
            None,
        )
        .await;
    assert_eq!(disabled.0, 202, "{}", disabled.1);
    schema_bootstrap::terminal(f, contracts::id(&disabled.1, "id").unwrap(), "succeeded").await;
}

pub(super) async fn exercise() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(std::env::var("XELAB_XFS_TEST").unwrap(), "1");
    let f = Arc::new(Fixture::new(true).await.expect("isolated PostgreSQL"));
    let c = f.app.db.connect().await.unwrap();
    let publisher: Uuid = "00000000-0000-4000-8000-000000000001".parse().unwrap();
    let pem = SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    c.execute(
        "INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'Object storage fixture','fixture',$2,'trusted',now(),now())",
        &[&publisher,&pem],
    ).await.unwrap();
    let (installation, manifest, digest) = schema_bootstrap::register_artifact(
        &f,
        publisher,
        Path::new("examples/object-storage/generated/xelab/plugin.json"),
        "XELAB_TEST_OBJECT_STORAGE_IMAGE",
        "1",
    )
    .await;
    assert_eq!(
        manifest["concurrency"],
        json!({
            "max_active_requests":4,"max_queue_requests":32,"queue_timeout_ms":5000
        })
    );

    f.app.runtime.prepare_host_service_network().await.unwrap();
    f.app.ready.store(false, Ordering::SeqCst);
    let host = tokio::spawn(host::serve(f.app.clone()));
    let controller = tokio::spawn(controller::run(f.app.clone()));
    let supervisor = tokio::spawn(schema_jobs::run(f.app.clone()));
    let started = tokio::time::Instant::now();
    while !f.app.ready.load(Ordering::SeqCst) {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "startup fencing did not finish"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let volume = f
        .api(
            "createVolume",
            None,
            json!({"name":"objects","capacity_bytes":manifest["volumes"][0]["minimum_bytes"],"access":"single_writer","scope":"deployment"}),
            "object-volume",
            None,
            None,
        )
        .await;
    assert_eq!(volume.0, 202, "{}", volume.1);
    f.finish(&volume.1).await;
    let volume = contracts::id(&volume.1, "resource_id").unwrap();
    let data = schema_bootstrap::data_path(&f, volume).await;
    let config: Value = serde_json::from_str(include_str!(
        "../../../../docs/preset-plugins/object-storage/defaults.json"
    ))
    .unwrap();
    let created = f
        .api(
            "createDeployment",
            None,
            json!({"installation_id":installation,"display_name":"Object storage kernel acceptance","config":config,"limits":manifest["minimum_resources"],"replicas":1,"enabled":false,"volume_ids":[volume]}),
            "object-deployment",
            None,
            None,
        )
        .await;
    assert_eq!(created.0, 202, "{}", created.1);
    let deployment = contracts::id(&created.1, "resource_id").unwrap();
    let revision = schema_bootstrap::current(&f, deployment).await["revision"].as_i64();
    let denied = f
        .api(
            "setDeploymentEnabled",
            Some(deployment),
            json!({"enabled":true}),
            "object-enable-unapproved",
            revision,
            None,
        )
        .await;
    assert_eq!(denied.0, 403, "{}", denied.1);
    assert!(fs::read_dir(&data).unwrap().next().is_none());
    let rules: Vec<_> = manifest["requested_rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|request| &request["rule"])
        .collect();
    let approved = f
        .api(
            "approvePlugin",
            Some(deployment),
            json!({"rules":rules,"egress":[]}),
            "object-approve",
            revision,
            None,
        )
        .await;
    assert_eq!(approved.0, 200, "{}", approved.1);
    let (operation, _) = schema_bootstrap::enable(&f, deployment, "object-enable").await;
    schema_bootstrap::terminal(&f, operation, "succeeded").await;
    let row = c.query_one(
        "SELECT schema_state,data_schema_version,schema_proof FROM volume_allocations WHERE volume_id=$1",
        &[&volume],
    ).await.unwrap();
    assert_eq!(row.get::<_, String>("schema_state"), "verified");
    assert_eq!(row.get::<_, String>("data_schema_version"), "1");
    let proof: Value = row.get("schema_proof");
    assert_eq!(proof["operation_id"], operation.to_string());
    assert_eq!(proof["manifest_digest"], digest);
    assert!(data.join("objects.sqlite3").is_file());

    let mut skills = BTreeMap::new();
    for definition in manifest["skills"].as_array().unwrap() {
        let registered = f
            .api(
                "registerSkill",
                None,
                json!({"installation_id":installation,"definition":definition,"enabled":true}),
                definition["name"].as_str().unwrap(),
                None,
                None,
            )
            .await;
        assert_eq!(registered.0, 201, "{}", registered.1);
        skills.insert(
            definition["target"]["contract"]["name"].as_str().unwrap(),
            contracts::id(&registered.1, "id").unwrap(),
        );
    }
    assert_eq!(skills.len(), 6);
    let bare = f.api(
        "invokeCapability", None, json!({"contract":manifest["capabilities"][1]["contract"],"input":{},"timeout_ms":15000}),
        "object-bare-call", None, None,
    ).await;
    assert_eq!(bare.0, 403, "{}", bare.1);

    let bytes: Vec<_> = (0..600_123).map(|i| (i % 251) as u8).collect();
    let source = blob(&f, None, &bytes).await;
    assert_eq!(source.0, 201, "{}", String::from_utf8_lossy(&source.1));
    let source: Value = serde_json::from_slice(&source.1).unwrap();
    let key = "acceptance/multi-chunk";
    let input = json!({
        "key":key,"blob_id":source["id"],"size_bytes":bytes.len(),
        "digest":contracts::digest(&bytes),"content_type":"application/octet-stream","mode":"create"
    });
    let put = skill(&f, skills["data.object.put"], input.clone(), "object-put").await;
    let object = &put["output"]["object"];
    assert_eq!(object["revision"], 1);
    assert_eq!(object["digest"], source["digest"]);
    let stat_id = skills["data.object.stat"];
    let start: chrono::DateTime<chrono::Utc> = c
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
    let barrier = Arc::new(tokio::sync::Barrier::new(12));
    let concurrent = futures_util::future::try_join_all((0..12).map(|index| {
        let fixture = f.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            let started = tokio::time::Instant::now();
            let result = fixture
                .api(
                    "invokeSkill",
                    Some(stat_id),
                    json!({"input":{"key":key},"timeout_ms":15000}),
                    &format!("object-concurrent-stat-{index}"),
                    None,
                    None,
                )
                .await;
            (result, started.elapsed())
        })
    }))
    .await
    .unwrap();
    if concurrent.iter().any(|((status, _), _)| *status != 200) {
        let results: Vec<_> = concurrent
            .iter()
            .enumerate()
            .map(|(index, ((status, body), elapsed))| (index, *status, elapsed, &body["error"]))
            .collect();
        let ledger: Vec<_> = c.query(
            "SELECT idempotency_key,state,error->>'code',
                    extract(epoch FROM (created_at-$1::timestamptz))::float8 AS admission,
                    extract(epoch FROM (completed_at-$1::timestamptz))::float8 AS settlement
               FROM calls WHERE idempotency_key LIKE 'object-concurrent-stat-%' ORDER BY idempotency_key",
            &[&start],
        ).await.unwrap().into_iter()
            .map(|row| (row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,Option<String>>(2),
                        row.get::<_,f64>("admission"),row.get::<_,Option<f64>>("settlement")))
            .collect();
        panic!("Concurrent object reads failed: responses {results:?}; Call transaction offsets (seconds) {ledger:?}");
    }
    let longest = concurrent.iter().map(|(_, elapsed)| elapsed).max().unwrap();
    eprintln!("All 12 concurrent object stat calls completed in at most {longest:?}");
    for ((_, result), _) in concurrent {
        assert_eq!(result["call"]["output"]["object"], *object);
    }
    let listed = skill(&f, skills["data.object.list"], json!({}), "object-list").await;
    assert_eq!(listed["output"]["items"], json!([object]));
    let usage = skill(
        &f,
        skills["data.object.usage.get"],
        json!({}),
        "object-usage",
    )
    .await;
    assert_eq!(usage["output"]["owner_id"], f.owner.to_string());
    assert_eq!(usage["output"]["logical_bytes"], bytes.len());
    other_subject(
        &f,
        skills["data.object.list"],
        skills["data.object.put"],
        &input,
    )
    .await;

    let target = json!({"key":key,"expected_revision":1});
    let exported = skill(
        &f,
        skills["data.object.export"],
        target.clone(),
        "object-export",
    )
    .await;
    let output = &exported["output"];
    let result_blob = contracts::id(output, "blob_id").unwrap();
    assert_ne!(output["blob_id"], source["id"]);
    assert_eq!(output["object_id"], object["id"]);
    assert_eq!(output["digest"], source["digest"]);
    let (status, downloaded) = blob(&f, Some(result_blob), b"").await;
    assert_eq!(status, 200);
    assert!(downloaded == bytes, "exported Blob content differed");
    let metadata = f
        .api(
            "getBlob",
            Some(result_blob),
            Value::Null,
            "object-blob-meta",
            None,
            None,
        )
        .await;
    assert_eq!(metadata.0, 200, "{}", metadata.1);
    assert_eq!(metadata.1["owner_id"], f.owner.to_string());
    let replayed = skill(
        &f,
        skills["data.object.export"],
        target.clone(),
        "object-export",
    )
    .await;
    assert_eq!(exported, replayed);
    assert_eq!(
        c.query_one(
            "SELECT blob_id FROM host_blob_outputs WHERE call_id=$1",
            &[&contracts::id(&exported, "call_id").unwrap()]
        )
        .await
        .unwrap()
        .get::<_, Uuid>(0),
        result_blob,
    );

    disable(&f, deployment, "object-disable").await;
    let (operation, _) = schema_bootstrap::enable(&f, deployment, "object-reenable").await;
    schema_bootstrap::terminal(&f, operation, "succeeded").await;
    let stat = skill(
        &f,
        skills["data.object.stat"],
        json!({"key":key}),
        "object-stat-restart",
    )
    .await;
    assert_ne!(stat["provider_instance_id"], put["provider_instance_id"]);
    assert_eq!(stat["output"]["object"], *object);
    let deleted = skill(&f, skills["data.object.delete"], target, "object-delete").await;
    assert_eq!(deleted["output"]["deleted_revision"], 2);
    let listed = skill(
        &f,
        skills["data.object.list"],
        json!({}),
        "object-list-deleted",
    )
    .await;
    assert_eq!(listed["output"]["items"], json!([]));
    disable(&f, deployment, "object-final-disable").await;

    f.app.shutdown.store(true, Ordering::SeqCst);
    supervisor.await.unwrap();
    controller.await.unwrap();
    host.await.unwrap().unwrap();
    println!("Object storage: verified XFS bootstrap, six Skill RPCs, delegated Blob I/O and persistent restart");
}
