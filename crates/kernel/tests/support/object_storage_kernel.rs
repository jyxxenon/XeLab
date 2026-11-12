//! Real kernel integration for the signed release image.
use super::*;
use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
use std::{collections::BTreeMap, path::Path, sync::atomic::Ordering};
use xelab_kernel::{controller, host, schema_jobs};

async fn blob(f: &Fixture, id: Option<Uuid>, data: &[u8]) -> (u16, Vec<u8>) {
    let request = Request::builder()
        .header("host", http_host::authority(None))
        .header("authorization", format!("Bearer {}", f.token));
    let request = if let Some(id) = id {
        request
            .method("GET")
            .uri(format!("/api/platform/v1/blobs/{id}/content"))
    } else {
        let digest = contracts::digest(data);
        request
            .method("POST")
            .uri("/api/platform/v1/blobs?content_type=application%2Foctet-stream")
            .header("content-type", "application/octet-stream")
            .header("content-length", data.len())
            .header("x-content-sha256", &digest)
            .header("idempotency-key", format!("object-source-{digest}"))
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

async fn invoke_skill(f: &Fixture, id: Uuid, input: Value, key: &str) -> (u16, Value) {
    invoke_skill_as(f, &f.token, id, input, key).await
}

async fn invoke_skill_as(
    f: &Fixture,
    token: &str,
    id: Uuid,
    input: Value,
    key: &str,
) -> (u16, Value) {
    f.api_as(
        ("invokeSkill", Some(id)),
        json!({"input":input,"timeout_ms":15000}),
        key,
        None,
        None,
        token,
    )
    .await
}

async fn skill(f: &Fixture, id: Uuid, input: Value, key: &str) -> Value {
    let result = invoke_skill(f, id, input, key).await;
    assert_eq!(result.0, 200, "{key}: {}", result.1);
    assert_eq!(result.1["skill_id"], id.to_string());
    result.1["call"].clone()
}

async fn rejected_skill(
    f: &Fixture,
    c: &tokio_postgres::Client,
    skill: Uuid,
    input: Value,
    key: &str,
    expected: (u16, &str),
    response: (u16, Value),
) {
    let (status, body) = response;
    assert_eq!(status, expected.0, "{key}: {body}");
    assert_eq!(body["error"]["code"], expected.1);
    let call = contracts::id(&body["error"], "resource_id").unwrap();
    let replay = invoke_skill(f, skill, input, key).await;
    assert_eq!(replay.0, status, "{key} replay: {}", replay.1);
    assert_eq!(replay.1["error"], body["error"]);
    let inspected = f
        .api(
            "getCall",
            Some(call),
            Value::Null,
            "object-inspect-failure",
            None,
            None,
        )
        .await;
    assert_eq!(inspected.0, 200, "{}", inspected.1);
    assert_eq!(inspected.1["state"], "failed");
    assert_eq!(inspected.1["error"], body["error"]);
    assert_eq!(
        c.query_one(
            "SELECT status FROM reservations WHERE id=$1 AND kind='call'",
            &[&call]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "released",
    );
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM calls WHERE skill_id=$1 AND idempotency_key=$2",
            &[&skill, &key]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1,
        "{key} left a single durable Call",
    );
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
    let listed = invoke_skill_as(f, token, list, json!({}), "child-list").await;
    assert_eq!(listed.0, 200, "{}", listed.1);
    assert_eq!(listed.1["call"]["output"]["items"], json!([]));
    let denied = invoke_skill_as(f, token, put, input.clone(), "child-foreign-source").await;
    assert_eq!(denied.0, 403, "{}", denied.1);
    assert_eq!(denied.1["error"]["code"], "PERMISSION_DENIED");
    assert!(
        denied.1["error"]["resource_id"].is_null(),
        "denial must precede dispatch"
    );
}

async fn api_key_authority(
    f: &Fixture,
    c: &tokio_postgres::Client,
    list: Uuid,
    put: Uuid,
    input: &Value,
    object: &Value,
) {
    let list_rules = vec![
        json!({"action":"skill.invoke","resource":{"kind":"skill","match":"ids","ids":[list]}}),
        json!({"action":"capability.invoke","resource":{"kind":"capability","match":"ids","ids":["data.object.list@1.0.0"]}}),
    ];
    let mut issuer_rules = list_rules.clone();
    issuer_rules.push(json!({
        "action":"credential.api-key.create",
        "resource":{"kind":"account","match":"ids","ids":[f.owner]}
    }));
    let now = chrono::Utc::now();
    let issuer = f
        .api(
            "createApiKey",
            Some(f.owner),
            json!({"name":"Object list key issuer","inheritance":{"mode":"selected","rules":issuer_rules},
                   "conditions":{"expires_at":now + chrono::Duration::hours(1)}}),
            "object-issue-list-issuer",
            None,
            None,
        )
        .await;
    assert_eq!(issuer.0, 201, "{}", issuer.1["error"]);
    let issuer_secret = issuer.1["secret"].as_str().unwrap();
    let credential = f
        .api_as(
            ("createApiKey", Some(f.owner)),
            json!({"name":"Object list only","inheritance":{"mode":"selected","rules":list_rules},
                   "conditions":{"expires_at":now + chrono::Duration::minutes(30)}}),
            "object-issue-list-key",
            None,
            None,
            issuer_secret,
        )
        .await;
    assert_eq!(credential.0, 201, "{}", credential.1["error"]);
    let secret = credential.1["secret"].as_str().unwrap();

    let listed = invoke_skill_as(f, secret, list, json!({}), "object-key-list").await;
    assert_eq!(listed.0, 200, "{}", listed.1);
    assert_eq!(listed.1["call"]["output"]["items"], json!([object]));
    let call = contracts::id(&listed.1["call"], "call_id").unwrap();
    let replay = invoke_skill_as(f, secret, list, json!({}), "object-key-list").await;
    assert_eq!(replay.0, 200, "{}", replay.1);
    assert_eq!(contracts::id(&replay.1["call"], "call_id").unwrap(), call);

    let denied = invoke_skill_as(f, secret, put, input.clone(), "object-key-put-denied").await;
    assert_eq!(denied.0, 403, "{}", denied.1);
    assert_eq!(denied.1["error"]["code"], "PERMISSION_DENIED");
    assert!(denied.1["error"]["resource_id"].is_null());

    let revoked = f
        .api(
            "revokeApiKey",
            Some(contracts::id(&issuer.1["credential"], "id").unwrap()),
            Value::Null,
            "object-revoke-list-issuer",
            issuer.1["credential"]["revision"].as_i64(),
            None,
        )
        .await;
    assert_eq!(revoked.0, 204, "{}", revoked.1);
    for key in ["object-key-list", "object-key-list-after-revoke"] {
        let rejected = invoke_skill_as(f, secret, list, json!({}), key).await;
        assert_eq!(rejected.0, 401, "{key}: {}", rejected.1);
        assert_eq!(rejected.1["error"]["code"], "INVALID_CREDENTIAL");
        assert!(rejected.1["error"]["resource_id"].is_null());
    }
    let records = c
        .query(
            "SELECT id,state FROM calls WHERE idempotency_key IN
               ('object-key-list','object-key-put-denied','object-key-list-after-revoke')",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].get::<_, Uuid>("id"), call);
    assert_eq!(records[0].get::<_, String>("state"), "succeeded");
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
    const TEST_QUOTA_BYTES: usize = 700_000;
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
    let mut config: Value = serde_json::from_str(include_str!(
        "../../../../docs/preset-plugins/object-storage/defaults.json"
    ))
    .unwrap();
    config["default_user_quota_bytes"] = json!(TEST_QUOTA_BYTES);
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
            let result = invoke_skill(
                &fixture,
                stat_id,
                json!({"key":key}),
                &format!("object-concurrent-stat-{index}"),
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
    assert_eq!(usage["output"]["quota_bytes"], TEST_QUOTA_BYTES);
    other_subject(
        &f,
        skills["data.object.list"],
        skills["data.object.put"],
        &input,
    )
    .await;
    api_key_authority(
        &f,
        &c,
        skills["data.object.list"],
        skills["data.object.put"],
        &input,
        object,
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
    let provider = contracts::id(&stat, "provider_instance_id").unwrap();
    let restart_count: i32 = c
        .query_one(
            "SELECT restart_count FROM instances WHERE id=$1",
            &[&provider],
        )
        .await
        .unwrap()
        .get(0);
    let other_bytes: Vec<_> = bytes.iter().map(|byte| *byte ^ 0x5a).collect();
    let other_source = blob(&f, None, &other_bytes).await;
    assert_eq!(other_source.0, 201);
    let other_source: Value = serde_json::from_slice(&other_source.1).unwrap();
    let mut replace = input.clone();
    replace["mode"] = json!("replace");
    replace["expected_revision"] = json!(1);
    let mut other_replace = replace.clone();
    other_replace["blob_id"] = other_source["id"].clone();
    other_replace["digest"] = other_source["digest"].clone();
    let put_id = skills["data.object.put"];
    let (left, right) = tokio::join!(
        invoke_skill(&f, put_id, replace.clone(), "object-replace-left"),
        invoke_skill(&f, put_id, other_replace.clone(), "object-replace-right"),
    );
    let mut winning_object = None;
    for (key, request, response) in [
        ("object-replace-left", replace, left),
        ("object-replace-right", other_replace, right),
    ] {
        if response.0 == 200 {
            assert!(
                winning_object.is_none(),
                "only one concurrent CAS may succeed"
            );
            assert_eq!(
                response.1["call"]["provider_instance_id"],
                provider.to_string()
            );
            let output = &response.1["call"]["output"]["object"];
            assert_eq!(output["id"], object["id"]);
            assert_eq!(output["revision"], 2);
            assert_eq!(output["digest"], request["digest"]);
            winning_object = Some(output.clone());
        } else {
            rejected_skill(
                &f,
                &c,
                put_id,
                request,
                key,
                (409, "STATE_CONFLICT"),
                response,
            )
            .await;
        }
    }
    let winning_object = winning_object.expect("one concurrent CAS committed");
    let after_cas = skill(&f, stat_id, json!({"key":key}), "object-stat-after-cas").await;
    assert_eq!(after_cas["output"]["object"], winning_object);

    let mut overflow = input.clone();
    overflow["key"] = json!("acceptance/over-quota");
    let quota_response = invoke_skill(&f, put_id, overflow.clone(), "object-over-quota").await;
    rejected_skill(
        &f,
        &c,
        put_id,
        overflow,
        "object-over-quota",
        (503, "RESOURCE_EXHAUSTED"),
        quota_response,
    )
    .await;
    let listed = skill(
        &f,
        skills["data.object.list"],
        json!({}),
        "object-list-after-quota-rejection",
    )
    .await;
    assert_eq!(listed["output"]["items"], json!([winning_object]));
    let usage = skill(
        &f,
        skills["data.object.usage.get"],
        json!({}),
        "object-usage-after-quota-rejection",
    )
    .await;
    assert_eq!(usage["output"]["logical_bytes"], bytes.len());
    assert_eq!(usage["output"]["reserved_bytes"], 0);

    let deleted = skill(
        &f,
        skills["data.object.delete"],
        json!({"key":key,"expected_revision":2}),
        "object-delete",
    )
    .await;
    assert_eq!(deleted["output"]["deleted_revision"], 3);
    let listed = skill(
        &f,
        skills["data.object.list"],
        json!({}),
        "object-list-deleted",
    )
    .await;
    assert_eq!(listed["output"]["items"], json!([]));
    let missing = json!({"key":key});
    let missing_response = invoke_skill(&f, stat_id, missing.clone(), "object-stat-deleted").await;
    rejected_skill(
        &f,
        &c,
        stat_id,
        missing,
        "object-stat-deleted",
        (404, "RESOURCE_NOT_FOUND"),
        missing_response,
    )
    .await;
    let current = c
        .query_one(
            "SELECT restart_count,phase FROM instances WHERE id=$1",
            &[&provider],
        )
        .await
        .unwrap();
    assert_eq!(current.get::<_, i32>("restart_count"), restart_count);
    assert_eq!(current.get::<_, String>("phase"), "ready");
    disable(&f, deployment, "object-final-disable").await;

    f.app.shutdown.store(true, Ordering::SeqCst);
    supervisor.await.unwrap();
    controller.await.unwrap();
    host.await.unwrap().unwrap();
    println!("Object storage: verified XFS bootstrap, six Skill RPCs, delegated Blob I/O and persistent restart");
    println!("Object storage: one concurrent CAS committed, and quota/missing/CAS rejections settled once without a provider restart");
}
