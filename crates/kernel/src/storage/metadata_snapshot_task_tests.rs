//! PostgreSQL COPY round-trip for Task and Call journals without runtime processes.
use super::{tests::target, *};
use crate::{
    api::{self, App},
    auth::Resource,
    backups::tests::Fixture,
    broker, contracts, task_engine,
};
use axum::{body::Body, extract::ConnectInfo, http::Request, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;

async fn post(f: &Fixture, router: &Router, path: &str, key: &str, body: Value) -> Value {
    let mut request = Request::post(path)
        .header(
            "host",
            crate::plugin_http_gateway::core_authority(&f.app.config).unwrap(),
        )
        .header("authorization", format!("Bearer {}", f.token))
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
    ));
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1048576)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, 201, "{value}");
    value
}

struct Provider {
    instance: Uuid,
    skill: Uuid,
    manifest: Value,
}

async fn provider(f: &Fixture, c: &Client, router: &Router, owner: Uuid) -> Provider {
    let publisher: Uuid = c
        .query_one("SELECT id FROM publishers LIMIT 1", &[])
        .await
        .unwrap()
        .get(0);
    let (installation, deployment, instance) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut manifest: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/secret-manifest.json")).unwrap();
    manifest["publisher_id"] = json!(publisher);
    manifest["requested_rules"] = json!([]);
    let capability = &manifest["capabilities"][0];
    let definition = json!({
        "name":"org.xelab.echo-python.snapshot-task", "version":"1.0.0",
        "description":"Task snapshot fixture", "mapping":"identity", "maximum_timeout_ms":30000,
        "target":{"kind":"capability","plugin_id":manifest["plugin_id"],"contract":capability["contract"]},
        "input_schema":capability["input_schema"], "output_schema":capability["output_schema"],
        "stream_item_schema":null, "input_blobs":false, "tags":[]
    });
    let contract = capability["contract"].clone();
    c.execute(
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
    manifest["skills"] = json!([definition]);
    crate::artifact::validate_profile(&manifest).unwrap();
    let hash = contracts::digest(&serde_json::to_vec(&manifest).unwrap());
    c.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at)
        VALUES($1,$2,'1.0.0',$3,$4,$4,$5,'installed',now(),now())",
        &[&installation,&manifest["plugin_id"].as_str().unwrap(),&publisher,&hash,&manifest]).await.unwrap();
    let spec = json!({"installation_id":installation,"display_name":"Snapshot Task provider","enabled":true,
        "replicas":1,"limits":manifest["minimum_resources"],"config":{},"volume_ids":[]});
    c.execute(
        "INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at)
        VALUES($1,$2,$3,$4,'ready',now(),now())",
        &[&deployment, &owner, &installation, &spec],
    )
    .await
    .unwrap();
    c.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,runtime_id,created_at,updated_at)
        VALUES($1,$2,1,0,'ready','alive',$3,$4,now(),now())",
        &[&instance,&deployment,&spec["limits"],&instance.to_string()]).await.unwrap();
    let skill = post(
        f,
        router,
        "/api/platform/v1/skills",
        "snapshot-task-skill",
        json!({"installation_id":installation,"definition":definition,"enabled":true}),
    )
    .await;
    Provider {
        instance,
        skill: contracts::id(&skill, "id").unwrap(),
        manifest,
    }
}

async fn submit(f: &Fixture, router: &Router, workflow: Uuid, key: &str) -> Uuid {
    let task = post(
        f,
        router,
        "/api/platform/v1/tasks",
        key,
        json!({"workflow_id":workflow,"input":{"message":key}}),
    )
    .await;
    assert_eq!(task["state"], "queued");
    contracts::id(&task, "id").unwrap()
}

async fn claim(c: &mut Client, app: &App, task: Uuid) -> task_engine::Lease {
    let tx = c.transaction().await.unwrap();
    let lease = task_engine::claim(&tx, &app.auth).await.unwrap().unwrap();
    assert_eq!(lease.task_id, task);
    tx.commit().await.unwrap();
    lease
}

async fn record_dispatch(
    c: &mut Client,
    app: &App,
    provider: &Provider,
    lease: &task_engine::Lease,
    output: Option<Value>,
) -> Uuid {
    let tx = c.transaction().await.unwrap();
    db::call_lock(&tx).await.unwrap();
    let (invocation, ctx) = task_engine::begin_broker(&tx, &app.auth, lease)
        .await
        .unwrap();
    let skill = crate::skills::resolve_for_invoke(&tx, &ctx, provider.skill)
        .await
        .unwrap();
    let capability = &provider.manifest["capabilities"][0];
    let contract = &capability["contract"];
    let resource = Resource::new(
        "capability",
        format!(
            "{}@{}",
            contract["name"].as_str().unwrap(),
            contract["version"].as_str().unwrap()
        ),
        None,
    );
    let (accounts, charged) = broker::reserve_business(
        &tx,
        &ctx,
        provider.instance,
        &provider.manifest,
        "capability.invoke",
        &resource,
        Some(&skill),
        None,
    )
    .await
    .unwrap();
    let call = Uuid::new_v4();
    let input_digest = contracts::digest(&serde_json::to_vec(&invocation.input).unwrap());
    tx.execute("INSERT INTO calls(id,owner_id,credential_id,provider_instance_id,skill_id,skill_definition_digest,
        contract,input_digest,idempotency_key,state,deadline_at,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'running',$10,now())",
        &[&call,&ctx.subject,&ctx.credential,&provider.instance,&provider.skill,&skill.definition_digest,
        &contract,&input_digest,&invocation.idempotency_key,&invocation.deadline]).await.unwrap();
    for credential in charged {
        tx.execute(
            "INSERT INTO call_credential_charges(call_id,credential_id) VALUES($1,$2)",
            &[&call, &credential],
        )
        .await
        .unwrap();
    }
    tx.execute("INSERT INTO reservations(id,account_id,kind,expires_at,status,created_at) VALUES($1,$2,'call',$3,'active',now())",
        &[&call,&ctx.subject,&invocation.deadline]).await.unwrap();
    app.auth
        .issue_rpc(&tx, &ctx, call, provider.instance, 1, invocation.deadline)
        .await
        .unwrap();
    crate::host_blobs::grant_skill_call(
        &tx,
        app,
        &ctx,
        call,
        invocation.deployment_id,
        &provider.manifest,
        capability,
        &invocation.input,
        false,
    )
    .await
    .unwrap();
    task_engine::record_broker_call(&tx, lease, call)
        .await
        .unwrap();
    if let Some(output) = output {
        task_engine::mark_broker_dispatch(&tx, lease, call)
            .await
            .unwrap();
        let result = json!({"call_id":call,"provider_instance_id":provider.instance,"contract":contract,
            "skill_id":skill.id,"skill_definition_digest":skill.definition_digest,
            "output":output,"completed_at":chrono::Utc::now()});
        contracts::validate("CallResult", &result).unwrap();
        broker::settle_business(&tx, &ctx, call, &accounts, "skill.invoke", &Ok(result))
            .await
            .unwrap();
        task_engine::complete(
            &tx,
            &app.auth,
            lease,
            task_engine::Outcome::Succeeded(output),
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    call
}

async fn journal(c: &Client, task: Uuid) -> Value {
    c.query_one(
        "SELECT jsonb_build_object('task',to_jsonb(t),'step',to_jsonb(s),'attempt',to_jsonb(a),'call',to_jsonb(c),
            'task_authority',e.status,'call_authority',ce.status,'reservation',r.status)
         FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN execution_delegations e ON e.id=t.delegation_id
         LEFT JOIN attempts a ON a.step_id=s.id LEFT JOIN calls c ON c.id=a.broker_call_id
         LEFT JOIN execution_delegations ce ON ce.id=c.delegation_id LEFT JOIN reservations r ON r.id=c.id
         WHERE t.id=$1", &[&task]).await.unwrap().get(0)
}

#[tokio::test]
async fn actual_postgres_task_copy_preserves_terminal_history_and_fences_unfinished_work() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut source = f.app.db.connect().await.unwrap();
    let owner = f
        .app
        .auth
        .authenticate(
            &source,
            &f.token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap()
        .subject;
    let router = api::router(f.app.clone());
    let provider = provider(&f, &source, &router, owner).await;
    let workflow = post(
        &f,
        &router,
        "/api/platform/v1/workflows",
        "snapshot-task-workflow",
        json!({
            "name":"snapshot-task","input_schema":{"type":"object"},"steps":[{
                "id":"echo","skill_id":provider.skill,"depends_on":[],"maximum_attempts":2,
                "timeout_ms":30000,"input_mapping":{"message":{"task_input":"/message"}}
            }]
        }),
    )
    .await;
    let workflow = contracts::id(&workflow, "id").unwrap();

    let completed = submit(&f, &router, workflow, "snapshot-task-succeeded").await;
    let lease = claim(&mut source, &f.app, completed).await;
    let confirmed = json!({"message":"confirmed before snapshot"});
    let completed_call = record_dispatch(
        &mut source,
        &f.app,
        &provider,
        &lease,
        Some(confirmed.clone()),
    )
    .await;
    let dispatched = submit(&f, &router, workflow, "snapshot-task-dispatched").await;
    let lease = claim(&mut source, &f.app, dispatched).await;
    let dispatched_call = record_dispatch(&mut source, &f.app, &provider, &lease, None).await;
    let leased = submit(&f, &router, workflow, "snapshot-task-leased").await;
    claim(&mut source, &f.app, leased).await;
    let queued = submit(&f, &router, workflow, "snapshot-task-queued").await;
    let ids = [completed, dispatched, leased, queued];
    let mut originals = Vec::new();
    for id in ids {
        originals.push(journal(&source, id).await);
    }
    assert_eq!(originals[0]["task"]["output"], json!({"echo":confirmed}));
    assert_eq!(originals[0]["call"]["id"], json!(completed_call));
    assert_eq!(originals[1]["attempt"]["state"], "running");
    assert_eq!(originals[1]["call"]["state"], "running");
    assert_eq!(originals[1]["reservation"], "active");
    assert_eq!(originals[2]["attempt"]["state"], "leased");
    assert!(originals[2]["call"].is_null());
    assert!(originals[3]["attempt"].is_null());

    crate::tasks::snapshot::validate(&source).await.unwrap();
    let tx = source.transaction().await.unwrap();
    tx.execute(
        "UPDATE calls SET idempotency_key='different-step-key' WHERE id=$1",
        &[&completed_call],
    )
    .await
    .unwrap();
    let error = crate::tasks::snapshot::validate(&tx).await.unwrap_err();
    assert_eq!(error.code, "STATE_CONFLICT");
    tx.rollback().await.unwrap();

    let mut bytes = Vec::new();
    let summary = export_inner(&mut source, &mut bytes).await.unwrap();
    let (_, mut destination, recovery) = target(f.backup).await;
    import_inner(
        &mut destination,
        &mut bytes.as_slice(),
        &summary,
        recovery,
        owner,
        "fresh Task metadata recovery password",
    )
    .await
    .unwrap();
    crate::recovery::ensure_task_authority_reset(&destination)
        .await
        .unwrap();

    let mut restored = Vec::new();
    for (id, original) in ids.into_iter().zip(&originals) {
        let saved = journal(&destination, id).await;
        assert_eq!(saved["task"]["admission"], original["task"]["admission"]);
        assert_eq!(saved["task_authority"], "revoked");
        assert_eq!(journal(&source, id).await, *original);
        restored.push(saved);
    }
    for field in ["task", "step", "attempt", "call"] {
        assert_eq!(restored[0][field], originals[0][field], "{field}");
    }
    assert_eq!(restored[0]["call"]["result"]["output"], confirmed);
    for field in ["task", "step", "attempt", "call"] {
        assert_eq!(restored[1][field]["state"], "unknown", "{field}");
    }
    assert_eq!(restored[1]["task"]["error"]["code"], "OUTCOME_UNKNOWN");
    assert_eq!(
        restored[1]["task"]["error"]["resource_id"],
        json!(dispatched_call)
    );
    assert_eq!(
        restored[1]["attempt"]["broker_call_id"],
        json!(dispatched_call)
    );
    assert_eq!(restored[1]["call_authority"], "revoked");
    assert_eq!(restored[1]["reservation"], "released");
    assert_eq!(restored[2]["task"]["state"], "paused_authorization");
    assert_eq!(restored[2]["step"]["state"], "ready");
    assert_eq!(restored[2]["attempt"]["state"], "expired");
    assert!(restored[2]["attempt"]["broker_call_id"].is_null());
    assert!(restored[2]["call"].is_null());
    assert_eq!(restored[3]["task"]["state"], "paused_authorization");
    assert_eq!(restored[3]["step"], originals[3]["step"]);
    assert!(restored[3]["attempt"].is_null());
    let active = destination
        .query_one(
            "SELECT
        (SELECT count(*) FROM attempts WHERE state IN ('leased','running')),
        (SELECT count(*) FROM rpc_delegations WHERE status='active'),
        (SELECT count(*) FROM reservations WHERE kind='call' AND status<>'released')",
            &[],
        )
        .await
        .unwrap();
    for index in 0..3 {
        assert_eq!(active.get::<_, i64>(index), 0);
    }
}
