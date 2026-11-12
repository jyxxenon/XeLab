use super::{login, request, Fixture, Reply, PASSWORD, WORKFLOWS};
use axum::http::Method;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicBool, Arc},
};
use uuid::Uuid;
use xelab_kernel::{
    api::{router, App},
    auth::Auth,
    config::Config,
    runtime::Runtime,
};

const TASKS: &str = "/api/platform/v1/tasks";

fn workflow_spec(fixture: &Fixture) -> Value {
    let mut spec = fixture.spec("task root");
    spec["input_schema"] = json!({
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
        "additionalProperties": false
    });
    spec["steps"][0]["timeout_ms"] = json!(2000);
    spec["steps"][0]["input_mapping"] = json!({"message": {"task_input": "/text"}});
    spec["steps"].as_array_mut().unwrap().push(json!({
        "id": "follow-up",
        "contract": fixture.contract,
        "depends_on": ["echo"],
        "input_mapping": {"message": {"step_output": {"step": "echo", "pointer": "/message"}}},
        "timeout_ms": 1000
    }));
    spec
}

async fn submit(fixture: &Fixture, token: &str, body: &Value, key: &str) -> Reply {
    request(
        &fixture.router,
        Method::POST,
        TASKS,
        Some(token),
        Some(body),
        &[("idempotency-key", key)],
    )
    .await
}

async fn scoped_key(
    fixture: &Fixture,
    owner: Uuid,
    session: &str,
    name: &str,
    rules: Value,
) -> String {
    request(
        &fixture.router,
        Method::POST,
        &format!("/api/platform/v1/accounts/{owner}/api-keys"),
        Some(session),
        Some(&json!({
            "name": name,
            "inheritance": {"mode": "selected", "rules": rules},
            "conditions": {"expires_at": Utc::now() + Duration::days(1)}
        })),
        &[("idempotency-key", name)],
    )
    .await
    .expect(201)
    .body["secret"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn id(object: &Value) -> Uuid {
    object["id"].as_str().unwrap().parse().unwrap()
}

fn timestamp(object: &Value, field: &str) -> DateTime<Utc> {
    object[field].as_str().unwrap().parse().unwrap()
}

fn capability_id(fixture: &Fixture) -> String {
    format!(
        "{}@{}",
        fixture.contract["name"].as_str().unwrap(),
        fixture.contract["version"].as_str().unwrap()
    )
}

async fn installed_deployment(fixture: &Fixture) -> Uuid {
    let deployment = Uuid::new_v4();
    fixture.db.connect().await.unwrap().execute(
        "INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at)
         SELECT $1,$2,id,jsonb_build_object('installation_id',id,'enabled',true,'limits',manifest->'minimum_resources'),'waiting_resources',now(),now()
         FROM installations WHERE id=$3",
        &[&deployment, &fixture.owner, &fixture.installation],
    ).await.unwrap();
    deployment
}

#[tokio::test]
async fn task_submission_pins_workflow_version_and_authority_without_execution() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let conn = fixture.db.connect().await.unwrap();
    let deployment = installed_deployment(&fixture).await;

    let mut spec = workflow_spec(&fixture);
    spec["steps"][0]["provider_deployment_id"] = json!(deployment);
    let first_workflow = fixture
        .publish(&fixture.token, &spec, "task-workflow-v1")
        .await
        .expect(201)
        .body;
    spec["steps"][1]["id"] = json!("new-version-only");
    let second_workflow = fixture
        .publish(&fixture.token, &spec, "task-workflow-v2")
        .await
        .expect(201)
        .body;
    assert_eq!(second_workflow["version"], 2);

    let body = json!({"workflow_id": first_workflow["id"], "input": {"text": "hello"}});
    let task = submit(&fixture, &fixture.token, &body, "create-task")
        .await
        .expect(201)
        .body;
    assert_eq!(task["workflow_id"], first_workflow["id"]);
    assert_eq!(task["owner_id"], json!(fixture.owner));
    assert_eq!(task["state"], "queued");
    assert_eq!(task["input"], body["input"]);
    assert!(task["output"].is_null());
    assert!(task["error"].is_null());
    assert!(task.get("admission").is_none());
    let deadline = timestamp(&task, "deadline_at");
    let lifetime = deadline - timestamp(&task, "created_at");
    assert!((lifetime - Duration::hours(24)).abs() < Duration::seconds(1));

    let steps = fixture
        .read(&fixture.token, &format!("{TASKS}/{}/steps", id(&task)))
        .await
        .expect(200)
        .body;
    let steps: BTreeMap<_, _> = steps["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| (step["step_key"].as_str().unwrap(), step))
        .collect();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps["echo"]["state"], "ready");
    assert_eq!(steps["echo"]["provider_deployment_id"], json!(deployment));
    assert_eq!(steps["follow-up"]["state"], "pending");
    assert!(steps["follow-up"]["provider_deployment_id"].is_null());
    for step in steps.values() {
        assert_eq!(step["attempt_count"], 0);
        assert_eq!(step["task_id"], task["id"]);
    }

    let stored = conn.query_one(
        "SELECT t.admission,d.subject_id,d.issuer_credential_id,d.maximum_rules,d.run_as,d.status,d.expires_at,
                c.expires_at AS issuer_expires_at
         FROM tasks t JOIN execution_delegations d ON d.id=t.delegation_id
         JOIN credentials c ON c.id=d.issuer_credential_id WHERE t.id=$1",
        &[&id(&task)],
    ).await.unwrap();
    let admission: Value = stored.get("admission");
    let issuer: Uuid = stored.get("issuer_credential_id");
    assert_eq!(admission["version"], 1);
    assert_eq!(admission["peer"], "127.0.0.1");
    assert!(admission["browser_origin"].is_null());
    assert!(admission["credential_chain"]
        .as_array()
        .unwrap()
        .contains(&json!(issuer)));
    assert!(!admission["workflow_paths"].as_array().unwrap().is_empty());
    assert_eq!(admission["steps"].as_array().unwrap().len(), 2);
    let frozen_steps: BTreeMap<_, _> = admission["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| (step["step_key"].as_str().unwrap(), step))
        .collect();
    let pinned = frozen_steps["echo"];
    assert_eq!(pinned["deployment_id"], json!(deployment));
    assert_eq!(pinned["installation_id"], json!(fixture.installation));
    assert_eq!(pinned["binding"]["routing"], "fixed");
    assert_eq!(pinned["binding"]["contract"], fixture.contract);
    let unpinned = frozen_steps["follow-up"];
    assert!(unpinned["deployment_id"].is_null());
    assert!(unpinned["installation_id"].is_null());
    assert_eq!(unpinned["binding"]["routing"], "stateless_direct");
    let capability_source: Uuid = conn
        .query_one(
            "SELECT id FROM grants WHERE subject_id=$1 AND scope->>'kind'='capability'",
            &[&fixture.owner],
        )
        .await
        .unwrap()
        .get(0);
    for step in admission["steps"].as_array().unwrap() {
        let target = step["targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|target| target["action"] == "capability.invoke")
            .unwrap();
        assert!(target["paths"].as_array().unwrap().iter().any(|path| {
            path["sources"]
                .as_array()
                .unwrap()
                .contains(&json!(capability_source))
        }));
    }
    let rules: Value = stored.get("maximum_rules");
    let capability_rules: Vec<_> = rules
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| rule["action"] == "capability.invoke")
        .collect();
    assert!(!capability_rules.is_empty());
    for rule in capability_rules {
        assert_eq!(
            rule["resource"],
            json!({"kind": "capability", "match": "ids", "ids": [capability_id(&fixture)]})
        );
    }
    assert_eq!(stored.get::<_, Uuid>("subject_id"), fixture.owner);
    assert_eq!(stored.get::<_, String>("run_as"), "user");
    assert_eq!(stored.get::<_, String>("status"), "active");
    let delegation_expiry: DateTime<Utc> = stored.get("expires_at");
    assert_eq!(
        delegation_expiry,
        stored.get::<_, DateTime<Utc>>("issuer_expires_at")
    );
    assert!(delegation_expiry < deadline);

    let audit = conn
        .query_one(
            "SELECT subject_id,credential_id,resource FROM audit_events
             WHERE action='createTask' AND outcome='succeeded'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(audit.get::<_, Uuid>("subject_id"), fixture.owner);
    assert_eq!(audit.get::<_, Uuid>("credential_id"), issuer);
    assert_eq!(
        audit.get::<_, Value>("resource"),
        json!({"kind": "task", "match": "ids", "ids": [task["id"]]})
    );

    let effects = conn
        .query_one(
            "SELECT (SELECT count(*) FROM calls), (SELECT count(*) FROM attempts),
                    (SELECT count(*) FROM reservations)",
            &[],
        )
        .await
        .unwrap();
    for index in 0..3 {
        assert_eq!(effects.get::<_, i64>(index), 0);
    }
}

#[tokio::test]
async fn task_skill_step_requires_skill_and_capability_authority_and_pins_provider() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let deployment = installed_deployment(&fixture).await;
    let skill = request(
        &fixture.router,
        Method::POST,
        "/api/platform/v1/skills",
        Some(&fixture.token),
        Some(&json!({
            "installation_id": fixture.installation,
            "definition": fixture.skill_definition,
            "enabled": true
        })),
        &[("idempotency-key", "task-register-skill")],
    )
    .await
    .expect(201)
    .body;
    let mut spec = workflow_spec(&fixture);
    let steps = spec["steps"].as_array_mut().unwrap();
    steps.truncate(1);
    let step = steps[0].as_object_mut().unwrap();
    step.remove("contract");
    step.insert("skill_id".to_owned(), skill["id"].clone());
    let workflow = fixture
        .publish(&fixture.token, &spec, "skill-workflow")
        .await
        .expect(201)
        .body;
    let body = json!({"workflow_id": workflow["id"], "input": {"text": "hello"}});

    for (name, target_rule) in [
        (
            "task-with-skill-only",
            json!({"action": "skill.invoke", "resource": {"kind": "skill", "match": "ids", "ids": [skill["id"]]}}),
        ),
        (
            "task-with-capability-only",
            json!({"action": "capability.invoke", "resource": {"kind": "capability", "match": "ids", "ids": [capability_id(&fixture)]}}),
        ),
    ] {
        let key = scoped_key(
            &fixture,
            fixture.owner,
            &fixture.token,
            name,
            json!([
                {"action": "task.create", "resource": {"kind": "task", "match": "owned_by", "owner_id": fixture.owner}},
                {"action": "workflow.read", "resource": {"kind": "workflow", "match": "ids", "ids": [workflow["id"]]}},
                target_rule
            ]),
        ).await;
        submit(&fixture, &key, &body, name).await.expect(403);
    }

    let task = submit(&fixture, &fixture.token, &body, "skill-task")
        .await
        .expect(201)
        .body;
    let steps = fixture
        .read(&fixture.token, &format!("{TASKS}/{}/steps", id(&task)))
        .await
        .expect(200)
        .body;
    assert_eq!(steps["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        steps["items"][0]["provider_deployment_id"],
        json!(deployment)
    );
    let admission: Value = fixture
        .db
        .connect()
        .await
        .unwrap()
        .query_one("SELECT admission FROM tasks WHERE id=$1", &[&id(&task)])
        .await
        .unwrap()
        .get(0);
    let bound = &admission["steps"][0];
    assert_eq!(bound["deployment_id"], json!(deployment));
    assert_eq!(bound["installation_id"], json!(fixture.installation));
    assert_eq!(bound["binding"]["kind"], "skill_capability");
    assert_eq!(bound["binding"]["skill_id"], skill["id"]);
    assert_eq!(
        bound["binding"]["definition_digest"],
        skill["definition_digest"]
    );
    assert_eq!(bound["binding"]["contract"], fixture.contract);
    let targets = bound["targets"].as_array().unwrap();
    for action in ["skill.invoke", "capability.invoke"] {
        assert!(targets.iter().any(|target| target["action"] == action));
    }

    installed_deployment(&fixture).await;
    submit(&fixture, &fixture.token, &body, "ambiguous-provider")
        .await
        .expect(409);
    assert_eq!(
        submit(&fixture, &fixture.token, &body, "skill-task")
            .await
            .expect(201)
            .body,
        task
    );
}

#[tokio::test]
async fn task_replay_survives_workflow_archive_and_fresh_submissions_are_rejected() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let workflow = fixture
        .publish(&fixture.token, &workflow_spec(&fixture), "archive-workflow")
        .await
        .expect(201);
    let submitter = scoped_key(
        &fixture,
        fixture.owner,
        &fixture.token,
        "task-submitter",
        json!([
            {"action": "task.create", "resource": {"kind": "task", "match": "owned_by", "owner_id": fixture.owner}},
            {"action": "workflow.read", "resource": {"kind": "workflow", "match": "ids", "ids": [workflow.body["id"]]}},
            {"action": "capability.invoke", "resource": {"kind": "capability", "match": "ids", "ids": [capability_id(&fixture)]}}
        ]),
    ).await;
    let body = json!({"workflow_id": workflow.body["id"], "input": {"text": "hello"}, "timeout_ms": 30000});
    let (first, duplicate) = tokio::join!(
        submit(&fixture, &submitter, &body, "archive-task"),
        submit(&fixture, &submitter, &body, "archive-task"),
    );
    let task = first.expect(201).body;
    assert_eq!(duplicate.expect(201).body, task);
    let timeout = timestamp(&task, "deadline_at") - timestamp(&task, "created_at");
    assert!((timeout - Duration::seconds(30)).abs() < Duration::seconds(1));
    fixture
        .archive(
            &format!("{WORKFLOWS}/{}", id(&workflow.body)),
            "archive-version",
            workflow.etag.as_deref(),
        )
        .await
        .expect(204);

    let replay = submit(&fixture, &submitter, &body, "archive-task")
        .await
        .expect(201);
    assert_eq!(replay.body, task);
    let mut changed = body.clone();
    changed["input"]["text"] = json!("changed");
    let conflict = submit(&fixture, &submitter, &changed, "archive-task")
        .await
        .expect(409);
    assert_eq!(conflict.body["error"]["code"], "IDEMPOTENCY_CONFLICT");
    submit(&fixture, &submitter, &body, "fresh-key")
        .await
        .expect(409);
    let read = fixture
        .read(&fixture.token, &format!("{TASKS}/{}", id(&task)))
        .await
        .expect(200);
    assert_eq!(read.body, task);
    assert_eq!(read.etag.as_deref(), Some("\"rev-1\""));
    let conn = fixture.db.connect().await.unwrap();
    let count: i64 = conn
        .query_one("SELECT count(*) FROM tasks", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);

    // Rebuild the HTTP boundary with a fresh leader connection and in-memory
    // state; both the task and its initial steps must be read from PostgreSQL.
    let Fixture {
        db,
        router: old_router,
        token,
        ..
    } = fixture;
    drop(old_router);
    let leader = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match db.leader().await {
                Ok(leader) => break leader,
                Err(error) if error.code == "STATE_CONFLICT" => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => panic!("Fresh controller could not acquire leadership: {error}"),
            }
        }
    })
    .await
    .unwrap();
    let source: toml::Value = toml::from_str(include_str!(
        "../../../../docs/contracts/examples/kernel.toml"
    ))
    .unwrap();
    let config = Config::from_value(serde_json::to_value(source).unwrap()).unwrap();
    let reopened = router(Arc::new(App {
        runtime: Runtime::new(config.clone()),
        config,
        db,
        auth: Auth::new(vec![55; 32]).unwrap(),
        leader: Arc::new(leader),
        ready: AtomicBool::new(true),
        shutdown: AtomicBool::new(false),
        blob_uploads: tokio::sync::Semaphore::new(4),
    }));
    let task_uri = format!("{TASKS}/{}", id(&task));
    assert_eq!(
        request(&reopened, Method::GET, &task_uri, Some(&token), None, &[])
            .await
            .expect(200)
            .body,
        task
    );
    let steps = request(
        &reopened,
        Method::GET,
        &format!("{task_uri}/steps"),
        Some(&token),
        None,
        &[],
    )
    .await
    .expect(200)
    .body;
    assert_eq!(steps["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn guest_capability_grant_does_not_authorize_task_creation_or_reads() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let workflow = fixture
        .publish(&fixture.token, &workflow_spec(&fixture), "guest-workflow")
        .await
        .expect(201)
        .body;
    let body = json!({"workflow_id": workflow["id"], "input": {"text": "hello"}});
    let task = submit(&fixture, &fixture.token, &body, "owner-task")
        .await
        .expect(201)
        .body;

    // A standalone account starts with no inherited Owner permissions.
    let guest = Uuid::new_v4();
    let hash = xelab_kernel::auth::password_hash(PASSWORD).unwrap();
    let conn = fixture.db.connect().await.unwrap();
    conn.execute(
        "INSERT INTO accounts(id,kind,status,display_name,password_hash,created_at,updated_at)
         VALUES($1,'user','active','Task Guest',$2,now(),now())",
        &[&guest, &hash],
    )
    .await
    .unwrap();
    conn.execute("INSERT INTO account_closure VALUES($1,$1,0)", &[&guest])
        .await
        .unwrap();
    conn.execute(
        "INSERT INTO quotas(account_id,spec,daily_bucket,created_at,updated_at)
         SELECT $1,spec,current_date,now(),now() FROM quotas WHERE account_id=$2",
        &[&guest, &fixture.owner],
    )
    .await
    .unwrap();
    request(
        &fixture.router,
        Method::POST,
        &format!("/api/platform/v1/accounts/{guest}/grants"),
        Some(&fixture.token),
        Some(&json!({
            "source": "role", "role_id": "Guest",
            "scope": {"kind": "capability", "match": "ids", "ids": [capability_id(&fixture)]}
        })),
        &[("idempotency-key", "task-guest-grant")],
    )
    .await
    .expect(201);
    let token = login(&fixture.router, guest).await;
    submit(&fixture, &token, &body, "guest-task")
        .await
        .expect(403);
    let task_uri = format!("{TASKS}/{}", id(&task));
    fixture.read(&token, &task_uri).await.expect(404);
    fixture
        .read(&token, &format!("{task_uri}/steps"))
        .await
        .expect(404);
    assert_eq!(
        fixture.read(&token, TASKS).await.expect(200).body["items"],
        json!([])
    );
}

#[tokio::test]
async fn parent_narrowing_blocks_child_task_replay_and_reads() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let (child, token) = fixture.child().await;
    let workflow = fixture
        .publish(&token, &workflow_spec(&fixture), "revocation-workflow")
        .await
        .expect(201)
        .body;
    let body = json!({"workflow_id": workflow["id"], "input": {"text": "hello"}});
    let task = submit(&fixture, &token, &body, "child-task")
        .await
        .expect(201)
        .body;
    let task_uri = format!("{TASKS}/{}", id(&task));
    fixture.read(&token, &task_uri).await.expect(200);

    let account = fixture
        .read(
            &fixture.token,
            &format!("/api/platform/v1/accounts/{child}"),
        )
        .await
        .expect(200);
    request(
        &fixture.router,
        Method::PUT,
        &format!("/api/platform/v1/accounts/{child}/inheritance"),
        Some(&fixture.token),
        Some(&json!({
            "mode": "selected",
            "rules": [{
                "action": "workflow.read",
                "resource": {"kind": "workflow", "match": "ids", "ids": [workflow["id"]]}
            }]
        })),
        &[
            ("idempotency-key", "withdraw-child-task-access"),
            ("if-match", account.etag.as_deref().unwrap()),
        ],
    )
    .await
    .expect(200);

    fixture
        .read(&token, &format!("{WORKFLOWS}/{}", id(&workflow)))
        .await
        .expect(200);
    submit(&fixture, &token, &body, "child-task")
        .await
        .expect(403);
    submit(&fixture, &token, &body, "child-fresh-task")
        .await
        .expect(403);
    fixture.read(&token, &task_uri).await.expect(404);
    fixture
        .read(&token, &format!("{task_uri}/steps"))
        .await
        .expect(404);
    assert_eq!(
        fixture.read(&token, TASKS).await.expect(200).body["items"],
        json!([])
    );
    assert_eq!(
        fixture
            .read(&fixture.token, &task_uri)
            .await
            .expect(200)
            .body,
        task
    );
}

#[tokio::test]
async fn task_admission_rejects_invalid_input_deadline_service_and_target_authority() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let workflow = fixture
        .publish(
            &fixture.token,
            &workflow_spec(&fixture),
            "negative-workflow",
        )
        .await
        .expect(201)
        .body;
    let body = json!({"workflow_id": workflow["id"], "input": {"text": "hello"}});
    let mut invalid_input = body.clone();
    invalid_input["input"]["text"] = json!(42);
    let mut short_deadline = body.clone();
    short_deadline["timeout_ms"] = json!(1000);
    let mut service = body.clone();
    service["run_as"] = json!("service");
    service["service_account_id"] = json!(Uuid::new_v4());
    let mut user_with_service_id = body.clone();
    user_with_service_id["service_account_id"] = service["service_account_id"].clone();
    for (key, request_body, status) in [
        ("invalid-input", invalid_input, 400),
        ("short-deadline", short_deadline, 400),
        ("unapproved-service", service, 403),
        ("user-with-service-id", user_with_service_id, 400),
    ] {
        submit(&fixture, &fixture.token, &request_body, key)
            .await
            .expect(status);
    }

    let without_target_authority = scoped_key(
        &fixture,
        fixture.owner,
        &fixture.token,
        "task-without-target",
        json!([
            {"action": "task.create", "resource": {"kind": "task", "match": "owned_by", "owner_id": fixture.owner}},
            {"action": "workflow.read", "resource": {"kind": "workflow", "match": "ids", "ids": [workflow["id"]]}}
        ]),
    ).await;
    submit(
        &fixture,
        &without_target_authority,
        &body,
        "forbidden-target",
    )
    .await
    .expect(403);
    let conn = fixture.db.connect().await.unwrap();
    let effects = conn
        .query_one(
            "SELECT (SELECT count(*) FROM tasks), (SELECT count(*) FROM task_steps),
                    (SELECT count(*) FROM execution_delegations), (SELECT count(*) FROM calls)",
            &[],
        )
        .await
        .unwrap();
    for index in 0..4 {
        assert_eq!(effects.get::<_, i64>(index), 0);
    }
}

#[tokio::test]
async fn task_step_insert_failure_rolls_back_submission_and_allows_same_key_retry() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let workflow = fixture
        .publish(
            &fixture.token,
            &workflow_spec(&fixture),
            "rollback-workflow",
        )
        .await
        .expect(201)
        .body;
    let conn = fixture.db.connect().await.unwrap();
    conn.batch_execute(
        "CREATE FUNCTION reject_test_follow_up() RETURNS trigger LANGUAGE plpgsql AS $test$
         BEGIN
           IF NEW.step_key='follow-up' AND EXISTS (
             SELECT FROM tasks t JOIN execution_delegations d ON d.id=t.delegation_id
             JOIN task_steps s ON s.task_id=t.id WHERE t.id=NEW.task_id AND s.step_key='echo'
           ) THEN
             RAISE EXCEPTION 'fixture rejected downstream step after initial writes';
           END IF;
           RETURN NEW;
         END;
         $test$;
         CREATE TRIGGER reject_test_follow_up BEFORE INSERT ON task_steps
           FOR EACH ROW EXECUTE FUNCTION reject_test_follow_up();",
    )
    .await
    .unwrap();

    let body = json!({"workflow_id": workflow["id"], "input": {"text": "hello"}});
    let key = "rollback-task";
    let failed = submit(&fixture, &fixture.token, &body, key)
        .await
        .expect(503);
    assert_eq!(
        failed.body["error"]["message"],
        "Metadata transaction failed"
    );
    let counts = conn
        .query_one(
            "SELECT (SELECT count(*) FROM tasks), (SELECT count(*) FROM execution_delegations),
                    (SELECT count(*) FROM task_steps),
                    (SELECT count(*) FROM idempotency_records WHERE method='POST' AND path=$1 AND key=$2)",
            &[&TASKS, &key],
        )
        .await
        .unwrap();
    for index in 0..4 {
        assert_eq!(counts.get::<_, i64>(index), 0);
    }
    conn.batch_execute(
        "DROP TRIGGER reject_test_follow_up ON task_steps;
         DROP FUNCTION reject_test_follow_up();",
    )
    .await
    .unwrap();
    let recovered = submit(&fixture, &fixture.token, &body, key)
        .await
        .expect(201);
    assert_eq!(recovered.body["workflow_id"], workflow["id"]);
    assert_eq!(recovered.body["state"], "queued");
    assert_eq!(
        fixture
            .read(
                &fixture.token,
                &format!("{TASKS}/{}/steps", id(&recovered.body))
            )
            .await
            .expect(200)
            .body["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn task_reads_scope_each_object_and_bind_cursors_to_state_subject_and_parent() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    let (child, child_token) = fixture.child().await;
    let spec = workflow_spec(&fixture);
    let owner_workflow = fixture
        .publish(&fixture.token, &spec, "read-owner-workflow")
        .await
        .expect(201)
        .body;
    let child_workflow = fixture
        .publish(&child_token, &spec, "read-child-workflow")
        .await
        .expect(201)
        .body;
    let owner_task = submit(
        &fixture,
        &fixture.token,
        &json!({"workflow_id": owner_workflow["id"], "input": {"text": "owner"}}),
        "read-owner-task",
    )
    .await
    .expect(201)
    .body;
    let child_task = submit(
        &fixture,
        &child_token,
        &json!({"workflow_id": child_workflow["id"], "input": {"text": "child"}}),
        "read-child-task",
    )
    .await
    .expect(201)
    .body;
    let reader = scoped_key(
        &fixture,
        child,
        &child_token,
        "task-reader",
        json!([{"action": "task.read", "resource": {"kind": "task", "match": "owned_by", "owner_id": child}}]),
    ).await;
    let owner_uri = format!("{TASKS}/{}", id(&owner_task));
    let child_uri = format!("{TASKS}/{}", id(&child_task));
    fixture.read(&reader, &owner_uri).await.expect(404);
    fixture
        .read(&reader, &format!("{owner_uri}/steps"))
        .await
        .expect(404);
    assert_eq!(
        fixture.read(&reader, &child_uri).await.expect(200).body,
        child_task
    );
    assert_eq!(
        fixture.read(&reader, TASKS).await.expect(200).body["items"],
        json!([child_task])
    );

    let page = fixture
        .read(&fixture.token, &format!("{TASKS}?state=queued&limit=1"))
        .await
        .expect(200)
        .body;
    let cursor = page["next_cursor"].as_str().unwrap();
    let next_uri = format!("{TASKS}?state=queued&limit=1&cursor={cursor}");
    fixture.read(&reader, &next_uri).await.expect(400);
    fixture
        .read(
            &fixture.token,
            &format!("{TASKS}?state=running&limit=1&cursor={cursor}"),
        )
        .await
        .expect(400);
    let next = fixture
        .read(&fixture.token, &next_uri)
        .await
        .expect(200)
        .body;
    assert_ne!(page["items"][0]["id"], next["items"][0]["id"]);
    assert!(next["next_cursor"].is_null());
    assert_eq!(
        fixture
            .read(&fixture.token, &format!("{TASKS}?state=running"))
            .await
            .expect(200)
            .body["items"],
        json!([])
    );

    let step_page = fixture
        .read(&fixture.token, &format!("{child_uri}/steps?limit=1"))
        .await
        .expect(200)
        .body;
    let step_cursor = step_page["next_cursor"].as_str().unwrap();
    fixture
        .read(
            &fixture.token,
            &format!("{owner_uri}/steps?limit=1&cursor={step_cursor}"),
        )
        .await
        .expect(400);
    let next_step = fixture
        .read(
            &fixture.token,
            &format!("{child_uri}/steps?limit=1&cursor={step_cursor}"),
        )
        .await
        .expect(200)
        .body;
    assert_ne!(step_page["items"][0]["id"], next_step["items"][0]["id"]);
    assert_eq!(next_step["items"][0]["task_id"], child_task["id"]);
    assert!(next_step["next_cursor"].is_null());
}
