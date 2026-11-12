use axum::Router;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;
use xelab_kernel::{api::App, contracts};

pub(crate) struct TaskCase<'a> {
    pub(crate) skill: Uuid,
    pub(crate) expected_instance: Uuid,
    pub(crate) reference_call: Uuid,
    pub(crate) input_mapping: Value,
    pub(crate) input: Value,
    pub(crate) expected_output: Value,
    pub(crate) suffix: &'a str,
}

/// Submit through the public API and wait for the real OCI Controller worker.
pub(crate) async fn run(app: &App, router: &Router, token: &str, case: TaskCase<'_>) -> Uuid {
    let c = app.db.connect().await.unwrap();
    let fixed = c
        .query_one(
            "SELECT k.definition,k.definition_digest,d.id AS deployment_id,c.owner_id,c.credential_id
             FROM calls c JOIN skills k ON k.id=c.skill_id JOIN instances i ON i.id=c.provider_instance_id
             JOIN deployments d ON d.id=i.deployment_id AND d.installation_id=k.installation_id
             WHERE c.id=$1 AND k.id=$2 AND i.id=$3 AND c.state='succeeded'
               AND c.skill_definition_digest=k.definition_digest",
            &[&case.reference_call, &case.skill, &case.expected_instance],
        )
        .await
        .unwrap();
    let issuer: Uuid = fixed.get("credential_id");
    let owner: Uuid = fixed.get("owner_id");
    let definition: Value = fixed.get("definition");
    let definition_digest: String = fixed.get("definition_digest");
    let deployment: Uuid = fixed.get("deployment_id");
    let step_timeout_ms = definition["maximum_timeout_ms"]
        .as_u64()
        .unwrap()
        .min(15_000);
    let suffix = case.suffix;
    let (status, workflow) = super::api(
        router,
        "createWorkflow",
        &[],
        Some(token),
        json!({
            "name":format!("oci-task-{suffix}"),
            "input_schema":{"type":"object"},
            "steps":[{
                "id":"probe", "skill_id":case.skill, "depends_on":[],
                "input_mapping":case.input_mapping, "timeout_ms":step_timeout_ms,
                "maximum_attempts":1,
            }],
        }),
        &format!("oci-task-workflow-{suffix}"),
        None,
    )
    .await;
    assert_eq!(status, 201, "{workflow}");
    let (status, task) = super::api(
        router,
        "createTask",
        &[],
        Some(token),
        json!({"workflow_id":workflow["id"],"input":case.input,"timeout_ms":45_000}),
        &format!("oci-task-submit-{suffix}"),
        None,
    )
    .await;
    assert_eq!(status, 201, "{task}");
    let task_id = contracts::id(&task, "id").unwrap();
    let result = wait_for_task(router, token, task_id).await;
    assert_eq!(result["output"], json!({"probe":case.expected_output}));

    let row = c.query_one(
        "SELECT s.id AS step_id,s.state AS step_state,s.output AS step_output,s.provider_deployment_id,
                a.id AS attempt_id,a.state AS attempt_state,a.idempotency_key AS attempt_key,
                c.id AS call_id,c.state AS call_state,c.credential_id,c.owner_id,c.skill_id,
                c.skill_definition_digest,c.provider_instance_id,c.idempotency_key AS call_key,c.result,
                c.delegation_id AS call_delegation,t.delegation_id AS task_delegation,r.status AS reservation_status,
                e.issuer_credential_id,
                (SELECT count(*) FROM attempts other WHERE other.step_id=s.id) AS attempts,
                (SELECT count(*) FROM calls other WHERE other.owner_id=t.owner_id AND other.idempotency_key=a.idempotency_key) AS calls,
                (SELECT count(*) FROM call_credential_charges q WHERE q.call_id=c.id AND q.credential_id=$2) AS issuer_charges
         FROM tasks t JOIN task_steps s ON s.task_id=t.id JOIN attempts a ON a.step_id=s.id
         JOIN execution_delegations e ON e.id=t.delegation_id JOIN calls c ON c.id=a.broker_call_id
         JOIN reservations r ON r.id=c.id AND r.kind='call' WHERE t.id=$1",
        &[&task_id, &issuer],
    ).await.unwrap();
    for column in ["step_state", "attempt_state", "call_state"] {
        assert_eq!(row.get::<_, String>(column), "succeeded", "{column}");
    }
    for column in ["attempts", "calls", "issuer_charges"] {
        assert_eq!(row.get::<_, i64>(column), 1, "{column}");
    }
    assert_eq!(row.get::<_, Uuid>("skill_id"), case.skill);
    assert_eq!(
        row.get::<_, String>("skill_definition_digest"),
        definition_digest
    );
    assert_eq!(
        row.get::<_, Uuid>("provider_instance_id"),
        case.expected_instance
    );
    assert_eq!(row.get::<_, Uuid>("provider_deployment_id"), deployment);
    assert_eq!(row.get::<_, Uuid>("owner_id"), owner);
    assert_eq!(row.get::<_, Uuid>("credential_id"), issuer);
    assert_eq!(row.get::<_, Uuid>("issuer_credential_id"), issuer);
    assert_ne!(
        row.get::<_, Uuid>("call_delegation"),
        row.get::<_, Uuid>("task_delegation")
    );
    assert_eq!(row.get::<_, String>("reservation_status"), "released");
    assert_eq!(row.get::<_, Value>("step_output"), case.expected_output);

    let step: Uuid = row.get("step_id");
    let attempt: Uuid = row.get("attempt_id");
    let call: Uuid = row.get("call_id");
    assert_ne!(call, case.reference_call);
    let business_key = format!("task-step:{step}");
    assert_eq!(row.get::<_, String>("attempt_key"), business_key);
    assert_eq!(row.get::<_, String>("call_key"), business_key);
    let call_result: Value = row.get("result");
    assert_eq!(call_result["call_id"], json!(call));
    assert_eq!(call_result.get("output"), Some(&case.expected_output));
    let event: Value = c
        .query_one(
            "SELECT payload FROM outbox WHERE topic='task.step.completed' AND aggregate_id=$1",
            &[&step],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        event,
        json!({"task_id":task_id,"step_id":step,"attempt_id":attempt,"state":"succeeded"})
    );
    call
}

async fn wait_for_task(router: &Router, token: &str, task: Uuid) -> Value {
    let params = [("task_id", task.to_string())];
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let (status, value) = super::api(
                router,
                "getTask",
                &params,
                Some(token),
                Value::Null,
                "oci-task-poll",
                None,
            )
            .await;
            assert_eq!(status, 200, "{value}");
            match value["state"].as_str() {
                Some("succeeded") => return value,
                Some("queued" | "running" | "waiting_dependency") => (),
                _ => panic!("Unexpected Task state {value}"),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Task {task} did not complete within 45 seconds"))
}
