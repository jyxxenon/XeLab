use super::{api, process_identity, process_start, register, wait_ready, HOLD};
use axum::Router;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;
use xelab_kernel::{api::App, contracts};

pub(crate) async fn cancel_hold_task(
    router: &Router,
    app: &App,
    token: &str,
    manifest: &Value,
    installed: &Value,
    deployment: &str,
) {
    let hold_index = manifest["skills"]
        .as_array()
        .unwrap()
        .iter()
        .position(|definition| definition["target"]["http_operation_id"] == "holdMessage")
        .expect("The mixed HTTP OCI test image must include the signed hold Skill");
    let skill: Uuid = register(router, token, manifest, installed, hold_index)
        .await
        .parse()
        .unwrap();
    let (status, workflow) = api(
        router,
        "createWorkflow",
        &[],
        Some(token),
        json!({
            "name":"oci-task-cancel-http-hold",
            "input_schema":{"type":"object"},
            "steps":[{
                "id":"hold", "skill_id":skill, "depends_on":[],
                "input_mapping":{"message":{"literal":"cancel this OCI hold"},"delay_ms":{"literal":5000}},
                "timeout_ms":10000, "maximum_attempts":2,
            }],
        }),
        "http-task-cancel-workflow",
        None,
    )
    .await;
    assert_eq!(status, 201, "{workflow}");

    let c = app.db.connect().await.unwrap();
    let deployment_id: Uuid = deployment.parse().unwrap();
    let instance: Uuid = c
        .query_one(
            "SELECT id FROM instances WHERE deployment_id=$1 AND phase='ready'",
            &[&deployment_id],
        )
        .await
        .unwrap()
        .get(0);
    let (pid, process_started) = process_identity(app, instance).await;
    let calls_before: i64 = c
        .query_one("SELECT count(*) FROM calls", &[])
        .await
        .unwrap()
        .get(0);

    let (status, submitted) = api(
        router,
        "createTask",
        &[],
        Some(token),
        json!({"workflow_id":workflow["id"],"input":{},"timeout_ms":45_000}),
        "http-task-cancel-submit",
        None,
    )
    .await;
    assert_eq!(status, 201, "{submitted}");
    let task = contracts::id(&submitted, "id").unwrap();
    let params = [("task_id", task.to_string())];
    let (call, revision) = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let row = c
                .query_opt(
                    "SELECT c.id,c.provider_instance_id,c.skill_id,c.http_binding,t.revision
                 FROM tasks t JOIN task_steps s ON s.task_id=t.id
                 JOIN attempts a ON a.step_id=s.id JOIN calls c ON c.id=a.broker_call_id
                 JOIN reservations r ON r.id=c.id AND r.kind='call'
                 WHERE t.id=$1 AND t.state='running' AND a.state='running'
                   AND c.state='running' AND r.status='active'",
                    &[&task],
                )
                .await
                .unwrap();
            if let Some(row) = row {
                assert_eq!(row.get::<_, Uuid>("provider_instance_id"), instance);
                assert_eq!(row.get::<_, Uuid>("skill_id"), skill);
                assert_eq!(row.get::<_, Value>("http_binding")["path"], HOLD);
                break (row.get::<_, Uuid>("id"), row.get::<_, i64>("revision"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("The HTTP hold Task did not admit a Call with a physical reservation");
    assert_eq!(process_start(pid).as_ref(), Some(&process_started));
    let (status, pending) = api(
        router,
        "cancelTask",
        &params,
        Some(token),
        json!({"reason":"Fence the in-flight HTTP hold"}),
        "http-task-cancel",
        Some(revision),
    )
    .await;
    assert_eq!(status, 200, "{pending}");
    assert_eq!(pending["state"], "cancel_requested");

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let row = c.query_one(
                "SELECT t.state AS task_state,c.state AS call_state,c.error,r.status AS reservation_status
                 FROM tasks t JOIN calls c ON c.id=$2 JOIN reservations r ON r.id=c.id AND r.kind='call'
                 WHERE t.id=$1",
                &[&task, &call],
            ).await.unwrap();
            assert_eq!(row.get::<_, String>("call_state"), "unknown");
            assert_eq!(row.get::<_, Value>("error")["code"], "CANCELED");
            let reservation: String = row.get("reservation_status");
            if reservation == "released" {
                assert_ne!(
                    process_start(pid).as_ref(),
                    Some(&process_started),
                    "Controller released the reservation while the original OCI process was alive"
                );
            }
            match row.get::<_, &str>("task_state") {
                "canceled" => {
                    assert_eq!(reservation, "released");
                    break;
                }
                "cancel_requested" => (),
                state => panic!("Unexpected Task state after cancel: {state}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Controller did not finish Task cancellation after fencing the HTTP workload");

    let (status, canceled) = api(
        router,
        "getTask",
        &params,
        Some(token),
        Value::Null,
        "http-task-cancel-read",
        None,
    )
    .await;
    assert_eq!(status, 200, "{canceled}");
    assert_eq!(canceled["state"], "canceled");
    let (status, steps) = api(
        router,
        "listTaskSteps",
        &params,
        Some(token),
        Value::Null,
        "http-task-cancel-steps",
        None,
    )
    .await;
    assert_eq!(status, 200, "{steps}");
    let steps = steps["items"].as_array().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["state"], "unknown");
    assert_eq!(steps[0]["attempt_count"], 1);
    wait_ready(&app.db, deployment).await;
    let calls: i64 = c
        .query_one("SELECT count(*) FROM calls", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(calls, calls_before + 1, "Expected one Call for this Task");
}
