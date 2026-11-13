use super::{api, process_identity, process_start, register, wait_ready, HOLD};
use axum::Router;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use uuid::Uuid;
use xelab_kernel::{api::App, contracts, controller};

fn hold_received(path: &Path, call: Uuid) -> io::Result<bool> {
    let mut receipt = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(receipt) => receipt,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut bytes = [0; 36];
    let meta = receipt.metadata()?;
    if !meta.is_file()
        || meta.len() != bytes.len() as u64
        || meta.permissions().mode() & 0o777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP hold receipt",
        ));
    }
    receipt.read_exact(&mut bytes)?;
    Ok(bytes.as_slice() == call.hyphenated().encode_lower(&mut [0; 36]).as_bytes())
}

struct RunningHold {
    task: Uuid,
    step: Uuid,
    attempt: Uuid,
    call: Uuid,
    revision: i64,
    lease_expires_at: DateTime<Utc>,
    pid: u32,
    process_started: String,
}

async fn ready_instance(c: &Client, deployment: Uuid) -> Uuid {
    c.query_one(
        "SELECT id FROM instances WHERE deployment_id=$1 AND phase='ready'",
        &[&deployment],
    )
    .await
    .unwrap()
    .get(0)
}

async fn call_count(c: &Client) -> i64 {
    c.query_one("SELECT count(*) FROM calls", &[])
        .await
        .unwrap()
        .get(0)
}

async fn submit_hold(
    router: &Router,
    app: &App,
    token: &str,
    workflow: Uuid,
    deployment: Uuid,
    skill: Uuid,
    key: &str,
) -> RunningHold {
    let c = app.db.connect().await.unwrap();
    let instance = ready_instance(&c, deployment).await;
    let (pid, process_started) = process_identity(app, instance).await;
    let receipt = PathBuf::from(format!("/proc/{pid}/root/tmp/xelab-http-hold-receipt"));
    let (status, submitted) = api(
        router,
        "createTask",
        &[],
        Some(token),
        json!({"workflow_id":workflow,"input":{},"timeout_ms":45_000}),
        key,
        None,
    )
    .await;
    assert_eq!(status, 201, "{submitted}");
    let task = contracts::id(&submitted, "id").unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let row = c
                .query_opt(
                    "SELECT c.id,c.provider_instance_id,c.skill_id,c.http_binding,t.revision,
                            s.id AS step_id,a.id AS attempt_id,a.lease_expires_at
                     FROM tasks t JOIN task_steps s ON s.task_id=t.id
                     JOIN attempts a ON a.step_id=s.id JOIN calls c ON c.id=a.broker_call_id
                     JOIN reservations r ON r.id=c.id AND r.kind='call'
                     WHERE t.id=$1 AND t.state='running' AND a.state='running'
                       AND a.lease_expires_at>clock_timestamp()
                       AND c.state='running' AND r.status='active'",
                    &[&task],
                )
                .await
                .unwrap();
            if let Some(row) = row {
                assert_eq!(row.get::<_, Uuid>("provider_instance_id"), instance);
                assert_eq!(row.get::<_, Uuid>("skill_id"), skill);
                assert_eq!(row.get::<_, Value>("http_binding")["path"], HOLD);
                let call: Uuid = row.get("id");
                assert_eq!(process_start(pid).as_ref(), Some(&process_started));
                if hold_received(&receipt, call)
                    .expect("Read the HTTP fixture's private hold receipt")
                {
                    return RunningHold {
                        task,
                        step: row.get("step_id"),
                        attempt: row.get("attempt_id"),
                        call,
                        revision: row.get("revision"),
                        lease_expires_at: row.get("lease_expires_at"),
                        pid,
                        process_started,
                    };
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("The real HTTP workload did not receive the Task's admitted hold Call")
}

pub(crate) async fn cancel_and_restart_hold_tasks(
    router: &Router,
    app: &Arc<App>,
    token: &str,
    manifest: &Value,
    installed: &Value,
    deployment: &str,
    worker: &mut JoinHandle<()>,
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
            "name":"oci-task-http-hold",
            "input_schema":{"type":"object"},
            "steps":[{
                "id":"hold", "skill_id":skill, "depends_on":[],
                "input_mapping":{"message":{"literal":"interrupt this OCI hold"},"delay_ms":{"literal":5000}},
                "timeout_ms":10000, "maximum_attempts":2,
            }],
        }),
        "http-task-hold-workflow",
        None,
    )
    .await;
    assert_eq!(status, 201, "{workflow}");

    let mut c = app.db.connect().await.unwrap();
    let workflow = contracts::id(&workflow, "id").unwrap();
    let deployment_id: Uuid = deployment.parse().unwrap();
    let calls_before = call_count(&c).await;
    let RunningHold {
        task,
        call,
        revision,
        pid,
        process_started,
        ..
    } = submit_hold(
        router,
        app,
        token,
        workflow,
        deployment_id,
        skill,
        "http-task-cancel-submit",
    )
    .await;
    let params = [("task_id", task.to_string())];
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
    assert_eq!(
        call_count(&c).await,
        calls_before + 1,
        "Expected one Call for cancellation"
    );

    let hold = submit_hold(
        router,
        app,
        token,
        workflow,
        deployment_id,
        skill,
        "http-task-restart-submit",
    )
    .await;
    restart_hold_task(&mut c, app, worker, &hold).await;
    wait_ready(&app.db, deployment).await;
    let replacement = ready_instance(&c, deployment_id).await;
    assert_ne!(
        process_identity(app, replacement).await,
        (hold.pid, hold.process_started),
        "Restart must make a replacement OCI process ready"
    );
    let attempts: i64 = c
        .query_one(
            "SELECT count(*) FROM attempts WHERE step_id=$1",
            &[&hold.step],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(attempts, 1, "Restart must leave the original attempt alone");
    assert_eq!(
        call_count(&c).await,
        calls_before + 2,
        "Restart must never redispatch the Task"
    );
}

async fn restart_hold_task(
    c: &mut Client,
    app: &Arc<App>,
    worker: &mut JoinHandle<()>,
    hold: &RunningHold,
) {
    // Restart only the controller component in this test process. Dropping its
    // JoinSet aborts the Task worker while the real OCI provider is still live.
    worker.abort();
    assert!((&mut *worker).await.unwrap_err().is_cancelled());
    app.ready.store(false, Ordering::SeqCst);

    let tx = c.transaction().await.unwrap();
    let row = tokio::time::timeout(
        Duration::from_secs(3),
        tx.query_one(
            "SELECT r.status,t.state AS task_state,a.state AS attempt_state,
                    a.broker_call_id,a.lease_expires_at>clock_timestamp() AS live
             FROM reservations r JOIN attempts a ON a.id=$2
             JOIN task_steps s ON s.id=a.step_id JOIN tasks t ON t.id=s.task_id
             WHERE r.id=$1 AND r.kind='call' FOR UPDATE OF r",
            &[&hold.call, &hold.attempt],
        ),
    )
    .await
    .expect("Lock the old Call reservation after the controller abort")
    .unwrap();
    assert_eq!(row.get::<_, &str>("status"), "active");
    assert_eq!(row.get::<_, &str>("task_state"), "running");
    assert_eq!(row.get::<_, &str>("attempt_state"), "running");
    assert_eq!(row.get::<_, Uuid>("broker_call_id"), hold.call);
    assert!(row.get::<_, bool>("live"));
    assert_eq!(
        process_start(hold.pid).as_ref(),
        Some(&hold.process_started)
    );
    *worker = tokio::spawn(controller::run(app.clone()));
    // If startup tried to release the reservation before stopping the process,
    // the held row would block it before it could fence the process.
    tokio::time::timeout(Duration::from_secs(7), async {
        while process_start(hold.pid).as_ref() == Some(&hold.process_started) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Controller must stop the old OCI process while its reservation is held");
    tx.commit().await.unwrap();

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let row = c
                .query_one(
                    "SELECT r.status,t.state AS task_state,t.error,t.updated_at,
                        s.state AS step_state,a.state AS attempt_state,a.broker_call_id,
                        b.state AS call_state,e.created_at AS event_at,e.payload,
                        (SELECT count(*) FROM attempts WHERE step_id=s.id) AS attempts
                 FROM tasks t JOIN task_steps s ON s.id=$2 AND s.task_id=t.id
                 JOIN attempts a ON a.id=$3 AND a.step_id=s.id JOIN calls b ON b.id=$4
                 JOIN reservations r ON r.id=b.id AND r.kind='call'
                 LEFT JOIN outbox e ON e.topic='task.step.completed' AND e.aggregate_id=s.id
                                   AND e.payload->>'attempt_id'=a.id::text
                 WHERE t.id=$1",
                    &[&hold.task, &hold.step, &hold.attempt, &hold.call],
                )
                .await
                .unwrap();
            if row.get::<_, &str>("status") == "released" {
                assert_ne!(
                    process_start(hold.pid).as_ref(),
                    Some(&hold.process_started)
                );
                for column in ["task_state", "step_state", "attempt_state", "call_state"] {
                    assert_eq!(row.get::<_, &str>(column), "unknown", "{column}");
                }
                assert_eq!(row.get::<_, Uuid>("broker_call_id"), hold.call);
                assert_eq!(row.get::<_, i64>("attempts"), 1);
                let error: Value = row.get("error");
                assert_eq!(error["code"], "OUTCOME_UNKNOWN");
                assert_eq!(error["resource_id"], json!(hold.call));
                assert_eq!(row.get::<_, Value>("payload")["state"], "unknown");
                assert!(row.get::<_, DateTime<Utc>>("event_at") < hold.lease_expires_at);
                assert!(row.get::<_, DateTime<Utc>>("updated_at") < hold.lease_expires_at);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Controller did not settle the old attempt and Call after restart");
}
