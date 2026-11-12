//! Shared privileged OCI fixtures for disposable Linux hosts.
use super::http_host;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::Request,
    Router,
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use serde_json::{json, Value};
use std::{fs, net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, time::Duration};
use tower::ServiceExt;
use xelab_kernel::{admission, config::Config, contracts, runtime::Runtime, tls};

pub(super) fn workload_ca() -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec!["xelab-test-ca".into()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = ca.self_signed(&key).unwrap();
    (cert, key)
}

pub(super) async fn prepare_runtime(
    root: &Path,
    namespace: &str,
    cert: &Certificate,
    key: &KeyPair,
) -> (Config, Runtime) {
    fs::write(root.join("ca.crt"), cert.pem()).unwrap();
    fs::write(root.join("ca.key"), key.serialize_pem()).unwrap();
    fs::set_permissions(root.join("ca.key"), fs::Permissions::from_mode(0o600)).unwrap();
    let t: toml::Value = toml::from_str(include_str!(
        "../../../../docs/contracts/examples/kernel.toml"
    ))
    .unwrap();
    let mut value = serde_json::to_value(t).unwrap();
    value["storage"]["root_path"] = json!(root.join("state"));
    value["security"]["workload_ca_cert_file"] = json!(root.join("ca.crt"));
    value["security"]["workload_ca_key_file"] = json!(root.join("ca.key"));
    value["security"]["master_key_file"] = json!(root.join("master.key"));
    fs::write(root.join("master.key"), [42; 32]).unwrap();
    fs::set_permissions(root.join("master.key"), fs::Permissions::from_mode(0o600)).unwrap();
    value["runtime"]["namespace"] = json!(namespace);
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
    (config, runtime)
}

#[allow(clippy::too_many_arguments)] // Test request envelope.
pub(super) async fn api(
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

pub(super) async fn finished_operation(router: &Router, id: &str, token: &str) -> Value {
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
        if matches!(value["state"].as_str(), Some("succeeded" | "failed")) {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("operation {id} did not finish");
}

pub(super) async fn operation(router: &Router, id: &str, token: &str) -> Value {
    let value = finished_operation(router, id, token).await;
    assert_eq!(value["state"], "succeeded", "{value}");
    if matches!(
        value["kind"].as_str(),
        Some("createDeployment" | "setDeploymentEnabled")
    ) {
        contracts::validate("Deployment", &value["result"]).unwrap();
        assert_eq!(value["result"]["id"], value["resource_id"]);
    }
    value["result"].clone()
}

// Controlled process restarts can change observation revisions between GET and
// PUT. Retry only a confirmed precondition rejection with unchanged intent;
// never replay an accepted or uncertain mutation with a new fingerprint.
pub(super) async fn disable_after_observation(
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

pub(super) async fn stream_skill_request(
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

pub(super) async fn collect_skill_events(body: Body) -> Vec<Value> {
    let bytes = tokio::time::timeout(Duration::from_secs(20), to_bytes(body, 4194304))
        .await
        .unwrap()
        .unwrap();
    parse_skill_events(std::str::from_utf8(&bytes).unwrap())
}

pub(super) fn parse_skill_events(text: &str) -> Vec<Value> {
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
