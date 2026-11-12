#![allow(clippy::result_large_err)] // Tonic service trait signatures.
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio::sync::{watch, RwLock};
use tonic::{Request, Response, Status};
use xelab_kernel::contracts::{digest, strict_json, validate_business};
use xelab_plugin_sdk::{
    rpc::{
        self,
        capability_service_server::{CapabilityService, CapabilityServiceServer},
        plugin_lifecycle_server::{PluginLifecycle, PluginLifecycleServer},
    },
    transport::{WorkloadIdentity, PLUGIN_RPC_LISTEN},
};

#[derive(Clone)]
struct Echo {
    manifest: Arc<Vec<u8>>,
    generation: u64,
    initialized: Arc<AtomicBool>,
    draining: Arc<AtomicBool>,
    results: Arc<RwLock<std::collections::HashMap<String, SavedResult>>>,
    effects: Arc<AtomicU64>,
    cells: Arc<RwLock<std::collections::BTreeMap<String, String>>>,
    active_streams: Arc<RwLock<std::collections::HashMap<String, watch::Sender<bool>>>>,
    health_observed: watch::Sender<u64>,
}
#[derive(Clone)]
struct SavedResult {
    key: String,
    input_digest: String,
    response: rpc::InvokeResponse,
}

impl Echo {
    async fn next_health(&self, deadline: i64) -> Result<(), Status> {
        // Subscribe after the result is committed. watch retains a subsequent
        // real Health observation even if it arrives before changed() is polled.
        let mut health = self.health_observed.subscribe();
        let expired = || Status::deadline_exceeded("No subsequent Health before call deadline");
        if chrono::Utc::now().timestamp_millis() >= deadline {
            return Err(expired());
        }
        let remaining = std::time::Duration::from_millis(
            deadline
                .saturating_sub(chrono::Utc::now().timestamp_millis())
                .clamp(0, 300000) as u64,
        );
        tokio::time::timeout(remaining, health.changed())
            .await
            .map_err(|_| expired())?
            .map_err(|_| Status::unavailable("Health observation channel closed"))?;
        if chrono::Utc::now().timestamp_millis() >= deadline {
            return Err(expired());
        }
        Ok(())
    }
    fn execution_count(&self, effect: &str) -> Option<u64> {
        match effect {
            "queryable" | "non_repeatable" => Some(self.effects.fetch_add(1, Ordering::SeqCst) + 1),
            _ => None,
        }
    }
    async fn assign_cell(&self, message: &str) -> Result<(), Status> {
        // Intrinsically idempotent assignment to the input's fixed cell. This
        // process-local probe is not a persistent business-data profile. There
        // is no increment or regenerated value on repetition or restart.
        let cell = digest(message.as_bytes());
        let mut cells = self.cells.write().await;
        if cells.len() >= 1024 && !cells.contains_key(&cell) {
            return Err(Status::resource_exhausted("Reference cells are full"));
        }
        cells.insert(cell, message.to_owned());
        Ok(())
    }
}
#[tonic::async_trait]
impl PluginLifecycle for Echo {
    async fn describe(
        &self,
        _: Request<rpc::DescribeRequest>,
    ) -> Result<Response<rpc::DescribeResponse>, Status> {
        Ok(Response::new(rpc::DescribeResponse {
            manifest_json: self.manifest.as_ref().clone(),
            manifest_digest: digest(&self.manifest),
        }))
    }
    async fn initialize(
        &self,
        r: Request<rpc::InitializeRequest>,
    ) -> Result<Response<rpc::InitializeResponse>, Status> {
        let r = r.into_inner();
        if r.generation != self.generation
            || r.instance_id != std::env::var("XELAB_INSTANCE_ID").unwrap_or_default()
            || r.deployment_id != std::env::var("XELAB_DEPLOYMENT_ID").unwrap_or_default()
            || digest(&r.config_json) != r.config_digest
        {
            return Err(Status::failed_precondition("Identity or config differs"));
        }
        self.initialized.store(true, Ordering::SeqCst);
        self.draining.store(false, Ordering::SeqCst);
        Ok(Response::new(rpc::InitializeResponse {
            observed_generation: self.generation,
            initialized: true,
        }))
    }
    async fn get_health(
        &self,
        _: Request<rpc::HealthRequest>,
    ) -> Result<Response<rpc::HealthResponse>, Status> {
        let m = strict_json(&self.manifest, 1048576)
            .map_err(|_| Status::internal("Invalid manifest"))?;
        // The SDK admits authenticated kernel connections. Signal readiness
        // only after a real probe reaches this service.
        let ready =
            self.initialized.load(Ordering::SeqCst) && !self.draining.load(Ordering::SeqCst);
        if ready {
            self.health_observed
                .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        }
        Ok(Response::new(rpc::HealthResponse {
            alive: true,
            observed_generation: self.generation,
            capabilities: m["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .map(|cap| rpc::CapabilityHealth {
                    features: Vec::new(),
                    contract: Some(rpc::ContractRef {
                        name: cap["contract"]["name"].as_str().unwrap().into(),
                        version: cap["contract"]["version"].as_str().unwrap().into(),
                        schema_digest: cap["contract"]["schema_digest"].as_str().unwrap().into(),
                    }),
                    ready,
                    reason_code: String::new(),
                })
                .collect(),
        }))
    }
    async fn drain(
        &self,
        _: Request<rpc::DrainRequest>,
    ) -> Result<Response<rpc::DrainResponse>, Status> {
        self.draining.store(true, Ordering::SeqCst);
        let active = self.active_streams.read().await;
        for cancellation in active.values() {
            let _ = cancellation.send(true);
        }
        Ok(Response::new(rpc::DrainResponse {
            accepting_requests: false,
            active_calls: active.len() as u32,
            drained: active.is_empty(),
        }))
    }
    async fn shutdown(
        &self,
        _: Request<rpc::ShutdownRequest>,
    ) -> Result<Response<rpc::Ack>, Status> {
        self.draining.store(true, Ordering::SeqCst);
        Ok(Response::new(rpc::Ack {
            request_id: uuid::Uuid::new_v4().to_string(),
            accepted: true,
        }))
    }
}
#[tonic::async_trait]
impl CapabilityService for Echo {
    async fn invoke(
        &self,
        r: Request<rpc::InvokeRequest>,
    ) -> Result<Response<rpc::InvokeResponse>, Status> {
        let r = r.into_inner();
        if !self.initialized.load(Ordering::SeqCst) || self.draining.load(Ordering::SeqCst) {
            return Err(Status::unavailable("Not initialized"));
        }
        if digest(&r.input_json) != r.input_digest {
            return Err(Status::invalid_argument("Digest differs"));
        }
        let input = strict_json(&r.input_json, 65536)
            .map_err(|_| Status::invalid_argument("Invalid input"))?;
        let context = r
            .context
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Context required"))?;
        if context.deadline_unix_ms <= chrono::Utc::now().timestamp_millis()
            || context.delegation_token.is_empty()
            || context.idempotency_key.is_empty()
        {
            return Err(Status::invalid_argument("Invalid request context"));
        }
        let manifest = strict_json(&self.manifest, 1048576)
            .map_err(|_| Status::internal("Invalid manifest"))?;
        let contract = r
            .contract
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Contract required"))?;
        let cap = manifest["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|cap| {
                cap["contract"]["name"] == contract.name
                    && cap["contract"]["version"] == contract.version
                    && cap["contract"]["schema_digest"] == contract.schema_digest
            })
            .ok_or_else(|| Status::invalid_argument("No matching signed contract"))?;
        validate_business(&cap["input_schema"], &input)
            .map_err(|_| Status::invalid_argument("Input schema differs"))?;
        let mut results = self.results.write().await;
        if let Some(saved) = results.get(&r.call_id) {
            if saved.key != context.idempotency_key || saved.input_digest != r.input_digest {
                return Err(Status::failed_precondition("Call key or input differs"));
            }
            return Ok(Response::new(saved.response.clone()));
        }
        if cap["side_effect"] == "idempotent" {
            self.assign_cell(input["message"].as_str().unwrap()).await?;
        }
        let mut value = if !cap["stream_item_schema"].is_null() {
            serde_json::json!({"message":input["message"]})
        } else {
            input.clone()
        };
        if let Some(count) = self.execution_count(cap["side_effect"].as_str().unwrap()) {
            value["execution_count"] = count.into();
        }
        let output =
            serde_json::to_vec(&value).map_err(|_| Status::internal("Serialization failed"))?;
        let response = rpc::InvokeResponse {
            call_id: r.call_id.clone(),
            output_digest: digest(&output),
            output_json: output,
        };
        if results.len() >= 1024 {
            results.clear();
        }
        results.insert(
            r.call_id,
            SavedResult {
                key: context.idempotency_key.clone(),
                input_digest: r.input_digest,
                response: response.clone(),
            },
        );
        drop(results);
        if input["fault"] == "after-commit-health" {
            self.next_health(context.deadline_unix_ms).await?;
        }
        if matches!(
            input["fault"].as_str(),
            Some("after-commit" | "after-commit-health")
        ) {
            return Err(Status::unavailable(
                "Reference response lost after committed execution",
            ));
        }
        Ok(Response::new(response))
    }
    type InvokeStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<rpc::InvokeChunk, Status>>;
    async fn invoke_stream(
        &self,
        request: Request<rpc::InvokeRequest>,
    ) -> Result<Response<Self::InvokeStreamStream>, Status> {
        if !self.initialized.load(Ordering::SeqCst) || self.draining.load(Ordering::SeqCst) {
            return Err(Status::unavailable("Not initialized"));
        }
        let request = request.into_inner();
        let context = request
            .context
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Context required"))?;
        if context.deadline_unix_ms <= chrono::Utc::now().timestamp_millis()
            || context.delegation_token.is_empty()
            || digest(&request.input_json) != request.input_digest
        {
            return Err(Status::invalid_argument(
                "Invalid request context or digest",
            ));
        }
        let manifest = strict_json(&self.manifest, 1048576)
            .map_err(|_| Status::internal("Invalid manifest"))?;
        let contract = request
            .contract
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Contract required"))?;
        let cap = manifest["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|cap| {
                cap["contract"]["name"] == contract.name
                    && cap["contract"]["version"] == contract.version
                    && cap["contract"]["schema_digest"] == contract.schema_digest
                    && !cap["stream_item_schema"].is_null()
            })
            .ok_or_else(|| Status::invalid_argument("No matching signed streaming contract"))?;
        let input = strict_json(&request.input_json, 65536)
            .map_err(|_| Status::invalid_argument("Invalid input"))?;
        validate_business(&cap["input_schema"], &input)
            .map_err(|_| Status::invalid_argument("Input schema differs"))?;
        // JSON Schema integers also include integral forms such as 1.0. The
        // signed schema above bounds both values to small exact integers.
        let count = input["count"]
            .as_f64()
            .map(|value| value as u64)
            .unwrap_or(3);
        let delay = std::time::Duration::from_millis(
            input["delay_ms"]
                .as_f64()
                .map(|value| value as u64)
                .unwrap_or(0),
        );
        let fault = input["fault"].as_str().unwrap_or("none").to_owned();
        let message = input["message"].as_str().unwrap().to_owned();
        let call = request.call_id;
        let key = context.idempotency_key.clone();
        let input_digest = request.input_digest;
        let deadline = context.deadline_unix_ms;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let (cancellation, mut canceled) = watch::channel(false);
        let mut active = self.active_streams.write().await;
        if active.len() >= 4 || active.contains_key(&call) {
            return Err(Status::resource_exhausted("Stream capacity unavailable"));
        }
        active.insert(call.clone(), cancellation);
        drop(active);
        if cap["side_effect"] == "idempotent" {
            if let Err(error) = self.assign_cell(&message).await {
                self.active_streams.write().await.remove(&call);
                return Err(error);
            }
        }
        let execution_count = self.execution_count(cap["side_effect"].as_str().unwrap());
        let this = self.clone();
        tokio::spawn(async move {
            let produce = async {
                for index in 0..count {
                    tokio::select! {
                        _ = sender.closed() => return,
                        _ = canceled.changed() => return,
                        _ = tokio::time::sleep(delay) => (),
                    }
                    if this.draining.load(Ordering::SeqCst)
                        || chrono::Utc::now().timestamp_millis() >= deadline
                    {
                        return;
                    }
                    let item = if fault == "item" && index == 0 {
                        serde_json::json!({"index":"invalid","message":message})
                    } else {
                        serde_json::json!({"index":index,"message":message})
                    };
                    let sequence = index + 1 + u64::from(fault == "sequence" && index > 0);
                    let chunk = rpc::InvokeChunk {
                        call_id: if fault == "call-id" && index == 0 {
                            uuid::Uuid::nil().to_string()
                        } else {
                            call.clone()
                        },
                        sequence,
                        body: Some(rpc::invoke_chunk::Body::ItemJson(
                            serde_json::to_vec(&item).unwrap(),
                        )),
                    };
                    tokio::select! {
                        _ = canceled.changed() => return,
                        sent = sender.send(Ok(chunk)) => if sent.is_err() { return; },
                    }
                }
                if fault == "missing-terminal" {
                    return;
                }
                let mut value = if fault == "output" {
                    serde_json::json!({"message":false})
                } else {
                    serde_json::json!({"message":message})
                };
                if let Some(count) = execution_count {
                    value["execution_count"] = count.into();
                }
                let output = serde_json::to_vec(&value).unwrap();
                let response = rpc::InvokeResponse {
                    call_id: call.clone(),
                    output_digest: if fault == "digest" {
                        digest(b"different")
                    } else {
                        digest(&output)
                    },
                    output_json: output,
                };
                if matches!(
                    fault.as_str(),
                    "none" | "after-commit" | "after-commit-health"
                ) {
                    let mut results = this.results.write().await;
                    if results.len() >= 1024 {
                        results.clear();
                    }
                    results.insert(
                        call.clone(),
                        SavedResult {
                            key: key.clone(),
                            input_digest: input_digest.clone(),
                            response: response.clone(),
                        },
                    );
                }
                if fault == "after-commit-health" {
                    tokio::select! {
                        _ = sender.closed() => return,
                        _ = canceled.changed() => return,
                        observed = this.next_health(deadline) => if let Err(error) = observed {
                            let _ = sender.send(Err(error)).await;
                            return;
                        },
                    }
                }
                if matches!(fault.as_str(), "after-commit" | "after-commit-health") {
                    let _ = sender
                        .send(Err(Status::unavailable(
                            "Reference stream ended after committed execution",
                        )))
                        .await;
                    return;
                }
                let completed = rpc::InvokeChunk {
                    call_id: call.clone(),
                    sequence: count + 1,
                    body: Some(rpc::invoke_chunk::Body::Completed(response.clone())),
                };
                if sender.send(Ok(completed)).await.is_err() {
                    return;
                }
                if fault == "after-terminal" {
                    let _ = sender
                        .send(Ok(rpc::InvokeChunk {
                            call_id: call.clone(),
                            sequence: count + 2,
                            body: Some(rpc::invoke_chunk::Body::ItemJson(
                                serde_json::to_vec(
                                    &serde_json::json!({"index":0,"message":message}),
                                )
                                .unwrap(),
                            )),
                        }))
                        .await;
                }
            };
            let remaining = std::time::Duration::from_millis(
                (deadline - chrono::Utc::now().timestamp_millis()).max(0) as u64,
            );
            let _ = tokio::time::timeout(remaining, produce).await;
            this.active_streams.write().await.remove(&call);
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            receiver,
        )))
    }
    async fn cancel(
        &self,
        r: Request<rpc::CancelCallRequest>,
    ) -> Result<Response<rpc::Ack>, Status> {
        let request = r.into_inner();
        if let Some(cancellation) = self.active_streams.read().await.get(&request.call_id) {
            let _ = cancellation.send(true);
        }
        Ok(Response::new(rpc::Ack {
            request_id: request.context.map(|c| c.request_id).unwrap_or_default(),
            accepted: true,
        }))
    }
    async fn query_result(
        &self,
        r: Request<rpc::QueryResultRequest>,
    ) -> Result<Response<rpc::QueryResultResponse>, Status> {
        let request = r.into_inner();
        let context = request
            .context
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Context required"))?;
        if context.deadline_unix_ms <= chrono::Utc::now().timestamp_millis()
            || context.delegation_token.is_empty()
            || request.idempotency_key.is_empty()
            || context.idempotency_key != request.idempotency_key
        {
            return Err(Status::invalid_argument("Invalid query context or key"));
        }
        let map = self.results.read().await;
        let result = match map.get(&request.call_id) {
            Some(saved) if saved.key == request.idempotency_key => Some(saved.response.clone()),
            Some(_) => return Err(Status::failed_precondition("Call key differs")),
            None => None,
        };
        Ok(Response::new(rpc::QueryResultResponse {
            state: if result.is_some() {
                rpc::ExecutionState::Succeeded as i32
            } else {
                rpc::ExecutionState::Unknown as i32
            },
            outcome: result.map(rpc::query_result_response::Outcome::Completed),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    xelab_kernel::init_crypto();
    let echo = Echo {
        manifest: Arc::new(std::fs::read("/xelab/plugin.json")?),
        generation: std::env::var("XELAB_GENERATION")?.parse()?,
        initialized: Arc::new(AtomicBool::new(false)),
        draining: Arc::new(AtomicBool::new(false)),
        results: Default::default(),
        effects: Default::default(),
        cells: Default::default(),
        active_streams: Default::default(),
        health_observed: watch::channel(0).0,
    };
    let identity = WorkloadIdentity::from_env()?;
    let listener = tokio::net::TcpListener::bind(PLUGIN_RPC_LISTEN).await?;
    tonic::transport::Server::builder()
        .add_service(PluginLifecycleServer::new(echo.clone()))
        .add_service(CapabilityServiceServer::new(echo))
        .serve_with_incoming(identity.plugin_incoming(listener)?)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(effect: &str) -> (Echo, rpc::InvokeRequest) {
        let contract = rpc::ContractRef {
            name: format!("org.xelab.echo.{}", effect.replace('_', "-")),
            version: "1.0.0".into(),
            schema_digest: digest(effect.as_bytes()),
        };
        let input = json!({"message":"committed once","fault":"after-commit"});
        let input_json = serde_json::to_vec(&input).unwrap();
        let manifest = json!({"capabilities":[{"contract":{"name":contract.name,"version":contract.version,"schema_digest":contract.schema_digest},"side_effect":effect,"input_schema":{"type":"object"},"stream_item_schema":{},"output_schema":{"type":"object"}}]});
        let echo = Echo {
            manifest: Arc::new(serde_json::to_vec(&manifest).unwrap()),
            generation: 1,
            initialized: Arc::new(AtomicBool::new(true)),
            draining: Arc::new(AtomicBool::new(false)),
            results: Default::default(),
            effects: Default::default(),
            cells: Default::default(),
            active_streams: Default::default(),
            health_observed: watch::channel(0).0,
        };
        let mut context = xelab_kernel::controller::context(None);
        context.deadline_unix_ms = chrono::Utc::now().timestamp_millis() + 10_000;
        context.delegation_token = "component-only-empty-authority".into();
        context.idempotency_key = "stable-reference-intent".into();
        let request = rpc::InvokeRequest {
            context: Some(context),
            call_id: uuid::Uuid::new_v4().to_string(),
            contract: Some(contract),
            input_digest: digest(&input_json),
            input_json,
            binding_id: String::new(),
        };
        (echo, request)
    }

    fn health_fixture() -> (Echo, rpc::InvokeRequest) {
        let (mut echo, mut request) = fixture("queryable");
        let contract = request.contract.as_mut().unwrap();
        contract.version = "1.0.1".into();
        contract.schema_digest = digest(b"health-synchronized queryable fixture");
        let mut manifest = strict_json(&echo.manifest, 1048576).unwrap();
        manifest["capabilities"][0]["contract"]["version"] = "1.0.1".into();
        manifest["capabilities"][0]["contract"]["schema_digest"] =
            contract.schema_digest.clone().into();
        echo.manifest = Arc::new(serde_json::to_vec(&manifest).unwrap());
        request.input_json = serde_json::to_vec(
            &serde_json::json!({"message":"committed once","fault":"after-commit-health"}),
        )
        .unwrap();
        request.input_digest = digest(&request.input_json);
        (echo, request)
    }

    #[tokio::test]
    async fn reference_health_loss_waits_for_new_probe_without_holding_results() {
        let (echo, request) = health_fixture();
        // Old probes with no subscribers are retained, but cannot release the
        // waiter created after this Call's actual cache commit.
        echo.get_health(Request::new(Default::default()))
            .await
            .unwrap();
        let actor = echo.clone();
        let invocation = request.clone();
        let pending = tokio::spawn(async move { actor.invoke(Request::new(invocation)).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if echo.results.read().await.contains_key(&request.call_id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("The business result must be committed without retaining its write lock");
        assert!(!pending.is_finished());
        let query = rpc::QueryResultRequest {
            context: request.context.clone(),
            call_id: request.call_id.clone(),
            idempotency_key: request.context.as_ref().unwrap().idempotency_key.clone(),
        };
        let saved = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            echo.query_result(Request::new(query)),
        )
        .await
        .unwrap()
        .unwrap()
        .into_inner();
        assert_eq!(saved.state, rpc::ExecutionState::Succeeded as i32);
        let health = echo
            .get_health(Request::new(Default::default()))
            .await
            .unwrap();
        assert!(health.into_inner().capabilities[0].ready);
        assert_eq!(
            pending.await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        let replay = echo
            .invoke(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(echo.effects.load(Ordering::SeqCst), 1);
        assert_eq!(
            strict_json(&replay.output_json, 65536).unwrap()["execution_count"],
            1
        );
    }

    #[tokio::test]
    async fn reference_health_wait_preserves_deadline_even_for_late_ready_signal() {
        let (echo, _) = health_fixture();
        let deadline = chrono::Utc::now().timestamp_millis() + 20;
        let wait = echo.next_health(deadline);
        tokio::pin!(wait);
        assert!(futures_util::poll!(wait.as_mut()).is_pending());
        // A ready signal after a blocked runtime must not bypass the original
        // deadline just because changed() can now immediately return Ready.
        std::thread::sleep(std::time::Duration::from_millis(30));
        echo.get_health(Request::new(Default::default()))
            .await
            .unwrap();
        assert_eq!(
            wait.await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        assert_eq!(
            echo.next_health(i64::MIN).await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        let started = tokio::time::Instant::now();
        assert_eq!(
            echo.next_health(chrono::Utc::now().timestamp_millis() + 10)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::DeadlineExceeded
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn reference_committed_response_loss_queries_only_the_same_call_key() {
        let (echo, request) = fixture("queryable");
        assert_eq!(
            echo.invoke(Request::new(request.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(echo.effects.load(Ordering::SeqCst), 1);
        let mut query = rpc::QueryResultRequest {
            context: request.context.clone(),
            call_id: request.call_id.clone(),
            idempotency_key: request.context.as_ref().unwrap().idempotency_key.clone(),
        };
        let known = echo
            .query_result(Request::new(query.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(known.state, rpc::ExecutionState::Succeeded as i32);
        let Some(rpc::query_result_response::Outcome::Completed(saved)) = known.outcome else {
            panic!("Actual committed reference result required")
        };
        assert_eq!(saved.call_id, request.call_id);
        assert_eq!(
            strict_json(&saved.output_json, 65536).unwrap()["execution_count"],
            1
        );
        assert_eq!(
            echo.invoke(Request::new(request.clone()))
                .await
                .unwrap()
                .into_inner(),
            saved
        );
        assert_eq!(
            echo.effects.load(Ordering::SeqCst),
            1,
            "A repeated reference Call cannot repeat its mutation"
        );
        query.idempotency_key = "another-intent".into();
        query
            .context
            .as_mut()
            .unwrap()
            .idempotency_key
            .clone_from(&query.idempotency_key);
        assert_eq!(
            echo.query_result(Request::new(query.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        query.call_id = uuid::Uuid::new_v4().to_string();
        let missing = echo
            .query_result(Request::new(query))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(missing.state, rpc::ExecutionState::Unknown as i32);
        assert!(
            missing.outcome.is_none(),
            "A missing record never establishes that an effect did not execute"
        );
    }
    #[tokio::test]
    async fn reference_fixed_assignment_has_same_value_across_fresh_instances() {
        let mut previous = None;
        for _ in 0..2 {
            let (echo, mut request) = fixture("idempotent");
            request.input_json =
                serde_json::to_vec(&json!({"message":"fixed reference cell"})).unwrap();
            request.input_digest = digest(&request.input_json);
            let first = echo
                .invoke(Request::new(request.clone()))
                .await
                .unwrap()
                .into_inner();
            request.call_id = uuid::Uuid::new_v4().to_string();
            let repeated = echo
                .invoke(Request::new(request))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(first.output_json, repeated.output_json);
            assert_eq!(echo.cells.read().await.len(), 1);
            assert_eq!(
                echo.effects.load(Ordering::SeqCst),
                0,
                "Intrinsic assignment never uses the non-idempotent counter"
            );
            if let Some(previous) = &previous {
                assert_eq!(previous, &first.output_json);
            }
            previous = Some(first.output_json);
        }
    }
}
