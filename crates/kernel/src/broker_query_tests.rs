use super::*;

fn fixed() -> Binding {
    let schema = json!({"type":"object","additionalProperties":false,"properties":{"message":{"type":"string"}},"required":["message"]});
    Binding {
        call: Uuid::new_v4(),
        subject: Uuid::new_v4(),
        credential: Uuid::new_v4(),
        instance: Uuid::new_v4(),
        generation: 1,
        deadline: Utc::now() + chrono::Duration::seconds(10),
        key: "fixed-business-key".into(),
        contract: json!({"name":"org.xelab.query","version":"1.0.0","schema_digest":digest(b"query-contract")}),
        capability: json!({"maximum_output_bytes":65536,"output_schema":schema}),
        skill: None,
    }
}

fn completed(binding: &Binding, output: Value) -> rpc::InvokeResponse {
    let bytes = serde_json::to_vec(&output).unwrap();
    rpc::InvokeResponse {
        call_id: binding.call.to_string(),
        output_digest: digest(&bytes),
        output_json: bytes,
        terminal_failure: None,
    }
}

#[test]
fn compact_query_result_rejects_large_json_before_model_validation() {
    let mut binding = fixed();
    binding.capability["maximum_output_bytes"] = json!(16777216);
    let result = completed(&binding, json!({"message": "x".repeat(256 * 1024)}));
    let wire = rpc::QueryResultResponse {
        state: rpc::ExecutionState::Succeeded as i32,
        outcome: Some(rpc::query_result_response::Outcome::Completed(result)),
    };
    assert_eq!(
        decode_bounded(&binding, wire.clone(), 256 * 1024)
            .err()
            .unwrap()
            .code,
        "PAYLOAD_TOO_LARGE"
    );
    assert!(decode(&binding, wire).unwrap().is_some());
}

#[test]
fn query_result_is_a_strict_state_outcome_pair_and_missing_is_unknown() {
    use rpc::{query_result_response::Outcome as Wire, ExecutionState as State};
    let binding = fixed();
    for state in [
        State::Accepted,
        State::Running,
        State::Unknown,
        State::Canceled,
    ] {
        assert!(decode(
            &binding,
            rpc::QueryResultResponse {
                state: state as i32,
                outcome: None
            }
        )
        .unwrap()
        .is_none());
        assert!(decode(
            &binding,
            rpc::QueryResultResponse {
                state: state as i32,
                outcome: Some(Wire::Completed(completed(
                    &binding,
                    json!({"message":"done"})
                )))
            }
        )
        .is_err());
    }
    for state in [
        State::Succeeded as i32,
        State::Failed as i32,
        State::Unspecified as i32,
        97,
    ] {
        assert!(decode(
            &binding,
            rpc::QueryResultResponse {
                state,
                outcome: None
            }
        )
        .is_err());
    }
    let error = rpc::ErrorDetail {
        code: "QUERY_FAILED".into(),
        message: "Declared failure".into(),
        retryable: true,
        retry_after_ms: 0,
        violations: vec![],
        resource_id: String::new(),
    };
    assert!(decode(
        &binding,
        rpc::QueryResultResponse {
            state: State::Succeeded as i32,
            outcome: Some(Wire::Failed(error.clone()))
        }
    )
    .is_err());
    let Some(Outcome::Failed(error)) = decode(
        &binding,
        rpc::QueryResultResponse {
            state: State::Failed as i32,
            outcome: Some(Wire::Failed(error)),
        },
    )
    .unwrap() else {
        panic!("Expected confirmed failure")
    };
    assert_eq!(error["retryable"], false);
    assert!(decode(
        &binding,
        rpc::QueryResultResponse {
            state: State::Failed as i32,
            outcome: Some(Wire::Completed(completed(
                &binding,
                json!({"message":"done"})
            )))
        }
    )
    .is_err());
}

#[test]
fn completed_query_checks_call_digest_strict_json_and_both_locked_schemas() {
    use rpc::{query_result_response::Outcome as Wire, ExecutionState as State};
    let mut binding = fixed();
    let response = completed(&binding, json!({"message":"done"}));
    let wire = |response| rpc::QueryResultResponse {
        state: State::Succeeded as i32,
        outcome: Some(Wire::Completed(response)),
    };
    let Some(Outcome::Completed(value)) = decode(&binding, wire(response.clone())).unwrap() else {
        panic!("Expected completed result")
    };
    assert_eq!(value["call_id"], binding.call.to_string());
    assert_eq!(value["provider_instance_id"], binding.instance.to_string());
    let mut wrong_call = response.clone();
    wrong_call.call_id = Uuid::new_v4().to_string();
    assert!(decode(&binding, wire(wrong_call)).is_err());
    let mut wrong_digest = response.clone();
    wrong_digest.output_digest = digest(b"other output");
    assert!(decode(&binding, wire(wrong_digest)).is_err());
    let mut duplicate_json = response.clone();
    duplicate_json.output_json = br#"{"message":"one","message":"two"}"#.to_vec();
    duplicate_json.output_digest = digest(&duplicate_json.output_json);
    assert!(decode(&binding, wire(duplicate_json)).is_err());
    assert!(decode(&binding, wire(completed(&binding, json!({"message":42})))).is_err());
    binding.capability["maximum_output_bytes"] = json!(4);
    assert!(decode(&binding, wire(response.clone())).is_err());
    binding.capability["maximum_output_bytes"] = json!(65536);
    binding.skill = Some((
        Uuid::new_v4(),
        digest(b"skill-definition"),
        json!({"output_schema":{"type":"object","properties":{"message":{"const":"approved"}},"required":["message"]}}),
    ));
    assert!(decode(&binding, wire(response)).is_err());
    let Some(Outcome::Completed(value)) = decode(
        &binding,
        wire(completed(&binding, json!({"message":"approved"}))),
    )
    .unwrap() else {
        panic!("Expected Skill result")
    };
    assert_eq!(
        value["skill_id"],
        binding.skill.as_ref().unwrap().0.to_string()
    );
    assert_eq!(
        value["skill_definition_digest"],
        binding.skill.as_ref().unwrap().1
    );
}

#[test]
fn queried_error_obeys_bounded_public_error_schema() {
    let binding = fixed();
    for (code, message) in [
        ("".into(), "message".into()),
        ("x".repeat(81), "message".into()),
        ("FAILED".into(), "x".repeat(2049)),
    ] {
        let response = rpc::QueryResultResponse {
            state: rpc::ExecutionState::Failed as i32,
            outcome: Some(rpc::query_result_response::Outcome::Failed(
                rpc::ErrorDetail {
                    code,
                    message,
                    retryable: false,
                    retry_after_ms: 0,
                    violations: vec![],
                    resource_id: String::new(),
                },
            )),
        };
        assert!(decode(&binding, response).is_err());
    }
}

// Actual PostgreSQL and mutual TLS. Installation/runtime rows are explicit
// component fixtures; signed OCI execution is covered by tests/oci.rs.
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tonic::{Request, Response, Status};

#[derive(Clone, Default)]
struct QueryPlugin {
    records: Arc<Mutex<HashMap<String, (String, rpc::QueryResultResponse)>>>,
    requests: Arc<AtomicUsize>,
    paused: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    proceed: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl rpc::capability_service_server::CapabilityService for QueryPlugin {
    async fn invoke(
        &self,
        _: Request<rpc::InvokeRequest>,
    ) -> std::result::Result<Response<rpc::InvokeResponse>, Status> {
        panic!("getCall must never execute Invoke")
    }
    type InvokeStreamStream =
        tokio_stream::wrappers::ReceiverStream<std::result::Result<rpc::InvokeChunk, Status>>;
    async fn invoke_stream(
        &self,
        _: Request<rpc::InvokeRequest>,
    ) -> std::result::Result<Response<Self::InvokeStreamStream>, Status> {
        panic!("getCall must never execute InvokeStream")
    }
    async fn cancel(
        &self,
        _: Request<rpc::CancelCallRequest>,
    ) -> std::result::Result<Response<rpc::Ack>, Status> {
        Err(Status::unimplemented("query-only component"))
    }
    async fn query_result(
        &self,
        request: Request<rpc::QueryResultRequest>,
    ) -> std::result::Result<Response<rpc::QueryResultResponse>, Status> {
        let certificates = request
            .peer_certs()
            .expect("query must authenticate with mTLS");
        let (_, certificate) =
            x509_parser::parse_x509_certificate(certificates.first().unwrap().as_ref()).unwrap();
        let san = certificate.subject_alternative_name().unwrap().unwrap();
        assert!(san.value.general_names.iter().any(|name| matches!(
            name,
            x509_parser::extensions::GeneralName::URI("spiffe://xelab.local/kernel")
        )));
        self.requests.fetch_add(1, Ordering::SeqCst);
        let query = request.into_inner();
        let context = query.context.as_ref().unwrap();
        assert!(!context.delegation_token.is_empty());
        assert_eq!(context.idempotency_key, query.idempotency_key);
        assert!(context.deadline_unix_ms > Utc::now().timestamp_millis());
        assert!(
            context.deadline_unix_ms
                <= (Utc::now() + chrono::Duration::seconds(2)).timestamp_millis()
        );
        if self.paused.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.proceed.notified().await;
        }
        let records = self.records.lock().unwrap();
        let Some((key, value)) = records.get(&query.call_id) else {
            return Ok(Response::new(rpc::QueryResultResponse {
                state: rpc::ExecutionState::Unknown as i32,
                outcome: None,
            }));
        };
        assert_eq!(*key, query.idempotency_key);
        Ok(Response::new(value.clone()))
    }
}

struct Component {
    _base: crate::backups::tests::Fixture,
    app: Arc<App>,
    headers: HeaderMap,
    owner: Uuid,
    instance: Uuid,
    deployment: Uuid,
    manifest: Value,
    plugin: QueryPlugin,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Component {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Component {
    async fn new() -> Option<Self> {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let base = crate::backups::tests::Fixture::new().await?;
        let root = base.app.config.root();
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["query-result-component-ca".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        fs::write(root.join("query-ca.crt"), ca.pem()).unwrap();
        fs::write(root.join("query-ca.key"), ca_key.serialize_pem()).unwrap();
        fs::set_permissions(root.join("query-ca.key"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut value = base.app.config.value.clone();
        value["security"]["workload_ca_cert_file"] = json!(root.join("query-ca.crt"));
        value["security"]["workload_ca_key_file"] = json!(root.join("query-ca.key"));
        let config = crate::config::Config::from_value(value).unwrap();
        crate::tls::issue(&config, None, &root.join("kernel-identity")).unwrap();
        let app = Arc::new(App {
            config: config.clone(),
            runtime: crate::runtime::Runtime::new(config),
            db: base.app.db.clone(),
            auth: base.app.auth.clone(),
            leader: base.app.leader.clone(),
            ready: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
            blob_uploads: Semaphore::new(4),
        });
        let connection = app.db.connect().await.unwrap();
        let ctx = app
            .auth
            .authenticate(
                &connection,
                &base.token,
                "127.0.0.1".parse().unwrap(),
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        let owner = ctx.subject;
        let publisher = Uuid::new_v4();
        let installation = Uuid::new_v4();
        let deployment = Uuid::new_v4();
        let instance = Uuid::new_v4();
        let mut manifest: Value =
            serde_json::from_str(include_str!("../tests/fixtures/secret-manifest.json")).unwrap();
        manifest["publisher_id"] = json!(publisher);
        manifest["requested_rules"] = json!([]);
        manifest["capabilities"][0]["side_effect"] = json!("queryable");
        let cap = &manifest["capabilities"][0];
        connection.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,'Query component',$2,'metadata fixture','trusted',now(),now())", &[&publisher,&publisher.to_string()]).await.unwrap();
        connection.execute("INSERT INTO installations(id,plugin_id,version,publisher_id,image_digest,manifest_digest,manifest,state,created_at,updated_at) VALUES($1,$2,'1.0.0',$3,$4,$4,$5,'installed',now(),now())", &[&installation,&manifest["plugin_id"].as_str().unwrap(),&publisher,&digest(b"query-component-metadata"),&manifest]).await.unwrap();
        connection.execute("INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4)", &[&cap["contract"]["name"].as_str().unwrap(),&cap["contract"]["version"].as_str().unwrap(),&cap["contract"]["schema_digest"].as_str().unwrap(),cap]).await.unwrap();
        let limits =
            json!({"cpu_millis":500,"memory_bytes":134217728,"ephemeral_bytes":1048576,"pids":64});
        connection.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,$4,'ready',now(),now())", &[&deployment,&owner,&installation,&json!({"enabled":true,"limits":limits,"config":{},"volume_ids":[],"replicas":1})]).await.unwrap();
        connection.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,1,0,'ready','alive',$3,now(),now())", &[&instance,&deployment,&limits]).await.unwrap();
        let directory = root.join("runtime").join(instance.to_string());
        // Component processes run as the test user, without production's
        // root-only chown to the OCI workload UID.
        let identity_directory = directory.join("identity");
        fs::create_dir_all(&identity_directory).unwrap();
        let key = KeyPair::generate().unwrap();
        let name = format!("i-{instance}-g-1.xelab.local");
        let mut params = CertificateParams::new(vec![name.clone()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names.push(rcgen::SanType::URI(
            format!("spiffe://xelab.local/instance/{instance}/generation/1")
                .try_into()
                .unwrap(),
        ));
        let certificate = params.signed_by(&key, &ca, &ca_key).unwrap();
        fs::write(identity_directory.join("tls.crt"), certificate.pem()).unwrap();
        fs::write(identity_directory.join("tls.key"), key.serialize_pem()).unwrap();
        fs::set_permissions(
            identity_directory.join("tls.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let listener = loop {
            let bytes = *Uuid::new_v4().as_bytes();
            let address = format!(
                "127.{}.{}.{}:7000",
                30 + bytes[0] % 150,
                bytes[1],
                2 + bytes[2] % 250
            );
            if let Ok(listener) = tokio::net::TcpListener::bind(address).await {
                break listener;
            }
        };
        fs::write(directory.join("network.json"),serde_json::to_vec(&json!({"instance":instance,"peer":listener.local_addr().unwrap().ip().to_string()})).unwrap()).unwrap();
        let plugin = QueryPlugin::default();
        let service = rpc::capability_service_server::CapabilityServiceServer::new(plugin.clone());
        let identity = tonic::transport::Identity::from_pem(
            fs::read(directory.join("identity/tls.crt")).unwrap(),
            fs::read(directory.join("identity/tls.key")).unwrap(),
        );
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(
                    tonic::transport::ServerTlsConfig::new()
                        .identity(identity)
                        .client_ca_root(tonic::transport::Certificate::from_pem(ca.pem())),
                )
                .unwrap()
                .add_service(service)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", base.token).parse().unwrap(),
        );
        Some(Self {
            _base: base,
            app,
            headers,
            owner,
            instance,
            deployment,
            manifest,
            plugin,
            server,
        })
    }

    async fn call(&self, save_result: bool) -> Uuid {
        let mut connection = self.app.db.connect().await.unwrap();
        let tx = connection.transaction().await.unwrap();
        db::call_lock(&tx).await.unwrap();
        let ctx = context(
            &tx,
            &self.app,
            &self.headers,
            "127.0.0.1:50000".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
        let call = Uuid::new_v4();
        let key = format!("business-{call}");
        let cap = &self.manifest["capabilities"][0];
        let deadline = Utc::now() + chrono::Duration::seconds(20);
        tx.execute("INSERT INTO calls(id,owner_id,credential_id,provider_instance_id,contract,input_digest,idempotency_key,state,deadline_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'unknown',$8,now())", &[&call,&ctx.subject,&ctx.credential,&self.instance,&cap["contract"],&digest(b"input"),&key,&deadline]).await.unwrap();
        tx.execute(
            "INSERT INTO call_credential_charges(call_id,credential_id) VALUES($1,$2)",
            &[&call, &ctx.credential],
        )
        .await
        .unwrap();
        self.app
            .auth
            .issue_rpc(&tx, &ctx, call, self.instance, 1, deadline)
            .await
            .unwrap();
        crate::host_blobs::grant_skill_call(
            &tx,
            &self.app,
            &ctx,
            call,
            self.deployment,
            &self.manifest,
            cap,
            &json!({"message":"query"}),
            false,
        )
        .await
        .unwrap();
        tx.execute(
            "UPDATE rpc_delegations SET status='revoked' WHERE call_id=$1",
            &[&call],
        )
        .await
        .unwrap();
        tx.execute("UPDATE execution_delegations SET status='revoked' WHERE id=(SELECT delegation_id FROM calls WHERE id=$1)", &[&call]).await.unwrap();
        tx.execute("INSERT INTO reservations(id,account_id,kind,status,created_at) VALUES($1,$2,'call','active',now())", &[&call,&self.owner]).await.unwrap();
        tx.execute(
            "UPDATE quotas SET concurrent_calls_used=concurrent_calls_used+1 WHERE account_id=$1",
            &[&self.owner],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if save_result {
            let mut fixed = fixed();
            fixed.call = call;
            let response = completed(&fixed, json!({"message":"committed"}));
            self.plugin.records.lock().unwrap().insert(
                call.to_string(),
                (
                    key,
                    rpc::QueryResultResponse {
                        state: rpc::ExecutionState::Succeeded as i32,
                        outcome: Some(rpc::query_result_response::Outcome::Completed(response)),
                    },
                ),
            );
        }
        call
    }
    async fn get(&self, call: Uuid) -> Result<Value> {
        get_call(
            &self.app,
            &self.headers,
            "127.0.0.1:50000".parse().unwrap(),
            Uuid::new_v4(),
            call,
        )
        .await
    }
}

#[tokio::test]
async fn postgres_mtls_query_is_pinned_authorized_and_releases_only_confirmed_work() {
    let Some(component) = Component::new().await else {
        return;
    };
    let connection = component.app.db.connect().await.unwrap();
    let call = component.call(true).await;
    // Exact Origin and original credential cannot be replaced on recovery.
    let mut wrong_origin = component.headers.clone();
    wrong_origin.insert(
        "origin",
        component
            .app
            .config
            .text("server", "public_origin")
            .parse()
            .unwrap(),
    );
    assert!(get_call(
        &component.app,
        &wrong_origin,
        "127.0.0.1:50000".parse().unwrap(),
        Uuid::new_v4(),
        call
    )
    .await
    .is_err());
    let issued = component
        .app
        .auth
        .login(
            &connection,
            component.owner,
            "correct horse backup fixture password".into(),
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let mut fresh = HeaderMap::new();
    fresh.insert(
        "authorization",
        format!("Bearer {}", issued["access_token"].as_str().unwrap())
            .parse()
            .unwrap(),
    );
    assert!(get_call(
        &component.app,
        &fresh,
        "127.0.0.1:50000".parse().unwrap(),
        Uuid::new_v4(),
        call
    )
    .await
    .is_err());
    assert_eq!(component.plugin.requests.load(Ordering::SeqCst), 0);
    connection
        .execute(
            "UPDATE instances SET generation=2 WHERE id=$1",
            &[&component.instance],
        )
        .await
        .unwrap();
    assert_eq!(component.get(call).await.unwrap()["state"], "unknown");
    assert_eq!(component.plugin.requests.load(Ordering::SeqCst), 0);
    connection
        .execute(
            "UPDATE instances SET generation=1 WHERE id=$1",
            &[&component.instance],
        )
        .await
        .unwrap();
    assert_eq!(
        component.get(call).await.unwrap()["result"]["output"]["message"],
        "committed"
    );
    assert_eq!(component.plugin.requests.load(Ordering::SeqCst), 1);
    assert_eq!(component.get(call).await.unwrap()["state"], "succeeded");
    assert_eq!(component.plugin.requests.load(Ordering::SeqCst), 1);
    let quota: i64 = connection
        .query_one(
            "SELECT concurrent_calls_used FROM quotas WHERE account_id=$1",
            &[&component.owner],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(quota, 0);
    let active: i64 = connection
        .query_one(
            "SELECT count(*) FROM rpc_delegations WHERE call_id=$1 AND status='active'",
            &[&call],
        )
        .await
        .unwrap()
        .get(0);
    // The original synthetic admission token is not reused or reactivated.
    assert_eq!(active, 0);
    let missing = component.call(false).await;
    assert_eq!(component.get(missing).await.unwrap()["state"], "unknown");
    let reservation: String = connection
        .query_one("SELECT status FROM reservations WHERE id=$1", &[&missing])
        .await
        .unwrap()
        .get(0);
    assert_eq!(reservation, "active");
    let expired = component.call(true).await;
    connection
        .execute(
            "UPDATE calls SET deadline_at=now()-interval '1 second' WHERE id=$1",
            &[&expired],
        )
        .await
        .unwrap();
    let count = component.plugin.requests.load(Ordering::SeqCst);
    assert_eq!(component.get(expired).await.unwrap()["state"], "unknown");
    assert_eq!(component.plugin.requests.load(Ordering::SeqCst), count);
    // A revocation writer must complete while QueryResult is in flight. A new
    // same-scope Owner grant cannot replace the Call's original frozen source.
    let revoked = component.call(true).await;
    component.plugin.paused.store(true, Ordering::SeqCst);
    let app = component.app.clone();
    let headers = component.headers.clone();
    let query = tokio::spawn(async move {
        get_call(
            &app,
            &headers,
            "127.0.0.1:50000".parse().unwrap(),
            Uuid::new_v4(),
            revoked,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), component.plugin.entered.notified())
        .await
        .unwrap();
    let leases:i64=connection.query_one("SELECT count(*) FROM rpc_delegations r JOIN execution_delegations e ON e.id=r.execution_delegation_id JOIN calls c ON c.id=r.call_id WHERE c.id=$1 AND r.status='active' AND e.status='active' AND e.maximum_rules='[]'::jsonb AND r.execution_delegation_id<>c.delegation_id AND c.state='unknown'", &[&revoked]).await.unwrap().get(0);
    assert_eq!(
        leases, 1,
        "Query-only lease must not replace or revive original HostService authority"
    );
    let mut connection = component.app.db.connect().await.unwrap();
    let tx = connection.transaction().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), db::auth_lock(&tx, true))
        .await
        .unwrap()
        .unwrap();
    let old:Uuid=tx.query_one("SELECT id FROM grants WHERE subject_id=$1 AND status='active' AND role_id='Owner' AND scope->>'kind'='capability' LIMIT 1", &[&component.owner]).await.unwrap().get(0);
    tx.execute("INSERT INTO grants(id,subject_id,issuer_id,issuer_credential_id,role_id,scope,status,created_at,updated_at) SELECT $1,subject_id,issuer_id,issuer_credential_id,role_id,scope,'active',now(),now() FROM grants WHERE id=$2", &[&Uuid::new_v4(),&old]).await.unwrap();
    tx.execute("UPDATE grants SET status='revoked' WHERE id=$1", &[&old])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    component.plugin.proceed.notify_one();
    assert!(query.await.unwrap().is_err());
    let state: String = connection
        .query_one("SELECT state FROM calls WHERE id=$1", &[&revoked])
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "unknown");
    assert!(component.get(call).await.is_err());
}
