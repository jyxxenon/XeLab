//! Actual PostgreSQL and authenticated HostService transport. Metadata and
//! loopback providers are component fixtures, never claims of OCI acceptance.
use super::*;
use crate::host_calls::{self, Workload};

#[path = "broker_queue_tests.rs"]
mod business_queue;

#[tokio::test]
async fn host_stream_deadline_covers_waiting_and_ready_queued_payloads() {
    use futures_util::StreamExt;
    let chunk = rpc::InvokeChunk {
        call_id: Uuid::new_v4().to_string(),
        sequence: 1,
        body: Some(rpc::invoke_chunk::Body::ItemJson(b"{}".to_vec())),
    };
    let mut queued = host_calls::with_deadline(
        Box::pin(tokio_stream::iter([Ok(chunk.clone())])),
        tokio::time::Instant::now() - Duration::from_millis(1),
    );
    assert_eq!(
        queued.next().await.unwrap().unwrap_err().code(),
        tonic::Code::DeadlineExceeded
    );
    assert!(queued.next().await.is_none());
    let mut idle = host_calls::with_deadline(
        Box::pin(futures_util::stream::pending()),
        tokio::time::Instant::now() + Duration::from_millis(10),
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), idle.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code(),
        tonic::Code::DeadlineExceeded
    );
    assert!(idle.next().await.is_none());
    // A synchronous producer can return Ready after monopolizing its runtime
    // thread past the deadline; the final clock check must still hide its data.
    let ready_late = futures_util::stream::once(async move {
        std::thread::sleep(Duration::from_millis(20));
        Ok(chunk)
    });
    let mut late = host_calls::with_deadline(
        Box::pin(ready_late),
        tokio::time::Instant::now() + Duration::from_millis(10),
    );
    assert_eq!(
        late.next().await.unwrap().unwrap_err().code(),
        tonic::Code::DeadlineExceeded
    );
    assert!(late.next().await.is_none());
}

async fn proxy(f: &Fixture, deployment: Uuid, extra: Vec<Value>) {
    let mut c = f.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(&tx, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap();
    let row = tx
        .query_one(
            "SELECT installation_id FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await
        .unwrap();
    let installation: Uuid = row.get(0);
    let mut manifest: Value = tx
        .query_one(
            "SELECT manifest FROM installations WHERE id=$1",
            &[&installation],
        )
        .await
        .unwrap()
        .get(0);
    let mut rules = vec![
        json!({"action":"blob.read","resource":{"kind":"blob","match":"all"}}),
        json!({"action":"blob.create","resource":{"kind":"blob","match":"all"}}),
    ];
    rules.extend(extra);
    manifest["requested_rules"] = json!(rules
        .iter()
        .map(|rule| json!({"required":false,"rule":rule}))
        .collect::<Vec<_>>());
    crate::artifact::validate_profile(&manifest).unwrap();
    tx.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    let approval = json!({"rules":rules,"egress":[]});
    crate::host_blobs::approve(&tx, &ctx, deployment, &manifest, &approval, ctx.subject)
        .await
        .unwrap();
    tx.execute(
        "UPDATE deployments SET approval=$2 WHERE id=$1",
        &[&deployment, &approval],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
fn proxy_rules() -> Vec<Value> {
    vec![
        json!({"action":"skill.read","resource":{"kind":"skill","match":"all"}}),
        json!({"action":"skill.invoke","resource":{"kind":"skill","match":"all"}}),
        json!({"action":"capability.discover","resource":{"kind":"capability","match":"all"}}),
        json!({"action":"capability.invoke","resource":{"kind":"capability","match":"all"}}),
        json!({"action":"event.publish","resource":{"kind":"event","match":"all"}}),
    ]
}
async fn skill(f: &Fixture, deployment: Uuid) -> (Uuid, Value) {
    skill_with_timeout(f, deployment, 30000).await
}

async fn skill_with_timeout(
    f: &Fixture,
    deployment: Uuid,
    maximum_timeout_ms: u64,
) -> (Uuid, Value) {
    let c = f.app.db.connect().await.unwrap();
    let row = c
        .query_one(
            "SELECT installation_id,owner_id FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await
        .unwrap();
    let installation: Uuid = row.get(0);
    let owner: Uuid = row.get(1);
    let mut manifest: Value = c
        .query_one(
            "SELECT manifest FROM installations WHERE id=$1",
            &[&installation],
        )
        .await
        .unwrap()
        .get(0);
    let cap = &manifest["capabilities"][0];
    let definition = json!({"name":"org.xelab.echo-python.host-test","version":"1.0.0","description":"Host component","target":{"kind":"capability","plugin_id":manifest["plugin_id"],"contract":cap["contract"]},"input_schema":cap["input_schema"],"output_schema":cap["output_schema"],"stream_item_schema":cap["stream_item_schema"],"mapping":"identity","maximum_timeout_ms":maximum_timeout_ms,"input_blobs":true,"tags":[]});
    contracts::validate("SkillDefinition", &definition).unwrap();
    manifest["skills"] = json!([definition]);
    c.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    let cap = &manifest["capabilities"][0];
    let target = &cap["contract"];
    c.execute("INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4) ON CONFLICT(name,version) DO UPDATE SET spec=$4",&[&target["name"].as_str().unwrap(),&target["version"].as_str().unwrap(),&target["schema_digest"].as_str().unwrap(),&cap]).await.unwrap();
    let id = Uuid::new_v4();
    let digest = crate::skills::definition_digest(&definition).unwrap();
    c.execute("INSERT INTO skills(id,name,version,installation_id,created_by,definition,definition_digest,enabled,created_at,updated_at) VALUES($1,$2,'1.0.0',$3,$4,$5,$6,true,now(),now())",&[&id,&definition["name"].as_str().unwrap(),&installation,&owner,&definition,&digest]).await.unwrap();
    let instance: Uuid = c
        .query_one(
            "SELECT id FROM instances WHERE deployment_id=$1",
            &[&deployment],
        )
        .await
        .unwrap()
        .get(0);
    c.execute(
        "UPDATE instances SET last_heartbeat_at=now() WHERE id=$1",
        &[&instance],
    )
    .await
    .unwrap();
    c.execute("INSERT INTO provider_records(instance_id,name,version,availability,features,observed_generation,observed_at) VALUES($1,$2,$3,'ready','[]',7,now())",&[&instance,&target["name"].as_str().unwrap(),&target["version"].as_str().unwrap()]).await.unwrap();
    fixture_health(f, instance);
    (id, definition)
}

#[tokio::test]
async fn host_mtls_skill_discovery_check_and_generation_delegation_fences() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, instance) = f.workload().await;
    proxy(&f, deployment, proxy_rules()).await;
    let (target, _) = f.workload().await;
    let (skill, definition) = skill(&f, target).await;
    let source = f.source(b"source".to_vec()).await;
    let (call, context) = f.delegation(deployment, instance, source).await;
    let server = tokio::spawn(crate::host::serve(f.app.clone()));
    let mut client = f
        .client(f.client_identity(&format!(
            "spiffe://xelab.local/instance/{instance}/generation/7"
        )))
        .await;
    let resolved = client
        .resolve_skill(rpc::ResolveSkillRequest {
            context: Some(context.clone()),
            skill_id: skill.to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(resolved.ready);
    assert_eq!(
        serde_json::from_slice::<Value>(&resolved.definition_json).unwrap(),
        definition
    );
    let request = rpc::CheckSkillAccessRequest {
        context: Some(context.clone()),
        skill_id: skill.to_string(),
        expected_definition_digest: resolved.definition_digest.clone(),
    };
    assert!(
        client
            .check_skill_access(request.clone())
            .await
            .unwrap()
            .into_inner()
            .ready
    );
    let mut mismatch = request.clone();
    mismatch.expected_definition_digest = contracts::digest(b"wrong");
    assert_eq!(
        client
            .check_skill_access(mismatch)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    for deadline in [-1, i64::MIN] {
        let mut expired = request.clone();
        expired.context.as_mut().unwrap().deadline_unix_ms = deadline;
        assert_eq!(
            client.check_skill_access(expired).await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded,
            "untrusted extreme deadline must fail closed without arithmetic overflow"
        );
    }
    let candidates = client
        .list_skill_candidates(rpc::ListSkillCandidatesRequest {
            context: Some(context.clone()),
            plugin_ids: vec!["org.xelab.echo-python".into()],
            capability_names: vec!["org.xelab.echo".into()],
            page_size: 1,
            cursor: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(candidates.items.len(), 1);
    assert_eq!(candidates.items[0].skill_id, skill.to_string());
    let mut wrong = request.clone();
    wrong.context.as_mut().unwrap().actor_instance_id = Uuid::new_v4().to_string();
    assert_eq!(
        client.check_skill_access(wrong).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let mut old = f
        .client(f.client_identity(&format!(
            "spiffe://xelab.local/instance/{instance}/generation/6"
        )))
        .await;
    assert_eq!(
        old.check_skill_access(request.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let c = f.app.db.connect().await.unwrap();
    c.execute("UPDATE calls SET state='succeeded' WHERE id=$1", &[&call])
        .await
        .unwrap();
    assert_eq!(
        client.check_skill_access(request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    server.abort();
}

#[tokio::test]
async fn host_signed_proxy_scope_and_current_approval_are_intersections() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, instance) = f.workload().await;
    proxy(&f, deployment, proxy_rules()).await;
    let source = f.source(b"scope".to_vec()).await;
    let (_, context) = f.delegation(deployment, instance, source).await;
    let workload = Workload {
        instance,
        generation: 7,
    };
    let resource = auth::Resource::new("event", "org.xelab.test", None);
    let mut c = f.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    host_calls::authority(&tx, &f.app, workload, &context, "event.publish", &resource)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    proxy(
        &f,
        deployment,
        proxy_rules()
            .into_iter()
            .filter(|v| v["action"] != "event.publish")
            .collect(),
    )
    .await;
    let tx = c.transaction().await.unwrap();
    assert!(
        host_calls::authority(&tx, &f.app, workload, &context, "event.publish", &resource)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // Granting an action that was never signed is rejected before any update.
    let tx = c.transaction().await.unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(&tx, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap();
    let manifest:Value=tx.query_one("SELECT n.manifest FROM installations n JOIN deployments d ON d.installation_id=n.id WHERE d.id=$1",&[&deployment]).await.unwrap().get(0);
    assert!(crate::host_blobs::approve(&tx,&ctx,deployment,&manifest,&json!({"rules":[{"action":"skill.archive","resource":{"kind":"skill","match":"all"}}],"egress":[]}),ctx.subject).await.is_err());
}

#[derive(Clone, Default)]
struct Echo {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    output_bytes: Arc<std::sync::atomic::AtomicUsize>,
    fail_after_dispatch: Arc<std::sync::atomic::AtomicBool>,
    unary_gate: Option<Arc<tokio::sync::Semaphore>>,
    delay: Option<(Arc<tokio::sync::Notify>, Duration)>,
}
#[tonic::async_trait]
impl rpc::capability_service_server::CapabilityService for Echo {
    type InvokeStreamStream = tokio_stream::wrappers::ReceiverStream<
        std::result::Result<rpc::InvokeChunk, tonic::Status>,
    >;
    async fn invoke(
        &self,
        r: tonic::Request<rpc::InvokeRequest>,
    ) -> std::result::Result<tonic::Response<rpc::InvokeResponse>, tonic::Status> {
        assert!(r.peer_certs().is_some());
        if let Some((entered, delay)) = &self.delay {
            let response = tokio::time::sleep(*delay);
            entered.notify_one();
            response.await;
        }
        let r = r.into_inner();
        assert!(!r
            .context
            .as_ref()
            .unwrap()
            .delegation_token
            .starts_with("host:"));
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.unary_gate {
            gate.acquire().await.unwrap().forget();
        }
        if self.fail_after_dispatch.load(Ordering::SeqCst) {
            return Err(tonic::Status::unavailable(
                "Simulated transport failure after dispatch",
            ));
        }
        let size = self.output_bytes.load(Ordering::SeqCst);
        let message = if size == 0 {
            "proxied".to_owned()
        } else {
            "x".repeat(size)
        };
        let bytes = serde_json::to_vec(&json!({"message":message})).unwrap();
        Ok(tonic::Response::new(rpc::InvokeResponse {
            call_id: r.call_id,
            output_digest: contracts::digest(&bytes),
            output_json: bytes,
        }))
    }
    async fn invoke_stream(
        &self,
        r: tonic::Request<rpc::InvokeRequest>,
    ) -> std::result::Result<tonic::Response<Self::InvokeStreamStream>, tonic::Status> {
        let r = r.into_inner();
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        let call = r.call_id.clone();
        let bytes = serde_json::to_vec(&json!({"message":"proxied"})).unwrap();
        let size = self.output_bytes.load(Ordering::SeqCst);
        let completed = if size == 0 {
            bytes.clone()
        } else {
            serde_json::to_vec(&json!({"message":"x".repeat(size)})).unwrap()
        };
        tokio::spawn(async move {
            tx.send(Ok(rpc::InvokeChunk {
                call_id: call.clone(),
                sequence: 1,
                body: Some(rpc::invoke_chunk::Body::ItemJson(bytes.clone())),
            }))
            .await
            .unwrap();
            tx.send(Ok(rpc::InvokeChunk {
                call_id: call.clone(),
                sequence: 2,
                body: Some(rpc::invoke_chunk::Body::Completed(rpc::InvokeResponse {
                    call_id: call,
                    output_digest: contracts::digest(&completed),
                    output_json: completed,
                })),
            }))
            .await
            .unwrap();
        });
        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }
    async fn cancel(
        &self,
        _: tonic::Request<rpc::CancelCallRequest>,
    ) -> std::result::Result<tonic::Response<rpc::Ack>, tonic::Status> {
        Ok(tonic::Response::new(rpc::Ack {
            request_id: String::new(),
            accepted: true,
        }))
    }
    async fn query_result(
        &self,
        _: tonic::Request<rpc::QueryResultRequest>,
    ) -> std::result::Result<tonic::Response<rpc::QueryResultResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("component"))
    }
}
async fn echo(f: &Fixture, instance: Uuid) -> (Echo, tokio::task::JoinHandle<()>) {
    echo_with(f, instance, Echo::default()).await
}

async fn echo_with(
    f: &Fixture,
    instance: Uuid,
    plugin: Echo,
) -> (Echo, tokio::task::JoinHandle<()>) {
    let server = serve_echo(f, instance, plugin.clone()).await;
    (plugin, server)
}

async fn serve_echo(f: &Fixture, instance: Uuid, plugin: Echo) -> tokio::task::JoinHandle<()> {
    let root = f.directory.path();
    let key = KeyPair::from_pem(&fs::read_to_string(root.join("ca.key")).unwrap()).unwrap();
    let ca = CertificateParams::from_ca_cert_pem(&fs::read_to_string(root.join("ca.crt")).unwrap())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let leaf = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![format!("i-{instance}-g-7.xelab.local")]).unwrap();
    p.subject_alt_names.push(SanType::URI(
        format!("spiffe://xelab.local/instance/{instance}/generation/7")
            .try_into()
            .unwrap(),
    ));
    let cert = p.signed_by(&leaf, &ca, &key).unwrap();
    let listener = loop {
        let b = *Uuid::new_v4().as_bytes();
        if let Ok(l) = tokio::net::TcpListener::bind(format!(
            "127.{}.{}.{}:7000",
            30 + b[0] % 150,
            b[1],
            2 + b[2] % 250
        ))
        .await
        {
            break l;
        }
    };
    let dir = f
        .app
        .config
        .root()
        .join("runtime")
        .join(instance.to_string());
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("network.json"),
        serde_json::to_vec(
            &json!({"instance":instance,"peer":listener.local_addr().unwrap().ip().to_string()}),
        )
        .unwrap(),
    )
    .unwrap();
    let service = rpc::capability_service_server::CapabilityServiceServer::new(plugin);
    let identity = tonic::transport::Identity::from_pem(cert.pem(), leaf.serialize_pem());
    tokio::spawn(async move {
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
    })
}

#[tokio::test]
async fn broker_rpc_keeps_the_admitted_deadline_past_thirty_seconds() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, instance) = f.workload().await;
    let (skill, _) = skill_with_timeout(&f, deployment, 60000).await;
    let source = f.source(b"long business call".to_vec()).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let server = serve_echo(
        &f,
        instance,
        Echo {
            delay: Some((entered.clone(), Duration::from_secs(31))),
            ..Echo::default()
        },
    )
    .await;
    let input = json!({"input":{"source":source},"timeout_ms":60000});
    let app = f.app.clone();
    let token = f.token.clone();
    let call = tokio::spawn(async move {
        crate::broker::invoke_skill(
            &app,
            &token,
            "127.0.0.1".parse().unwrap(),
            Uuid::new_v4(),
            skill,
            &input,
            "long-business-call",
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("the authenticated provider must receive the admitted Call");

    // Keep PostgreSQL, credential and TLS clocks real. Advance only the
    // asynchronous transport timers after both ends have scheduled them.
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(30500)).await;
    tokio::time::resume();
    let result = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the provider must return within the admitted deadline")
        .unwrap()
        .expect("the broker transport must allow this admitted business call");
    assert_eq!(result["call"]["output"], json!({"message":"proxied"}));
    let id = contracts::id(&result["call"], "call_id").unwrap();
    let c = f.app.db.connect().await.unwrap();
    let settled = c
        .query_one(
            "SELECT c.state,r.status FROM calls c JOIN reservations r ON r.id=c.id WHERE c.id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(settled.get::<_, &str>(0), "succeeded");
    assert_eq!(settled.get::<_, &str>(1), "released");
    server.abort();
}

#[tokio::test]
async fn host_real_mtls_skill_invocation_replay_stream_and_parent_lineage() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, instance) = f.workload().await;
    proxy(&f, deployment, proxy_rules()).await;
    let (target, target_instance) = f.workload().await;
    let c = f.app.db.connect().await.unwrap();
    let installation: Uuid = c
        .query_one(
            "SELECT installation_id FROM deployments WHERE id=$1",
            &[&target],
        )
        .await
        .unwrap()
        .get(0);
    let mut manifest: Value = c
        .query_one(
            "SELECT manifest FROM installations WHERE id=$1",
            &[&installation],
        )
        .await
        .unwrap()
        .get(0);
    manifest["capabilities"][0]["stream_item_schema"] =
        manifest["capabilities"][0]["output_schema"].clone();
    c.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    let (skill, _) = skill(&f, target).await;
    let source = f.source(b"invoke".to_vec()).await;
    let (parent, context) = f.delegation(deployment, instance, source).await;
    let (plugin, downstream) = echo(&f, target_instance).await;
    let host = tokio::spawn(crate::host::serve(f.app.clone()));
    let mut client = f
        .client(f.client_identity(&format!(
            "spiffe://xelab.local/instance/{instance}/generation/7"
        )))
        .await;
    let bytes = serde_json::to_vec(&json!({"source":source})).unwrap();
    let request = rpc::SkillInvokeRequest {
        call_id: None,
        context: Some(context.clone()),
        skill_id: skill.to_string(),
        input_digest: contracts::digest(&bytes),
        input_json: bytes,
    };
    // The caller owns both Blobs and the actor has read-all approval, but the
    // live parent delegation only contains `source`. A child input cannot add
    // an unrelated Blob to that frozen whitelist by borrowing raw caller rights.
    let unrelated = f.source(b"outside parent input".to_vec()).await;
    let mut outside = request.clone();
    let outside_call = Uuid::new_v4();
    outside.call_id = Some(outside_call.to_string());
    outside.context.as_mut().unwrap().idempotency_key = Uuid::new_v4().to_string();
    outside.input_json = serde_json::to_vec(&json!({"source":unrelated})).unwrap();
    outside.input_digest = contracts::digest(&outside.input_json);
    let quota_before:i64=c.query_one("SELECT concurrent_calls_used FROM quotas WHERE account_id=(SELECT id FROM accounts WHERE independent_owner)",&[]).await.unwrap().get(0);
    assert_eq!(
        client.invoke_skill(outside).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 0);
    assert!(!c
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM calls WHERE id=$1)",
            &[&outside_call]
        )
        .await
        .unwrap()
        .get::<_, bool>(0));
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM host_child_calls WHERE parent_call_id=$1",
            &[&parent]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(c.query_one("SELECT concurrent_calls_used FROM quotas WHERE account_id=(SELECT id FROM accounts WHERE independent_owner)",&[]).await.unwrap().get::<_,i64>(0),quota_before);
    let result = client
        .invoke_skill(request.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        serde_json::from_slice::<Value>(&result.output_json).unwrap(),
        json!({"message":"proxied"})
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    let replay = client
        .invoke_skill(request.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result, replay);
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    let child: Uuid = result.call_id.parse().unwrap();
    let recorded: Uuid = c
        .query_one(
            "SELECT parent_call_id FROM host_child_calls WHERE child_call_id=$1",
            &[&child],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(recorded, parent);
    let mut generation = request.clone();
    generation.context.as_mut().unwrap().idempotency_key = Uuid::new_v4().to_string();
    let mut stream = client
        .invoke_skill_stream(generation)
        .await
        .unwrap()
        .into_inner();
    let item = stream.message().await.unwrap().unwrap();
    assert_eq!(item.sequence, 1);
    assert!(matches!(
        item.body,
        Some(rpc::invoke_chunk::Body::ItemJson(_))
    ));
    let end = stream.message().await.unwrap().unwrap();
    assert_eq!(end.sequence, 2);
    assert!(matches!(
        end.body,
        Some(rpc::invoke_chunk::Body::Completed(_))
    ));
    assert!(stream.message().await.unwrap().is_none());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    c.execute("UPDATE calls SET state='failed' WHERE id=$1", &[&parent])
        .await
        .unwrap();
    assert_eq!(
        client.invoke_skill(request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    host.abort();
    downstream.abort();
}

#[path = "host_proxy_transport_tests.rs"]
mod capability_transport;

#[path = "host_candidates_expiry_tests.rs"]
mod candidates_expiry;

#[tokio::test]
async fn required_host_proxy_rules_need_complete_signed_current_approval() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, _) = f.workload().await;
    proxy(&f, deployment, proxy_rules()).await;
    let c = f.app.db.connect().await.unwrap();
    let installation: Uuid = c
        .query_one(
            "SELECT installation_id FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await
        .unwrap()
        .get(0);
    let mut manifest: Value = c
        .query_one(
            "SELECT manifest FROM installations WHERE id=$1",
            &[&installation],
        )
        .await
        .unwrap()
        .get(0);
    for request in manifest["requested_rules"].as_array_mut().unwrap() {
        if request["rule"]["action"] == "event.publish" {
            request["required"] = json!(true);
        }
    }
    crate::artifact::validate_profile(&manifest).unwrap();
    c.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    crate::host_blobs::check_approval(&c, &f.app, deployment, &manifest)
        .await
        .unwrap();
    let mut approval: Value = c
        .query_one(
            "SELECT approval FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await
        .unwrap()
        .get(0);
    approval["rules"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["action"] != "event.publish");
    c.execute(
        "UPDATE deployments SET approval=$2 WHERE id=$1",
        &[&deployment, &approval],
    )
    .await
    .unwrap();
    assert!(
        crate::host_blobs::check_approval(&c, &f.app, deployment, &manifest)
            .await
            .is_err()
    );
    let mut unsupported = manifest;
    unsupported["requested_rules"] = json!([{"required":true,"rule":{"action":"secret.use","resource":{"kind":"secret","match":"all"}}}]);
    assert!(crate::artifact::validate_profile(&unsupported).is_err());
}

// Maintain explicit lifecycle metadata for these loopback component fixtures.
// This does not claim OCI health/resource evidence and never changes generation,
// phase, availability or disabled deployments back to ready.
fn fixture_health(f: &Fixture, instance: Uuid) {
    let app = Arc::downgrade(&f.app);
    tokio::spawn(async move {
        loop {
            {
                let Some(app) = app.upgrade() else {
                    break;
                };
                if let Ok(c) = app.db.connect().await {
                    let _=c.execute("UPDATE instances SET last_heartbeat_at=now() WHERE id=$1 AND phase='ready'",&[&instance]).await;
                    let _=c.execute("UPDATE provider_records SET observed_at=now() WHERE instance_id=$1 AND availability='ready'",&[&instance]).await;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

#[tokio::test]
async fn signed_and_required_proxy_id_sets_allow_equivalent_split_coverage() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, _) = f.workload().await;
    let mut c = f.app.db.connect().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(&tx, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap();
    let installation: Uuid = tx
        .query_one(
            "SELECT installation_id FROM deployments WHERE id=$1",
            &[&deployment],
        )
        .await
        .unwrap()
        .get(0);
    let mut manifest: Value = tx
        .query_one(
            "SELECT manifest FROM installations WHERE id=$1",
            &[&installation],
        )
        .await
        .unwrap()
        .get(0);
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let rule = |ids: Vec<Uuid>| json!({"action":"skill.read","resource":{"kind":"skill","match":"ids","ids":ids}});
    manifest["requested_rules"] = json!([{"required":true,"rule":rule(vec![a,b])}]);
    let split = json!({"rules":[rule(vec![a]),rule(vec![b])],"egress":[]});
    crate::host_blobs::approve(&tx, &ctx, deployment, &manifest, &split, ctx.subject)
        .await
        .unwrap();
    tx.execute(
        "UPDATE deployments SET approval=$2 WHERE id=$1",
        &[&deployment, &split],
    )
    .await
    .unwrap();
    crate::host_blobs::check_approval(&tx, &f.app, deployment, &manifest)
        .await
        .unwrap();
    manifest["requested_rules"] =
        json!([{"required":true,"rule":rule(vec![a])},{"required":true,"rule":rule(vec![b])}]);
    let combined = json!({"rules":[rule(vec![a,b])],"egress":[]});
    crate::host_blobs::approve(&tx, &ctx, deployment, &manifest, &combined, ctx.subject)
        .await
        .unwrap();
    tx.execute(
        "UPDATE deployments SET approval=$2 WHERE id=$1",
        &[&deployment, &combined],
    )
    .await
    .unwrap();
    crate::host_blobs::check_approval(&tx, &f.app, deployment, &manifest)
        .await
        .unwrap();
    let excessive = json!({"rules":[rule(vec![a,b,Uuid::new_v4()])],"egress":[]});
    assert!(
        crate::host_blobs::approve(&tx, &ctx, deployment, &manifest, &excessive, ctx.subject)
            .await
            .is_err()
    );
}
