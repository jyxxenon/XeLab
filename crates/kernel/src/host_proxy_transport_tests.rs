//! HostService's real mTLS entrypoints and a real mTLS downstream transport.
//! Workload health, metadata, and loopback network.json are component fixtures;
//! no OCI/container resource enforcement or production-host claim is made here.
use super::*;

async fn capability_target(f: &Fixture, deployment: Uuid, instance: Uuid) -> rpc::ContractRef {
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
    // Distinct target name prevents an unconstrained fixture's own capability
    // from becoming an accidental dependency candidate.
    let target = rpc::ContractRef {
        name: "org.xelab.host-transport".into(),
        version: "1.0.0".into(),
        schema_digest: contracts::digest(b"Host mTLS component contract"),
    };
    manifest["capabilities"][0]["contract"] =
        json!({"name":target.name,"version":target.version,"schema_digest":target.schema_digest});
    manifest["capabilities"][0]["stream_item_schema"] =
        manifest["capabilities"][0]["output_schema"].clone();
    crate::artifact::validate_profile(&manifest).unwrap();
    let cap = &manifest["capabilities"][0];
    c.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO capability_contracts(name,version,schema_digest,spec) VALUES($1,$2,$3,$4)",
        &[&target.name, &target.version, &target.schema_digest, cap],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE instances SET last_heartbeat_at=now() WHERE id=$1",
        &[&instance],
    )
    .await
    .unwrap();
    c.execute("INSERT INTO provider_records(instance_id,name,version,availability,features,observed_generation,observed_at) VALUES($1,$2,$3,'ready','[]',7,now())", &[&instance,&target.name,&target.version]).await.unwrap();
    fixture_health(f, instance);
    target
}

async fn dependency(f: &Fixture, consumer: Uuid, contract: &rpc::ContractRef) {
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
            &[&consumer],
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
    manifest["dependencies"] = json!([{"name":"downstream","required":true,"target_kind":"capability","target":contract.name,"version_range":contract.version,"binding_scope":"request","failure_policy":"wait","features":[]}]);
    crate::dependencies::validate_manifest(&manifest).unwrap();
    tx.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    crate::dependencies::bind(&tx, &f.app, &ctx, consumer)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn invocation(
    context: &rpc::RpcContext,
    contract: &rpc::ContractRef,
    binding: &str,
    source: Uuid,
) -> rpc::InvokeRequest {
    let input_json = serde_json::to_vec(&json!({"source":source})).unwrap();
    rpc::InvokeRequest {
        context: Some(context.clone()),
        call_id: Uuid::new_v4().to_string(),
        contract: Some(contract.clone()),
        input_digest: contracts::digest(&input_json),
        input_json,
        binding_id: binding.into(),
        terminal_failure_version: 0,
    }
}

#[tokio::test]
async fn host_mtls_resolve_invoke_stream_replay_and_fixed_binding_fences() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (consumer, consumer_instance) = f.workload().await;
    proxy(&f, consumer, proxy_rules()).await;
    let (provider, provider_instance) = f.workload().await;
    let contract = capability_target(&f, provider, provider_instance).await;
    dependency(&f, consumer, &contract).await;
    let source = f.source(b"Host transport input allowlist".to_vec()).await;
    let (parent, context) = f.delegation(consumer, consumer_instance, source).await;
    let (plugin, downstream) = echo(&f, provider_instance).await;
    let host = tokio::spawn(crate::host::serve(f.app.clone()));
    let mut client = f
        .client(f.client_identity(&format!(
            "spiffe://xelab.local/instance/{consumer_instance}/generation/7"
        )))
        .await;
    let resolve_request = rpc::ResolveRequest {
        context: Some(context.clone()),
        contract: Some(contract.clone()),
        binding_scope_id: parent.to_string(),
    };
    let resolved = client
        .resolve(resolve_request.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resolved.provider_deployment_id, provider.to_string());
    assert_eq!(resolved.contract, Some(contract.clone()));
    assert!(resolved.expires_unix_ms <= context.deadline_unix_ms);
    assert!(Uuid::parse_str(&resolved.binding_id).is_ok());
    let repeated = client
        .resolve(resolve_request.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(repeated.binding_id, resolved.binding_id);
    let request = invocation(&context, &contract, &resolved.binding_id, source);
    let response = client.invoke(request.clone()).await.unwrap().into_inner();
    assert_eq!(
        response.call_id, request.call_id,
        "Host Invoke preserves the caller's fixed child Call ID"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&response.output_json).unwrap(),
        json!({"message":"proxied"})
    );
    assert_eq!(
        response.output_digest,
        contracts::digest(&response.output_json)
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    let replay = client.invoke(request.clone()).await.unwrap().into_inner();
    assert_eq!(replay, response);
    assert_eq!(
        plugin.calls.load(Ordering::SeqCst),
        1,
        "same valid request must not be dispatched twice"
    );
    let c = f.app.db.connect().await.unwrap();
    let child: Uuid = request.call_id.parse().unwrap();
    assert_eq!(
        c.query_one(
            "SELECT parent_call_id FROM host_child_calls WHERE child_call_id=$1",
            &[&child]
        )
        .await
        .unwrap()
        .get::<_, Uuid>(0),
        parent
    );
    let mut stream_context = context.clone();
    stream_context.idempotency_key = Uuid::new_v4().to_string();
    let stream_request = invocation(&stream_context, &contract, &resolved.binding_id, source);
    let mut stream = client
        .invoke_stream(stream_request.clone())
        .await
        .unwrap()
        .into_inner();
    let first = stream.message().await.unwrap().unwrap();
    assert_eq!(first.call_id, stream_request.call_id);
    assert_eq!(first.sequence, 1);
    assert!(matches!(
        first.body,
        Some(rpc::invoke_chunk::Body::ItemJson(_))
    ));
    let terminal = stream.message().await.unwrap().unwrap();
    assert_eq!(terminal.sequence, 2);
    assert!(matches!(
        terminal.body,
        Some(rpc::invoke_chunk::Body::Completed(_))
    ));
    assert!(stream.message().await.unwrap().is_none());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    let mut bad_digest = invocation(&context, &contract, &resolved.binding_id, source);
    bad_digest.context.as_mut().unwrap().idempotency_key = Uuid::new_v4().to_string();
    bad_digest.input_digest = contracts::digest(b"unrelated bytes");
    assert_eq!(
        client.invoke(bad_digest).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    // A new parent Call has a fresh delegation. An old opaque request handle
    // cannot be rebound by replacing body-supplied identities or scope IDs.
    let (_, other_context) = f.delegation(consumer, consumer_instance, source).await;
    let other_request = invocation(&other_context, &contract, &resolved.binding_id, source);
    assert_eq!(
        client.invoke(other_request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let mut wrong_scope = resolve_request.clone();
    wrong_scope.binding_scope_id = consumer.to_string();
    assert_eq!(
        client.resolve(wrong_scope).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    c.execute(
        "UPDATE instances SET generation=8 WHERE id=$1",
        &[&provider_instance],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE provider_records SET observed_generation=8,observed_at=now() WHERE instance_id=$1",
        &[&provider_instance],
    )
    .await
    .unwrap();
    assert!(
        client.resolve(resolve_request.clone()).await.is_err(),
        "healthy new generation cannot inherit old dependency pins"
    );
    let mut drift = invocation(&context, &contract, &resolved.binding_id, source);
    drift.context.as_mut().unwrap().idempotency_key = Uuid::new_v4().to_string();
    assert!(client.invoke(drift).await.is_err());
    c.execute(
        "UPDATE instances SET generation=7 WHERE id=$1",
        &[&provider_instance],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE provider_records SET observed_generation=7,observed_at=now() WHERE instance_id=$1",
        &[&provider_instance],
    )
    .await
    .unwrap();
    proxy(
        &f,
        consumer,
        proxy_rules()
            .into_iter()
            .filter(|rule| rule["action"] != "capability.invoke")
            .collect(),
    )
    .await;
    assert_eq!(
        client.invoke(request.clone()).await.unwrap_err().code(),
        tonic::Code::PermissionDenied,
        "current proxy withdrawal also fences a cached successful result"
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    proxy(&f, consumer, proxy_rules()).await;
    c.execute("UPDATE calls SET state='unknown' WHERE id=$1", &[&parent])
        .await
        .unwrap();
    assert_eq!(
        client.resolve(resolve_request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        client.invoke(request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    host.abort();
    downstream.abort();
}

// Install only the ancestry metadata normally committed by Broker admission.
// No fake execution or runtime readiness proof is inferred from this fixture.
async fn synthetic_ancestry(
    f: &Fixture,
    parent: Uuid,
    parent_instance: Uuid,
    context: &rpc::RpcContext,
    child: Uuid,
) {
    let c = f.app.db.connect().await.unwrap();
    let ticket = Uuid::new_v4();
    let hash = f.app.auth.token_digest(&Uuid::new_v4().to_string());
    let expires = chrono::DateTime::from_timestamp_millis(context.deadline_unix_ms).unwrap();
    let bounds:Value=c.query_one("SELECT e.maximum_rules FROM calls q JOIN execution_delegations e ON e.id=q.delegation_id WHERE q.id=$1",&[&parent]).await.unwrap().get(0);
    c.execute("INSERT INTO host_call_tickets(id,parent_call_id,instance_id,generation,delegation_digest,verification_digest,rpc_context,invocation,bounds,idempotency_key,fingerprint,requested_call_id,input_digest,expires_at) VALUES($1,$2,$3,7,$4,$5,$6,'{}',$12,$7,$8,$9,$10,$11)",&[&ticket,&parent,&parent_instance,&f.app.auth.token_digest(&context.delegation_token),&hash,&json!({"deadline":context.deadline_unix_ms}),&Uuid::new_v4().to_string(),&contracts::digest(b"synthetic ancestry fixture"),&child,&contracts::digest(b"{}"),&expires,&bounds]).await.unwrap();
    c.execute(
        "INSERT INTO host_child_calls(child_call_id,parent_call_id,ticket_id) VALUES($1,$2,$3)",
        &[&child, &parent, &ticket],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn host_mtls_recursive_ancestor_proxy_revocation_expiry_and_frozen_ceiling() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (ancestor, ancestor_instance) = f.workload().await;
    let (middle, middle_instance) = f.workload().await;
    proxy(&f, ancestor, proxy_rules()).await;
    proxy(&f, middle, proxy_rules()).await;
    let (provider, _) = f.workload().await;
    let (skill, _) = skill(&f, provider).await;
    let source = f
        .source(b"recursive HostService ancestor fixture".to_vec())
        .await;
    let (parent, ancestor_context) = f.delegation(ancestor, ancestor_instance, source).await;
    let (child, middle_context) = f.delegation(middle, middle_instance, source).await;
    synthetic_ancestry(&f, parent, ancestor_instance, &ancestor_context, child).await;
    let host = tokio::spawn(crate::host::serve(f.app.clone()));
    let mut client = f
        .client(f.client_identity(&format!(
            "spiffe://xelab.local/instance/{middle_instance}/generation/7"
        )))
        .await;
    let request = rpc::ResolveSkillRequest {
        context: Some(middle_context.clone()),
        skill_id: skill.to_string(),
    };
    assert!(
        client
            .resolve_skill(request.clone())
            .await
            .unwrap()
            .into_inner()
            .ready
    );
    proxy(
        &f,
        ancestor,
        proxy_rules()
            .into_iter()
            .filter(|rule| rule["action"] != "skill.read")
            .collect(),
    )
    .await;
    assert_eq!(
        client
            .resolve_skill(request.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied,
        "middle approval cannot replace withdrawn ancestor proxy authority"
    );
    // A second ancestry chain is issued while the ancestor lacks skill.read.
    // Later adding that approval must not widen its frozen execution ceiling.
    let (limited_parent, limited_ancestor_context) =
        f.delegation(ancestor, ancestor_instance, source).await;
    let (limited_child, limited_middle_context) =
        f.delegation(middle, middle_instance, source).await;
    synthetic_ancestry(
        &f,
        limited_parent,
        ancestor_instance,
        &limited_ancestor_context,
        limited_child,
    )
    .await;
    proxy(&f, ancestor, proxy_rules()).await;
    assert!(
        client
            .resolve_skill(request.clone())
            .await
            .unwrap()
            .into_inner()
            .ready
    );
    let limited = rpc::ResolveSkillRequest {
        context: Some(limited_middle_context),
        skill_id: skill.to_string(),
    };
    assert_eq!(
        client.resolve_skill(limited).await.unwrap_err().code(),
        tonic::Code::PermissionDenied,
        "new approval cannot enlarge an older ancestor's maximum_rules"
    );
    let c = f.app.db.connect().await.unwrap();
    c.execute(
        "UPDATE rpc_delegations SET expires_at=now()-interval '1 second' WHERE call_id=$1",
        &[&parent],
    )
    .await
    .unwrap();
    assert_eq!(
        client.resolve_skill(request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied,
        "an expired ancestor delegation fences a still-live child Call"
    );
    assert!(
        c.query_one(
            "SELECT bool_and(spec->>'enabled'='true') FROM deployments WHERE id=ANY($1)",
            &[&vec![ancestor, middle]]
        )
        .await
        .unwrap()
        .get::<_, bool>(0),
        "tests keep both deployments enabled; denial comes from recursive authority"
    );
    host.abort();
}

#[tokio::test]
async fn host_mtls_large_input_and_large_completed_output_keep_item_bounds_separate() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (consumer, consumer_instance) = f.workload().await;
    proxy(&f, consumer, proxy_rules()).await;
    let (provider, provider_instance) = f.workload().await;
    let contract = capability_target(&f, provider, provider_instance).await;
    let c = f.app.db.connect().await.unwrap();
    let installation: Uuid = c
        .query_one(
            "SELECT installation_id FROM deployments WHERE id=$1",
            &[&provider],
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
    manifest["capabilities"][0]["input_schema"]["properties"]["padding"] =
        json!({"type":"string","maxLength":350000});
    manifest["capabilities"][0]["maximum_input_bytes"] = json!(400000);
    manifest["capabilities"][0]["output_schema"]["properties"]["message"]["maxLength"] =
        json!(2 * 1024 * 1024);
    manifest["capabilities"][0]["maximum_output_bytes"] = json!(2 * 1024 * 1024);
    crate::artifact::validate_profile(&manifest).unwrap();
    c.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE capability_contracts SET spec=$3 WHERE name=$1 AND version=$2",
        &[
            &contract.name,
            &contract.version,
            &manifest["capabilities"][0],
        ],
    )
    .await
    .unwrap();
    dependency(&f, consumer, &contract).await;
    let source = f.source(b"large transport test".to_vec()).await;
    let (parent, context) = f.delegation(consumer, consumer_instance, source).await;
    let (plugin, downstream) = echo(&f, provider_instance).await;
    let output_size = 1024 * 1024 + 4096;
    plugin.output_bytes.store(output_size, Ordering::SeqCst);
    let host = tokio::spawn(crate::host::serve(f.app.clone()));
    let mut client = f
        .client(f.client_identity(&format!(
            "spiffe://xelab.local/instance/{consumer_instance}/generation/7"
        )))
        .await
        .max_decoding_message_size(16 * 1024 * 1024 + 65536);
    let resolved = client
        .resolve(rpc::ResolveRequest {
            context: Some(context.clone()),
            contract: Some(contract.clone()),
            binding_scope_id: parent.to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    let mut request = invocation(&context, &contract, &resolved.binding_id, source);
    request.input_json =
        serde_json::to_vec(&json!({"source":source,"padding":"p".repeat(300*1024)})).unwrap();
    request.input_digest = contracts::digest(&request.input_json);
    assert!(request.input_json.len() > 256 * 1024);
    let unary = client.invoke(request.clone()).await.unwrap().into_inner();
    assert!(unary.output_json.len() > 1024 * 1024);
    assert_eq!(
        serde_json::from_slice::<Value>(&unary.output_json).unwrap()["message"]
            .as_str()
            .unwrap()
            .len(),
        output_size
    );
    assert_eq!(unary.output_digest, contracts::digest(&unary.output_json));
    let mut context = context;
    context.idempotency_key = Uuid::new_v4().to_string();
    request.context = Some(context);
    request.call_id = Uuid::new_v4().to_string();
    let mut stream = client.invoke_stream(request).await.unwrap().into_inner();
    let item = stream.message().await.unwrap().unwrap();
    match item.body.unwrap() {
        rpc::invoke_chunk::Body::ItemJson(bytes) => assert!(bytes.len() < 1024 * 1024),
        _ => panic!("expected bounded ordinary item"),
    }
    let completed = stream.message().await.unwrap().unwrap();
    match completed.body.unwrap() {
        rpc::invoke_chunk::Body::Completed(value) => {
            assert!(value.output_json.len() > 1024 * 1024);
            assert_eq!(
                serde_json::from_slice::<Value>(&value.output_json).unwrap()["message"]
                    .as_str()
                    .unwrap()
                    .len(),
                output_size
            );
            assert_eq!(value.output_digest, contracts::digest(&value.output_json));
        }
        _ => panic!("expected the larger separately bounded completed response"),
    }
    assert!(stream.message().await.unwrap().is_none());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    host.abort();
    downstream.abort();
}

#[tokio::test]
async fn host_queued_stream_frame_rechecks_proxy_authority_at_first_poll() {
    use futures_util::StreamExt;
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (consumer, consumer_instance) = f.workload().await;
    proxy(&f, consumer, proxy_rules()).await;
    let (provider, provider_instance) = f.workload().await;
    let contract = capability_target(&f, provider, provider_instance).await;
    dependency(&f, consumer, &contract).await;
    let source = f.source(b"queued stream authority fixture".to_vec()).await;
    let (parent, context) = f.delegation(consumer, consumer_instance, source).await;
    let (plugin, downstream) = echo(&f, provider_instance).await;
    let c = f.app.db.connect().await.unwrap();
    let ctx = f
        .app
        .auth
        .authenticate(&c, &f.token, "127.0.0.1".parse().unwrap(), Uuid::new_v4())
        .await
        .unwrap();
    let binding=crate::dependencies::resolve_host(&c,&ctx,consumer,parent,&parent.to_string(),&json!({"name":contract.name,"version":contract.version,"schema_digest":contract.schema_digest})).await.unwrap();
    let request = invocation(
        &context,
        &contract,
        binding["binding_id"].as_str().unwrap(),
        source,
    );
    let child: Uuid = request.call_id.parse().unwrap();
    // Keep the returned helper stream entirely unpolled while its producer
    // finishes and queues frames; this is deliberately not an OCI/Tonic test.
    let mut stream = crate::host_calls::invoke_stream(
        f.app.clone(),
        Workload {
            instance: consumer_instance,
            generation: 7,
        },
        request,
    )
    .await
    .unwrap();
    let mut succeeded = false;
    // Admission and completion retain the real Invoke budget. This polling
    // bound only waits for the fixture's successful queue, before revocation.
    for _ in 0..1500 {
        if let Some(row) = c
            .query_opt("SELECT state FROM calls WHERE id=$1", &[&child])
            .await
            .unwrap()
        {
            let state = row.get::<_, String>(0);
            if state == "succeeded" {
                succeeded = true;
                break;
            }
            assert_eq!(
                state, "running",
                "producer failed before queueing its result"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        succeeded,
        "producer must finish before the delivery check is exercised"
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    proxy(
        &f,
        consumer,
        proxy_rules()
            .into_iter()
            .filter(|rule| rule["action"] != "capability.invoke")
            .collect(),
    )
    .await;
    assert_eq!(
        c.query_one("SELECT state FROM calls WHERE id=$1", &[&parent])
            .await
            .unwrap()
            .get::<_, String>(0),
        "running"
    );
    let first = stream.next().await.unwrap().unwrap_err();
    assert_eq!(
        first.code(),
        tonic::Code::PermissionDenied,
        "queued output must not leak after the proxy approval is withdrawn"
    );
    assert!(stream.next().await.is_none());
    downstream.abort();
}

#[path = "host_proxy_ceilings_tests.rs"]
mod layered_ceilings;

fn structured_error(status: &tonic::Status) -> rpc::ErrorDetail {
    use prost::Message;
    let metadata = status
        .metadata()
        .get_bin("xelab-error-bin")
        .expect("Host error includes its typed detail");
    rpc::ErrorDetail::decode(metadata.to_bytes().unwrap()).unwrap()
}

#[tokio::test]
async fn unary_skill_preserves_typed_provider_error_and_unknown_call() {
    use prost::Message;

    let Some(f) = Fixture::new().await else {
        return;
    };
    let (deployment, instance) = f.workload().await;
    let c = f.app.db.connect().await.unwrap();
    c.execute(
        "UPDATE installations SET manifest=jsonb_set(manifest,'{capabilities,0,side_effect}','\"idempotent\"')
          WHERE id=(SELECT installation_id FROM deployments WHERE id=$1)",
        &[&deployment],
    )
    .await
    .unwrap();
    let (skill, _) = skill(&f, deployment).await;
    let source = f.source(b"input".to_vec()).await;
    let (plugin, server) = echo(&f, instance).await;
    let untrusted_id = Uuid::new_v4();
    let detail = rpc::ErrorDetail {
        code: "STATE_CONFLICT".into(),
        message: "opaque provider detail".into(),
        retryable: true,
        retry_after_ms: 17,
        violations: vec![rpc::FieldViolation {
            path: "/private".into(),
            reason: "opaque provider violation".into(),
        }],
        resource_id: untrusted_id.to_string(),
    };
    let mut failure = tonic::Status::failed_precondition("opaque transport message");
    failure.metadata_mut().insert_bin(
        "xelab-error-bin",
        tonic::metadata::MetadataValue::from_bytes(&detail.encode_to_vec()),
    );
    *plugin.unary_failure.lock().unwrap() = Some(failure);

    let input = json!({"input":{"source":source}});
    let key = "typed-unary-error";
    let response = f
        .call(
            "invokeSkill",
            &[("skill_id", skill)],
            input.clone(),
            None,
            key,
            None,
        )
        .await;
    assert_eq!(response.0, 409, "{}", response.1);
    let error = &response.1["error"];
    assert_eq!(error["code"], "STATE_CONFLICT");
    assert_eq!(error["retryable"], false);
    assert!(error["retry_after_ms"].is_null());
    assert_eq!(error["violations"], json!([]));
    assert!(!response.1.to_string().contains("opaque"));
    let id = contracts::id(error, "resource_id").unwrap();
    assert_ne!(id, untrusted_id);
    let row = c
        .query_one(
            "SELECT c.state,c.error,r.status FROM calls c JOIN reservations r ON r.id=c.id
          WHERE c.id=$1 AND c.provider_instance_id=$2",
            &[&id, &instance],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("state"), "unknown");
    assert_eq!(row.get::<_, String>("status"), "active");
    assert_eq!(row.get::<_, Value>("error")["code"], "STATE_CONFLICT");

    let replay = f
        .call(
            "invokeSkill",
            &[("skill_id", skill)],
            input,
            None,
            key,
            None,
        )
        .await;
    assert_eq!(replay.0, 409);
    assert_eq!(replay.1["error"]["code"], "OUTCOME_UNKNOWN");
    assert_eq!(replay.1["error"]["resource_id"], id.to_string());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn host_mtls_effectful_failure_exposes_admitted_call_without_redispatch() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (consumer, consumer_instance) = f.workload().await;
    proxy(&f, consumer, proxy_rules()).await;
    let (provider, provider_instance) = f.workload().await;
    let c = f.app.db.connect().await.unwrap();
    let installation: Uuid = c
        .query_one(
            "SELECT installation_id FROM deployments WHERE id=$1",
            &[&provider],
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
    manifest["capabilities"][0]["side_effect"] = json!("non_repeatable");
    crate::artifact::validate_profile(&manifest).unwrap();
    c.execute(
        "UPDATE installations SET manifest=$2 WHERE id=$1",
        &[&installation, &manifest],
    )
    .await
    .unwrap();
    let (skill, _) = skill(&f, provider).await;
    let source = f.source(b"effectful failure input".to_vec()).await;
    let (parent, context) = f.delegation(consumer, consumer_instance, source).await;
    let (plugin, downstream) = echo(&f, provider_instance).await;
    *plugin.unary_failure.lock().unwrap() = Some(tonic::Status::unavailable(
        "Simulated transport failure after dispatch",
    ));
    let host = tokio::spawn(crate::host::serve(f.app.clone()));
    let mut client = f
        .client(f.client_identity(&format!(
            "spiffe://xelab.local/instance/{consumer_instance}/generation/7"
        )))
        .await;
    let input = serde_json::to_vec(&json!({"source":source})).unwrap();
    // The fixed UUID is known before sending, so it remains usable even if no
    // gRPC status or metadata arrives. This test receives a real mTLS status;
    // it does not pretend to observe metadata after a completely lost response.
    let known = Uuid::new_v4();
    let request = rpc::SkillInvokeRequest {
        context: Some(context.clone()),
        skill_id: skill.to_string(),
        input_digest: contracts::digest(&input),
        input_json: input.clone(),
        call_id: Some(known.to_string()),
    };
    let failed = client.invoke_skill(request.clone()).await.unwrap_err();
    let detail = structured_error(&failed);
    assert_eq!(detail.resource_id, known.to_string());
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        c.query_one("SELECT state FROM calls WHERE id=$1", &[&known])
            .await
            .unwrap()
            .get::<_, String>(0),
        "unknown"
    );
    assert_eq!(
        c.query_one(
            "SELECT parent_call_id FROM host_child_calls WHERE child_call_id=$1",
            &[&known]
        )
        .await
        .unwrap()
        .get::<_, Uuid>(0),
        parent
    );
    let replay = client.invoke_skill(request.clone()).await.unwrap_err();
    assert_eq!(
        structured_error(&replay).resource_id,
        known.to_string(),
        "unknown replay status: {replay:?}"
    );
    assert_eq!(
        plugin.calls.load(Ordering::SeqCst),
        1,
        "unknown non-repeatable calls cannot be dispatched again by a stable replay"
    );
    let inspected = f
        .call(
            "getCall",
            &[("call_id", known)],
            Value::Null,
            None,
            "inspect-effectful-unknown",
            None,
        )
        .await;
    assert_eq!(inspected.0, 200, "{}", inspected.1);
    assert_eq!(inspected.1["state"], "unknown");
    // Schema errors happen before durable admission and must not pretend that
    // the caller's proposed UUID identifies an admitted business operation.
    let rejected = Uuid::new_v4();
    let mut invalid = request.clone();
    invalid.call_id = Some(rejected.to_string());
    invalid.context.as_mut().unwrap().idempotency_key = Uuid::new_v4().to_string();
    invalid.input_json = serde_json::to_vec(&json!({"source":17})).unwrap();
    invalid.input_digest = contracts::digest(&invalid.input_json);
    let preadmission = client.invoke_skill(invalid).await.unwrap_err();
    assert!(structured_error(&preadmission).resource_id.is_empty());
    assert_eq!(
        c.query_one("SELECT count(*) FROM calls WHERE id=$1", &[&rejected])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
    let mut legacy = request.clone();
    legacy.call_id = None;
    legacy.context.as_mut().unwrap().idempotency_key = Uuid::new_v4().to_string();
    let first = client.invoke_skill(legacy.clone()).await.unwrap_err();
    let assigned = structured_error(&first).resource_id;
    let assigned_id: Uuid = assigned
        .parse()
        .expect("legacy admitted errors also expose the core-assigned UUID");
    assert_ne!(assigned_id, known);
    assert_eq!(
        c.query_one("SELECT state FROM calls WHERE id=$1", &[&assigned_id])
            .await
            .unwrap()
            .get::<_, String>(0),
        "unknown"
    );
    assert_eq!(
        structured_error(&client.invoke_skill(legacy.clone()).await.unwrap_err()).resource_id,
        assigned
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    let quota_before: i64 = c
        .query_one("SELECT concurrent_calls_used FROM quotas WHERE account_id=(SELECT id FROM accounts WHERE independent_owner)", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        client.invoke_skill_stream(legacy).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition,
        "changing the response mode must not re-dispatch an unknown effectful call"
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM host_child_calls WHERE parent_call_id=$1",
            &[&parent],
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    assert_eq!(
        c.query_one("SELECT concurrent_calls_used FROM quotas WHERE account_id=(SELECT id FROM accounts WHERE independent_owner)", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        quota_before
    );
    proxy(
        &f,
        consumer,
        proxy_rules()
            .into_iter()
            .filter(|rule| rule["action"] != "skill.invoke")
            .collect(),
    )
    .await;
    let denied = client.invoke_skill(request).await.unwrap_err();
    assert!(
        structured_error(&denied).resource_id.is_empty(),
        "a denied caller cannot obtain an admitted call reference through error replay"
    );
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 2);
    host.abort();
    downstream.abort();
}

#[path = "host_proxy_proof_tests.rs"]
mod transaction_proofs;

#[path = "host_resolve_expiry_tests.rs"]
mod resolve_expiry;
