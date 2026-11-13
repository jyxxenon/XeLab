#![allow(clippy::result_large_err)] // Tonic service signatures use tonic::Status.

use super::*;
use crate::rpc::{
    self,
    capability_service_client::CapabilityServiceClient,
    capability_service_server::{CapabilityService, CapabilityServiceServer},
    plugin_lifecycle_client::PluginLifecycleClient,
    plugin_lifecycle_server::{PluginLifecycle, PluginLifecycleServer},
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    SanType,
};
use std::{fs, sync::Mutex};
use tonic::{
    transport::{ClientTlsConfig, Identity, Server, ServerTlsConfig},
    Response,
};

const INSTANCE_NAME: &str = "i-00000000-0000-4000-8000-000000000001-g-1.xelab.local";
const INSTANCE_URI: &str =
    "spiffe://xelab.local/instance/00000000-0000-4000-8000-000000000001/generation/1";

struct TestCa {
    directory: tempfile::TempDir,
    cert: Certificate,
    key: KeyPair,
}

impl TestCa {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self {
            directory: tempfile::tempdir().unwrap(),
            cert: params.self_signed(&key).unwrap(),
            key,
        }
    }

    fn leaf(&self, name: &str, uri: &str, serial: u64, key: &KeyPair) -> Certificate {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params
            .subject_alt_names
            .push(SanType::URI(uri.try_into().unwrap()));
        params.serial_number = Some(serial.into());
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.signed_by(key, &self.cert, &self.key).unwrap()
    }

    fn files(&self, leaf: &Certificate, key: &KeyPair) -> WorkloadIdentity {
        let root = self.directory.path();
        let identity = WorkloadIdentity {
            cert: root.join("tls.crt"),
            key: root.join("tls.key"),
            ca: root.join("ca.crt"),
        };
        fs::write(&identity.cert, leaf.pem()).unwrap();
        fs::write(&identity.key, key.serialize_pem()).unwrap();
        fs::write(&identity.ca, self.cert.pem()).unwrap();
        identity
    }

    fn plugin_endpoint(&self, address: SocketAddr, identity: Option<Identity>) -> Endpoint {
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(self.cert.pem()))
            .domain_name(INSTANCE_NAME);
        if let Some(identity) = identity {
            tls = tls.identity(identity);
        }
        Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(CONNECT_TIMEOUT)
            .tls_config(tls)
            .unwrap()
    }

    async fn observed_leaf(
        &self,
        address: SocketAddr,
        kernel: &Certificate,
        key: &KeyPair,
    ) -> CertificateDer<'static> {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert.der().clone()).unwrap();
        let mut tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![kernel.der().clone()],
                key.serialize_der().try_into().unwrap(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(tls));
        let tcp = TcpStream::connect(address).await.unwrap();
        let stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connector.connect(ServerName::try_from(INSTANCE_NAME).unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap();
        stream.get_ref().1.peer_certificates().unwrap()[0].clone()
    }
}

#[derive(Clone)]
struct Probe {
    peer: CertificateDer<'static>,
    calls: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Probe {
    fn record<T>(&self, request: &Request<T>) -> Result<(), Status> {
        self.calls
            .lock()
            .unwrap()
            .push(request.remote_addr().unwrap());
        if !request
            .peer_certs()
            .is_some_and(|certs| certs.first() == Some(&self.peer))
        {
            return Err(Status::permission_denied("Unexpected test peer"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl PluginLifecycle for Probe {
    async fn describe(
        &self,
        request: Request<rpc::DescribeRequest>,
    ) -> Result<Response<rpc::DescribeResponse>, Status> {
        self.record(&request)?;
        Ok(Response::new(rpc::DescribeResponse::default()))
    }

    async fn initialize(
        &self,
        request: Request<rpc::InitializeRequest>,
    ) -> Result<Response<rpc::InitializeResponse>, Status> {
        self.record(&request)?;
        Ok(Response::new(rpc::InitializeResponse {
            observed_generation: request.get_ref().generation,
            initialized: true,
        }))
    }

    async fn get_health(
        &self,
        _: Request<rpc::HealthRequest>,
    ) -> Result<Response<rpc::HealthResponse>, Status> {
        Err(Status::unimplemented("Test fixture"))
    }

    async fn drain(
        &self,
        _: Request<rpc::DrainRequest>,
    ) -> Result<Response<rpc::DrainResponse>, Status> {
        Err(Status::unimplemented("Test fixture"))
    }

    async fn shutdown(
        &self,
        _: Request<rpc::ShutdownRequest>,
    ) -> Result<Response<rpc::Ack>, Status> {
        Err(Status::unimplemented("Test fixture"))
    }
}

#[tonic::async_trait]
impl CapabilityService for Probe {
    type InvokeStreamStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<rpc::InvokeChunk, Status>>>;

    async fn invoke(
        &self,
        request: Request<rpc::InvokeRequest>,
    ) -> Result<Response<rpc::InvokeResponse>, Status> {
        self.record(&request)?;
        let request = request.into_inner();
        // The same success fixture also builds with additive protocol fields.
        #[allow(clippy::needless_update)]
        let response = rpc::InvokeResponse {
            call_id: request.call_id,
            output_json: request.input_json,
            output_digest: request.input_digest,
            ..Default::default()
        };
        Ok(Response::new(response))
    }

    async fn invoke_stream(
        &self,
        request: Request<rpc::InvokeRequest>,
    ) -> Result<Response<Self::InvokeStreamStream>, Status> {
        let completed = self.invoke(request).await?.into_inner();
        Ok(Response::new(tokio_stream::iter(vec![
            Ok(rpc::InvokeChunk {
                call_id: completed.call_id.clone(),
                sequence: 1,
                body: Some(rpc::invoke_chunk::Body::ItemJson(
                    completed.output_json.clone(),
                )),
            }),
            Ok(rpc::InvokeChunk {
                call_id: completed.call_id.clone(),
                sequence: 2,
                body: Some(rpc::invoke_chunk::Body::Completed(completed)),
            }),
        ])))
    }

    async fn cancel(
        &self,
        _: Request<rpc::CancelCallRequest>,
    ) -> Result<Response<rpc::Ack>, Status> {
        Err(Status::unimplemented("Test fixture"))
    }

    async fn query_result(
        &self,
        _: Request<rpc::QueryResultRequest>,
    ) -> Result<Response<rpc::QueryResultResponse>, Status> {
        Err(Status::unimplemented("Test fixture"))
    }
}

#[tokio::test]
async fn plugin_rpc_checks_mtls_and_keeps_serving_during_certificate_rotation() {
    let ca = TestCa::new();
    let key = KeyPair::generate().unwrap();
    let kernel_key = KeyPair::generate().unwrap();
    let kernel = ca.leaf(KERNEL_NAME, KERNEL_URI, 1, &kernel_key);
    let leaf = ca.leaf(INSTANCE_NAME, INSTANCE_URI, 2, &key);
    let identity = ca.files(&leaf, &key);
    let service = Probe {
        peer: kernel.der().clone(),
        calls: Arc::default(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = identity.plugin_incoming(listener).unwrap();
    let task = tokio::spawn(
        Server::builder()
            .add_service(PluginLifecycleServer::new(service.clone()))
            .add_service(CapabilityServiceServer::new(service.clone()))
            .serve_with_incoming(incoming),
    );
    let trusted = ca.plugin_endpoint(
        address,
        Some(Identity::from_pem(kernel.pem(), kernel_key.serialize_pem())),
    );
    let channel = trusted.connect().await.unwrap();
    let mut lifecycle = PluginLifecycleClient::new(channel.clone());
    let initialized = lifecycle
        .initialize(rpc::InitializeRequest {
            generation: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(initialized.initialized);
    assert_eq!(initialized.observed_generation, 1);

    let mut capability = CapabilityServiceClient::new(channel);
    let request = rpc::InvokeRequest {
        call_id: "00000000-0000-4000-8000-000000000002".into(),
        input_json: br#"{"message":"hello"}"#.to_vec(),
        ..Default::default()
    };
    let result = capability
        .invoke(request.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.call_id, request.call_id);
    assert_eq!(result.output_json, request.input_json);
    let mut stream = capability
        .invoke_stream(request)
        .await
        .unwrap()
        .into_inner();
    let item = stream.message().await.unwrap().unwrap();
    assert_eq!(item.sequence, 1);
    assert_eq!(
        item.body,
        Some(rpc::invoke_chunk::Body::ItemJson(
            result.output_json.clone()
        ))
    );
    let end = stream.message().await.unwrap().unwrap();
    assert_eq!(end.sequence, 2);
    assert_eq!(end.body, Some(rpc::invoke_chunk::Body::Completed(result)));
    assert!(stream.message().await.unwrap().is_none());

    for rejected in [
        None,
        Some(Identity::from_pem(leaf.pem(), key.serialize_pem())),
    ] {
        if let Ok(channel) = ca.plugin_endpoint(address, rejected).connect().await {
            assert!(PluginLifecycleClient::new(channel)
                .describe(rpc::DescribeRequest::default())
                .await
                .is_err());
        }
    }
    assert_eq!(service.calls.lock().unwrap().len(), 3);

    assert_eq!(
        ca.observed_leaf(address, &kernel, &kernel_key).await,
        *leaf.der()
    );
    let rotated = ca.leaf(INSTANCE_NAME, INSTANCE_URI, 3, &key);
    let staged = identity.cert.with_extension("next");
    fs::write(&staged, rotated.pem()).unwrap();
    fs::rename(&staged, &identity.cert).unwrap();
    assert_eq!(
        ca.observed_leaf(address, &kernel, &kernel_key).await,
        *rotated.der()
    );
    lifecycle
        .describe(rpc::DescribeRequest::default())
        .await
        .unwrap();
    let channel = trusted.connect().await.unwrap();
    PluginLifecycleClient::new(channel)
        .describe(rpc::DescribeRequest::default())
        .await
        .unwrap();
    let calls = service.calls.lock().unwrap();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[..4], [calls[0]; 4]);
    assert_ne!(calls[0], calls[4]);
    task.abort();
}

#[tokio::test]
async fn host_channel_verifies_kernel_name_and_uri_and_sends_workload_identity() {
    let ca = TestCa::new();
    let workload_key = KeyPair::generate().unwrap();
    let workload = ca.leaf(INSTANCE_NAME, INSTANCE_URI, 1, &workload_key);
    let identity = ca.files(&workload, &workload_key);
    let service = Probe {
        peer: workload.der().clone(),
        calls: Arc::default(),
    };
    for (name, uri, trusted) in [
        ("different.xelab.local", KERNEL_URI, false),
        (KERNEL_NAME, INSTANCE_URI, false),
        (KERNEL_NAME, KERNEL_URI, true),
    ] {
        let key = KeyPair::generate().unwrap();
        let leaf = ca.leaf(name, uri, 2, &key);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(
            Server::builder()
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(Identity::from_pem(leaf.pem(), key.serialize_pem()))
                        .client_ca_root(tonic::transport::Certificate::from_pem(ca.cert.pem())),
                )
                .unwrap()
                .add_service(PluginLifecycleServer::new(service.clone()))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let channel = identity.host_channel(address).await;
        if trusted {
            tokio::time::timeout(
                CONNECT_TIMEOUT,
                PluginLifecycleClient::new(channel.unwrap())
                    .describe(rpc::DescribeRequest::default()),
            )
            .await
            .unwrap()
            .unwrap();
        } else {
            assert!(channel.is_err());
        }
        task.abort();
    }
    assert_eq!(service.calls.lock().unwrap().len(), 1);
}

#[test]
fn host_endpoint_accepts_only_https_socket_addresses() {
    for valid in ["https://127.0.0.1:7000", "https://[::1]:7000"] {
        assert!(host_address(valid).is_ok());
    }
    for invalid in [
        "http://127.0.0.1:7000",
        "https://kernel.xelab.local:7000",
        "https://127.0.0.1:0",
        "https://127.0.0.1:7000/",
        "https://127.0.0.1:7000?x=y",
    ] {
        assert!(host_address(invalid).is_err());
    }
}
