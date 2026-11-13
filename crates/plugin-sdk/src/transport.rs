use crate::rpc::host_service_client::HostServiceClient;
use futures_util::{Stream, StreamExt};
use hyper_util::rt::TokioIo;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        Resumption, VerifierBuilderError, WebPkiServerVerifier,
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{ClientHello, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier},
    sign::CertifiedKey,
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme,
};
use std::{
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor, TlsConnector};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    transport::{Channel, Endpoint, Uri},
    Request, Status,
};

pub const MAX_RPC_MESSAGE_BYTES: usize = 20 * 1024 * 1024;
pub const PLUGIN_RPC_LISTEN: &str = "0.0.0.0:7000";
const KERNEL_NAME: &str = "kernel.xelab.local";
const KERNEL_URI: &str = "spiffe://xelab.local/kernel";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PEM_BYTES: u64 = 65536;

/// The workload TLS files injected by XeLab for the current instance.
#[derive(Clone, Debug)]
pub struct WorkloadIdentity {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

impl WorkloadIdentity {
    pub fn from_env() -> io::Result<Self> {
        fn path(name: &'static str) -> io::Result<PathBuf> {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, name))
        }

        Ok(Self {
            cert: path("XELAB_TLS_CERT_PATH")?,
            key: path("XELAB_TLS_KEY_PATH")?,
            ca: path("XELAB_TLS_CA_PATH")?,
        })
    }

    /// Supply authenticated kernel connections to a Tonic server. New handshakes
    /// read the current certificate and key from the workload files.
    pub fn plugin_incoming(
        &self,
        listener: TcpListener,
    ) -> io::Result<impl Stream<Item = io::Result<TlsStream<TcpStream>>> + Send + 'static> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(self.roots()?, provider.clone())
            .build()
            .map_err(|_| invalid("Invalid workload CA"))?;
        let resolver = RotatingCertificate {
            identity: self.clone(),
            provider: provider.clone(),
        };
        resolver.load()?;
        let mut tls = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid("Invalid workload TLS configuration"))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(resolver));
        tls.alpn_protocols = vec![b"h2".to_vec()];
        tls.session_storage = Arc::new(NoServerSessionStorage {});
        tls.send_tls13_tickets = 0;
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        Ok(TcpListenerStream::new(listener)
            .map(move |socket| {
                let acceptor = acceptor.clone();
                async move {
                    let socket = match socket {
                        Ok(socket) => socket,
                        Err(error) => return Some(Err(error)),
                    };
                    if socket.set_nodelay(true).is_err() {
                        return None;
                    }
                    let Ok(Ok(stream)) =
                        tokio::time::timeout(CONNECT_TIMEOUT, acceptor.accept(socket)).await
                    else {
                        return None;
                    };
                    let session = stream.get_ref().1;
                    let leaf = session.peer_certificates().and_then(|certs| certs.first());
                    let kernel =
                        leaf.is_some_and(|cert| matches!(has_uri_san(cert, KERNEL_URI), Ok(true)));
                    (kernel && session.alpn_protocol() == Some(b"h2")).then_some(Ok(stream))
                }
            })
            .buffer_unordered(32)
            .filter_map(std::future::ready))
    }

    /// Connect to the HostService address injected by XeLab. Use the current
    /// call's delegated context and deadline on each generated request.
    pub async fn connect_host(&self) -> io::Result<HostServiceClient<Channel>> {
        let value = std::env::var("XELAB_HOST_RPC_ENDPOINT")
            .map_err(|_| invalid("Missing XELAB_HOST_RPC_ENDPOINT"))?;
        let channel = self.host_channel(host_address(&value)?).await?;
        Ok(HostServiceClient::new(channel)
            .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES))
    }

    async fn host_channel(&self, address: SocketAddr) -> io::Result<Channel> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = pinned_server_verifier(self.roots()?, provider.clone(), KERNEL_URI.into())
            .map_err(|_| invalid("Invalid workload CA"))?;
        let identity = self.clone();
        // The connector applies TLS. Use HTTPS as the HTTP/2 origin while
        // letting the connector own the entire TCP and TLS handshake.
        Endpoint::from_static("http://kernel.xelab.local")
            .origin(Uri::from_static("https://kernel.xelab.local"))
            .connect_timeout(CONNECT_TIMEOUT)
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let identity = identity.clone();
                let provider = provider.clone();
                let verifier = verifier.clone();
                async move {
                    let (certs, key) = identity.key_pair()?;
                    let mut tls = ClientConfig::builder_with_provider(provider)
                        .with_safe_default_protocol_versions()
                        .map_err(|_| invalid("Invalid workload TLS configuration"))?
                        .dangerous()
                        .with_custom_certificate_verifier(verifier)
                        .with_client_auth_cert(certs, key)
                        .map_err(|_| invalid("Invalid workload TLS identity"))?;
                    tls.alpn_protocols = vec![b"h2".to_vec()];
                    tls.resumption = Resumption::disabled();
                    let stream = TcpStream::connect(address).await?;
                    stream.set_nodelay(true)?;
                    let name = ServerName::try_from(KERNEL_NAME).expect("fixed kernel DNS name");
                    let tls = TlsConnector::from(Arc::new(tls))
                        .connect(name, stream)
                        .await?;
                    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                        return Err(invalid("HostService requires HTTP/2"));
                    }
                    Ok(TokioIo::new(tls))
                }
            }))
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::NotConnected, error))
    }

    fn roots(&self) -> io::Result<Arc<RootCertStore>> {
        let mut roots = RootCertStore::empty();
        for cert in read_certificates(&self.ca)? {
            roots
                .add(cert)
                .map_err(|_| invalid("Invalid workload CA"))?;
        }
        Ok(Arc::new(roots))
    }

    fn key_pair(&self) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let certs = read_certificates(&self.cert)?;
        let raw = zeroize::Zeroizing::new(read_pem(&self.key)?);
        let key = rustls_pemfile::private_key(&mut raw.as_slice())?
            .ok_or_else(|| invalid("Missing workload private key"))?;
        Ok((certs, key))
    }
}

fn host_address(value: &str) -> io::Result<SocketAddr> {
    value
        .strip_prefix("https://")
        .and_then(|address| address.parse::<SocketAddr>().ok())
        .filter(|address| address.port() != 0)
        .ok_or_else(|| invalid("Expected the injected HTTPS HostService address"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_pem(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(invalid("Workload PEM file exceeds its limit"));
    }
    Ok(bytes)
}

fn read_certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs =
        rustls_pemfile::certs(&mut read_pem(path)?.as_slice()).collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(invalid("Missing workload certificate"));
    }
    Ok(certs)
}

#[derive(Debug)]
struct RotatingCertificate {
    identity: WorkloadIdentity,
    provider: Arc<CryptoProvider>,
}

impl RotatingCertificate {
    fn load(&self) -> io::Result<CertifiedKey> {
        let (certs, key) = self.identity.key_pair()?;
        CertifiedKey::from_der(certs, key, &self.provider)
            .map_err(|_| invalid("Invalid workload TLS identity"))
    }
}

impl ResolvesServerCert for RotatingCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.load().ok().map(Arc::new)
    }
}

#[allow(clippy::result_large_err)] // Preserve the Tonic interceptor interface.
pub fn require_kernel<T>(request: Request<T>) -> Result<Request<T>, Status> {
    let certs = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("mTLS required"))?;
    let cert = certs
        .first()
        .ok_or_else(|| Status::unauthenticated("mTLS required"))?;
    if !has_uri_san(cert, KERNEL_URI)? {
        return Err(Status::permission_denied("Kernel identity required"));
    }
    Ok(request)
}

#[allow(clippy::result_large_err)]
fn has_uri_san(cert: &[u8], expected: &str) -> Result<bool, Status> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert)
        .map_err(|_| Status::unauthenticated("Invalid certificate"))?;
    let san = parsed
        .subject_alternative_name()
        .map_err(|_| Status::unauthenticated("Invalid SAN"))?;
    Ok(san.is_some_and(|s| {
        s.value.general_names.iter().any(|name| {
            matches!(name, x509_parser::extensions::GeneralName::URI(uri) if *uri == expected)
        })
    }))
}

/// Verify the platform CA, TLS server name and expected XeLab workload URI.
pub fn pinned_server_verifier(
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    expected_uri: String,
) -> Result<Arc<dyn ServerCertVerifier>, VerifierBuilderError> {
    let webpki = WebPkiServerVerifier::builder_with_provider(roots, provider).build()?;
    Ok(Arc::new(PinnedServerVerifier {
        webpki,
        expected_uri,
    }))
}

#[derive(Debug)]
struct PinnedServerVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    expected_uri: String,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .webpki
            .verify_server_cert(cert, intermediates, name, ocsp, now)?;
        if !matches!(has_uri_san(cert, &self.expected_uri), Ok(true)) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, signed)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests;
