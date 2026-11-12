//! Fixed-instance mTLS transport. It does not select providers, authorize callers,
//! reserve quota or retry: the existing Broker must do those before dispatch.
use super::*;
use crate::{config::Config, runtime::Runtime};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::StreamExt;
use std::{
    fs,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use uuid::Uuid;
use xelab_plugin_sdk::transport::pinned_server_verifier;

pub struct InstanceHttp {
    client: reqwest::Client,
    origin: url::Url,
    tls: Arc<rustls::ClientConfig>,
    address: SocketAddr,
    server_name: String,
    maximum_json_bytes: usize,
}

pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub bytes: Vec<u8>,
}

/// Created by the trusted caller after durable Broker admission. Never parse
/// this from external headers; its opaque delegation comes from Auth::issue_rpc.
pub struct Delegation<'a> {
    pub token: &'a str,
    pub subject: Uuid,
    pub call: Uuid,
    pub deadline_unix_ms: i64,
    pub idempotency_key: &'a str,
}

/// Origin allocation is trusted platform configuration, never a plugin field.
/// All third-party pages require an origin separate from the trusted login and
/// the embedding shell. The caller must also ensure uniqueness across plugins.
pub struct StaticOrigin {
    origin: String,
    frame_ancestor: String,
}
impl StaticOrigin {
    pub fn for_deployment(
        config: &Config,
        deployment: Uuid,
        shell_origin: Option<&str>,
    ) -> Result<Self> {
        let gateway = &config.value["ui_gateway"];
        if gateway.is_null() {
            return Err(Error::unavailable("UI origin allocation is not configured"));
        }
        if shell_origin.is_some_and(|shell| {
            !gateway["shell_origins"]
                .as_array()
                .is_some_and(|list| list.iter().any(|v| v == shell))
        }) {
            return Err(Error::invalid("UI shell origin is not approved"));
        }
        let base = string(gateway, "base_domain")?;
        let port = unsigned(&gateway["public_port"])?;
        let suffix = if port == 443 {
            String::new()
        } else {
            format!(":{port}")
        };
        let mut policy = Self::new(
            &format!("https://d-{}.{base}{suffix}", deployment.simple()),
            config.origin()?.as_str().trim_end_matches('/'),
            shell_origin,
        )?;
        if shell_origin.is_none() {
            let origins = gateway["shell_origins"]
                .as_array()
                .ok_or_else(|| Error::invalid("UI shell origins are missing"))?
                .iter()
                .map(|value| {
                    exact_origin(
                        value
                            .as_str()
                            .ok_or_else(|| Error::invalid("Invalid UI shell origin"))?,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            if !origins.is_empty() {
                policy.frame_ancestor = origins.join(" ");
            }
        }
        Ok(policy)
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn new(
        plugin_origin: &str,
        trusted_origin: &str,
        shell_origin: Option<&str>,
    ) -> Result<Self> {
        let plugin = exact_origin(plugin_origin)?;
        let trusted = exact_origin(trusted_origin)?;
        if plugin == trusted {
            return Err(Error::invalid("Plugin pages require an isolated origin"));
        }
        let frame_ancestor = if let Some(shell) = shell_origin {
            let shell = exact_origin(shell)?;
            if shell == plugin {
                return Err(Error::invalid(
                    "Plugin frames cannot share the shell origin",
                ));
            }
            shell
        } else {
            "'none'".into()
        };
        Ok(Self {
            origin: plugin,
            frame_ancestor,
        })
    }
}

fn exact_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).map_err(|_| Error::invalid("Invalid isolated origin"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization() != value
    {
        return Err(Error::invalid("An exact HTTPS origin is required"));
    }
    Ok(value.into())
}

impl InstanceHttp {
    pub fn from_runtime(
        config: &Config,
        runtime: &Runtime,
        instance: Uuid,
        generation: i64,
    ) -> Result<Self> {
        let address: IpAddr = runtime
            .address(instance)?
            .parse()
            .map_err(|_| Error::invalid("Runtime HTTP address is not an IP"))?;
        let cidr: ipnet::Ipv4Net = config
            .text("runtime", "network_cidr")
            .parse()
            .map_err(|_| Error::invalid("Invalid runtime CIDR"))?;
        if !matches!(address, IpAddr::V4(ip) if cidr.contains(&ip)) || generation < 1 {
            return Err(Error::invalid(
                "Runtime HTTP address or generation is invalid",
            ));
        }
        let identity = config.root().join("kernel-identity");
        let mut pem = fs::read(identity.join("tls.crt"))?;
        pem.extend(fs::read(identity.join("tls.key"))?);
        let mut transport = Self::new(
            instance,
            generation,
            SocketAddr::new(address, 8080),
            &fs::read(config.text("security", "workload_ca_cert_file"))?,
            &pem,
        )?;
        transport.maximum_json_bytes = config.json_limit(MAXIMUM_RESPONSE_BYTES);
        Ok(transport)
    }

    pub(super) fn new(
        instance: Uuid,
        generation: i64,
        address: SocketAddr,
        ca: &[u8],
        identity: &[u8],
    ) -> Result<Self> {
        let host = format!("i-{instance}-g-{generation}.xelab.local");
        let origin = url::Url::parse(&format!("https://{host}:{}", address.port()))
            .map_err(|_| Error::invalid("Invalid instance origin"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut Cursor::new(ca)) {
            roots
                .add(cert.map_err(|_| Error::invalid("Invalid workload CA"))?)
                .map_err(|_| Error::invalid("Invalid workload CA"))?;
        }
        let verifier = pinned_server_verifier(
            Arc::new(roots),
            provider.clone(),
            format!("spiffe://xelab.local/instance/{instance}/generation/{generation}"),
        )
        .map_err(|_| Error::invalid("Invalid workload CA"))?;
        let certificates = rustls_pemfile::certs(&mut Cursor::new(identity))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::invalid("Invalid kernel HTTP identity"))?;
        let private_key = rustls_pemfile::private_key(&mut Cursor::new(identity))
            .map_err(|_| Error::invalid("Invalid kernel HTTP identity"))?
            .ok_or_else(|| Error::invalid("Kernel HTTP key is missing"))?;
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::unavailable("Cannot configure workload HTTP TLS"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certificates, private_key)
            .map_err(|_| Error::invalid("Invalid kernel HTTP identity"))?;
        let tls = Arc::new(tls);
        let client = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .use_preconfigured_tls((*tls).clone())
            .resolve(&host, address)
            .connect_timeout(Duration::from_secs(2))
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| Error::unavailable("Cannot build workload HTTP transport"))?;
        Ok(Self {
            client,
            origin,
            tls,
            address,
            server_name: host,
            maximum_json_bytes: MAXIMUM_RESPONSE_BYTES,
        })
    }

    /// Verify the declared HTTP listener without inventing an undeclared probe
    /// operation or executing any business work during lifecycle readiness.
    pub async fn probe(&self) -> Result<()> {
        let work = async {
            let socket = tokio::net::TcpStream::connect(self.address).await?;
            let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
                .map_err(|_| Error::invalid("Invalid HTTP workload name"))?;
            let connection = tokio_rustls::TlsConnector::from(self.tls.clone())
                .connect(name, socket)
                .await
                .map_err(|_| Error::unavailable("HTTP workload TLS listener is unavailable"))?;
            drop(connection);
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(2), work)
            .await
            .map_err(|_| timeout())?
    }

    pub async fn invoke(
        &self,
        op: &Operation,
        headers: &HeaderMap,
        bytes: &[u8],
        delegation: Delegation<'_>,
        remaining: Duration,
    ) -> Result<Response> {
        let deadline = tokio::time::Instant::now() + remaining.min(op.route.timeout);
        check_deadline(deadline)?;
        if bytes.len() > self.maximum_json_bytes {
            return Err(too_large());
        }
        let mut headers = op.request(headers, bytes)?;
        inject(&mut headers, Some(delegation))?;
        check_deadline(deadline)?;
        let work = async {
            let response = self
                .send(
                    &op.method,
                    &op.path,
                    headers,
                    bytes,
                    deadline,
                    self.maximum_json_bytes,
                )
                .await?;
            let headers = op.response(response.status, &response.headers, &response.bytes)?;
            check_deadline(deadline)?;
            Ok(Response {
                headers,
                ..response
            })
        };
        tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| timeout())?
    }

    pub async fn static_page(
        &self,
        route: &Route,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        origin: &StaticOrigin,
        remaining: Duration,
    ) -> Result<Response> {
        let deadline = tokio::time::Instant::now() + remaining.min(route.timeout);
        check_deadline(deadline)?;
        canonical_path(path)?;
        if route.kind == "http"
            || !route.methods.contains(method)
            || !under(path, &route.prefix)
            || (method != Method::GET && method != Method::HEAD)
        {
            return Err(Error::not_found());
        }
        reject_upgrade(headers)?;
        // Range is deliberately unsupported until its response validation and
        // multipart limits are implemented; do not silently forward it.
        if headers.contains_key("range") {
            return Err(Error::invalid("Static byte ranges are not supported"));
        }
        let headers = allowed_request_headers(headers, false)?;
        check_deadline(deadline)?;
        let work = async {
            let response = self
                .send(method, path, headers, &[], deadline, MAXIMUM_RESPONSE_BYTES)
                .await?;
            let headers = static_response(
                method,
                response.status,
                &response.headers,
                &response.bytes,
                origin,
            )?;
            check_deadline(deadline)?;
            Ok(Response {
                headers,
                ..response
            })
        };
        tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| timeout())?
    }

    async fn send(
        &self,
        method: &Method,
        path: &str,
        headers: HeaderMap,
        bytes: &[u8],
        deadline: tokio::time::Instant,
        maximum: usize,
    ) -> Result<Response> {
        let response = self
            .open_request(method, path, headers, bytes, deadline)
            .await?;
        collect(response, maximum).await
    }
    pub(crate) async fn open(
        &self,
        op: &Operation,
        headers: &HeaderMap,
        bytes: &[u8],
        context: Delegation<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<reqwest::Response> {
        check_deadline(deadline)?;
        if bytes.len() > self.maximum_json_bytes {
            return Err(too_large());
        }
        let mut headers = op.request(headers, bytes)?;
        inject(&mut headers, Some(context))?;
        check_deadline(deadline)?;
        self.open_request(&op.method, &op.path, headers, bytes, deadline)
            .await
    }
    async fn open_request(
        &self,
        method: &Method,
        path: &str,
        headers: HeaderMap,
        bytes: &[u8],
        deadline: tokio::time::Instant,
    ) -> Result<reqwest::Response> {
        canonical_path(path)?;
        check_deadline(deadline)?;
        let mut url = self.origin.clone();
        url.set_path(path);
        if url.path() != path {
            return Err(Error::invalid(
                "HTTP target path changed during serialization",
            ));
        }
        let response = self
            .client
            .request(method.clone(), url)
            .headers(headers)
            .body(bytes.to_owned())
            .timeout(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    timeout()
                } else {
                    Error::unavailable(
                        "Plugin HTTP request failed; dispatch outcome may be unknown",
                    )
                }
            })?;
        check_deadline(deadline)?;
        Ok(response)
    }
}

/// Bound both declared and chunked HTTP responses before schema/JSON parsing.
pub(crate) async fn collect(response: reqwest::Response, maximum: usize) -> Result<Response> {
    if response
        .content_length()
        .is_some_and(|size| size > maximum as u64)
    {
        return Err(too_large());
    }
    let status = response.status();
    let headers = response.headers().clone();
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            if error.is_timeout() {
                timeout()
            } else {
                Error::unavailable("Plugin HTTP response ended before completion")
            }
        })?;
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Response {
        status,
        headers,
        bytes,
    })
}

pub(crate) fn static_response(
    method: &Method,
    status: StatusCode,
    headers: &HeaderMap,
    bytes: &[u8],
    origin: &StaticOrigin,
) -> Result<HeaderMap> {
    reject_upgrade(headers)?;
    if ![
        StatusCode::OK,
        StatusCode::NOT_MODIFIED,
        StatusCode::NOT_FOUND,
    ]
    .contains(&status)
        || headers.contains_key("location")
        || headers.contains_key("set-cookie")
    {
        return Err(Error::invalid(
            "Static response attempted a redirect, cookie or undeclared status",
        ));
    }
    if bytes.len() > MAXIMUM_RESPONSE_BYTES {
        return Err(too_large());
    }
    if (method == Method::HEAD || status == StatusCode::NOT_MODIFIED) && !bytes.is_empty() {
        return Err(Error::invalid("Static HEAD or 304 must be bodyless"));
    }
    if unique(headers, "content-encoding")?.is_some_and(|v| v != "identity") {
        return Err(Error::invalid("Encoded static responses are not admitted"));
    }
    let mut result = HeaderMap::new();
    if status != StatusCode::NOT_MODIFIED {
        let media = unique(headers, "content-type")?
            .ok_or_else(|| Error::invalid("Static content type is missing"))?;
        let name = media
            .to_str()
            .map_err(|_| Error::invalid("Invalid static media type"))?
            .split(';')
            .next()
            .unwrap()
            .trim();
        if ![
            "text/html",
            "text/css",
            "text/plain",
            "application/javascript",
            "text/javascript",
            "application/json",
            "image/png",
            "image/jpeg",
            "image/gif",
            "image/webp",
            "image/svg+xml",
            "image/x-icon",
            "font/woff",
            "font/woff2",
        ]
        .contains(&name)
        {
            return Err(Error::invalid("Unapproved static media type"));
        }
        result.insert("content-type", media.clone());
    }
    for name in ["etag", "last-modified"] {
        if let Some(value) = unique(headers, name)? {
            result.insert(HeaderName::from_static(name), value.clone());
        }
    }
    let csp = format!("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' blob:; media-src 'self' blob:; connect-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors {}",origin.frame_ancestor);
    result.insert(
        "content-security-policy",
        HeaderValue::from_str(&csp).map_err(|_| Error::invalid("Invalid static CSP"))?,
    );
    result.insert("cache-control", HeaderValue::from_static("no-store"));
    result.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    result.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    result.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    Ok(result)
}

fn inject(headers: &mut HeaderMap, delegation: Option<Delegation<'_>>) -> Result<()> {
    if let Some(d) = delegation {
        if d.token.len() < 32 || d.token.len() > 512 {
            return Err(Error::invalid("Invalid admitted HTTP delegation"));
        }
        headers.insert(
            "x-xelab-delegation",
            HeaderValue::from_str(d.token)
                .map_err(|_| Error::invalid("Invalid admitted HTTP delegation"))?,
        );
        headers.insert(
            "x-xelab-subject",
            HeaderValue::from_str(&d.subject.to_string()).unwrap(),
        );
        if d.deadline_unix_ms <= chrono::Utc::now().timestamp_millis()
            || d.idempotency_key.is_empty()
            || d.idempotency_key.chars().count() > 128
        {
            return Err(Error::invalid(
                "Admitted HTTP context deadline or business key is invalid",
            ));
        }
        headers.insert(
            "x-xelab-call-id",
            HeaderValue::from_str(&d.call.to_string()).unwrap(),
        );
        headers.insert(
            "x-xelab-deadline-unix-ms",
            HeaderValue::from_str(&d.deadline_unix_ms.to_string()).unwrap(),
        );
        headers.insert(
            "x-xelab-idempotency-key",
            HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(d.idempotency_key.as_bytes())).unwrap(),
        );
    }
    Ok(())
}
fn timeout() -> Error {
    Error::new(
        "DEADLINE_EXCEEDED",
        "Plugin HTTP deadline exceeded",
        StatusCode::GATEWAY_TIMEOUT,
    )
}
fn check_deadline(deadline: tokio::time::Instant) -> Result<()> {
    if deadline <= tokio::time::Instant::now() {
        Err(timeout())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod compact_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn wire_response(
        wire: &'static [u8],
    ) -> (reqwest::Response, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket.write_all(wire).await.unwrap();
            std::future::pending::<()>().await;
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        (response, server)
    }

    #[tokio::test]
    async fn compact_response_cap_precedes_json_parse_for_declared_and_chunked_bodies() {
        for wire in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".as_slice(),
        ] {
            let (response, server) = wire_response(wire).await;
            let result = tokio::time::timeout(Duration::from_secs(2), collect(response, 4)).await;
            server.abort();
            assert_eq!(result.unwrap().err().unwrap().code, "PAYLOAD_TOO_LARGE");
        }
        let (response, server) =
            wire_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnull").await;
        let response = collect(response, 4).await.unwrap();
        server.abort();
        assert_eq!(response.bytes, b"null");
    }
}
