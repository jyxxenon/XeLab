use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use xelab_kernel::{
    artifact::Artifact,
    auth,
    config::{read_private, require_host_admin, Config},
    contracts::{openapi, strict_json},
    db::{Db, LEADER_LOCK, SCHEMA_VERSION},
    error::{Error, Result},
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    /// Issue one-time activation for a password-cleared historical user.
    RecoverAccount {
        #[arg(long)]
        config: PathBuf,
        /// Root-owned file containing a current recovery-Owner credential.
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        account_id: uuid::Uuid,
        #[arg(long)]
        confirm_account_id: uuid::Uuid,
        /// Preserve this UUID when inspecting an uncertain one-time response.
        #[arg(long)]
        operation_id: uuid::Uuid,
        #[arg(long)]
        revision: i64,
    },
    ValidateConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Check staged manifest and contracts against a signed install request.
    ValidateArtifact {
        /// Local directory containing xelab/plugin.json and contract members.
        #[arg(long)]
        artifact_root: PathBuf,
        /// The signed InstallRequest JSON from the artifact producer.
        #[arg(long)]
        install_request: PathBuf,
        /// An independently obtained Ed25519 publisher public key in PEM format.
        #[arg(long)]
        publisher_key: PathBuf,
    },
    /// Read-only XFS project quota preflight; does not enable Volume APIs.
    StorageCheck {
        #[arg(long)]
        config: PathBuf,
    },
    /// Capture the stopped platform into its configured off-host repository.
    PlatformBackup {
        #[arg(long)]
        config: PathBuf,
        /// Stop and drain all platform workloads under exclusive host/DB leases.
        #[arg(long)]
        allow_downtime: bool,
        /// Finish a saved snapshot only after every source object was prepared.
        #[arg(long)]
        resume: Option<uuid::Uuid>,
        /// Abort failed-snapshot uploads by saved ID and exact object key.
        #[arg(long, conflicts_with = "resume")]
        cleanup_failed: Option<uuid::Uuid>,
    },
    /// Restore a complete platform into a fresh, exclusively owned target.
    PlatformRestore {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        receipt_file: PathBuf,
        #[arg(long)]
        owner_id: uuid::Uuid,
        /// Independently fence the old host before using this target.
        #[arg(long)]
        source_host_fenced: bool,
        /// Continue the exact UUID saved in the private target recovery journal.
        #[arg(long)]
        resume: Option<uuid::Uuid>,
    },
    Migrate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        target: u64,
    },
    Bootstrap {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        owner_name: String,
    },
    Api {
        operation_id: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        body_file: Option<String>,
        /// Atomically publish a verified Blob download without overwriting files.
        #[arg(long)]
        output_file: Option<PathBuf>,
        #[arg(long = "path")]
        path: Vec<String>,
        #[arg(long = "query")]
        query: Vec<String>,
        #[arg(long)]
        if_match: Option<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long, default_value_t = 60000)]
        timeout_ms: u64,
    },
}
#[tokio::main]
async fn main() {
    xelab_kernel::init_crypto();
    if let Err(e) = run(Args::parse()).await {
        eprintln!("{e}");
        std::process::exit(match e.status.as_u16() {
            400 | 413 | 415 => 2,
            401 => 3,
            403 => 4,
            409 | 412 | 428 => 5,
            504 => 6,
            429 | 503 => 7,
            _ => 8,
        });
    }
}
fn read_body(path: &str, limit: usize) -> Result<Vec<u8>> {
    if path == "-" {
        read_bounded(io::stdin(), limit)
    } else {
        read_bounded(std::fs::File::open(path)?, limit)
    }
}

fn read_bounded(input: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::invalid("Input exceeds its limit"));
    }
    Ok(bytes)
}

fn read_artifact_input(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::invalid("Artifact inputs must be regular files"));
    }
    read_bounded(file, limit)
}

async fn run(args: Args) -> Result<()> {
    match args.command {
        Cmd::RecoverAccount {
            config,
            token_file,
            account_id,
            confirm_account_id,
            operation_id,
            revision,
        } => {
            require_host_admin()?;
            let token = zeroize::Zeroizing::new(
                String::from_utf8(read_private(&token_file, 16384)?)
                    .map_err(|_| Error::invalid("Credential file is not UTF-8"))?,
            );
            let result = xelab_kernel::account_recovery::issue(
                Config::load(&config)?,
                token.trim(),
                xelab_kernel::account_recovery::Request {
                    account: account_id,
                    confirm_account: confirm_account_id,
                    operation: operation_id,
                    revision,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Cmd::ValidateConfig { config } => {
            Config::load(&config)?;
            println!(
                "{}",
                json!({"configuration":"valid","runtime_checked":false})
            );
        }
        Cmd::ValidateArtifact {
            artifact_root,
            install_request,
            publisher_key,
        } => {
            const MAX_REQUEST: usize = 1024 * 1024;
            let request = strict_json(
                &read_artifact_input(&install_request, MAX_REQUEST)?,
                MAX_REQUEST,
            )?;
            let key = String::from_utf8(read_artifact_input(&publisher_key, 64 * 1024)?)
                .map_err(|_| Error::invalid("Publisher public key is not UTF-8"))?;
            let artifact = Artifact::inspect_files(&artifact_root, &request, &key)?;
            println!(
                "{}",
                json!({
                    "artifact_files": "valid",
                    "publisher_id": artifact.manifest["publisher_id"],
                    "plugin_id": artifact.manifest["plugin_id"],
                    "version": artifact.manifest["version"],
                    "manifest_digest": artifact.manifest_digest,
                    "signed_image_digest": artifact.image_digest,
                    "image_content_verified": false,
                })
            );
        }
        Cmd::StorageCheck { config } => {
            require_host_admin()?;
            let cfg = Config::load(&config)?;
            let status = xelab_kernel::storage::xfs::check(&cfg.root().join("volumes"))?;
            println!("{}", serde_json::to_string(&status)?);
        }
        Cmd::PlatformBackup {
            config,
            allow_downtime,
            resume,
            cleanup_failed,
        } => {
            require_host_admin()?;
            if !allow_downtime {
                return Err(Error::invalid(
                    "Offline maintenance requires explicit downtime",
                ));
            }
            let config = Config::load(&config)?;
            if let Some(snapshot) = cleanup_failed {
                let receipt =
                    xelab_kernel::offline::backup::cleanup(config, snapshot, true).await?;
                println!("{}", serde_json::to_string(&receipt)?);
                return Ok(());
            }
            let receipt = match resume {
                Some(snapshot) => {
                    xelab_kernel::offline::backup::resume(config, snapshot, true).await?
                }
                None => xelab_kernel::offline::backup::create(config, true).await?,
            };
            println!("{}", serde_json::to_string(&receipt)?);
        }
        Cmd::PlatformRestore {
            config,
            receipt_file,
            owner_id,
            source_host_fenced,
            resume,
        } => {
            require_host_admin()?;
            if !source_host_fenced {
                return Err(Error::invalid(
                    "Platform recovery requires the source host to be fenced",
                ));
            }
            let receipt = read_private(&receipt_file, 1024 * 1024)?;
            let receipt = serde_json::from_value(strict_json(&receipt, 1024 * 1024)?)?;
            let password = zeroize::Zeroizing::new(
                String::from_utf8(read_body("-", 1024)?)
                    .map_err(|_| Error::invalid("Password must be UTF-8"))?
                    .trim_end_matches(['\r', '\n'])
                    .to_owned(),
            );
            let result = xelab_kernel::offline::restore::run(
                Config::load(&config)?,
                receipt,
                true,
                resume,
                owner_id,
                password,
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Cmd::Migrate { config, target } => {
            require_host_admin()?;
            if target != SCHEMA_VERSION {
                return Err(Error::invalid(
                    "Only the current explicit migration target is supported",
                ));
            }
            let cfg = Config::load(&config)?;
            let (dsn, _) = cfg.secrets()?;
            Db::new(dsn)?.migrate().await?;
            println!(
                "{}",
                json!({"migration":SCHEMA_VERSION,"status":"applied_or_verified"})
            );
        }
        Cmd::Bootstrap { config, owner_name } => {
            require_host_admin()?;
            let cfg = Config::load(&config)?;
            let (dsn, _) = cfg.secrets()?;
            let db = Db::new(dsn)?;
            db.check().await?;
            let password = String::from_utf8(read_body("-", 1024)?)
                .map_err(|_| Error::invalid("Password must be UTF-8"))?;
            let mut c = db.connect().await?;
            let tx = c.transaction().await?;
            tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&LEADER_LOCK])
                .await?;
            let id = auth::bootstrap(
                &tx,
                &owner_name,
                password.trim_end_matches(['\r', '\n']),
                &cfg.value["quota_defaults"],
            )
            .await?;
            tx.commit().await?;
            println!("{}", json!({"owner_id":id}));
        }
        Cmd::Api {
            operation_id,
            endpoint,
            token_file,
            ca_file,
            body_file,
            output_file,
            path,
            query,
            if_match,
            idempotency_key,
            timeout_ms,
        } => {
            let mut selected = None;
            for (p, methods) in openapi()["paths"].as_object().unwrap() {
                for (m, op) in methods.as_object().unwrap() {
                    if op["operationId"] == operation_id {
                        selected = Some((p.clone(), m.clone(), op));
                    }
                }
            }
            let (mut route, method, op) =
                selected.ok_or_else(|| Error::invalid("Unknown operationId"))?;
            for item in path {
                let (k, v) = item
                    .split_once('=')
                    .ok_or_else(|| Error::invalid("Path arguments require NAME=VALUE"))?;
                if v.contains(['/', '?', '#', '%']) {
                    return Err(Error::invalid("Invalid path argument"));
                }
                route = route.replace(&format!("{{{k}}}"), v);
            }
            if route.contains('{') {
                return Err(Error::invalid("Missing path argument"));
            }
            let mut url = xelab_kernel::config::checked_origin(&endpoint)?;
            url.set_path(&route);
            for item in query {
                let (k, v) = item
                    .split_once('=')
                    .ok_or_else(|| Error::invalid("Query arguments require NAME=VALUE"))?;
                url.query_pairs_mut().append_pair(k, v);
            }
            let mut builder = reqwest::Client::builder()
                .timeout(Duration::from_millis(timeout_ms))
                .redirect(reqwest::redirect::Policy::none());
            if let Some(path) = ca_file {
                builder = builder.add_root_certificate(
                    reqwest::Certificate::from_pem(&std::fs::read(path)?)
                        .map_err(|_| Error::invalid("Invalid CA certificate"))?,
                );
            }
            let client = builder
                .build()
                .map_err(|_| Error::unavailable("Cannot initialize HTTP client"))?;
            let mut request = client.request(
                method
                    .to_ascii_uppercase()
                    .parse()
                    .map_err(|_| Error::invalid("Invalid operation method"))?,
                url,
            );
            if let Some(path) = token_file {
                let token = String::from_utf8(read_private(Path::new(&path), 1024)?)
                    .map_err(|_| Error::invalid("Invalid token file"))?;
                request = request.bearer_auth(token.trim());
            }
            if operation_id == "downloadBlob" && output_file.is_none() {
                return Err(Error::invalid("downloadBlob requires --output-file"));
            }
            if operation_id != "downloadBlob" && output_file.is_some() {
                return Err(Error::invalid(
                    "--output-file is supported only for downloadBlob",
                ));
            }
            if operation_id == "uploadBlob" {
                let path = body_file
                    .ok_or_else(|| Error::invalid("uploadBlob requires a regular --body-file"))?;
                if path == "-" {
                    return Err(Error::invalid(
                        "Binary upload requires a regular file with known length",
                    ));
                }
                let mut file = std::fs::File::open(&path)?;
                let meta = file.metadata()?;
                if !meta.is_file() || meta.len() > 67108864 {
                    return Err(Error::invalid(
                        "Blob upload requires a file of at most 64 MiB",
                    ));
                }
                use sha2::{Digest, Sha256};
                let mut hash = Sha256::new();
                let mut buffer = [0u8; 65536];
                let mut count = 0u64;
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    count += n as u64;
                    if count > meta.len() {
                        return Err(Error::conflict("Blob upload file changed"));
                    }
                    hash.update(&buffer[..n]);
                }
                if count != meta.len() {
                    return Err(Error::conflict("Blob upload file changed"));
                }
                file.seek(SeekFrom::Start(0))?;
                request = request
                    .header("content-type", "application/octet-stream")
                    .header("content-length", count)
                    .header("x-content-sha256", format!("sha256:{:x}", hash.finalize()))
                    .body(reqwest::Body::wrap_stream(
                        tokio_util::io::ReaderStream::new(tokio::fs::File::from_std(file)),
                    ));
            } else if let Some(path) = body_file {
                let bytes = read_body(&path, 4194304)?;
                strict_json(&bytes, 4194304)?;
                request = request
                    .header("content-type", "application/json")
                    .body(bytes);
            }
            if let Some(value) = if_match {
                request = request.header("if-match", value);
            }
            if op["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "Idempotency-Key")
            {
                request = request.header(
                    "idempotency-key",
                    idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
            }
            let mut response = request.send().await.map_err(|_| {
                Error::unavailable("HTTP request failed; operation outcome may need inspection")
            })?;
            let status = response.status();
            if status.is_success() && operation_id == "downloadBlob" {
                let value = download(response, output_file.as_deref().unwrap()).await?;
                println!("{}", serde_json::to_string(&value)?);
                return Ok(());
            }
            if response.content_length().is_some_and(|n| n > 16777216) {
                return Err(Error::invalid("HTTP response exceeds its limit"));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| Error::unavailable("HTTP response was interrupted"))?
            {
                if body.len() + chunk.len() > 16777216 {
                    return Err(Error::invalid("HTTP response exceeds its limit"));
                }
                body.extend_from_slice(&chunk);
            }
            if !body.is_empty() {
                let value: Value = serde_json::from_slice(&body)?;
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            if !status.is_success() {
                return Err(Error::new(
                    "HTTP_ERROR",
                    "Server rejected the operation",
                    axum::http::StatusCode::from_u16(status.as_u16()).unwrap(),
                ));
            }
        }
    }
    Ok(())
}

async fn download(mut response: reqwest::Response, path: &Path) -> Result<Value> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::OpenOptionsExt;
    use tokio::io::AsyncWriteExt;
    let expected = response
        .headers()
        .get("x-content-sha256")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() == 71 && v.starts_with("sha256:"))
        .ok_or_else(|| Error::invalid("Blob response digest is missing"))?
        .to_string();
    let size = response
        .content_length()
        .filter(|n| *n <= 67108864)
        .ok_or_else(|| Error::invalid("Blob response length is invalid"))?;
    let temp = path.with_extension(format!("xelab-{}", uuid::Uuid::new_v4()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)?;
    let result = async {
        let mut file = tokio::fs::File::from_std(file);
        let mut count = 0u64;
        let mut hash = Sha256::new();
        while let Some(bytes) = response
            .chunk()
            .await
            .map_err(|_| Error::unavailable("Blob download was interrupted"))?
        {
            count += bytes.len() as u64;
            if count > size {
                return Err(Error::invalid("Blob response length differs"));
            }
            hash.update(&bytes);
            file.write_all(&bytes).await?;
        }
        if count != size || format!("sha256:{:x}", hash.finalize()) != expected {
            return Err(Error::invalid("Blob response length or digest differs"));
        }
        file.sync_all().await?;
        drop(file);
        // hard_link fails if the destination exists, including a symlink. Both
        // files are on the same filesystem, so publication is atomic.
        std::fs::hard_link(&temp, path)?;
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(json!({"download":"verified","size_bytes":count,"digest":expected}))
    }
    .await;
    let cleanup = std::fs::remove_file(&temp);
    if cleanup.is_err() && result.is_ok() {
        return Err(Error::unavailable("Blob download cleanup failed"));
    }
    result
}
