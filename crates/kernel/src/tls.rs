use crate::{
    config::{read_private, Config},
    error::{Error, Result},
};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
use uuid::Uuid;
pub use xelab_plugin_sdk::transport::require_kernel;

pub fn issue(config: &Config, instance: Option<(Uuid, i64)>, directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    let ca_pem = fs::read_to_string(config.text("security", "workload_ca_cert_file"))?;
    let ca_key = read_private(
        Path::new(config.text("security", "workload_ca_key_file")),
        16384,
    )?;
    let key = KeyPair::from_pem(
        std::str::from_utf8(&ca_key).map_err(|_| Error::invalid("Invalid CA key encoding"))?,
    )
    .map_err(|_| Error::invalid("Invalid CA key"))?;
    let issuer = CertificateParams::from_ca_cert_pem(&ca_pem)
        .map_err(|_| Error::invalid("Invalid CA certificate"))?
        .self_signed(&key)
        .map_err(|_| Error::invalid("Invalid CA issuer"))?;
    let name = instance
        .map(|(id, g)| format!("i-{id}-g-{g}.xelab.local"))
        .unwrap_or_else(|| "kernel.xelab.local".to_owned());
    let uri = instance
        .map(|(id, g)| format!("spiffe://xelab.local/instance/{id}/generation/{g}"))
        .unwrap_or_else(|| "spiffe://xelab.local/kernel".to_owned());
    // Keep the private key for this generation, so atomically replacing the certificate
    // cannot expose a mismatched certificate/key pair to concurrent readers.
    let key_path = directory.join("tls.key");
    let fresh = !key_path.exists();
    let leaf = if fresh {
        KeyPair::generate()
    } else {
        KeyPair::from_pem(&fs::read_to_string(&key_path)?)
    }
    .map_err(|_| Error::unavailable("Workload private key is unavailable"))?;
    let mut params = CertificateParams::new(vec![name.clone()])
        .map_err(|_| Error::invalid("Invalid workload identity"))?;
    // A leaf must not inherit rcgen's default CA subject: OpenSSL/BoringSSL
    // can otherwise treat it as self-issued and reject the client chain.
    params.distinguished_name.push(DnType::CommonName, name);
    params.subject_alt_names.push(SanType::URI(
        uri.try_into()
            .map_err(|_| Error::invalid("Invalid identity URI"))?,
    ));
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::seconds(30);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::seconds(3600);
    let cert = params
        .signed_by(&leaf, &issuer, &key)
        .map_err(|_| Error::unavailable("Certificate signing failed"))?;
    atomic_file(&directory.join("tls.crt"), cert.pem().as_bytes(), 0o644)?;
    atomic_file(&directory.join("ca.crt"), ca_pem.as_bytes(), 0o644)?;
    if fresh {
        atomic_file(
            &directory.join("tls.key"),
            leaf.serialize_pem().as_bytes(),
            0o600,
        )?;
    }
    if instance.is_some() {
        let path = std::ffi::CString::new(directory.join("tls.key").as_os_str().as_encoded_bytes())
            .map_err(|_| Error::invalid("Invalid identity path"))?;
        if unsafe { libc::chown(path.as_ptr(), 65532, 65532) } != 0 {
            return Err(Error::unavailable(
                "Cannot assign workload private key owner",
            ));
        }
        fs::set_permissions(directory.join("tls.key"), fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
}

pub fn atomic_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    fs::File::open(
        path.parent()
            .ok_or_else(|| Error::invalid("Missing parent directory"))?,
    )?
    .sync_all()?;
    Ok(())
}

pub async fn channel(
    config: &Config,
    id: Uuid,
    generation: i64,
    address: &str,
) -> Result<tonic::transport::Channel> {
    channel_with_timeout(
        config,
        id,
        generation,
        address,
        std::time::Duration::from_secs(30),
    )
    .await
}

pub(crate) async fn channel_with_timeout(
    config: &Config,
    id: Uuid,
    generation: i64,
    address: &str,
    timeout: std::time::Duration,
) -> Result<tonic::transport::Channel> {
    if timeout.is_zero() || timeout > std::time::Duration::from_secs(3600) {
        return Err(Error::invalid("Invalid workload channel deadline"));
    }
    let identity = config.root().join("kernel-identity");
    let ca = fs::read(config.text("security", "workload_ca_cert_file"))?;
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(ca))
        .identity(tonic::transport::Identity::from_pem(
            fs::read(identity.join("tls.crt"))?,
            fs::read(identity.join("tls.key"))?,
        ))
        .domain_name(format!("i-{id}-g-{generation}.xelab.local"));
    tonic::transport::Endpoint::from_shared(format!("https://{address}:7000"))
        .map_err(|_| Error::invalid("Invalid runtime address"))?
        .tls_config(tls)
        .map_err(|_| Error::unavailable("Invalid workload TLS configuration"))?
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(timeout)
        .connect()
        .await
        .map_err(|_| Error::unavailable("Workload TLS connection failed"))
}
