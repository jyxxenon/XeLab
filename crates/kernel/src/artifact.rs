use crate::{
    contracts::{digest, id, strict_json, string, validate, validate_business},
    error::{Error, Result},
    runtime::Runtime,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, Verifier, VerifyingKey};
use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path},
};

pub struct Artifact {
    pub image: String,
    pub manifest: Value,
    pub raw: Vec<u8>,
    pub image_digest: String,
    pub manifest_digest: String,
    /// Original immutable OpenAPI member, validated after OCI/Manifest signature.
    pub http_contract: Option<Vec<u8>>,
}

pub fn image_ref(image: &str) -> Result<&str> {
    if image.len() > 2048
        || !image
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !image
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._-:@".contains(&c))
    {
        return Err(Error::invalid("Invalid immutable OCI reference"));
    }
    let (_, d) = image
        .rsplit_once('@')
        .ok_or_else(|| Error::invalid("OCI digest is required"))?;
    if d.len() != 71
        || !d.starts_with("sha256:")
        || !d[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::invalid("Invalid SHA-256 image digest"));
    }
    Ok(d)
}

pub fn read_image_file(root: &Path, relative: &str, maximum: usize) -> Result<Vec<u8>> {
    let mut path = root.to_owned();
    let parts: Vec<_> = Path::new(relative).components().collect();
    if parts.is_empty() {
        return Err(Error::invalid("Invalid artifact path"));
    }
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(Error::invalid("Artifact path escapes its root"));
        };
        path.push(name);
        if path.symlink_metadata()?.file_type().is_symlink() {
            return Err(Error::invalid(
                "Signed artifact paths cannot contain symbolic links",
            ));
        }
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(Error::invalid("Artifact member must be a regular file"));
    }
    let mut bytes = Vec::new();
    f.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::invalid("Artifact member exceeds its size limit"));
    }
    Ok(bytes)
}

pub fn signature_envelope(manifest: &Value, image_digest: &str, raw: &[u8]) -> Result<String> {
    let publisher = id(manifest, "publisher_id")?;
    let plugin = string(manifest, "plugin_id")?;
    let version = string(manifest, "version")?;
    if [plugin, version, image_digest]
        .iter()
        .any(|s| s.contains(['\r', '\n']))
    {
        return Err(Error::invalid("Invalid signature field"));
    }
    Ok(format!(
        "xelab-artifact-v1\n{publisher}\n{plugin}\n{version}\n{image_digest}\n{}\n",
        digest(raw)
    ))
}

pub fn verify_signature(
    key: &str,
    signature: &str,
    manifest: &Value,
    image_digest: &str,
    raw: &[u8],
) -> Result<()> {
    let key = VerifyingKey::from_public_key_pem(key)
        .map_err(|_| Error::invalid("Expected an Ed25519 public key"))?;
    let bytes = STANDARD
        .decode(signature)
        .map_err(|_| Error::invalid("Invalid signature encoding"))?;
    let sig =
        Signature::from_slice(&bytes).map_err(|_| Error::invalid("Invalid Ed25519 signature"))?;
    key.verify(
        signature_envelope(manifest, image_digest, raw)?.as_bytes(),
        &sig,
    )
    .map_err(|_| Error::invalid("Artifact signature verification failed"))
}

pub fn validate_profile(manifest: &Value) -> Result<()> {
    validate_profile_inner(manifest, false)
}

/// Internal execution validation for durable schema jobs. Public installation
/// stays closed until format upgrades, restores and physical acceptance finish.
pub(crate) fn validate_runtime_profile(manifest: &Value) -> Result<()> {
    validate_profile_inner(manifest, true)
}

fn validate_profile_inner(manifest: &Value, allow_versioned: bool) -> Result<()> {
    validate("Manifest", manifest)?;
    let versioned = manifest["data_schema_version"] != "none";
    crate::webui::validate_manifest(manifest)?;
    crate::ui::validate_manifest(manifest)?;
    crate::dependencies::validate_manifest(manifest)?;
    crate::events::validate_manifest(manifest)?;
    if manifest
        .get("extension_points")
        .is_some_and(|value| !value.as_array().is_some_and(Vec::is_empty))
    {
        return Err(Error::invalid(
            "This ordinary-plugin profile does not support extension points",
        ));
    }

    if manifest
        .get("requested_rules")
        .and_then(Value::as_array)
        .is_some_and(|rules| {
            rules.iter().any(|r| {
                !(r["required"] == false
                    && r["rule"]["action"] == "secret.use"
                    && r["rule"]["resource"]["kind"] == "secret"
                    || crate::host_blobs::proxy_action(
                        r["rule"]["action"].as_str().unwrap_or(""),
                        r["rule"]["resource"]["kind"].as_str().unwrap_or(""),
                    ))
                    || r["rule"]
                        .get("conditions")
                        .is_some_and(|v| !v.as_object().is_some_and(serde_json::Map::is_empty))
            })
        })
    {
        return Err(Error::invalid("Only unconditional supported HostService proxy requests and optional secret.use are accepted"));
    }
    crate::volumes::validate_mounts(manifest)?;
    if (versioned && !allow_versioned)
        || manifest
            .get("business_entry")
            .is_some_and(|v| v != "direct" && v != "skill_required")
        || manifest.get("micro_runtime").is_some()
        || manifest.get("extension_host").is_some()
    {
        return Err(Error::invalid("Unsupported plugin profile"));
    }
    if versioned {
        let schema = manifest["data_schema_version"].as_str().unwrap();
        let requests = manifest.get("requested_rules").and_then(Value::as_array);
        let volumes = manifest["volumes"].as_array().unwrap();
        if schema.len() > 64
            || schema.chars().any(char::is_control)
            || requests.is_some_and(|r| !r.is_empty())
            || manifest["upgrade_strategy"] != "recreate"
            || volumes.is_empty()
            || volumes.len() > 16
            || volumes.iter().any(|v| {
                v["access"] != "rw"
                    || v["scope"] != "deployment"
                    || v["mount_path"].as_str().is_some_and(|path| {
                        path == "/xelab-migration"
                            || path.starts_with("/xelab-migration/")
                            || "/xelab-migration".starts_with(&format!("{path}/"))
                    })
            })
        {
            return Err(Error::invalid(
                "Versioned data requires an exclusive recreate volume group without proxy requests",
            ));
        }
    }
    let platform = if cfg!(target_arch = "x86_64") {
        "linux/amd64"
    } else if cfg!(target_arch = "aarch64") {
        "linux/arm64"
    } else {
        return Err(Error::invalid("Unsupported host architecture"));
    };
    if !manifest["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == platform)
    {
        return Err(Error::invalid(
            "Artifact does not support this host platform",
        ));
    }
    if manifest
        .get("concurrency")
        .is_some_and(|c| c["max_queue_requests"] != 0)
    {
        return Err(Error::invalid("This profile requires max_queue_requests=0"));
    }
    crate::contracts::compile_business(&manifest["config_schema"])?;
    for cap in manifest["capabilities"].as_array().unwrap() {
        // Side effects control retries, not whether a signed ordinary plugin
        // can execute its first call. The Broker never regenerates a stream or
        // retries an uncertain invocation. The internal versioned-data profile
        // remains limited to its independently verified write semantics.
        if !matches!(
            cap["side_effect"].as_str(),
            Some("none" | "idempotent" | "queryable" | "non_repeatable")
        ) || (versioned && !matches!(cap["side_effect"].as_str(), Some("none" | "idempotent")))
        {
            return Err(Error::invalid(
                "Unsupported ordinary capability or versioned-data side effects",
            ));
        }
        for key in ["input_schema", "output_schema", "stream_item_schema"] {
            if key != "stream_item_schema" || !cap[key].is_null() {
                crate::contracts::compile_business(&cap[key])?;
            }
        }
    }
    // HTTP candidates are checked against the signed OpenAPI member by inspect
    // and subsequently against immutable stored bytes. Keep ordinary capability
    // validation unchanged and reject all future target kinds.
    let mut capability_manifest = manifest.clone();
    if let Some(candidates) = capability_manifest
        .get_mut("skills")
        .and_then(Value::as_array_mut)
    {
        let mut versions = std::collections::HashSet::new();
        for definition in candidates.iter() {
            if definition["target"]["kind"] != "capability"
                && definition["target"]["kind"] != "http"
            {
                return Err(Error::invalid(
                    "Unsupported Skill target in the ordinary plugin profile",
                ));
            }
            validate("SkillDefinition", definition)?;
            if !versions.insert((
                string(definition, "name")?.to_owned(),
                string(definition, "version")?.to_owned(),
            )) {
                return Err(Error::invalid("Duplicate signed Skill name and version"));
            }
        }
        candidates.retain(|definition| definition["target"]["kind"] == "capability");
    }
    crate::skills::validate_candidates(&capability_manifest)?;
    Ok(())
}

impl Artifact {
    pub async fn inspect(runtime: &Runtime, request: &Value, key: &str) -> Result<Self> {
        let (image, image_digest) = installation_image(request)?;
        // Host administrators import images into the dedicated namespace. No unbounded registry pull runs in the daemon.
        runtime.verify_image(image, image_digest).await?;
        let root = runtime.mount_image(image, image_digest).await?;
        Self::inspect_members(&root, request, key, image, image_digest)
    }

    /// Check staged files with the installation verifier. The caller supplies
    /// the publisher key and the directory, so this establishes file and
    /// signature consistency with the declared image digest only.
    pub fn inspect_files(root: &Path, request: &Value, key: &str) -> Result<Self> {
        let (image, image_digest) = installation_image(request)?;
        Self::inspect_members(root, request, key, image, image_digest)
    }

    fn inspect_members(
        root: &Path,
        request: &Value,
        key: &str,
        image: &str,
        image_digest: &str,
    ) -> Result<Self> {
        let raw = read_image_file(root, "xelab/plugin.json", 1048576)?;
        let manifest = strict_json(&raw, 1048576)?;
        if manifest["publisher_id"] != request["publisher_id"] {
            return Err(Error::invalid(
                "Publisher does not match the signed manifest",
            ));
        }
        verify_signature(
            key,
            string(request, "signature")?,
            &manifest,
            image_digest,
            &raw,
        )?;
        validate_profile(&manifest)?;
        let http_contract = if manifest["routes"]
            .as_array()
            .is_some_and(|routes| routes.iter().any(|route| route["kind"] == "http"))
        {
            Some(read_image_file(
                root,
                "xelab/http/openapi.json",
                crate::plugin_http::MAXIMUM_CONTRACT_BYTES,
            )?)
        } else {
            None
        };
        crate::plugin_http::Registry::compile(&manifest, http_contract.as_deref())?;
        for cap in manifest["capabilities"].as_array().unwrap() {
            let name = string(&cap["contract"], "name")?;
            let version = string(&cap["contract"], "version")?;
            let mut checks = String::new();
            for (file, field) in [
                ("input.schema.json", "input_schema"),
                ("output.schema.json", "output_schema"),
                ("stream.schema.json", "stream_item_schema"),
                ("semantics.json", ""),
            ] {
                let bytes = read_image_file(
                    root,
                    &format!("xelab/contracts/{name}/{version}/{file}"),
                    1048576,
                )?;
                let value = strict_json(&bytes, 1048576)?;
                if !field.is_empty() && value != cap[field] {
                    return Err(Error::invalid(
                        "Contract package differs from signed manifest",
                    ));
                }
                if field.is_empty() && value["side_effect"] != cap["side_effect"] {
                    return Err(Error::invalid("Contract side effects differ"));
                }
                checks.push_str(&format!("{file} {}\n", &digest(&bytes)[7..]));
            }
            if digest(checks.as_bytes()) != cap["contract"]["schema_digest"] {
                return Err(Error::invalid("Contract package digest differs"));
            }
        }
        Ok(Self {
            image: image.to_owned(),
            manifest_digest: digest(&raw),
            manifest,
            raw,
            image_digest: image_digest.to_owned(),
            http_contract,
        })
    }
    pub fn validate_deployment(&self, spec: &Value) -> Result<()> {
        validate("DeploymentSpec", spec)?;
        if spec["replicas"].as_u64().unwrap_or(1) != 1 {
            return Err(Error::invalid("This runtime profile requires one replica"));
        }
        for field in ["cpu_millis", "memory_bytes", "ephemeral_bytes", "pids"] {
            if spec["limits"][field].as_u64() < self.manifest["minimum_resources"][field].as_u64() {
                return Err(Error::invalid(
                    "Deployment limits are below the signed minimum",
                ));
            }
        }
        validate_business(&self.manifest["config_schema"], &spec["config"])
    }
}

fn installation_image(request: &Value) -> Result<(&str, &str)> {
    validate("InstallRequest", request)?;
    let image = string(request, "image")?;
    Ok((image, image_ref(image)?))
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_reference_profiles_match_manifest_and_raw_contracts() {
        let root = tempfile::tempdir().unwrap();
        let builder =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/echo/build_artifact.py");
        let platform = if cfg!(target_arch = "aarch64") {
            "linux/arm64"
        } else {
            "linux/amd64"
        };
        let variants: &[(&str, &[&str], bool)] = &[
            ("rust-default", &[], false),
            ("rust-upgrade", &["--plugin-version", "2.0.0"], false),
            (
                "rust-failed-upgrade",
                &["--plugin-version", "3.0.0", "--failed-startup"],
                false,
            ),
            ("rust-blob", &["--request-blob"], false),
            (
                "python-secret",
                &["--implementation", "python", "--request-secret"],
                false,
            ),
            (
                "python-host-blob",
                &["--implementation", "python", "--request-blob"],
                false,
            ),
            (
                "python-schema-1",
                &[
                    "--implementation",
                    "python",
                    "--volume-access",
                    "rw",
                    "--data-schema",
                    "1",
                ],
                true,
            ),
            (
                "python-schema-2",
                &[
                    "--implementation",
                    "python",
                    "--volume-access",
                    "rw",
                    "--data-schema",
                    "2",
                    "--plugin-version",
                    "2.0.0",
                ],
                true,
            ),
        ];
        for &(variant, arguments, versioned) in variants {
            let directory = root.path().join(variant);
            let output = std::process::Command::new("python3")
                .arg(&builder)
                .args([
                    "--publisher-id",
                    "00000000-0000-4000-8000-000000000001",
                    "--platform",
                    platform,
                    "--output",
                ])
                .arg(&directory)
                .args(arguments)
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "Reference generator failed for {variant}"
            );
            let bytes = read_image_file(&directory, "xelab/plugin.json", 4 * 1024 * 1024).unwrap();
            let manifest = strict_json(&bytes, 4 * 1024 * 1024).unwrap();
            validate_runtime_profile(&manifest).unwrap_or_else(|error| {
                panic!("Generated {variant} profile failed: {}", error.code)
            });
            assert_eq!(
                validate_profile(&manifest).is_err(),
                versioned,
                "Only versioned-data artifacts retain their public installation gate"
            );
            for capability in manifest["capabilities"].as_array().unwrap() {
                let contract = &capability["contract"];
                let name = contract["name"].as_str().unwrap();
                let version = contract["version"].as_str().unwrap();
                let mut checks = String::new();
                for (file, field) in [
                    ("input.schema.json", "input_schema"),
                    ("output.schema.json", "output_schema"),
                    ("stream.schema.json", "stream_item_schema"),
                    ("semantics.json", ""),
                ] {
                    let bytes = read_image_file(
                        &directory,
                        &format!("xelab/contracts/{name}/{version}/{file}"),
                        1024 * 1024,
                    )
                    .unwrap();
                    let value = strict_json(&bytes, 1024 * 1024).unwrap();
                    if field.is_empty() {
                        assert_eq!(value["side_effect"], capability["side_effect"]);
                    } else {
                        assert_eq!(value, capability[field]);
                    }
                    checks.push_str(&format!("{file} {}\n", &digest(&bytes)[7..]));
                }
                assert_eq!(contract["schema_digest"], digest(checks.as_bytes()));
            }
            if variant.starts_with("rust-") {
                let capabilities = manifest["capabilities"].as_array().unwrap();
                assert_eq!(capabilities.len(), 6);
                let health_query = capabilities.last().unwrap();
                assert_eq!(
                    health_query["contract"]["name"],
                    format!("{}.queryable", manifest["plugin_id"].as_str().unwrap())
                );
                assert_eq!(health_query["contract"]["version"], "1.0.1");
                assert_eq!(health_query["side_effect"], "queryable");
                let effect = capabilities
                    .iter()
                    .find(|cap| cap["side_effect"] == "non_repeatable")
                    .unwrap();
                assert!(effect["contract"]["name"]
                    .as_str()
                    .unwrap()
                    .ends_with(".non-repeatable"));
                assert!(!effect["stream_item_schema"].is_null());
            }
        }
    }

    #[test]
    fn ordinary_streaming_profiles_keep_side_effects_and_local_schemas() {
        let mut manifest: Value =
            serde_json::from_str(include_str!("../tests/fixtures/secret-manifest.json")).unwrap();
        manifest["requested_rules"] = json!([]);
        manifest["capabilities"][0]["stream_item_schema"] = json!({"type":"string"});
        for side_effect in ["none", "idempotent", "queryable", "non_repeatable"] {
            manifest["capabilities"][0]["side_effect"] = json!(side_effect);
            validate_profile(&manifest).unwrap();
        }
        let mut referenced = manifest.clone();
        referenced["capabilities"][0]["stream_item_schema"] =
            json!({"$ref":"https://example.invalid/item.json"});
        assert!(validate_profile(&referenced).is_err());
        manifest["data_schema_version"] = json!("1");
        manifest["volumes"] = json!([{"name":"data","mount_path":"/data","access":"rw","scope":"deployment","minimum_bytes":1048576}]);
        manifest["capabilities"][0]["side_effect"] = json!("idempotent");
        validate_runtime_profile(&manifest).unwrap();
        assert!(validate_profile(&manifest).is_err());
        for side_effect in ["queryable", "non_repeatable", "non_idempotent"] {
            manifest["capabilities"][0]["side_effect"] = json!(side_effect);
            assert!(validate_runtime_profile(&manifest).is_err());
        }
    }
    #[test]
    fn versioned_execution_profile_keeps_public_installation_closed() {
        let mut manifest: Value =
            serde_json::from_str(include_str!("../tests/fixtures/secret-manifest.json")).unwrap();
        manifest["requested_rules"] = json!([]);
        manifest["data_schema_version"] = json!("1");
        manifest["capabilities"][0]["side_effect"] = json!("idempotent");
        manifest["volumes"] = json!([{"name":"data","mount_path":"/data","access":"rw","scope":"deployment","minimum_bytes":1048576}]);
        validate_runtime_profile(&manifest).unwrap();
        assert!(validate_profile(&manifest).is_err());
        for variant in [
            "no_volumes",
            "read_only",
            "scratch",
            "parallel",
            "proxy",
            "non_idempotent",
            "invalid_schema",
        ] {
            let mut wrong = manifest.clone();
            match variant {
                "no_volumes" => wrong["volumes"] = json!([]),
                "read_only" => wrong["volumes"][0]["access"] = json!("ro"),
                "scratch" => wrong["volumes"][0]["mount_path"] = json!("/xelab-migration/nested"),
                "parallel" => wrong["upgrade_strategy"] = json!("parallel_compatible"),
                "proxy" => {
                    wrong["requested_rules"] = json!([{"rule":{"action":"secret.use","resource":{"kind":"secret","match":"all"}},"required":false}])
                }
                "non_idempotent" => {
                    wrong["capabilities"][0]["side_effect"] = json!("non_idempotent")
                }
                "invalid_schema" => wrong["data_schema_version"] = json!("a\nb"),
                _ => unreachable!(),
            }
            assert!(validate_runtime_profile(&wrong).is_err(), "{variant}");
        }
    }

    #[test]
    fn optional_secret_requests_use_the_manifest_permission_request_contract() {
        let manifest: Value =
            serde_json::from_str(include_str!("../tests/fixtures/secret-manifest.json")).unwrap();
        validate_profile(&manifest).unwrap();
        let mut required = manifest.clone();
        required["requested_rules"][0]["required"] = json!(true);
        assert!(
            validate_profile(&required).is_err(),
            "required requests cannot bypass explicit binding readiness"
        );
        let mut malformed = manifest.clone();
        malformed["requested_rules"][0] = manifest["requested_rules"][0]["rule"].clone();
        assert!(validate_profile(&malformed).is_err());
        let mut broader = manifest.clone();
        broader["requested_rules"][0]["rule"]["action"] = json!("blob.read");
        assert!(validate_profile(&broader).is_err());
    }

    use super::*;
    use serde_json::json;
    #[test]
    fn only_fixed_safe_image_names_are_accepted() {
        assert!(image_ref(&format!("example.org/a@sha256:{}", "a".repeat(64))).is_ok());
        for s in [
            "example.org/a:latest",
            "--help",
            "a,b@sha256:1",
            "a@sha256:ABC",
        ] {
            assert!(image_ref(s).is_err());
        }
    }
    #[test]
    fn envelope_preserves_raw_manifest_bytes_and_final_newline() {
        let m = json!({"publisher_id":uuid::Uuid::nil(),"plugin_id":"org.xelab.echo","version":"1.0.0"});
        let e = signature_envelope(&m, "sha256:abc", b"{}\n").unwrap();
        assert!(e.ends_with('\n'));
        assert!(e.contains(&digest(b"{}\n")));
        assert!(!e.contains(&digest(b"{}")));
    }
    #[test]
    fn image_reader_rejects_symlink_escape() {
        let d = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("xelab")).unwrap();
        assert!(read_image_file(d.path(), "xelab/passwd", 1024).is_err());
        assert!(read_image_file(d.path(), "../passwd", 1024).is_err());
    }
}
