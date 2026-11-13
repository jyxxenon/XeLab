use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use xelab_kernel::contracts::digest;

const PUBLISHER: &str = "00000000-0000-4000-8000-000000000001";

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

struct Fixture {
    directory: tempfile::TempDir,
    manifest: Value,
    request: Value,
}

impl Fixture {
    fn new(example: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let script = examples().join(example).join("build_artifact.py");
        assert!(Command::new("python3")
            .arg(script)
            .args(["--publisher-id", PUBLISHER, "--output"])
            .arg(directory.path().join("staged"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .status()
            .unwrap()
            .success());
        let raw = fs::read(directory.path().join("staged/xelab/plugin.json")).unwrap();
        let manifest: Value = serde_json::from_slice(&raw).unwrap();
        let image_digest = format!("sha256:{}", "a".repeat(64));
        let key = directory.path().join("publisher.key");
        assert!(Command::new("openssl")
            .args(["genpkey", "-algorithm", "Ed25519", "-out"])
            .arg(&key)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&key)
            .args(["-pubout", "-out"])
            .arg(directory.path().join("publisher.pem"))
            .status()
            .unwrap()
            .success());
        let image = format!("example.invalid/xelab/{example}@{image_digest}");
        let request = Self::sign(directory.path(), &image);
        Self {
            directory,
            manifest,
            request,
        }
    }

    fn sign(directory: &Path, image: &str) -> Value {
        let output = Command::new("python3")
            .arg(examples().join("echo/sign_artifact.py"))
            .arg("--manifest")
            .arg(directory.join("staged/xelab/plugin.json"))
            .args(["--image", image])
            .arg("--key")
            .arg(directory.join("publisher.key"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn member(&self, path: &str) -> PathBuf {
        self.directory.path().join("staged/xelab").join(path)
    }

    fn run(&self) -> Output {
        let request = self.directory.path().join("install.json");
        fs::write(&request, serde_json::to_vec(&self.request).unwrap()).unwrap();
        Command::new(env!("CARGO_BIN_EXE_xelabctl"))
            .arg("validate-artifact")
            .arg("--artifact-root")
            .arg(self.directory.path().join("staged"))
            .arg("--install-request")
            .arg(request)
            .arg("--publisher-key")
            .arg(self.directory.path().join("publisher.pem"))
            .output()
            .unwrap()
    }

    fn rejects(&self, message: &str) {
        let output = self.run();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(message), "{stderr}");
    }
}

#[test]
fn validates_staged_signed_rpc_and_http_packages_without_a_runtime() {
    for example in ["echo", "http"] {
        let fixture = Fixture::new(example);
        let output = fixture.run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({
                "artifact_files": "valid",
                "publisher_id": PUBLISHER,
                "plugin_id": fixture.manifest["plugin_id"],
                "version": fixture.manifest["version"],
                "manifest_digest": digest(&fs::read(fixture.member("plugin.json")).unwrap()),
                "signed_image_digest": format!("sha256:{}", "a".repeat(64)),
                "image_content_verified": false,
            })
        );
    }
}

#[test]
fn rejects_publisher_or_image_mismatch_and_changed_manifest_bytes() {
    let mut fixture = Fixture::new("echo");
    let request = fixture.request.clone();
    fixture.request["publisher_id"] = json!("00000000-0000-4000-8000-000000000002");
    fixture.rejects("Publisher does not match the signed manifest");
    fixture.request = request.clone();
    fixture.request["image"] = json!(format!(
        "example.invalid/xelab/echo@sha256:{}",
        "b".repeat(64)
    ));
    fixture.rejects("Artifact signature verification failed");
    fixture.request = request;
    let manifest = fixture.member("plugin.json");
    let mut bytes = fs::read(&manifest).unwrap();
    bytes.extend_from_slice(b"\n");
    fs::write(manifest, bytes).unwrap();
    fixture.rejects("Artifact signature verification failed");
}

#[test]
fn rejects_unknown_install_request_and_signed_manifest_fields() {
    let mut fixture = Fixture::new("echo");
    fixture.request["unknown"] = json!(true);
    fixture.rejects("Value does not match the existing contract");

    fixture.manifest["unknown"] = json!(true);
    fs::write(
        fixture.member("plugin.json"),
        serde_json::to_vec(&fixture.manifest).unwrap(),
    )
    .unwrap();
    fixture.request = Fixture::sign(
        fixture.directory.path(),
        fixture.request["image"].as_str().unwrap(),
    );
    fixture.rejects("Value does not match the existing contract");
}

#[test]
fn rejects_rpc_and_http_contract_member_digest_mismatches() {
    let rpc = Fixture::new("echo");
    let contract = &rpc.manifest["capabilities"][0]["contract"];
    let input = rpc.member(&format!(
        "contracts/{}/{}/input.schema.json",
        contract["name"].as_str().unwrap(),
        contract["version"].as_str().unwrap(),
    ));
    let mut bytes = fs::read(&input).unwrap();
    bytes.extend_from_slice(b"\n");
    fs::write(input, bytes).unwrap();
    rpc.rejects("Contract package digest differs");

    let http = Fixture::new("http");
    let openapi = http.member("http/openapi.json");
    let mut bytes = fs::read(&openapi).unwrap();
    bytes.extend_from_slice(b"\n");
    fs::write(openapi, bytes).unwrap();
    http.rejects("digest differs");
}
