#!/usr/bin/env python3
"""Run the same mTLS gRPC client against the Rust and C++ Echo executables."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = "00000000-0000-4000-8000-000000000001"
INSTANCE = "00000000-0000-4000-8000-000000000003"
DEPLOYMENT = "00000000-0000-4000-8000-000000000004"
KERNEL_NAME = "kernel.xelab.local"
KERNEL_URI = "spiffe://xelab.local/kernel"
INSTANCE_NAME = f"i-{INSTANCE}-g-1.xelab.local"
INSTANCE_URI = f"spiffe://xelab.local/instance/{INSTANCE}/generation/1"


def openssl(*args):
    result = subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError("OpenSSL failed to generate a local SDK test identity")


def generate_identities(root):
    identity = root / "identity"
    identity.mkdir(mode=0o700)
    for name in ("ca", "foreign-ca"):
        openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-days", "1", "-subj", f"/CN=XeLab SDK {name}", "-keyout", root / f"{name}.key",
                "-out", root / f"{name}.crt", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    (identity / "ca.crt").write_bytes((root / "ca.crt").read_bytes())
    leaves = [
        ("tls", INSTANCE_NAME, INSTANCE_URI, "ca"),
        ("kernel", KERNEL_NAME, KERNEL_URI, "ca"),
        ("foreign", INSTANCE_NAME, INSTANCE_URI, "ca"),
        ("untrusted", KERNEL_NAME, KERNEL_URI, "foreign-ca"),
        ("wrong-dns", "other.xelab.local", KERNEL_URI, "ca"),
        ("wrong-uri", KERNEL_NAME, INSTANCE_URI, "ca"),
    ]
    for serial, (name, dns, uri, issuer) in enumerate(leaves, 1):
        csr = root / f"{name}.csr"
        extension = root / f"{name}.ext"
        extension.write_text(f"subjectAltName=DNS:{dns},URI:{uri}\nextendedKeyUsage=serverAuth,clientAuth\n")
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-subj", f"/CN={dns}", "-keyout", identity / f"{name}.key", "-out", csr)
        openssl("x509", "-req", "-in", csr, "-CA", root / f"{issuer}.crt", "-CAkey", root / f"{issuer}.key",
                "-set_serial", str(serial), "-days", "1", "-extfile", extension, "-out", identity / f"{name}.crt")
    return identity


def generate_artifacts(root):
    artifacts = {name: root / name for name in ("rust", "cpp")}
    for name, directory in artifacts.items():
        subprocess.run([sys.executable, ROOT / "examples/echo/build_artifact.py", "--publisher-id", PUBLISHER,
                        "--implementation", name, "--output", directory], check=True, timeout=10)
    contracts = {}
    for name, directory in artifacts.items():
        manifest = json.loads((directory / "xelab/plugin.json").read_bytes())
        contracts[name] = {entry["contract"]["name"]: entry["contract"] for entry in manifest["capabilities"]}
    for name in ("org.xelab.echo", "org.xelab.echo.stream"):
        if contracts["rust"][name] != contracts["cpp"][name]:
            raise RuntimeError("The Rust and C++ Echo contract references differ")
        relative = Path("xelab/contracts") / name / contracts["cpp"][name]["version"]
        for file in ("input.schema.json", "output.schema.json", "stream.schema.json", "semantics.json"):
            if (artifacts["rust"] / relative / file).read_bytes() != (artifacts["cpp"] / relative / file).read_bytes():
                raise RuntimeError("The Rust and C++ Echo contract bytes differ")
    return artifacts


def bubblewrap(mounts, environment, command):
    invocation = ["bwrap", "--clearenv", "--unshare-user", "--unshare-net", "--unshare-pid",
                  "--die-with-parent", "--ro-bind", "/usr", "/usr", "--dev", "/dev",
                  "--proc", "/proc", "--tmpfs", "/tmp", "--chdir", "/"]
    for name in ("/bin", "/lib", "/lib64"):
        path = Path(name)
        if path.is_symlink():
            invocation.extend(("--symlink", path.readlink(), path))
        elif path.is_dir():
            invocation.extend(("--ro-bind", path, path))
    for source, target in mounts:
        invocation.extend(("--ro-bind", source, target))
    for key, value in environment.items():
        invocation.extend(("--setenv", key, value))
    return [*invocation, "--", *command]


def docker(image, mounts, environment, command):
    invocation = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
                  "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777"]
    for source, target in mounts:
        invocation.extend(("--mount", f"type=bind,source={source},target={target},readonly"))
    for key, value in environment.items():
        invocation.extend(("--env", f"{key}={value}"))
    return [*invocation, "--entrypoint", "/usr/bin/timeout", image,
            "--kill-after=2s", "25s", *command]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--cpp", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--library-dir", type=Path, help="Shared libraries for an SDK built in a local prefix")
    parser.add_argument("--container-image", help="Local SDK runtime image to run with Docker network isolation")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="xelab-sdk-") as directory:
        root = Path(directory)
        identity = generate_identities(root)
        artifacts = generate_artifacts(root)
        mounts = [(identity, "/identity"), (args.client.resolve(strict=True), "/test/client")]
        environment = {
            "XELAB_GENERATION": "1",
            "XELAB_INSTANCE_ID": INSTANCE,
            "XELAB_DEPLOYMENT_ID": DEPLOYMENT,
            "XELAB_TLS_CERT_PATH": "/identity/tls.crt",
            "XELAB_TLS_KEY_PATH": "/identity/tls.key",
            "XELAB_TLS_CA_PATH": "/identity/ca.crt",
        }
        if args.library_dir:
            mounts.append((args.library_dir.resolve(strict=True), "/test/lib"))
            environment["LD_LIBRARY_PATH"] = "/test/lib"

        def run(command, extra_mounts=()):
            all_mounts = [*mounts, *extra_mounts]
            invocation = (docker(args.container_image, all_mounts, environment, command)
                          if args.container_image else bubblewrap(all_mounts, environment, command))
            subprocess.run(invocation, check=True, timeout=30)

        for name, executable in (("rust", args.rust), ("cpp", args.cpp)):
            run(("/bin/sh", "-c", "/test/echo & child=$!\ntrap 'kill \"$child\" 2>/dev/null || true' EXIT\n/test/client"),
                ((artifacts[name] / "xelab", "/xelab"), (executable.resolve(strict=True), "/test/echo")))
        run(("/test/client", "host"))


if __name__ == "__main__":
    main()
