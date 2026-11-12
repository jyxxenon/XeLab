"""Explicit tests for an isolated, host-provisioned XFS project mount."""

import json
import os
from pathlib import Path
import subprocess

import grpc
from xelab.v1 import lifecycle_pb2 as life
from xelab.v1 import migration_pb2 as mig

from test_rpc import ObjectRpc, identifier
from volume import mounted_capacity


class ObjectXfs(ObjectRpc):
    def data_volume(self):
        self.assertEqual(os.environ.get("XELAB_OBJECT_TEST_XFS"), "1")
        return Path("/data/objects")

    def start_plugin(self):
        manifest = json.loads(self.manifest_path.read_bytes())
        environment = {
            **os.environ,
            "XELAB_PLUGIN_ID": manifest["plugin_id"],
            "XELAB_PLUGIN_VERSION": manifest["version"],
            "XELAB_DEPLOYMENT_ID": self.deployment,
            "XELAB_INSTANCE_ID": self.instance,
            "XELAB_GENERATION": str(self.generation),
            "XELAB_HOST_RPC_ENDPOINT": self.host_address,
            "XELAB_TLS_CERT_PATH": str(self.plugin_tls.cert),
            "XELAB_TLS_KEY_PATH": str(self.plugin_tls.key),
            "XELAB_TLS_CA_PATH": str(self.plugin_tls.ca),
            "XELAB_PLUGIN_RPC_LISTEN": "0.0.0.0:7000",
        }
        diagnostics = self.root / "entrypoint.log"
        with diagnostics.open("wb") as output:
            self.process = subprocess.Popen(
                ["/usr/local/bin/plugin"], env=environment, stdout=output,
                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            )
        self.connect_plugin("127.0.0.1:7000")
        try:
            grpc.channel_ready_future(self.channel).result(timeout=6)
        except grpc.FutureTimeoutError:
            self.fail("Object storage entrypoint failed to start: " + diagnostics.read_text()[-1500:])

    def stop_plugin(self):
        process = getattr(self, "process", None)
        if process is None:
            return
        if hasattr(self, "channel"):
            self.channel.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.process = None

    def test_write_on_project_volume(self):
        self.assertEqual(mounted_capacity(self.volume, True), 20 * 1024**3)
        self.assertEqual(list(self.volume.iterdir()), [])
        self.assertTrue(self.lifecycle.Initialize(self.initialize(), timeout=5).initialized)
        data = b"project-volume contents"
        created = self.output(self.put("project-smoke", data))
        self.assertEqual(created["object"]["revision"], 1)
        blob, = self.volume.glob("users/*/content/*.blob")
        self.assertEqual(blob.read_bytes(), data)

    def test_verify_on_read_only_project_volume(self):
        self.assertEqual(mounted_capacity(self.volume, False), 20 * 1024**3)
        operation = identifier()
        plan = self.migration.Plan(mig.PlanMigrationRequest(
            context=self.context(self.owner, operation + ":plan"), deployment_id=self.deployment,
            source_schema="1", target_schema="1",
        ), timeout=5)
        self.assertFalse(plan.requires_exclusive_write)
        result = self.migration.Verify(mig.VerifyMigrationRequest(
            context=self.context(self.owner, operation + ":verify"), plan_id=plan.plan_id, volume_fence=1,
        ), timeout=5)
        self.assertEqual((result.succeeded, result.observed_schema), (True, "1"))
        self.refused(self.lifecycle.Initialize, self.initialize(), grpc.StatusCode.FAILED_PRECONDITION)
        health = self.lifecycle.GetHealth(life.HealthRequest(context=self.context()), timeout=5)
        self.assertFalse(any(entry.ready for entry in health.capabilities))

    def test_refuses_an_undersized_project_volume(self):
        self.assertEqual(mounted_capacity(self.volume, True), 1024**3)
        self.refused(self.lifecycle.Initialize, self.initialize(), grpc.StatusCode.FAILED_PRECONDITION)
        blob, = self.volume.glob("users/*/content/*.blob")
        self.assertEqual(blob.read_bytes(), b"project-volume contents")
