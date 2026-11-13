#!/usr/bin/env python3
"""Build the signed manifest/contract inputs; image signing happens after import."""
import argparse
import hashlib
import json
import pathlib
import uuid


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def build(root, publisher, platform="linux/amd64", implementation="rust", request_secret=False, volume_access=None, request_blob=False, plugin_version="1.0.0", failed_startup=False, data_schema=None, migration_fail_after_write=False, migration_pause_after_initialize=False, migration_observe_apply=False):
    if data_schema not in (None, "1", "2"):
        raise ValueError("Unsupported reference business schema")
    if data_schema is not None and (implementation != "python" or volume_access != "rw" or request_blob or request_secret):
        raise ValueError("The reference business schema requires Python and its dedicated writable data volume")
    if migration_fail_after_write and data_schema != "2":
        raise ValueError("The migration outcome fault requires the explicit version 2 business format")
    if migration_pause_after_initialize and (data_schema != "1" or failed_startup):
        raise ValueError("The initialization crash probe requires the explicit version 1 business format")
    if migration_observe_apply and (data_schema is None or failed_startup):
        raise ValueError("The Apply observer requires an explicit business format")
    if implementation == "cpp" and (request_secret or request_blob or volume_access):
        raise ValueError("The C++ reference supports only the ordinary Echo capabilities")
    publisher = str(uuid.UUID(publisher))
    schema = {"type": "object", "properties": {"message": {"type": "string", "maxLength": 1024}}, "required": ["message"], "additionalProperties": False}
    input_schema = json.loads(json.dumps(schema))
    output_schema = json.loads(json.dumps(schema))
    name, version = ("org.xelab.echo-blobs" if request_blob else "org.xelab.echo"), "1.0.0"
    if data_schema is not None:
        name = "org.xelab.migrating-store"
    side_effect = "idempotent" if data_schema is not None else "none"
    if request_blob:
        input_schema["properties"].update({"blob_id": {"type": "string", "format": "uuid", "x-xelab-resource-kind": "blob"}, "export": {"type": "boolean"}})
        output_schema["properties"].update({"source_digest": {"type": "string", "maxLength": 71}, "blob": {"type": "object", "properties": {"blob_id": {"type": "string", "format": "uuid"}, "size_bytes": {"type": "integer", "minimum": 0, "maximum": 67108864}, "digest": {"type": "string", "maxLength": 71}}, "required": ["blob_id", "size_bytes", "digest"], "additionalProperties": False}})
    directory = root / "xelab" / "contracts" / name / version
    directory.mkdir(parents=True, exist_ok=True)
    checks = []
    for file, value in [("input.schema.json", input_schema), ("output.schema.json", output_schema), ("stream.schema.json", None), ("semantics.json", {"side_effect": side_effect})]:
        raw = encoded(value)
        (directory / file).write_bytes(raw)
        checks.append(f"{file} {hashlib.sha256(raw).hexdigest()}\n")
    contract = {"name": name, "version": version, "schema_digest": "sha256:" + hashlib.sha256("".join(checks).encode()).hexdigest()}
    plugin_id, entrypoint = {
        "rust": (name, ["/usr/local/bin/xelab-echo"]),
        "python": (name if data_schema is not None else "org.xelab.echo-python", ["/usr/bin/python3", "/opt/plugin/server.py"]),
        "cpp": ("org.xelab.echo-cpp", ["/usr/local/bin/xelab-echo-cpp"]),
    }[implementation]
    manifest = {
        "manifest_version": "1", "plugin_id": plugin_id, "version": plugin_version,
        "publisher_id": publisher, "host_api_major": 1, "platforms": [platform],
        "entrypoint": entrypoint,
        "capabilities": [{"contract": contract, "input_schema": input_schema, "output_schema": output_schema, "stream_item_schema": None, "side_effect": side_effect, "maximum_input_bytes": 65536, "maximum_output_bytes": 65536}],
        "dependencies": [], "requested_rules": [], "volumes": [], "routes": [],
        "minimum_resources": {"cpu_millis": 100, "memory_bytes": 67108864, "ephemeral_bytes": 1048576, "pids": 64},
        "health": {"startup_timeout_ms": 60000, "interval_ms": 5000, "timeout_ms": 2000, "failure_threshold": 3},
        "config_schema": {"type": "object", "additionalProperties": False},
        "data_schema_version": data_schema or "none", "upgrade_strategy": "recreate", "business_entry": "direct",
        "concurrency": {"max_active_requests": 4, "max_queue_requests": 0, "queue_timeout_ms": 100},
    }
    if request_secret:
        manifest["requested_rules"] = [{"rule": {"action": "secret.use", "resource": {"kind": "secret", "match": "all"}}, "required": False}]
    if request_blob:
        manifest["plugin_id"] = "org.xelab.echo-blobs"
        manifest["requested_rules"].extend({"rule": {"action": action, "resource": {"kind": "blob", "match": "all"}}, "required": False} for action in ["blob.read", "blob.create"])
    # A signed ordinary Skill candidate; registration remains an explicit core
    # operation and does not grant users either layer of execution authority.
    manifest["skills"] = [{
        "name": manifest["plugin_id"] + ".echo", "version": plugin_version,
        "description": "Echo a message through the fixed signed OCI artifact",
        "input_schema": input_schema, "output_schema": output_schema,
        "stream_item_schema": None,
        "target": {"kind": "capability", "plugin_id": manifest["plugin_id"], "contract": contract},
        "mapping": "identity", "maximum_timeout_ms": 10000,
        "input_blobs": request_blob, "tags": ["echo"],
    }]
    if implementation in ("rust", "cpp"):
        # A separate signed business contract exercises the actual streaming
        # transport without changing the ordinary echo capability's schemas.
        stream_input = {"type": "object", "properties": {
            "message": {"type": "string", "maxLength": 1024},
            "count": {"type": "integer", "minimum": 1, "maximum": 64},
            "delay_ms": {"type": "integer", "minimum": 0, "maximum": 1000},
            "fault": {"enum": ["none", "call-id", "sequence", "item", "digest", "output", "missing-terminal", "after-terminal"]},
        }, "required": ["message"], "additionalProperties": False}
        stream_output = json.loads(json.dumps(schema))
        stream_item = {"type": "object", "properties": {
            "index": {"type": "integer", "minimum": 0, "maximum": 63},
            "message": {"type": "string", "maxLength": 1024},
        }, "required": ["index", "message"], "additionalProperties": False}
        stream_name = "org.xelab.echo.stream"
        stream_directory = root / "xelab" / "contracts" / stream_name / version
        stream_directory.mkdir(parents=True, exist_ok=True)
        stream_checks = []
        for file, value in [("input.schema.json", stream_input), ("output.schema.json", stream_output), ("stream.schema.json", stream_item), ("semantics.json", {"side_effect": "none"})]:
            raw = encoded(value)
            (stream_directory / file).write_bytes(raw)
            stream_checks.append(f"{file} {hashlib.sha256(raw).hexdigest()}\n")
        stream_contract = {"name": stream_name, "version": version, "schema_digest": "sha256:" + hashlib.sha256("".join(stream_checks).encode()).hexdigest()}
        manifest["capabilities"].append({"contract": stream_contract, "input_schema": stream_input, "output_schema": stream_output, "stream_item_schema": stream_item, "side_effect": "none", "maximum_input_bytes": 65536, "maximum_output_bytes": 65536})
        manifest["skills"].append({
            "name": manifest["plugin_id"] + ".stream", "version": plugin_version,
            "description": "Stream bounded echo items from the fixed signed OCI artifact",
            "input_schema": stream_input, "output_schema": stream_output,
            "stream_item_schema": stream_item,
            "target": {"kind": "capability", "plugin_id": manifest["plugin_id"], "contract": stream_contract},
            "mapping": "identity", "maximum_timeout_ms": 120000,
            "input_blobs": False, "tags": ["echo", "stream"],
        })
    if implementation == "rust":
        # Conservative ordinary side-effect classes use distinct immutable
        # contracts. They share the same bounded unary/stream transport shape,
        # with a real per-generation mutation counter for queryable and
        # non-repeatable execution. No public versioned data profile is opened.
        for effect in ["idempotent", "queryable", "non_repeatable"]:
            # The semantic enum uses an underscore; public capability/Skill
            # names use the existing lowercase dot/hyphen namespace grammar.
            effect_name = manifest["plugin_id"] + "." + effect.replace("_", "-")
            effect_input = json.loads(json.dumps(stream_input))
            effect_input["properties"]["fault"]["enum"].append("after-commit")
            effect_output = json.loads(json.dumps(stream_output))
            if effect != "idempotent":
                effect_output["properties"]["execution_count"] = {"type": "integer", "minimum": 1}
                effect_output["required"].append("execution_count")
            effect_directory = root / "xelab" / "contracts" / effect_name / version
            effect_directory.mkdir(parents=True, exist_ok=True)
            effect_checks = []
            for file, value in [("input.schema.json", effect_input), ("output.schema.json", effect_output), ("stream.schema.json", stream_item), ("semantics.json", {"side_effect": effect})]:
                raw = encoded(value)
                (effect_directory / file).write_bytes(raw)
                effect_checks.append(f"{file} {hashlib.sha256(raw).hexdigest()}\n")
            effect_contract = {"name": effect_name, "version": version, "schema_digest": "sha256:" + hashlib.sha256("".join(effect_checks).encode()).hexdigest()}
            manifest["capabilities"].append({"contract": effect_contract, "input_schema": effect_input, "output_schema": effect_output, "stream_item_schema": stream_item, "side_effect": effect, "maximum_input_bytes": 65536, "maximum_output_bytes": 65536})
            manifest["skills"].append({
                "name": effect_name, "version": plugin_version,
                "description": "Execute the fixed ordinary " + effect + " reference contract without automatic retries",
                "input_schema": effect_input, "output_schema": effect_output,
                "stream_item_schema": stream_item,
                "target": {"kind": "capability", "plugin_id": manifest["plugin_id"], "contract": effect_contract},
                "mapping": "identity", "maximum_timeout_ms": 10000,
                "input_blobs": False, "tags": ["echo", "ordinary-effects"],
            })
        # An additive acceptance contract gives the positive QueryResult case
        # a real post-commit Health observation. Existing 1.0.0 contracts,
        # schemas, Skill definitions and digests remain byte-for-byte unchanged.
        queryable = next(cap for cap in manifest["capabilities"]
                         if cap["contract"]["name"] == manifest["plugin_id"] + ".queryable")
        health_cap = json.loads(json.dumps(queryable))
        health_cap["input_schema"]["properties"]["fault"]["enum"].append("after-commit-health")
        health_directory = root / "xelab" / "contracts" / queryable["contract"]["name"] / "1.0.1"
        health_directory.mkdir(parents=True, exist_ok=True)
        health_checks = []
        for file, value in [("input.schema.json", health_cap["input_schema"]), ("output.schema.json", health_cap["output_schema"]), ("stream.schema.json", health_cap["stream_item_schema"]), ("semantics.json", {"side_effect": "queryable"})]:
            raw = encoded(value)
            (health_directory / file).write_bytes(raw)
            health_checks.append(f"{file} {hashlib.sha256(raw).hexdigest()}\n")
        health_cap["contract"] = {"name": queryable["contract"]["name"], "version": "1.0.1", "schema_digest": "sha256:" + hashlib.sha256("".join(health_checks).encode()).hexdigest()}
        health_skill = json.loads(json.dumps(next(skill for skill in manifest["skills"]
                                                if skill["target"].get("contract") == queryable["contract"])))
        health_skill["name"] += ".health-sync"
        health_skill["description"] = "Lose the committed response after the next real Health probe, then query the original provider"
        health_skill["input_schema"] = health_cap["input_schema"]
        health_skill["target"]["contract"] = health_cap["contract"]
        manifest["capabilities"].append(health_cap)
        manifest["skills"].append(health_skill)
    if volume_access:
        manifest["volumes"] = [{"name": "data", "mount_path": "/data", "access": volume_access, "scope": "deployment", "minimum_bytes": 1048576}]
    if failed_startup:
        manifest["entrypoint"] = ["/bin/false"]
        manifest["health"]["startup_timeout_ms"] = 2000
    if migration_fail_after_write:
        manifest["entrypoint"].append("--migration-fail-after-write")
    if migration_pause_after_initialize:
        manifest["entrypoint"].append("--migration-pause-after-initialize")
    if migration_observe_apply:
        manifest["entrypoint"].append("--migration-observe-apply")
    (root / "xelab" / "plugin.json").write_bytes(encoded(manifest))
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publisher-id", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("examples/generated"))
    parser.add_argument("--platform", choices=["linux/amd64", "linux/arm64"], default="linux/amd64")
    parser.add_argument("--implementation", choices=["rust", "python", "cpp"], default="rust")
    parser.add_argument("--request-secret", action="store_true", help="Enable the explicit Secret lease acceptance probe")
    parser.add_argument("--volume-access", choices=["ro", "rw"], help="Enable explicit persistent-volume acceptance")
    parser.add_argument("--request-blob", action="store_true", help="Enable explicit Blob proxy acceptance with a separate contract")
    parser.add_argument("--plugin-version", choices=["1.0.0", "2.0.0", "3.0.0"], default="1.0.0", help="Plugin release version; existing capability contract versions remain fixed")
    parser.add_argument("--failed-startup", action="store_true", help="Build an explicit failing startup acceptance artifact")
    parser.add_argument("--data-schema", choices=["1", "2"], help="Reference DataMigration format; kernel admission remains disabled until its durable coordinator is complete")
    parser.add_argument("--migration-fail-after-write", action="store_true", help="Explicit acceptance artifact returning an ambiguous RPC outcome after a real committed write")
    parser.add_argument("--migration-pause-after-initialize", action="store_true", help="Explicit crash-test artifact pausing after fsynced initialization and tracing migration phases in private scratch")
    parser.add_argument("--migration-observe-apply", action="store_true", help="Explicit acceptance artifact recording Apply RPC attempts in private scratch")
    args = parser.parse_args()
    build(args.output, args.publisher_id, args.platform, args.implementation, args.request_secret, args.volume_access, args.request_blob, args.plugin_version, args.failed_startup, args.data_schema, args.migration_fail_after_write, args.migration_pause_after_initialize, args.migration_observe_apply)

