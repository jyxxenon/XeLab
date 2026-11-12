"""Materialize the signed object storage manifest and its unchanged contracts."""

import argparse
import json
from pathlib import Path

from model import canonical_uuid, digest


SPEC = Path(__file__).resolve().parents[2] / "docs/preset-plugins/object-storage"
FILES = ("input.schema.json", "output.schema.json", "stream.schema.json", "semantics.json")


def build(output, publisher, platform, *, disable_queue=False):
    manifest = json.loads((SPEC / "manifest.json").read_bytes())
    manifest["publisher_id"] = canonical_uuid(publisher)
    if platform not in manifest["platforms"]:
        raise ValueError("Platform is absent from the object storage manifest")
    manifest["platforms"] = [platform]
    if disable_queue:
        manifest["concurrency"]["max_queue_requests"] = 0
    root = output / "xelab"
    root.mkdir(parents=True, exist_ok=True)
    for definition in manifest["skills"]:
        suffix = definition["name"].rsplit(".", 1)[1]
        reference = definition["target"]["contract"]
        capability, = (item for item in manifest["capabilities"] if item["contract"] == reference)
        source = SPEC / "contracts" / suffix
        files = {name: (source / name).read_bytes() for name in FILES}
        check = "".join(f"{name} {digest(raw)[7:]}\n" for name, raw in files.items()).encode()
        if digest(check) != reference["schema_digest"]:
            raise ValueError("Raw object contract files differ from the declared digest")
        for name, field in zip(FILES[:3], ("input_schema", "output_schema", "stream_item_schema")):
            if json.loads(files[name]) != capability[field]:
                raise ValueError("Object schemas differ from the signed contract")
        if json.loads(files["semantics.json"])["side_effect"] != capability["side_effect"]:
            raise ValueError("Object side effects differ from the signed contract")
        directory = root / "contracts" / reference["name"] / reference["version"]
        directory.mkdir(parents=True, exist_ok=True)
        for name, raw in files.items():
            (directory / name).write_bytes(raw)
    (root / "plugin.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publisher-id", required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), default="linux/amd64")
    parser.add_argument("--output", type=Path, default=Path("examples/object-storage/generated"))
    parser.add_argument("--disable-queue", action="store_true",
                        help="Build a separate fixture for the kernel's current zero-queue profile")
    args = parser.parse_args()
    build(args.output, args.publisher_id, args.platform, disable_queue=args.disable_queue)


if __name__ == "__main__":
    main()
