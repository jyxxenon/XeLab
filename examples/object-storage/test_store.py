from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import multiprocessing
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import threading
import unittest
import uuid

from model import Call, MAX_CHUNK_BYTES, MAX_OBJECT_BYTES, StoreError, digest
from store import Limits, Store


def identifier():
    return str(uuid.uuid4())


def call(owner, key=None):
    return Call(owner, identifier(), key or identifier())


def put_request(key, data, expected=None):
    result = {
        "key": key, "blob_id": identifier(), "size_bytes": len(data),
        "digest": digest(data), "content_type": "text/plain; charset=utf-8",
        "mode": "create" if expected is None else "replace",
    }
    if expected is not None:
        result["expected_revision"] = expected
    return result


def chunks(data):
    for offset in range(0, len(data), MAX_CHUNK_BYTES):
        yield offset, data[offset:offset + MAX_CHUNK_BYTES]


def check():
    pass


def reject_io(*_):
    raise AssertionError("This operation must not transfer bytes")


def crash_put(volume, identity, request, data, now):
    with Store(volume, "deployment-1", clock=lambda: now) as store:
        # put has fsynced the renamed file and holds its write transaction
        # when it reaches publication. No rollback handler runs on exit.
        store._publish_put = lambda *_: os._exit(73)
        store.put(identity, request, lambda _: chunks(data), check)


def crash_export(volume, receipt, identity, request, now):
    with Store(volume, "deployment-1", clock=lambda: now) as store:
        def accepted(_, data):
            # A separate receipt represents a transport that accepted every
            # byte, followed by a lost result before the local transaction.
            Path(receipt).write_bytes(b"".join(part for _, part in data))
            os._exit(74)

        store.export(identity, request, accepted, check)


class ObjectStorage(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.volume = Path(temporary.name) / "objects"
        self.volume.mkdir()
        self.owner = identifier()
        self.other = identifier()
        self.now = 1700000000.0
        self.open()

    def open(self, limits=Limits(), scope="deployment-1"):
        self.store = Store(self.volume, scope, limits, clock=lambda: self.now)
        self.addCleanup(self.store.close)

    def error(self, code, function, *args):
        with self.assertRaises(StoreError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def put(self, name, data, *, owner=None, expected=None):
        return self.store.put(
            call(owner or self.owner), put_request(name, data, expected),
            lambda _: chunks(data), check,
        )["object"]

    def object_files(self):
        return list(self.volume.glob("users/*/content/*"))

    def process_exit(self, worker, code, *args):
        process = multiprocessing.get_context("spawn").Process(target=worker, args=args)
        process.start()
        process.join(15)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail("Object storage crash fixture did not reach its exit point")
        self.assertEqual(process.exitcode, code)
        process.close()

    def test_subjects_have_separate_keys_and_usage(self):
        left = self.put("reports/a.txt", b"left")
        self.error("RESOURCE_NOT_FOUND", self.store.stat, self.other, {"key": left["key"]})
        revision = {"key": left["key"], "expected_revision": left["revision"]}
        self.error("RESOURCE_NOT_FOUND", self.store.delete, call(self.other), revision, check)
        self.error("RESOURCE_NOT_FOUND", self.store.export, call(self.other), revision, reject_io, check)
        right = self.put(left["key"], b"right-side", owner=self.other)
        self.assertNotEqual(left["id"], right["id"])
        self.assertEqual(self.store.stat(self.owner, {"key": left["key"]}), {"object": left})
        self.assertEqual(self.store.list(self.other, {}), {"items": [right], "next_cursor": None})
        self.assertEqual(self.store.usage(self.owner, {})["logical_bytes"], 4)
        self.assertEqual(self.store.usage(self.other, {})["logical_bytes"], 10)
        self.error("INVALID_ARGUMENT", self.store.stat, self.owner,
                   {"key": left["key"], "owner_id": self.other})
        self.assertEqual({p.parent.parent.name for p in self.object_files()}, {self.owner, self.other})

    def test_revision_and_business_result_survive_restart_and_delete(self):
        request = put_request("notes/plan.txt", b"one")
        original = call(self.owner, "create")
        first = self.store.put(original, request, lambda _: chunks(b"one"), check)
        replaced = self.put(request["key"], b"two", expected=1)
        self.assertEqual(replaced["id"], first["object"]["id"])
        self.assertEqual(replaced["created_at"], first["object"]["created_at"])
        self.assertEqual(replaced["revision"], 2)
        removal = call(self.owner, "delete")
        delete = {"key": request["key"], "expected_revision": 2}
        deleted = self.store.delete(removal, delete, check)
        self.assertEqual(deleted, {"object_id": replaced["id"], "deleted_revision": 3})
        self.store.close()
        self.open()
        replay = call(self.owner, "create")
        self.assertEqual(self.store.put(replay, request, reject_io, check), first)
        self.assertEqual(self.store.query_result(original), ("succeeded", first))
        self.assertEqual(self.store.query_result(replay), ("succeeded", first))
        self.assertEqual(self.store.query_result(Call(self.other, replay.call_id, "create")), ("unknown", None))
        self.assertEqual(self.store.query_result(Call(self.owner, replay.call_id, "other")), ("unknown", None))
        self.assertEqual(self.store.delete(call(self.owner, "delete"), delete, check), deleted)
        self.error("STATE_CONFLICT", self.store.put, call(self.owner, "create"),
                   {**request, "content_type": "text/html"}, reject_io, check)
        recreated = self.put(request["key"], b"")
        self.assertEqual(recreated["revision"], 4)
        self.assertNotEqual(recreated["id"], replaced["id"])
        self.assertEqual(recreated["size_bytes"], 0)
        self.error("STATE_CONFLICT", self.store.delete, call(self.owner), delete, check)
        self.error("STATE_CONFLICT", self.store.export, call(self.owner), delete, reject_io, check)
        self.assertEqual(self.store.usage(self.owner, {})["object_count"], 1)

    def test_bad_blob_stream_releases_reservations(self):
        cases = (
            ([(1, b"abc")], b"abc"),
            ([(0, b"abcd")], b"abc"),
            ([(0, b"axc")], b"abc"),
            ([], b"abc"),
            ([(0, b"x" * (MAX_CHUNK_BYTES + 1))], b"x" * (MAX_CHUNK_BYTES + 1)),
        )
        for stream, data in cases:
            with self.subTest(size=len(data), frames=len(stream)):
                request = put_request("failed", data)
                self.error("INVALID_ARGUMENT", self.store.put, call(self.owner), request,
                           lambda _: iter(stream), check)
                self.assertEqual(self.store.usage(self.owner, {})["reserved_bytes"], 0)
                self.assertEqual(self.store.list(self.owner, {})["items"], [])
                self.assertEqual(self.object_files(), [])
        self.assertEqual(self.put("failed", b"abc")["size_bytes"], 3)

    def test_maximum_object_uses_bounded_frames(self):
        data = b"x" * MAX_CHUNK_BYTES
        sha = hashlib.sha256()
        for _ in range(MAX_OBJECT_BYTES // len(data)):
            sha.update(data)
        request = {
            **put_request("limit", b""), "size_bytes": MAX_OBJECT_BYTES,
            "digest": "sha256:" + sha.hexdigest(),
        }
        self.error("INVALID_ARGUMENT", self.store.put, call(self.owner),
                   {**request, "size_bytes": MAX_OBJECT_BYTES + 1}, reject_io, check)
        stored = self.store.put(
            call(self.owner), request,
            lambda _: ((offset, data) for offset in range(0, MAX_OBJECT_BYTES, len(data))),
            check,
        )["object"]
        self.assertEqual(stored["size_bytes"], MAX_OBJECT_BYTES)
        blob = identifier()

        def export(value, frames):
            size = 0
            for offset, part in frames:
                self.assertEqual(offset, size)
                self.assertEqual(part, data)
                size += len(part)
            self.assertEqual(size, MAX_OBJECT_BYTES)
            return {"blob_id": blob, "size_bytes": size, "digest": value["digest"]}

        result = self.store.export(
            call(self.owner), {"key": "limit", "expected_revision": 1}, export, check,
        )
        self.assertEqual((result["blob_id"], result["digest"]), (blob, request["digest"]))

    def test_key_validation_and_literal_percent_encoding(self):
        for key in ("", "/a", "a/", "a//b", "a/../b", "a/./b", "a\\b", "a\u0000b",
                    "a\u007fb", "e\u0301", "字" * 342):
            with self.subTest(key=key):
                self.error("INVALID_ARGUMENT", self.store.put, call(self.owner),
                           put_request(key, b""), reject_io, check)
        literal = self.put("a%2Fb", b"x")
        self.assertEqual(literal["key"], "a%2Fb")
        file, = self.object_files()
        self.assertEqual(file.name, str(uuid.UUID(file.stem)) + ".blob")

    def test_integral_json_numbers_preserve_the_same_business_request(self):
        request = put_request("number", b"x")
        first = self.store.put(
            call(self.owner, "create"), {**request, "size_bytes": 1.0}, lambda _: chunks(b"x"), check,
        )
        self.assertEqual(self.store.put(call(self.owner, "create"), request, reject_io, check), first)
        self.error("INVALID_ARGUMENT", self.store.put, call(self.owner),
                   {**request, "size_bytes": 1.5}, reject_io, check)

    def test_concurrent_replace_locks_head_and_reserves_logical_delta(self):
        self.store.close()
        self.open(Limits(quota_bytes=10, max_objects=2))
        old = self.put("file", b"1234")
        arrived, release = threading.Event(), threading.Event()
        request = put_request("file", b"12345678", expected=old["revision"])

        def reader(_):
            arrived.set()
            if not release.wait(10):
                raise RuntimeError("Test did not release the active writer")
            return chunks(b"12345678")

        with ThreadPoolExecutor(max_workers=1) as pool:
            writer = pool.submit(self.store.put, call(self.owner), request, reader, check)
            try:
                self.assertTrue(arrived.wait(10))
                self.assertEqual(self.store.usage(self.owner, {})["reserved_bytes"], 4)
                self.assertEqual(self.store.stat(self.owner, {"key": "file"})["object"], old)
                self.error("STATE_CONFLICT", self.store.put, call(self.owner), request, reject_io, check)
                self.error("STATE_CONFLICT", self.store.delete, call(self.owner),
                           {"key": "file", "expected_revision": 1}, check)
                self.error("RESOURCE_EXHAUSTED", self.store.put, call(self.owner),
                           put_request("another", b"abc"), reject_io, check)
                self.assertEqual(self.put("file", b"12345678", owner=self.other)["revision"], 1)
            finally:
                release.set()
            self.assertEqual(writer.result(timeout=10)["object"]["revision"], 2)
        usage = self.store.usage(self.owner, {})
        self.assertEqual((usage["logical_bytes"], usage["reserved_bytes"]), (8, 0))
        self.put("another", b"")
        self.error("RESOURCE_EXHAUSTED", self.store.put, call(self.owner),
                   put_request("third", b""), reject_io, check)
        self.store.close()
        self.open(Limits(quota_bytes=100))
        self.assertEqual(self.store.usage(self.owner, {})["quota_bytes"], 10)
        self.assertEqual(self.store.usage(identifier(), {})["quota_bytes"], 100)

    def test_deployment_budget_applies_before_reader(self):
        self.store.close()
        self.open(Limits(storage_budget_bytes=1024 * 1024))
        request = put_request("too-big", b"x" * (1024 * 1024))
        self.error("RESOURCE_EXHAUSTED", self.store.put, call(self.owner), request, reject_io, check)
        self.assertEqual(self.store.usage(self.owner, {})["reserved_bytes"], 0)
        self.assertEqual(self.object_files(), [])

    def test_deployment_budget_includes_wal_retained_by_a_reader(self):
        self.store.close()
        budget = 768 * 1024
        self.open(Limits(storage_budget_bytes=budget))
        with closing(sqlite3.connect(self.volume / "objects.sqlite3")) as reader:
            reader.execute("BEGIN")
            reader.execute("SELECT count(*) FROM os_metadata").fetchone()
            for index in range(100):
                try:
                    self.put(f"empty/{index}", b"")
                except StoreError as error:
                    self.assertEqual(error.code, "RESOURCE_EXHAUSTED")
                    self.assertGreater(index, 0)
                    break
                metadata = sum(path.stat().st_size for path in self.volume.glob("objects.sqlite3*"))
                self.assertLessEqual(metadata, budget)
            else:
                self.fail("The pinned WAL never hit the deployment budget")
        self.assertEqual(self.put("after-checkpoint", b"")["revision"], 1)

    def test_cancelled_copy_keeps_old_revision_and_releases_reservation(self):
        previous = self.put("file", b"old")
        identity = call(self.owner, "replace")
        request = put_request("file", b"new", expected=previous["revision"])
        cancelled = threading.Event()

        def reader(_):
            yield 0, b"new"
            cancelled.set()

        def checkpoint():
            if cancelled.is_set():
                raise StoreError("CANCELED", "Fixture cancelled the import")

        self.error("CANCELED", self.store.put, identity, request, reader, checkpoint)
        self.assertEqual(self.store.stat(self.owner, {"key": "file"})["object"], previous)
        self.assertEqual(self.store.usage(self.owner, {})["reserved_bytes"], 0)
        self.assertEqual(len(self.object_files()), 1)
        self.assertEqual(self.store.put(identity, request, lambda _: chunks(b"new"), check)["object"]["revision"], 2)

    def test_cursor_is_bound_and_uses_utf8_keyset_with_original_expiry(self):
        for name in ("x/字", "x/a", "x/z", "x/é", "y/a"):
            self.put(name, b"")
        query = {"prefix": "x/", "limit": 1}
        page = self.store.list(self.owner, query)
        self.assertEqual([item["key"] for item in page["items"]], ["x/a"])
        cursor = page["next_cursor"]
        self.error("STATE_CONFLICT", self.store.list, self.other, {**query, "cursor": cursor})
        self.error("STATE_CONFLICT", self.store.list, self.owner, {**query, "limit": 2, "cursor": cursor})
        self.now += 899
        next_page = self.store.list(self.owner, {**query, "cursor": cursor})
        self.assertEqual([item["key"] for item in next_page["items"]], ["x/z"])
        self.now += 1
        self.error("STATE_CONFLICT", self.store.list, self.owner,
                   {**query, "cursor": next_page["next_cursor"]})
        fresh = self.store.list(self.owner, query)["next_cursor"]
        self.store.close()
        self.open(scope="deployment-2")
        self.error("STATE_CONFLICT", self.store.list, self.owner, {**query, "cursor": fresh})

    def test_pinned_export_survives_delete_and_replays_the_same_blob(self):
        data = b"abc" * MAX_CHUNK_BYTES
        obj = self.put("file", data)
        export = call(self.owner, "export")
        request = {"key": "file", "expected_revision": obj["revision"]}
        started, release = threading.Event(), threading.Event()
        blob = identifier()

        def write(value, frames):
            started.set()
            if not release.wait(10):
                raise RuntimeError("Test did not release the exporter")
            offset = 0
            for position, part in frames:
                self.assertEqual(position, offset)
                self.assertLessEqual(len(part), MAX_CHUNK_BYTES)
                self.assertEqual(part, data[offset:offset + len(part)])
                offset += len(part)
            self.assertEqual(offset, len(data))
            return {"blob_id": blob, "size_bytes": offset, "digest": value["digest"]}

        with ThreadPoolExecutor(max_workers=1) as pool:
            writer = pool.submit(self.store.export, export, request, write, check)
            try:
                self.assertTrue(started.wait(10))
                self.store.delete(call(self.owner), request, check)
                self.assertEqual(self.store.collect_garbage(), 0)
                self.assertEqual(len(self.object_files()), 1)
            finally:
                release.set()
            result = writer.result(timeout=10)
        self.assertEqual(result["blob_id"], blob)
        self.assertEqual(result["digest"], digest(data))
        self.assertEqual(self.store.collect_garbage(), 1)
        self.assertEqual(self.object_files(), [])
        self.assertEqual(self.store.export(call(self.owner, "export"), request, reject_io, check), result)

    def test_damaged_content_never_reaches_the_blob_writer(self):
        self.put("file", b"abc")
        self.object_files()[0].write_bytes(b"abd")
        request = {"key": "file", "expected_revision": 1}
        self.error("INTERNAL", self.store.export, call(self.owner), request, reject_io, check)
        self.assertEqual(self.store.usage(self.owner, {})["logical_bytes"], 3)

    def test_exit_after_content_rename_releases_only_the_unpublished_reservation(self):
        live = self.put("old", b"live")
        self.store.close()
        identity = call(self.owner, "crash-put")
        request = put_request("new", b"uncommitted")
        self.process_exit(crash_put, 73, self.volume, identity, request, b"uncommitted", self.now)
        self.assertEqual(len(self.object_files()), 2)
        with closing(sqlite3.connect(self.volume / "objects.sqlite3")) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM os_write_reservations").fetchone()[0], 1)
        self.open()
        self.assertEqual(len(self.object_files()), 1)
        self.assertEqual(self.store.stat(self.owner, {"key": "old"}), {"object": live})
        self.error("RESOURCE_NOT_FOUND", self.store.stat, self.owner, {"key": "new"})
        self.assertEqual(self.store.usage(self.owner, {})["reserved_bytes"], 0)
        value = self.store.put(identity, request, lambda _: chunks(b"uncommitted"), check)
        self.assertEqual(value["object"]["revision"], 1)

    def test_exit_after_export_is_unknown_and_same_key_cannot_write_again(self):
        self.put("file", b"delivered bytes")
        self.store.close()
        identity = call(self.owner, "crash-export")
        request = {"key": "file", "expected_revision": 1}
        receipt = self.volume.parent / "blob-receipt"
        self.process_exit(crash_export, 74, self.volume, receipt, identity, request, self.now)
        self.assertEqual(receipt.read_bytes(), b"delivered bytes")
        self.open()
        self.assertEqual(self.store.query_result(identity), ("unknown", None))
        self.error("OUTCOME_UNKNOWN", self.store.export, identity, request, reject_io, check)
        self.store.delete(call(self.owner), request, check)
        self.assertEqual(self.store.collect_garbage(), 1)

    def test_volume_lock_prevents_recovery_from_releasing_a_live_reservation(self):
        self.error("STATE_CONFLICT", Store, self.volume, "other")
        self.assertEqual(self.put("file", b"ok")["revision"], 1)


if __name__ == "__main__":
    unittest.main()
