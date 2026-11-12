"""Persistent, subject-scoped objects on a single-writer plugin volume."""

from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
import uuid

from model import (
    Cursor, MAX_CHUNK_BYTES, MAX_INTEGER, StoreError, canonical_json, canonical_uuid,
    conflict, digest, digest_string, integer, invalid, logical_key, prefix_end,
    put_request, request_fields, revision,
)


SCHEMA = Path(__file__).resolve().parents[2] / "docs/preset-plugins/object-storage/storage.sql"
_OBJECT_COLUMNS = (
    "h.object_id AS id, h.owner_id, h.logical_key AS key, h.revision, "
    "c.size_bytes, c.digest, h.content_type, h.created_at, h.updated_at"
)


@dataclass(frozen=True, slots=True)
class Limits:
    quota_bytes: int = 1073741824
    max_objects: int = 10000
    storage_budget_bytes: int = 17179869184
    idempotency_ttl_seconds: int = 86400
    cursor_ttl_seconds: int = 900

    def __post_init__(self):
        integer(self.quota_bytes, 0, MAX_INTEGER)
        integer(self.max_objects, 1, MAX_INTEGER)
        integer(self.storage_budget_bytes, 1, MAX_INTEGER)
        integer(self.idempotency_ttl_seconds, 1, 86400)
        integer(self.cursor_ttl_seconds, 1, 900)


def _timestamp(when):
    return datetime.fromtimestamp(when, timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _exhausted():
    return StoreError("RESOURCE_EXHAUSTED", "Object storage quota is exhausted")


def _missing():
    return StoreError("RESOURCE_NOT_FOUND", "Object does not exist")


def _corrupt():
    return StoreError("INTERNAL", "Object storage contents are inconsistent")


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _directory(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        if not stat.S_ISDIR(path.stat(follow_symlinks=False).st_mode):
            raise _corrupt() from None
    else:
        _sync_directory(path.parent)


def _unlink_files(paths):
    for path in paths:
        with suppress(FileNotFoundError):
            path.unlink()
    # Sync even an already absent name. A previous owner may have unlinked
    # it and stopped before flushing the directory entry.
    for parent in {path.parent for path in paths}:
        with suppress(FileNotFoundError):
            _sync_directory(parent)


def _next_revision(current):
    if current >= MAX_INTEGER:
        raise _exhausted()
    return current + 1


class Store:
    def __init__(self, volume, scope, limits=Limits(), *, schema=SCHEMA, clock=time.time):
        self.volume = Path(volume).resolve(strict=True)
        self.database = self.volume / "objects.sqlite3"
        self.users = self.volume / "users"
        self.limits = limits
        self.clock = clock
        lock = self.volume / ".object-storage.lock"
        self.lock_fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise conflict("Object storage volume already has an active writer") from None
            self._initialize(Path(schema), lock)
            _directory(self.users)
            with self._write() as conn:
                conn.execute(
                    "INSERT INTO os_storage_usage VALUES(1,0,0,0) ON CONFLICT DO NOTHING"
                )
                conn.execute(
                    "INSERT INTO os_metadata VALUES('cursor_key',?) ON CONFLICT DO NOTHING",
                    (secrets.token_hex(32),),
                )
                key = bytes.fromhex(conn.execute(
                    "SELECT value FROM os_metadata WHERE key='cursor_key'"
                ).fetchone()[0])
                if len(key) != 32:
                    raise _corrupt()
            self.cursor = Cursor(key, scope, limits.cursor_ttl_seconds)
            self._recover()
            self.collect_garbage()
            with self._write() as conn:
                self._check_budget(conn)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def _initialize(self, schema, lock):
        staging = self.volume / ".object-storage-format.sqlite3"
        stage_files = [staging, staging.with_name(staging.name + "-wal"),
                       staging.with_name(staging.name + "-shm"),
                       staging.with_name(staging.name + "-journal")]
        if not self.database.exists():
            if set(self.volume.iterdir()) - {lock, *stage_files}:
                raise conflict("Cannot initialize a nonempty object storage volume")
            _unlink_files(stage_files)
            # Build the initial layout privately. A crash before publication
            # leaves only disposable formatting files in an otherwise empty volume.
            fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            with self._connection(staging) as conn:
                conn.executescript(schema.read_text(encoding="utf-8"))
                if conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
                    raise _corrupt()
            with staging.open("rb") as source:
                os.fsync(source.fileno())
            os.rename(staging, self.database)
            _sync_directory(self.volume)
        if not stat.S_ISREG(self.database.stat(follow_symlinks=False).st_mode):
            raise _corrupt()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT value FROM os_metadata WHERE key='data_schema_version'"
            ).fetchone()
            if row is None or row[0] != "1":
                raise conflict("Object storage format differs")

    @contextmanager
    def _connection(self, path=None):
        if self.lock_fd is None:
            raise conflict("Object storage volume is closed")
        conn = sqlite3.connect(path or self.database, isolation_level=None, timeout=2.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA cache_spill=OFF")
            conn.execute("PRAGMA wal_autocheckpoint=128")
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _write(self):
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            with conn:
                yield conn

    def _path(self, owner, content, *, pending=False, create=False):
        owner_dir = self.users / canonical_uuid(owner)
        directory = owner_dir / "content"
        if create:
            _directory(owner_dir)
            _directory(directory)
        else:
            for path in (owner_dir, directory):
                with suppress(FileNotFoundError):
                    if not stat.S_ISDIR(path.stat(follow_symlinks=False).st_mode):
                        raise _corrupt()
        return directory / (canonical_uuid(content) + (".pending" if pending else ".blob"))

    def _recover(self):
        # The exclusive volume lock proves no previous writer can still own
        # these reservations or pins. No time-based guess can release a live pin.
        while True:
            with self._connection() as conn:
                rows = conn.execute("SELECT id FROM os_write_reservations LIMIT 32").fetchall()
            if not rows:
                break
            for row in rows:
                self._discard_put(row["id"])
        with self._write() as conn:
            conn.execute("DELETE FROM os_read_pins")
            conn.execute(
                "UPDATE os_operations SET state='unknown', updated_at=? WHERE state='running'",
                (_timestamp(self.clock()),),
            )

    def _usage(self, conn, owner, create=False):
        if create:
            conn.execute(
                "INSERT INTO os_users(owner_id,quota_bytes,max_objects) VALUES(?,?,?) "
                "ON CONFLICT(owner_id) DO NOTHING",
                (owner, self.limits.quota_bytes, self.limits.max_objects),
            )
        return conn.execute("SELECT * FROM os_users WHERE owner_id=?", (owner,)).fetchone()

    def _database_size(self, suffix):
        try:
            return self.database.with_name(self.database.name + suffix).stat().st_size
        except FileNotFoundError:
            return 0

    def _check_budget(self, conn):
        page_count = conn.execute("PRAGMA page_count").fetchone()[0]
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        database = page_count * page_size
        wal = self._database_size("-wal")
        index = self._database_size("-shm")
        # With spilling off, budget a WAL frame per database page plus the
        # repeated commit frames SQLite may use to reach a sector boundary.
        # SQLite's pager caps that sector at 64 KiB. Include the WAL index
        # growth even when an older reader pins the existing WAL.
        # https://www.sqlite.org/fileformat2.html#the_write_ahead_log
        # https://www.sqlite.org/walformat.html#wal_index_hash_tables
        # https://sqlite.org/src/file/src/pager.c
        frame_size = page_size + 24
        padding_frames = (64 * 1024 + frame_size - 1) // frame_size
        wal_peak = max(wal, 32) + (page_count + padding_frames) * frame_size
        frames = (wal_peak - 32 + frame_size - 1) // frame_size
        index_blocks = 1 + (max(frames - 4062, 0) + 4095) // 4096
        metadata_peak = database + wal_peak + max(index, 32768 * index_blocks)
        content, reserved = conn.execute(
            "SELECT physical_content_bytes,reserved_physical_bytes FROM os_storage_usage"
        ).fetchone()
        if metadata_peak + content + reserved > self.limits.storage_budget_bytes:
            raise _exhausted()
        conn.execute(
            "UPDATE os_storage_usage SET measured_metadata_bytes=?", (database + wal + index,),
        )

    def _expire_operations(self, conn, now):
        conn.execute(
            "DELETE FROM os_operations WHERE (owner_id,capability,idempotency_key) IN ("
            "SELECT owner_id,capability,idempotency_key FROM os_operations "
            "WHERE expires_at<=? AND state<>'running' ORDER BY expires_at LIMIT 64)",
            (now,),
        )

    def _start_operation(self, conn, call, capability, request):
        identity = (call.subject, capability, call.idempotency_key)
        fingerprint = digest(canonical_json(request))
        now = self.clock()
        timestamp = _timestamp(now)
        conn.execute(
            "DELETE FROM os_operations WHERE owner_id=? AND capability=? AND idempotency_key=? "
            "AND expires_at<=? AND state<>'running'",
            (*identity, timestamp),
        )
        prior = conn.execute(
            "SELECT input_digest,state,result_json FROM os_operations "
            "WHERE owner_id=? AND capability=? AND idempotency_key=?",
            identity,
        ).fetchone()
        if prior is not None:
            if prior["input_digest"] != fingerprint:
                raise conflict("Idempotency key has a different request")
            if prior["state"] == "unknown":
                raise StoreError("OUTCOME_UNKNOWN", "Previous object operation is unresolved")
            if prior["state"] != "succeeded":
                raise conflict("Object operation is already in progress")
        else:
            conn.execute(
                "INSERT INTO os_operations(owner_id,capability,idempotency_key,input_digest,state,"
                "expires_at,updated_at) VALUES(?,?,?,?,'running',?,?)",
                (*identity, fingerprint, _timestamp(now + self.limits.idempotency_ttl_seconds),
                 timestamp),
            )
        conn.execute(
            "INSERT INTO os_operation_calls(owner_id,call_id,capability,idempotency_key) "
            "VALUES(?,?,?,?) ON CONFLICT(owner_id,call_id) DO NOTHING",
            (call.subject, call.call_id, capability, call.idempotency_key),
        )
        binding = conn.execute(
            "SELECT capability,idempotency_key FROM os_operation_calls WHERE owner_id=? AND call_id=?",
            (call.subject, call.call_id),
        ).fetchone()
        if tuple(binding) != (capability, call.idempotency_key):
            raise conflict("Call already belongs to a different object operation")
        return json.loads(prior["result_json"]) if prior is not None else None

    def _succeed(self, conn, call, capability, result):
        now = self.clock()
        changed = conn.execute(
            "UPDATE os_operations SET state='succeeded',result_json=?,expires_at=?,updated_at=? "
            "WHERE owner_id=? AND capability=? AND idempotency_key=? AND state='running'",
            (canonical_json(result).decode(), _timestamp(now + self.limits.idempotency_ttl_seconds),
             _timestamp(now), call.subject, capability, call.idempotency_key),
        )
        if changed.rowcount != 1:
            raise _corrupt()

    def query_result(self, call):
        """Read the previously committed outcome for this subject, Call and key."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT o.state,o.result_json FROM os_operation_calls a JOIN os_operations o "
                "USING(owner_id,capability,idempotency_key) WHERE a.owner_id=? AND a.call_id=? "
                "AND a.idempotency_key=? AND (o.expires_at>? OR o.state='running')",
                (call.subject, call.call_id, call.idempotency_key, _timestamp(self.clock())),
            ).fetchone()
        if row is None:
            return "unknown", None
        return row["state"], json.loads(row["result_json"]) if row["result_json"] else None

    def _head(self, conn, owner, key):
        return conn.execute(
            "SELECT h.*,coalesce(c.size_bytes,0) AS size_bytes FROM os_heads h "
            "LEFT JOIN os_contents c ON c.id=h.content_id AND c.owner_id=h.owner_id "
            "WHERE h.owner_id=? AND h.logical_key=?",
            (owner, key),
        ).fetchone()

    def _object(self, conn, owner, key):
        row = conn.execute(
            f"SELECT {_OBJECT_COLUMNS},c.id AS content_id FROM os_heads h "
            "JOIN os_contents c ON c.id=h.content_id AND c.owner_id=h.owner_id "
            "WHERE h.owner_id=? AND h.logical_key=? AND h.state='live'",
            (owner, key),
        ).fetchone()
        if row is None:
            raise _missing()
        value = dict(row)
        content_id = value.pop("content_id")
        return value, content_id

    def stat(self, subject, request):
        canonical_uuid(subject)
        request_fields(request, ("key",))
        with self._connection() as conn:
            value, _ = self._object(conn, subject, logical_key(request["key"]))
        return {"object": value}

    def usage(self, subject, request):
        canonical_uuid(subject)
        request_fields(request, ())
        with self._connection() as conn:
            row = self._usage(conn, subject)
        if row is None:
            return {"owner_id": subject, "logical_bytes": 0, "reserved_bytes": 0,
                    "object_count": 0, "quota_bytes": self.limits.quota_bytes,
                    "max_objects": self.limits.max_objects}
        fields = ("owner_id", "logical_bytes", "reserved_bytes", "object_count",
                  "quota_bytes", "max_objects")
        return {field: row[field] for field in fields}

    def list(self, subject, request):
        canonical_uuid(subject)
        request_fields(request, (), ("prefix", "limit", "cursor"))
        prefix = logical_key(request.get("prefix", ""), prefix=True)
        limit = integer(request.get("limit", 50), 1, 200)
        now = int(self.clock())
        binding = self.cursor.binding(subject, prefix, limit)
        last, expires = "", now + self.cursor.ttl
        if "cursor" in request:
            last, expires = self.cursor.decode(request["cursor"], binding, now)
        upper = prefix_end(prefix)
        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT {_OBJECT_COLUMNS} FROM os_heads h "
                "JOIN os_contents c ON c.id=h.content_id AND c.owner_id=h.owner_id "
                "WHERE h.owner_id=? AND h.state='live' AND h.logical_key>=? AND h.logical_key>? "
                "AND (? IS NULL OR h.logical_key<?) ORDER BY h.logical_key LIMIT ?",
                (subject, prefix, last, upper, upper, limit + 1),
            ).fetchall()
        items = [dict(row) for row in rows[:limit]]
        next_cursor = self.cursor.encode(binding, items[-1]["key"], expires) if len(rows) > limit else None
        return {"items": items, "next_cursor": next_cursor}

    def _require_idle_head(self, conn, owner, key):
        if conn.execute(
            "SELECT 1 FROM os_write_reservations WHERE owner_id=? AND logical_key=?",
            (owner, key),
        ).fetchone():
            raise conflict("Object has a write in progress")

    def _reserve_put(self, conn, call, request, content):
        owner, key = call.subject, request["key"]
        self._require_idle_head(conn, owner, key)
        head = self._head(conn, owner, key)
        live = head is not None and head["state"] == "live"
        if request["mode"] == "create":
            if live:
                raise conflict("Object already exists")
        elif not live:
            raise _missing()
        elif head["revision"] != request["expected_revision"]:
            raise conflict("Object revision differs")
        current = head["revision"] if head else 0
        _next_revision(current)
        size = request["size_bytes"]
        increase = max(0, size - (head["size_bytes"] if live else 0))
        slots = int(not live)
        user = self._usage(conn, owner, create=True)
        if (
            user["logical_bytes"] + user["reserved_bytes"] + increase > user["quota_bytes"]
            or user["object_count"] + user["reserved_objects"] + slots > user["max_objects"]
        ):
            raise _exhausted()
        conn.execute(
            "INSERT INTO os_write_reservations(id,owner_id,logical_key,expected_head_revision,"
            "logical_reserved_bytes,physical_reserved_bytes,object_slots,idempotency_key,input_digest,"
            "state,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'copying',?)",
            (content, owner, key, current, increase, size, slots, call.idempotency_key,
             digest(canonical_json(request)), _timestamp(self.clock())),
        )
        conn.execute(
            "UPDATE os_users SET reserved_bytes=reserved_bytes+?,reserved_objects=reserved_objects+? "
            "WHERE owner_id=?",
            (increase, slots, owner),
        )
        conn.execute(
            "UPDATE os_storage_usage SET reserved_physical_bytes=reserved_physical_bytes+?",
            (size,),
        )
        self._check_budget(conn)

    def _release_reservation(self, conn, row):
        conn.execute(
            "UPDATE os_users SET reserved_bytes=reserved_bytes-?,reserved_objects=reserved_objects-? "
            "WHERE owner_id=?",
            (row["logical_reserved_bytes"], row["object_slots"], row["owner_id"]),
        )
        conn.execute(
            "UPDATE os_storage_usage SET reserved_physical_bytes=reserved_physical_bytes-?",
            (row["physical_reserved_bytes"],),
        )
        conn.execute("DELETE FROM os_write_reservations WHERE id=?", (row["id"],))

    def _discard_put(self, content):
        with self._write() as conn:
            row = conn.execute(
                "SELECT * FROM os_write_reservations WHERE id=?", (content,),
            ).fetchone()
            if row is None:
                # The final transaction removed the reservation. Its content may
                # already be published even if the caller saw a commit error.
                return
            owner = row["owner_id"]
            _unlink_files([self._path(owner, content), self._path(owner, content, pending=True)])
            self._release_reservation(conn, row)
            conn.execute(
                "DELETE FROM os_operations WHERE owner_id=? AND capability='data.object.put' "
                "AND idempotency_key=? AND state='running'",
                (owner, row["idempotency_key"]),
            )

    def _copy_blob(self, pending, request, reader, check):
        offset = 0
        sha = hashlib.sha256()
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as target:
            check()
            for position, data in reader(request["blob_id"]):
                check()
                if (
                    type(position) is not int or position != offset
                    or not isinstance(data, bytes) or not 1 <= len(data) <= MAX_CHUNK_BYTES
                    or offset + len(data) > request["size_bytes"]
                ):
                    raise invalid("Blob stream does not match the declared size or offsets")
                target.write(data)
                sha.update(data)
                offset += len(data)
            if offset != request["size_bytes"] or "sha256:" + sha.hexdigest() != request["digest"]:
                raise invalid("Blob content does not match the declared size and digest")
            target.flush()
            os.fsync(target.fileno())

    def _retire(self, conn, owner, content):
        changed = conn.execute(
            "UPDATE os_contents SET state='garbage',reference_count=0 "
            "WHERE owner_id=? AND id=? AND state='committed' AND reference_count=1",
            (owner, content),
        )
        if changed.rowcount != 1:
            raise _corrupt()

    def _publish_put(self, conn, call, request, content):
        reservation = conn.execute(
            "SELECT * FROM os_write_reservations WHERE id=?", (content,),
        ).fetchone()
        owner, key = call.subject, request["key"]
        if reservation is None or reservation["owner_id"] != owner:
            raise _corrupt()
        head = self._head(conn, owner, key)
        current = head["revision"] if head else 0
        if current != reservation["expected_head_revision"]:
            raise conflict("Object revision differs")
        live = head is not None and head["state"] == "live"
        now = _timestamp(self.clock())
        object_id = head["object_id"] if live else str(uuid.uuid4())
        created_at = head["created_at"] if live else now
        size = request["size_bytes"]
        conn.execute(
            "INSERT INTO os_contents(id,owner_id,private_file_key,size_bytes,digest,state,"
            "reference_count,created_at) VALUES(?,?,?,?,?,'committed',1,?)",
            (content, owner, f"{owner}/content/{content}.blob", size, request["digest"], now),
        )
        conn.execute(
            "INSERT INTO os_heads(owner_id,logical_key,revision,state,object_id,content_id,"
            "content_type,created_at,updated_at) VALUES(?,?,?,'live',?,?,?,?,?) "
            "ON CONFLICT(owner_id,logical_key) DO UPDATE SET revision=excluded.revision,"
            "state=excluded.state,object_id=excluded.object_id,content_id=excluded.content_id,"
            "content_type=excluded.content_type,created_at=excluded.created_at,updated_at=excluded.updated_at",
            (owner, key, _next_revision(current), object_id, content, request["content_type"],
             created_at, now),
        )
        if live:
            self._retire(conn, owner, head["content_id"])
        conn.execute(
            "UPDATE os_users SET logical_bytes=logical_bytes+?,object_count=object_count+? WHERE owner_id=?",
            (size - (head["size_bytes"] if live else 0), reservation["object_slots"], owner),
        )
        conn.execute(
            "UPDATE os_storage_usage SET physical_content_bytes=physical_content_bytes+?", (size,),
        )
        self._release_reservation(conn, reservation)
        value, _ = self._object(conn, owner, key)
        result = {"object": value}
        self._succeed(conn, call, "data.object.put", result)
        self._check_budget(conn)
        return result

    def put(self, call, request, reader, check):
        """Copy an authorized Blob iterator of (offset, bytes) into the volume."""
        request = put_request(request)
        check()
        self.collect_garbage()
        content = str(uuid.uuid4())
        try:
            with self._write() as conn:
                result = self._start_operation(conn, call, "data.object.put", request)
                if result is not None:
                    self._check_budget(conn)
                    return result
                self._reserve_put(conn, call, request, content)
            pending = self._path(call.subject, content, pending=True, create=True)
            self._copy_blob(pending, request, reader, check)
            check()
            os.rename(pending, self._path(call.subject, content))
            _sync_directory(pending.parent)
            with self._write() as conn:
                check()
                return self._publish_put(conn, call, request, content)
        except BaseException:
            # If recovery cannot yet inspect the ledger, keep the reservation
            # and let the next exclusive owner reconcile it.
            with suppress(OSError, sqlite3.Error, StoreError):
                self._discard_put(content)
            raise

    def delete(self, call, request, check):
        request_fields(request, ("key", "expected_revision"))
        owner, key = call.subject, logical_key(request["key"])
        expected = revision(request["expected_revision"])
        request = {"key": key, "expected_revision": expected}
        with self._write() as conn:
            check()
            result = self._start_operation(conn, call, "data.object.delete", request)
            if result is not None:
                self._check_budget(conn)
                return result
            self._require_idle_head(conn, owner, key)
            value, content = self._object(conn, owner, key)
            if value["revision"] != expected:
                raise conflict("Object revision differs")
            deleted = _next_revision(expected)
            conn.execute(
                "UPDATE os_heads SET revision=?,state='deleted',object_id=NULL,content_id=NULL,"
                "content_type=NULL,updated_at=? WHERE owner_id=? AND logical_key=?",
                (deleted, _timestamp(self.clock()), owner, key),
            )
            self._retire(conn, owner, content)
            conn.execute(
                "UPDATE os_users SET logical_bytes=logical_bytes-?,object_count=object_count-1 "
                "WHERE owner_id=?",
                (value["size_bytes"], owner),
            )
            result = {"object_id": value["id"], "deleted_revision": deleted}
            self._succeed(conn, call, "data.object.delete", result)
            self._check_budget(conn)
            check()
            return result

    def _read_content(self, source, value, check):
        sha = hashlib.sha256()
        offset = 0
        while True:
            check()
            data = source.read(MAX_CHUNK_BYTES)
            if not data:
                break
            if offset + len(data) > value["size_bytes"]:
                raise _corrupt()
            sha.update(data)
            yield offset, data
            offset += len(data)
        if offset != value["size_bytes"] or "sha256:" + sha.hexdigest() != value["digest"]:
            raise _corrupt()

    def _unwind_export(self, call, pin, dispatched):
        operation = (call.subject, call.idempotency_key)
        with self._write() as conn:
            if conn.execute("DELETE FROM os_read_pins WHERE id=?", (pin,)).rowcount != 1:
                return
            if dispatched:
                conn.execute(
                    "UPDATE os_operations SET state='unknown',updated_at=? "
                    "WHERE owner_id=? AND capability='data.object.export' AND idempotency_key=? "
                    "AND state='running'",
                    (_timestamp(self.clock()), *operation),
                )
            else:
                conn.execute(
                    "DELETE FROM os_operations WHERE owner_id=? AND capability='data.object.export' "
                    "AND idempotency_key=? AND state='running'",
                    operation,
                )

    def export(self, call, request, writer, check):
        """Pin a revision while the authorized Blob writer consumes its bytes."""
        request_fields(request, ("key", "expected_revision"))
        owner, key = call.subject, logical_key(request["key"])
        expected = revision(request["expected_revision"])
        request = {"key": key, "expected_revision": expected}
        pin = str(uuid.uuid4())
        dispatched = False
        try:
            with self._write() as conn:
                check()
                result = self._start_operation(conn, call, "data.object.export", request)
                if result is not None:
                    self._check_budget(conn)
                    return result
                value, content = self._object(conn, owner, key)
                if value["revision"] != expected:
                    raise conflict("Object revision differs")
                conn.execute(
                    "INSERT INTO os_read_pins(id,content_id,call_id,expires_at) VALUES(?,?,?,?)",
                    (pin, content, call.call_id, _timestamp(self.clock() + self.limits.idempotency_ttl_seconds)),
                )
                self._check_budget(conn)
            path = self._path(owner, content)
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                raise _corrupt() from None
            with os.fdopen(fd, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise _corrupt()
                for _ in self._read_content(source, value, check):
                    pass
                source.seek(0)
                # The writer must consume the whole body; no incomplete
                # transport reply can become a successful export.
                chunks = self._read_content(source, value, check)
                dispatched = True
                reference = writer(dict(value), chunks)
                if next(chunks, None) is not None:
                    raise _corrupt()
            request_fields(reference, ("blob_id", "size_bytes", "digest"))
            if (
                integer(reference["size_bytes"], 0, value["size_bytes"]) != value["size_bytes"]
                or digest_string(reference["digest"]) != value["digest"]
            ):
                raise _corrupt()
            result = {
                "object_id": value["id"], "revision": expected,
                "blob_id": canonical_uuid(reference["blob_id"]), "size_bytes": value["size_bytes"],
                "digest": value["digest"], "content_type": value["content_type"],
            }
            with self._write() as conn:
                self._succeed(conn, call, "data.object.export", result)
                conn.execute("DELETE FROM os_read_pins WHERE id=?", (pin,))
                self._check_budget(conn)
            return result
        except BaseException:
            with suppress(OSError, sqlite3.Error, StoreError):
                self._unwind_export(call, pin, dispatched)
            raise

    def collect_garbage(self):
        """Release only durably unreferenced files, in a bounded transaction."""
        with self._write() as conn:
            rows = conn.execute(
                "SELECT id,owner_id,size_bytes FROM os_contents c WHERE state='garbage' "
                "AND reference_count=0 AND NOT EXISTS(SELECT 1 FROM os_heads WHERE content_id=c.id) "
                "AND NOT EXISTS(SELECT 1 FROM os_read_pins WHERE content_id=c.id) "
                "ORDER BY id LIMIT 32",
            ).fetchall()
            _unlink_files([self._path(row["owner_id"], row["id"]) for row in rows])
            conn.executemany("DELETE FROM os_contents WHERE id=?", [(row["id"],) for row in rows])
            if rows:
                conn.execute(
                    "UPDATE os_storage_usage SET physical_content_bytes=physical_content_bytes-?",
                    (sum(row["size_bytes"] for row in rows),),
                )
            self._expire_operations(conn, _timestamp(self.clock()))
            return len(rows)
