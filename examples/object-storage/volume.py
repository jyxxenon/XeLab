"""Inspect the kernel-bound XFS project and verify the persisted format."""

from contextlib import closing, suppress
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import struct

from model import MAX_CHUNK_BYTES, canonical_uuid, conflict


_FSXATTR = struct.Struct("=5I8x")
# Linux uapi/linux/fs.h. This ioctl reads the existing project assignment.
_FS_IOC_FSGETXATTR = (2 << 30) | (_FSXATTR.size << 16) | (ord("X") << 8) | 31
_FS_XFLAG_PROJINHERIT = 0x00000200


def mounted_capacity(volume, writable):
    candidates = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        before, after = line.split(" - ", 1)
        fields, filesystem = before.split(), after.split()
        if fields[4] == str(volume):
            candidates.append((fields[5].split(","), filesystem[0], filesystem[2].split(",")))
    mode = "rw" if writable else "ro"
    if len(candidates) != 1:
        raise conflict("Object data requires a distinct volume mount")
    options, filesystem, super_options = candidates[0]
    if (
        mode not in options or filesystem != "xfs"
        or not {"prjquota", "pquota"}.intersection(super_options)
    ):
        raise conflict("Object volume has the wrong mount mode or project quota")
    fd = os.open(volume, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        attrs = _FSXATTR.unpack(fcntl.ioctl(fd, _FS_IOC_FSGETXATTR, bytes(_FSXATTR.size)))
        if not attrs[0] & _FS_XFLAG_PROJINHERIT or attrs[3] == 0:
            raise conflict("Object volume lacks an inherited XFS project")
        # XFS bounds statfs by the enforced project quota on a PROJINHERIT inode.
        # https://github.com/torvalds/linux/blob/master/fs/xfs/xfs_super.c
        volume_stats = os.fstatvfs(fd)
        return volume_stats.f_blocks * volume_stats.f_frsize
    finally:
        os.close(fd)


def _regular(path):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise conflict("Object volume contains an invalid format file")
    return info


def _verify_contents(conn, volume, check):
    usage = conn.execute(
        "SELECT physical_content_bytes,reserved_physical_bytes FROM os_storage_usage"
    ).fetchone()
    recorded = conn.execute(
        "SELECT coalesce(sum(size_bytes),0) FROM os_contents WHERE state IN ('committed','garbage')"
    ).fetchone()[0]
    secret = conn.execute("SELECT value FROM os_metadata WHERE key='cursor_key'").fetchone()
    if (
        conn.execute("PRAGMA integrity_check(1)").fetchone() != ("ok",)
        or conn.execute("PRAGMA foreign_key_check").fetchone() is not None
        or usage != (recorded, 0) or secret is None or len(bytes.fromhex(secret[0])) != 32
        or conn.execute(
            "SELECT EXISTS(SELECT 1 FROM os_write_reservations) "
            "OR EXISTS(SELECT 1 FROM os_read_pins) "
            "OR EXISTS(SELECT 1 FROM os_contents WHERE state='staging') "
            "OR EXISTS(SELECT 1 FROM os_operations WHERE state='running')"
        ).fetchone()[0]
    ):
        raise conflict("Object volume is inconsistent or still has active operations")
    inconsistent = conn.execute(
        "SELECT 1 FROM os_users u LEFT JOIN os_heads h ON h.owner_id=u.owner_id AND h.state='live' "
        "LEFT JOIN os_contents c ON c.owner_id=h.owner_id AND c.id=h.content_id GROUP BY u.owner_id "
        "HAVING u.object_count<>count(h.object_id) OR u.logical_bytes<>coalesce(sum(c.size_bytes),0) "
        "OR u.reserved_bytes<>0 OR u.reserved_objects<>0 "
        "OR u.logical_bytes>u.quota_bytes OR u.object_count>u.max_objects LIMIT 1"
    ).fetchone()
    if inconsistent:
        raise conflict("Object volume quota ledger differs from its live heads")
    for owner, content, size, digest, state in conn.execute(
        "SELECT c.owner_id,c.id,c.size_bytes,c.digest,c.state FROM os_heads h "
        "JOIN os_contents c ON c.owner_id=h.owner_id AND c.id=h.content_id WHERE h.state='live'"
    ):
        check()
        owner_directory = volume / "users" / canonical_uuid(owner)
        directory = owner_directory / "content"
        if state != "committed" or any(
            not stat.S_ISDIR(path.stat(follow_symlinks=False).st_mode)
            for path in (volume / "users", owner_directory, directory)
        ):
            raise conflict("Object content is outside its committed layout")
        path = directory / (canonical_uuid(content) + ".blob")
        _regular(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            if os.fstat(source.fileno()).st_size != size:
                raise conflict("Object volume contains an incorrect content size")
            sha = hashlib.sha256()
            while data := source.read(MAX_CHUNK_BYTES):
                check()
                sha.update(data)
            if digest != "sha256:" + sha.hexdigest():
                raise conflict("Object volume contains an incorrect content digest")


def observe_format(volume, check, *, verify=False):
    """Read a frozen volume without creating a database, WAL or lock file."""
    check()
    if not any(volume.iterdir()):
        return "none"
    database = volume / "objects.sqlite3"
    _regular(database)
    lock = volume / ".object-storage.lock"
    _regular(lock)
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise conflict("Object volume still has an active writer") from None
        # The controller freezes the volume and the lock excludes Store.
        # Open an existing WAL through SQLite's regular read-only path so
        # Verify sees committed frames beyond the last main-file checkpoint.
        # https://www.sqlite.org/wal.html#read_only_databases
        wal = database.with_name(database.name + "-wal")
        shm = database.with_name(database.name + "-shm")
        has_wal = False
        with suppress(FileNotFoundError):
            has_wal = _regular(wal).st_size > 0
        if has_wal:
            try:
                _regular(shm)
            except FileNotFoundError:
                raise conflict("Frozen object volume lacks its WAL index") from None
        uri = database.as_uri() + ("?mode=ro" if has_wal else "?mode=ro&immutable=1")
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            conn.execute("PRAGMA query_only=ON")

            def progress():
                try:
                    check()
                except Exception:
                    return 1
                return 0

            conn.set_progress_handler(progress, 1024)
            try:
                version = conn.execute(
                    "SELECT value FROM os_metadata WHERE key='data_schema_version'"
                ).fetchone()
                if version != ("1",):
                    raise conflict("Unsupported object volume format")
                if verify:
                    _verify_contents(conn, volume, check)
            except sqlite3.Error:
                check()
                raise conflict("Object volume format cannot be read") from None
        return "1"
    finally:
        os.close(fd)
