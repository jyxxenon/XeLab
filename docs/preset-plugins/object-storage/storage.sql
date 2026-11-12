-- Initial object storage layout for data_schema_version=1, SQLite 3.37+.
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
BEGIN;
CREATE TABLE os_users (
  owner_id TEXT PRIMARY KEY NOT NULL,
  quota_bytes INTEGER NOT NULL CHECK(quota_bytes>=0), max_objects INTEGER NOT NULL CHECK(max_objects>0),
  logical_bytes INTEGER NOT NULL DEFAULT 0 CHECK(logical_bytes>=0), reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0),
  object_count INTEGER NOT NULL DEFAULT 0 CHECK(object_count>=0), reserved_objects INTEGER NOT NULL DEFAULT 0 CHECK(reserved_objects>=0)
) STRICT;
CREATE TABLE os_contents (
  id TEXT PRIMARY KEY NOT NULL, owner_id TEXT NOT NULL REFERENCES os_users(owner_id), private_file_key TEXT NOT NULL UNIQUE,
  size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 67108864), digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('staging','committed','garbage')),
  reference_count INTEGER NOT NULL DEFAULT 0 CHECK(reference_count>=0), created_at TEXT NOT NULL,
  UNIQUE(owner_id,id)
) STRICT;
CREATE TABLE os_heads (
  owner_id TEXT NOT NULL REFERENCES os_users(owner_id), logical_key TEXT NOT NULL COLLATE BINARY,
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
  state TEXT NOT NULL CHECK(state IN ('live','deleted')), object_id TEXT UNIQUE,
  content_id TEXT REFERENCES os_contents(id), content_type TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(owner_id,logical_key),
  FOREIGN KEY(owner_id,content_id) REFERENCES os_contents(owner_id,id),
  CHECK((state='live' AND object_id IS NOT NULL AND content_id IS NOT NULL AND content_type IS NOT NULL)
    OR (state='deleted' AND object_id IS NULL AND content_id IS NULL))
) STRICT;
-- Permanent head/tombstone revisions prevent ABA after same-key deletion and recreation.
CREATE TRIGGER os_head_monotonic BEFORE UPDATE ON os_heads
WHEN NEW.revision<=OLD.revision
BEGIN SELECT RAISE(ABORT,'head revision must increase'); END;
CREATE TRIGGER os_head_identity BEFORE UPDATE OF owner_id,logical_key ON os_heads
WHEN NEW.owner_id<>OLD.owner_id OR NEW.logical_key<>OLD.logical_key
BEGIN SELECT RAISE(ABORT,'head namespace and key are immutable'); END;
CREATE TRIGGER os_head_no_reuse BEFORE DELETE ON os_heads
BEGIN SELECT RAISE(ABORT,'head tombstones are permanent'); END;
CREATE TABLE os_write_reservations (
  id TEXT PRIMARY KEY NOT NULL, owner_id TEXT NOT NULL REFERENCES os_users(owner_id), logical_key TEXT NOT NULL,
  expected_head_revision INTEGER NOT NULL CHECK(expected_head_revision>=0),
  logical_reserved_bytes INTEGER NOT NULL CHECK(logical_reserved_bytes>=0),
  physical_reserved_bytes INTEGER NOT NULL CHECK(physical_reserved_bytes BETWEEN 0 AND 67108864),
  object_slots INTEGER NOT NULL CHECK(object_slots IN (0,1)), content_id TEXT REFERENCES os_contents(id),
  idempotency_key TEXT NOT NULL, input_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('reserved','copying','published','released','unknown')),
  updated_at TEXT NOT NULL, UNIQUE(owner_id,idempotency_key)
) STRICT;
-- Only one in-flight writer may deduct the same head's previous logical size.
CREATE UNIQUE INDEX os_write_reservations_head ON os_write_reservations(owner_id,logical_key);
CREATE TABLE os_read_pins (
  id TEXT PRIMARY KEY NOT NULL, content_id TEXT NOT NULL REFERENCES os_contents(id), call_id TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT;
CREATE INDEX os_read_pins_content ON os_read_pins(content_id);
CREATE INDEX os_contents_gc ON os_contents(state,id);
CREATE TABLE os_operations (
  owner_id TEXT NOT NULL, capability TEXT NOT NULL, idempotency_key TEXT NOT NULL, input_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('running','succeeded','failed','unknown')),
  result_json TEXT CHECK(result_json IS NULL OR json_valid(result_json)),
  error_json TEXT CHECK(error_json IS NULL OR json_valid(error_json)), output_blob_id TEXT,
  expires_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(owner_id,capability,idempotency_key)
) STRICT;
CREATE INDEX os_operations_expiry ON os_operations(expires_at);
-- QueryResult must resolve an admitted Call, including one that replayed a
-- prior result, without deriving its owner or operation from untrusted input.
CREATE TABLE os_operation_calls (
  owner_id TEXT NOT NULL, call_id TEXT NOT NULL, capability TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  PRIMARY KEY(owner_id,call_id),
  FOREIGN KEY(owner_id,capability,idempotency_key)
    REFERENCES os_operations(owner_id,capability,idempotency_key) ON DELETE CASCADE
) STRICT;
CREATE TABLE os_storage_usage (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), physical_content_bytes INTEGER NOT NULL CHECK(physical_content_bytes>=0),
  reserved_physical_bytes INTEGER NOT NULL CHECK(reserved_physical_bytes>=0), measured_metadata_bytes INTEGER NOT NULL CHECK(measured_metadata_bytes>=0)
) STRICT;
CREATE TABLE os_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL) STRICT;
INSERT INTO os_metadata(key,value) VALUES('data_schema_version','1');
COMMIT;
