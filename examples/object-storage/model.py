"""Input and pagination rules for the volume-backed object store."""

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import unicodedata
import uuid


MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_CHUNK_BYTES = 256 * 1024
MAX_INTEGER = (1 << 53) - 1
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_MIME_TOKEN = r"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+"
_MIME = re.compile(
    rf'{_MIME_TOKEN}/{_MIME_TOKEN}'
    rf'(?: *; *{_MIME_TOKEN}=(?:{_MIME_TOKEN}|"[^"\\\r\n]*"))*'
)


class StoreError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.completed = False


def invalid(message):
    return StoreError("INVALID_ARGUMENT", message)


def conflict(message):
    return StoreError("STATE_CONFLICT", message)


def canonical_uuid(value):
    try:
        if isinstance(value, str) and str(uuid.UUID(value)) == value:
            return value
    except ValueError:
        pass
    raise invalid("Expected a canonical UUID")


def integer(value, minimum, maximum):
    if type(value) is float and value.is_integer():
        value = int(value)
    if type(value) is not int or not minimum <= value <= maximum:
        raise invalid("Integer is outside its allowed range")
    return value


def digest_string(value):
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise invalid("Expected a SHA-256 digest")
    return value


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def logical_key(value, *, prefix=False):
    if not isinstance(value, str):
        raise invalid("Expected a logical object key")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise invalid("Expected a UTF-8 logical key") from None
    if (
        length > 1024
        or unicodedata.normalize("NFC", value) != value
        or "\\" in value
        or any(unicodedata.category(char) == "Cc" for char in value)
    ):
        raise invalid("Invalid logical object key")
    if not prefix and any(part in ("", ".", "..") for part in value.split("/")):
        raise invalid("Object key contains an empty or dot segment")
    return value


def mime_type(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or not all(" " <= char <= "~" for char in value)
        or not _MIME.fullmatch(value)
    ):
        raise invalid("Invalid content type")
    return value


def request_fields(value, required, optional=()):
    if (
        not isinstance(value, dict)
        or not set(required) <= value.keys()
        or not value.keys() <= set(required) | set(optional)
    ):
        raise invalid("Object request has missing or unknown fields")


def revision(value):
    return integer(value, 1, MAX_INTEGER)


def put_request(value):
    request_fields(
        value, ("key", "blob_id", "size_bytes", "digest", "content_type", "mode"),
        ("expected_revision",),
    )
    value = dict(value)
    logical_key(value["key"])
    canonical_uuid(value["blob_id"])
    value["size_bytes"] = integer(value["size_bytes"], 0, MAX_OBJECT_BYTES)
    digest_string(value["digest"])
    mime_type(value["content_type"])
    if value["mode"] == "replace" and "expected_revision" in value:
        value["expected_revision"] = revision(value["expected_revision"])
    elif value["mode"] != "create" or "expected_revision" in value:
        raise invalid("Create and replace have different revision requirements")
    return value


@dataclass(frozen=True, slots=True)
class Call:
    """Identity and business key supplied by the authenticated caller adapter."""

    subject: str
    call_id: str
    idempotency_key: str

    def __post_init__(self):
        canonical_uuid(self.subject)
        canonical_uuid(self.call_id)
        if not isinstance(self.idempotency_key, str):
            raise invalid("Expected a UTF-8 idempotency key")
        try:
            self.idempotency_key.encode("utf-8")
        except UnicodeEncodeError:
            raise invalid("Expected a UTF-8 idempotency key") from None
        if not 1 <= len(self.idempotency_key) <= 128:
            raise invalid("Expected an idempotency key")


def prefix_end(prefix):
    """Exclusive upper bound for a prefix in SQLite's UTF-8 BINARY order."""
    for index in range(len(prefix) - 1, -1, -1):
        codepoint = ord(prefix[index])
        if codepoint < 0x10FFFF:
            successor = 0xE000 if codepoint == 0xD7FF else codepoint + 1
            return prefix[:index] + chr(successor)
    return None


class Cursor:
    def __init__(self, secret, scope, ttl):
        self.secret = secret
        self.scope = scope
        self.ttl = ttl

    def binding(self, subject, prefix, limit):
        return hashlib.sha256(canonical_json([self.scope, subject, prefix, limit])).digest()

    def encode(self, binding, last, expires):
        payload = expires.to_bytes(8, "big") + binding + last.encode("utf-8")
        tag = hmac.digest(self.secret, payload, "sha256")
        return base64.urlsafe_b64encode(payload + tag).decode("ascii").rstrip("=")

    def decode(self, token, binding, now):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,4096}", token):
            raise invalid("Malformed object cursor")
        try:
            data = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        except binascii.Error:
            raise invalid("Malformed object cursor") from None
        if not 73 <= len(data) <= 72 + 1024:
            raise invalid("Malformed object cursor")
        payload, tag = data[:-32], data[-32:]
        expires = int.from_bytes(payload[:8], "big")
        if (
            not hmac.compare_digest(tag, hmac.digest(self.secret, payload, "sha256"))
            or base64.urlsafe_b64encode(data).decode("ascii").rstrip("=") != token
            or not hmac.compare_digest(binding, payload[8:40])
            or expires <= now
        ):
            raise conflict("Object cursor has expired or does not match this query")
        return payload[40:].decode("utf-8"), expires
