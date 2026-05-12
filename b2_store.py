"""
b2_store — Backblaze B2-backed persistence for ZeroFlaw.

Replaces the in-memory scan_store dict and REPORTS_DIR filesystem
with B2 S3-compatible object storage so scan results survive Render
cold starts / sleep cycles.

Requires B2_APPLICATION_KEY_ID and B2_APPLICATION_KEY env vars.
Bucket name is configurable via B2_BUCKET (default: zeroflaw-scans).
"""

import b2sdk.v2 as b2
import json
import logging
import os
from typing import Optional

logger = logging.getLogger("b2_store")

B2_KEY_ID = os.environ.get("B2_APPLICATION_KEY_ID", "")
B2_SECRET = os.environ.get("B2_APPLICATION_KEY", "")
B2_BUCKET_NAME = os.environ.get("B2_BUCKET", "zeroflaw-scans")

_bucket: Optional[b2.Bucket] = None


def _get_bucket() -> b2.Bucket:
    global _bucket
    if _bucket is not None:
        return _bucket

    if not B2_KEY_ID or not B2_SECRET:
        raise RuntimeError(
            "B2_APPLICATION_KEY_ID and B2_APPLICATION_KEY environment "
            "variables must be set to use B2 storage."
        )

    auth = b2.InMemoryAccountInfo()
    api = b2.B2Api(auth)
    api.authorize_account("production", B2_KEY_ID, B2_SECRET)

    try:
        _bucket = api.get_bucket_by_name(B2_BUCKET_NAME)
    except b2.exception.BucketNotFound:
        _bucket = api.create_bucket(B2_BUCKET_NAME, "allPrivate")
        logger.info("Created B2 bucket: %s", B2_BUCKET_NAME)

    return _bucket


def put(scan_id: str, data: dict) -> None:
    """Store scan metadata as JSON in B2. Overwrites existing entries."""
    key = f"scan_store/{scan_id}.json"
    bucket = _get_bucket()
    try:
        file = bucket.download_file_by_name(key)
        bucket.delete_file_version(file.download_version.id_, key)
    except (b2.exception.FileNotPresent, b2.exception.B2Error):
        pass
    bucket.upload_bytes(
        json.dumps(data, default=str).encode("utf-8"),
        key,
        content_type="application/json",
    )


def get(scan_id: str) -> Optional[dict]:
    """Retrieve scan metadata from B2. Returns None if not found."""
    key = f"scan_store/{scan_id}.json"
    bucket = _get_bucket()
    try:
        file = bucket.download_file_by_name(key)
        return json.loads(file.response.content.decode("utf-8"))
    except (b2.exception.FileNotPresent, b2.exception.B2Error):
        return None


def _delete_by_key(b2_key: str) -> None:
    """Delete a file from B2 by key."""
    bucket = _get_bucket()
    try:
        try:
            file = bucket.download_file_by_name(b2_key)
            bucket.delete_file_version(file.download_version.id_, b2_key)
        except b2.exception.FileNotPresent:
            pass
    except b2.exception.B2Error:
        pass


def delete(scan_id: str) -> None:
    """Delete scan metadata from B2."""
    _delete_by_key(f"scan_store/{scan_id}.json")


def delete_file(b2_key: str) -> None:
    """Delete a file from B2."""
    _delete_by_key(b2_key)


def put_file(b2_key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
    """Upload a binary file to B2."""
    bucket = _get_bucket()
    bucket.upload_bytes(data, b2_key, content_type=content_type)


def get_file(b2_key: str) -> Optional[bytes]:
    """Download a binary file from B2. Returns None if not found."""
    bucket = _get_bucket()
    try:
        file = bucket.download_file_by_name(b2_key)
        return file.response.content
    except (b2.exception.FileNotPresent, b2.exception.B2Error):
        return None


def put_text(b2_key: str, text: str, content_type: str = "text/plain") -> None:
    """Upload a text file to B2."""
    put_file(b2_key, text.encode("utf-8"), content_type)


def get_text(b2_key: str) -> Optional[str]:
    """Download a text file from B2. Returns None if not found."""
    data = get_file(b2_key)
    if data is None:
        return None
    return data.decode("utf-8")


def _prefix_files(prefix: str) -> list[str]:
    """List all B2 keys with a given prefix."""
    bucket = _get_bucket()
    keys = []
    for file_version, _ in bucket.list_file_versions(prefix):
        keys.append(file_version.file_name)
    return keys


def cleanup_expired(days: int = 1) -> int:
    """Delete scan_store entries older than `days` and their report files."""
    import time

    cutoff = time.time() - (days * 86400)
    deleted = 0

    for key in _prefix_files("scan_store/"):
        try:
            file = _get_bucket().download_file_by_name(key)
            data = json.loads(file.response.content.decode("utf-8"))
            created_at = data.get("created_at", 0)
            if created_at < cutoff:
                scan_id = key.split("/")[-1].replace(".json", "")
                delete(scan_id)
                for ext in ("", "-download"):
                    delete_file(f"reports/{scan_id}{ext}.html")
                delete_file(f"reports/{scan_id}.pdf")
                delete_file(f"reports/{scan_id}-fixed.zip")
                delete_file(f"reports/{scan_id}-download.html")
                for item in _prefix_files(f"reports/{scan_id}/"):
                    delete_file(item)
                deleted += 1
        except Exception:
            pass

    return deleted