#!/usr/bin/env python3
"""
External backup: PostgreSQL (pg_dump) + uploads directory → Cloudflare R2 (S3-compatible).

Usage:
  python scripts/backup_external.py

Required env vars:
  DATABASE_URL, BACKUP_S3_ENDPOINT, BACKUP_S3_BUCKET,
  BACKUP_S3_ACCESS_KEY_ID, BACKUP_S3_SECRET_ACCESS_KEY

Optional env vars:
  BACKUP_S3_REGION          (default: auto)
  BACKUP_S3_PREFIX          (default: backups)
  BACKUP_UPLOADS_DIR        (default: $RAILWAY_VOLUME_MOUNT_PATH/static)
  BACKUP_RETENTION_DAYS     (default: 14)
  BACKUP_NOTIFY_WEBHOOK_URL (Discord or Slack webhook URL)
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("backup_external")

REQUIRED_ENVS = [
    "DATABASE_URL",
    "BACKUP_S3_ENDPOINT",
    "BACKUP_S3_BUCKET",
    "BACKUP_S3_ACCESS_KEY_ID",
    "BACKUP_S3_SECRET_ACCESS_KEY",
]

TMP_DIR = "/tmp/backups"


# ─── helpers ────────────────────────────────────────────────────────────────

def _human_size(path: str) -> str:
    size = os.path.getsize(path)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _normalize_db_url(url: str) -> str:
    """Strip async driver prefixes — pg_dump needs plain postgresql://."""
    return (
        url.replace("postgresql+asyncpg://", "postgresql://")
           .replace("postgres://", "postgresql://")
    )


def _validate_envs() -> None:
    missing = [k for k in REQUIRED_ENVS if not os.getenv(k)]
    if missing:
        logger.error("Missing required env vars: %s", ", ".join(missing))
        sys.exit(1)


def _send_webhook(url: str, message: str, success: bool) -> None:
    try:
        color = 3066993 if success else 15158332  # green / red
        if "hooks.slack.com" in url:
            payload = {"text": message}
        else:
            title = "✅ Backup — sukces" if success else "❌ Backup — błąd"
            payload = {"embeds": [{"title": title, "description": message, "color": color}]}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        logger.warning("Webhook send failed: %s", exc)


# ─── backup steps ────────────────────────────────────────────────────────────

def _backup_postgres(tmp_dir: str, database_url: str) -> str:
    """Run pg_dump → gzip. Returns path to .dump.gz file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    dump_path = os.path.join(tmp_dir, f"postgres_{ts}.dump")
    gz_path = dump_path + ".gz"
    pg_url = _normalize_db_url(database_url)

    logger.info("pg_dump → %s", dump_path)
    with open(dump_path, "wb") as dump_fh:
        result = subprocess.run(
            ["pg_dump", "--format=custom", "--no-owner", "--no-acl", pg_url],
            stdout=dump_fh,
            stderr=subprocess.PIPE,
            timeout=600,
        )
    if result.returncode != 0:
        err = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"pg_dump exited {result.returncode}: {err}")

    logger.info("Compressing dump → %s", gz_path)
    with open(dump_path, "rb") as f_in, gzip.open(gz_path, "wb", compresslevel=6) as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(dump_path)

    logger.info("DB backup ready: %s  (%s)", gz_path, _human_size(gz_path))
    return gz_path


def _backup_uploads(tmp_dir: str, uploads_dir: str) -> Optional[str]:
    """Create .tar.gz of uploads_dir. Returns path or None if dir missing."""
    if not os.path.isdir(uploads_dir):
        logger.warning("Uploads dir not found, skipping: %s", uploads_dir)
        return None

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    tar_path = os.path.join(tmp_dir, f"uploads_{ts}.tar.gz")

    logger.info("Creating uploads archive → %s  (source: %s)", tar_path, uploads_dir)
    with tarfile.open(tar_path, "w:gz", compresslevel=6) as tar:
        tar.add(uploads_dir, arcname="uploads")

    logger.info("Uploads backup ready: %s  (%s)", tar_path, _human_size(tar_path))
    return tar_path


def _upload_to_s3(file_path: str, s3_key: str, s3_client: object, bucket: str) -> None:
    logger.info("Uploading %s → s3://%s/%s", os.path.basename(file_path), bucket, s3_key)
    s3_client.upload_file(file_path, bucket, s3_key)  # type: ignore[attr-defined]
    logger.info("Upload OK: %s", s3_key)


def _apply_retention(
    s3_client: object, bucket: str, prefix: str, retention_days: int
) -> None:
    logger.info("Retention check (%d days) for prefix: %s", retention_days, prefix)
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    deleted = 0
    paginator = s3_client.get_paginator("list_objects_v2")  # type: ignore[attr-defined]
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"] < cutoff:
                logger.info("Deleting expired: %s", obj["Key"])
                s3_client.delete_object(Bucket=bucket, Key=obj["Key"])  # type: ignore[attr-defined]
                deleted += 1
    if deleted:
        logger.info("Retention: deleted %d expired object(s)", deleted)


# ─── main entry point ────────────────────────────────────────────────────────

def run_backup() -> None:
    """
    Main entry point — called from main.py scheduler or directly as a script.
    Raises on failure (caller should handle and alert).
    """
    t_start = time.monotonic()
    logger.info("=" * 60)
    logger.info("External backup starting (UTC: %s)", datetime.now(timezone.utc).isoformat())

    _validate_envs()

    database_url = os.environ["DATABASE_URL"]
    endpoint     = os.environ["BACKUP_S3_ENDPOINT"]
    region       = os.getenv("BACKUP_S3_REGION", "auto")
    bucket       = os.environ["BACKUP_S3_BUCKET"]
    access_key   = os.environ["BACKUP_S3_ACCESS_KEY_ID"]
    secret_key   = os.environ["BACKUP_S3_SECRET_ACCESS_KEY"]
    prefix       = os.getenv("BACKUP_S3_PREFIX", "backups").rstrip("/")
    retention    = int(os.getenv("BACKUP_RETENTION_DAYS", "14"))
    webhook_url  = os.getenv("BACKUP_NOTIFY_WEBHOOK_URL")

    # Resolve uploads dir: explicit env → Railway volume → cwd/static
    uploads_dir = os.getenv("BACKUP_UPLOADS_DIR") or os.path.join(
        os.getenv("RAILWAY_VOLUME_MOUNT_PATH", ""), "static"
    )

    os.makedirs(TMP_DIR, exist_ok=True)

    import boto3  # imported here so the module loads even without boto3 installed
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )

    uploaded: list[str] = []

    try:
        # ── 1. PostgreSQL dump ───────────────────────────────────────────────
        gz_path = _backup_postgres(TMP_DIR, database_url)
        db_key = f"{prefix}/postgres/daily/{os.path.basename(gz_path)}"
        _upload_to_s3(gz_path, db_key, s3, bucket)
        uploaded.append(db_key)
        os.remove(gz_path)

        # ── 2. Uploads archive ───────────────────────────────────────────────
        tar_path = _backup_uploads(TMP_DIR, uploads_dir)
        if tar_path:
            up_key = f"{prefix}/uploads/daily/{os.path.basename(tar_path)}"
            _upload_to_s3(tar_path, up_key, s3, bucket)
            uploaded.append(up_key)
            os.remove(tar_path)

        # ── 3. Retention ─────────────────────────────────────────────────────
        _apply_retention(s3, bucket, f"{prefix}/postgres/daily/", retention)
        _apply_retention(s3, bucket, f"{prefix}/uploads/daily/", retention)

        elapsed = time.monotonic() - t_start
        summary = f"Completed in {elapsed:.1f}s\nFiles:\n" + "\n".join(f"  {f}" for f in uploaded)
        logger.info("=" * 60)
        logger.info("External backup DONE  (%s)", f"{elapsed:.1f}s")
        logger.info("Uploaded: %s", ", ".join(uploaded))

        if webhook_url:
            _send_webhook(webhook_url, summary, success=True)

    except Exception as exc:
        elapsed = time.monotonic() - t_start
        logger.error("External backup FAILED after %.1fs: %s", elapsed, exc, exc_info=True)
        if webhook_url:
            _send_webhook(webhook_url, f"Backup FAILED after {elapsed:.1f}s:\n{exc}", success=False)
        # Clean up any partial temp files
        for f in Path(TMP_DIR).glob("*.gz"):
            try:
                f.unlink()
            except OSError:
                pass
        for f in Path(TMP_DIR).glob("*.dump"):
            try:
                f.unlink()
            except OSError:
                pass
        raise


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        run_backup()
    except Exception:
        sys.exit(1)
