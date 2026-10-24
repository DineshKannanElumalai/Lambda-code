"""
lambda-backup
Exports Lambda functions (configuration, code, layers, aliases, triggers,
versions, resource policy) from source accounts into a central S3 bucket.

Runs in the CENTRAL account. Assumes LambdaBackupReadRole in each source
account and discovers every enabled region automatically.

Environment variables
  BACKUP_BUCKET     required  central bucket name
  SOURCE_ACCOUNTS   required  comma-separated 12-digit account IDs
  SOURCE_ROLE       optional  role name in source accounts (default LambdaBackupReadRole)
  REDACT_ENV        optional  "true" (default) masks environment variable values
                              "false" stores them (only if bucket access is locked down)
  BACKUP_LAYERS     optional  "true" (default) also stores layer zip files

S3 layout
  <account>/<region>/<run-id>/<function>/function.json
  <account>/<region>/<run-id>/<function>/extras.json
  <account>/<region>/<run-id>/<function>/code.zip
  <account>/<region>/<run-id>/_layers/<layer-name>-v<version>.zip
  _runs/<run-id>.json                       (run summary / audit record)
"""

import base64
import datetime
import hashlib
import json
import logging
import os
import re
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Configuration (validated once, at cold start)
# ---------------------------------------------------------------------------

def _flag(name, default):
    return os.environ.get(name, default).strip().lower() == "true"


BUCKET = os.environ["BACKUP_BUCKET"].strip()
ROLE = os.environ.get("SOURCE_ROLE", "LambdaBackupReadRole").strip()
REDACT_ENV = _flag("REDACT_ENV", "true")
BACKUP_LAYERS = _flag("BACKUP_LAYERS", "true")
HOME_REGION = os.environ.get("AWS_REGION", "us-east-1")

if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", BUCKET):
    raise ValueError("BACKUP_BUCKET is not a valid S3 bucket name")
if not re.fullmatch(r"[\w+=,.@-]{1,64}", ROLE):
    raise ValueError("SOURCE_ROLE is not a valid IAM role name")

ACCOUNTS = sorted({a.strip() for a in os.environ["SOURCE_ACCOUNTS"].split(",") if a.strip()})
if not ACCOUNTS:
    raise ValueError("SOURCE_ACCOUNTS is empty")
for _a in ACCOUNTS:
    if not re.fullmatch(r"\d{12}", _a):
        raise ValueError(f"Invalid account ID in SOURCE_ACCOUNTS: {_a!r}")

BOTO_CFG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},  # handles API throttling
    connect_timeout=10,
    read_timeout=60,
)
DOWNLOAD_TIMEOUT_S = 120
CHUNK = 1024 * 1024
TIME_RESERVE_MS = 90_000          # stop starting new work with 90 s left
ALLOWED_HOST_SUFFIX = ".amazonaws.com"
SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,140}")

s3 = boto3.client("s3", config=BOTO_CFG)
sts = boto3.client("sts", region_name=HOME_REGION, config=BOTO_CFG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class OutOfTime(Exception):
    """Raised when the invocation is close to its timeout."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so a download can never be steered to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirects are not allowed", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect)


def _session_for(account):
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account}:role/{ROLE}",
        RoleSessionName="lambda-backup",
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _enabled_regions(sess):
    ec2 = sess.client("ec2", region_name=HOME_REGION, config=BOTO_CFG)
    return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])


def _paginate(client, op, key, **kwargs):
    items = []
    for page in client.get_paginator(op).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def _safe(name):
    if not SAFE_NAME.fullmatch(name):
        raise ValueError(f"Unexpected characters in name: {name!r}")
    return name


def _put_json(key, data, owner):
    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(data, default=str, indent=2).encode("utf-8"),
        ContentType="application/json",
        ExpectedBucketOwner=owner,          # never write into someone else's bucket
        ChecksumAlgorithm="SHA256",         # S3 verifies integrity on arrival
    )


def _download_verified(url, expected_sha256_b64, expected_size):
    """Download to /tmp over HTTPS from AWS only, then verify size and SHA-256."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host.endswith(ALLOWED_HOST_SUFFIX):
        raise ValueError(f"Refusing download from unexpected host {host!r}")

    digest = hashlib.sha256()
    size = 0
    fd, path = tempfile.mkstemp(dir="/tmp", suffix=".zip")
    try:
        with os.fdopen(fd, "wb") as out, _OPENER.open(url, timeout=DOWNLOAD_TIMEOUT_S) as resp:
            for chunk in iter(lambda: resp.read(CHUNK), b""):
                digest.update(chunk)
                size += len(chunk)
                out.write(chunk)

        if expected_size is not None and size != expected_size:
            raise ValueError(f"Size mismatch: got {size}, expected {expected_size}")
        if expected_sha256_b64:
            actual = base64.b64encode(digest.digest()).decode("ascii")
            if actual != expected_sha256_b64:
                raise ValueError("SHA-256 mismatch: downloaded package is not the deployed one")
        return path
    except Exception:
        os.remove(path)
        raise


def _upload_zip(path, key, owner):
    try:
        s3.upload_file(
            path,
            BUCKET,
            key,
            ExtraArgs={
                "ContentType": "application/zip",
                "ExpectedBucketOwner": owner,
                "ChecksumAlgorithm": "SHA256",
            },
        )
    finally:
        os.remove(path)


def _redact(info):
    env = info.get("Configuration", {}).get("Environment", {})
    if REDACT_ENV and env.get("Variables"):
        env["Variables"] = {k: "***REDACTED***" for k in env["Variables"]}


# ---------------------------------------------------------------------------
# Backup of one function / layer
# ---------------------------------------------------------------------------

def _backup_layers(lam, info, base, owner, seen_layers, warnings):
    for layer in info.get("Configuration", {}).get("Layers", []):
        arn = layer["Arn"]
        if arn in seen_layers:
            continue
        seen_layers.add(arn)
        parts = arn.split(":")              # arn:aws:lambda:region:acct:layer:name:version
        try:
            name, version = _safe(parts[6]), _safe(parts[7])
            content = lam.get_layer_version_by_arn(Arn=arn)["Content"]
            path = _download_verified(content["Location"], content.get("CodeSha256"), content.get("CodeSize"))
            _upload_zip(path, f"{base}/_layers/{name}-v{version}.zip", owner)
        except Exception as e:  # third-party layers are often not readable
            warnings.append(f"layer {arn}: {type(e).__name__}: {e}")
            logger.warning("Layer not backed up %s: %s", arn, e)


def _backup_function(lam, base, name, owner, seen_layers, warnings):
    prefix = f"{base}/{_safe(name)}"

    info = lam.get_function(FunctionName=name)
    info.pop("ResponseMetadata", None)
    code = info.get("Code", {})
    code_url = code.pop("Location", None)   # pre-signed URL: never stored
    _redact(info)

    extras = {
        "aliases": _paginate(lam, "list_aliases", "Aliases", FunctionName=name),
        "versions": _paginate(lam, "list_versions_by_function", "Versions", FunctionName=name),
        "event_sources": _paginate(lam, "list_event_source_mappings", "EventSourceMappings", FunctionName=name),
    }
    for v in extras["versions"]:            # version configs also carry env vars
        if REDACT_ENV and v.get("Environment", {}).get("Variables"):
            v["Environment"]["Variables"] = {k: "***REDACTED***" for k in v["Environment"]["Variables"]}
    try:
        extras["resource_policy"] = json.loads(lam.get_policy(FunctionName=name)["Policy"])
    except lam.exceptions.ResourceNotFoundException:
        extras["resource_policy"] = None

    package = info.get("Configuration", {}).get("PackageType", "Zip")
    if package == "Zip" and code.get("RepositoryType") == "S3" and code_url:
        cfg = info["Configuration"]
        path = _download_verified(code_url, cfg.get("CodeSha256"), cfg.get("CodeSize"))
        _upload_zip(path, f"{prefix}/code.zip", owner)
    elif package == "Image":
        warnings.append(f"{prefix}: container image ({code.get('ImageUri')}), use ECR replication")

    _put_json(f"{prefix}/function.json", info, owner)
    _put_json(f"{prefix}/extras.json", extras, owner)

    if BACKUP_LAYERS:
        _backup_layers(lam, info, base, owner, seen_layers, warnings)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    owner = sts.get_caller_identity()["Account"]
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    count, failures, warnings = 0, [], []
    incomplete = False

    def check_time():
        if context.get_remaining_time_in_millis() < TIME_RESERVE_MS:
            raise OutOfTime()

    try:
        for acct in ACCOUNTS:
            check_time()
            try:
                sess = _session_for(acct)
                regions = _enabled_regions(sess)
            except Exception as e:
                failures.append(f"{acct}: {type(e).__name__}: {e}")
                logger.error("Account %s skipped: %s", acct, e)
                continue

            for region in regions:
                check_time()
                base = f"{acct}/{region}/{run_id}"
                seen_layers = set()
                try:
                    lam = sess.client("lambda", region_name=region, config=BOTO_CFG)
                    functions = _paginate(lam, "list_functions", "Functions")
                except Exception as e:
                    failures.append(f"{acct}/{region}: {type(e).__name__}: {e}")
                    logger.error("Region %s/%s skipped: %s", acct, region, e)
                    continue

                for fn in functions:
                    check_time()
                    name = fn["FunctionName"]
                    try:
                        _backup_function(lam, base, name, owner, seen_layers, warnings)
                        count += 1
                        logger.info("Backed up %s/%s/%s", acct, region, name)
                    except Exception as e:
                        failures.append(f"{acct}/{region}/{name}: {type(e).__name__}: {e}")
                        logger.error("Failed %s/%s/%s: %s", acct, region, name, e)
    except OutOfTime:
        incomplete = True
        logger.error("Stopped early: invocation close to timeout")

    summary = {
        "run_id": run_id,
        "accounts": ACCOUNTS,
        "functions_backed_up": count,
        "failures": failures,
        "warnings": warnings,
        "incomplete": incomplete,
        "env_vars_redacted": REDACT_ENV,
    }
    try:
        _put_json(f"_runs/{run_id}.json", summary, owner)
    except Exception as e:
        logger.error("Could not write run summary: %s", e)

    logger.info(json.dumps({k: v for k, v in summary.items() if k not in ("failures", "warnings")}))

    if failures or incomplete:
        # Fail the invocation so the Lambda "Errors" metric and alarm fire.
        raise RuntimeError(
            f"Backup run {run_id}: {len(failures)} failures, incomplete={incomplete}. "
            f"See s3://{BUCKET}/_runs/{run_id}.json"
        )
    return {"run_id": run_id, "functions_backed_up": count, "warnings": len(warnings)}