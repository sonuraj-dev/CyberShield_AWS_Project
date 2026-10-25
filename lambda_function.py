import json
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

TABLE_NAME = os.environ.get("FINDINGS_TABLE", "CyberShieldFindings")
MAX_EVENTS = 500
ALLOWED_EVENTS = {"login_failed", "login_success"}
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
table = boto3.resource("dynamodb").Table(TABLE_NAME)


def response(status, payload):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": os.environ.get("CORS_ORIGIN", "*"),
            "Access-Control-Allow-Headers": "content-type",
            "Access-Control-Allow-Methods": "POST,OPTIONS"
        },
        "body": json.dumps(payload)
    }


def valid_ip(value):
    if not isinstance(value, str) or not IPV4_RE.fullmatch(value):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in value.split("."))
    except ValueError:
        return False


def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    if method == "OPTIONS":
        return response(200, {"ok": True})
    if method and method != "POST":
        return response(405, {"error": "Use POST /analyze."})

    try:
        body = event.get("body", event)
        if isinstance(body, str):
            body = json.loads(body)
        events = body.get("events") if isinstance(body, dict) else None
        if not isinstance(events, list) or not events:
            return response(400, {"error": "Provide a non-empty events array."})
        if len(events) > MAX_EVENTS:
            return response(400, {"error": f"Maximum {MAX_EVENTS} events per request."})

        normalized = []
        for row in events:
            if not isinstance(row, dict):
                return response(400, {"error": "Every event must be a JSON object."})
            ip = row.get("ip")
            kind = row.get("event")
            timestamp = row.get("timestamp", "")
            if not valid_ip(ip) or kind not in ALLOWED_EVENTS:
                return response(400, {"error": "Each event needs a valid IPv4 'ip' and event login_failed or login_success."})
            if not isinstance(timestamp, str) or len(timestamp) > 64:
                return response(400, {"error": "Timestamp must be a string of at most 64 characters."})
            normalized.append({"ip": ip, "event": kind, "timestamp": timestamp})

        by_ip = defaultdict(list)
        for row in normalized:
            by_ip[row["ip"]].append(row)

        findings = []
        now = datetime.now(timezone.utc).isoformat()
        for ip, records in by_ip.items():
            failures = [i for i, r in enumerate(records) if r["event"] == "login_failed"]
            successes = [i for i, r in enumerate(records) if r["event"] == "login_success"]
            fail_count = len(failures)
            if fail_count >= 5:
                findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "severity": "HIGH",
                    "ip": ip,
                    "description": "Repeated failed login attempts detected",
                    "failed_attempts": fail_count,
                    "rule": "AUTH-001",
                    "created_at": now
                })
            if fail_count >= 3 and successes and max(failures) < max(successes):
                findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "severity": "MEDIUM",
                    "ip": ip,
                    "description": "Successful login observed after repeated failures in this batch",
                    "failed_attempts": fail_count,
                    "rule": "AUTH-002",
                    "created_at": now
                })

        saved = 0
        for finding in findings:
            try:
                table.put_item(Item=finding)
                saved += 1
            except ClientError:
                # Fail visibly instead of claiming persistence succeeded.
                raise

        return response(200, {
            "events_analyzed": len(normalized),
            "findings": findings,
            "findings_saved": saved,
            "note": "Rule-based prototype; investigate findings before drawing conclusions."
        })
    except json.JSONDecodeError:
        return response(400, {"error": "Request body must contain valid JSON."})
    except ClientError:
        print("DynamoDB write failed; inspect CloudWatch logs.")
        return response(500, {"error": "Could not persist findings. Check table and IAM configuration."})
    except Exception:
        print("Unexpected processing error; inspect CloudWatch logs.")
        return response(500, {"error": "Unexpected server error."})
