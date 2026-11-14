"""JSON serialization and deserialization for AuditReport with privacy redaction."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from netpolicy.models import AuditReport
from netpolicy.store.raw import chown_to_sudo_user

MAC_REGEX = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b")
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class ReportValidationError(ValueError):
    """Raised when an audit report file is invalid, corrupt, or unparseable."""


class SchemaVersionError(ReportValidationError):
    """Raised when an audit report's schema_version does not match expected version."""


def _is_public_ipv4(ip_str: str) -> bool:
    """Return True if the string is a valid non-private, non-loopback IPv4 address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False


def _redact_string(text: str, client_ip: str | None = None) -> str:
    """Redact MAC addresses and public client IP occurrences from a string."""
    # Redact any MAC addresses
    text = MAC_REGEX.sub("[REDACTED_MAC]", text)

    # Redact client public IP if provided
    if client_ip and _is_public_ipv4(client_ip):
        text = text.replace(client_ip, "[REDACTED_PUBLIC_IP]")

    return text


def _redact_data(item: Any, client_ip: str | None = None) -> Any:
    """Recursively scrub sensitive identifiers from data structures."""
    if isinstance(item, str):
        return _redact_string(item, client_ip)
    if isinstance(item, list):
        return [_redact_data(v, client_ip) for v in item]
    if isinstance(item, dict):
        return {k: _redact_data(v, client_ip) for k, v in item.items()}
    return item


def redact_identifiers(data: dict[str, Any], include_identifiers: bool) -> dict[str, Any]:
    """Redact SSIDs, MAC addresses, and client public IPs unless requested otherwise.

    Per GEMINI.md non-negotiable safety rules:
    Never store SSIDs, MAC addresses, or public IPs in reports unless
    include_identifiers is set.
    """
    if include_identifiers:
        return data

    scrubbed = dict(data)
    metadata = dict(scrubbed.get("metadata", {}))

    # Mask network SSID / label
    net_label = metadata.get("network_label", "")
    if net_label:
        metadata["network_label"] = "[REDACTED_SSID]"

    # Mask client address if public or present
    client_addr = metadata.get("client_address", "")
    if client_addr and client_addr != "127.0.0.1":
        if _is_public_ipv4(client_addr):
            metadata["client_address"] = "[REDACTED_PUBLIC_IP]"
        else:
            octets = client_addr.split(".")
            if len(octets) == 4:
                metadata["client_address"] = f"{octets[0]}.{octets[1]}.*.*"
            else:
                metadata["client_address"] = "[REDACTED_IP]"

    scrubbed["metadata"] = metadata

    # Recursively redact MACs and references across verdicts, evidence, and findings
    return cast(dict[str, Any], _redact_data(scrubbed, client_ip=client_addr))


def serialize_report(
    report: AuditReport,
    include_identifiers: bool = False,
    indent: int = 2,
) -> str:
    """Serialize AuditReport to schema-versioned JSON string.

    Args:
        report: The AuditReport to serialize.
        include_identifiers: If True, keep SSIDs, MACs, and public IPs.
        indent: JSON indentation level.

    Returns:
        JSON-encoded string with schema_version '1'.
    """
    raw_dict = report.to_dict()
    raw_dict["schema_version"] = "1"
    cleaned = redact_identifiers(raw_dict, include_identifiers)
    return json.dumps(cleaned, indent=indent)


def generate_json_report(
    report: AuditReport,
    output_path: Path | str | None = None,
    include_identifiers: bool = False,
    indent: int = 2,
) -> str:
    """Serialize the audit report to JSON, optionally writing to disk."""
    json_str = serialize_report(
        report=report,
        include_identifiers=include_identifiers,
        indent=indent,
    )
    if output_path is not None:
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(path.parent)
        path.write_text(json_str, encoding="utf-8")
        chown_to_sudo_user(path)
    return json_str


def load_report(path: Path | str) -> AuditReport:
    """Load and validate an AuditReport from a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        Validated AuditReport instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        SchemaVersionError: If the schema_version does not match '1'.
        ReportValidationError: If the JSON is invalid or fails schema validation.
    """
    report_path = Path(path).expanduser().resolve()
    if not report_path.is_file():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    try:
        content = report_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ReportValidationError(f"Invalid JSON format in {report_path}: {exc}") from exc
    except Exception as exc:
        raise ReportValidationError(f"Could not read report file {report_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ReportValidationError(f"Report root must be a JSON object, got {type(data).__name__}")

    schema_version = str(data.get("schema_version", ""))
    if schema_version != "1":
        raise SchemaVersionError(
            f"Unsupported schema version: expected '1', got '{data.get('schema_version')}'"
        )

    try:
        return AuditReport.from_dict(data)
    except ValidationError as exc:
        raise ReportValidationError(f"Report validation failed for {report_path}: {exc}") from exc
