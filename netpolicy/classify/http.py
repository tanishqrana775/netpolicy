"""Pure classification functions and decision rules for HTTP integrity observations.

Adheres strictly to GEMINI.md design rules:
1. Pure functions: list[Observation] -> Verdict. No I/O.
2. If control probe fails, verdicts must become UNKNOWN.
3. Every verdict carries a confidence level (HIGH/MEDIUM/LOW) and human-readable evidence strings.
4. If canary fetch itself failed, return UNKNOWN, not tampering.

HTTP Verdict Kinds:
- CLEAN: Canary payload matches expected hash, nonce echoed intact, no proxy headers or redirects.
- HEADERS_INJECTED: Unexpected proxy or cache headers observed in response (e.g. Via, X-Cache).
- BODY_MODIFIED: Body SHA-256 mismatch against canary manifest (payload tampering).
- PROXIED: Missing or altered X-NetPolicy-Nonce echo, indicating a rewriting intermediary proxy.
- REDIRECTED: Unexpected HTTP redirects (e.g. captive portal or proxy landing page).
- UNKNOWN: Control probe failed, empty observations, or canary fetch failed to connect.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from netpolicy.models import Confidence, Observation, Target, Verdict, VerdictKind

__all__ = [
    "classify_http",
    "classify_http_checks",
    "CanaryManifest",
    "DEFAULT_CANARY_SHA256",
    "STANDARD_DISALLOWED_HEADERS",
]

# Standard verification payload hash
try:
    from canary.server import CANARY_SHA256 as _CANARY_SHA256

    DEFAULT_CANARY_SHA256: str = _CANARY_SHA256
except ImportError:
    DEFAULT_CANARY_SHA256 = hashlib.sha256(
        b"NETPOLICY_CANARY_STABLE_VERIFICATION_PAYLOAD\n"
    ).hexdigest()

# Known proxy/middlebox response headers that indicate intermediary injection
STANDARD_DISALLOWED_HEADERS: frozenset[str] = frozenset(
    {
        "via",
        "x-cache",
        "x-cache-lookup",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-squid-error",
        "cf-ray",
        "x-varnish",
        "x-proxy-id",
        "x-bluecoat-via",
        "x-content-encoded-by",
    }
)


@dataclass(frozen=True)
class CanaryManifest:
    """Canary expectation manifest for HTTP integrity verification."""

    expected_sha256: str = DEFAULT_CANARY_SHA256
    disallowed_headers: frozenset[str] = STANDARD_DISALLOWED_HEADERS
    expected_status: int = 200


def classify_http_checks(
    observations: list[Observation],
    control_reachable: bool = True,
    manifest: CanaryManifest | None = None,
) -> list[Verdict]:
    """Evaluate individual HTTP observations against the canary manifest.

    Returns a list of verdicts corresponding to each endpoint/scheme inspected.
    """
    if not observations:
        return [
            Verdict(
                target=Target(host="unknown", service="HTTP"),
                kind=VerdictKind.UNKNOWN,
                confidence=Confidence.LOW,
                evidence=["No HTTP observations provided."],
            )
        ]

    first_target = observations[0].target
    if not control_reachable:
        return [
            Verdict(
                target=first_target,
                kind=VerdictKind.UNKNOWN,
                confidence=Confidence.HIGH,
                evidence=["Control probe failed; cannot verify HTTP baseline."],
            )
        ]

    active_manifest = manifest or CanaryManifest()
    verdicts: list[Verdict] = []

    for obs in observations:
        raw: dict[str, Any] = obs.raw or {}
        target = obs.target
        status = raw.get("status")
        err = raw.get("error")
        path = raw.get("path", "")
        headers = raw.get("headers", [])
        body_sha256 = raw.get("body_sha256")
        redirects = raw.get("redirects", [])
        nonce_sent = raw.get("nonce_sent")
        nonce_echoed = raw.get("nonce_echoed")
        echoed_headers = raw.get("echoed_headers") or {}

        # 1. Fetch failure check: return UNKNOWN, not tampering
        if status is None or (err and not status):
            verdicts.append(
                Verdict(
                    target=target,
                    kind=VerdictKind.UNKNOWN,
                    confidence=Confidence.HIGH,
                    evidence=[
                        f"Canary fetch failed to connect for {path}: "
                        f"{err or 'no response received'}."
                    ],
                )
            )
            continue

        # 2. Redirect check
        if redirects or status in (301, 302, 303, 307, 308, 403, 511):
            evidence: list[str] = []
            if redirects:
                evidence.append(f"Unexpected HTTP redirect encountered on {path}: {redirects}")
            if status != active_manifest.expected_status:
                evidence.append(
                    f"Unexpected HTTP status code {status} on {path} "
                    f"(expected {active_manifest.expected_status}) - "
                    "possible captive portal or block page."
                )
            verdicts.append(
                Verdict(
                    target=target,
                    kind=VerdictKind.REDIRECTED,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                )
            )
            continue

        # 3. Payload integrity check (/canary.txt)
        if path == "/canary.txt" and body_sha256 and body_sha256 != active_manifest.expected_sha256:
            verdicts.append(
                Verdict(
                    target=target,
                    kind=VerdictKind.BODY_MODIFIED,
                    confidence=Confidence.HIGH,
                    evidence=[
                        f"Body SHA-256 hash mismatch for {path}: received '{body_sha256}' "
                        f"vs expected '{active_manifest.expected_sha256}'."
                    ],
                )
            )
            continue

        # 4. Proxy rewriting check (/echo nonce verification)
        if path == "/echo":
            if nonce_sent is not None and nonce_echoed is None:
                verdicts.append(
                    Verdict(
                        target=target,
                        kind=VerdictKind.PROXIED,
                        confidence=Confidence.HIGH,
                        evidence=[
                            "X-NetPolicy-Nonce header was stripped before reaching canary server "
                            "(rewriting proxy detected)."
                        ],
                    )
                )
                continue
            if nonce_sent is not None and nonce_echoed != nonce_sent:
                verdicts.append(
                    Verdict(
                        target=target,
                        kind=VerdictKind.PROXIED,
                        confidence=Confidence.HIGH,
                        evidence=[
                            f"X-NetPolicy-Nonce was altered in transit: sent '{nonce_sent}', "
                            f"canary received '{nonce_echoed}' (rewriting proxy detected)."
                        ],
                    )
                )
                continue
            # Check for request headers injected upstream
            forwarded_keys = [
                k for k in echoed_headers if k.lower() in active_manifest.disallowed_headers
            ]
            if forwarded_keys:
                hdr_str = ", ".join(forwarded_keys)
                verdicts.append(
                    Verdict(
                        target=target,
                        kind=VerdictKind.PROXIED,
                        confidence=Confidence.HIGH,
                        evidence=[f"Canary /echo received proxy request headers: {hdr_str}."],
                    )
                )
                continue

        # 5. Response header injection check
        injected_headers: list[tuple[str, str]] = []
        for name, value in headers:
            if name.lower() in active_manifest.disallowed_headers:
                injected_headers.append((name, value))

        if injected_headers:
            verdicts.append(
                Verdict(
                    target=target,
                    kind=VerdictKind.HEADERS_INJECTED,
                    confidence=Confidence.HIGH,
                    evidence=[
                        f"Injected proxy header detected: '{name}: {val}'"
                        for name, val in injected_headers
                    ],
                )
            )
            continue

        # 6. Clean check
        clean_evidence = [
            f"Endpoint {path} responded with status {status}.",
        ]
        if path == "/canary.txt":
            sha_display = str(body_sha256)[:12] if body_sha256 else "verified"
            clean_evidence.append(f"Body SHA-256 verified against manifest ({sha_display}...).")
        elif path == "/echo":
            clean_evidence.append("X-NetPolicy-Nonce echoed intact without alteration.")
        clean_evidence.append("No unexpected proxy headers or redirects observed.")

        verdicts.append(
            Verdict(
                target=target,
                kind=VerdictKind.CLEAN,
                confidence=Confidence.HIGH,
                evidence=clean_evidence,
            )
        )

    return verdicts


def classify_http(
    observations: list[Observation],
    control_reachable: bool = True,
    manifest: CanaryManifest | None = None,
) -> Verdict:
    """Classify a collection of HTTP canary observations into an aggregate Verdict.

    Follows priority:
    1. BODY_MODIFIED (high confidence): payload hash mismatch.
    2. HEADERS_INJECTED (high confidence): unexpected proxy headers (Via, X-Cache).
    3. PROXIED (high confidence): missing or altered nonce echo.
    4. REDIRECTED (high confidence): captive portal redirection or status mismatch.
    5. CLEAN: all endpoints verified against the canary manifest.
    6. UNKNOWN: fetch failed or control probe failed.
    """
    if not observations:
        return Verdict(
            target=Target(host="unknown", service="HTTP"),
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.LOW,
            evidence=["No HTTP observations provided for classification."],
        )

    target = observations[0].target
    if not control_reachable:
        return Verdict(
            target=target,
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.HIGH,
            evidence=["Control probe failed; cannot verify HTTP baseline."],
        )

    # Check if ALL canary fetches failed to receive any HTTP response
    all_failed = all(
        (o.raw.get("status") is None or (o.raw.get("error") and not o.raw.get("status")))
        for o in observations
    )
    if all_failed:
        first_err = next(
            (o.raw.get("error") for o in observations if o.raw.get("error")),
            "connection failed",
        )
        return Verdict(
            target=target,
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.HIGH,
            evidence=[
                f"Canary fetch failed to connect: {first_err} (fetch failure, not tampering)."
            ],
        )

    check_verdicts = classify_http_checks(
        observations=observations,
        control_reachable=control_reachable,
        manifest=manifest,
    )

    if not check_verdicts:
        return Verdict(
            target=target,
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.LOW,
            evidence=["No interpretable HTTP checks found in observations."],
        )

    # Precedence hierarchy:
    # BODY_MODIFIED > HEADERS_INJECTED > PROXIED > REDIRECTED > CLEAN > UNKNOWN
    body_modified = [v for v in check_verdicts if v.kind == VerdictKind.BODY_MODIFIED]
    if body_modified:
        all_evidence: list[str] = []
        for v in body_modified:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.BODY_MODIFIED,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    headers_injected = [v for v in check_verdicts if v.kind == VerdictKind.HEADERS_INJECTED]
    if headers_injected:
        all_evidence = []
        for v in headers_injected:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.HEADERS_INJECTED,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    proxied = [v for v in check_verdicts if v.kind == VerdictKind.PROXIED]
    if proxied:
        all_evidence = []
        for v in proxied:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.PROXIED,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    redirected = [v for v in check_verdicts if v.kind == VerdictKind.REDIRECTED]
    if redirected:
        all_evidence = []
        for v in redirected:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.REDIRECTED,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    clean_checks = [v for v in check_verdicts if v.kind == VerdictKind.CLEAN]
    if clean_checks:
        all_evidence = [
            "Canary body SHA-256 matches expected manifest.",
            "X-NetPolicy-Nonce echoed intact without alteration.",
            "No injected proxy headers detected in response.",
            "Direct HTTP communication confirmed without redirects.",
        ]
        return Verdict(
            target=target,
            kind=VerdictKind.CLEAN,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    return check_verdicts[0]
