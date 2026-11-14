"""Configuration schema and loading utilities for netpolicy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# Standard audited port list with service designations
DEFAULT_PORTS: list[dict[str, Any]] = [
    {"port": 21, "service": "FTP"},
    {"port": 22, "service": "SSH"},
    {"port": 25, "service": "SMTP"},
    {"port": 53, "service": "DNS"},
    {"port": 80, "service": "HTTP"},
    {"port": 110, "service": "POP3"},
    {"port": 143, "service": "IMAP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 465, "service": "SMTPS"},
    {"port": 587, "service": "Submission"},
    {"port": 993, "service": "IMAPS"},
    {"port": 3478, "service": "STUN"},
]

# DNS check defaults
DEFAULT_DNS_SERVERS: list[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DEFAULT_DNS_DOMAINS: list[str] = ["example.com", "cloudflare.com"]
DEFAULT_DOH_SERVERS: list[str] = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]
DEFAULT_DNS_RECORD_TYPES: list[str] = ["A", "AAAA"]
DEFAULT_BLACKHOLE_SERVERS: list[str] = ["192.0.2.1", "198.51.100.1"]
DEFAULT_WHOAMI_NAME: str = "o-o.myaddr.l.google.com"
DEFAULT_WHOAMI_RESOLVER: str = "8.8.8.8"
DEFAULT_NXDOMAIN_RESOLVER: str = "8.8.8.8"
DEFAULT_DOH_CROSSCHECK_DOMAINS: list[str] = ["example.com", "cloudflare.com"]
DEFAULT_DOH_RESOLVER_IP: str = "1.1.1.1"
DEFAULT_DOH_RESOLVER_URL: str = "https://cloudflare-dns.com/dns-query"
DEFAULT_SOURCE_MISMATCH_RESOLVERS: list[str] = ["8.8.8.8", "1.1.1.1"]

# HTTP tampering check defaults
DEFAULT_HTTP_PORTS: list[int] = [80, 443]
DEFAULT_HTTP_PATHS: list[str] = ["/", "/generate_204"]
DEFAULT_HTTP_USER_AGENT: str = "netpolicy/0.1.0"
DEFAULT_CONTROL_TARGET: str = "1.1.1.1"


class PortDefinition(BaseModel):
    """Specification for an audited port."""

    port: int
    service: str


class PortsConfig(BaseModel):
    """Configuration for port reachability auditing."""

    ports: list[PortDefinition] = Field(
        default_factory=lambda: [PortDefinition(**p) for p in DEFAULT_PORTS]
    )
    runs: int = 5
    timeout: float = 3.0
    retries: int = 2
    mode: str = "auto"
    control_port: int = 443


class DNSConfig(BaseModel):
    """Configuration for DNS interception and spoofing detection."""

    servers: list[str] = Field(default_factory=lambda: list(DEFAULT_DNS_SERVERS))
    domains: list[str] = Field(default_factory=lambda: list(DEFAULT_DNS_DOMAINS))
    doh_servers: list[str] = Field(default_factory=lambda: list(DEFAULT_DOH_SERVERS))
    record_types: list[str] = Field(default_factory=lambda: list(DEFAULT_DNS_RECORD_TYPES))
    blackhole_servers: list[str] = Field(default_factory=lambda: list(DEFAULT_BLACKHOLE_SERVERS))
    whoami_name: str = DEFAULT_WHOAMI_NAME
    whoami_resolver: str = DEFAULT_WHOAMI_RESOLVER
    nxdomain_resolver: str = DEFAULT_NXDOMAIN_RESOLVER
    nxdomain_count: int = 5
    doh_crosscheck_domains: list[str] = Field(
        default_factory=lambda: list(DEFAULT_DOH_CROSSCHECK_DOMAINS)
    )
    doh_crosscheck_resolver: str = DEFAULT_DOH_RESOLVER_IP
    doh_crosscheck_url: str = DEFAULT_DOH_RESOLVER_URL
    source_mismatch_resolvers: list[str] = Field(
        default_factory=lambda: list(DEFAULT_SOURCE_MISMATCH_RESOLVERS)
    )
    timeout: float = 3.0
    retries: int = 2


class HTTPConfig(BaseModel):
    """Configuration for HTTP tampering auditing."""

    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_HTTP_PORTS))
    paths: list[str] = Field(default_factory=lambda: list(DEFAULT_HTTP_PATHS))
    user_agent: str = DEFAULT_HTTP_USER_AGENT
    timeout: float = 3.0
    retries: int = 2


class GeneralConfig(BaseModel):
    """General audit execution options."""

    target: str | None = None
    control_target: str = DEFAULT_CONTROL_TARGET
    output: Path | None = None
    json_output: bool = False
    quiet: bool = False
    verbose: bool = False
    no_color: bool = False
    include_identifiers: bool = False
    demo: bool = False


class AppConfig(BaseModel):
    """Master application configuration."""

    ports: PortsConfig = Field(default_factory=PortsConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    general: GeneralConfig = Field(default_factory=GeneralConfig)


def parse_ports_arg(
    ports_str: str | None,
    default_ports: list[PortDefinition],
) -> list[PortDefinition]:
    """Parse a comma-separated list of ports into PortDefinition objects."""
    if not ports_str:
        return default_ports

    service_map = {p.port: p.service for p in default_ports}
    result: list[PortDefinition] = []
    for item in ports_str.split(","):
        cleaned = item.strip()
        if not cleaned:
            continue
        try:
            port_num = int(cleaned)
            service_name = service_map.get(port_num, "Custom")
            result.append(PortDefinition(port=port_num, service=service_name))
        except ValueError as exc:
            raise ValueError(f"Invalid port number: {cleaned}") from exc
    return result


def load_config(config_path: Path | str | None = None) -> AppConfig:
    """Load configuration from a YAML file, merging with default values.

    Args:
        config_path: Optional path to a YAML configuration file.

    Returns:
        AppConfig instance with defaults and user overrides.
    """
    if config_path is None:
        return AppConfig()

    resolved_path = Path(config_path).expanduser().resolve()
    if not resolved_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {resolved_path}")

    with resolved_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return AppConfig.model_validate(data)
