#!/usr/bin/env python3
"""Generate validated Microsoft IPv4 EDL files from official sources."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import uuid
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


M365_API_URL = "https://endpoints.office.com/endpoints/worldwide"
DEFENDER_STANDARD_LEARN_URL = (
    "https://learn.microsoft.com/en-us/defender-endpoint/"
    "standard-device-connectivity-urls-commercial"
)
DEFENDER_STANDARD_RAW_URL = (
    "https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/"
    "defender-endpoint/standard-device-connectivity-urls-commercial.md"
)
DEFENDER_ANTIVIRUS_LEARN_URL = (
    "https://learn.microsoft.com/en-us/defender-endpoint/"
    "configure-network-connections-microsoft-defender-antivirus"
)
DEFENDER_ANTIVIRUS_RAW_URL = (
    "https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/"
    "defender-endpoint/configure-network-connections-microsoft-defender-antivirus.md"
)
TEAMS_DIRECT_ROUTING_URL = (
    "https://learn.microsoft.com/en-us/microsoftteams/direct-routing-plan"
)
INTUNE_ENDPOINTS_LEARN_URL = (
    "https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/"
    "intune-endpoints"
)
INTUNE_ENDPOINTS_RAW_URL = (
    "https://raw.githubusercontent.com/MicrosoftDocs/memdocs/main/"
    "intune/fundamentals/endpoints.md"
)

MAX_SOURCE_BYTES = 10 * 1024 * 1024
M365_SERVICE_FILES = {
    "Common": "m365-common-ipv4.txt",
    "Exchange": "m365-exchange-ipv4.txt",
    "SharePoint": "m365-sharepoint-ipv4.txt",
    "Skype": "m365-teams-ipv4.txt",
}
DEFENDER_FILE = "microsoft-defender-ipv4.txt"
TEAMS_MEDIA_FILE = "microsoft-teams-media-ipv4.txt"
INTUNE_WINDOWS_FILE = "microsoft-intune-windows-ipv4.txt"

PUBLICATIONS = (
    ("Microsoft 365 Common", "m365-common-ipv4.txt"),
    ("Microsoft 365 Exchange", "m365-exchange-ipv4.txt"),
    ("Microsoft 365 SharePoint", "m365-sharepoint-ipv4.txt"),
    ("Microsoft 365 Teams/Skype", "m365-teams-ipv4.txt"),
    ("Microsoft Defender EU/global", DEFENDER_FILE),
    ("Microsoft Teams Media/Direct Routing", TEAMS_MEDIA_FILE),
    ("Microsoft Intune / Windows", INTUNE_WINDOWS_FILE),
)

EXPECTED_TEAMS_MEDIA_NETWORKS = {
    ipaddress.IPv4Network("52.112.0.0/14"),
    ipaddress.IPv4Network("52.120.0.0/14"),
}

# Wildcards can't be exhaustively converted into IPs. These deterministic,
# documented targets keep the conversion auditable and avoid inventing Azure
# ranges. Every target must resolve successfully or the workflow fails.
WILDCARD_RESOLUTION_TARGETS = {
    "*.delivery.mp.microsoft.com": ("fe3cr.delivery.mp.microsoft.com",),
    "*.download.microsoft.com": ("download.microsoft.com",),
    "*.download.windowsupdate.com": ("download.windowsupdate.com",),
    "*.events.data.microsoft.com": (
        "events.data.microsoft.com",
        "eu-mobile.events.data.microsoft.com",
        "mobile.events.data.microsoft.com",
        "eu-v20.events.data.microsoft.com",
    ),
    "*.update.microsoft.com": ("update.microsoft.com",),
    "*.wd.microsoft.com": ("europe.x.cp.wd.microsoft.com",),
    "*.wdcp.microsoft.com": ("wdcp.microsoft.com",),
    "*.wdcpalt.microsoft.com": ("wdcpalt.microsoft.com",),
    "*.windowsupdate.com": (
        "ctldl.windowsupdate.com",
        "download.windowsupdate.com",
    ),
    "*ecs.office.com": ("ecs.office.com",),
}

REQUIRED_DEFENDER_HOSTS = {
    "europe.x.cp.wd.microsoft.com",
    "eu.vortex-win.data.microsoft.com",
    "eu-v20.events.data.microsoft.com",
    "winatp-gw-neu.microsoft.com",
    "winatp-gw-weu.microsoft.com",
    "winatp-gw-neu3.microsoft.com",
    "winatp-gw-weu3.microsoft.com",
    "vortex-win.data.microsoft.com",
    "events.data.microsoft.com",
}

HOSTNAME_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
EVENT_HOST_PATTERN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+events\.data\.microsoft\.com\b"
)


class GenerationError(RuntimeError):
    """Raised when publishing a new EDL set would be unsafe."""


class DirectRoutingMediaParser(HTMLParser):
    """Capture the commercial Teams media subsection from Microsoft Learn."""

    TARGET_H3 = "Media traffic: port ranges"
    TARGET_H4 = "Microsoft 365, Office 365, and Office 365 GCC environments"

    def __init__(self) -> None:
        super().__init__()
        self.current_h3 = ""
        self.current_h4 = ""
        self.heading_tag: str | None = None
        self.heading_parts: list[str] = []
        self.target_parts: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        del attrs
        if tag in {"h3", "h4"}:
            self.heading_tag = tag
            self.heading_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag != self.heading_tag:
            return
        heading = " ".join("".join(self.heading_parts).split())
        if tag == "h3":
            self.current_h3 = heading
            self.current_h4 = ""
        elif tag == "h4":
            self.current_h4 = heading
        self.heading_tag = None
        self.heading_parts = []

    def handle_data(self, data: str) -> None:
        if self.heading_tag is not None:
            self.heading_parts.append(data)
        elif self.current_h3 == self.TARGET_H3 and self.current_h4 == self.TARGET_H4:
            self.target_parts.append(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("docs"))
    parser.add_argument("--input-file", type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--request-url", required=True)
    parser.add_argument("--defender-standard-file", type=Path, required=True)
    parser.add_argument("--defender-antivirus-file", type=Path, required=True)
    parser.add_argument("--teams-direct-routing-file", type=Path, required=True)
    parser.add_argument("--intune-endpoints-file", type=Path, required=True)
    return parser.parse_args()


def load_bytes(path: Path, *, label: str) -> bytes:
    try:
        body = path.read_bytes()
    except OSError as error:
        raise GenerationError(f"Unable to read {label}: {error}") from error
    if not body:
        raise GenerationError(f"{label} is empty")
    if len(body) > MAX_SOURCE_BYTES:
        raise GenerationError(f"{label} exceeds the 10 MiB safety limit")
    return body


def load_json_payload(path: Path) -> Any:
    body = load_bytes(path, label="Microsoft 365 response")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GenerationError(f"Microsoft returned invalid JSON: {error}") from error


def load_text_source(path: Path, *, label: str) -> str:
    body = load_bytes(path, label=label)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GenerationError(f"{label} isn't valid UTF-8: {error}") from error


def validate_request_id(raw_request_id: str) -> str:
    try:
        parsed = uuid.UUID(raw_request_id)
    except ValueError as error:
        raise GenerationError(f"Invalid ClientRequestId UUID: {raw_request_id}") from error
    return str(parsed)


def validate_ipv4_network(
    network: ipaddress.IPv4Network, *, context: str
) -> ipaddress.IPv4Network:
    if network == ipaddress.IPv4Network("0.0.0.0/0"):
        raise GenerationError(f"Forbidden default route in {context}")

    forbidden = {
        "private": network.is_private,
        "loopback": network.is_loopback,
        "multicast": network.is_multicast,
        "link-local": network.is_link_local,
        "reserved": network.is_reserved,
        "unspecified": network.is_unspecified,
        "non-global": not network.is_global,
    }
    reasons = [name for name, matched in forbidden.items() if matched]
    if reasons:
        raise GenerationError(
            f"Forbidden IPv4 network {network} in {context}: {', '.join(reasons)}"
        )
    return network


def sort_networks(
    networks: set[ipaddress.IPv4Network] | list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    return sorted(
        set(networks), key=lambda item: (int(item.network_address), item.prefixlen)
    )


def extract_m365_networks(payload: Any) -> dict[str, list[ipaddress.IPv4Network]]:
    if not isinstance(payload, list) or not payload:
        raise GenerationError("Expected a non-empty JSON array from Microsoft 365")

    networks_by_area: dict[str, set[ipaddress.IPv4Network]] = {
        area: set() for area in M365_SERVICE_FILES
    }

    for record_index, record in enumerate(payload):
        context = f"Microsoft 365 record {record_index}"
        if not isinstance(record, dict):
            raise GenerationError(f"Expected an object at {context}")

        service_area = record.get("serviceArea")
        if not isinstance(service_area, str):
            raise GenerationError(f"Missing or invalid serviceArea at {context}")
        if service_area not in M365_SERVICE_FILES:
            raise GenerationError(
                f"Unexpected serviceArea {service_area!r} at {context}"
            )

        if "ips" not in record:
            continue
        raw_ips = record["ips"]
        if not isinstance(raw_ips, list) or not raw_ips:
            raise GenerationError(f"Expected a non-empty ips array at {context}")

        for ip_index, raw_network in enumerate(raw_ips):
            ip_context = f"{context}, ips[{ip_index}]"
            if not isinstance(raw_network, str) or not raw_network:
                raise GenerationError(f"Invalid CIDR value at {ip_context}")
            try:
                network = ipaddress.ip_network(raw_network, strict=True)
            except ValueError as error:
                raise GenerationError(
                    f"Invalid CIDR {raw_network!r} at {ip_context}: {error}"
                ) from error

            if network.version == 6:
                continue
            if not isinstance(network, ipaddress.IPv4Network):
                raise GenerationError(f"Unexpected IP version at {ip_context}")
            networks_by_area[service_area].add(
                validate_ipv4_network(network, context=ip_context)
            )

    result: dict[str, list[ipaddress.IPv4Network]] = {}
    for service_area, filename in M365_SERVICE_FILES.items():
        networks = sort_networks(networks_by_area[service_area])
        if not networks:
            raise GenerationError(
                f"Microsoft returned no public IPv4 CIDR for {service_area}"
            )
        result[filename] = networks
    return result


def extract_markdown_table(
    text: str, *, header_prefix: str, expected_columns: int, label: str
) -> list[list[str]]:
    lines = text.splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(header_prefix)]
    if len(matches) != 1:
        raise GenerationError(
            f"Expected exactly one {label} table, found {len(matches)}"
        )

    header_index = matches[0]
    if header_index + 1 >= len(lines) or not lines[header_index + 1].startswith("|---"):
        raise GenerationError(f"Unexpected {label} table separator")

    rows: list[list[str]] = []
    for line in lines[header_index + 2 :]:
        if not line.startswith("|"):
            break
        if not line.endswith("|"):
            raise GenerationError(f"Unexpected {label} table row delimiter")
        cells = line[1:-1].split("|")
        if len(cells) != expected_columns:
            raise GenerationError(
                f"Unexpected {label} table width: {len(cells)} columns"
            )
        rows.append([cell.strip() for cell in cells])

    if not rows:
        raise GenerationError(f"The {label} table contains no rows")
    return rows


def hostname_from_token(token: str) -> str:
    value = token.strip()
    if "://" in value:
        hostname = urlsplit(value).hostname or ""
    else:
        hostname = value.split("/", 1)[0]
    hostname = hostname.lower().rstrip(".")
    if not hostname:
        raise GenerationError(f"Unable to extract a hostname from {token!r}")
    return hostname


def add_defender_token(
    token: str, *, exact: set[str], wildcards: set[str], context: str
) -> None:
    hostname = hostname_from_token(token)
    if "*" in hostname:
        if hostname not in WILDCARD_RESOLUTION_TARGETS:
            raise GenerationError(
                f"Unexpected Defender wildcard {hostname!r} in {context}"
            )
        wildcards.add(hostname)
        return
    if not HOSTNAME_PATTERN.fullmatch(hostname):
        raise GenerationError(f"Invalid Defender hostname {hostname!r} in {context}")
    exact.add(hostname)


def code_tokens(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def extract_defender_hostnames(
    standard_markdown: str, antivirus_markdown: str
) -> tuple[list[str], list[str], dict[str, tuple[str, ...]]]:
    exact: set[str] = set()
    wildcards: set[str] = set()

    standard_rows = extract_markdown_table(
        standard_markdown,
        header_prefix="|Service|Geography|Category|",
        expected_columns=13,
        label="Defender standard connectivity",
    )
    for cells in standard_rows:
        service = cells[0]
        geography = cells[1]
        endpoint_cell = cells[4]
        requirement = cells[6]

        selection: str | None = None
        if service == "Microsoft Defender for Endpoint" and geography == "EU":
            selection = "Microsoft Defender for Endpoint EU"
        elif (
            service == "Microsoft Defender for Endpoint"
            and geography == "WW"
            and requirement == "Required"
            and any(value.startswith("Yes") for value in cells[7:10])
        ):
            selection = "required global Windows/Windows Server endpoint"
        elif service == "Microsoft Defender Antivirus" and geography == "WW":
            selection = "Microsoft Defender Antivirus global endpoint"

        if selection is None:
            continue
        tokens = code_tokens(endpoint_cell)
        if not tokens:
            raise GenerationError(
                f"Selected Defender row has no parseable endpoint: {endpoint_cell!r}"
            )
        for token in tokens:
            add_defender_token(
                token, exact=exact, wildcards=wildcards, context=selection
            )

        if service == "Microsoft Defender Antivirus" and (
            "events.data.microsoft.com" in endpoint_cell
        ):
            for hostname in EVENT_HOST_PATTERN.findall(cells[12].lower()):
                if hostname in {
                    "eu-mobile.events.data.microsoft.com",
                    "mobile.events.data.microsoft.com",
                }:
                    exact.add(hostname)

    antivirus_rows = extract_markdown_table(
        antivirus_markdown,
        header_prefix="|Service and description|URL|",
        expected_columns=2,
        label="Defender Antivirus connectivity",
    )
    for description, endpoint_cell in antivirus_rows:
        tokens = code_tokens(endpoint_cell)
        if not tokens:
            raise GenerationError(
                f"Selected Defender Antivirus row has no endpoints: {description!r}"
            )
        for token in tokens:
            hostname = hostname_from_token(token)
            if description.startswith("Malware submission storage") and not (
                hostname.endswith(".blob.core.windows.net")
                and re.match(r"^(?:uss|ws)eu", hostname)
            ):
                continue
            add_defender_token(
                token,
                exact=exact,
                wildcards=wildcards,
                context="Defender Antivirus official connectivity",
            )

    missing_hosts = REQUIRED_DEFENDER_HOSTS - exact
    if missing_hosts:
        raise GenerationError(
            "Official Defender sources no longer contain required hosts: "
            + ", ".join(sorted(missing_hosts))
        )

    missing_wildcards = set(WILDCARD_RESOLUTION_TARGETS) - wildcards
    if missing_wildcards:
        raise GenerationError(
            "Official Defender sources no longer contain required patterns: "
            + ", ".join(sorted(missing_wildcards))
        )

    targets_by_wildcard = {
        pattern: WILDCARD_RESOLUTION_TARGETS[pattern]
        for pattern in sorted(wildcards)
    }
    for targets in targets_by_wildcard.values():
        exact.update(targets)

    return sorted(exact), sorted(wildcards), targets_by_wildcard


def resolve_defender_hostnames(
    hostnames: list[str],
) -> tuple[list[ipaddress.IPv4Network], dict[str, list[str]]]:
    socket.setdefaulttimeout(20)
    networks: set[ipaddress.IPv4Network] = set()
    resolutions: dict[str, list[str]] = {}

    for hostname in hostnames:
        try:
            answers = socket.getaddrinfo(
                hostname,
                443,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as error:
            raise GenerationError(
                f"Unable to resolve Defender hostname {hostname}: {error}"
            ) from error

        addresses = sorted({answer[4][0] for answer in answers}, key=ipaddress.IPv4Address)
        if not addresses:
            raise GenerationError(f"No IPv4 address returned for {hostname}")

        resolutions[hostname] = addresses
        for address in addresses:
            network = ipaddress.IPv4Network(f"{address}/32", strict=True)
            networks.add(
                validate_ipv4_network(network, context=f"Defender DNS {hostname}")
            )

    if not networks:
        raise GenerationError("Defender DNS resolution produced an empty IPv4 EDL")
    print(
        f"Defender DNS: {len(hostnames)} hostnames resolved to "
        f"{len(networks)} unique public IPv4 addresses"
    )
    return sort_networks(networks), resolutions


def extract_teams_media_networks(learn_html: str) -> list[ipaddress.IPv4Network]:
    parser = DirectRoutingMediaParser()
    parser.feed(learn_html)
    section = " ".join(parser.target_parts)
    if not section:
        raise GenerationError(
            "Unable to find the commercial Teams media section in Microsoft Learn"
        )

    raw_cidrs = set(
        re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b", section)
    )
    try:
        networks = {
            ipaddress.IPv4Network(raw_network, strict=True)
            for raw_network in raw_cidrs
        }
    except ValueError as error:
        raise GenerationError(f"Invalid Teams media CIDR: {error}") from error

    if networks != EXPECTED_TEAMS_MEDIA_NETWORKS:
        raise GenerationError(
            "Unexpected Teams media ranges in Microsoft Learn: "
            + ", ".join(str(network) for network in sort_networks(networks))
        )
    return [
        validate_ipv4_network(network, context="Teams Direct Routing documentation")
        for network in sort_networks(networks)
    ]


def extract_intune_windows_networks(
    intune_markdown: str,
) -> list[ipaddress.IPv4Network]:
    """Extract only Microsoft's explicit consolidated Intune IP subnets."""
    lines = intune_markdown.splitlines()
    section_markers = [
        index
        for index, line in enumerate(lines)
        if line.strip() == "## Consolidated Endpoint List"
    ]
    if len(section_markers) != 1:
        raise GenerationError(
            "Expected exactly one Intune consolidated endpoint section, found "
            f"{len(section_markers)}"
        )

    section_start = section_markers[0] + 1
    section_end = next(
        (
            index
            for index in range(section_start, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    section = lines[section_start:section_end]
    subnet_markers = [
        index for index, line in enumerate(section) if line.strip() == "IP Subnets"
    ]
    if len(subnet_markers) != 1:
        raise GenerationError(
            "Expected exactly one Intune IP Subnets block, found "
            f"{len(subnet_markers)}"
        )

    cursor = subnet_markers[0] + 1
    while cursor < len(section) and not section[cursor].strip():
        cursor += 1
    if cursor >= len(section) or section[cursor].strip() != "```":
        raise GenerationError("Unexpected Intune IP Subnets code block opening")

    cursor += 1
    raw_networks: list[str] = []
    while cursor < len(section) and section[cursor].strip() != "```":
        value = section[cursor].strip()
        if not value:
            raise GenerationError("Unexpected blank line in Intune IP Subnets block")
        raw_networks.append(value)
        cursor += 1
    if cursor >= len(section):
        raise GenerationError("Intune IP Subnets code block isn't closed")
    if not raw_networks:
        raise GenerationError("Intune IP Subnets block is empty")

    networks: set[ipaddress.IPv4Network] = set()
    for line_number, raw_network in enumerate(raw_networks, start=1):
        context = f"Intune consolidated IP Subnets line {line_number}"
        try:
            network = ipaddress.ip_network(raw_network, strict=True)
        except ValueError as error:
            raise GenerationError(
                f"Invalid Intune CIDR {raw_network!r} at {context}: {error}"
            ) from error
        if network.version == 6:
            continue
        if not isinstance(network, ipaddress.IPv4Network):
            raise GenerationError(f"Unexpected IP version at {context}")
        networks.add(validate_ipv4_network(network, context=context))

    if not networks:
        raise GenerationError("Intune source contains no public IPv4 CIDR")
    return sort_networks(networks)


def parse_previous_file(path: Path) -> list[ipaddress.IPv4Network] | None:
    if not path.exists():
        return None

    lines = path.read_text(encoding="ascii").splitlines()
    if not lines:
        raise GenerationError(f"Previous EDL is empty: {path}")

    networks: list[ipaddress.IPv4Network] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            network = ipaddress.ip_network(line, strict=True)
        except ValueError as error:
            raise GenerationError(
                f"Invalid previous CIDR in {path}:{line_number}: {error}"
            ) from error
        if not isinstance(network, ipaddress.IPv4Network):
            raise GenerationError(f"IPv6 found in previous EDL {path}:{line_number}")
        networks.append(
            validate_ipv4_network(
                network, context=f"previous EDL {path}:{line_number}"
            )
        )

    if len(networks) != len(set(networks)):
        raise GenerationError(f"Previous EDL contains duplicates: {path}")
    return networks


def render_edl(networks: list[ipaddress.IPv4Network]) -> str:
    return "".join(f"{network}\n" for network in networks)


def check_drop_guard(
    output_dir: Path, generated: dict[str, list[ipaddress.IPv4Network]]
) -> None:
    for filename, new_networks in generated.items():
        previous = parse_previous_file(output_dir / filename)
        if previous is None:
            continue
        previous_count = len(previous)
        new_count = len(new_networks)
        if new_count * 2 < previous_count:
            raise GenerationError(
                f"Refusing {filename}: CIDR count dropped from "
                f"{previous_count} to {new_count} (>50%)"
            )


def source_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document_date(markdown: str) -> str | None:
    match = re.search(r"^ms\.date:\s*(.+?)\s*$", markdown, flags=re.MULTILINE)
    return match.group(1) if match else None


def build_sources(
    *,
    generated_at: str,
    request_id: str,
    request_url: str,
    record_count: int,
    generated: dict[str, list[ipaddress.IPv4Network]],
    defender_standard: str,
    defender_antivirus: str,
    teams_direct_routing: str,
    intune_endpoints: str,
    defender_hostnames: list[str],
    defender_wildcards: list[str],
    wildcard_targets: dict[str, tuple[str, ...]],
    defender_resolutions: dict[str, list[str]],
) -> str:
    files: dict[str, dict[str, Any]] = {
        filename: {
            "serviceArea": service_area,
            "cidrCount": len(generated[filename]),
            "method": "Filter the Microsoft 365 ips field by serviceArea",
        }
        for service_area, filename in M365_SERVICE_FILES.items()
    }
    files[DEFENDER_FILE] = {
        "cidrCount": len(generated[DEFENDER_FILE]),
        "hostnameCount": len(defender_hostnames),
        "method": "Resolve selected official Defender FQDN A records to IPv4 /32",
        "scope": [
            "Microsoft Defender for Endpoint EU",
            "Required global Windows and Windows Server endpoints",
            "Microsoft Defender Antivirus and official update dependencies",
        ],
        "wildcardPatterns": defender_wildcards,
        "wildcardResolutionTargets": {
            pattern: list(targets) for pattern, targets in wildcard_targets.items()
        },
        "resolvedHostnames": defender_resolutions,
    }
    files[TEAMS_MEDIA_FILE] = {
        "cidrCount": len(generated[TEAMS_MEDIA_FILE]),
        "method": "Validate documented commercial Direct Routing media CIDRs",
        "documentedRanges": [
            str(network) for network in generated[TEAMS_MEDIA_FILE]
        ],
    }
    files[INTUNE_WINDOWS_FILE] = {
        "cidrCount": len(generated[INTUNE_WINDOWS_FILE]),
        "method": (
            "Extract and validate explicit IPv4 CIDRs from the consolidated "
            "Intune IP Subnets block"
        ),
        "scope": (
            "Intune-managed devices, including the explicitly published "
            "Intune and Azure Front Door Microsoft Security subnets"
        ),
    }

    document = {
        "generatedAt": generated_at,
        "sources": {
            "microsoft365Endpoints": {
                "publisher": "Microsoft",
                "name": "Microsoft 365 IP Address and URL web service",
                "instance": "Worldwide",
                "url": M365_API_URL,
                "requestUrl": request_url,
                "clientRequestId": request_id,
                "responseRecordCount": record_count,
                "field": "ips",
            },
            "defenderStandardConnectivity": {
                "publisher": "Microsoft",
                "learnUrl": DEFENDER_STANDARD_LEARN_URL,
                "sourceUrl": DEFENDER_STANDARD_RAW_URL,
                "documentDate": document_date(defender_standard),
                "sha256": source_hash(defender_standard),
            },
            "defenderAntivirusConnectivity": {
                "publisher": "Microsoft",
                "learnUrl": DEFENDER_ANTIVIRUS_LEARN_URL,
                "sourceUrl": DEFENDER_ANTIVIRUS_RAW_URL,
                "documentDate": document_date(defender_antivirus),
                "sha256": source_hash(defender_antivirus),
            },
            "teamsDirectRouting": {
                "publisher": "Microsoft",
                "learnUrl": TEAMS_DIRECT_ROUTING_URL,
                "sha256": source_hash(teams_direct_routing),
            },
            "intuneNetworkEndpoints": {
                "publisher": "Microsoft",
                "learnUrl": INTUNE_ENDPOINTS_LEARN_URL,
                "sourceUrl": INTUNE_ENDPOINTS_RAW_URL,
                "documentDate": document_date(intune_endpoints),
                "sha256": source_hash(intune_endpoints),
                "section": "Consolidated Endpoint List / IP Subnets",
            },
        },
        "filters": {
            "ipVersion": 4,
            "excludeDefaultRoute": True,
            "publicNetworksOnly": True,
        },
        "files": files,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def build_index(
    generated_at: str, generated: dict[str, list[ipaddress.IPv4Network]]
) -> str:
    rows = []
    for label, filename in PUBLICATIONS:
        rows.append(
            "<tr>"
            f"<td>{html.escape(label)}</td>"
            f'<td><a href="{html.escape(filename)}">{html.escape(filename)}</a></td>'
            f"<td>{len(generated[filename])}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Microsoft IPv4 EDLs</title>
    <style>
      :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
      body {{ max-width: 68rem; margin: 4rem auto; padding: 0 1.25rem; line-height: 1.55; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border-bottom: 1px solid #8888; padding: .65rem; text-align: left; }}
      code {{ overflow-wrap: anywhere; }}
    </style>
  </head>
  <body>
    <h1>Microsoft IPv4 EDLs</h1>
    <p>Listes IPv4 publiques générées depuis les sources officielles Microsoft.</p>
    <table>
      <thead><tr><th>Périmètre</th><th>Fichier</th><th>CIDR</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    <p>Dernière modification des listes : {html.escape(generated_at)}</p>
    <p><a href="sources.json">Provenance et métadonnées</a></p>
  </body>
</html>
"""


def publish(
    *,
    output_dir: Path,
    payload: list[Any],
    request_id: str,
    request_url: str,
    generated: dict[str, list[ipaddress.IPv4Network]],
    defender_standard: str,
    defender_antivirus: str,
    teams_direct_routing: str,
    intune_endpoints: str,
    defender_hostnames: list[str],
    defender_wildcards: list[str],
    wildcard_targets: dict[str, tuple[str, ...]],
    defender_resolutions: dict[str, list[str]],
) -> bool:
    check_drop_guard(output_dir, generated)
    rendered = {filename: render_edl(items) for filename, items in generated.items()}

    edl_changed = any(
        not (output_dir / filename).exists()
        or (output_dir / filename).read_text(encoding="ascii") != content
        for filename, content in rendered.items()
    )
    support_missing = any(
        not (output_dir / name).exists()
        for name in ("sources.json", "index.html", ".nojekyll")
    )

    for filename, networks in generated.items():
        print(f"{filename}: {len(networks)} IPv4 CIDRs")

    if not edl_changed and not support_missing:
        print("No EDL content change detected; keeping the previous publication")
        return False

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    sources = build_sources(
        generated_at=generated_at,
        request_id=request_id,
        request_url=request_url,
        record_count=len(payload),
        generated=generated,
        defender_standard=defender_standard,
        defender_antivirus=defender_antivirus,
        teams_direct_routing=teams_direct_routing,
        intune_endpoints=intune_endpoints,
        defender_hostnames=defender_hostnames,
        defender_wildcards=defender_wildcards,
        wildcard_targets=wildcard_targets,
        defender_resolutions=defender_resolutions,
    )
    index = build_index(generated_at, generated)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="m365-edl-", dir=output_dir.parent
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        for filename, content in rendered.items():
            (temporary / filename).write_text(content, encoding="ascii")
        (temporary / "sources.json").write_text(sources, encoding="utf-8")
        (temporary / "index.html").write_text(index, encoding="utf-8")
        (temporary / ".nojekyll").write_text("", encoding="ascii")

        output_dir.mkdir(parents=True, exist_ok=True)
        for filename in (*rendered, "sources.json", "index.html", ".nojekyll"):
            os.replace(temporary / filename, output_dir / filename)

    print("Validated EDL changes written to the publication directory")
    return True


def main() -> int:
    args = parse_args()
    try:
        payload = load_json_payload(args.input_file)
        request_id = validate_request_id(args.request_id)
        defender_standard = load_text_source(
            args.defender_standard_file, label="Defender standard connectivity source"
        )
        defender_antivirus = load_text_source(
            args.defender_antivirus_file,
            label="Defender Antivirus connectivity source",
        )
        teams_direct_routing = load_text_source(
            args.teams_direct_routing_file,
            label="Teams Direct Routing Microsoft Learn source",
        )
        intune_endpoints = load_text_source(
            args.intune_endpoints_file,
            label="Microsoft Intune network endpoints source",
        )

        generated = extract_m365_networks(payload)
        defender_hostnames, defender_wildcards, wildcard_targets = (
            extract_defender_hostnames(defender_standard, defender_antivirus)
        )
        defender_networks, defender_resolutions = resolve_defender_hostnames(
            defender_hostnames
        )
        teams_media_networks = extract_teams_media_networks(teams_direct_routing)
        intune_windows_networks = extract_intune_windows_networks(intune_endpoints)
        generated[DEFENDER_FILE] = defender_networks
        generated[TEAMS_MEDIA_FILE] = teams_media_networks
        generated[INTUNE_WINDOWS_FILE] = intune_windows_networks

        publish(
            output_dir=args.output_dir,
            payload=payload,
            request_id=request_id,
            request_url=args.request_url,
            generated=generated,
            defender_standard=defender_standard,
            defender_antivirus=defender_antivirus,
            teams_direct_routing=teams_direct_routing,
            intune_endpoints=intune_endpoints,
            defender_hostnames=defender_hostnames,
            defender_wildcards=defender_wildcards,
            wildcard_targets=wildcard_targets,
            defender_resolutions=defender_resolutions,
        )
    except GenerationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
