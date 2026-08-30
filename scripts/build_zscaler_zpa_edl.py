#!/usr/bin/env python3
"""Build a Palo Alto IPv4 EDL for Zscaler ZPA Public Service Edges.

The generator accepts only the official private.zscaler.com ZPA exports.  It
cross-checks the JSON export against both the official plaintext export and
the data rendered by the Zscaler configuration page before publishing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

if __package__:
    from scripts.generate_edl import ZSCALER_ZPA_FILE, build_index
else:
    from generate_edl import ZSCALER_ZPA_FILE, build_index


ZSCALER_ZPA_PAGE_URL = "https://config.zscaler.com/private.zscaler.com/zpa"
ZSCALER_ZPA_PAGE_DATA_URL = (
    "https://config.zscaler.com/api/getpagedata/"
    "private.zscaler.com/all/zpa?site=config.zscaler.com"
)
ZSCALER_ZPA_JSON_URL = (
    "https://config.zscaler.com/api/private.zscaler.com/zpa/json"
)
ZSCALER_ZPA_PLAINTEXT_URL = (
    "https://config.zscaler.com/api/private.zscaler.com/zpa/plaintext"
)
ZSCALER_ZPA_METADATA_FILE = "metadata/zscaler-zpa.json"
INDEX_FILE = "index.html"
EXPECTED_CLOUD_NAME = "private.zscaler.com"
EXPECTED_PAGE_NAME = "Zscaler Private Access (ZPA)"
EXPECTED_PAGE_ALIAS = "zpa"
EXPECTED_CONNECTOR_SOURCE = (
    "Connector, Private Service Edge, Zscaler Client Connector"
)
ALLOWED_CONNECTOR_DOMAINS = {
    "*.private.zscaler.com",
    "*.prod.zpath.net",
    "*.prod.zpath.vip",
}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_COUNT_CHANGE_RATIO = 0.50
USER_AGENT = "hove-io-m365-edl-zscaler-zpa/1.0"


class BuildError(RuntimeError):
    """Raised when a source or prospective publication is unsafe."""


@dataclass(frozen=True)
class ParsedJson:
    selected_ipv4: tuple[ipaddress.IPv4Network, ...]
    all_networks: frozenset[ipaddress.IPv4Network | ipaddress.IPv6Network]
    selected_rows: int
    selected_raw_entries: int
    selected_ipv6_entries: int
    duplicate_entries_removed: int


@dataclass(frozen=True)
class Publication:
    ipv4_networks: tuple[ipaddress.IPv4Network, ...]
    metadata: str
    source_hashes: dict[str, str]


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_source_file(path: Path, *, label: str) -> bytes:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise BuildError(f"Unable to read {label} fixture {path}: {exc}") from exc
    if len(payload) > MAX_SOURCE_BYTES:
        raise BuildError(f"{label} exceeds {MAX_SOURCE_BYTES} bytes")
    if not payload.strip():
        raise BuildError(f"{label} is empty")
    return payload


def fetch_https(url: str, *, timeout: float, accept: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "config.zscaler.com":
        raise BuildError(f"Refusing non-official Zscaler source URL: {url}")
    request = urllib.request.Request(
        url,
        headers={"Accept": accept, "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=ssl.create_default_context()
        ) as response:
            final_url = urlparse(response.geturl())
            if (
                final_url.scheme != "https"
                or final_url.hostname != "config.zscaler.com"
            ):
                raise BuildError(
                    f"Official Zscaler source redirected outside its host: {response.geturl()}"
                )
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_SOURCE_BYTES:
                raise BuildError(f"Zscaler source exceeds {MAX_SOURCE_BYTES} bytes")
            payload = response.read(MAX_SOURCE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise BuildError(f"Unable to retrieve {url}: {exc}") from exc
    except urllib.error.URLError:
        payload = fetch_https_with_curl(url, timeout=timeout, accept=accept)
    except (TimeoutError, OSError, ValueError) as exc:
        raise BuildError(f"Unable to retrieve {url}: {exc}") from exc
    if len(payload) > MAX_SOURCE_BYTES:
        raise BuildError(f"Zscaler source exceeds {MAX_SOURCE_BYTES} bytes")
    if not payload.strip():
        raise BuildError(f"Zscaler source is empty: {url}")
    return payload


def fetch_https_with_curl(url: str, *, timeout: float, accept: str) -> bytes:
    """Fallback for hosts whose certificate chain is absent from Python's CA set."""
    command = [
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
        str(max(1, int(timeout))),
        "--max-time",
        str(max(1, int(timeout))),
        "--max-filesize",
        str(MAX_SOURCE_BYTES),
        "--header",
        f"Accept: {accept}",
        "--header",
        f"User-Agent: {USER_AGENT}",
        url,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=timeout + 5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BuildError(f"Unable to retrieve {url} with curl: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise BuildError(
            f"Unable to retrieve {url} with curl: {message or result.returncode}"
        )
    if len(result.stdout) > MAX_SOURCE_BYTES:
        raise BuildError(f"Zscaler source exceeds {MAX_SOURCE_BYTES} bytes")
    if not result.stdout.strip():
        raise BuildError(f"Zscaler source is empty: {url}")
    return result.stdout


def load_json(payload: bytes, *, label: str) -> Any:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuildError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def validate_network(value: Any, *, label: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise BuildError(f"{label} contains a non-string or non-normalized IP value: {value!r}")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise BuildError(f"{label} contains an invalid IP/CIDR: {value!r}") from exc
    if network.prefixlen == 0 or not network.is_global:
        raise BuildError(f"{label} contains a non-public or overbroad network: {value!r}")
    if (
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    ):
        raise BuildError(f"{label} contains a forbidden network: {value!r}")
    return network


def network_sort_key(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def parse_zscaler_json(payload: bytes) -> ParsedJson:
    document = load_json(payload, label="Zscaler ZPA JSON export")
    if not isinstance(document, dict):
        raise BuildError("Zscaler ZPA JSON root is not an object")
    if document.get("Cloud Name") != EXPECTED_CLOUD_NAME:
        raise BuildError(
            "Zscaler ZPA JSON does not identify the private.zscaler.com cloud"
        )
    rows = document.get("content")
    if not isinstance(rows, list) or not rows:
        raise BuildError("Zscaler ZPA JSON contains no content rows")

    all_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    selected_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    selected_rows = 0
    selected_raw_entries = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise BuildError(f"Zscaler ZPA row {index} is not an object")
        values = row.get("IPs")
        if not isinstance(values, list) or not values:
            raise BuildError(f"Zscaler ZPA row {index} has no IP list")
        row_networks = [
            validate_network(value, label=f"Zscaler ZPA row {index}")
            for value in values
        ]
        all_networks.update(row_networks)

        if row.get("Source") != EXPECTED_CONNECTOR_SOURCE:
            continue
        if row.get("IP Protocol") != "TCP/UDP" or row.get("Port") != 443:
            raise BuildError(
                f"Zscaler connector row {index} no longer describes TCP/UDP 443"
            )
        raw_domains = row.get("Domains")
        if not isinstance(raw_domains, str):
            raise BuildError(f"Zscaler connector row {index} has no domain scope")
        domains = {part.strip() for part in raw_domains.split(",") if part.strip()}
        if (
            "*.private.zscaler.com" not in domains
            or not domains.issubset(ALLOWED_CONNECTOR_DOMAINS)
        ):
            raise BuildError(
                f"Zscaler connector row {index} has an unexpected domain scope: {raw_domains!r}"
            )
        selected_rows += 1
        selected_raw_entries += len(row_networks)
        selected_networks.extend(row_networks)

    if selected_rows == 0 or not selected_networks:
        raise BuildError("Zscaler ZPA JSON contains no connector Public Service Edge rows")
    selected_ipv4 = {
        network for network in selected_networks if isinstance(network, ipaddress.IPv4Network)
    }
    if not selected_ipv4:
        raise BuildError("Zscaler ZPA connector selection contains no IPv4 networks")
    selected_ipv6_entries = sum(
        1 for network in selected_networks if isinstance(network, ipaddress.IPv6Network)
    )
    return ParsedJson(
        selected_ipv4=tuple(sorted(selected_ipv4, key=network_sort_key)),
        all_networks=frozenset(all_networks),
        selected_rows=selected_rows,
        selected_raw_entries=selected_raw_entries,
        selected_ipv6_entries=selected_ipv6_entries,
        duplicate_entries_removed=len(selected_networks) - len(set(selected_networks)),
    )


def parse_zscaler_plaintext(payload: bytes) -> frozenset[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BuildError("Zscaler ZPA plaintext export is not ASCII") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise BuildError("Zscaler ZPA plaintext export is empty")
    return frozenset(
        validate_network(line, label="Zscaler ZPA plaintext export") for line in lines
    )


def validate_page_data(
    payload: bytes,
) -> None:
    document = load_json(payload, label="Zscaler ZPA page data")
    if not isinstance(document, dict) or document.get("status") != "success":
        raise BuildError("Zscaler ZPA page data does not report success")
    data = document.get("data")
    if not isinstance(data, dict):
        raise BuildError("Zscaler ZPA page data has no data object")
    if data.get("name") != EXPECTED_PAGE_NAME or data.get("alias") != EXPECTED_PAGE_ALIAS:
        raise BuildError("Zscaler page data no longer identifies the expected ZPA page")
    body = data.get("body")
    if not isinstance(body, str) or not body.strip():
        raise BuildError("Zscaler ZPA page body is empty")
    visible_source = html.unescape(body)
    for url in (ZSCALER_ZPA_JSON_URL, ZSCALER_ZPA_PLAINTEXT_URL):
        if url not in visible_source:
            raise BuildError(f"Zscaler ZPA page no longer links its official export: {url}")
    for marker in (
        EXPECTED_CONNECTOR_SOURCE,
        "*.private.zscaler.com",
        "TCP/UDP",
        "443",
    ):
        if marker not in visible_source:
            raise BuildError(
                "Zscaler ZPA page no longer exposes the expected connector "
                f"Public Service Edge section marker: {marker}"
            )


def render_ipv4(networks: Iterable[ipaddress.IPv4Network]) -> str:
    ordered = sorted(set(networks), key=network_sort_key)
    if not ordered:
        raise BuildError("Refusing to render an empty Zscaler ZPA IPv4 EDL")
    return "".join(f"{network.with_prefixlen}\n" for network in ordered)


def parse_existing_metadata(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def build_publication(
    *,
    json_payload: bytes,
    plaintext_payload: bytes,
    page_payload: bytes,
    generated_at: str,
) -> Publication:
    parsed = parse_zscaler_json(json_payload)
    plaintext_networks = parse_zscaler_plaintext(plaintext_payload)
    if plaintext_networks != parsed.all_networks:
        json_only = sorted(parsed.all_networks - plaintext_networks, key=network_sort_key)
        text_only = sorted(plaintext_networks - parsed.all_networks, key=network_sort_key)
        raise BuildError(
            "Official Zscaler JSON/plaintext exports disagree "
            f"(JSON-only={len(json_only)}, plaintext-only={len(text_only)})"
        )
    validate_page_data(page_payload)

    ipv4_content = render_ipv4(parsed.selected_ipv4)
    source_hashes = {
        "json": sha256_bytes(json_payload),
        "plaintext": sha256_bytes(plaintext_payload),
        "pageData": sha256_bytes(page_payload),
    }
    metadata_document = {
        "schemaVersion": 1,
        "generatedAt": generated_at,
        "scope": "Zscaler ZPA Public Service Edges for App Connectors",
        "source": {
            "page": ZSCALER_ZPA_PAGE_URL,
            "pageData": ZSCALER_ZPA_PAGE_DATA_URL,
            "json": ZSCALER_ZPA_JSON_URL,
            "plaintext": ZSCALER_ZPA_PLAINTEXT_URL,
            "officialOnly": True,
            "sha256": source_hashes,
        },
        "selection": {
            "cloudName": EXPECTED_CLOUD_NAME,
            "source": EXPECTED_CONNECTOR_SOURCE,
            "protocol": "TCP/UDP",
            "port": 443,
            "requiredDomain": "*.private.zscaler.com",
            "selectedRows": parsed.selected_rows,
            "rawEntries": parsed.selected_raw_entries,
            "excludedValidIPv6Entries": parsed.selected_ipv6_entries,
            "duplicateEntriesRemoved": parsed.duplicate_entries_removed,
        },
        "crossChecks": {
            "jsonEqualsPlaintext": True,
            "visiblePageIdentityAndExportLinksValidated": True,
            "visiblePageConnectorSectionValidated": True,
            "outputEqualsJsonConnectorIpv4Selection": True,
            "allOfficialUniqueIpNetworks": len(parsed.all_networks),
        },
        "output": {
            "file": ZSCALER_ZPA_FILE,
            "type": "Palo Alto IP List",
            "ipVersion": 4,
            "entries": len(parsed.selected_ipv4),
            "sha256": sha256_bytes(ipv4_content.encode("ascii")),
        },
        "failSafe": {
            "emptyOutputRejected": True,
            "invalidOrNonPublicNetworkRejected": True,
            "maximumCountVariation": "50%",
            "atomicPublication": True,
        },
    }
    return Publication(
        ipv4_networks=parsed.selected_ipv4,
        metadata=json.dumps(
            metadata_document, indent=2, ensure_ascii=True, sort_keys=True
        )
        + "\n",
        source_hashes=source_hashes,
    )


def count_existing_entries(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise BuildError(f"Unable to read previous Zscaler ZPA EDL: {exc}") from exc
    return sum(1 for line in lines if line.strip() and not line.lstrip().startswith("#"))


def check_count_variation(path: Path, new_count: int) -> None:
    if new_count <= 0:
        raise BuildError("Refusing to publish an empty Zscaler ZPA EDL")
    old_count = count_existing_entries(path)
    if not old_count:
        return
    ratio = abs(new_count - old_count) / old_count
    if ratio > MAX_COUNT_CHANGE_RATIO:
        raise BuildError(
            f"Refusing {path.name}: abnormal entry-count variation "
            f"({old_count} -> {new_count}, {ratio:.1%})"
        )


def publication_is_unchanged(
    *,
    output_path: Path,
    metadata_path: Path,
    index_path: Path,
    ipv4_content: str,
    publication: Publication,
) -> bool:
    if not output_path.is_file():
        return False
    try:
        if output_path.read_text(encoding="ascii") != ipv4_content:
            return False
    except (OSError, UnicodeDecodeError):
        return False
    previous = parse_existing_metadata(metadata_path)
    if previous is None:
        return False
    hashes = previous.get("source", {}).get("sha256")
    output = previous.get("output", {})
    checks = previous.get("crossChecks", {})
    expected_hash = sha256_bytes(ipv4_content.encode("ascii"))
    if (
        hashes != publication.source_hashes
        or output.get("file") != ZSCALER_ZPA_FILE
        or output.get("entries") != len(publication.ipv4_networks)
        or output.get("sha256") != expected_hash
        or not all(
            checks.get(name) is True
            for name in (
                "jsonEqualsPlaintext",
                "visiblePageIdentityAndExportLinksValidated",
                "visiblePageConnectorSectionValidated",
                "outputEqualsJsonConnectorIpv4Selection",
            )
        )
    ):
        return False
    try:
        index = index_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return f'href="{ZSCALER_ZPA_FILE}"' in index


def publish(
    *,
    output_dir: Path,
    generated_at: str,
    publication: Publication,
) -> bool:
    output_path = output_dir / ZSCALER_ZPA_FILE
    metadata_path = output_dir / ZSCALER_ZPA_METADATA_FILE
    index_path = output_dir / INDEX_FILE
    ipv4_content = render_ipv4(publication.ipv4_networks)
    check_count_variation(output_path, len(publication.ipv4_networks))
    if publication_is_unchanged(
        output_path=output_path,
        metadata_path=metadata_path,
        index_path=index_path,
        ipv4_content=ipv4_content,
        publication=publication,
    ):
        print("No Zscaler ZPA source or EDL content change detected")
        return False

    index_content = build_index(
        generated_at,
        {},
        output_dir=output_dir,
        supplemental_counts={ZSCALER_ZPA_FILE: len(publication.ipv4_networks)},
    )
    rendered = {
        ZSCALER_ZPA_FILE: ipv4_content,
        ZSCALER_ZPA_METADATA_FILE: publication.metadata,
        INDEX_FILE: index_content,
    }
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="zscaler-zpa-edl-", dir=output_dir.parent
    ) as temporary_name:
        temporary = Path(temporary_name)
        for relative, content in rendered.items():
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                content,
                encoding="ascii" if relative.endswith(".txt") else "utf-8",
                newline="\n",
            )
        output_dir.mkdir(parents=True, exist_ok=True)
        for relative in rendered:
            destination = output_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(temporary / relative, destination)
    print(
        f"{ZSCALER_ZPA_FILE}: {len(publication.ipv4_networks)} validated IPv4 CIDRs"
    )
    print("Official JSON, plaintext, and visible-page data cross-check: passed")
    return True


def source_payload(
    *,
    override: Path | None,
    url: str,
    timeout: float,
    accept: str,
    label: str,
) -> bytes:
    if override is not None:
        return read_source_file(override, label=label)
    return fetch_https(url, timeout=timeout, accept=accept)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("docs"))
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json-source-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--plaintext-source-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--page-source-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--generated-at", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.timeout <= 0:
            raise BuildError("--timeout must be positive")
        generated_at = args.generated_at or utc_now()
        json_payload = source_payload(
            override=args.json_source_file,
            url=ZSCALER_ZPA_JSON_URL,
            timeout=args.timeout,
            accept="application/json",
            label="Zscaler ZPA JSON export",
        )
        plaintext_payload = source_payload(
            override=args.plaintext_source_file,
            url=ZSCALER_ZPA_PLAINTEXT_URL,
            timeout=args.timeout,
            accept="text/plain",
            label="Zscaler ZPA plaintext export",
        )
        page_payload = source_payload(
            override=args.page_source_file,
            url=ZSCALER_ZPA_PAGE_DATA_URL,
            timeout=args.timeout,
            accept="application/json",
            label="Zscaler ZPA visible page data",
        )
        publication = build_publication(
            json_payload=json_payload,
            plaintext_payload=plaintext_payload,
            page_payload=page_payload,
            generated_at=generated_at,
        )
        publish(
            output_dir=args.output_dir,
            generated_at=generated_at,
            publication=publication,
        )
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
