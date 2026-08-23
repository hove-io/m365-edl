#!/usr/bin/env python3
"""Build conservative historical Log4Shell IOC EDLs with provenance.

Only structured incident IOCs and explicitly selected payload/C2 sections are
accepted. Broad scanner lists, owner-only attribution, and opportunistic number
extraction are intentionally out of scope for this blocking-oriented feed.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

if __package__:
    from scripts.generate_edl import build_index
else:
    from generate_edl import build_index


IPV4_FILE = "log4j-ipv4.txt"
DOMAIN_FILE = "log4j-domains.txt"
METADATA_FILE = "metadata/log4j.json"
INDEX_FILE = "index.html"
MAX_SOURCE_BYTES = 5 * 1024 * 1024
USER_AGENT = "hove-io-m365-edl-log4j/1.0"
CVES = (
    "CVE-2021-44228",
    "CVE-2021-45046",
    "CVE-2021-45105",
    "CVE-2021-44832",
)


class BuildError(RuntimeError):
    """Raised when validation must stop publication."""


@dataclass(frozen=True)
class SourceDefinition:
    source_id: str
    organization: str
    url: str
    reference_url: str
    last_updated_known: str
    parser: Callable[[bytes], "ParsedSource"]
    evidence_scope: str


@dataclass
class ParsedSource:
    ipv4_candidates: list[str] = field(default_factory=list)
    domain_candidates: list[str] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)
    parser_details: dict[str, object] = field(default_factory=dict)


@dataclass
class RetrievedSource:
    definition: SourceDefinition
    payload: bytes
    retrieved_at: str
    transport: str
    parsed: ParsedSource


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def element_text(element: ET.Element) -> str:
    return "".join(element.itertext()).strip()


def parse_cisa_stix(payload: bytes) -> ParsedSource:
    """Read only typed STIX Address and DomainName objects."""
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise BuildError(f"Invalid CISA STIX XML: {exc}") from exc

    xsi_type = "{http://www.w3.org/2001/XMLSchema-instance}type"
    result = ParsedSource()
    address_objects = 0
    domain_objects = 0
    for properties in root.iter():
        if local_name(properties.tag) != "Properties":
            continue
        object_type = properties.attrib.get(xsi_type, "").split(":")[-1]
        if object_type == "AddressObjectType":
            if properties.attrib.get("category") != "ipv4-addr":
                continue
            values = [
                element_text(child)
                for child in properties.iter()
                if local_name(child.tag) == "Address_Value"
                and child.attrib.get("condition", "Equals") == "Equals"
            ]
            if len(values) != 1 or not values[0]:
                raise BuildError("CISA STIX IPv4 object has no single Equals value")
            result.ipv4_candidates.append(values[0])
            address_objects += 1
        elif object_type == "DomainNameObjectType":
            values = [
                element_text(child)
                for child in properties.iter()
                if local_name(child.tag) == "Value"
                and child.attrib.get("condition", "Equals") == "Equals"
            ]
            if len(values) != 1 or not values[0]:
                raise BuildError("CISA STIX domain object has no single Equals value")
            domain = values[0].rstrip(".").lower()
            if domain == "transfer.sh":
                result.rejected.append(
                    {
                        "value": domain,
                        "type": "domain",
                        "reason": "legitimate shared file-transfer service; not safe for domain blocking",
                    }
                )
            else:
                result.domain_candidates.append(domain)
            domain_objects += 1

    if address_objects == 0:
        raise BuildError("CISA STIX source contains no typed ipv4-addr objects")
    result.parser_details = {
        "format": "STIX XML",
        "acceptedObjectTypes": ["AddressObjectType/ipv4-addr", "DomainNameObjectType"],
        "addressObjects": address_objects,
        "domainObjects": domain_objects,
    }
    return result


UNIT42_SECTIONS = {
    "v8-password-stealer": 1,
    "happy-everyday-cobaltstrike": 1,
    "coinminer": 4,
}
DEFANGED_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\[\.\]|\.)){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])"
    r"(?![A-Za-z0-9])"
)
DEFANGED_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\[\.\])+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9-])"
)


class Unit42SectionParser(HTMLParser):
    """Capture text only from the audited payload/C2 sections."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.current_section: str | None = None
        self.parts: dict[str, list[str]] = {name: [] for name in UNIT42_SECTIONS}
        self.seen_sections: set[str] = set()

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag not in {"h2", "h3"}:
            return
        attributes = dict(attrs)
        section_id = attributes.get("id")
        self.current_section = section_id if section_id in UNIT42_SECTIONS else None
        if self.current_section is not None:
            self.seen_sections.add(self.current_section)

    def handle_data(self, data: str) -> None:
        if self.current_section is not None:
            self.parts[self.current_section].append(data)


def parse_unit42(payload: bytes) -> ParsedSource:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuildError("Unit 42 article is not valid UTF-8") from exc
    parser = Unit42SectionParser()
    parser.feed(text)
    missing = sorted(set(UNIT42_SECTIONS) - parser.seen_sections)
    if missing:
        raise BuildError(f"Unit 42 audited sections missing: {', '.join(missing)}")

    result = ParsedSource()
    counts: dict[str, int] = {}
    for section, minimum in UNIT42_SECTIONS.items():
        section_text = " ".join(parser.parts[section])
        addresses = [
            match.replace("[.]", ".")
            for match in DEFANGED_IPV4_RE.findall(section_text)
            if "[.]" in match
        ]
        domains = [
            match.replace("[.]", ".").lower()
            for match in DEFANGED_DOMAIN_RE.findall(section_text)
        ]
        counts[section] = len(set(addresses))
        if counts[section] < minimum:
            raise BuildError(
                f"Unit 42 section {section!r} returned {counts[section]} IPv4 IOCs; expected at least {minimum}"
            )
        result.ipv4_candidates.extend(addresses)
        result.domain_candidates.extend(domains)
    result.parser_details = {
        "format": "HTML",
        "acceptedSections": sorted(UNIT42_SECTIONS),
        "uniqueIPv4BySection": counts,
        "excludedScope": "mass-scanner, vulnerable-server-discovery, and unrelated article sections",
    }
    return result


SOURCES = (
    SourceDefinition(
        source_id="cisa-aa22-320a",
        organization="CISA",
        url="https://www.cisa.gov/sites/default/files/publications/AA22-320A.stix.xml",
        reference_url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a",
        last_updated_known="2022-11-25",
        parser=parse_cisa_stix,
        evidence_scope="STIX indicators from a confirmed Log4Shell compromise incident",
    ),
    SourceDefinition(
        source_id="cisa-aa22-174a",
        organization="CISA",
        url="https://www.cisa.gov/sites/default/files/publications/AA22-174A.stix.xml",
        reference_url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-174a",
        last_updated_known="2022-07-18",
        parser=parse_cisa_stix,
        evidence_scope="STIX indicators from a confirmed Log4Shell exploitation incident",
    ),
    SourceDefinition(
        source_id="unit42-log4j-payload-c2",
        organization="Palo Alto Networks Unit 42",
        url="https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/",
        reference_url="https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/",
        last_updated_known="2022-02-02 observation cutoff",
        parser=parse_unit42,
        evidence_scope="Only audited V8 stealer, Cobalt Strike, and coinminer payload/C2 sections",
    ),
)


EVALUATED_NOT_USED = (
    {
        "name": "CISA AA21-356A and Curated Intelligence scanner list",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a",
        "reason": "CISA describes the list as low-to-medium confidence and warns that scanner activity includes researchers and vendors; unsuitable as a production deny list.",
    },
    {
        "name": "Microsoft Sentinel Log4j IP IOC sample feed",
        "url": "https://github.com/Azure/Azure-Sentinel/blob/master/Sample%20Data/Feeds/Log4j_IOC_List.csv",
        "reason": "Historical mass-scan sample without per-indicator role or confidence; retained for hunting, not blocking.",
    },
    {
        "name": "NCSC-NL Log4Shell IOC catalog",
        "url": "https://github.com/NCSC-NL/log4shell/tree/main/iocs",
        "reason": "Archived link catalog whose maintainers state that the listed IOCs were not verified.",
    },
    {
        "name": "CERT-EU 2021-067 and CERT/CC VU#930724",
        "url": "https://cert.europa.eu/publications/security-advisories/2021-067/",
        "reason": "Authoritative vulnerability context but no structured, high-confidence IP feed for deterministic ingestion.",
    },
    {
        "name": "Unit 42 mass-scanning and vulnerable-server-discovery sections",
        "url": "https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/",
        "reason": "Scanner infrastructure and victim-discovery observations are deliberately excluded from permanent blocking.",
    },
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def fetch_https(
    url: str, *, timeout: float, max_bytes: int = MAX_SOURCE_BYTES
) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise BuildError(f"Refusing non-HTTPS source URL: {url}")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/xml,text/html;q=0.9,*/*;q=0.1",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=ssl.create_default_context()
        ) as response:
            final_url = response.geturl()
            if urlparse(final_url).scheme != "https":
                raise BuildError(f"Source redirected outside HTTPS: {final_url}")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise BuildError(f"Source exceeds {max_bytes} bytes: {url}")
            payload = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise BuildError(f"Unable to retrieve {url}: {exc}") from exc
        payload = fetch_https_with_curl(url, timeout=timeout, max_bytes=max_bytes)
    except urllib.error.URLError:
        payload = fetch_https_with_curl(url, timeout=timeout, max_bytes=max_bytes)
    except (TimeoutError, OSError, ValueError) as exc:
        raise BuildError(f"Unable to retrieve {url}: {exc}") from exc
    if len(payload) > max_bytes:
        raise BuildError(f"Source exceeds {max_bytes} bytes: {url}")
    if not payload.strip():
        raise BuildError(f"Source is empty: {url}")
    return payload


def fetch_https_with_curl(url: str, *, timeout: float, max_bytes: int) -> bytes:
    """Use curl for official sites whose WAF rejects Python's HTTP fingerprint."""
    command = [
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
        str(max(1, int(timeout))),
        "--max-time",
        str(max(1, int(timeout))),
        "--max-filesize",
        str(max_bytes),
        "--header",
        "Accept: application/xml,text/html;q=0.9,*/*;q=0.1",
        "--header",
        f"User-Agent: Mozilla/5.0 (compatible; {USER_AGENT}; +https://github.com/hove-io/m365-edl)",
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
    if len(result.stdout) > max_bytes:
        raise BuildError(f"Source exceeds {max_bytes} bytes: {url}")
    return result.stdout


def normalize_ipv4(value: str) -> str | None:
    candidate = value.strip()
    try:
        network = ipaddress.ip_network(candidate, strict=True)
    except ValueError:
        return None
    if network.version != 4 or network.prefixlen == 0 or not network.is_global:
        return None
    if (
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    ):
        return None
    if network.prefixlen == 32:
        return str(network.network_address)
    return network.with_prefixlen


DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def normalize_domain(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253 or "*" in candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    labels = candidate.split(".")
    if len(labels) < 2 or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return None
    if not re.search(r"[a-z]", labels[-1]):
        return None
    return candidate


def ipv4_sort_key(value: str) -> tuple[int, int]:
    network = ipaddress.ip_network(value, strict=True)
    return int(network.network_address), network.prefixlen


def render_lines(values: Iterable[str], *, ip_values: bool) -> str:
    unique = set(values)
    ordered = sorted(unique, key=ipv4_sort_key) if ip_values else sorted(unique)
    return "".join(f"{value}\n" for value in ordered)


def count_edl_entries(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def check_drop_guard(path: Path, new_count: int) -> None:
    old_count = count_edl_entries(path)
    if old_count and new_count * 2 < old_count:
        raise BuildError(
            f"Refusing {path.name}: entry count fell by more than 50% ({old_count} -> {new_count})"
        )


def parse_source_overrides(items: list[str]) -> dict[str, Path]:
    known = {source.source_id for source in SOURCES}
    overrides: dict[str, Path] = {}
    for item in items:
        source_id, separator, raw_path = item.partition("=")
        if not separator or source_id not in known or not raw_path:
            raise BuildError(f"Invalid --source-file value: {item}")
        if source_id in overrides:
            raise BuildError(f"Duplicate --source-file source: {source_id}")
        overrides[source_id] = Path(raw_path)
    return overrides


def retrieve_sources(
    *, timeout: float, source_files: dict[str, Path], retrieved_at: str
) -> list[RetrievedSource]:
    retrieved: list[RetrievedSource] = []
    for definition in SOURCES:
        if definition.source_id in source_files:
            path = source_files[definition.source_id]
            try:
                payload = path.read_bytes()
            except OSError as exc:
                raise BuildError(f"Unable to read source fixture {path}: {exc}") from exc
            transport = f"local override: {path.name}"
        else:
            payload = fetch_https(definition.url, timeout=timeout)
            transport = "HTTPS with certificate validation"
        if not payload.strip():
            raise BuildError(f"Source is empty: {definition.source_id}")
        parsed = definition.parser(payload)
        if not parsed.ipv4_candidates and not parsed.domain_candidates:
            raise BuildError(
                f"Source returned no accepted IOC candidates: {definition.source_id}"
            )
        retrieved.append(
            RetrievedSource(
                definition=definition,
                payload=payload,
                retrieved_at=retrieved_at,
                transport=transport,
                parsed=parsed,
            )
        )
    return retrieved


def aggregate_sources(
    retrieved: list[RetrievedSource],
) -> tuple[dict[str, set[str]], dict[str, set[str]], list[dict[str, object]]]:
    ipv4_provenance: dict[str, set[str]] = {}
    domain_provenance: dict[str, set[str]] = {}
    source_metadata: list[dict[str, object]] = []
    for source in retrieved:
        rejected = list(source.parsed.rejected)
        accepted_ipv4: set[str] = set()
        accepted_domains: set[str] = set()
        for candidate in source.parsed.ipv4_candidates:
            normalized = normalize_ipv4(candidate)
            if normalized is None:
                rejected.append(
                    {
                        "value": candidate,
                        "type": "ipv4",
                        "reason": "invalid or non-public IPv4/CIDR",
                    }
                )
                continue
            accepted_ipv4.add(normalized)
            ipv4_provenance.setdefault(normalized, set()).add(source.definition.source_id)
        for candidate in source.parsed.domain_candidates:
            normalized = normalize_domain(candidate)
            if normalized is None:
                rejected.append(
                    {"value": candidate, "type": "domain", "reason": "invalid domain"}
                )
                continue
            accepted_domains.add(normalized)
            domain_provenance.setdefault(normalized, set()).add(source.definition.source_id)
        if not accepted_ipv4 and not accepted_domains:
            raise BuildError(f"All IOC candidates were rejected: {source.definition.source_id}")
        source_metadata.append(
            {
                "id": source.definition.source_id,
                "organization": source.definition.organization,
                "url": source.definition.url,
                "referenceUrl": source.definition.reference_url,
                "reference_url": source.definition.reference_url,
                "status": "retrieved-and-validated",
                "maintenance_status": "historical",
                "lastUpdatedKnown": source.definition.last_updated_known,
                "last_updated_known": source.definition.last_updated_known,
                "retrievedAt": source.retrieved_at,
                "retrieved_at": source.retrieved_at,
                "transport": source.transport,
                "evidenceScope": source.definition.evidence_scope,
                "evidence_scope": source.definition.evidence_scope,
                "sha256": sha256_bytes(source.payload),
                "bytes": len(source.payload),
                "counts": {
                    "rawIPv4Candidates": len(source.parsed.ipv4_candidates),
                    "rawDomainCandidates": len(source.parsed.domain_candidates),
                    "acceptedUniqueIPv4": len(accepted_ipv4),
                    "acceptedUniqueDomains": len(accepted_domains),
                    "rejected": len(rejected),
                },
                "parser": source.parsed.parser_details,
                "rejected": sorted(rejected, key=lambda item: (item["type"], item["value"])),
            }
        )
    return ipv4_provenance, domain_provenance, source_metadata


def indicator_metadata(
    provenance: dict[str, set[str]],
    sources_by_id: dict[str, SourceDefinition],
    kind: str,
) -> list[dict[str, object]]:
    values = (
        sorted(provenance, key=ipv4_sort_key)
        if kind == "ipv4"
        else sorted(provenance)
    )
    return [
        {
            "value": value,
            "type": kind,
            "sources": [
                {
                    "id": source_id,
                    "organization": sources_by_id[source_id].organization,
                    "url": sources_by_id[source_id].reference_url,
                }
                for source_id in sorted(provenance[value])
            ],
        }
        for value in values
    ]


def build_metadata(
    *,
    generated_at: str,
    source_metadata: list[dict[str, object]],
    ipv4_provenance: dict[str, set[str]],
    domain_provenance: dict[str, set[str]],
    ipv4_content: str,
    domain_content: str,
) -> str:
    sources_by_id = {source.source_id: source for source in SOURCES}
    raw_ipv4_count = sum(
        int(source["counts"]["rawIPv4Candidates"]) for source in source_metadata
    )
    raw_domain_count = sum(
        int(source["counts"]["rawDomainCandidates"]) for source in source_metadata
    )
    rejected_count = sum(
        int(source["counts"]["rejected"]) for source in source_metadata
    )
    document = {
        "schemaVersion": 1,
        "generatedAt": generated_at,
        "generated_at": generated_at,
        "classification": "historical-curated-incident-iocs",
        "cves": list(CVES),
        "warning": (
            "Historical Log4Shell indicators are not real-time reputation and are not standalone protection. "
            "Patch Log4j, use IPS, segment vulnerable systems, and restrict unexpected LDAP/RMI egress."
        ),
        "policy": {
            "purpose": "Conservative Palo Alto deny-list companion for historical Log4Shell infrastructure",
            "publicIPv4Only": True,
            "manualIndicators": False,
            "broadCloudOrCdnPrefixes": False,
            "massScannersExcluded": True,
            "maximumAllowedDrop": "50%",
        },
        "counts": {
            "rawIPv4Candidates": raw_ipv4_count,
            "rawDomainCandidates": raw_domain_count,
            "rejected": rejected_count,
            "finalUniqueIPv4": len(ipv4_provenance),
            "finalUniqueDomains": len(domain_provenance),
        },
        "sources": source_metadata,
        "evaluatedButNotUsed": list(EVALUATED_NOT_USED),
        "outputs": {
            IPV4_FILE: {
                "type": "Palo Alto IP List",
                "entries": len(ipv4_provenance),
                "sha256": sha256_bytes(ipv4_content.encode("ascii")),
            },
            DOMAIN_FILE: {
                "type": "Palo Alto Domain List",
                "entries": len(domain_provenance),
                "sha256": sha256_bytes(domain_content.encode("ascii")),
            },
        },
        "indicators": {
            "ipv4": indicator_metadata(ipv4_provenance, sources_by_id, "ipv4"),
            "domains": indicator_metadata(domain_provenance, sources_by_id, "domain"),
        },
    }
    return json.dumps(document, indent=2, ensure_ascii=True, sort_keys=True) + "\n"


def publish(
    *,
    output_dir: Path,
    generated_at: str,
    ipv4_provenance: dict[str, set[str]],
    domain_provenance: dict[str, set[str]],
    source_metadata: list[dict[str, object]],
) -> bool:
    if not ipv4_provenance:
        raise BuildError("Refusing to publish an empty IPv4 EDL")
    if not domain_provenance:
        raise BuildError("Refusing to publish an empty domain EDL")
    ipv4_content = render_lines(ipv4_provenance, ip_values=True)
    domain_content = render_lines(domain_provenance, ip_values=False)
    check_drop_guard(output_dir / IPV4_FILE, len(ipv4_provenance))
    check_drop_guard(output_dir / DOMAIN_FILE, len(domain_provenance))
    metadata_content = build_metadata(
        generated_at=generated_at,
        source_metadata=source_metadata,
        ipv4_provenance=ipv4_provenance,
        domain_provenance=domain_provenance,
        ipv4_content=ipv4_content,
        domain_content=domain_content,
    )
    index_content = build_index(
        generated_at,
        {},
        output_dir=output_dir,
        supplemental_counts={
            IPV4_FILE: len(ipv4_provenance),
            DOMAIN_FILE: len(domain_provenance),
        },
    )
    rendered = {
        IPV4_FILE: ipv4_content,
        DOMAIN_FILE: domain_content,
        METADATA_FILE: metadata_content,
        INDEX_FILE: index_content,
    }
    changed = any(
        not (output_dir / relative).is_file()
        or (output_dir / relative).read_text(
            encoding="ascii" if relative.endswith(".txt") else "utf-8"
        )
        != content
        for relative, content in rendered.items()
    )
    if not changed:
        print("No Log4Shell publication content change detected")
        return False

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="log4j-edl-", dir=output_dir.parent
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
    print(f"{IPV4_FILE}: {len(ipv4_provenance)} public historical IPv4 indicators")
    print(f"{DOMAIN_FILE}: {len(domain_provenance)} historical domain indicators")
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("docs"))
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--source-file",
        action="append",
        default=[],
        metavar="SOURCE_ID=PATH",
        help="Use a local source payload (tests and reproducible offline generation)",
    )
    parser.add_argument("--generated-at", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.timeout <= 0:
            raise BuildError("--timeout must be positive")
        generated_at = args.generated_at or utc_now()
        source_files = parse_source_overrides(args.source_file)
        retrieved = retrieve_sources(
            timeout=args.timeout, source_files=source_files, retrieved_at=generated_at
        )
        ipv4_provenance, domain_provenance, source_metadata = aggregate_sources(retrieved)
        publish(
            output_dir=args.output_dir,
            generated_at=generated_at,
            ipv4_provenance=ipv4_provenance,
            domain_provenance=domain_provenance,
            source_metadata=source_metadata,
        )
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
