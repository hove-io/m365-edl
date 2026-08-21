#!/usr/bin/env python3
"""Generate validated Microsoft 365 IPv4 EDL files."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


API_URL = "https://endpoints.office.com/endpoints/worldwide"
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
SERVICE_FILES = {
    "Common": "m365-common-ipv4.txt",
    "Exchange": "m365-exchange-ipv4.txt",
    "SharePoint": "m365-sharepoint-ipv4.txt",
    "Skype": "m365-teams-ipv4.txt",
}


class GenerationError(RuntimeError):
    """Raised when publishing a new EDL set would be unsafe."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("docs"))
    parser.add_argument("--input-file", type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--request-url", required=True)
    return parser.parse_args()


def load_payload(input_file: Path) -> Any:
    try:
        body = input_file.read_bytes()
    except OSError as error:
        raise GenerationError(f"Unable to read Microsoft response: {error}") from error

    if not body:
        raise GenerationError("Microsoft response is empty")
    if len(body) > MAX_RESPONSE_BYTES:
        raise GenerationError("Microsoft response exceeds the 10 MiB safety limit")

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GenerationError(f"Microsoft returned invalid JSON: {error}") from error

    return payload


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


def extract_service_networks(
    payload: Any,
) -> dict[str, list[ipaddress.IPv4Network]]:
    if not isinstance(payload, list) or not payload:
        raise GenerationError("Expected a non-empty JSON array from Microsoft")

    networks_by_area: dict[str, set[ipaddress.IPv4Network]] = {
        area: set() for area in SERVICE_FILES
    }

    for record_index, record in enumerate(payload):
        context = f"record {record_index}"
        if not isinstance(record, dict):
            raise GenerationError(f"Expected an object at {context}")

        service_area = record.get("serviceArea")
        if not isinstance(service_area, str):
            raise GenerationError(f"Missing or invalid serviceArea at {context}")
        if service_area not in SERVICE_FILES:
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
    for service_area, filename in SERVICE_FILES.items():
        networks = sorted(
            networks_by_area[service_area],
            key=lambda item: (int(item.network_address), item.prefixlen),
        )
        if not networks:
            raise GenerationError(
                f"Microsoft returned no public IPv4 CIDR for {service_area}"
            )
        result[filename] = networks
    return result


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


def build_sources(
    *,
    generated_at: str,
    request_id: str,
    request_url: str,
    record_count: int,
    generated: dict[str, list[ipaddress.IPv4Network]],
) -> str:
    files = {
        filename: {
            "serviceArea": service_area,
            "cidrCount": len(generated[filename]),
        }
        for service_area, filename in SERVICE_FILES.items()
    }
    document = {
        "generatedAt": generated_at,
        "source": {
            "publisher": "Microsoft",
            "name": "Microsoft 365 IP Address and URL web service",
            "instance": "Worldwide",
            "url": API_URL,
            "requestUrl": request_url,
            "clientRequestId": request_id,
            "responseRecordCount": record_count,
            "field": "ips",
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
    for service_area, filename in SERVICE_FILES.items():
        rows.append(
            "<tr>"
            f"<td>{html.escape(service_area)}</td>"
            f'<td><a href="{html.escape(filename)}">{html.escape(filename)}</a></td>'
            f"<td>{len(generated[filename])}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Microsoft 365 IPv4 EDLs</title>
    <style>
      :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
      body {{ max-width: 64rem; margin: 4rem auto; padding: 0 1.25rem; line-height: 1.55; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border-bottom: 1px solid #8888; padding: .65rem; text-align: left; }}
      code {{ overflow-wrap: anywhere; }}
    </style>
  </head>
  <body>
    <h1>Microsoft 365 IPv4 EDLs</h1>
    <p>Listes IPv4 publiques générées depuis le web service officiel Microsoft 365.</p>
    <table>
      <thead><tr><th>Service area</th><th>Fichier</th><th>CIDR</th></tr></thead>
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
        payload = load_payload(args.input_file)
        request_id = validate_request_id(args.request_id)
        generated = extract_service_networks(payload)
        publish(
            output_dir=args.output_dir,
            payload=payload,
            request_id=request_id,
            request_url=args.request_url,
            generated=generated,
        )
    except GenerationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
