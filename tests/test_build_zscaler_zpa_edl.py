import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_zscaler_zpa_edl import (
    BuildError,
    EXPECTED_CONNECTOR_SOURCE,
    ZSCALER_ZPA_JSON_URL,
    ZSCALER_ZPA_PLAINTEXT_URL,
    build_publication,
    check_count_variation,
    main,
    parse_zscaler_json,
)
from scripts.generate_edl import ZSCALER_ZPA_FILE


def connector_row(values: list[str]) -> dict[str, object]:
    return {
        "IP Protocol": "TCP/UDP",
        "Port": 443,
        "Source": EXPECTED_CONNECTOR_SOURCE,
        "Domains": "*.prod.zpath.net,*.private.zscaler.com,*.prod.zpath.vip",
        "IPs": values,
        "Date Added": "Test fixture",
    }


def json_payload(*rows: dict[str, object]) -> bytes:
    return json.dumps(
        {"Cloud Name": "private.zscaler.com", "content": list(rows)}
    ).encode("utf-8")


def page_payload(*, alias: str = "zpa", include_section: bool = True) -> bytes:
    section = (
        f"<p>{EXPECTED_CONNECTOR_SOURCE}</p>"
        "<p>TCP/UDP 443 *.private.zscaler.com</p>"
        if include_section
        else "<p>Unexpected layout</p>"
    )
    body = (
        f'<a href="{ZSCALER_ZPA_JSON_URL}">JSON formatted</a>'
        f'<a href="{ZSCALER_ZPA_PLAINTEXT_URL}">Plaintext</a>'
        f"{section}"
    )
    return json.dumps(
        {
            "status": "success",
            "data": {
                "name": "Zscaler Private Access (ZPA)",
                "alias": alias,
                "body": body,
                "modules": [],
            },
        }
    ).encode("utf-8")


class ZscalerZpaParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connector_values = [
            "8.8.8.0/24",
            "1.1.1.1/32",
            "8.8.8.0/24",
            "2606:4700:4700::1111/128",
        ]
        self.browser_row = {
            "IP Protocol": "TCP/UDP",
            "Port": 443,
            "Source": "Browser Access",
            "Domains": "*.zpa-auth.net,*.zpa-app.net",
            "IPs": ["9.9.9.9"],
            "Date Added": "Test fixture",
        }
        self.json = json_payload(
            connector_row(self.connector_values), self.browser_row
        )
        self.plaintext = (
            "9.9.9.9\n"
            "2606:4700:4700::1111/128\n"
            "1.1.1.1/32\n"
            "8.8.8.0/24\n"
        ).encode("ascii")

    def test_nominal_parsing_selects_only_connector_ipv4(self) -> None:
        parsed = parse_zscaler_json(self.json)

        self.assertEqual(
            [network.with_prefixlen for network in parsed.selected_ipv4],
            ["1.1.1.1/32", "8.8.8.0/24"],
        )
        self.assertEqual(parsed.selected_rows, 1)
        self.assertEqual(parsed.selected_ipv6_entries, 1)
        self.assertEqual(parsed.duplicate_entries_removed, 1)

    def test_build_cross_checks_json_plaintext_and_visible_page(self) -> None:
        publication = build_publication(
            json_payload=self.json,
            plaintext_payload=self.plaintext,
            page_payload=page_payload(),
            generated_at="2026-08-30T00:00:00Z",
        )

        self.assertEqual(len(publication.ipv4_networks), 2)
        metadata = json.loads(publication.metadata)
        self.assertTrue(metadata["crossChecks"]["jsonEqualsPlaintext"])
        self.assertTrue(
            metadata["crossChecks"]["outputEqualsJsonConnectorIpv4Selection"]
        )

    def test_rejects_invalid_ip_value(self) -> None:
        payload = json_payload(connector_row(["8.8.8.0/24", "not-an-ip"]))

        with self.assertRaisesRegex(BuildError, "invalid IP/CIDR"):
            parse_zscaler_json(payload)

    def test_rejects_non_public_network(self) -> None:
        payload = json_payload(connector_row(["10.0.0.0/8"]))

        with self.assertRaisesRegex(BuildError, "non-public"):
            parse_zscaler_json(payload)

    def test_rejects_empty_connector_selection(self) -> None:
        payload = json_payload(self.browser_row)

        with self.assertRaisesRegex(BuildError, "no connector Public Service Edge"):
            parse_zscaler_json(payload)

    def test_rejects_changed_page_identity(self) -> None:
        with self.assertRaisesRegex(BuildError, "expected ZPA page"):
            build_publication(
                json_payload=self.json,
                plaintext_payload=self.plaintext,
                page_payload=page_payload(alias="changed"),
                generated_at="2026-08-30T00:00:00Z",
            )

    def test_rejects_page_without_expected_connector_section(self) -> None:
        with self.assertRaisesRegex(BuildError, "section marker"):
            build_publication(
                json_payload=self.json,
                plaintext_payload=self.plaintext,
                page_payload=page_payload(include_section=False),
                generated_at="2026-08-30T00:00:00Z",
            )

    def test_rejects_json_plaintext_disagreement(self) -> None:
        with self.assertRaisesRegex(BuildError, "exports disagree"):
            build_publication(
                json_payload=self.json,
                plaintext_payload=b"1.1.1.1/32\n",
                page_payload=page_payload(),
                generated_at="2026-08-30T00:00:00Z",
            )

    def test_rejects_abnormal_entry_count_variation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            existing = Path(temporary_name) / "zpa_ipv4.txt"
            existing.write_text(
                "".join(f"8.8.8.{index}/32\n" for index in range(10)),
                encoding="ascii",
            )

            with self.assertRaisesRegex(BuildError, "abnormal entry-count variation"):
                check_count_variation(existing, 4)

            with self.assertRaisesRegex(BuildError, "abnormal entry-count variation"):
                check_count_variation(existing, 16)

    def test_parser_failure_preserves_last_valid_edl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            output_dir = root / "docs"
            output_path = output_dir / ZSCALER_ZPA_FILE
            output_path.parent.mkdir(parents=True)
            output_path.write_text("1.1.1.1/32\n", encoding="ascii")
            json_path = root / "zpa.json"
            plaintext_path = root / "zpa.txt"
            page_path = root / "page.json"
            json_path.write_bytes(json_payload(connector_row(["not-an-ip"])))
            plaintext_path.write_bytes(b"1.1.1.1/32\n")
            page_path.write_bytes(page_payload())

            with contextlib.redirect_stderr(io.StringIO()):
                result = main(
                    [
                        "--output-dir",
                        str(output_dir),
                        "--json-source-file",
                        str(json_path),
                        "--plaintext-source-file",
                        str(plaintext_path),
                        "--page-source-file",
                        str(page_path),
                    ]
                )

            self.assertEqual(result, 1)
            self.assertEqual(output_path.read_text(encoding="ascii"), "1.1.1.1/32\n")


if __name__ == "__main__":
    unittest.main()
