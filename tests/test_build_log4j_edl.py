import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from scripts.build_log4j_edl import (
    BuildError,
    DOMAIN_FILE,
    IPV4_FILE,
    ParsedSource,
    RetrievedSource,
    SOURCES,
    aggregate_sources,
    check_drop_guard,
    fetch_https,
    normalize_domain,
    normalize_ipv4,
    parse_cisa_stix,
    parse_unit42,
    publish,
    render_lines,
    retrieve_sources,
)


CISA_STIX = b"""<?xml version="1.0" encoding="UTF-8"?>
<stix:STIX_Package
 xmlns:stix="http://stix.mitre.org/stix-1"
 xmlns:cybox="http://cybox.mitre.org/cybox-2"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
 xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1">
  <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
    <AddressObj:Address_Value condition="Equals">8.8.8.8</AddressObj:Address_Value>
  </cybox:Properties>
  <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv6-addr">
    <AddressObj:Address_Value condition="Equals">2001:4860:4860::8888</AddressObj:Address_Value>
  </cybox:Properties>
  <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
    <DomainNameObj:Value condition="Equals">evil.example</DomainNameObj:Value>
  </cybox:Properties>
  <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
    <DomainNameObj:Value condition="Equals">transfer.sh</DomainNameObj:Value>
  </cybox:Properties>
</stix:STIX_Package>
"""


UNIT42_HTML = b"""<!doctype html><html><body>
<h3 id="mass-scanner">Mass scanners</h3><p>9.9.9[.]9</p>
<h3 id="v8-password-stealer">V8 password stealer</h3>
<p>Payload at 161.35.184[.]54 and C2 1ma[.]xyz.</p>
<h3 id="happy-everyday-cobaltstrike">Happy Everyday Cobalt Strike</h3>
<p>139.155.2[.]105</p>
<h3 id="coinminer">Coinminer</h3>
<p>192.46.216[.]224 165.22.2[.]186 150.60.139[.]51 68.183.165[.]105</p>
<h3 id="vulnerable-server-discovery">Discovery</h3><p>2.57.121[.]36</p>
</body></html>"""


class ValidationTests(unittest.TestCase):
    def test_accepts_public_ipv4_and_cidr(self) -> None:
        self.assertEqual(normalize_ipv4("8.8.8.8"), "8.8.8.8")
        self.assertEqual(normalize_ipv4("8.8.8.0/24"), "8.8.8.0/24")

    def test_rejects_invalid_ipv6_and_non_public_networks(self) -> None:
        rejected = (
            "not-an-ip",
            "2001:4860:4860::8888",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "192.0.2.1",
            "0.0.0.0/0",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertIsNone(normalize_ipv4(value))

    def test_domain_validation(self) -> None:
        self.assertEqual(normalize_domain("Example.COM."), "example.com")
        for value in ("*.example.com", "bad label.example", "8.8.8.8", "localhost"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_domain(value))

    def test_render_is_sorted_deduplicated_and_deterministic(self) -> None:
        values = ["9.9.9.9", "8.8.8.8", "9.9.9.9", "8.8.8.0/24"]
        expected = "8.8.8.0/24\n8.8.8.8\n9.9.9.9\n"
        self.assertEqual(render_lines(values, ip_values=True), expected)
        self.assertEqual(render_lines(reversed(values), ip_values=True), expected)


class SourceParserTests(unittest.TestCase):
    def test_cisa_parser_uses_typed_objects_and_rejects_shared_domain(self) -> None:
        parsed = parse_cisa_stix(CISA_STIX)
        self.assertEqual(parsed.ipv4_candidates, ["8.8.8.8"])
        self.assertEqual(parsed.domain_candidates, ["evil.example"])
        self.assertEqual(parsed.rejected[0]["value"], "transfer.sh")

    def test_cisa_parser_rejects_empty_or_untyped_source(self) -> None:
        with self.assertRaisesRegex(BuildError, "no typed ipv4-addr"):
            parse_cisa_stix(b"<root />")

    def test_unit42_parser_is_limited_to_audited_payload_sections(self) -> None:
        parsed = parse_unit42(UNIT42_HTML)
        self.assertEqual(
            set(parsed.ipv4_candidates),
            {
                "161.35.184.54",
                "139.155.2.105",
                "192.46.216.224",
                "165.22.2.186",
                "150.60.139.51",
                "68.183.165.105",
            },
        )
        self.assertEqual(parsed.domain_candidates, ["1ma.xyz"])
        self.assertNotIn("9.9.9.9", parsed.ipv4_candidates)
        self.assertNotIn("2.57.121.36", parsed.ipv4_candidates)

    def test_unit42_parser_fails_if_audited_section_disappears(self) -> None:
        with self.assertRaisesRegex(BuildError, "audited sections missing"):
            parse_unit42(b'<h3 id="coinminer">192.46.216[.]224</h3>')


class RetrievalAndGuardTests(unittest.TestCase):
    def test_source_unavailable_fails_closed(self) -> None:
        with patch(
            "scripts.build_log4j_edl.urllib.request.urlopen",
            side_effect=urllib.error.URLError("offline"),
        ), patch(
            "scripts.build_log4j_edl.fetch_https_with_curl",
            side_effect=BuildError("Unable to retrieve with curl: offline"),
        ):
            with self.assertRaisesRegex(BuildError, "Unable to retrieve"):
                fetch_https("https://example.invalid/source", timeout=1)

    def test_empty_source_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            empty = Path(temporary_name) / "empty.xml"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(BuildError, "Source is empty"):
                retrieve_sources(
                    timeout=1,
                    source_files={SOURCES[0].source_id: empty},
                    retrieved_at="2026-01-01T00:00:00Z",
                )

    def test_more_than_fifty_percent_drop_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            path = Path(temporary_name) / IPV4_FILE
            path.write_text("".join(f"8.8.8.{index}\n" for index in range(1, 11)), encoding="ascii")
            with self.assertRaisesRegex(BuildError, "more than 50%"):
                check_drop_guard(path, 4)
            check_drop_guard(path, 5)

    def test_aggregate_deduplicates_and_preserves_multi_source_provenance(self) -> None:
        first = RetrievedSource(
            SOURCES[0], b"one", "2026-01-01T00:00:00Z", "test", ParsedSource(["8.8.8.8"], ["evil.example"])
        )
        second = RetrievedSource(
            SOURCES[1], b"two", "2026-01-01T00:00:00Z", "test", ParsedSource(["8.8.8.8"], ["evil.example"])
        )
        ipv4, domains, metadata = aggregate_sources([first, second])
        self.assertEqual(ipv4["8.8.8.8"], {SOURCES[0].source_id, SOURCES[1].source_id})
        self.assertEqual(domains["evil.example"], {SOURCES[0].source_id, SOURCES[1].source_id})
        self.assertEqual(len(metadata), 2)


class PublicationTests(unittest.TestCase):
    def test_publication_is_reproducible_for_fixed_inputs_and_timestamp(self) -> None:
        generated_at = "2026-01-01T00:00:00Z"
        ipv4 = {"8.8.8.8": {SOURCES[0].source_id}}
        domains = {"evil.example": {SOURCES[0].source_id}}
        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first = Path(first_name) / "docs"
            second = Path(second_name) / "docs"
            publish(
                output_dir=first,
                generated_at=generated_at,
                ipv4_provenance=ipv4,
                domain_provenance=domains,
                source_metadata=[],
            )
            publish(
                output_dir=second,
                generated_at=generated_at,
                ipv4_provenance=ipv4,
                domain_provenance=domains,
                source_metadata=[],
            )
            for relative in (IPV4_FILE, DOMAIN_FILE, "metadata/log4j.json", "index.html"):
                self.assertEqual((first / relative).read_bytes(), (second / relative).read_bytes())
            metadata = json.loads((first / "metadata/log4j.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["generated_at"], generated_at)
            self.assertEqual(metadata["counts"]["finalUniqueIPv4"], 1)
            self.assertEqual(metadata["counts"]["finalUniqueDomains"], 1)
            self.assertEqual(metadata["outputs"][IPV4_FILE]["entries"], 1)
            self.assertEqual(metadata["outputs"][DOMAIN_FILE]["entries"], 1)


if __name__ == "__main__":
    unittest.main()
