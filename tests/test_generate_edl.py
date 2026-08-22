import ipaddress
import json
import unittest
from unittest.mock import patch

from scripts.generate_edl import (
    APPLE_SECTION_REQUIREMENTS,
    APPLE_XCODE_HOSTS,
    GenerationError,
    INTUNE_EVENT_WILDCARD_TARGETS,
    MICROSOFT_DELIVERY_OPTIMIZATION_URL,
    MICROSOFT_EDGE_WINDOWS_FILE,
    RESIDUAL_IPS,
    WINDOWS_UPDATE_WILDCARD_TARGETS,
    build_residual_coverage,
    expand_documented_hostnames,
    extract_apple_section_hostnames,
    extract_intune_consolidated_hostnames,
    extract_intune_windows_networks,
    extract_teams_media_networks,
    resolve_service_hostnames,
)


EXPECTED = [
    ipaddress.IPv4Network("52.112.0.0/14"),
    ipaddress.IPv4Network("52.120.0.0/14"),
]


class TeamsMediaParserTests(unittest.TestCase):
    def test_extracts_legacy_commercial_section_only(self) -> None:
        learn_html = """
        <h3>Media traffic: port ranges</h3>
        <h4>Microsoft 365, Office 365, and Office 365 GCC environments</h4>
        <p>52.112.0.0/14 52.120.0.0/14</p>
        <h4>Office 365 GCC High environment</h4>
        <p>52.127.88.0/21</p>
        <h4>Office 365 DoD environment</h4>
        <p>52.127.64.0/21</p>
        """

        self.assertEqual(extract_teams_media_networks(learn_html), EXPECTED)

    def test_extracts_current_commercial_section_only(self) -> None:
        learn_html = """
        <h2><span>Media processor IP ranges</span></h2>
        <h3>Microsoft 365 / Office 365</h3>
        <ul><li>52.112.0.0/14</li><li>52.120.0.0/14</li></ul>
        <h3>GCC High</h3>
        <ul><li>52.127.88.0/21</li></ul>
        <h3>DoD</h3>
        <ul><li>52.127.64.0/21</li></ul>
        """

        self.assertEqual(extract_teams_media_networks(learn_html), EXPECTED)

    def test_rejects_unexpected_commercial_range(self) -> None:
        learn_html = """
        <h2>Media processor IP ranges</h2>
        <h3>Microsoft 365 / Office 365</h3>
        <p>52.112.0.0/14 52.120.0.0/14 52.127.88.0/21</p>
        """

        with self.assertRaisesRegex(GenerationError, "Unexpected Teams media ranges"):
            extract_teams_media_networks(learn_html)


class IntuneConsolidatedParserTests(unittest.TestCase):
    SOURCE = """
## Consolidated Endpoint List

FQDNs
```
*.events.data.microsoft.com
manage.microsoft.com
```

IP Subnets
```
4.150.254.64/27
2620:1ec:40::/48
```

## Related content
"""

    def test_parses_fqdns_and_ipv4_subnets_independently(self) -> None:
        self.assertEqual(
            extract_intune_consolidated_hostnames(self.SOURCE),
            ["*.events.data.microsoft.com", "manage.microsoft.com"],
        )
        self.assertEqual(
            extract_intune_windows_networks(self.SOURCE),
            [ipaddress.IPv4Network("4.150.254.64/27")],
        )

    def test_expands_only_audited_intune_event_targets(self) -> None:
        hosts, wildcards, selected = expand_documented_hostnames(
            ["*.events.data.microsoft.com"],
            wildcard_targets=INTUNE_EVENT_WILDCARD_TARGETS,
            label="Microsoft Intune events",
        )

        self.assertEqual(wildcards, ["*.events.data.microsoft.com"])
        self.assertEqual(
            selected["*.events.data.microsoft.com"],
            INTUNE_EVENT_WILDCARD_TARGETS["*.events.data.microsoft.com"],
        )
        self.assertIn("us-mobile.events.data.microsoft.com", hosts)

    def test_windows_update_targets_are_dns_names_not_ip_overrides(self) -> None:
        targets = {
            hostname
            for hostnames in WINDOWS_UPDATE_WILDCARD_TARGETS.values()
            for hostname in hostnames
        }

        self.assertIn("array504.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("array508.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("array516.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("array808.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("disc601.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("kv601.prod.do.dsp.mp.microsoft.com", targets)
        for target in targets:
            with self.assertRaises(ValueError):
                ipaddress.ip_address(target)


class AppleEndpointTests(unittest.TestCase):
    def test_device_setup_section_is_guarded_and_parsed(self) -> None:
        rows = "".join(
            f"<tr><td>{hostname}</td><td>443</td><td>TCP</td>"
            "<td>iOS</td><td>Required</td><td>Purpose</td></tr>"
            for hostname in sorted(APPLE_SECTION_REQUIREMENTS["devicesetup"])
        )
        source = (
            '<h2 id="devicesetup">Device setup</h2><table>'
            "<tr><th>Hosts</th><th>Ports</th><th>Protocol</th>"
            "<th>OS</th><th>Availability</th><th>Description</th></tr>"
            f"{rows}</table>"
        )

        self.assertEqual(
            extract_apple_section_hostnames(source, section_id="devicesetup"),
            sorted(APPLE_SECTION_REQUIREMENTS["devicesetup"]),
        )

    def test_xcode_hosts_are_officially_scoped_and_exact(self) -> None:
        self.assertEqual(
            APPLE_XCODE_HOSTS,
            {"devimages-cdn.apple.com", "download.developer.apple.com"},
        )
        self.assertTrue(
            APPLE_XCODE_HOSTS.issubset(APPLE_SECTION_REQUIREMENTS["appscontent"])
        )


class DnsProvenanceTests(unittest.TestCase):
    @patch("scripts.generate_edl.time.sleep")
    @patch("scripts.generate_edl.socket.gethostbyname_ex")
    def test_records_cname_chain_and_all_public_a_records(
        self, gethostbyname_ex, sleep
    ) -> None:
        gethostbyname_ex.return_value = (
            "edge.example.net",
            ["service.example.test", "intermediate.example.net"],
            ["8.8.8.8", "9.9.9.9"],
        )

        networks, resolutions, chains, unresolved = resolve_service_hostnames(
            ["service.example.test"], label="test", attempts=2
        )

        self.assertEqual(
            networks,
            [
                ipaddress.IPv4Network("8.8.8.8/32"),
                ipaddress.IPv4Network("9.9.9.9/32"),
            ],
        )
        self.assertEqual(
            resolutions["service.example.test"],
            ["8.8.8.8", "9.9.9.9"],
        )
        self.assertEqual(
            chains["service.example.test"],
            ["intermediate.example.net", "edge.example.net"],
        )
        self.assertEqual(unresolved, {})
        sleep.assert_called_once()


class ResidualCoverageTests(unittest.TestCase):
    REQUIRED_IPS = {
        "72.153.5.61",
        "72.153.5.129",
        "72.153.5.137",
        "72.154.7.101",
        "17.248.209.16",
        "17.248.236.28",
        "17.253.29.146",
        "17.253.37.204",
        "17.188.170.10",
        "95.101.137.16",
        "95.101.137.21",
        "95.101.137.23",
        "95.101.137.24",
        "23.58.84.19",
        "151.101.1.64",
        "151.101.129.64",
    }

    def test_tracks_requested_ips_and_emits_provenance_schema(self) -> None:
        self.assertTrue(self.REQUIRED_IPS.issubset(RESIDUAL_IPS))
        document = json.loads(
            build_residual_coverage(
                generated_at="2026-08-22T00:00:00Z",
                generated={
                    MICROSOFT_EDGE_WINDOWS_FILE: [
                        ipaddress.IPv4Network("72.153.5.61/32")
                    ]
                },
                resolutions_by_file={
                    MICROSOFT_EDGE_WINDOWS_FILE: {
                        "array504.prod.do.dsp.mp.microsoft.com": ["72.153.5.61"]
                    }
                },
                cname_chains_by_file={
                    MICROSOFT_EDGE_WINDOWS_FILE: {
                        "array504.prod.do.dsp.mp.microsoft.com": []
                    }
                },
            )
        )
        entries = {entry["ip"]: entry for entry in document["entries"]}

        for address in self.REQUIRED_IPS:
            self.assertIn(address, entries)
            self.assertTrue(
                {
                    "ip",
                    "covered",
                    "edl",
                    "fqdn",
                    "cname_chain",
                    "source_documentation",
                }.issubset(entries[address])
            )
        self.assertTrue(entries["72.153.5.61"]["covered"])
        self.assertEqual(
            entries["72.153.5.61"]["source_documentation"],
            MICROSOFT_DELIVERY_OPTIMIZATION_URL,
        )
        self.assertFalse(entries["17.248.209.16"]["covered"])


if __name__ == "__main__":
    unittest.main()
