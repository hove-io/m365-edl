import ipaddress
import unittest

from scripts.generate_edl import (
    GenerationError,
    INTUNE_EVENT_WILDCARD_TARGETS,
    WINDOWS_UPDATE_WILDCARD_TARGETS,
    expand_documented_hostnames,
    extract_intune_consolidated_hostnames,
    extract_intune_windows_networks,
    extract_teams_media_networks,
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
        for target in targets:
            with self.assertRaises(ValueError):
                ipaddress.ip_address(target)


if __name__ == "__main__":
    unittest.main()
