import datetime as dt
import ipaddress
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.generate_edl import (
    APPLE_SECTION_REQUIREMENTS,
    APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS,
    APPLE_XCODE_HOSTS,
    APPLE_XCODE_FILE,
    COVERAGE_CATEGORIES,
    CURRENT_INTERNET_ONLY_AUDIT,
    DNS_HISTORY_GRACE_PERIOD,
    GenerationError,
    GITHUB_ACTIONS_FILE,
    GITHUB_ACTIONS_REQUIRED_HOSTS,
    INTUNE_EVENT_RESIDUAL_IPS,
    INTUNE_EVENT_EXACT_SOURCE_REQUIREMENTS,
    INTUNE_EVENT_WILDCARD_TARGETS,
    INTUNE_WINDOWS_FILE,
    M365_COMMON_WILDCARD_TARGETS,
    M365_SERVICE_FILES,
    MICROSOFT_DOH_ECS_SUBNETS,
    MICROSOFT_DOH_HOSTS,
    MICROSOFT_DOH_RESOLVER,
    MICROSOFT_DELIVERY_OPTIMIZATION_URL,
    MICROSOFT_EDGE_WINDOWS_FILE,
    RESIDUAL_IPS,
    WINDOWS_UPDATE_WILDCARD_TARGETS,
    UBUNTU_MOTD_HOSTS,
    XCODE_DNS_ATTEMPTS,
    XCODE_DOH_ECS_SUBNETS,
    XCODE_DOH_RESOLVER,
    build_residual_coverage,
    combine_dns_observation_details,
    build_dns_history,
    build_dns_observation_details,
    build_xcode_dns_history,
    expand_documented_hostnames,
    extract_apple_section_hostnames,
    extract_doh_observations,
    extract_xcode_doh_observations,
    extract_intune_consolidated_hostnames,
    extract_intune_windows_networks,
    extract_github_actions_hostnames,
    extract_teams_media_networks,
    resolve_service_hostnames,
    validate_m365_documented_urls,
    validate_ubuntu_motd_source,
)


EXPECTED = [
    ipaddress.IPv4Network("52.112.0.0/14"),
    ipaddress.IPv4Network("52.120.0.0/14"),
]


class Microsoft365CommonDnsTests(unittest.TestCase):
    PAYLOAD = [
        {
            "id": 147,
            "serviceArea": "Common",
            "urls": ["*.office.com", "www.microsoft365.com"],
            "ips": None,
            "required": True,
        }
    ]

    def test_validates_official_common_wildcard_and_selects_one_target(self) -> None:
        patterns = validate_m365_documented_urls(
            self.PAYLOAD,
            service_area="Common",
            required_patterns=set(M365_COMMON_WILDCARD_TARGETS),
        )
        hosts, wildcards, selected = expand_documented_hostnames(
            patterns,
            wildcard_targets=M365_COMMON_WILDCARD_TARGETS,
            label="Microsoft 365 Common test",
        )

        self.assertEqual(wildcards, ["*.office.com"])
        self.assertEqual(hosts, ["word.office.com"])
        self.assertEqual(selected, M365_COMMON_WILDCARD_TARGETS)

    def test_rejects_disappearance_of_official_common_wildcard(self) -> None:
        with self.assertRaisesRegex(GenerationError, "no longer contain"):
            validate_m365_documented_urls(
                self.PAYLOAD,
                service_area="Common",
                required_patterns={"*.missing.example"},
            )


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
        self.assertIn("browser.events.data.microsoft.com", hosts)
        self.assertIn("self.events.data.microsoft.com", hosts)
        self.assertIn("v20.events.data.microsoft.com", hosts)
        self.assertIn("watson.events.data.microsoft.com", hosts)
        self.assertIn("umwatsonc.events.data.microsoft.com", hosts)
        self.assertEqual(
            {
                hostname
                for hostnames in INTUNE_EVENT_EXACT_SOURCE_REQUIREMENTS.values()
                for hostname in hostnames
            },
            {
                "watson.events.data.microsoft.com",
                "umwatsonc.events.data.microsoft.com",
            },
        )

    def test_intune_history_seeds_previous_snapshot_and_retains_it_24_hours(
        self,
    ) -> None:
        observed_at = dt.datetime(2026, 8, 22, 12, tzinfo=dt.timezone.utc)
        hostname = "v20.events.data.microsoft.com"
        previous_sources = {
            "generatedAt": "2026-08-22T11:00:00Z",
            "files": {
                INTUNE_WINDOWS_FILE: {
                    "resolvedHostnames": {hostname: ["51.132.193.104"]},
                    "cnameChains": {
                        hostname: [
                            "win-global-asimov-leafs-events-data.trafficmanager.net",
                            "onedscolprdwus.example.cloudapp.azure.com",
                        ]
                    },
                }
            },
        }
        current_details = build_dns_observation_details(
            authorized_hostnames={hostname},
            resolutions={hostname: ["20.184.175.5"]},
            cname_chains={
                hostname: [
                    "win-global-asimov-leafs-events-data.trafficmanager.net"
                ]
            },
            observation_source="system-resolver",
        )

        networks, resolutions, history, expired = build_dns_history(
            previous_sources=previous_sources,
            filename=INTUNE_WINDOWS_FILE,
            authorized_hostnames={hostname},
            current_details=current_details,
            observed_at=observed_at,
            label="Microsoft Intune events",
        )

        self.assertIn(ipaddress.IPv4Network("51.132.193.104/32"), networks)
        self.assertIn("51.132.193.104", resolutions[hostname])
        self.assertEqual(
            history[hostname]["51.132.193.104"]["lastSeen"],
            "2026-08-22T11:00:00Z",
        )
        self.assertEqual(expired, [])

    def test_windows_update_targets_are_dns_names_not_ip_overrides(self) -> None:
        targets = {
            hostname
            for hostnames in WINDOWS_UPDATE_WILDCARD_TARGETS.values()
            for hostname in hostnames
        }

        self.assertIn("array504.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("array508.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("array511.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("array516.prod.do.dsp.mp.microsoft.com", targets)
        self.assertIn("array804.prod.do.dsp.mp.microsoft.com", targets)
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

    def test_private_cloud_compute_hosts_are_exact_and_guarded(self) -> None:
        self.assertEqual(
            APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS,
            {
                "apple-relay.cloudflare.com",
                "apple-relay.fastly-edge.com",
                "cp4.cloudflare.com",
            },
        )
        self.assertEqual(
            APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS,
            APPLE_SECTION_REQUIREMENTS["aisirisearch"],
        )

    def test_ubuntu_motd_requires_canonical_exact_endpoint(self) -> None:
        source = 'APT_NEWS_URL = "https://motd.ubuntu.com/aptnews.json"\n'
        self.assertEqual(validate_ubuntu_motd_source(source), ["motd.ubuntu.com"])
        self.assertEqual(UBUNTU_MOTD_HOSTS, {"motd.ubuntu.com"})
        with self.assertRaisesRegex(GenerationError, "no longer document"):
            validate_ubuntu_motd_source('APT_NEWS_URL = "https://example.com"')


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


class MicrosoftControlledDnsTests(unittest.TestCase):
    HOSTNAME = "settings.data.microsoft.com"

    @classmethod
    def observation_source(cls) -> str:
        lines = []
        for attempt in (1, 2):
            for subnet in MICROSOFT_DOH_ECS_SUBNETS:
                address = (
                    "48.209.138.189"
                    if subnet == MICROSOFT_DOH_ECS_SUBNETS[0]
                    else "48.209.138.168"
                )
                lines.append(
                    json.dumps(
                        {
                            "fqdn": cls.HOSTNAME,
                            "ecsSubnet": subnet,
                            "resolver": MICROSOFT_DOH_RESOLVER,
                            "attempt": attempt,
                            "response": {
                                "Status": 0,
                                "edns_client_subnet": (
                                    "82.64.0.0/0"
                                    if subnet == MICROSOFT_DOH_ECS_SUBNETS[0]
                                    else subnet
                                ),
                                "Question": [{"name": cls.HOSTNAME, "type": 1}],
                                "Answer": [
                                    {
                                        "name": cls.HOSTNAME,
                                        "type": 5,
                                        "data": "atm-settingsfe-prod-geo2.trafficmanager.net.",
                                    },
                                    {
                                        "name": "atm-settingsfe-prod-geo2.trafficmanager.net.",
                                        "type": 5,
                                        "data": "settings-prod-neu.northeurope.cloudapp.azure.com.",
                                    },
                                    {
                                        "name": "settings-prod-neu.northeurope.cloudapp.azure.com.",
                                        "type": 1,
                                        "data": address,
                                    },
                                ],
                            },
                        }
                    )
                )
        return "\n".join(lines) + "\n"

    def test_aggregates_controlled_views_and_merges_system_provenance(self) -> None:
        resolutions, doh_details, counts = extract_doh_observations(
            self.observation_source(),
            authorized_hostnames={self.HOSTNAME},
            ecs_subnets=MICROSOFT_DOH_ECS_SUBNETS,
            resolver_url=MICROSOFT_DOH_RESOLVER,
            required_attempts=2,
            label="Microsoft",
        )
        system_details = build_dns_observation_details(
            authorized_hostnames={self.HOSTNAME},
            resolutions={self.HOSTNAME: ["48.209.133.15"]},
            cname_chains={self.HOSTNAME: []},
            observation_source="system-resolver",
        )
        merged_resolutions, merged_details = combine_dns_observation_details(
            authorized_hostnames={self.HOSTNAME},
            observation_sets=[system_details, doh_details],
        )

        self.assertEqual(
            resolutions[self.HOSTNAME],
            ["48.209.138.168", "48.209.138.189"],
        )
        self.assertEqual(set(counts.values()), {2})
        self.assertEqual(
            merged_resolutions[self.HOSTNAME],
            ["48.209.133.15", "48.209.138.168", "48.209.138.189"],
        )
        self.assertEqual(
            merged_details[self.HOSTNAME]["48.209.138.189"]["cnameChain"],
            [
                "atm-settingsfe-prod-geo2.trafficmanager.net",
                "settings-prod-neu.northeurope.cloudapp.azure.com",
            ],
        )


class WorkflowDnsCoverageTests(unittest.TestCase):
    def test_workflow_collects_every_controlled_dns_hostname(self) -> None:
        workflow = Path(".github/workflows/update-edl.yml").read_text(
            encoding="utf-8"
        )
        for hostname in sorted(
            MICROSOFT_DOH_HOSTS
            | APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS
            | UBUNTU_MOTD_HOSTS
        ):
            self.assertIn(f"'{hostname}'", workflow)
        self.assertIn("--apple-pcc-dns-observations-file", workflow)
        self.assertIn("--ubuntu-dns-observations-file", workflow)


class GitHubActionsTests(unittest.TestCase):
    META = {
        "domains": {
            "actions": [
                "github.com",
                "*.actions.githubusercontent.com",
                "runnerghubeus21.actions.githubusercontent.com",
                "tokenghub.actions.githubusercontent.com",
            ],
            "actions_inbound": {
                "full_domains": [
                    "results-receiver.actions.githubusercontent.com",
                    "tokenghub.actions.githubusercontent.com",
                    "productionresultssa0.blob.core.windows.net",
                ]
            },
        }
    }

    def test_selects_only_concrete_official_actions_hostnames(self) -> None:
        hostnames = extract_github_actions_hostnames(self.META)

        self.assertEqual(
            hostnames,
            [
                "results-receiver.actions.githubusercontent.com",
                "runnerghubeus21.actions.githubusercontent.com",
                "tokenghub.actions.githubusercontent.com",
            ],
        )
        self.assertTrue(GITHUB_ACTIONS_REQUIRED_HOSTS.issubset(hostnames))

    def test_rejects_meta_payload_without_required_token_endpoint(self) -> None:
        payload = json.loads(json.dumps(self.META))
        payload["domains"]["actions"].remove(
            "tokenghub.actions.githubusercontent.com"
        )
        payload["domains"]["actions_inbound"]["full_domains"].remove(
            "tokenghub.actions.githubusercontent.com"
        )

        with self.assertRaisesRegex(GenerationError, "required Actions endpoints"):
            extract_github_actions_hostnames(payload)

    def test_rejects_non_string_actions_domain(self) -> None:
        payload = json.loads(json.dumps(self.META))
        payload["domains"]["actions"].append({"unexpected": "value"})

        with self.assertRaisesRegex(GenerationError, "must be strings"):
            extract_github_actions_hostnames(payload)

    def test_actions_history_retains_only_dns_observations_for_24_hours(self) -> None:
        observed_at = dt.datetime(2026, 8, 22, 12, tzinfo=dt.timezone.utc)
        hostnames = set(GITHUB_ACTIONS_REQUIRED_HOSTS)
        details = build_dns_observation_details(
            authorized_hostnames=hostnames,
            resolutions={"tokenghub.actions.githubusercontent.com": ["20.85.108.33"]},
            cname_chains={
                "tokenghub.actions.githubusercontent.com": [
                    "tokenghubeus21.actions.githubusercontent.com"
                ]
            },
            observation_source="system-resolver",
        )

        networks, resolutions, history, expired = build_dns_history(
            previous_sources=None,
            filename=GITHUB_ACTIONS_FILE,
            authorized_hostnames=hostnames,
            current_details=details,
            observed_at=observed_at,
            label="GitHub Actions hosted runners",
            grace_period=DNS_HISTORY_GRACE_PERIOD,
        )

        self.assertEqual(networks, [ipaddress.IPv4Network("20.85.108.33/32")])
        self.assertEqual(
            resolutions["tokenghub.actions.githubusercontent.com"],
            ["20.85.108.33"],
        )
        self.assertEqual(
            history["tokenghub.actions.githubusercontent.com"]["20.85.108.33"][
                "cnameChain"
            ],
            ["tokenghubeus21.actions.githubusercontent.com"],
        )
        self.assertEqual(expired, [])


class XcodeDnsHistoryTests(unittest.TestCase):
    @staticmethod
    def observation_source() -> str:
        lines = []
        for attempt in range(1, XCODE_DNS_ATTEMPTS + 1):
            for hostname in sorted(APPLE_XCODE_HOSTS):
                for subnet in XCODE_DOH_ECS_SUBNETS:
                    address = (
                        "17.253.29.140"
                        if hostname == "devimages-cdn.apple.com"
                        else "17.253.29.135"
                    )
                    cname = (
                        "devimages-cdn-origin-apple-com.v.aaplimg.com."
                        if hostname == "devimages-cdn.apple.com"
                        else "dd-cdn-origin-apple-com.v.aaplimg.com."
                    )
                    lines.append(
                        json.dumps(
                            {
                                "fqdn": hostname,
                                "ecsSubnet": subnet,
                                "resolver": XCODE_DOH_RESOLVER,
                                "attempt": attempt,
                                "response": {
                                    "Status": 0,
                                    "edns_client_subnet": subnet,
                                    "Question": [{"name": hostname, "type": 1}],
                                    "Answer": [
                                        {
                                            "name": hostname,
                                            "type": 5,
                                            "data": cname,
                                        },
                                        {
                                            "name": cname,
                                            "type": 1,
                                            "data": address,
                                        },
                                    ],
                                },
                            }
                        )
                    )
        return "\n".join(lines) + "\n"

    def test_validates_all_doh_series_and_records_cname_provenance(self) -> None:
        resolutions, details, counts = extract_xcode_doh_observations(
            self.observation_source()
        )

        self.assertEqual(
            resolutions["download.developer.apple.com"], ["17.253.29.135"]
        )
        self.assertEqual(
            details["download.developer.apple.com"]["17.253.29.135"][
                "cnameChain"
            ],
            ["dd-cdn-origin-apple-com.v.aaplimg.com"],
        )
        self.assertTrue(
            all(count == XCODE_DNS_ATTEMPTS for count in counts.values())
        )

    def test_rejects_an_unauthorized_observation_hostname(self) -> None:
        source = self.observation_source().replace(
            '"fqdn": "devimages-cdn.apple.com"',
            '"fqdn": "unapproved.apple.com"',
            1,
        )
        with self.assertRaisesRegex(GenerationError, "Unauthorized Xcode"):
            extract_xcode_doh_observations(source)

    def test_ignores_a_records_outside_the_validated_cname_chain(self) -> None:
        lines = self.observation_source().splitlines()
        first = json.loads(lines[0])
        first["response"]["Answer"].append(
            {"name": "unrelated.example.com.", "type": 1, "data": "8.8.8.8"}
        )
        lines[0] = json.dumps(first)

        resolutions, _, _ = extract_xcode_doh_observations("\n".join(lines))

        self.assertNotIn(
            "8.8.8.8",
            {
                address
                for addresses in resolutions.values()
                for address in addresses
            },
        )

    def test_retains_recent_dns_records_and_expires_them_after_24_hours(self) -> None:
        observed_at = dt.datetime(2026, 8, 22, 12, tzinfo=dt.timezone.utc)
        previous_sources = {
            "generatedAt": "2026-08-22T00:00:00Z",
            "files": {
                APPLE_XCODE_FILE: {
                    "resolvedHostnames": {
                        "devimages-cdn.apple.com": ["17.253.5.131"],
                        "download.developer.apple.com": ["17.253.5.142"],
                    },
                    "cnameChains": {
                        "devimages-cdn.apple.com": [
                            "devimages-cdn-origin-apple-com.v.aaplimg.com"
                        ],
                        "download.developer.apple.com": [
                            "dd-cdn-origin-apple-com.v.aaplimg.com"
                        ],
                    },
                }
            },
        }
        current = {
            "devimages-cdn.apple.com": {
                "17.253.29.140": {
                    "cnameChain": [
                        "devimages-cdn-origin-apple-com.v.aaplimg.com"
                    ],
                    "observationSources": ["google-doh-ecs:82.64.0.0/11"],
                }
            },
            "download.developer.apple.com": {
                "17.253.29.135": {
                    "cnameChain": ["dd-cdn-origin-apple-com.v.aaplimg.com"],
                    "observationSources": ["google-doh-ecs:82.66.0.0/16"],
                }
            },
        }

        networks, resolutions, history, expired = build_xcode_dns_history(
            previous_sources=previous_sources,
            current_details=current,
            observed_at=observed_at,
        )

        self.assertIn(
            ipaddress.IPv4Network("17.253.5.131/32"), networks
        )
        self.assertIn(
            "17.253.29.135", resolutions["download.developer.apple.com"]
        )
        self.assertEqual(
            history["download.developer.apple.com"]["17.253.29.135"][
                "firstSeen"
            ],
            "2026-08-22T12:00:00Z",
        )
        self.assertEqual(expired, [])

        _, expired_resolutions, _, expired = build_xcode_dns_history(
            previous_sources=previous_sources,
            current_details=current,
            observed_at=dt.datetime(2026, 8, 23, 1, tzinfo=dt.timezone.utc),
        )
        self.assertNotIn(
            "17.253.5.131", expired_resolutions["devimages-cdn.apple.com"]
        )
        self.assertTrue(any(record["ip"] == "17.253.5.131" for record in expired))


class ResidualCoverageTests(unittest.TestCase):
    REQUIRED_IPS = {
        "2.16.193.188",
        "34.244.58.147",
        "40.79.150.123",
        "72.153.5.132",
        "72.154.7.97",
        "172.66.0.227",
        "72.153.5.61",
        "72.153.5.129",
        "72.153.5.137",
        "72.154.7.101",
        "17.248.209.16",
        "17.145.16.2",
        "17.248.209.62",
        "17.248.209.73",
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
        "17.253.29.135",
        "17.253.29.147",
        "17.253.29.140",
        "17.253.29.151",
        "17.253.37.209",
        "17.253.37.210",
        "17.248.209.46",
        "17.188.171.202",
        "17.111.103.20",
        "162.159.194.64",
        "162.159.194.66",
        "172.64.69.66",
        "51.132.193.104",
        "4.150.223.98",
        "4.150.223.112",
        "20.184.175.2",
        "20.42.72.131",
        "4.150.223.107",
        "150.171.22.17",
        "13.107.6.156",
        "20.184.175.3",
        "104.208.16.94",
        "20.105.245.153",
        "17.145.0.2",
        "17.248.209.54",
        "23.200.213.147",
        "95.101.137.28",
        "95.101.137.33",
        "95.101.137.34",
        "95.101.137.35",
        "52.85.118.32",
        "52.85.118.49",
        "52.85.118.61",
        "52.85.118.108",
        "52.222.169.45",
        "52.222.169.104",
        "20.42.65.88",
        "48.209.138.189",
        "48.209.138.168",
        "51.116.246.106",
        "20.184.175.21",
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
                dns_history_by_file={},
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
                    "first_seen",
                    "last_seen",
                    "source_documentation",
                    "owner",
                    "suspectedService",
                    "verified",
                    "officialFqdn",
                    "cnameChain",
                    "firstSeen",
                    "lastSeen",
                    "targetEdl",
                    "reason",
                    "sourcePalo",
                    "paloSource",
                    "officialSource",
                    "category",
                    "confidence",
                }.issubset(entries[address])
            )
        self.assertTrue(entries["72.153.5.61"]["covered"])
        self.assertEqual(
            entries["72.153.5.61"]["source_documentation"],
            MICROSOFT_DELIVERY_OPTIMIZATION_URL,
        )
        self.assertFalse(entries["17.248.209.16"]["covered"])
        self.assertTrue(INTUNE_EVENT_RESIDUAL_IPS.issubset(entries))
        self.assertFalse(entries["20.184.175.2"]["covered"])
        self.assertFalse(entries["20.184.175.2"]["verified"])
        self.assertEqual(entries["20.184.175.2"]["owner"], "Microsoft/Azure")
        self.assertFalse(entries["20.42.72.131"]["covered"])
        self.assertFalse(entries["20.42.72.131"]["verified"])
        self.assertIsNone(entries["20.42.72.131"]["officialFqdn"])
        self.assertEqual(
            set(document["currentInternetOnlyAudit"]["ips"]),
            set(CURRENT_INTERNET_ONLY_AUDIT),
        )
        self.assertEqual(
            set(CURRENT_INTERNET_ONLY_AUDIT),
            {
                "72.154.7.97",
                "72.153.5.132",
                "40.79.150.123",
                "2.16.193.188",
                "172.66.0.227",
                "34.244.58.147",
            },
        )
        self.assertEqual(
            document["currentInternetOnlyAudit"]["ipCount"],
            len(CURRENT_INTERNET_ONLY_AUDIT),
        )
        self.assertEqual(
            sum(document["currentInternetOnlyAudit"]["categoryCounts"].values()),
            len(CURRENT_INTERNET_ONLY_AUDIT),
        )
        self.assertTrue(
            set(document["currentInternetOnlyAudit"]["categoryCounts"])
            == COVERAGE_CATEGORIES
        )
        for address in CURRENT_INTERNET_ONLY_AUDIT:
            self.assertIn(entries[address]["category"], COVERAGE_CATEGORIES)
            self.assertEqual(
                entries[address]["sourcePalo"], entries[address]["paloSource"]
            )
            self.assertIsNotNone(entries[address]["paloSource"])

    def test_intune_telemetry_residual_requires_dns_provenance(self) -> None:
        observed_at = "2026-08-22T12:00:00Z"
        hostname = "v20.events.data.microsoft.com"
        address = "51.132.193.104"
        document = json.loads(
            build_residual_coverage(
                generated_at=observed_at,
                generated={
                    INTUNE_WINDOWS_FILE: [
                        ipaddress.IPv4Network(f"{address}/32")
                    ]
                },
                resolutions_by_file={
                    INTUNE_WINDOWS_FILE: {hostname: [address]}
                },
                cname_chains_by_file={INTUNE_WINDOWS_FILE: {}},
                dns_history_by_file={
                    INTUNE_WINDOWS_FILE: {
                        hostname: {
                            address: {
                                "cnameChain": [
                                    "win-global-asimov-leafs-events-data.trafficmanager.net"
                                ],
                                "firstSeen": observed_at,
                                "lastSeen": observed_at,
                                "observationSources": ["system-resolver"],
                            }
                        }
                    }
                },
            )
        )
        entry = next(item for item in document["entries"] if item["ip"] == address)

        self.assertTrue(entry["covered"])
        self.assertTrue(entry["verified"])
        self.assertEqual(entry["edl"], INTUNE_WINDOWS_FILE)
        self.assertEqual(entry["fqdn"], hostname)
        self.assertEqual(entry["officialFqdn"], hostname)
        self.assertEqual(entry["targetEdl"], INTUNE_WINDOWS_FILE)
        self.assertEqual(entry["firstSeen"], observed_at)

    def test_github_actions_canary_is_verified_only_with_dns_provenance(self) -> None:
        observed_at = "2026-08-22T12:00:00Z"
        document = json.loads(
            build_residual_coverage(
                generated_at=observed_at,
                generated={
                    GITHUB_ACTIONS_FILE: [
                        ipaddress.IPv4Network("20.85.108.33/32")
                    ]
                },
                resolutions_by_file={
                    GITHUB_ACTIONS_FILE: {
                        "tokenghub.actions.githubusercontent.com": ["20.85.108.33"]
                    }
                },
                cname_chains_by_file={GITHUB_ACTIONS_FILE: {}},
                dns_history_by_file={
                    GITHUB_ACTIONS_FILE: {
                        "tokenghub.actions.githubusercontent.com": {
                            "20.85.108.33": {
                                "cnameChain": [
                                    "tokenghubeus21.actions.githubusercontent.com"
                                ],
                                "firstSeen": observed_at,
                                "lastSeen": observed_at,
                                "observationSources": ["system-resolver"],
                            }
                        }
                    }
                },
            )
        )
        entry = next(
            item for item in document["entries"] if item["ip"] == "20.85.108.33"
        )

        self.assertTrue(entry["covered"])
        self.assertTrue(entry["verified"])
        self.assertEqual(entry["owner"], "Microsoft/Azure")
        self.assertEqual(entry["suspectedService"], "GitHub Actions")
        self.assertEqual(entry["edl"], GITHUB_ACTIONS_FILE)
        self.assertEqual(
            entry["cname_chain"],
            ["tokenghubeus21.actions.githubusercontent.com"],
        )

    def test_m365_common_canary_is_covered_only_by_official_dns(self) -> None:
        observed_at = "2026-08-22T12:00:00Z"
        address = "13.107.6.156"
        hostname = "word.office.com"
        common_file = M365_SERVICE_FILES["Common"]
        document = json.loads(
            build_residual_coverage(
                generated_at=observed_at,
                generated={common_file: [ipaddress.IPv4Network(f"{address}/32")]},
                resolutions_by_file={common_file: {hostname: [address]}},
                cname_chains_by_file={common_file: {}},
                dns_history_by_file={
                    common_file: {
                        hostname: {
                            address: {
                                "cnameChain": [
                                    "home-redirects.www.office.com",
                                    "home-office365-com.b-0004.b-msedge.net",
                                    "b-0004.b-msedge.net",
                                ],
                                "firstSeen": observed_at,
                                "lastSeen": observed_at,
                                "observationSources": ["system-resolver"],
                            }
                        }
                    }
                },
            )
        )
        entry = next(item for item in document["entries"] if item["ip"] == address)

        self.assertTrue(entry["covered"])
        self.assertTrue(entry["verified"])
        self.assertEqual(entry["category"], "COVERED_OFFICIAL")
        self.assertEqual(entry["targetEdl"], common_file)
        self.assertEqual(entry["officialFqdn"], hostname)
        self.assertEqual(entry["firstSeen"], observed_at)


if __name__ == "__main__":
    unittest.main()
