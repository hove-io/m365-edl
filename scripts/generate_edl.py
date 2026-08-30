#!/usr/bin/env python3
"""Generate validated public-service IPv4 EDL files from official sources."""

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
import time
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
APPLE_ENTERPRISE_URL = "https://support.apple.com/en-us/101555"
APPLE_APNS_URL = (
    "https://developer.apple.com/library/archive/documentation/NetworkingInternet/"
    "Conceptual/RemoteNotificationsPG/CommunicatingwithAPNs.html"
)
UBUNTU_PRO_DEFAULTS_URL = (
    "https://raw.githubusercontent.com/canonical/ubuntu-pro-client/main/"
    "uaclient/defaults.py"
)
UBUNTU_PRO_DEFAULTS_DOCUMENTATION_URL = (
    "https://github.com/canonical/ubuntu-pro-client/blob/main/uaclient/defaults.py"
)
GITHUB_META_URL = "https://api.github.com/meta"
GITHUB_META_DOCS_URL = "https://docs.github.com/en/rest/meta/meta"
DROPBOX_FIREWALL_URL = "https://help.dropbox.com/installs/configuring-firewall"
DROPBOX_ARIN_URL = "https://whois.arin.net/rest/org/DROPB/nets.json"
DELL_UPDATE_DOCUMENTATION_URL = (
    "https://www.dell.com/support/manuals/en-us/command-update/"
    "dellcommandupdate_3.1_ug/install-updates"
    "?guid=guid-2ecd73e2-0593-43f1-8e99-07be35e86bf8"
)
DELL_UPDATE_URL = "https://downloads.dell.com/catalog/CatalogPC.cab"
MICROSOFT_EDGE_URL = (
    "https://learn.microsoft.com/en-us/deployedge/"
    "microsoft-edge-security-endpoints"
)
MICROSOFT_WINDOWS_URL = (
    "https://learn.microsoft.com/en-us/windows/privacy/"
    "manage-windows-11-endpoints"
)
MICROSOFT_DELIVERY_OPTIMIZATION_URL = (
    "https://learn.microsoft.com/en-us/windows/deployment/do/"
    "delivery-optimization-workflow"
)
WINDOWS_DIAGNOSTIC_ENDPOINTS_URL = (
    "https://learn.microsoft.com/en-us/windows/privacy/"
    "windows-11-endpoints-non-enterprise-editions"
)
CONFIGMGR_INTERNET_ENDPOINTS_URL = (
    "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/"
    "network/internet-endpoints"
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
APPLE_UPDATES_FILE = "apple-updates-ipv4.txt"
APPLE_CONTENT_FILE = "apple-appstore-content-ipv4.txt"
APPLE_DEVICE_FILE = "apple-device-services-ipv4.txt"
APPLE_XCODE_FILE = "apple-xcode-developer-ipv4.txt"
UBUNTU_MOTD_FILE = "ubuntu-motd-ipv4.txt"
GITHUB_FILE = "github-ipv4.txt"
GITHUB_ACTIONS_FILE = "github-actions-ipv4.txt"
DROPBOX_FILE = "dropbox-ipv4.txt"
DELL_UPDATE_FILE = "dell-update-ipv4.txt"
MICROSOFT_EDGE_WINDOWS_FILE = "microsoft-edge-windows-services-ipv4.txt"
ZSCALER_ZPA_FILE = "zscaler/zpa/zpa_ipv4.txt"
RESIDUAL_COVERAGE_FILE = "residual-ip-coverage.json"
XCODE_DNS_GRACE_PERIOD = dt.timedelta(hours=24)
XCODE_DNS_ATTEMPTS = 8
XCODE_DOH_RESOLVER = "https://dns.google/resolve"
XCODE_DOH_ECS_SUBNETS = ("82.64.0.0/11", "82.66.0.0/16")
DNS_HISTORY_GRACE_PERIOD = dt.timedelta(hours=24)
GITHUB_ACTIONS_DNS_ATTEMPTS = 8
GITHUB_ACTIONS_SUFFIX = ".actions.githubusercontent.com"
GITHUB_ACTIONS_REQUIRED_HOSTS = {
    "results-receiver.actions.githubusercontent.com",
    "tokenghub.actions.githubusercontent.com",
}
M365_COMMON_WILDCARD_TARGETS = {
    "*.office.com": ("word.office.com",),
}
M365_COMMON_DNS_RESIDUAL_IPS = {"13.107.6.156"}

COVERAGE_CATEGORIES = {
    "COVERED_OFFICIAL",
    "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
    "CDN_SHARED_UNATTRIBUTED",
    "OWNER_ONLY_UNATTRIBUTED",
    "INTENTIONALLY_UNCOVERED",
}

# The Palo source, owner, and passive-DNS-like service hints below are audit
# context only. They never add an address to an EDL. Coverage still requires an
# address to be present in an official CIDR or in the current/24-hour DNS
# history of an authorized FQDN.
PREVIOUS_INTERNET_ONLY_AUDIT: dict[str, dict[str, str | None]] = {
    "4.150.223.107": {
        "paloSource": "10.50.82.50",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft telemetry / events.data.microsoft.com",
        "officialSource": INTUNE_ENDPOINTS_LEARN_URL,
        "officialFqdn": "*.events.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "medium",
        "reason": (
            "Microsoft telemetry is a plausible attribution, but no authorized "
            "*.events.data.microsoft.com target returned this address in the "
            "current or rolling 24-hour DNS window"
        ),
    },
    "150.171.22.17": {
        "paloSource": "10.50.84.3",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft ECS/Office configuration infrastructure",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "OWNER_ONLY_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Microsoft ownership and historical ECS infrastructure names are "
            "only clues; no in-scope official commercial FQDN currently maps "
            "this address"
        ),
    },
    "13.107.6.156": {
        "paloSource": "10.50.84.3",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft 365 Office web front door",
        "officialSource": M365_API_URL,
        "officialFqdn": "word.office.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "The official Microsoft 365 Common wildcard *.office.com is in "
            "scope, but its audited word.office.com target did not return this "
            "address in the current or rolling 24-hour DNS window"
        ),
    },
    "20.184.175.3": {
        "paloSource": "10.50.84.3",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft telemetry / events.data.microsoft.com",
        "officialSource": INTUNE_ENDPOINTS_LEARN_URL,
        "officialFqdn": "*.events.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "medium",
        "reason": (
            "Microsoft telemetry is a plausible attribution, but no authorized "
            "*.events.data.microsoft.com target returned this address in the "
            "current or rolling 24-hour DNS window"
        ),
    },
    "104.208.16.94": {
        "paloSource": "10.50.83.87",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft telemetry / events.data.microsoft.com",
        "officialSource": INTUNE_ENDPOINTS_LEARN_URL,
        "officialFqdn": "*.events.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "medium",
        "reason": (
            "Microsoft telemetry is a plausible attribution, but no authorized "
            "*.events.data.microsoft.com target returned this address in the "
            "current or rolling 24-hour DNS window"
        ),
    },
    "20.105.245.153": {
        "paloSource": "10.50.83.87",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Azure AI/Cognitive Services infrastructure",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "OWNER_ONLY_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Microsoft ownership and historical cognitive-service names do not "
            "prove that this flow belongs to an authorized repository service"
        ),
    },
    "17.145.0.2": {
        "paloSource": "10.50.83.27",
        "owner": "Apple (AS714)",
        "suspectedService": "Apple app/content service",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "OWNER_ONLY_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Apple ownership and historical app.apple.com attribution are not "
            "an official in-scope endpoint proof, and no permitted Apple FQDN "
            "currently maps this address"
        ),
    },
    "17.248.209.54": {
        "paloSource": "10.50.83.27",
        "owner": "Apple (AS714)",
        "suspectedService": "Apple iCloud edge service",
        "officialSource": APPLE_ENTERPRISE_URL,
        "officialFqdn": "*.icloud.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "medium",
        "reason": (
            "Apple documents the *.icloud.com family, but no in-scope concrete "
            "Apple FQDN currently or recently maps this address"
        ),
    },
    "23.200.213.147": {
        "paloSource": "10.50.84.3",
        "owner": "Akamai (AS16625)",
        "suspectedService": "Microsoft developer website on shared Akamai",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "medium",
        "reason": (
            "Shared Akamai address with historical Microsoft developer names, "
            "but no authorized official service FQDN currently maps it"
        ),
    },
    "95.101.137.28": {
        "paloSource": "10.50.83.27",
        "owner": "Akamai (AS20940)",
        "suspectedService": "Unattributed shared CDN traffic",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Shared Akamai address without a demonstrated official client FQDN; "
            "Akamai ownership alone is not authorization"
        ),
    },
    "95.101.137.33": {
        "paloSource": "10.50.83.27",
        "owner": "Akamai (AS20940)",
        "suspectedService": "Unattributed shared CDN traffic",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Shared Akamai address without a demonstrated official client FQDN; "
            "Akamai ownership alone is not authorization"
        ),
    },
    "52.85.118.49": {
        "paloSource": "10.50.83.126",
        "owner": "AWS CloudFront (AS16509)",
        "suspectedService": "Unattributed shared CloudFront distribution",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Shared CloudFront address without a demonstrated official client "
            "FQDN; CloudFront ownership alone is not authorization"
        ),
    },
    "52.85.118.108": {
        "paloSource": "10.50.83.125",
        "owner": "AWS CloudFront (AS16509)",
        "suspectedService": "Possible AWS CodeBuild console on shared CloudFront",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Historical CodeBuild names on a shared CloudFront address do not "
            "identify this TLS flow or authorize the whole distribution"
        ),
    },
    "52.222.169.45": {
        "paloSource": "10.50.83.125",
        "owner": "AWS CloudFront (AS16509)",
        "suspectedService": "Unattributed shared CloudFront distribution",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Shared CloudFront address without a demonstrated official client "
            "FQDN; unrelated tenants may use the same edge"
        ),
    },
    "52.222.169.104": {
        "paloSource": "10.50.83.126",
        "owner": "AWS CloudFront (AS16509)",
        "suspectedService": "Unattributed shared CloudFront distribution",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Shared CloudFront address without a demonstrated official client "
            "FQDN; the distribution hostname alone does not identify a service"
        ),
    },
}

LAST_INTERNET_ONLY_AUDIT: dict[str, dict[str, str | None]] = {
    "20.42.65.88": {
        "paloSource": "10.50.84.24",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft telemetry / events.data.microsoft.com",
        "officialSource": INTUNE_ENDPOINTS_LEARN_URL,
        "officialFqdn": "*.events.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "The official events.data.microsoft.com family has returned this "
            "address historically, but it was not observed in the current or "
            "rolling 24-hour authorized DNS window"
        ),
    },
    "20.105.245.153": PREVIOUS_INTERNET_ONLY_AUDIT["20.105.245.153"],
    "48.209.138.189": {
        "paloSource": "10.50.84.24",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Windows dynamic settings service",
        "officialSource": MICROSOFT_WINDOWS_URL,
        "officialFqdn": "settings.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "The official Windows settings FQDNs are authorized, but neither "
            "returned this address in the current or rolling 24-hour DNS window"
        ),
    },
    "48.209.138.168": {
        "paloSource": "10.50.83.87",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Windows dynamic settings service",
        "officialSource": MICROSOFT_WINDOWS_URL,
        "officialFqdn": "settings.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "The official Windows settings FQDNs are authorized, but neither "
            "returned this address in the current or rolling 24-hour DNS window"
        ),
    },
    "51.116.246.106": {
        "paloSource": "10.50.83.22",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft telemetry / events.data.microsoft.com",
        "officialSource": INTUNE_ENDPOINTS_LEARN_URL,
        "officialFqdn": "*.events.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "The official events.data.microsoft.com family has returned this "
            "address historically, but it was not observed in the current or "
            "rolling 24-hour authorized DNS window"
        ),
    },
    "150.171.22.17": {
        "paloSource": "10.50.84.3",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Microsoft Edge configuration service",
        "officialSource": MICROSOFT_EDGE_URL,
        "officialFqdn": "config.edge.skype.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "config.edge.skype.com is officially documented, but it did not "
            "return this address in the current or rolling 24-hour DNS window"
        ),
    },
    "20.184.175.21": {
        "paloSource": "10.50.82.50",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Unresolved Microsoft/Azure service",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "OWNER_ONLY_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "Microsoft ownership is the only reliable attribution; no official "
            "Intune, Defender, Edge, Windows Update, or Delivery Optimization "
            "FQDN currently maps this address"
        ),
    },
}

PREVIOUS_INTERNET_ONLY_AUDIT.update(LAST_INTERNET_ONLY_AUDIT)

CURRENT_INTERNET_ONLY_AUDIT: dict[str, dict[str, str | None]] = {
    "72.154.7.97": {
        "paloSource": "10.50.82.50",
        "owner": "Microsoft (AS8075)",
        "suspectedService": "Windows Delivery Optimization Array service",
        "officialSource": MICROSOFT_DELIVERY_OPTIMIZATION_URL,
        "officialFqdn": "array804.prod.do.dsp.mp.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "The concrete array804 target belongs to Microsoft's documented "
            "array*.prod.do.dsp.mp.microsoft.com family, but coverage still "
            "requires a current or rolling 24-hour DNS observation"
        ),
    },
    "72.153.5.132": {
        "paloSource": "10.50.84.24",
        "owner": "Microsoft (AS8075)",
        "suspectedService": "Windows Delivery Optimization Array service",
        "officialSource": MICROSOFT_DELIVERY_OPTIMIZATION_URL,
        "officialFqdn": "array511.prod.do.dsp.mp.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "The concrete array511 target belongs to Microsoft's documented "
            "array*.prod.do.dsp.mp.microsoft.com family, but coverage still "
            "requires a current or rolling 24-hour DNS observation"
        ),
    },
    "40.79.150.123": {
        "paloSource": "10.50.84.3",
        "owner": "Microsoft/Azure (AS8075)",
        "suspectedService": "Probable Microsoft OneDS telemetry backend",
        "officialSource": INTUNE_ENDPOINTS_LEARN_URL,
        "officialFqdn": "*.events.data.microsoft.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "medium",
        "reason": (
            "The France Central OneDS backend name is only an attribution clue; "
            "no authorized *.events.data.microsoft.com target returned this "
            "address in the current or rolling 24-hour DNS window"
        ),
    },
    "2.16.193.188": {
        "paloSource": "10.50.82.50",
        "owner": "Akamai (AS20940)",
        "suspectedService": "Unattributed shared Akamai delivery edge",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": (
            "No authorized Microsoft service FQDN returned this shared Akamai "
            "address; Akamai ownership is not service authorization"
        ),
    },
    "172.66.0.227": {
        "paloSource": "10.50.83.87",
        "owner": "Cloudflare (AS13335)",
        "suspectedService": "Possible Apple Private Cloud Compute or shared CDN",
        "officialSource": APPLE_ENTERPRISE_URL,
        "officialFqdn": (
            "apple-relay.cloudflare.com / cp4.cloudflare.com / "
            "apple-relay.fastly-edge.com"
        ),
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "medium",
        "reason": (
            "Apple documents three Private Cloud Compute relay FQDNs, but none "
            "returned this shared Cloudflare address in the current or rolling "
            "24-hour authorized DNS window"
        ),
    },
    "34.244.58.147": {
        "paloSource": "10.50.83.23",
        "owner": "AWS hosting / Canonical Ubuntu service",
        "suspectedService": "Ubuntu Pro APT News / MOTD",
        "officialSource": UBUNTU_PRO_DEFAULTS_DOCUMENTATION_URL,
        "officialFqdn": "motd.ubuntu.com",
        "uncoveredCategory": "OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED",
        "confidence": "high",
        "reason": (
            "Canonical's official Ubuntu Pro client config documents "
            "motd.ubuntu.com; coverage still requires a current or rolling "
            "24-hour DNS observation"
        ),
    },
}

CURRENT_CDN_WITNESS_AUDIT: dict[str, dict[str, str | None]] = {
    "23.200.213.147": PREVIOUS_INTERNET_ONLY_AUDIT["23.200.213.147"],
    "95.101.137.28": PREVIOUS_INTERNET_ONLY_AUDIT["95.101.137.28"],
    "95.101.137.34": {
        "paloSource": None,
        "owner": "Akamai (AS20940)",
        "suspectedService": "Unattributed shared Akamai edge",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": "No authorized official service FQDN currently maps this Akamai address",
    },
    "95.101.137.35": {
        "paloSource": None,
        "owner": "Akamai (AS20940)",
        "suspectedService": "Unattributed shared Akamai edge",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": "No authorized official service FQDN currently maps this Akamai address",
    },
    "52.85.118.32": {
        "paloSource": None,
        "owner": "AWS CloudFront (AS16509)",
        "suspectedService": "Unattributed shared CloudFront distribution",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": "No authorized official service FQDN currently maps this CloudFront address",
    },
    "52.85.118.49": PREVIOUS_INTERNET_ONLY_AUDIT["52.85.118.49"],
    "52.85.118.61": {
        "paloSource": None,
        "owner": "AWS CloudFront (AS16509)",
        "suspectedService": "Unattributed shared CloudFront distribution",
        "officialSource": None,
        "officialFqdn": None,
        "uncoveredCategory": "CDN_SHARED_UNATTRIBUTED",
        "confidence": "low",
        "reason": "No authorized official service FQDN currently maps this CloudFront address",
    },
}

INTERNET_ONLY_AUDIT_CONTEXT = {
    **PREVIOUS_INTERNET_ONLY_AUDIT,
    **CURRENT_CDN_WITNESS_AUDIT,
    **CURRENT_INTERNET_ONLY_AUDIT,
}

PUBLICATIONS = (
    ("Microsoft 365 Common", "m365-common-ipv4.txt"),
    ("Microsoft 365 Exchange", "m365-exchange-ipv4.txt"),
    ("Microsoft 365 SharePoint", "m365-sharepoint-ipv4.txt"),
    ("Microsoft 365 Teams/Skype", "m365-teams-ipv4.txt"),
    ("Microsoft Defender EU/global", DEFENDER_FILE),
    ("Microsoft Teams Media/Direct Routing", TEAMS_MEDIA_FILE),
    ("Microsoft Intune / Windows", INTUNE_WINDOWS_FILE),
    ("Apple Software Updates", APPLE_UPDATES_FILE),
    ("Apple App Store / Content", APPLE_CONTENT_FILE),
    ("Apple Device Services / APNs / Private Cloud Compute", APPLE_DEVICE_FILE),
    ("Apple Xcode / Developer downloads", APPLE_XCODE_FILE),
    ("Ubuntu Pro APT News / MOTD", UBUNTU_MOTD_FILE),
    ("GitHub web/API/git/Pages", GITHUB_FILE),
    ("GitHub Actions / hosted runners", GITHUB_ACTIONS_FILE),
    ("Dropbox product networks", DROPBOX_FILE),
    ("Dell Command Update", DELL_UPDATE_FILE),
    ("Microsoft Edge / Windows services", MICROSOFT_EDGE_WINDOWS_FILE),
    ("Zscaler ZPA Public Service Edges", ZSCALER_ZPA_FILE),
    ("Log4Shell / Log4j historical IPv4 IOCs", "log4j-ipv4.txt"),
    ("Log4Shell / Log4j historical domains", "log4j-domains.txt"),
)

NEW_SERVICE_FILES = (
    APPLE_UPDATES_FILE,
    APPLE_CONTENT_FILE,
    APPLE_DEVICE_FILE,
    APPLE_XCODE_FILE,
    UBUNTU_MOTD_FILE,
    GITHUB_ACTIONS_FILE,
    GITHUB_FILE,
    DROPBOX_FILE,
    DELL_UPDATE_FILE,
    MICROSOFT_EDGE_WINDOWS_FILE,
)

RESIDUAL_IPS = (
    "2.16.193.188",
    "34.244.58.147",
    "40.79.150.123",
    "72.153.5.132",
    "72.154.7.97",
    "52.85.118.32",
    "52.85.118.49",
    "52.85.118.61",
    "52.85.118.108",
    "20.42.65.85",
    "20.42.65.88",
    "20.42.72.131",
    "4.150.223.96",
    "4.150.223.98",
    "4.150.223.104",
    "4.150.223.107",
    "4.150.223.112",
    "4.150.223.115",
    "20.184.175.2",
    "20.184.175.3",
    "20.184.175.21",
    "51.132.193.104",
    "51.116.246.106",
    "150.171.22.17",
    "104.208.16.94",
    "23.103.234.43",
    "17.248.236.28",
    "72.153.5.61",
    "72.153.5.129",
    "72.153.5.137",
    "72.153.5.140",
    "72.154.7.101",
    "95.101.137.11",
    "95.101.137.12",
    "95.101.137.14",
    "20.85.108.33",
    "48.209.138.189",
    "48.209.138.168",
    "52.168.117.169",
    "52.168.117.170",
    "23.200.213.147",
    "20.85.130.105",
    "48.209.133.15",
    "17.253.29.146",
    "17.188.170.10",
    "13.107.6.156",
    "143.166.124.33",
    "20.105.245.153",
    "162.125.67.18",
    "172.66.0.227",
    "140.82.121.5",
    "150.171.28.11",
    "17.248.209.16",
    "17.145.16.2",
    "17.145.0.2",
    "17.248.209.54",
    "17.253.37.204",
    "17.253.29.135",
    "17.253.29.147",
    "17.253.29.140",
    "17.253.29.151",
    "17.253.37.209",
    "17.253.37.210",
    "17.248.209.46",
    "17.248.209.62",
    "17.248.209.73",
    "17.188.171.202",
    "17.111.103.20",
    "95.101.137.16",
    "95.101.137.21",
    "95.101.137.23",
    "95.101.137.24",
    "95.101.137.28",
    "95.101.137.33",
    "95.101.137.34",
    "95.101.137.35",
    "23.58.84.19",
    "151.101.1.64",
    "151.101.129.64",
    "162.159.194.64",
    "162.159.194.66",
    "172.64.69.66",
    "52.222.169.45",
    "52.222.169.104",
)
INTUNE_EVENT_RESIDUAL_IPS = {
    "40.79.150.123",
    "4.150.223.107",
    "4.150.223.98",
    "4.150.223.112",
    "20.184.175.3",
    "20.184.175.2",
    "20.42.72.131",
    "20.42.65.88",
    "51.116.246.106",
    "51.132.193.104",
    "104.208.16.94",
}

GITHUB_META_FIELDS = ("web", "api", "git", "pages")
DROPBOX_PRODUCT_NET_NAMES = {"DROPBOX", "DROPB"}

APPLE_SECTION_REQUIREMENTS = {
    "software": {
        "appldnld.apple.com",
        "configuration.apple.com",
        "fcs-keys-pub-prod.cdn-apple.com",
        "gdmf-ados.apple.com",
        "gdmf.apple.com",
        "gg.apple.com",
        "gs.apple.com",
        "gsra.apple.com",
        "ig.apple.com",
        "mesu.apple.com",
        "oscdn.apple.com",
        "osrecovery.apple.com",
        "skl.apple.com",
        "swcdn.apple.com",
        "swdist.apple.com",
        "swdownload.apple.com",
        "swscan.apple.com",
        "updates-http.cdn-apple.com",
        "updates.cdn-apple.com",
        "wkms-public.apple.com",
        "xp.apple.com",
    },
    "appscontent": {
        "*.appattest.apple.com",
        "*.apps-marketplace.apple.com",
        "*.itunes.apple.com",
        "*.apps.apple.com",
        "*.mzstatic.com",
        "itunes.apple.com",
        "ppq.apple.com",
        "api.apple-cloudkit.com",
        "audiocontentdownload.apple.com",
        "devimages-cdn.apple.com",
        "download.developer.apple.com",
        "gateway.icloud.com",
        "playground-assets-cdn.apple.com",
        "playground-cdn.apple.com",
        "sylvan.apple.com",
        "token.safebrowsing.apple",
    },
    "devicesetup": {
        "albert.apple.com",
        "captive.apple.com",
        "gs.apple.com",
        "humb.apple.com",
        "static.ips.apple.com",
        "sq-device.apple.com",
        "tbsc.apple.com",
        "time-ios.apple.com",
        "time.apple.com",
        "time-macos.apple.com",
    },
    "devicemanagement": {
        "*.push.apple.com",
        "deviceenrollment.apple.com",
        "deviceservices-external.apple.com",
        "gdmf.apple.com",
        "identity.apple.com",
        "iprofiles.apple.com",
        "mdmenrollment.apple.com",
        "setup.icloud.com",
        "vpp.itunes.apple.com",
        "*.appattest.apple.com",
        "axm-servicediscovery.apple.com",
    },
    "aisirisearch": {
        "apple-relay.cloudflare.com",
        "apple-relay.fastly-edge.com",
        "cp4.cloudflare.com",
    },
}

APPLE_XCODE_HOSTS = {
    "devimages-cdn.apple.com",
    "download.developer.apple.com",
}
APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS = {
    "apple-relay.cloudflare.com",
    "apple-relay.fastly-edge.com",
    "cp4.cloudflare.com",
}
APPLE_PCC_DNS_ATTEMPTS = 8
APPLE_PCC_DOH_RESOLVER = XCODE_DOH_RESOLVER
APPLE_PCC_DOH_ECS_SUBNETS = XCODE_DOH_ECS_SUBNETS

UBUNTU_MOTD_HOSTS = {"motd.ubuntu.com"}
UBUNTU_DNS_ATTEMPTS = 8
UBUNTU_DOH_RESOLVER = XCODE_DOH_RESOLVER
UBUNTU_DOH_ECS_SUBNETS = XCODE_DOH_ECS_SUBNETS

APPLE_APP_WILDCARD_TARGETS = {
    "*.itunes.apple.com": ("itunes.apple.com",),
    "*.apps.apple.com": ("apps.apple.com",),
    "*.mzstatic.com": ("mzstatic.com",),
    "*.appattest.apple.com": ("appattest.apple.com",),
    "*.apps-marketplace.apple.com": ("apps-marketplace.apple.com",),
}
APPLE_DEVICE_WILDCARD_TARGETS = {
    "*.push.apple.com": ("api.push.apple.com", "api.development.push.apple.com"),
    "*.appattest.apple.com": ("appattest.apple.com",),
}

MICROSOFT_EDGE_HOSTS = {
    "msedge.api.cdp.microsoft.com",
    "config.edge.skype.com",
    "edge.microsoft.com",
    "clients.config.office.net",
    "edgepasskeysenclave.microsoft.com",
    "msedge.b.dl.delivery.mp.microsoft.com",
    "msedge.b.tlu.dl.delivery.mp.microsoft.com",
    "msedge.f.dl.delivery.mp.microsoft.com",
    "msedge.f.tlu.dl.delivery.mp.microsoft.com",
    "msedge.sb.dl.delivery.mp.microsoft.com",
    "msedge.sb.tlu.dl.delivery.mp.microsoft.com",
    "msedge.sf.dl.delivery.mp.microsoft.com",
    "msedge.sf.tlu.dl.delivery.mp.microsoft.com",
    "msedgeextensions.b.dl.delivery.mp.microsoft.com",
    "msedgeextensions.b.tlu.dl.delivery.mp.microsoft.com",
    "msedgeextensions.f.dl.delivery.mp.microsoft.com",
    "msedgeextensions.f.tlu.dl.delivery.mp.microsoft.com",
    "msedgeextensions.sb.dl.delivery.mp.microsoft.com",
    "msedgeextensions.sb.tlu.dl.delivery.mp.microsoft.com",
    "msedgeextensions.sf.dl.delivery.mp.microsoft.com",
    "msedgeextensions.sf.tlu.dl.delivery.mp.microsoft.com",
}
MICROSOFT_WINDOWS_HOSTS = {
    "adl.windows.com",
    "checkappexec.microsoft.com",
    "ctldl.windowsupdate.com",
    "data-edge.smartscreen.microsoft.com",
    "definitionupdates.microsoft.com",
    "displaycatalog.mp.microsoft.com",
    "licensing.mp.microsoft.com",
    "manage.devcenter.microsoft.com",
    "nav-edge.smartscreen.microsoft.com",
    "ping-edge.smartscreen.microsoft.com",
    "settings-win.data.microsoft.com",
    "settings.data.microsoft.com",
    "share.microsoft.com",
    "storecatalogrevocation.storequality.microsoft.com",
    "storeedgefd.dsx.mp.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "tsfe.trafficshaping.dsp.mp.microsoft.com",
    "www.telecommandsvc.microsoft.com",
}

# Microsoft documents these wildcard families for Windows Update, Delivery
# Optimization, and Intune. DNS wildcards can't be queried directly, so the
# generator resolves only concrete, auditable service names below. The IPs are
# never hard-coded and may change on every workflow run.
WINDOWS_UPDATE_WILDCARD_TARGETS = {
    "*.prod.do.dsp.mp.microsoft.com": (
        "array504.prod.do.dsp.mp.microsoft.com",
        "array506.prod.do.dsp.mp.microsoft.com",
        "array508.prod.do.dsp.mp.microsoft.com",
        "array511.prod.do.dsp.mp.microsoft.com",
        "array516.prod.do.dsp.mp.microsoft.com",
        "array804.prod.do.dsp.mp.microsoft.com",
        "array808.prod.do.dsp.mp.microsoft.com",
        "disc501.prod.do.dsp.mp.microsoft.com",
        "disc601.prod.do.dsp.mp.microsoft.com",
        "disc801.prod.do.dsp.mp.microsoft.com",
        "geo-prod.do.dsp.mp.microsoft.com",
        "geo.prod.do.dsp.mp.microsoft.com",
        "geover-prod.do.dsp.mp.microsoft.com",
        "geover.prod.do.dsp.mp.microsoft.com",
        "kv501.prod.do.dsp.mp.microsoft.com",
        "kv601.prod.do.dsp.mp.microsoft.com",
        "kv801.prod.do.dsp.mp.microsoft.com",
    ),
    "*.dl.delivery.mp.microsoft.com": ("dl.delivery.mp.microsoft.com",),
    "*.delivery.mp.microsoft.com": ("fe3cr.delivery.mp.microsoft.com",),
    "*.update.microsoft.com": ("update.microsoft.com",),
    "*.windowsupdate.com": (
        "ctldl.windowsupdate.com",
        "download.windowsupdate.com",
    ),
}

DELIVERY_OPTIMIZATION_REQUIRED_PATTERNS = {
    "geover-prod.do.dsp.mp.microsoft.com",
    "geo-prod.do.dsp.mp.microsoft.com",
    "geo.prod.do.dsp.mp.microsoft.com",
    "geover.prod.do.dsp.mp.microsoft.com",
    "kv*.prod.do.dsp.mp.microsoft.com",
    "disc*.prod.do.dsp.mp.microsoft.com",
    "array*.prod.do.dsp.mp.microsoft.com",
    "dl.delivery.mp.microsoft.com",
    "*.windowsupdate.com",
}

INTUNE_EVENT_WILDCARD_TARGETS = {
    "*.events.data.microsoft.com": (
        "events.data.microsoft.com",
        "functional.events.data.microsoft.com",
        "self.events.data.microsoft.com",
        "v10.events.data.microsoft.com",
        "v10c.events.data.microsoft.com",
        "v20.events.data.microsoft.com",
        "mobile.events.data.microsoft.com",
        "au-mobile.events.data.microsoft.com",
        "eu-mobile.events.data.microsoft.com",
        "uk-mobile.events.data.microsoft.com",
        "us-mobile.events.data.microsoft.com",
        "au-v20.events.data.microsoft.com",
        "browser.events.data.microsoft.com",
        "eu-v20.events.data.microsoft.com",
        "uk-v20.events.data.microsoft.com",
        "us-v20.events.data.microsoft.com",
        "umwatsonc.events.data.microsoft.com",
        "watson.events.data.microsoft.com",
    ),
}
INTUNE_EVENT_EXACT_SOURCE_REQUIREMENTS = {
    WINDOWS_DIAGNOSTIC_ENDPOINTS_URL: {"watson.events.data.microsoft.com"},
    CONFIGMGR_INTERNET_ENDPOINTS_URL: {"umwatsonc.events.data.microsoft.com"},
}

MICROSOFT_DOH_RESOLVER = XCODE_DOH_RESOLVER
MICROSOFT_DOH_ECS_SUBNETS = XCODE_DOH_ECS_SUBNETS
MICROSOFT_DOH_ATTEMPTS = 8
MICROSOFT_INTUNE_DOH_HOSTS = set(
    INTUNE_EVENT_WILDCARD_TARGETS["*.events.data.microsoft.com"]
)
MICROSOFT_EDGE_DOH_HOSTS = {
    "adl.windows.com",
    "array511.prod.do.dsp.mp.microsoft.com",
    "array804.prod.do.dsp.mp.microsoft.com",
    "config.edge.skype.com",
    "ctldl.windowsupdate.com",
    "dl.delivery.mp.microsoft.com",
    "download.windowsupdate.com",
    "fe3cr.delivery.mp.microsoft.com",
    "settings.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "update.microsoft.com",
}
MICROSOFT_DOH_HOSTS = MICROSOFT_INTUNE_DOH_HOSTS | MICROSOFT_EDGE_DOH_HOSTS

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
    """Capture commercial Teams media ranges across Microsoft Learn layouts."""

    LEGACY_H3 = "Media traffic: port ranges"
    LEGACY_H4 = "Microsoft 365, Office 365, and Office 365 GCC environments"
    CURRENT_H2 = "Media processor IP ranges"
    CURRENT_H3 = "Microsoft 365 / Office 365"

    def __init__(self) -> None:
        super().__init__()
        self.current_h2 = ""
        self.current_h3 = ""
        self.current_h4 = ""
        self.heading_tag: str | None = None
        self.heading_parts: list[str] = []
        self.target_parts: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        del attrs
        if tag in {"h2", "h3", "h4"}:
            self.heading_tag = tag
            self.heading_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag != self.heading_tag:
            return
        heading = " ".join("".join(self.heading_parts).split())
        if tag == "h2":
            self.current_h2 = heading
            self.current_h3 = ""
            self.current_h4 = ""
        elif tag == "h3":
            self.current_h3 = heading
            self.current_h4 = ""
        elif tag == "h4":
            self.current_h4 = heading
        self.heading_tag = None
        self.heading_parts = []

    def _in_commercial_media_section(self) -> bool:
        legacy = (
            self.current_h3 == self.LEGACY_H3
            and self.current_h4 == self.LEGACY_H4
        )
        current = (
            self.current_h2 == self.CURRENT_H2
            and self.current_h3 == self.CURRENT_H3
        )
        return legacy or current

    def handle_data(self, data: str) -> None:
        if self.heading_tag is not None:
            self.heading_parts.append(data)
        elif self._in_commercial_media_section():
            self.target_parts.append(data)


class AppleSectionTableParser(HTMLParser):
    """Capture rows from the first table following a selected Apple h2 id."""

    def __init__(self, section_id: str) -> None:
        super().__init__()
        self.section_id = section_id
        self.in_target_section = False
        self.in_target_table = False
        self.table_complete = False
        self.in_cell = False
        self.cell_parts: list[str] = []
        self.current_row: list[str] | None = None
        self.rows: list[list[str]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        if tag == "h2":
            self.in_target_section = attributes.get("id") == self.section_id
        elif tag == "table" and self.in_target_section and not self.table_complete:
            self.in_target_table = True
        elif tag == "tr" and self.in_target_table:
            self.current_row = []
        elif tag in {"th", "td"} and self.current_row is not None:
            self.in_cell = True
            self.cell_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"th", "td"} and self.in_cell and self.current_row is not None:
            self.current_row.append(" ".join("".join(self.cell_parts).split()))
            self.in_cell = False
            self.cell_parts = []
        elif tag == "tr" and self.current_row is not None:
            if self.current_row:
                self.rows.append(self.current_row)
            self.current_row = None
        elif tag == "table" and self.in_target_table:
            self.in_target_table = False
            self.table_complete = True

    def handle_data(self, data: str) -> None:
        if self.in_cell:
            self.cell_parts.append(data)


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
    parser.add_argument("--apple-enterprise-file", type=Path, required=True)
    parser.add_argument("--apple-apns-file", type=Path, required=True)
    parser.add_argument(
        "--apple-xcode-dns-observations-file", type=Path, required=True
    )
    parser.add_argument(
        "--apple-pcc-dns-observations-file", type=Path, required=True
    )
    parser.add_argument("--ubuntu-pro-defaults-file", type=Path, required=True)
    parser.add_argument(
        "--ubuntu-dns-observations-file", type=Path, required=True
    )
    parser.add_argument(
        "--microsoft-dns-observations-file", type=Path, required=True
    )
    parser.add_argument("--github-meta-file", type=Path, required=True)
    parser.add_argument("--dropbox-firewall-file", type=Path, required=True)
    parser.add_argument("--dropbox-arin-file", type=Path, required=True)
    parser.add_argument("--dell-update-file", type=Path, required=True)
    parser.add_argument("--microsoft-edge-file", type=Path, required=True)
    parser.add_argument("--microsoft-windows-file", type=Path, required=True)
    parser.add_argument(
        "--microsoft-delivery-optimization-file", type=Path, required=True
    )
    parser.add_argument(
        "--windows-diagnostic-endpoints-file", type=Path, required=True
    )
    parser.add_argument(
        "--configmgr-internet-endpoints-file", type=Path, required=True
    )
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


def load_json_source(path: Path, *, label: str) -> Any:
    body = load_bytes(path, label=label)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GenerationError(f"{label} contains invalid JSON: {error}") from error


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


def validate_m365_documented_urls(
    payload: Any,
    *,
    service_area: str,
    required_patterns: set[str],
) -> list[str]:
    """Require selected URL patterns in the official Microsoft 365 web service."""
    if not isinstance(payload, list) or not payload:
        raise GenerationError("Expected a non-empty JSON array from Microsoft 365")
    observed: set[str] = set()
    for record_index, record in enumerate(payload):
        if not isinstance(record, dict) or record.get("serviceArea") != service_area:
            continue
        raw_urls = record.get("urls")
        if raw_urls is None:
            continue
        if not isinstance(raw_urls, list):
            raise GenerationError(
                f"Microsoft 365 record {record_index} urls must be an array"
            )
        for url_index, raw_url in enumerate(raw_urls):
            if not isinstance(raw_url, str) or not raw_url.strip():
                raise GenerationError(
                    "Invalid Microsoft 365 URL at record "
                    f"{record_index}, urls[{url_index}]"
                )
            observed.add(hostname_from_token(raw_url))
    missing = required_patterns - observed
    if missing:
        raise GenerationError(
            f"Microsoft 365 {service_area} URLs no longer contain required "
            "patterns: " + ", ".join(sorted(missing))
        )
    return sorted(required_patterns)


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


def extract_intune_consolidated_values(
    intune_markdown: str, *, block_label: str
) -> list[str]:
    """Extract one fenced block from Intune's consolidated endpoint section."""
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
    block_markers = [
        index for index, line in enumerate(section) if line.strip() == block_label
    ]
    if len(block_markers) != 1:
        raise GenerationError(
            f"Expected exactly one Intune {block_label} block, found "
            f"{len(block_markers)}"
        )

    cursor = block_markers[0] + 1
    while cursor < len(section) and not section[cursor].strip():
        cursor += 1
    if cursor >= len(section) or section[cursor].strip() != "```":
        raise GenerationError(
            f"Unexpected Intune {block_label} code block opening"
        )

    cursor += 1
    values: list[str] = []
    while cursor < len(section) and section[cursor].strip() != "```":
        value = section[cursor].strip()
        if not value:
            raise GenerationError(
                f"Unexpected blank line in Intune {block_label} block"
            )
        values.append(value)
        cursor += 1
    if cursor >= len(section):
        raise GenerationError(f"Intune {block_label} code block isn't closed")
    if not values:
        raise GenerationError(f"Intune {block_label} block is empty")
    return values


def extract_intune_consolidated_hostnames(intune_markdown: str) -> list[str]:
    """Validate the FQDNs published in Intune's consolidated endpoint list."""
    hostnames = extract_intune_consolidated_values(
        intune_markdown, block_label="FQDNs"
    )
    if len(hostnames) != len(set(hostnames)):
        raise GenerationError("Intune consolidated FQDN block contains duplicates")
    for hostname in hostnames:
        validation_target = hostname[2:] if hostname.startswith("*.") else hostname
        if not HOSTNAME_PATTERN.fullmatch(validation_target):
            raise GenerationError(
                f"Invalid Intune consolidated FQDN {hostname!r}"
            )
    return sorted(hostnames)


def extract_intune_windows_networks(
    intune_markdown: str,
) -> list[ipaddress.IPv4Network]:
    """Extract only Microsoft's explicit consolidated Intune IP subnets."""
    raw_networks = extract_intune_consolidated_values(
        intune_markdown, block_label="IP Subnets"
    )

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


def extract_apple_section_hostnames(
    apple_html: str, *, section_id: str
) -> list[str]:
    parser = AppleSectionTableParser(section_id)
    parser.feed(apple_html)
    if not parser.table_complete or len(parser.rows) < 2:
        raise GenerationError(
            f"Unable to parse the Apple {section_id!r} endpoint table"
        )
    if parser.rows[0][:2] != ["Hosts", "Ports"]:
        raise GenerationError(f"Unexpected Apple {section_id!r} table header")

    hosts: list[str] = []
    for row_index, row in enumerate(parser.rows[1:], start=1):
        if len(row) != 6:
            raise GenerationError(
                f"Unexpected Apple {section_id!r} row width at row {row_index}"
            )
        hostname = row[0].strip().lower().rstrip(".")
        validation_target = hostname[2:] if hostname.startswith("*.") else hostname
        if not HOSTNAME_PATTERN.fullmatch(validation_target):
            raise GenerationError(
                f"Invalid Apple hostname {hostname!r} in section {section_id!r}"
            )
        hosts.append(hostname)

    if len(hosts) != len(set(hosts)):
        raise GenerationError(f"Duplicate Apple hostnames in section {section_id!r}")
    missing = APPLE_SECTION_REQUIREMENTS[section_id] - set(hosts)
    if missing:
        raise GenerationError(
            f"Apple section {section_id!r} no longer contains required hosts: "
            + ", ".join(sorted(missing))
        )
    return sorted(hosts)


def validate_ubuntu_motd_source(source: str) -> list[str]:
    """Validate Canonical's exact Ubuntu Pro APT News endpoint."""
    expected = 'APT_NEWS_URL = "https://motd.ubuntu.com/aptnews.json"'
    if expected not in source:
        raise GenerationError(
            "Canonical Ubuntu Pro defaults no longer document the expected "
            "motd.ubuntu.com APT News endpoint"
        )
    return sorted(UBUNTU_MOTD_HOSTS)


def expand_documented_hostnames(
    documented: list[str],
    *,
    wildcard_targets: dict[str, tuple[str, ...]],
    label: str,
) -> tuple[list[str], list[str], dict[str, tuple[str, ...]]]:
    exact = {hostname for hostname in documented if not hostname.startswith("*.")}
    wildcards = {hostname for hostname in documented if hostname.startswith("*.")}
    unexpected = wildcards - set(wildcard_targets)
    if unexpected:
        raise GenerationError(
            f"No audited {label} targets for wildcard patterns: "
            + ", ".join(sorted(unexpected))
        )
    selected_targets = {
        pattern: wildcard_targets[pattern] for pattern in sorted(wildcards)
    }
    for targets in selected_targets.values():
        exact.update(targets)
    for hostname in exact:
        if not HOSTNAME_PATTERN.fullmatch(hostname):
            raise GenerationError(f"Invalid {label} resolution target: {hostname}")
    return sorted(exact), sorted(wildcards), selected_targets


def resolve_service_hostnames(
    hostnames: list[str],
    *,
    label: str,
    attempts: int = 3,
    retry_delay_seconds: float = 0.1,
) -> tuple[
    list[ipaddress.IPv4Network],
    dict[str, list[str]],
    dict[str, list[str]],
    dict[str, str],
]:
    if not hostnames:
        raise GenerationError(f"No {label} hostnames selected")
    socket.setdefaulttimeout(20)
    networks: set[ipaddress.IPv4Network] = set()
    resolutions: dict[str, list[str]] = {}
    cname_chains: dict[str, list[str]] = {}
    unresolved: dict[str, str] = {}
    no_name_errors = {socket.EAI_NONAME}
    if hasattr(socket, "EAI_NODATA"):
        no_name_errors.add(socket.EAI_NODATA)

    for hostname in hostnames:
        addresses: set[str] = set()
        cname_chain: list[str] = []
        transient_error: socket.gaierror | None = None
        no_record = False
        for attempt in range(attempts):
            try:
                canonical_name, aliases, answers = socket.gethostbyname_ex(hostname)
            except socket.gaierror as error:
                if error.errno in no_name_errors:
                    no_record = True
                    break
                transient_error = error
            else:
                addresses.update(answers)
                for cname in (*aliases, canonical_name):
                    normalized = cname.strip().lower().rstrip(".")
                    if (
                        normalized
                        and normalized != hostname
                        and normalized not in cname_chain
                    ):
                        cname_chain.append(normalized)
            if attempt + 1 < attempts:
                time.sleep(retry_delay_seconds)

        if not addresses:
            if no_record:
                unresolved[hostname] = "DNS returned no A record"
                continue
            if transient_error is not None:
                raise GenerationError(
                    f"Unable to resolve {label} hostname {hostname} after "
                    f"{attempts} attempts: {transient_error}"
                ) from transient_error
            raise GenerationError(f"No IPv4 address returned for {label} {hostname}")

        sorted_addresses = sorted(addresses, key=ipaddress.IPv4Address)
        resolutions[hostname] = sorted_addresses
        cname_chains[hostname] = cname_chain
        for address in sorted_addresses:
            network = ipaddress.IPv4Network(f"{address}/32", strict=True)
            networks.add(
                validate_ipv4_network(network, context=f"{label} DNS {hostname}")
            )

    if not networks:
        raise GenerationError(f"{label} DNS resolution produced an empty IPv4 EDL")
    print(
        f"{label} DNS: {len(resolutions)}/{len(hostnames)} hostnames resolved to "
        f"{len(networks)} unique public IPv4 addresses"
    )
    if unresolved:
        print(
            f"{label} DNS: {len(unresolved)} documented hostnames currently "
            "have no A record"
        )
    return sort_networks(networks), resolutions, cname_chains, unresolved


def parse_utc_timestamp(value: Any, *, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise GenerationError(f"{label} must be an ISO-8601 string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GenerationError(f"Invalid {label}: {value!r}") from error
    if parsed.tzinfo is None:
        raise GenerationError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def format_utc_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def extract_doh_observations(
    source: str,
    *,
    authorized_hostnames: set[str],
    ecs_subnets: tuple[str, ...],
    resolver_url: str,
    required_attempts: int,
    label: str,
) -> tuple[
    dict[str, list[str]],
    dict[str, dict[str, dict[str, Any]]],
    dict[str, int],
]:
    """Validate controlled DNS-over-HTTPS observations for official FQDNs."""
    addresses_by_hostname: dict[str, set[str]] = {
        hostname: set() for hostname in authorized_hostnames
    }
    details: dict[str, dict[str, dict[str, Any]]] = {
        hostname: {} for hostname in authorized_hostnames
    }
    attempts: dict[tuple[str, str], set[int]] = {}

    for line_number, line in enumerate(source.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            observation = json.loads(line)
        except json.JSONDecodeError as error:
            raise GenerationError(
                f"Invalid {label} DNS observation JSON at line {line_number}: {error}"
            ) from error
        if not isinstance(observation, dict):
            raise GenerationError(
                f"{label} DNS observation line {line_number} must be an object"
            )
        hostname = observation.get("fqdn")
        ecs_subnet = observation.get("ecsSubnet")
        resolver = observation.get("resolver")
        attempt = observation.get("attempt")
        response = observation.get("response")
        if hostname not in authorized_hostnames:
            raise GenerationError(
                f"Unauthorized {label} DNS observation hostname: {hostname!r}"
            )
        if ecs_subnet not in ecs_subnets:
            raise GenerationError(
                f"Unauthorized {label} DNS ECS subnet: {ecs_subnet!r}"
            )
        if resolver != resolver_url:
            raise GenerationError(
                f"Unexpected {label} DNS resolver: {resolver!r}"
            )
        if not isinstance(attempt, int) or not 1 <= attempt <= required_attempts:
            raise GenerationError(
                f"Invalid {label} DNS attempt at line {line_number}: {attempt!r}"
            )
        if not isinstance(response, dict) or response.get("Status") != 0:
            raise GenerationError(
                f"{label} DNS resolver returned an error at line {line_number}"
            )
        response_ecs_subnet = response.get("edns_client_subnet")
        try:
            requested_ecs = ipaddress.IPv4Network(ecs_subnet)
            if not isinstance(response_ecs_subnet, str):
                raise ValueError("ECS response isn't a string")
            returned_address_text, returned_scope_text = (
                response_ecs_subnet.rsplit("/", 1)
            )
            returned_address = ipaddress.IPv4Address(returned_address_text)
            returned_scope = int(returned_scope_text)
            if not 0 <= returned_scope <= 32:
                raise ValueError("ECS scope is outside 0..32")
        except (ValueError, ipaddress.AddressValueError) as error:
            raise GenerationError(
                f"Invalid {label} DNS ECS response at line {line_number}"
            ) from error
        if returned_address not in requested_ecs:
            raise GenerationError(
                f"{label} DNS ECS response escaped the requested subnet at line {line_number}"
            )
        questions = response.get("Question")
        if (
            not isinstance(questions, list)
            or len(questions) != 1
            or not isinstance(questions[0], dict)
            or questions[0].get("type") != 1
            or not isinstance(questions[0].get("name"), str)
            or questions[0]["name"].strip().lower().rstrip(".") != hostname
        ):
            raise GenerationError(
                f"{label} DNS response question mismatch at line {line_number}"
            )
        answers = response.get("Answer")
        if not isinstance(answers, list):
            raise GenerationError(
                f"{label} DNS response has no Answer list at line {line_number}"
            )

        cname_targets: dict[str, str] = {}
        addresses_by_owner: dict[str, list[str]] = {}
        for answer in answers:
            if not isinstance(answer, dict):
                raise GenerationError(
                    f"Invalid {label} DNS answer at line {line_number}"
                )
            record_type = answer.get("type")
            data = answer.get("data")
            owner = answer.get("name")
            if not isinstance(data, str) or not isinstance(owner, str):
                continue
            normalized = data.strip().lower().rstrip(".")
            normalized_owner = owner.strip().lower().rstrip(".")
            if not HOSTNAME_PATTERN.fullmatch(normalized_owner):
                raise GenerationError(
                    f"Invalid {label} DNS answer owner at line {line_number}: {owner!r}"
                )
            if record_type == 5:
                if not HOSTNAME_PATTERN.fullmatch(normalized):
                    raise GenerationError(
                        f"Invalid {label} DNS CNAME at line {line_number}: {data!r}"
                    )
                previous_target = cname_targets.setdefault(
                    normalized_owner, normalized
                )
                if previous_target != normalized:
                    raise GenerationError(
                        f"Conflicting {label} DNS CNAMEs at line {line_number}"
                    )
            elif record_type == 1:
                try:
                    address = ipaddress.IPv4Address(normalized)
                except ipaddress.AddressValueError as error:
                    raise GenerationError(
                        f"Invalid {label} DNS A record at line {line_number}: {data!r}"
                    ) from error
                validate_ipv4_network(
                    ipaddress.IPv4Network(f"{address}/32"),
                    context=f"{label} DNS-over-HTTPS {hostname}",
                )
                addresses_by_owner.setdefault(normalized_owner, []).append(
                    str(address)
                )

        cname_chain: list[str] = []
        terminal_name = hostname
        visited = {hostname}
        while terminal_name in cname_targets:
            terminal_name = cname_targets[terminal_name]
            if terminal_name in visited:
                raise GenerationError(
                    f"{label} DNS CNAME loop at line {line_number}"
                )
            visited.add(terminal_name)
            cname_chain.append(terminal_name)
        addresses = addresses_by_owner.get(terminal_name, [])
        if not addresses:
            raise GenerationError(
                f"{label} DNS response returned no public A record at the end of "
                f"its CNAME chain at line {line_number}"
            )

        source_name = f"google-doh-ecs:{returned_address}/{returned_scope}"
        for address in addresses:
            addresses_by_hostname[hostname].add(address)
            record = details[hostname].setdefault(
                address,
                {"cnameChain": list(cname_chain), "observationSources": []},
            )
            if len(cname_chain) > len(record["cnameChain"]):
                record["cnameChain"] = list(cname_chain)
            if source_name not in record["observationSources"]:
                record["observationSources"].append(source_name)
        attempts.setdefault((hostname, ecs_subnet), set()).add(attempt)

    required_pairs = {
        (hostname, subnet)
        for hostname in authorized_hostnames
        for subnet in ecs_subnets
    }
    missing = required_pairs - set(attempts)
    if missing:
        raise GenerationError(
            f"Missing {label} DNS observation series for: "
            + ", ".join(f"{hostname}@{subnet}" for hostname, subnet in sorted(missing))
        )
    incomplete = {
        pair: len(observed) for pair, observed in attempts.items()
        if len(observed) != required_attempts
    }
    if incomplete:
        raise GenerationError(
            f"Incomplete {label} DNS observation series: "
            + ", ".join(
                f"{hostname}@{subnet}={count}/{required_attempts}"
                for (hostname, subnet), count in sorted(incomplete.items())
            )
        )

    resolutions = {
        hostname: sorted(addresses, key=ipaddress.IPv4Address)
        for hostname, addresses in sorted(addresses_by_hostname.items())
    }
    counts = {
        f"{hostname}@{subnet}": len(values)
        for (hostname, subnet), values in sorted(attempts.items())
    }
    return resolutions, details, counts


def extract_xcode_doh_observations(
    source: str,
) -> tuple[
    dict[str, list[str]],
    dict[str, dict[str, dict[str, Any]]],
    dict[str, int],
]:
    return extract_doh_observations(
        source,
        authorized_hostnames=APPLE_XCODE_HOSTS,
        ecs_subnets=XCODE_DOH_ECS_SUBNETS,
        resolver_url=XCODE_DOH_RESOLVER,
        required_attempts=XCODE_DNS_ATTEMPTS,
        label="Xcode",
    )


def combine_xcode_observations(
    *,
    native_resolutions: dict[str, list[str]],
    native_cname_chains: dict[str, list[str]],
    doh_resolutions: dict[str, list[str]],
    doh_details: dict[str, dict[str, dict[str, Any]]],
) -> tuple[dict[str, list[str]], dict[str, dict[str, dict[str, Any]]]]:
    combined: dict[str, set[str]] = {
        hostname: set() for hostname in APPLE_XCODE_HOSTS
    }
    details: dict[str, dict[str, dict[str, Any]]] = {
        hostname: {} for hostname in APPLE_XCODE_HOSTS
    }
    for hostname, addresses in native_resolutions.items():
        for address in addresses:
            combined[hostname].add(address)
            details[hostname][address] = {
                "cnameChain": list(native_cname_chains.get(hostname, [])),
                "observationSources": ["system-resolver"],
            }
    for hostname, addresses in doh_resolutions.items():
        for address in addresses:
            combined[hostname].add(address)
            incoming = doh_details[hostname][address]
            record = details[hostname].setdefault(
                address,
                {
                    "cnameChain": list(incoming["cnameChain"]),
                    "observationSources": [],
                },
            )
            if len(incoming["cnameChain"]) > len(record["cnameChain"]):
                record["cnameChain"] = list(incoming["cnameChain"])
            record["observationSources"] = sorted(
                set(record["observationSources"])
                | set(incoming["observationSources"])
            )
    resolutions = {
        hostname: sorted(addresses, key=ipaddress.IPv4Address)
        for hostname, addresses in sorted(combined.items())
    }
    return resolutions, details


def combine_dns_observation_details(
    *,
    authorized_hostnames: set[str],
    observation_sets: list[dict[str, dict[str, dict[str, Any]]]],
) -> tuple[dict[str, list[str]], dict[str, dict[str, dict[str, Any]]]]:
    """Merge current system/DoH observations without losing provenance."""
    combined: dict[str, dict[str, dict[str, Any]]] = {
        hostname: {} for hostname in authorized_hostnames
    }
    for observations in observation_sets:
        unexpected = set(observations) - authorized_hostnames
        if unexpected:
            raise GenerationError(
                "DNS observation set contains unauthorized hostnames: "
                + ", ".join(sorted(unexpected))
            )
        for hostname, records in observations.items():
            for address, incoming in records.items():
                record = combined[hostname].setdefault(
                    address,
                    {"cnameChain": [], "observationSources": []},
                )
                incoming_chain = incoming.get("cnameChain", [])
                incoming_sources = incoming.get("observationSources", [])
                if len(incoming_chain) > len(record["cnameChain"]):
                    record["cnameChain"] = list(incoming_chain)
                record["observationSources"] = sorted(
                    set(record["observationSources"]) | set(incoming_sources)
                )
    resolutions = {
        hostname: sorted(records, key=ipaddress.IPv4Address)
        for hostname, records in sorted(combined.items())
        if records
    }
    return resolutions, combined


def build_dns_observation_details(
    *,
    authorized_hostnames: set[str],
    resolutions: dict[str, list[str]],
    cname_chains: dict[str, list[str]],
    observation_source: str,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Convert current DNS results to the common auditable history schema."""
    unexpected = set(resolutions) - authorized_hostnames
    if unexpected:
        raise GenerationError(
            "DNS observations contain unauthorized hostnames: "
            + ", ".join(sorted(unexpected))
        )
    details: dict[str, dict[str, dict[str, Any]]] = {
        hostname: {} for hostname in authorized_hostnames
    }
    for hostname, addresses in resolutions.items():
        for address in addresses:
            validate_ipv4_network(
                ipaddress.IPv4Network(f"{address}/32", strict=True),
                context=f"current DNS observation {hostname}",
            )
            details[hostname][address] = {
                "cnameChain": list(cname_chains.get(hostname, [])),
                "observationSources": [observation_source],
            }
    return details


def build_dns_history(
    *,
    previous_sources: Any | None,
    filename: str,
    authorized_hostnames: set[str],
    current_details: dict[str, dict[str, dict[str, Any]]],
    observed_at: dt.datetime,
    label: str,
    grace_period: dt.timedelta = DNS_HISTORY_GRACE_PERIOD,
) -> tuple[
    list[ipaddress.IPv4Network],
    dict[str, list[str]],
    dict[str, dict[str, dict[str, Any]]],
    list[dict[str, str]],
]:
    """Merge official DNS observations into a bounded rolling history."""
    observed_at = observed_at.astimezone(dt.timezone.utc)
    history: dict[str, dict[str, dict[str, Any]]] = {
        hostname: {} for hostname in authorized_hostnames
    }
    previous_file: dict[str, Any] = {}
    previous_generated_at: dt.datetime | None = None
    if previous_sources is not None:
        if not isinstance(previous_sources, dict):
            raise GenerationError("Previous sources.json must contain an object")
        previous_generated_at = parse_utc_timestamp(
            previous_sources.get("generatedAt"), label="previous generatedAt"
        )
        files = previous_sources.get("files")
        if not isinstance(files, dict):
            raise GenerationError("Previous sources.json has no files object")
        candidate = files.get(filename, {})
        if not isinstance(candidate, dict):
            raise GenerationError(f"Previous {label} source metadata must be an object")
        previous_file = candidate

    previous_history = previous_file.get("dnsHistory")
    if previous_history is not None:
        if not isinstance(previous_history, dict):
            raise GenerationError(f"Previous {label} dnsHistory must be an object")
        records_by_hostname = previous_history.get("recordsByHostname")
        if not isinstance(records_by_hostname, dict):
            raise GenerationError(
                f"Previous {label} dnsHistory has no recordsByHostname object"
            )
        unexpected_hosts = set(records_by_hostname) - authorized_hostnames
        if unexpected_hosts:
            raise GenerationError(
                f"Previous {label} DNS history contains unauthorized hostnames: "
                + ", ".join(sorted(unexpected_hosts))
            )
        for hostname, records in records_by_hostname.items():
            if not isinstance(records, dict):
                raise GenerationError(
                    f"Previous {label} DNS history for {hostname} must be an object"
                )
            for address, record in records.items():
                if not isinstance(record, dict):
                    raise GenerationError(
                        f"Previous {label} DNS history record {hostname}/{address} is invalid"
                    )
                network = validate_ipv4_network(
                    ipaddress.IPv4Network(f"{address}/32", strict=True),
                    context=f"previous {label} DNS history {hostname}",
                )
                first_seen = parse_utc_timestamp(
                    record.get("firstSeen"), label=f"firstSeen for {hostname}/{address}"
                )
                last_seen = parse_utc_timestamp(
                    record.get("lastSeen"), label=f"lastSeen for {hostname}/{address}"
                )
                if first_seen > last_seen or last_seen > observed_at + dt.timedelta(minutes=5):
                    raise GenerationError(
                        f"Invalid {label} DNS history timestamps for {hostname}/{address}"
                    )
                cname_chain = record.get("cnameChain", [])
                sources = record.get("observationSources", [])
                if not isinstance(cname_chain, list) or not all(
                    isinstance(value, str) and HOSTNAME_PATTERN.fullmatch(value)
                    for value in cname_chain
                ):
                    raise GenerationError(
                        f"Invalid {label} CNAME history for {hostname}/{address}"
                    )
                if not isinstance(sources, list) or not all(
                    isinstance(value, str) and value for value in sources
                ):
                    raise GenerationError(
                        f"Invalid {label} observation sources for {hostname}/{address}"
                    )
                history[hostname][str(network.network_address)] = {
                    "cnameChain": cname_chain,
                    "firstSeen": format_utc_timestamp(first_seen),
                    "lastSeen": format_utc_timestamp(last_seen),
                    "observationSources": sorted(set(sources)),
                }
    elif previous_file and previous_generated_at is not None:
        legacy_resolutions = previous_file.get("resolvedHostnames", {})
        legacy_chains = previous_file.get("cnameChains", {})
        if not isinstance(legacy_resolutions, dict) or not isinstance(
            legacy_chains, dict
        ):
            raise GenerationError(f"Previous {label} DNS metadata is malformed")
        for hostname, addresses in legacy_resolutions.items():
            if hostname not in authorized_hostnames or not isinstance(addresses, list):
                raise GenerationError(
                    f"Previous {label} DNS metadata is unauthorized"
                )
            for address in addresses:
                network = validate_ipv4_network(
                    ipaddress.IPv4Network(f"{address}/32", strict=True),
                    context=f"legacy {label} DNS history {hostname}",
                )
                history[hostname][str(network.network_address)] = {
                    "cnameChain": list(legacy_chains.get(hostname, [])),
                    "firstSeen": format_utc_timestamp(previous_generated_at),
                    "lastSeen": format_utc_timestamp(previous_generated_at),
                    "observationSources": ["previous-published-dns-snapshot"],
                }

    now_text = format_utc_timestamp(observed_at)
    for hostname, records in current_details.items():
        if hostname not in authorized_hostnames:
            raise GenerationError(f"Unauthorized current {label} hostname: {hostname}")
        if not isinstance(records, dict):
            raise GenerationError(f"Current {label} records must be an object")
        for address, current in records.items():
            if not isinstance(current, dict):
                raise GenerationError(
                    f"Current {label} record {hostname}/{address} is invalid"
                )
            validate_ipv4_network(
                ipaddress.IPv4Network(f"{address}/32", strict=True),
                context=f"current {label} DNS observation {hostname}",
            )
            cname_chain = current.get("cnameChain", [])
            sources = current.get("observationSources", [])
            if not isinstance(cname_chain, list) or not all(
                isinstance(value, str) and HOSTNAME_PATTERN.fullmatch(value)
                for value in cname_chain
            ):
                raise GenerationError(
                    f"Invalid current {label} CNAME chain for {hostname}/{address}"
                )
            if not isinstance(sources, list) or not all(
                isinstance(value, str) and value for value in sources
            ):
                raise GenerationError(
                    f"Invalid current {label} observation sources for {hostname}/{address}"
                )
            existing = history[hostname].get(address)
            history[hostname][address] = {
                "cnameChain": list(cname_chain),
                "firstSeen": existing["firstSeen"] if existing else now_text,
                "lastSeen": now_text,
                "observationSources": sorted(
                    set(sources)
                    | set(existing["observationSources"] if existing else [])
                ),
            }

    expired: list[dict[str, str]] = []
    for hostname in sorted(history):
        for address, record in list(history[hostname].items()):
            last_seen = parse_utc_timestamp(
                record["lastSeen"], label=f"lastSeen for {hostname}/{address}"
            )
            if observed_at - last_seen > grace_period:
                expired.append(
                    {"fqdn": hostname, "ip": address, "lastSeen": record["lastSeen"]}
                )
                del history[hostname][address]

    networks: set[ipaddress.IPv4Network] = set()
    active_resolutions: dict[str, list[str]] = {}
    for hostname, records in sorted(history.items()):
        active_resolutions[hostname] = sorted(records, key=ipaddress.IPv4Address)
        for address in records:
            networks.add(
                validate_ipv4_network(
                    ipaddress.IPv4Network(f"{address}/32", strict=True),
                    context=f"active {label} DNS history {hostname}",
                )
            )
    if not networks:
        raise GenerationError(f"{label} DNS history produced an empty IPv4 EDL")
    return sort_networks(networks), active_resolutions, history, expired


def build_xcode_dns_history(
    *,
    previous_sources: Any | None,
    current_details: dict[str, dict[str, dict[str, Any]]],
    observed_at: dt.datetime,
) -> tuple[
    list[ipaddress.IPv4Network],
    dict[str, list[str]],
    dict[str, dict[str, dict[str, Any]]],
    list[dict[str, str]],
]:
    """Merge official Xcode DNS observations into a bounded 24-hour history."""
    return build_dns_history(
        previous_sources=previous_sources,
        filename=APPLE_XCODE_FILE,
        authorized_hostnames=APPLE_XCODE_HOSTS,
        current_details=current_details,
        observed_at=observed_at,
        label="Apple Xcode",
        grace_period=XCODE_DNS_GRACE_PERIOD,
    )


def extract_github_actions_hostnames(payload: Any) -> list[str]:
    """Select only concrete Actions FQDNs published by GitHub's Meta API."""
    if not isinstance(payload, dict):
        raise GenerationError("Expected a JSON object from the GitHub Meta API")
    domains = payload.get("domains")
    if not isinstance(domains, dict):
        raise GenerationError("GitHub Meta domains field is missing")
    actions = domains.get("actions")
    actions_inbound = domains.get("actions_inbound")
    if not isinstance(actions, list) or not actions:
        raise GenerationError("GitHub Meta domains.actions is missing or empty")
    if not isinstance(actions_inbound, dict):
        raise GenerationError("GitHub Meta domains.actions_inbound is missing")
    inbound_full = actions_inbound.get("full_domains")
    if not isinstance(inbound_full, list) or not inbound_full:
        raise GenerationError(
            "GitHub Meta domains.actions_inbound.full_domains is missing or empty"
        )
    if "*.actions.githubusercontent.com" not in actions:
        raise GenerationError(
            "GitHub Meta no longer documents *.actions.githubusercontent.com"
        )

    selected: set[str] = set()
    for hostname in [*actions, *inbound_full]:
        if not isinstance(hostname, str):
            raise GenerationError("GitHub Meta Actions domains must be strings")
        normalized = hostname.strip().lower().rstrip(".")
        if normalized.startswith("*."):
            continue
        if normalized.endswith(GITHUB_ACTIONS_SUFFIX):
            if not HOSTNAME_PATTERN.fullmatch(normalized):
                raise GenerationError(
                    f"Invalid GitHub Actions hostname: {normalized!r}"
                )
            selected.add(normalized)

    missing = GITHUB_ACTIONS_REQUIRED_HOSTS - selected
    if missing:
        raise GenerationError(
            "GitHub Meta no longer publishes required Actions endpoints: "
            + ", ".join(sorted(missing))
        )
    return sorted(selected)


def extract_github_networks(
    payload: Any,
) -> tuple[list[ipaddress.IPv4Network], dict[str, int]]:
    if not isinstance(payload, dict):
        raise GenerationError("Expected a JSON object from the GitHub Meta API")
    networks: set[ipaddress.IPv4Network] = set()
    field_counts: dict[str, int] = {}
    for field in GITHUB_META_FIELDS:
        values = payload.get(field)
        if not isinstance(values, list) or not values:
            raise GenerationError(f"GitHub Meta field {field!r} is missing or empty")
        field_count = 0
        for index, raw_network in enumerate(values):
            if not isinstance(raw_network, str) or not raw_network:
                raise GenerationError(f"Invalid GitHub {field}[{index}] CIDR")
            try:
                network = ipaddress.ip_network(raw_network, strict=True)
            except ValueError as error:
                raise GenerationError(
                    f"Invalid GitHub {field}[{index}] CIDR {raw_network!r}: {error}"
                ) from error
            if network.version == 6:
                continue
            if not isinstance(network, ipaddress.IPv4Network):
                raise GenerationError(f"Unexpected GitHub IP version in {field}")
            networks.add(
                validate_ipv4_network(network, context=f"GitHub Meta {field}")
            )
            field_count += 1
        if field_count == 0:
            raise GenerationError(f"GitHub Meta field {field!r} has no IPv4 CIDR")
        field_counts[field] = field_count
    if not networks:
        raise GenerationError("GitHub Meta API produced an empty IPv4 EDL")
    return sort_networks(networks), field_counts


def extract_dropbox_networks(
    payload: Any, *, firewall_html: str
) -> tuple[list[ipaddress.IPv4Network], list[dict[str, str]], list[str]]:
    if "whois.arin.net/rest/org/dropb/nets" not in firewall_html.lower():
        raise GenerationError(
            "Dropbox firewall guidance no longer links to its ARIN allocations"
        )
    try:
        records = payload["nets"]["netRef"]
    except (KeyError, TypeError) as error:
        raise GenerationError("Unexpected Dropbox ARIN response format") from error
    if not isinstance(records, list) or not records:
        raise GenerationError("Dropbox ARIN response contains no network records")

    networks: set[ipaddress.IPv4Network] = set()
    selected_records: list[dict[str, str]] = []
    excluded_names: set[str] = set()
    seen_product_names: set[str] = set()
    for record_index, record in enumerate(records):
        if not isinstance(record, dict):
            raise GenerationError(f"Invalid Dropbox ARIN record {record_index}")
        name = record.get("@name")
        start = record.get("@startAddress")
        end = record.get("@endAddress")
        handle = record.get("@handle")
        if not all(isinstance(value, str) and value for value in (name, start, end, handle)):
            raise GenerationError(f"Incomplete Dropbox ARIN record {record_index}")
        try:
            start_address = ipaddress.ip_address(start)
            end_address = ipaddress.ip_address(end)
        except ValueError as error:
            raise GenerationError(
                f"Invalid Dropbox ARIN address at record {record_index}: {error}"
            ) from error
        if start_address.version == 6:
            continue
        if name not in DROPBOX_PRODUCT_NET_NAMES:
            excluded_names.add(name)
            continue
        if not isinstance(start_address, ipaddress.IPv4Address) or not isinstance(
            end_address, ipaddress.IPv4Address
        ):
            raise GenerationError("Unexpected Dropbox ARIN IP version")
        if end_address < start_address:
            raise GenerationError(f"Reversed Dropbox ARIN range {start} - {end}")
        record_networks = list(
            ipaddress.summarize_address_range(start_address, end_address)
        )
        for network in record_networks:
            networks.add(
                validate_ipv4_network(network, context=f"Dropbox ARIN {handle}")
            )
        selected_records.append(
            {"name": name, "handle": handle, "start": start, "end": end}
        )
        seen_product_names.add(name)

    missing_names = DROPBOX_PRODUCT_NET_NAMES - seen_product_names
    if missing_names:
        raise GenerationError(
            "Dropbox ARIN source no longer contains expected product allocations: "
            + ", ".join(sorted(missing_names))
        )
    if not networks:
        raise GenerationError("Dropbox ARIN source produced an empty IPv4 EDL")
    return sort_networks(networks), selected_records, sorted(excluded_names)


def validate_documented_hostnames(
    source: str, hostnames: set[str], *, label: str
) -> list[str]:
    lowered = html.unescape(source).lower()
    missing = {hostname for hostname in hostnames if hostname not in lowered}
    if missing:
        raise GenerationError(
            f"Official {label} source no longer contains required hostnames: "
            + ", ".join(sorted(missing))
        )
    return sorted(hostnames)


def validate_dell_catalog_source(source: bytes) -> list[str]:
    """Validate Dell's official update catalog and select its exact host."""
    hostname = urlsplit(DELL_UPDATE_URL).hostname
    if hostname != "downloads.dell.com":
        raise GenerationError("Unexpected Dell catalog source hostname")
    if not source.startswith(b"MSCF"):
        raise GenerationError("Dell update catalog is not a valid CAB payload")
    return [hostname]


def exclude_existing_networks(
    networks: list[ipaddress.IPv4Network],
    generated: dict[str, list[ipaddress.IPv4Network]],
) -> tuple[list[ipaddress.IPv4Network], dict[str, list[str]]]:
    kept: list[ipaddress.IPv4Network] = []
    excluded: dict[str, list[str]] = {}
    for network in networks:
        if network.prefixlen != 32:
            raise GenerationError(
                "Only DNS-derived /32 networks can be deduplicated against existing EDLs"
            )
        matches = [
            filename
            for filename, published in generated.items()
            if any(network.subnet_of(existing) for existing in published)
        ]
        if matches:
            excluded[str(network)] = sorted(matches)
        else:
            kept.append(network)
    if not kept:
        raise GenerationError(
            "Microsoft Edge/Windows EDL is empty after existing-list deduplication"
        )
    return sort_networks(kept), excluded


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


def residual_noncoverage_reason(address: ipaddress.IPv4Address) -> str:
    audit = INTERNET_ONLY_AUDIT_CONTEXT.get(str(address))
    if audit is not None:
        reason = audit.get("reason")
        if isinstance(reason, str) and reason:
            return reason
    shared_cdn = {
        ipaddress.IPv4Address(value)
        for value in {
            "52.85.118.32",
            "52.85.118.49",
            "52.85.118.61",
            "52.85.118.108",
            "95.101.137.11",
            "95.101.137.12",
            "95.101.137.14",
            "95.101.137.16",
            "95.101.137.21",
            "95.101.137.23",
            "95.101.137.24",
            "23.200.213.147",
            "23.58.84.19",
            "151.101.1.64",
            "151.101.129.64",
            "172.66.0.227",
            "162.159.194.64",
            "162.159.194.66",
            "172.64.69.66",
        }
    }
    if address in shared_cdn:
        return (
            "Shared CDN address not returned by an authorized service FQDN; "
            "global CloudFront, Akamai, Cloudflare, or Fastly ranges are forbidden"
        )
    if address == ipaddress.IPv4Address("143.166.124.33"):
        return (
            "PTR stor-g3-ph-legacy-pc1.dell.com observed, but the current A records "
            "of the officially documented downloads.dell.com endpoint do not "
            "contain this address; PTR ownership alone isn't authorization"
        )
    if address == ipaddress.IPv4Address("17.188.170.10"):
        return (
            "Not returned by the targeted official APNs FQDNs; the prohibited "
            "17.0.0.0/8 fallback was not used"
        )
    if str(address) in INTUNE_EVENT_RESIDUAL_IPS:
        if address == ipaddress.IPv4Address("20.184.175.2"):
            return (
                "Microsoft/Azure ownership observed, but no in-scope official "
                "Microsoft FQDN currently or recently maps this address to a service"
            )
        return (
            "Probable Microsoft telemetry address not returned during the current "
            "or rolling 24-hour DNS window by an authorized "
            "*.events.data.microsoft.com target"
        )
    if address in {
        ipaddress.IPv4Address("17.248.236.28"),
        ipaddress.IPv4Address("17.145.16.2"),
        ipaddress.IPv4Address("17.248.209.16"),
        ipaddress.IPv4Address("17.248.209.62"),
        ipaddress.IPv4Address("17.248.209.73"),
        ipaddress.IPv4Address("17.253.29.146"),
        ipaddress.IPv4Address("17.253.37.204"),
        ipaddress.IPv4Address("17.253.29.135"),
        ipaddress.IPv4Address("17.253.29.147"),
        ipaddress.IPv4Address("17.253.29.140"),
        ipaddress.IPv4Address("17.253.29.151"),
        ipaddress.IPv4Address("17.253.37.209"),
        ipaddress.IPv4Address("17.253.37.210"),
        ipaddress.IPv4Address("17.248.209.46"),
        ipaddress.IPv4Address("17.188.171.202"),
        ipaddress.IPv4Address("17.111.103.20"),
    }:
        return "Apple address not returned by an in-scope official FQDN"
    return (
        "No in-scope official source or current DNS A resolution maps this address "
        "to an authorized service"
    )


def residual_classification(
    address: ipaddress.IPv4Address,
    *,
    covered: bool,
    selected_file: str | None,
    fqdn: str | None,
) -> dict[str, Any]:
    """Describe ownership separately from service authorization evidence."""
    audit = INTERNET_ONLY_AUDIT_CONTEXT.get(str(address))
    if audit is not None:
        return {
            "owner": audit["owner"],
            "suspectedService": audit["suspectedService"],
            "verified": bool(covered and selected_file and fqdn),
        }
    if address == ipaddress.IPv4Address("20.85.108.33"):
        verified = (
            covered
            and selected_file == GITHUB_ACTIONS_FILE
            and fqdn == "tokenghub.actions.githubusercontent.com"
        )
        return {
            "owner": "Microsoft/Azure",
            "suspectedService": "GitHub Actions",
            "verified": verified,
        }
    if str(address) in INTUNE_EVENT_RESIDUAL_IPS:
        verified = bool(
            covered
            and selected_file == INTUNE_WINDOWS_FILE
            and fqdn
            and (
                fqdn == "events.data.microsoft.com"
                or fqdn.endswith(".events.data.microsoft.com")
            )
        )
        suspected_service = (
            "Unresolved Microsoft/Azure service"
            if address == ipaddress.IPv4Address("20.184.175.2")
            else "Microsoft telemetry / events.data.microsoft.com"
        )
        return {
            "owner": "Microsoft/Azure",
            "suspectedService": suspected_service,
            "verified": verified,
        }
    if address in ipaddress.IPv4Network("17.0.0.0/8"):
        return {
            "owner": "Apple",
            "suspectedService": "Apple service",
            "verified": bool(covered and selected_file in {
                APPLE_UPDATES_FILE,
                APPLE_CONTENT_FILE,
                APPLE_DEVICE_FILE,
                APPLE_XCODE_FILE,
            } and fqdn),
        }
    if address in ipaddress.IPv4Network("95.101.137.0/24"):
        return {
            "owner": "Akamai",
            "suspectedService": "Apple Maps / shared CDN",
            "verified": bool(covered and fqdn),
        }
    if address in {
        ipaddress.IPv4Address("162.159.194.64"),
        ipaddress.IPv4Address("162.159.194.66"),
        ipaddress.IPv4Address("172.64.69.66"),
        ipaddress.IPv4Address("172.66.0.227"),
    }:
        return {
            "owner": "Cloudflare",
            "suspectedService": "Shared CDN service",
            "verified": bool(covered and fqdn),
        }
    if address in {
        ipaddress.IPv4Address("151.101.1.64"),
        ipaddress.IPv4Address("151.101.129.64"),
    }:
        return {
            "owner": "Fastly",
            "suspectedService": "Shared CDN service",
            "verified": bool(covered and fqdn),
        }
    return {
        "owner": None,
        "suspectedService": None,
        "verified": covered,
    }


def build_residual_coverage(
    *,
    generated_at: str,
    generated: dict[str, list[ipaddress.IPv4Network]],
    resolutions_by_file: dict[str, dict[str, list[str]]],
    cname_chains_by_file: dict[str, dict[str, list[str]]],
    dns_history_by_file: dict[
        str, dict[str, dict[str, dict[str, Any]]]
    ],
) -> str:
    source_by_file = {
        "m365-common-ipv4.txt": "Microsoft 365 endpoint web service: Common",
        "m365-exchange-ipv4.txt": "Microsoft 365 endpoint web service: Exchange",
        "m365-sharepoint-ipv4.txt": "Microsoft 365 endpoint web service: SharePoint",
        "m365-teams-ipv4.txt": "Microsoft 365 endpoint web service: Skype",
        DEFENDER_FILE: "Official Microsoft Defender endpoints and DNS",
        TEAMS_MEDIA_FILE: "Microsoft Teams Direct Routing media ranges",
        INTUNE_WINDOWS_FILE: (
            "Microsoft Intune consolidated IP Subnets and official FQDN DNS"
        ),
        APPLE_UPDATES_FILE: "Apple enterprise Software updates FQDN resolution",
        APPLE_CONTENT_FILE: "Apple enterprise Apps and additional content FQDN resolution",
        APPLE_DEVICE_FILE: (
            "Apple enterprise Device management/APNs/Private Cloud Compute "
            "FQDN resolution"
        ),
        APPLE_XCODE_FILE: "Apple enterprise Xcode download FQDN resolution",
        UBUNTU_MOTD_FILE: "Canonical Ubuntu Pro APT News FQDN resolution",
        GITHUB_FILE: "GitHub Meta API fields web, api, git, and pages",
        GITHUB_ACTIONS_FILE: (
            "GitHub Meta official Actions FQDNs and rolling DNS resolution"
        ),
        DROPBOX_FILE: "Dropbox-linked ARIN product allocations",
        DELL_UPDATE_FILE: "Dell Command Update official FQDN resolution",
        MICROSOFT_EDGE_WINDOWS_FILE: (
            "Official Microsoft Edge, Windows, and Delivery Optimization "
            "endpoint FQDN resolution"
        ),
    }
    documentation_by_file = {
        "m365-common-ipv4.txt": M365_API_URL,
        "m365-exchange-ipv4.txt": M365_API_URL,
        "m365-sharepoint-ipv4.txt": M365_API_URL,
        "m365-teams-ipv4.txt": M365_API_URL,
        DEFENDER_FILE: DEFENDER_STANDARD_LEARN_URL,
        TEAMS_MEDIA_FILE: TEAMS_DIRECT_ROUTING_URL,
        INTUNE_WINDOWS_FILE: INTUNE_ENDPOINTS_LEARN_URL,
        APPLE_UPDATES_FILE: APPLE_ENTERPRISE_URL,
        APPLE_CONTENT_FILE: APPLE_ENTERPRISE_URL,
        APPLE_DEVICE_FILE: APPLE_ENTERPRISE_URL,
        APPLE_XCODE_FILE: APPLE_ENTERPRISE_URL,
        UBUNTU_MOTD_FILE: UBUNTU_PRO_DEFAULTS_DOCUMENTATION_URL,
        DELL_UPDATE_FILE: DELL_UPDATE_DOCUMENTATION_URL,
        MICROSOFT_EDGE_WINDOWS_FILE: MICROSOFT_WINDOWS_URL,
        GITHUB_FILE: GITHUB_META_DOCS_URL,
        GITHUB_ACTIONS_FILE: GITHUB_META_DOCS_URL,
        DROPBOX_FILE: DROPBOX_FIREWALL_URL,
    }
    preferred_order = (*NEW_SERVICE_FILES, *(name for _, name in PUBLICATIONS))
    ordered_files = list(dict.fromkeys(preferred_order))
    address_fqdns: dict[str, dict[str, list[str]]] = {}
    for filename, resolutions in resolutions_by_file.items():
        for hostname, addresses in resolutions.items():
            for address in addresses:
                address_fqdns.setdefault(filename, {}).setdefault(address, []).append(
                    hostname
                )

    entries: list[dict[str, Any]] = []
    for raw_address in RESIDUAL_IPS:
        address = ipaddress.IPv4Address(raw_address)
        audit = INTERNET_ONLY_AUDIT_CONTEXT.get(raw_address)
        matching_files = [
            filename
            for filename in ordered_files
            if filename in generated
            and any(address in network for network in generated[filename])
        ]
        if not matching_files:
            classification = residual_classification(
                address,
                covered=False,
                selected_file=None,
                fqdn=None,
            )
            reason = residual_noncoverage_reason(address)
            category = (
                audit["uncoveredCategory"]
                if audit is not None
                else (
                    "CDN_SHARED_UNATTRIBUTED"
                    if reason.startswith("Shared CDN address")
                    else (
                        "OWNER_ONLY_UNATTRIBUTED"
                        if classification["owner"] is not None
                        else "INTENTIONALLY_UNCOVERED"
                    )
                )
            )
            if category not in COVERAGE_CATEGORIES:
                raise GenerationError(
                    f"Invalid residual coverage category for {raw_address}: {category}"
                )
            entries.append(
                {
                    "ip": raw_address,
                    "sourcePalo": audit["paloSource"] if audit else None,
                    "paloSource": audit["paloSource"] if audit else None,
                    **classification,
                    "category": category,
                    "confidence": audit["confidence"] if audit else "low",
                    "covered": False,
                    "edl": None,
                    "targetEdl": None,
                    "source": None,
                    "fqdn": None,
                    "officialFqdn": audit["officialFqdn"] if audit else None,
                    "cname_chain": [],
                    "cnameChain": [],
                    "first_seen": None,
                    "firstSeen": None,
                    "last_seen": None,
                    "lastSeen": None,
                    "observation_sources": [],
                    "source_documentation": (
                        audit["officialSource"] if audit else None
                    ),
                    "officialSource": audit["officialSource"] if audit else None,
                    "reason": reason,
                }
            )
            continue

        if (
            raw_address in INTUNE_EVENT_RESIDUAL_IPS
            and INTUNE_WINDOWS_FILE in matching_files
        ):
            selected_file = INTUNE_WINDOWS_FILE
        elif (
            raw_address in M365_COMMON_DNS_RESIDUAL_IPS
            and M365_SERVICE_FILES["Common"] in matching_files
        ):
            selected_file = M365_SERVICE_FILES["Common"]
        else:
            selected_file = matching_files[0]
        fqdns = sorted(
            set(address_fqdns.get(selected_file, {}).get(raw_address, []))
        )
        source_documentation = documentation_by_file.get(selected_file)
        if fqdns and fqdns[0].endswith(".prod.do.dsp.mp.microsoft.com"):
            source_documentation = MICROSOFT_DELIVERY_OPTIMIZATION_URL
        elif fqdns and fqdns[0] == "config.edge.skype.com":
            source_documentation = MICROSOFT_EDGE_URL
        elif fqdns and fqdns[0] == "watson.events.data.microsoft.com":
            source_documentation = WINDOWS_DIAGNOSTIC_ENDPOINTS_URL
        elif fqdns and fqdns[0] == "umwatsonc.events.data.microsoft.com":
            source_documentation = CONFIGMGR_INTERNET_ENDPOINTS_URL
        history_record = (
            dns_history_by_file.get(selected_file, {})
            .get(fqdns[0], {})
            .get(raw_address)
            if fqdns
            else None
        )
        classification = residual_classification(
            address,
            covered=True,
            selected_file=selected_file,
            fqdn=fqdns[0] if fqdns else None,
        )
        entry: dict[str, Any] = {
            "ip": raw_address,
            "sourcePalo": audit["paloSource"] if audit else None,
            "paloSource": audit["paloSource"] if audit else None,
            **classification,
            "category": "COVERED_OFFICIAL",
            "confidence": "high",
            "covered": True,
            "edl": selected_file,
            "source": source_by_file[selected_file],
            "fqdn": fqdns[0] if fqdns else None,
            "cname_chain": (
                history_record["cnameChain"]
                if history_record is not None
                else (
                    cname_chains_by_file.get(selected_file, {}).get(fqdns[0], [])
                    if fqdns
                    else []
                )
            ),
            "first_seen": (
                history_record["firstSeen"] if history_record is not None else None
            ),
            "last_seen": (
                history_record["lastSeen"] if history_record is not None else None
            ),
            "observation_sources": (
                history_record["observationSources"]
                if history_record is not None
                else []
            ),
            "source_documentation": source_documentation,
            "officialSource": source_documentation,
        }
        if len(matching_files) > 1:
            entry["allEdls"] = matching_files
        if len(fqdns) > 1:
            entry["allFqdns"] = fqdns
        entry.update(
            {
                "targetEdl": entry["edl"],
                "officialFqdn": entry["fqdn"],
                "cnameChain": entry["cname_chain"],
                "firstSeen": entry["first_seen"],
                "lastSeen": entry["last_seen"],
                "reason": (
                    "Covered by a DNS-observed official FQDN"
                    if fqdns
                    else "Covered by an explicit official source CIDR"
                ),
            }
        )
        entries.append(entry)

    audit_entries = [
        entry for entry in entries if entry["ip"] in CURRENT_INTERNET_ONLY_AUDIT
    ]
    if len(audit_entries) != len(CURRENT_INTERNET_ONLY_AUDIT):
        raise GenerationError(
            "The current INTERNET-ONLY residual audit is incomplete: "
            f"expected {len(CURRENT_INTERNET_ONLY_AUDIT)} IPs, "
            f"found {len(audit_entries)}"
        )
    audit_category_counts = {
        category: sum(entry["category"] == category for entry in audit_entries)
        for category in sorted(COVERAGE_CATEGORIES)
    }
    document = {
        "generatedAt": generated_at,
        "policy": (
            "Coverage is reported only from generated EDL content; unmatched IPs "
            "are never added to force coverage"
        ),
        "currentInternetOnlyAudit": {
            "ipCount": len(audit_entries),
            "ips": [entry["ip"] for entry in audit_entries],
            "categoryCounts": audit_category_counts,
        },
        "entries": entries,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


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
    additional_sources: dict[str, dict[str, Any]],
    additional_files: dict[str, dict[str, Any]],
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
    files.update(additional_files)

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
                "fields": ["ips", "urls"],
                "note": (
                    "All service-area EDLs use explicit ips; Microsoft 365 "
                    "Common additionally validates *.office.com in urls and "
                    "resolves only the audited word.office.com target"
                ),
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
    document["sources"].update(additional_sources)
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def build_index(
    generated_at: str,
    generated: dict[str, list[ipaddress.IPv4Network]],
    *,
    output_dir: Path | None = None,
    supplemental_counts: dict[str, int] | None = None,
) -> str:
    supplemental_counts = supplemental_counts or {}
    rows = []
    for label, filename in PUBLICATIONS:
        if filename in generated:
            count = len(generated[filename])
        elif filename in supplemental_counts:
            count = supplemental_counts[filename]
        elif output_dir is not None and (output_dir / filename).is_file():
            count = sum(
                1
                for line in (output_dir / filename).read_text(
                    encoding="ascii"
                ).splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        else:
            continue
        rows.append(
            "<tr>"
            f"<td>{html.escape(label)}</td>"
            f'<td><a href="{html.escape(filename)}">{html.escape(filename)}</a></td>'
            f"<td>{count}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Public service EDLs</title>
    <style>
      :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
      body {{ max-width: 68rem; margin: 4rem auto; padding: 0 1.25rem; line-height: 1.55; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border-bottom: 1px solid #8888; padding: .65rem; text-align: left; }}
      code {{ overflow-wrap: anywhere; }}
      .notice {{ border-left: .3rem solid #1683ff; padding: .2rem 1rem; background: #1683ff12; }}
    </style>
  </head>
  <body>
    <h1>Public service EDLs</h1>
    <p>Listes publiques générées et validées automatiquement depuis des sources officielles.</p>
    <div class="notice">
      <p><strong>Microsoft 365 Common :</strong> les CIDR explicites du web service
      sont complétés uniquement par les A publics observés pour
      <code>word.office.com</code>, cible auditée du wildcard officiel
      <code>*.office.com</code>. La provenance DNS est conservée 24 heures ; aucun
      préfixe Azure ni <code>/32</code> manuel n'est ajouté.</p>
    </div>
    <div class="notice">
      <p><strong>Teams Media / Direct Routing :</strong> seules les plages commerciales
      <code>52.112.0.0/14</code> et <code>52.120.0.0/14</code> sont acceptées.
      Les plages GCC High, DoD ou toute plage inattendue font échouer la publication.</p>
    </div>
    <div class="notice">
      <p><strong>Windows Update, Delivery Optimization et Intune :</strong> les
      familles FQDN officielles sont validées dans les sources Microsoft puis des
      cibles DNS auditées sont résolues à chaque exécution. L'EDL Intune conserve
      pendant 24 heures uniquement les IPv4 publiques réellement observées sous
      <code>*.events.data.microsoft.com</code>, y compris les diagnostics Windows
      et Configuration Manager explicitement documentés. Les cibles dynamiques
      prioritaires Intune, Windows Settings et Edge sont aussi observées depuis
      deux vues DNS françaises contrôlées, avec chaîne CNAME et grâce de 24 heures.
      Aucune IP de logs ni plage Azure globale n'est injectée manuellement.</p>
    </div>
    <div class="notice">
      <p><strong>Apple :</strong> les listes utilisent uniquement les A publics
      courants des FQDN présents dans la source Apple. Les services Device setup
      et Device management sont regroupés avec les trois relais Private Cloud
      Compute exacts documentés par Apple, tandis que les téléchargements Xcode
      sont isolés. Chaque EDL Apple conserve pendant 24 heures uniquement les IPv4
      réellement observées via ses FQDN officiels, avec leur chaîne CNAME. Les
      relais PCC sont interrogés huit fois depuis deux vues DNS françaises.
      Aucun <code>17.0.0.0/8</code> ni range CDN global n'est ajouté.
      Apple recommande d'exempter ces FQDN de l'inspection HTTPS.</p>
    </div>
    <div class="notice">
      <p><strong>Ubuntu Pro APT News :</strong> la liste dédiée valide
      <code>motd.ubuntu.com</code> dans la configuration officielle Canonical,
      puis conserve pendant 24 heures uniquement ses A publics observés depuis
      le résolveur système et deux vues DNS françaises. Aucun range AWS ou EC2
      global n'est ajouté.</p>
    </div>
    <div class="notice">
      <p><strong>GitHub Actions :</strong> la liste dédiée est alimentée uniquement
      par les FQDN <code>*.actions.githubusercontent.com</code> concrets publiés
      dans l'API Meta GitHub. Leurs A publics sont conservés 24 heures avec leur
      chaîne CNAME ; les CIDR Actions et Azure globaux ne sont jamais importés.</p>
    </div>
    <div class="notice">
      <p><strong>Log4Shell / Log4j :</strong> ces IOC historiques et fortement
      qualifiés proviennent d'incidents CISA confirmés et de sections payload/C2
      Unit 42 ciblées. Ils ne constituent ni une réputation temps réel ni une
      protection autonome : corrigez Log4j, activez l'IPS, segmentez les systèmes
      et contrôlez les sorties LDAP/RMI. Les scanners de masse et les listes
      communautaires non qualifiées sont exclus. La
      <a href="metadata/log4j.json">provenance par indicateur</a> est publique.</p>
    </div>
    <table>
      <thead><tr><th>Périmètre</th><th>Fichier</th><th>Entrées</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    <p>Dernière modification des listes : {html.escape(generated_at)}</p>
    <p><a href="sources.json">Provenance et métadonnées</a></p>
    <p><a href="residual-ip-coverage.json">Couverture des IP résiduelles et matrice INTERNET-ONLY</a></p>
    <p><a href="https://github.com/hove-io/m365-edl">Code source, méthode et garde-fous</a></p>
  </body>
</html>
"""


def publish(
    *,
    output_dir: Path,
    generated_at: str,
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
    additional_sources: dict[str, dict[str, Any]],
    additional_files: dict[str, dict[str, Any]],
    resolutions_by_file: dict[str, dict[str, list[str]]],
    cname_chains_by_file: dict[str, dict[str, list[str]]],
    dns_history_by_file: dict[
        str, dict[str, dict[str, dict[str, Any]]]
    ],
) -> bool:
    check_drop_guard(output_dir, generated)
    rendered = {filename: render_edl(items) for filename, items in generated.items()}

    edl_changed = any(
        not (output_dir / filename).exists()
        or (output_dir / filename).read_text(encoding="ascii") != content
        for filename, content in rendered.items()
    )
    for filename, networks in generated.items():
        print(f"{filename}: {len(networks)} IPv4 CIDRs")
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
        additional_sources=additional_sources,
        additional_files=additional_files,
    )
    residual_coverage = build_residual_coverage(
        generated_at=generated_at,
        generated=generated,
        resolutions_by_file=resolutions_by_file,
        cname_chains_by_file=cname_chains_by_file,
        dns_history_by_file=dns_history_by_file,
    )
    index = build_index(generated_at, generated, output_dir=output_dir)
    support_rendered = {
        "sources.json": sources,
        RESIDUAL_COVERAGE_FILE: residual_coverage,
        "index.html": index,
        ".nojekyll": "",
    }
    support_changed = any(
        not (output_dir / filename).exists()
        or (output_dir / filename).read_text(encoding="utf-8") != content
        for filename, content in support_rendered.items()
    )
    if not edl_changed and not support_changed:
        print("No publication content change detected; keeping the previous files")
        return False

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="m365-edl-", dir=output_dir.parent
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        for filename, content in rendered.items():
            (temporary / filename).write_text(content, encoding="ascii")
        for filename, content in support_rendered.items():
            (temporary / filename).write_text(content, encoding="utf-8")

        output_dir.mkdir(parents=True, exist_ok=True)
        for filename in (
            *rendered,
            "sources.json",
            RESIDUAL_COVERAGE_FILE,
            "index.html",
            ".nojekyll",
        ):
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
        apple_enterprise = load_text_source(
            args.apple_enterprise_file,
            label="Apple enterprise network endpoints source",
        )
        apple_apns = load_text_source(
            args.apple_apns_file,
            label="Apple APNs endpoint source",
        )
        apple_xcode_dns_observations = load_text_source(
            args.apple_xcode_dns_observations_file,
            label="Apple Xcode DNS-over-HTTPS observations",
        )
        apple_pcc_dns_observations = load_text_source(
            args.apple_pcc_dns_observations_file,
            label="Apple Private Cloud Compute DNS-over-HTTPS observations",
        )
        ubuntu_pro_defaults = load_text_source(
            args.ubuntu_pro_defaults_file,
            label="Canonical Ubuntu Pro defaults source",
        )
        ubuntu_dns_observations = load_text_source(
            args.ubuntu_dns_observations_file,
            label="Ubuntu MOTD DNS-over-HTTPS observations",
        )
        microsoft_dns_observations = load_text_source(
            args.microsoft_dns_observations_file,
            label="Microsoft DNS-over-HTTPS observations",
        )
        github_meta = load_json_source(
            args.github_meta_file,
            label="GitHub Meta API response",
        )
        dropbox_firewall = load_text_source(
            args.dropbox_firewall_file,
            label="Dropbox firewall guidance source",
        )
        dropbox_arin = load_json_source(
            args.dropbox_arin_file,
            label="Dropbox ARIN allocation response",
        )
        dell_update = load_bytes(
            args.dell_update_file,
            label="Dell Command Update catalog source",
        )
        microsoft_edge = load_text_source(
            args.microsoft_edge_file,
            label="Microsoft Edge endpoints source",
        )
        microsoft_windows = load_text_source(
            args.microsoft_windows_file,
            label="Microsoft Windows endpoints source",
        )
        microsoft_delivery_optimization = load_text_source(
            args.microsoft_delivery_optimization_file,
            label="Microsoft Delivery Optimization workflow source",
        )
        windows_diagnostic_endpoints = load_text_source(
            args.windows_diagnostic_endpoints_file,
            label="Microsoft Windows diagnostic endpoints source",
        )
        configmgr_internet_endpoints = load_text_source(
            args.configmgr_internet_endpoints_file,
            label="Microsoft Configuration Manager internet endpoints source",
        )
        previous_sources_path = args.output_dir / "sources.json"
        previous_sources = (
            load_json_source(previous_sources_path, label="previous sources.json")
            if previous_sources_path.exists()
            else None
        )
        observed_at = dt.datetime.now(dt.timezone.utc)
        (
            microsoft_doh_resolutions,
            microsoft_doh_details,
            microsoft_doh_attempt_counts,
        ) = extract_doh_observations(
            microsoft_dns_observations,
            authorized_hostnames=MICROSOFT_DOH_HOSTS,
            ecs_subnets=MICROSOFT_DOH_ECS_SUBNETS,
            resolver_url=MICROSOFT_DOH_RESOLVER,
            required_attempts=MICROSOFT_DOH_ATTEMPTS,
            label="Microsoft",
        )
        (
            apple_pcc_doh_resolutions,
            apple_pcc_doh_details,
            apple_pcc_doh_attempt_counts,
        ) = extract_doh_observations(
            apple_pcc_dns_observations,
            authorized_hostnames=APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS,
            ecs_subnets=APPLE_PCC_DOH_ECS_SUBNETS,
            resolver_url=APPLE_PCC_DOH_RESOLVER,
            required_attempts=APPLE_PCC_DNS_ATTEMPTS,
            label="Apple Private Cloud Compute",
        )
        (
            ubuntu_doh_resolutions,
            ubuntu_doh_details,
            ubuntu_doh_attempt_counts,
        ) = extract_doh_observations(
            ubuntu_dns_observations,
            authorized_hostnames=UBUNTU_MOTD_HOSTS,
            ecs_subnets=UBUNTU_DOH_ECS_SUBNETS,
            resolver_url=UBUNTU_DOH_RESOLVER,
            required_attempts=UBUNTU_DNS_ATTEMPTS,
            label="Ubuntu MOTD",
        )

        generated = extract_m365_networks(payload)
        m365_common_file = M365_SERVICE_FILES["Common"]
        m365_common_explicit_networks = list(generated[m365_common_file])
        m365_common_documented_patterns = validate_m365_documented_urls(
            payload,
            service_area="Common",
            required_patterns=set(M365_COMMON_WILDCARD_TARGETS),
        )
        (
            m365_common_dns_hosts,
            m365_common_dns_wildcards,
            m365_common_dns_targets,
        ) = expand_documented_hostnames(
            m365_common_documented_patterns,
            wildcard_targets=M365_COMMON_WILDCARD_TARGETS,
            label="Microsoft 365 Common web endpoints",
        )
        (
            _m365_common_current_networks,
            m365_common_current_resolutions,
            m365_common_cname_chains,
            m365_common_unresolved,
        ) = resolve_service_hostnames(
            m365_common_dns_hosts,
            label="Microsoft 365 Common web endpoints",
            attempts=8,
        )
        m365_common_current_details = build_dns_observation_details(
            authorized_hostnames=set(m365_common_dns_hosts),
            resolutions=m365_common_current_resolutions,
            cname_chains=m365_common_cname_chains,
            observation_source="system-resolver",
        )
        (
            m365_common_dns_networks,
            m365_common_resolutions,
            m365_common_dns_history,
            m365_common_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=m365_common_file,
            authorized_hostnames=set(m365_common_dns_hosts),
            current_details=m365_common_current_details,
            observed_at=observed_at,
            label="Microsoft 365 Common web endpoints",
        )
        generated[m365_common_file] = sort_networks(
            [*m365_common_explicit_networks, *m365_common_dns_networks]
        )
        defender_hostnames, defender_wildcards, wildcard_targets = (
            extract_defender_hostnames(defender_standard, defender_antivirus)
        )
        defender_networks, defender_resolutions = resolve_defender_hostnames(
            defender_hostnames
        )
        teams_media_networks = extract_teams_media_networks(teams_direct_routing)
        intune_explicit_networks = extract_intune_windows_networks(intune_endpoints)
        intune_documented_hostnames = extract_intune_consolidated_hostnames(
            intune_endpoints
        )
        missing_intune_wildcards = set(INTUNE_EVENT_WILDCARD_TARGETS) - set(
            intune_documented_hostnames
        )
        if missing_intune_wildcards:
            raise GenerationError(
                "Intune consolidated FQDN block no longer contains required "
                "wildcards: " + ", ".join(sorted(missing_intune_wildcards))
            )
        validate_documented_hostnames(
            windows_diagnostic_endpoints,
            INTUNE_EVENT_EXACT_SOURCE_REQUIREMENTS[
                WINDOWS_DIAGNOSTIC_ENDPOINTS_URL
            ],
            label="Microsoft Windows diagnostic endpoints",
        )
        validate_documented_hostnames(
            configmgr_internet_endpoints,
            INTUNE_EVENT_EXACT_SOURCE_REQUIREMENTS[
                CONFIGMGR_INTERNET_ENDPOINTS_URL
            ],
            label="Microsoft Configuration Manager internet endpoints",
        )
        (
            intune_event_hosts,
            intune_event_wildcards,
            intune_event_targets,
        ) = expand_documented_hostnames(
            sorted(INTUNE_EVENT_WILDCARD_TARGETS),
            wildcard_targets=INTUNE_EVENT_WILDCARD_TARGETS,
            label="Microsoft Intune events",
        )
        (
            _intune_event_current_networks,
            intune_event_current_resolutions,
            intune_event_cname_chains,
            intune_event_unresolved,
        ) = resolve_service_hostnames(
            intune_event_hosts,
            label="Microsoft Intune events",
            attempts=8,
        )
        intune_event_current_details = build_dns_observation_details(
            authorized_hostnames=set(intune_event_hosts),
            resolutions=intune_event_current_resolutions,
            cname_chains=intune_event_cname_chains,
            observation_source="system-resolver",
        )
        missing_intune_doh_hosts = MICROSOFT_INTUNE_DOH_HOSTS - set(
            intune_event_hosts
        )
        if missing_intune_doh_hosts:
            raise GenerationError(
                "Controlled Microsoft Intune DNS hosts are not authorized by "
                "the official source: " + ", ".join(sorted(missing_intune_doh_hosts))
            )
        intune_doh_details = {
            hostname: microsoft_doh_details[hostname]
            for hostname in MICROSOFT_INTUNE_DOH_HOSTS
        }
        (
            intune_event_current_resolutions,
            intune_event_current_details,
        ) = combine_dns_observation_details(
            authorized_hostnames=set(intune_event_hosts),
            observation_sets=[intune_event_current_details, intune_doh_details],
        )
        (
            intune_event_networks,
            intune_event_resolutions,
            intune_event_dns_history,
            intune_event_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=INTUNE_WINDOWS_FILE,
            authorized_hostnames=set(intune_event_hosts),
            current_details=intune_event_current_details,
            observed_at=observed_at,
            label="Microsoft Intune events",
        )
        intune_windows_networks = sort_networks(
            [*intune_explicit_networks, *intune_event_networks]
        )
        generated[DEFENDER_FILE] = defender_networks
        generated[TEAMS_MEDIA_FILE] = teams_media_networks
        generated[INTUNE_WINDOWS_FILE] = intune_windows_networks

        existing_generated = {
            filename: list(networks) for filename, networks in generated.items()
        }

        apple_updates_documented = extract_apple_section_hostnames(
            apple_enterprise, section_id="software"
        )
        apple_updates_hosts, apple_updates_wildcards, apple_updates_targets = (
            expand_documented_hostnames(
                apple_updates_documented,
                wildcard_targets={},
                label="Apple Software updates",
            )
        )
        (
            apple_updates_networks,
            apple_updates_resolutions,
            apple_updates_cname_chains,
            apple_updates_unresolved,
        ) = resolve_service_hostnames(
            apple_updates_hosts, label="Apple Software updates"
        )
        apple_updates_current_resolutions = apple_updates_resolutions
        apple_updates_current_details = build_dns_observation_details(
            authorized_hostnames=set(apple_updates_hosts),
            resolutions=apple_updates_current_resolutions,
            cname_chains=apple_updates_cname_chains,
            observation_source="system-resolver",
        )
        (
            apple_updates_networks,
            apple_updates_resolutions,
            apple_updates_dns_history,
            apple_updates_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=APPLE_UPDATES_FILE,
            authorized_hostnames=set(apple_updates_hosts),
            current_details=apple_updates_current_details,
            observed_at=observed_at,
            label="Apple Software updates",
        )

        apple_content_documented = extract_apple_section_hostnames(
            apple_enterprise, section_id="appscontent"
        )
        if not APPLE_XCODE_HOSTS.issubset(apple_content_documented):
            raise GenerationError(
                "Apple Apps and additional content no longer documents all "
                "required Xcode download hosts"
            )
        apple_xcode_documented = sorted(APPLE_XCODE_HOSTS)
        apple_content_documented = sorted(
            set(apple_content_documented) - APPLE_XCODE_HOSTS
        )
        apple_content_hosts, apple_content_wildcards, apple_content_targets = (
            expand_documented_hostnames(
                apple_content_documented,
                wildcard_targets=APPLE_APP_WILDCARD_TARGETS,
                label="Apple Apps and content",
            )
        )
        (
            apple_content_networks,
            apple_content_resolutions,
            apple_content_cname_chains,
            apple_content_unresolved,
        ) = resolve_service_hostnames(
            apple_content_hosts, label="Apple Apps and content"
        )
        apple_content_current_resolutions = apple_content_resolutions
        apple_content_current_details = build_dns_observation_details(
            authorized_hostnames=set(apple_content_hosts),
            resolutions=apple_content_current_resolutions,
            cname_chains=apple_content_cname_chains,
            observation_source="system-resolver",
        )
        (
            apple_content_networks,
            apple_content_resolutions,
            apple_content_dns_history,
            apple_content_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=APPLE_CONTENT_FILE,
            authorized_hostnames=set(apple_content_hosts),
            current_details=apple_content_current_details,
            observed_at=observed_at,
            label="Apple Apps and content",
        )

        apple_xcode_hosts, apple_xcode_wildcards, apple_xcode_targets = (
            expand_documented_hostnames(
                apple_xcode_documented,
                wildcard_targets={},
                label="Apple Xcode developer downloads",
            )
        )
        (
            _apple_xcode_native_networks,
            apple_xcode_native_resolutions,
            apple_xcode_native_cname_chains,
            apple_xcode_unresolved,
        ) = resolve_service_hostnames(
            apple_xcode_hosts,
            label="Apple Xcode developer downloads",
            attempts=XCODE_DNS_ATTEMPTS,
        )
        (
            apple_xcode_doh_resolutions,
            apple_xcode_doh_details,
            apple_xcode_doh_attempt_counts,
        ) = extract_xcode_doh_observations(apple_xcode_dns_observations)
        (
            apple_xcode_current_resolutions,
            apple_xcode_current_details,
        ) = combine_xcode_observations(
            native_resolutions=apple_xcode_native_resolutions,
            native_cname_chains=apple_xcode_native_cname_chains,
            doh_resolutions=apple_xcode_doh_resolutions,
            doh_details=apple_xcode_doh_details,
        )
        (
            apple_xcode_networks,
            apple_xcode_resolutions,
            apple_xcode_dns_history,
            apple_xcode_expired_records,
        ) = build_xcode_dns_history(
            previous_sources=previous_sources,
            current_details=apple_xcode_current_details,
            observed_at=observed_at,
        )
        apple_xcode_cname_chains = {
            hostname: list(apple_xcode_native_cname_chains.get(hostname, []))
            for hostname in apple_xcode_hosts
        }

        apple_device_setup_documented = extract_apple_section_hostnames(
            apple_enterprise, section_id="devicesetup"
        )
        apple_device_management_documented = extract_apple_section_hostnames(
            apple_enterprise, section_id="devicemanagement"
        )
        apple_intelligence_documented = extract_apple_section_hostnames(
            apple_enterprise, section_id="aisirisearch"
        )
        if not APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS.issubset(
            apple_intelligence_documented
        ):
            raise GenerationError(
                "Apple Intelligence no longer documents all required Private "
                "Cloud Compute relay hosts"
            )
        apple_pcc_documented = sorted(APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS)
        apple_device_documented = sorted(
            set(apple_device_setup_documented)
            | set(apple_device_management_documented)
            | APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS
        )
        validate_documented_hostnames(
            apple_apns,
            {"api.push.apple.com", "api.development.push.apple.com"},
            label="Apple APNs",
        )
        apple_device_hosts, apple_device_wildcards, apple_device_targets = (
            expand_documented_hostnames(
                apple_device_documented,
                wildcard_targets=APPLE_DEVICE_WILDCARD_TARGETS,
                label="Apple Device management",
            )
        )
        (
            apple_device_networks,
            apple_device_resolutions,
            apple_device_cname_chains,
            apple_device_unresolved,
        ) = resolve_service_hostnames(
            apple_device_hosts,
            label="Apple Device management/APNs/Private Cloud Compute",
            attempts=8,
        )
        apple_device_current_resolutions = apple_device_resolutions
        apple_device_current_details = build_dns_observation_details(
            authorized_hostnames=set(apple_device_hosts),
            resolutions=apple_device_current_resolutions,
            cname_chains=apple_device_cname_chains,
            observation_source="system-resolver",
        )
        (
            apple_device_current_resolutions,
            apple_device_current_details,
        ) = combine_dns_observation_details(
            authorized_hostnames=set(apple_device_hosts),
            observation_sets=[
                apple_device_current_details,
                apple_pcc_doh_details,
            ],
        )
        (
            apple_device_networks,
            apple_device_resolutions,
            apple_device_dns_history,
            apple_device_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=APPLE_DEVICE_FILE,
            authorized_hostnames=set(apple_device_hosts),
            current_details=apple_device_current_details,
            observed_at=observed_at,
            label="Apple Device management/APNs/Private Cloud Compute",
        )

        ubuntu_hosts = validate_ubuntu_motd_source(ubuntu_pro_defaults)
        (
            _ubuntu_current_networks,
            ubuntu_current_resolutions,
            ubuntu_cname_chains,
            ubuntu_unresolved,
        ) = resolve_service_hostnames(
            ubuntu_hosts,
            label="Ubuntu Pro APT News / MOTD",
            attempts=UBUNTU_DNS_ATTEMPTS,
        )
        ubuntu_current_details = build_dns_observation_details(
            authorized_hostnames=set(ubuntu_hosts),
            resolutions=ubuntu_current_resolutions,
            cname_chains=ubuntu_cname_chains,
            observation_source="system-resolver",
        )
        (
            ubuntu_current_resolutions,
            ubuntu_current_details,
        ) = combine_dns_observation_details(
            authorized_hostnames=set(ubuntu_hosts),
            observation_sets=[ubuntu_current_details, ubuntu_doh_details],
        )
        (
            ubuntu_networks,
            ubuntu_resolutions,
            ubuntu_dns_history,
            ubuntu_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=UBUNTU_MOTD_FILE,
            authorized_hostnames=set(ubuntu_hosts),
            current_details=ubuntu_current_details,
            observed_at=observed_at,
            label="Ubuntu Pro APT News / MOTD",
        )

        github_networks, github_field_counts = extract_github_networks(github_meta)
        github_actions_hosts = extract_github_actions_hostnames(github_meta)
        (
            _github_actions_current_networks,
            github_actions_current_resolutions,
            github_actions_cname_chains,
            github_actions_unresolved,
        ) = resolve_service_hostnames(
            github_actions_hosts,
            label="GitHub Actions hosted runners",
            attempts=GITHUB_ACTIONS_DNS_ATTEMPTS,
        )
        github_actions_current_details = build_dns_observation_details(
            authorized_hostnames=set(github_actions_hosts),
            resolutions=github_actions_current_resolutions,
            cname_chains=github_actions_cname_chains,
            observation_source="system-resolver",
        )
        (
            github_actions_networks,
            github_actions_resolutions,
            github_actions_dns_history,
            github_actions_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=GITHUB_ACTIONS_FILE,
            authorized_hostnames=set(github_actions_hosts),
            current_details=github_actions_current_details,
            observed_at=observed_at,
            label="GitHub Actions hosted runners",
        )
        (
            dropbox_networks,
            dropbox_allocations,
            dropbox_excluded_names,
        ) = extract_dropbox_networks(
            dropbox_arin,
            firewall_html=dropbox_firewall,
        )

        dell_hosts = validate_dell_catalog_source(dell_update)
        (
            dell_networks,
            dell_resolutions,
            dell_cname_chains,
            dell_unresolved,
        ) = resolve_service_hostnames(dell_hosts, label="Dell Command Update")

        edge_hosts = validate_documented_hostnames(
            microsoft_edge,
            MICROSOFT_EDGE_HOSTS,
            label="Microsoft Edge endpoints",
        )
        windows_documented_hostnames = validate_documented_hostnames(
            microsoft_windows,
            MICROSOFT_WINDOWS_HOSTS | set(WINDOWS_UPDATE_WILDCARD_TARGETS),
            label="Microsoft Windows endpoints",
        )
        validate_documented_hostnames(
            microsoft_delivery_optimization,
            DELIVERY_OPTIMIZATION_REQUIRED_PATTERNS,
            label="Delivery Optimization workflow",
        )
        windows_hosts, windows_wildcards, windows_targets = (
            expand_documented_hostnames(
                windows_documented_hostnames,
                wildcard_targets=WINDOWS_UPDATE_WILDCARD_TARGETS,
                label="Microsoft Windows endpoints",
            )
        )
        microsoft_service_hosts = sorted(set(edge_hosts) | set(windows_hosts))
        (
            _microsoft_service_current_networks,
            microsoft_service_current_resolutions,
            microsoft_service_cname_chains,
            microsoft_service_unresolved,
        ) = resolve_service_hostnames(
            microsoft_service_hosts,
            label="Microsoft Edge/Windows services",
            attempts=8,
        )
        microsoft_service_current_details = build_dns_observation_details(
            authorized_hostnames=set(microsoft_service_hosts),
            resolutions=microsoft_service_current_resolutions,
            cname_chains=microsoft_service_cname_chains,
            observation_source="system-resolver",
        )
        missing_edge_doh_hosts = MICROSOFT_EDGE_DOH_HOSTS - set(
            microsoft_service_hosts
        )
        if missing_edge_doh_hosts:
            raise GenerationError(
                "Controlled Microsoft Edge/Windows DNS hosts are not authorized "
                "by the official sources: "
                + ", ".join(sorted(missing_edge_doh_hosts))
            )
        edge_doh_details = {
            hostname: microsoft_doh_details[hostname]
            for hostname in MICROSOFT_EDGE_DOH_HOSTS
        }
        (
            microsoft_service_current_resolutions,
            microsoft_service_current_details,
        ) = combine_dns_observation_details(
            authorized_hostnames=set(microsoft_service_hosts),
            observation_sets=[
                microsoft_service_current_details,
                edge_doh_details,
            ],
        )
        (
            microsoft_service_networks,
            microsoft_service_resolutions,
            microsoft_service_dns_history,
            microsoft_service_expired_records,
        ) = build_dns_history(
            previous_sources=previous_sources,
            filename=MICROSOFT_EDGE_WINDOWS_FILE,
            authorized_hostnames=set(microsoft_service_hosts),
            current_details=microsoft_service_current_details,
            observed_at=observed_at,
            label="Microsoft Edge/Windows services",
        )
        (
            microsoft_service_networks,
            microsoft_existing_exclusions,
        ) = exclude_existing_networks(
            microsoft_service_networks,
            existing_generated,
        )

        generated[APPLE_UPDATES_FILE] = apple_updates_networks
        generated[APPLE_CONTENT_FILE] = apple_content_networks
        generated[APPLE_DEVICE_FILE] = apple_device_networks
        generated[APPLE_XCODE_FILE] = apple_xcode_networks
        generated[UBUNTU_MOTD_FILE] = ubuntu_networks
        generated[GITHUB_FILE] = github_networks
        generated[GITHUB_ACTIONS_FILE] = github_actions_networks
        generated[DROPBOX_FILE] = dropbox_networks
        generated[DELL_UPDATE_FILE] = dell_networks
        generated[MICROSOFT_EDGE_WINDOWS_FILE] = microsoft_service_networks

        resolutions_by_file = {
            m365_common_file: m365_common_resolutions,
            DEFENDER_FILE: defender_resolutions,
            INTUNE_WINDOWS_FILE: intune_event_resolutions,
            APPLE_UPDATES_FILE: apple_updates_resolutions,
            APPLE_CONTENT_FILE: apple_content_resolutions,
            APPLE_DEVICE_FILE: apple_device_resolutions,
            APPLE_XCODE_FILE: apple_xcode_resolutions,
            UBUNTU_MOTD_FILE: ubuntu_resolutions,
            GITHUB_ACTIONS_FILE: github_actions_resolutions,
            DELL_UPDATE_FILE: dell_resolutions,
            MICROSOFT_EDGE_WINDOWS_FILE: microsoft_service_resolutions,
        }
        cname_chains_by_file = {
            m365_common_file: m365_common_cname_chains,
            INTUNE_WINDOWS_FILE: intune_event_cname_chains,
            APPLE_UPDATES_FILE: apple_updates_cname_chains,
            APPLE_CONTENT_FILE: apple_content_cname_chains,
            APPLE_DEVICE_FILE: apple_device_cname_chains,
            APPLE_XCODE_FILE: apple_xcode_cname_chains,
            UBUNTU_MOTD_FILE: ubuntu_cname_chains,
            GITHUB_ACTIONS_FILE: github_actions_cname_chains,
            DELL_UPDATE_FILE: dell_cname_chains,
            MICROSOFT_EDGE_WINDOWS_FILE: microsoft_service_cname_chains,
        }
        dns_history_by_file = {
            m365_common_file: m365_common_dns_history,
            INTUNE_WINDOWS_FILE: intune_event_dns_history,
            APPLE_UPDATES_FILE: apple_updates_dns_history,
            APPLE_CONTENT_FILE: apple_content_dns_history,
            APPLE_DEVICE_FILE: apple_device_dns_history,
            APPLE_XCODE_FILE: apple_xcode_dns_history,
            UBUNTU_MOTD_FILE: ubuntu_dns_history,
            GITHUB_ACTIONS_FILE: github_actions_dns_history,
            MICROSOFT_EDGE_WINDOWS_FILE: microsoft_service_dns_history,
        }

        additional_sources: dict[str, dict[str, Any]] = {
            "appleEnterpriseNetworks": {
                "publisher": "Apple",
                "url": APPLE_ENTERPRISE_URL,
                "sha256": source_hash(apple_enterprise),
                "sections": [
                    "Software updates",
                    "Apps and additional content",
                    "Device setup",
                    "Device management",
                    "Apple Intelligence, Siri, and Search",
                ],
            },
            "appleApns": {
                "publisher": "Apple",
                "url": APPLE_APNS_URL,
                "sha256": source_hash(apple_apns),
                "purpose": "Audited concrete targets for *.push.apple.com",
            },
            "appleXcodeDnsObservations": {
                "resolver": XCODE_DOH_RESOLVER,
                "ecsSubnets": list(XCODE_DOH_ECS_SUBNETS),
                "attemptsPerHostnameAndSubnet": XCODE_DNS_ATTEMPTS,
                "sha256": source_hash(apple_xcode_dns_observations),
                "purpose": (
                    "Collect multiple current public A records for the two "
                    "official Apple Xcode FQDNs from controlled France DNS views"
                ),
            },
            "applePrivateCloudComputeDnsObservations": {
                "resolver": APPLE_PCC_DOH_RESOLVER,
                "ecsSubnets": list(APPLE_PCC_DOH_ECS_SUBNETS),
                "attemptsPerHostnameAndSubnet": APPLE_PCC_DNS_ATTEMPTS,
                "hostnames": sorted(APPLE_PRIVATE_CLOUD_COMPUTE_HOSTS),
                "resolvedHostnames": apple_pcc_doh_resolutions,
                "sha256": source_hash(apple_pcc_dns_observations),
                "purpose": (
                    "Test the exact Private Cloud Compute relay FQDNs from "
                    "Apple's official enterprise network documentation"
                ),
            },
            "ubuntuProDefaults": {
                "publisher": "Canonical",
                "url": UBUNTU_PRO_DEFAULTS_URL,
                "documentationUrl": UBUNTU_PRO_DEFAULTS_DOCUMENTATION_URL,
                "sha256": source_hash(ubuntu_pro_defaults),
                "validatedHostnames": ubuntu_hosts,
            },
            "ubuntuMotdDnsObservations": {
                "resolver": UBUNTU_DOH_RESOLVER,
                "ecsSubnets": list(UBUNTU_DOH_ECS_SUBNETS),
                "attemptsPerHostnameAndSubnet": UBUNTU_DNS_ATTEMPTS,
                "hostnames": ubuntu_hosts,
                "resolvedHostnames": ubuntu_doh_resolutions,
                "sha256": source_hash(ubuntu_dns_observations),
                "purpose": (
                    "Resolve only Canonical's documented Ubuntu Pro APT News "
                    "endpoint from controlled France DNS views"
                ),
            },
            "microsoftControlledDnsObservations": {
                "resolver": MICROSOFT_DOH_RESOLVER,
                "ecsSubnets": list(MICROSOFT_DOH_ECS_SUBNETS),
                "attemptsPerHostnameAndSubnet": MICROSOFT_DOH_ATTEMPTS,
                "hostnames": sorted(MICROSOFT_DOH_HOSTS),
                "resolvedHostnames": microsoft_doh_resolutions,
                "sha256": source_hash(microsoft_dns_observations),
                "purpose": (
                    "Collect current public A records and complete CNAME chains "
                    "for selected official Microsoft dynamic FQDNs from "
                    "controlled France DNS views"
                ),
            },
            "githubMeta": {
                "publisher": "GitHub",
                "url": GITHUB_META_URL,
                "documentationUrl": GITHUB_META_DOCS_URL,
                "sha256": source_hash(
                    json.dumps(github_meta, sort_keys=True, ensure_ascii=False)
                ),
            },
            "dropboxFirewallGuidance": {
                "publisher": "Dropbox",
                "url": DROPBOX_FIREWALL_URL,
                "sha256": source_hash(dropbox_firewall),
                "note": (
                    "Dropbox recommends domain allowlisting because third-party "
                    "infrastructure isn't covered by Dropbox-owned ranges"
                ),
            },
            "dropboxArinAllocations": {
                "publisher": "ARIN, linked by Dropbox",
                "url": DROPBOX_ARIN_URL,
                "sha256": source_hash(
                    json.dumps(dropbox_arin, sort_keys=True, ensure_ascii=False)
                ),
            },
            "dellCommandUpdate": {
                "publisher": "Dell",
                "url": DELL_UPDATE_URL,
                "documentationUrl": DELL_UPDATE_DOCUMENTATION_URL,
                "sha256": hashlib.sha256(dell_update).hexdigest(),
            },
            "windowsDiagnosticEndpoints": {
                "publisher": "Microsoft",
                "url": WINDOWS_DIAGNOSTIC_ENDPOINTS_URL,
                "sha256": source_hash(windows_diagnostic_endpoints),
                "validatedHostnames": sorted(
                    INTUNE_EVENT_EXACT_SOURCE_REQUIREMENTS[
                        WINDOWS_DIAGNOSTIC_ENDPOINTS_URL
                    ]
                ),
            },
            "configurationManagerInternetEndpoints": {
                "publisher": "Microsoft",
                "url": CONFIGMGR_INTERNET_ENDPOINTS_URL,
                "sha256": source_hash(configmgr_internet_endpoints),
                "validatedHostnames": sorted(
                    INTUNE_EVENT_EXACT_SOURCE_REQUIREMENTS[
                        CONFIGMGR_INTERNET_ENDPOINTS_URL
                    ]
                ),
            },
            "microsoftEdgeEndpoints": {
                "publisher": "Microsoft",
                "url": MICROSOFT_EDGE_URL,
                "sha256": source_hash(microsoft_edge),
            },
            "microsoftWindowsEndpoints": {
                "publisher": "Microsoft",
                "url": MICROSOFT_WINDOWS_URL,
                "sha256": source_hash(microsoft_windows),
            },
            "microsoftDeliveryOptimizationWorkflow": {
                "publisher": "Microsoft",
                "url": MICROSOFT_DELIVERY_OPTIMIZATION_URL,
                "sha256": source_hash(microsoft_delivery_optimization),
                "validatedPatterns": sorted(
                    DELIVERY_OPTIMIZATION_REQUIRED_PATTERNS
                ),
            },
        }
        additional_files: dict[str, dict[str, Any]] = {
            m365_common_file: {
                "serviceArea": "Common",
                "cidrCount": len(generated[m365_common_file]),
                "explicitCidrCount": len(m365_common_explicit_networks),
                "method": (
                    "Combine Microsoft 365 Common ips CIDRs with public A records "
                    "from an audited concrete target under the official "
                    "*.office.com URL pattern, retained for 24 hours"
                ),
                "officialUrlPatterns": m365_common_dns_wildcards,
                "wildcardResolutionTargets": {
                    pattern: list(targets)
                    for pattern, targets in m365_common_dns_targets.items()
                },
                "resolvedHostnames": m365_common_resolutions,
                "currentResolvedHostnames": m365_common_current_resolutions,
                "cnameChains": m365_common_cname_chains,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": m365_common_dns_history,
                    "expiredThisRun": m365_common_expired_records,
                },
                "unresolvedHostnames": m365_common_unresolved,
                "dnsAttemptsPerHostname": 8,
                "manualIpOverrides": False,
                "globalAzureOrAs8075RangesIncluded": False,
            },
            INTUNE_WINDOWS_FILE: {
                "cidrCount": len(intune_windows_networks),
                "explicitCidrCount": len(intune_explicit_networks),
                "method": (
                    "Combine explicit consolidated Intune IP Subnets with IPv4 "
                    "A records from audited *.events.data.microsoft.com targets "
                    "retained for a rolling 24-hour window"
                ),
                "scope": (
                    "Intune-managed devices, including consolidated IP subnets "
                    "and optional reporting/Endpoint Analytics endpoints"
                ),
                "wildcardPatterns": intune_event_wildcards,
                "wildcardResolutionTargets": {
                    pattern: list(targets)
                    for pattern, targets in intune_event_targets.items()
                },
                "resolvedHostnames": intune_event_resolutions,
                "currentResolvedHostnames": intune_event_current_resolutions,
                "cnameChains": intune_event_cname_chains,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": intune_event_dns_history,
                    "expiredThisRun": intune_event_expired_records,
                },
                "unresolvedHostnames": intune_event_unresolved,
                "dnsAttemptsPerHostname": 8,
                "controlledDohHostnames": sorted(MICROSOFT_INTUNE_DOH_HOSTS),
                "dnsObservationAttempts": {
                    key: count
                    for key, count in microsoft_doh_attempt_counts.items()
                    if key.split("@", 1)[0] in MICROSOFT_INTUNE_DOH_HOSTS
                },
                "manualIpOverrides": False,
                "globalAzureOrAs8075RangesIncluded": False,
            },
            APPLE_UPDATES_FILE: {
                "cidrCount": len(apple_updates_networks),
                "method": (
                    "Resolve official Apple Software updates FQDNs and retain "
                    "DNS-proven IPv4 /32 records for a rolling 24-hour window"
                ),
                "documentedHostnames": apple_updates_documented,
                "wildcardPatterns": apple_updates_wildcards,
                "wildcardResolutionTargets": apple_updates_targets,
                "resolvedHostnames": apple_updates_resolutions,
                "currentResolvedHostnames": apple_updates_current_resolutions,
                "cnameChains": apple_updates_cname_chains,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": apple_updates_dns_history,
                    "expiredThisRun": apple_updates_expired_records,
                },
                "unresolvedHostnames": apple_updates_unresolved,
                "manualIpOverrides": False,
            },
            APPLE_CONTENT_FILE: {
                "cidrCount": len(apple_content_networks),
                "method": (
                    "Resolve official Apple Apps and additional content FQDNs "
                    "to IPv4 /32"
                ),
                "documentedHostnames": apple_content_documented,
                "excludedXcodeHostnames": apple_xcode_documented,
                "wildcardPatterns": apple_content_wildcards,
                "wildcardResolutionTargets": {
                    pattern: list(targets)
                    for pattern, targets in apple_content_targets.items()
                },
                "resolvedHostnames": apple_content_resolutions,
                "currentResolvedHostnames": apple_content_current_resolutions,
                "cnameChains": apple_content_cname_chains,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": apple_content_dns_history,
                    "expiredThisRun": apple_content_expired_records,
                },
                "unresolvedHostnames": apple_content_unresolved,
                "manualIpOverrides": False,
            },
            APPLE_DEVICE_FILE: {
                "cidrCount": len(apple_device_networks),
                "method": (
                    "Resolve official Apple Device setup, Device management, "
                    "audited APNs, and Private Cloud Compute FQDNs to IPv4 /32"
                ),
                "documentedHostnames": apple_device_documented,
                "documentedSections": {
                    "Device setup": apple_device_setup_documented,
                    "Device management": apple_device_management_documented,
                    "Apple Intelligence, Siri, and Search": (
                        apple_intelligence_documented
                    ),
                },
                "privateCloudComputeHostnames": apple_pcc_documented,
                "privateCloudComputeDohResolvedHostnames": (
                    apple_pcc_doh_resolutions
                ),
                "dnsObservationAttempts": apple_pcc_doh_attempt_counts,
                "wildcardPatterns": apple_device_wildcards,
                "wildcardResolutionTargets": {
                    pattern: list(targets)
                    for pattern, targets in apple_device_targets.items()
                },
                "resolvedHostnames": apple_device_resolutions,
                "currentResolvedHostnames": apple_device_current_resolutions,
                "cnameChains": apple_device_cname_chains,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": apple_device_dns_history,
                    "expiredThisRun": apple_device_expired_records,
                },
                "unresolvedHostnames": apple_device_unresolved,
                "forbiddenFallback": "17.0.0.0/8 or global CDN ranges",
                "manualIpOverrides": False,
            },
            APPLE_XCODE_FILE: {
                "cidrCount": len(apple_xcode_networks),
                "method": (
                    "Resolve only the Xcode downloadable-component FQDNs from "
                    "Apple's official Apps and additional content table, then "
                    "retain DNS-proven IPv4 /32 records for a rolling 24-hour window"
                ),
                "documentedHostnames": apple_xcode_documented,
                "wildcardPatterns": apple_xcode_wildcards,
                "wildcardResolutionTargets": apple_xcode_targets,
                "resolvedHostnames": apple_xcode_resolutions,
                "currentResolvedHostnames": apple_xcode_current_resolutions,
                "nativeResolvedHostnames": apple_xcode_native_resolutions,
                "dohResolvedHostnames": apple_xcode_doh_resolutions,
                "cnameChains": apple_xcode_cname_chains,
                "dnsObservationAttempts": apple_xcode_doh_attempt_counts,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        XCODE_DNS_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": apple_xcode_dns_history,
                    "expiredThisRun": apple_xcode_expired_records,
                },
                "unresolvedHostnames": apple_xcode_unresolved,
                "forbiddenFallback": "17.0.0.0/8 or global CDN ranges",
                "manualIpOverrides": False,
            },
            UBUNTU_MOTD_FILE: {
                "cidrCount": len(ubuntu_networks),
                "method": (
                    "Validate Canonical's Ubuntu Pro APT News URL, resolve only "
                    "motd.ubuntu.com, and retain DNS-proven IPv4 records for 24 hours"
                ),
                "documentedHostnames": ubuntu_hosts,
                "resolvedHostnames": ubuntu_resolutions,
                "currentResolvedHostnames": ubuntu_current_resolutions,
                "dohResolvedHostnames": ubuntu_doh_resolutions,
                "cnameChains": ubuntu_cname_chains,
                "dnsObservationAttempts": ubuntu_doh_attempt_counts,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": ubuntu_dns_history,
                    "expiredThisRun": ubuntu_expired_records,
                },
                "unresolvedHostnames": ubuntu_unresolved,
                "manualIpOverrides": False,
                "globalAwsRangesIncluded": False,
            },
            GITHUB_FILE: {
                "cidrCount": len(github_networks),
                "method": "Filter GitHub Meta API CIDRs by approved fields",
                "selectedFields": list(GITHUB_META_FIELDS),
                "ipv4CountsByFieldBeforeDeduplication": github_field_counts,
                "excludedFields": [
                    "actions",
                    "actions_macos",
                    "hooks",
                    "dependabot",
                    "packages",
                    "importer",
                    "github_enterprise_importer",
                ],
                "warning": (
                    "GitHub states that the Meta API isn't exhaustive for all "
                    "services, including some LFS and Packages use cases"
                ),
            },
            GITHUB_ACTIONS_FILE: {
                "cidrCount": len(github_actions_networks),
                "method": (
                    "Select concrete *.actions.githubusercontent.com FQDNs "
                    "published by GitHub Meta, resolve their public A records, "
                    "and retain them for a rolling 24-hour window"
                ),
                "officialWildcard": "*.actions.githubusercontent.com",
                "documentedHostnames": github_actions_hosts,
                "requiredHostnames": sorted(GITHUB_ACTIONS_REQUIRED_HOSTS),
                "resolvedHostnames": github_actions_resolutions,
                "currentResolvedHostnames": github_actions_current_resolutions,
                "cnameChains": github_actions_cname_chains,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": github_actions_dns_history,
                    "expiredThisRun": github_actions_expired_records,
                },
                "unresolvedHostnames": github_actions_unresolved,
                "manualIpOverrides": False,
                "globalAzureRangesIncluded": False,
                "githubMetaActionsCidrsIncluded": False,
            },
            DROPBOX_FILE: {
                "cidrCount": len(dropbox_networks),
                "method": (
                    "Use only Dropbox product IPv4 allocations linked from "
                    "official Dropbox firewall guidance"
                ),
                "selectedAllocations": dropbox_allocations,
                "excludedAllocationNames": dropbox_excluded_names,
                "thirdPartyInfrastructureIncluded": False,
            },
            DELL_UPDATE_FILE: {
                "cidrCount": len(dell_networks),
                "method": "Resolve the official Dell Command Update FQDN to IPv4 /32",
                "documentedHostnames": dell_hosts,
                "resolvedHostnames": dell_resolutions,
                "cnameChains": dell_cname_chains,
                "unresolvedHostnames": dell_unresolved,
            },
            MICROSOFT_EDGE_WINDOWS_FILE: {
                "cidrCount": len(microsoft_service_networks),
                "method": (
                    "Resolve selected official Microsoft Edge and Windows FQDNs "
                    "to IPv4 /32, retain DNS-proven records for 24 hours, then "
                    "remove networks already covered by existing EDLs"
                ),
                "edgeHostnames": edge_hosts,
                "windowsHostnames": windows_hosts,
                "windowsWildcardPatterns": windows_wildcards,
                "windowsWildcardResolutionTargets": {
                    pattern: list(targets)
                    for pattern, targets in windows_targets.items()
                },
                "resolvedHostnames": microsoft_service_resolutions,
                "currentResolvedHostnames": microsoft_service_current_resolutions,
                "cnameChains": microsoft_service_cname_chains,
                "dnsHistory": {
                    "gracePeriodHours": int(
                        DNS_HISTORY_GRACE_PERIOD.total_seconds() // 3600
                    ),
                    "recordsByHostname": microsoft_service_dns_history,
                    "expiredThisRun": microsoft_service_expired_records,
                },
                "controlledDohHostnames": sorted(MICROSOFT_EDGE_DOH_HOSTS),
                "dnsObservationAttempts": {
                    key: count
                    for key, count in microsoft_doh_attempt_counts.items()
                    if key.split("@", 1)[0] in MICROSOFT_EDGE_DOH_HOSTS
                },
                "unresolvedHostnames": microsoft_service_unresolved,
                "excludedExistingNetworks": microsoft_existing_exclusions,
                "manualIpOverrides": False,
                "globalAzureOrAs8075RangesIncluded": False,
            },
        }

        publish(
            output_dir=args.output_dir,
            generated_at=format_utc_timestamp(observed_at),
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
            additional_sources=additional_sources,
            additional_files=additional_files,
            resolutions_by_file=resolutions_by_file,
            cname_chains_by_file=cname_chains_by_file,
            dns_history_by_file=dns_history_by_file,
        )
    except GenerationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
