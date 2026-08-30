# Public service EDLs

Automatically generated public lists for use as Palo Alto Networks External
Dynamic Lists (**IP List** or **Domain List**).

The project accepts only official, attributable source data. Every generated
IP entry is validated, normalized, deduplicated, and sorted before it can be
published.

## Published EDLs

| File | Scope | Public URL |
|---|---|---|
| `m365-common-ipv4.txt` | Microsoft 365 `Common` | https://hove-io.github.io/m365-edl/m365-common-ipv4.txt |
| `m365-exchange-ipv4.txt` | Microsoft 365 `Exchange` | https://hove-io.github.io/m365-edl/m365-exchange-ipv4.txt |
| `m365-sharepoint-ipv4.txt` | Microsoft 365 `SharePoint` | https://hove-io.github.io/m365-edl/m365-sharepoint-ipv4.txt |
| `m365-teams-ipv4.txt` | Microsoft 365 `Skype` / Teams | https://hove-io.github.io/m365-edl/m365-teams-ipv4.txt |
| `microsoft-defender-ipv4.txt` | Defender for Endpoint EU/global and Defender Antivirus | https://hove-io.github.io/m365-edl/microsoft-defender-ipv4.txt |
| `microsoft-teams-media-ipv4.txt` | Teams Media / Direct Routing | https://hove-io.github.io/m365-edl/microsoft-teams-media-ipv4.txt |
| `microsoft-intune-windows-ipv4.txt` | Intune / Windows device management | https://hove-io.github.io/m365-edl/microsoft-intune-windows-ipv4.txt |
| `apple-updates-ipv4.txt` | Apple software updates | https://hove-io.github.io/m365-edl/apple-updates-ipv4.txt |
| `apple-appstore-content-ipv4.txt` | Apple App Store and content | https://hove-io.github.io/m365-edl/apple-appstore-content-ipv4.txt |
| `apple-device-services-ipv4.txt` | Apple device management, APNs, and Private Cloud Compute | https://hove-io.github.io/m365-edl/apple-device-services-ipv4.txt |
| `apple-xcode-developer-ipv4.txt` | Xcode and Apple Developer downloads | https://hove-io.github.io/m365-edl/apple-xcode-developer-ipv4.txt |
| `ubuntu-motd-ipv4.txt` | Ubuntu Pro APT News / MOTD | https://hove-io.github.io/m365-edl/ubuntu-motd-ipv4.txt |
| `github-ipv4.txt` | GitHub `web`, `api`, `git`, and `pages` | https://hove-io.github.io/m365-edl/github-ipv4.txt |
| `github-actions-ipv4.txt` | GitHub Actions and hosted runners | https://hove-io.github.io/m365-edl/github-actions-ipv4.txt |
| `dropbox-ipv4.txt` | Dropbox product allocations | https://hove-io.github.io/m365-edl/dropbox-ipv4.txt |
| `dell-update-ipv4.txt` | Dell Command Update | https://hove-io.github.io/m365-edl/dell-update-ipv4.txt |
| `microsoft-edge-windows-services-ipv4.txt` | Microsoft Edge and supporting Windows services | https://hove-io.github.io/m365-edl/microsoft-edge-windows-services-ipv4.txt |
| `zscaler/zpa/zpa_ipv4.txt` | Zscaler ZPA Public Service Edges for App Connectors | https://hove-io.github.io/m365-edl/zscaler/zpa/zpa_ipv4.txt |
| `log4j-ipv4.txt` | Curated historical Log4Shell/Log4j IPv4 IOCs | https://hove-io.github.io/m365-edl/log4j-ipv4.txt |
| `log4j-domains.txt` | Curated historical Log4Shell/Log4j domains | https://hove-io.github.io/m365-edl/log4j-domains.txt |

All IP lists are **IPv4 only**. `microsoft-teams-media-ipv4.txt` complements
`m365-teams-ipv4.txt`; it does not replace it.

## Official sources and scope

### Microsoft 365

The four Microsoft 365 lists use the official endpoint web service:

```text
https://endpoints.office.com/endpoints/worldwide
```

The generator filters the `ips` field by `serviceArea`. Microsoft officially
publishes `Common`, `Exchange`, `SharePoint`, and `Skype`; the `Skype` service
area feeds the Teams/Skype list.

The `Common` list supplements explicit CIDRs with public A records observed for
`word.office.com`, an audited concrete target under the official
`*.office.com` wildcard. DNS provenance, including CNAME chains, `firstSeen`,
and `lastSeen`, is retained for 24 hours. No generic Microsoft/Azure prefix or
manual `/32` is added.

Documentation: [Microsoft 365 IP Address and URL web service](https://learn.microsoft.com/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide)

### Microsoft Defender

The Defender list is built from these Microsoft sources:

- [Defender for Endpoint standard connectivity URLs — commercial](https://learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-commercial)
- [Configure Microsoft Defender Antivirus network connections](https://learn.microsoft.com/defender-endpoint/configure-network-connections-microsoft-defender-antivirus)

It includes Defender for Endpoint EU endpoints, required global endpoints for
Windows and Windows Server, Defender Antivirus dependencies, and only the Blob
Storage endpoints explicitly documented for Europe. Selected FQDNs are
resolved to public A records and published as `/32`; generic Azure prefixes are
never imported.

Official wildcard DNS names cannot be converted exhaustively into IP
addresses. The generator therefore resolves only explicit, audited targets and
records them in `sources.json`. Domain or URL controls remain necessary for
complete wildcard coverage.

### Microsoft Teams Media / Direct Routing

The supplemental Teams Media list is validated against
[Plan Direct Routing](https://learn.microsoft.com/microsoftteams/direct-routing-plan)
and accepts exactly these commercial ranges:

```text
52.112.0.0/14
52.120.0.0/14
```

The parser supports both known Microsoft Learn layouts. GCC High
(`52.127.88.0/21`), DoD (`52.127.64.0/21`), or any unexpected commercial range
causes publication to fail.

### Microsoft Intune / Windows

The Intune list is extracted from the **Consolidated Endpoint List** in
[Network endpoints for Microsoft Intune](https://learn.microsoft.com/intune/intune-service/fundamentals/intune-endpoints).
It combines explicit Intune CIDRs with current public A records for audited
targets under the official `*.events.data.microsoft.com` wildcard.

The generator validates the wildcard in the source, resolves only approved
concrete targets, and observes priority targets from two controlled French DNS
views through Google DNS over HTTPS with EDNS Client Subnet. Each proven
FQDN/IP pair and CNAME chain is retained for 24 hours. Microsoft/Azure addresses
seen only in logs are never added.

`watson.events.data.microsoft.com` and
`umwatsonc.events.data.microsoft.com` are also checked against the official
[Windows diagnostic endpoints](https://learn.microsoft.com/windows/privacy/windows-11-endpoints-non-enterprise-editions)
and [Configuration Manager internet endpoints](https://learn.microsoft.com/intune/configmgr/core/plan-design/network/internet-endpoints)
documentation.

### Apple

The four Apple lists use
[Use Apple products on enterprise networks](https://support.apple.com/101555).
The generator isolates the **Software updates**, **Apps and additional
content**, **Device setup**, and **Device management** tables and resolves only
their public A records.

`apple-device-services-ipv4.txt` also includes the three exact Private Cloud
Compute relays documented by Apple:

- `apple-relay.cloudflare.com`
- `apple-relay.fastly-edge.com`
- `cp4.cloudflare.com`

Xcode downloads are isolated in `apple-xcode-developer-ipv4.txt`. Apple DNS
observations, including CNAME chains, remain active for 24 hours to absorb
normal DNS rotation. The global `17.0.0.0/8` prefix and global CDN ranges are
never imported.

Apple warns that HTTPS interception can prevent its services from working.
Approved Apple FQDNs should therefore be excluded from TLS decryption in
addition to using the IP EDLs.

### Ubuntu Pro APT News / MOTD

`ubuntu-motd-ipv4.txt` validates `motd.ubuntu.com` against Canonical's official
[`uaclient/defaults.py`](https://github.com/canonical/ubuntu-pro-client/blob/main/uaclient/defaults.py),
then retains only public A records observed through the system resolver and two
controlled French DNS views for 24 hours. No global AWS, EC2, or CloudFront
range is added.

### GitHub

`github-ipv4.txt` uses the official [GitHub Meta API](https://api.github.com/meta)
and only the `web`, `api`, `git`, and `pages` fields. `actions`,
`actions_macos`, `hooks`, `dependabot`, `packages`, and `importer` are excluded.

`github-actions-ipv4.txt` is intentionally separate. It validates the official
`*.actions.githubusercontent.com` wildcard and resolves only concrete Action
service FQDNs published by GitHub, including the required documentary canaries
`tokenghub.actions.githubusercontent.com` and
`results-receiver.actions.githubusercontent.com`. Public A records and CNAME
chains are retained for 24 hours. Generic Actions CIDRs and Azure ranges are
not imported.

### Zscaler ZPA Public Service Edges

`zscaler/zpa/zpa_ipv4.txt` is built exclusively from the official
[Zscaler Private Access configuration page](https://config.zscaler.com/private.zscaler.com/zpa)
and its official JSON and plaintext exports.

The generator selects only `TCP/UDP 443` rows whose source is exactly
`Connector, Private Service Edge, Zscaler Client Connector` and whose domain
scope includes `*.private.zscaler.com`. Browser Access rows and valid IPv6
entries are excluded from this IPv4 EDL.

Before publication, the dedicated workflow requires all of the following:

- the expected ZPA page identity and `private.zscaler.com` cloud;
- the Connector/Public Service Edge section and official export links;
- exact equality between the complete JSON and plaintext network sets;
- exact equality between the output and the JSON Connector IPv4 selection;
- a non-empty list and no entry-count variation greater than 50% from the last
  valid version.

HTTP failures, schema changes, invalid entries, source disagreement, and
abnormal count changes stop the run before replacement. Publication is atomic,
and a commit is created only when the source or published content actually
changes. Full evidence is available in
[`metadata/zscaler-zpa.json`](https://hove-io.github.io/m365-edl/metadata/zscaler-zpa.json).

The stable Palo Alto URL is:

```text
https://hove-io.github.io/m365-edl/zscaler/zpa/zpa_ipv4.txt
```

The equivalent GitHub raw URL is:

```text
https://raw.githubusercontent.com/hove-io/m365-edl/main/docs/zscaler/zpa/zpa_ipv4.txt
```

ZPA App Connectors use certificate pinning. Keep `*.prod.zpath.net` in a
dedicated **no-decrypt** rule. When ZPA OAuth enrollment is used,
`zpa-oauth.private.zscaler.com` must also be allowed according to the Zscaler
documentation for the tenant.

### Dropbox

Dropbox's [firewall documentation](https://help.dropbox.com/installs/configuring-firewall)
points to its ARIN allocations. The list accepts only the `DROPBOX` and `DROPB`
product allocations and excludes corporate and third-party networks. Dropbox
still recommends domain-based controls for complete product coverage.

### Dell Command Update

Dell documents `downloads.dell.com` as the Dell Command Update endpoint. The
workflow validates the official `CatalogPC.cab` directly on that FQDN and
publishes only its current public A records. A Dell PTR or a global Dell-owned
range is not sufficient evidence.

### Microsoft Edge and Windows services

This supplemental list resolves audited FQDNs from the official
[Microsoft Edge](https://learn.microsoft.com/deployedge/microsoft-edge-security-endpoints)
and [Windows 11](https://learn.microsoft.com/windows/privacy/manage-windows-11-endpoints)
documentation. It covers Edge Update, Edge downloads, Windows Update, Store,
certificate and revocation services, SmartScreen, and selected diagnostics.

Windows Update and Delivery Optimization wildcard families are validated in
the official sources and represented only by audited concrete targets. Dynamic
priority targets are observed from two controlled French DNS views and retained
for 24 hours with CNAME provenance. Existing `/32` entries already covered by
another Microsoft EDL are removed. No global AS8075 or Azure range is used.

### Shared CDNs

The project does not publish a global Akamai, CloudFront, Cloudflare, or Fastly
EDL. A shared-CDN address is accepted only when it is currently returned by an
official in-scope service FQDN. Provider ownership alone is never treated as
service authorization.

### Historical Log4Shell / Log4j IOCs

`log4j-ipv4.txt` and `log4j-domains.txt` are conservative, reproducible
historical lists. They include only:

- typed IPv4 and domain STIX objects from confirmed CISA incidents
  [AA22-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a)
  and [AA22-174A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-174a);
- defanged indicators from explicitly audited payload/C2 sections of the
  [Unit 42 analysis](https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/).

Mass scanners, victim-discovery infrastructure, low-confidence community
lists, and legitimate shared services such as `transfer.sh` are excluded.
Per-indicator provenance, source hashes, accepted and rejected counts, and
output hashes are published in
[`metadata/log4j.json`](https://hove-io.github.io/m365-edl/metadata/log4j.json).

> [!CAUTION]
> These are historical IOCs. Their presence does not prove current malicious
> activity, and their absence does not prove that traffic is safe. They do not
> replace Log4j patching, IPS signatures, segmentation, or controls on
> unexpected LDAP/RMI egress.

## Automation and safeguards

The workflows run as follows:

- `.github/workflows/update-edl.yml`: hourly and on manual dispatch;
- `.github/workflows/update-log4j-edl.yml`: every Monday and on manual dispatch;
- `.github/workflows/update-zscaler-zpa-edl.yml`: daily and on manual dispatch.

No external secret is required. The publication pipeline enforces:

1. explicit JSON and source-section validation;
2. Python `ipaddress` validation for every network;
3. public IPv4-only output, sorted and deduplicated;
4. rejection of `0.0.0.0/0`, RFC1918, loopback, multicast, link-local,
   reserved, unspecified, and non-global networks;
5. rejection of empty output;
6. abnormal entry-count drop protection, plus bidirectional 50% variation
   protection for Zscaler ZPA;
7. repeated DNS observation for dynamic FQDNs with CNAME provenance;
8. atomic generation and replacement;
9. commits only when a published EDL or persistent DNS observation changes.

An HTTP error, invalid parse, unexpected source change, or required DNS failure
stops publication. The last valid public files remain available.

## Provenance and audit data

- [`sources.json`](https://hove-io.github.io/m365-edl/sources.json) records
  source URLs, SHA-256 hashes, generation time, methods, resolved Defender
  FQDNs, DNS history, and per-file CIDR counts.
- [`residual-ip-coverage.json`](https://hove-io.github.io/m365-edl/residual-ip-coverage.json)
  explains whether observed residual IPs are officially covered and classifies
  unattributed or intentionally excluded addresses.
- [`metadata/log4j.json`](https://hove-io.github.io/m365-edl/metadata/log4j.json)
  contains independent Log4Shell source and per-indicator provenance.
- [`metadata/zscaler-zpa.json`](https://hove-io.github.io/m365-edl/metadata/zscaler-zpa.json)
  records ZPA source correspondence, selection criteria, counters, and output
  hashes.

Metadata files are informational and must not be configured as Palo Alto EDLs.

## Palo Alto deployment

Create **IP List** EDL objects with an hourly refresh where appropriate. A
suggested naming scheme is:

```text
EDL-M365-COMMON-IPV4
EDL-M365-EXCHANGE-IPV4
EDL-M365-SHAREPOINT-IPV4
EDL-M365-TEAMS-IPV4
EDL-MICROSOFT-DEFENDER-IPV4
EDL-MICROSOFT-TEAMS-MEDIA-IPV4
EDL-MICROSOFT-INTUNE-WINDOWS-IPV4
EDL-APPLE-UPDATES-IPV4
EDL-APPLE-APPSTORE-CONTENT-IPV4
EDL-APPLE-DEVICE-SERVICES-IPV4
EDL-APPLE-XCODE-DEVELOPER-IPV4
EDL-UBUNTU-MOTD-IPV4
EDL-GITHUB-IPV4
EDL-GITHUB-ACTIONS-IPV4
EDL-DROPBOX-IPV4
EDL-DELL-UPDATE-IPV4
EDL-MICROSOFT-EDGE-WINDOWS-SERVICES-IPV4
EDL-ZSCALER-ZPA-PSE-IPV4
EDL-LOG4J-HISTORICAL-IPV4
```

For `EDL-ZSCALER-ZPA-PSE-IPV4`, use
`https://hove-io.github.io/m365-edl/zscaler/zpa/zpa_ipv4.txt`, restrict the
security rule source to the App Connector addresses, use TCP/443 with
`application-default`, and configure the ZPA TLS decryption exemption
separately.

Create `EDL-LOG4J-HISTORICAL-DOMAINS` separately as a **Domain List** if the
PAN-OS policy consumes the historical domains. Daily or weekly refresh is
sufficient for these historical IOCs; they are not a real-time reputation
feed.

For HTTPS retrieval, associate a **Certificate Profile** that trusts the chain
presented by GitHub Pages.

> [!WARNING]
> Never edit generated TXT files under `docs/` manually. Every published change
> must come from the generator and its official sources.
