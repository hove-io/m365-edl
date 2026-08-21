# Public service IPv4 EDLs

Listes IPv4 publiques générées automatiquement pour être consommées comme
External Dynamic Lists (**IP List**) par un pare-feu Palo Alto Networks.

## EDL publiées

| Fichier | Périmètre | URL |
|---|---|---|
| `m365-common-ipv4.txt` | Microsoft 365 `Common` | https://hove-io.github.io/m365-edl/m365-common-ipv4.txt |
| `m365-exchange-ipv4.txt` | Microsoft 365 `Exchange` | https://hove-io.github.io/m365-edl/m365-exchange-ipv4.txt |
| `m365-sharepoint-ipv4.txt` | Microsoft 365 `SharePoint` | https://hove-io.github.io/m365-edl/m365-sharepoint-ipv4.txt |
| `m365-teams-ipv4.txt` | Microsoft 365 `Skype` | https://hove-io.github.io/m365-edl/m365-teams-ipv4.txt |
| `microsoft-defender-ipv4.txt` | Defender for Endpoint EU/global et Defender Antivirus | https://hove-io.github.io/m365-edl/microsoft-defender-ipv4.txt |
| `microsoft-teams-media-ipv4.txt` | Teams Media / Direct Routing | https://hove-io.github.io/m365-edl/microsoft-teams-media-ipv4.txt |
| `microsoft-intune-windows-ipv4.txt` | Intune / gestion des appareils Windows | https://hove-io.github.io/m365-edl/microsoft-intune-windows-ipv4.txt |
| `apple-updates-ipv4.txt` | Mises à jour logicielles Apple | https://hove-io.github.io/m365-edl/apple-updates-ipv4.txt |
| `apple-appstore-content-ipv4.txt` | Apple App Store et contenu | https://hove-io.github.io/m365-edl/apple-appstore-content-ipv4.txt |
| `apple-device-services-ipv4.txt` | Apple Device Management et APNs | https://hove-io.github.io/m365-edl/apple-device-services-ipv4.txt |
| `github-ipv4.txt` | GitHub `web`, `api`, `git` et `pages` | https://hove-io.github.io/m365-edl/github-ipv4.txt |
| `dropbox-ipv4.txt` | Allocations produit Dropbox | https://hove-io.github.io/m365-edl/dropbox-ipv4.txt |
| `dell-update-ipv4.txt` | Dell Command Update | https://hove-io.github.io/m365-edl/dell-update-ipv4.txt |
| `microsoft-edge-windows-services-ipv4.txt` | Microsoft Edge et services Windows complémentaires | https://hove-io.github.io/m365-edl/microsoft-edge-windows-services-ipv4.txt |

Toutes les listes sont **IPv4 only**. `microsoft-teams-media-ipv4.txt` complète
la liste `m365-teams-ipv4.txt` et ne la remplace pas.

## Sources officielles

### Microsoft 365

Les quatre listes M365 proviennent du web service officiel :

```text
https://endpoints.office.com/endpoints/worldwide
```

Le générateur filtre uniquement le champ `ips` par `serviceArea`. Microsoft
expose officiellement `Common`, `Exchange`, `SharePoint` et `Skype` ; `Skype`
alimente ici la liste Teams/Skype.

Documentation : [Microsoft 365 IP Address and URL web service](https://learn.microsoft.com/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide)

### Microsoft Defender

La liste Defender est construite depuis les sources Microsoft suivantes :

- [Defender for Endpoint standard connectivity URLs — commercial](https://learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-commercial)
- [Configure Microsoft Defender Antivirus network connections](https://learn.microsoft.com/defender-endpoint/configure-network-connections-microsoft-defender-antivirus)

Le générateur extrait :

- tous les endpoints `Microsoft Defender for Endpoint EU` ;
- les endpoints globaux `Required` applicables à Windows/Windows Server ;
- les endpoints Microsoft Defender Antivirus et leurs dépendances officielles
  Microsoft Update, Windows Update, ADL, CRL et télémétrie ;
- uniquement les stockages Blob explicitement documentés pour l'Europe.

Chaque FQDN sélectionné est résolu en enregistrements A, puis chaque IPv4
publique est convertie en `/32`. Aucun préfixe Azure générique n'est ajouté.

Les wildcards DNS publiés par Microsoft ne peuvent pas être convertis de façon
exhaustive en adresses IP. Le générateur emploie donc des cibles explicites et
traçables pour ces motifs, documentées dans `sources.json`. Cette IP EDL reflète
les résolutions observées par le runner GitHub ; pour une couverture exhaustive
des wildcards, des contrôles Domain/URL restent nécessaires.

### Microsoft Teams Media / Direct Routing

La liste complémentaire Teams Media est validée directement contre
[Plan Direct Routing](https://learn.microsoft.com/microsoftteams/direct-routing-plan)
et contient uniquement les plages commerciales officiellement documentées :

```text
52.112.0.0/14
52.120.0.0/14
```

La plage `52.120.0.0/14` couvre notamment `52.123.242.163`.

### Microsoft Intune / Windows

La liste Intune est extraite de la documentation officielle
[Network endpoints for Microsoft Intune](https://learn.microsoft.com/intune/intune-service/fundamentals/intune-endpoints),
section **Consolidated Endpoint List / IP Subnets**. Elle contient uniquement
les CIDR explicitement publiés par Microsoft pour les appareils gérés par
Intune, y compris les sous-réseaux Azure Front Door `MicrosoftSecurity` que la
page intègre à sa liste consolidée.

Les dépendances Windows Update, Delivery Optimization, WNS et Autopilot qui ne
sont publiées que sous forme de FQDN ne sont pas résolues artificiellement dans
cette EDL. Aucun préfixe Azure générique ni aucune plage AS8075 n'est ajouté.

### Apple

Les trois listes Apple proviennent de
[Use Apple products on enterprise networks](https://support.apple.com/101555).
Le générateur isole strictement les tableaux **Software updates**, **Apps and
additional content** et **Device management**, puis résout leurs enregistrements
A en `/32`. Les cibles concrètes APNs sont validées contre la documentation
Apple Developer officielle.

Le préfixe global `17.0.0.0/8` n'est jamais utilisé. Lorsqu'un FQDN Apple est
hébergé par un CDN, seule l'IPv4 obtenue par sa résolution est conservée. Les
wildcards ne sont pas exhaustivement convertibles : une EDL Domain/URL et une
exemption d'inspection TLS restent nécessaires pour une couverture Apple
complète.

### GitHub

`github-ipv4.txt` utilise l'[API Meta GitHub](https://api.github.com/meta) et
uniquement les champs `web`, `api`, `git` et `pages`. Les champs `actions`,
`actions_macos`, `hooks`, `dependabot`, `packages` et `importer` sont exclus.
GitHub précise que cette API n'est pas exhaustive pour certains services,
notamment LFS et Packages ; une politique FQDN reste préférable pour ces usages.

### Dropbox

Dropbox renvoie depuis sa
[documentation pare-feu](https://help.dropbox.com/installs/configuring-firewall)
vers ses allocations ARIN. La liste retient uniquement les allocations produit
`DROPBOX` et `DROPB`, en excluant les réseaux corporate et tiers. Elle ne tente
pas d'autoriser globalement les infrastructures externes utilisées par Dropbox.
Dropbox recommande l'autorisation par domaines pour une couverture produit
complète.

### Dell Command Update

La documentation Dell indique que Dell Command Update se connecte à
`downloads.dell.com`. Seuls les A records courants de ce FQDN officiel sont
publiés. Aucun réseau Dell global n'est ajouté et un PTR sous `dell.com` ne
suffit pas, à lui seul, à autoriser une adresse.

### Microsoft Edge et services Windows

La liste complémentaire Microsoft résout un ensemble audité de FQDN provenant
des documentations officielles
[Microsoft Edge](https://learn.microsoft.com/deployedge/microsoft-edge-security-endpoints)
et [Windows 11](https://learn.microsoft.com/windows/privacy/manage-windows-11-endpoints).
Elle couvre Edge Update, les téléchargements Edge, Windows Update, Store,
certificats/révocation, SmartScreen et les services de diagnostic retenus.

Les `/32` déjà couverts par une EDL Microsoft existante sont retirés de cette
nouvelle liste. Aucun range Azure global ni AS8075 n'est utilisé.

### CDN mutualisés

Aucune EDL globale Akamai, CloudFront, Cloudflare ou Fastly n'est créée. Une IP
de CDN n'est publiée que lorsqu'elle résulte au moment de la génération d'un
FQDN officiel appartenant à Apple, Dell, Microsoft ou un autre service ciblé.

## Génération et garde-fous

Le workflow `.github/workflows/update-edl.yml` s'exécute toutes les heures et
peut être lancé manuellement. Aucun token Microsoft ni secret n'est requis.

Il applique les contrôles suivants à chaque liste :

1. validation explicite des JSON et des sections/tableaux des documentations
   officielles ;
2. validation Python `ipaddress` de chaque réseau ;
3. IPv4 publiques uniquement, triées et dédupliquées ;
4. refus de `0.0.0.0/0`, RFC1918, loopback, multicast, link-local, réseaux
   réservés, non spécifiés ou non globaux ;
5. refus de tout fichier vide ;
6. blocage d'une baisse de plus de 50 % du nombre d'entrées ;
7. jusqu'à trois tentatives DNS par FQDN ciblé, suivi des CNAME par le résolveur
   et journalisation de chaque mapping FQDN vers IPv4 ;
8. génération atomique de l'ensemble ;
9. commit et publication uniquement lorsqu'une EDL a changé.

Une erreur HTTP, un parsing invalide, un changement inattendu des sources ou
un échec DNS arrête le workflow avant le remplacement des fichiers. La dernière
publication valide reste disponible. Les nombres de CIDR sont affichés dans les
logs GitHub Actions.

## Provenance

Le fichier public [`sources.json`](https://hove-io.github.io/m365-edl/sources.json)
documente les sources, leurs empreintes SHA-256, la date de génération, la
méthode, les FQDN Defender résolus et le nombre de CIDR par fichier. Ce fichier
est informatif et ne doit pas être utilisé comme EDL Palo Alto.

Le rapport public
[`residual-ip-coverage.json`](https://hove-io.github.io/m365-edl/residual-ip-coverage.json)
indique pour chaque IP observée si elle est couverte, par quelle EDL et par
quelle source/FQDN. Une IP sans preuve officielle reste `covered: false`.

## Exploitation Palo Alto

Créer des EDL de type **IP List** avec un rafraîchissement horaire, notamment :

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
EDL-GITHUB-IPV4
EDL-DROPBOX-IPV4
EDL-DELL-UPDATE-IPV4
EDL-MICROSOFT-EDGE-WINDOWS-SERVICES-IPV4
```

Pour HTTPS, associer un **Certificate Profile** faisant confiance à la chaîne
de certification présentée par GitHub Pages.

> [!WARNING]
> Ne jamais éditer manuellement les fichiers TXT générés dans `docs/`. Toute
> modification doit provenir du générateur et des sources officielles.
