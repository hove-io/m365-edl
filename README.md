# Public service EDLs

Listes publiques générées automatiquement pour être consommées comme External
Dynamic Lists (**IP List** ou **Domain List**) par un pare-feu Palo Alto
Networks.

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
| `apple-device-services-ipv4.txt` | Apple Device Management, APNs et Private Cloud Compute | https://hove-io.github.io/m365-edl/apple-device-services-ipv4.txt |
| `apple-xcode-developer-ipv4.txt` | Xcode et téléchargements Developer | https://hove-io.github.io/m365-edl/apple-xcode-developer-ipv4.txt |
| `ubuntu-motd-ipv4.txt` | Ubuntu Pro APT News / MOTD | https://hove-io.github.io/m365-edl/ubuntu-motd-ipv4.txt |
| `github-ipv4.txt` | GitHub `web`, `api`, `git` et `pages` | https://hove-io.github.io/m365-edl/github-ipv4.txt |
| `github-actions-ipv4.txt` | GitHub Actions et runners hébergés | https://hove-io.github.io/m365-edl/github-actions-ipv4.txt |
| `dropbox-ipv4.txt` | Allocations produit Dropbox | https://hove-io.github.io/m365-edl/dropbox-ipv4.txt |
| `dell-update-ipv4.txt` | Dell Command Update | https://hove-io.github.io/m365-edl/dell-update-ipv4.txt |
| `microsoft-edge-windows-services-ipv4.txt` | Microsoft Edge et services Windows complémentaires | https://hove-io.github.io/m365-edl/microsoft-edge-windows-services-ipv4.txt |
| `log4j-ipv4.txt` | IOC IPv4 historiques Log4Shell/Log4j fortement qualifiés | https://hove-io.github.io/m365-edl/log4j-ipv4.txt |
| `log4j-domains.txt` | Domaines historiques Log4Shell/Log4j fortement qualifiés | https://hove-io.github.io/m365-edl/log4j-domains.txt |

Toutes les listes IP sont **IPv4 only**. `microsoft-teams-media-ipv4.txt`
complète la liste `m365-teams-ipv4.txt` et ne la remplace pas.

## Sources officielles

### Microsoft 365

Les quatre listes M365 proviennent du web service officiel :

```text
https://endpoints.office.com/endpoints/worldwide
```

Le générateur filtre le champ `ips` par `serviceArea`. Microsoft expose
officiellement `Common`, `Exchange`, `SharePoint` et `Skype` ; `Skype` alimente
ici la liste Teams/Skype.

La liste `Common` complète ses CIDR explicites par une seule cible concrète et
auditée, `word.office.com`, sous le wildcard officiel `*.office.com` publié par
le même web service. Elle est résolue huit fois par run et ses A publics sont
conservés pendant 24 heures avec leur chaîne CNAME, `firstSeen` et `lastSeen`.
Cette extension qualifie les frontaux Office web sans importer un préfixe
Microsoft/Azure ni ajouter un `/32` manuel.

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

Le parseur accepte les deux structures de titres Microsoft Learn connues :

- historique : **Media traffic: port ranges** → **Microsoft 365, Office 365,
  and Office 365 GCC environments** ;
- actuelle : **Media processor IP ranges** → **Microsoft 365 / Office 365**.

Cette compatibilité de mise en page ne relâche pas le contrôle du contenu :
l'ensemble extrait doit rester exactement `52.112.0.0/14` et `52.120.0.0/14`.
Les plages souveraines GCC High (`52.127.88.0/21`) et DoD
(`52.127.64.0/21`), ainsi que toute autre plage inattendue, provoquent un
échec de validation avant publication.

### Microsoft Intune / Windows

La liste Intune est extraite de la documentation officielle
[Network endpoints for Microsoft Intune](https://learn.microsoft.com/intune/intune-service/fundamentals/intune-endpoints),
section **Consolidated Endpoint List**. Elle combine :

- les CIDR explicitement publiés pour les appareils gérés par Intune, y compris
  les sous-réseaux Azure Front Door `MicrosoftSecurity` ;
- les A records IPv4 courants d'un ensemble audité de cibles géographiques sous
  le wildcard officiel `*.events.data.microsoft.com`, utilisé pour le reporting
  Intune optionnel, Endpoint Analytics et les diagnostics clients.

Le wildcard n'est jamais résolu artificiellement et aucune IP observée n'est
ajoutée en dur. Le générateur valide sa présence dans la source Microsoft, puis
résout huit fois des cibles concrètes auditées appartenant à ce wildcard
(`events`, `functional`, `self`, `browser`, `mobile`, `v10`, `v10c`, `v20`,
`watson` et `umwatsonc`, ainsi que leurs variantes `au`, `eu`, `uk` et `us`).
Les cibles prioritaires sont également observées huit fois depuis chacune de
deux vues DNS françaises contrôlées par Google DNS over HTTPS avec EDNS Client
Subnet. Les résultats sont publiés en `/32` et consignés dans `sources.json`.

Les cibles `watson.events.data.microsoft.com` et
`umwatsonc.events.data.microsoft.com` sont en plus validées à chaque run contre
les documentations Microsoft [Windows diagnostic endpoints](https://learn.microsoft.com/windows/privacy/windows-11-endpoints-non-enterprise-editions)
et [Configuration Manager internet endpoints](https://learn.microsoft.com/intune/configmgr/core/plan-design/network/internet-endpoints).

Comme ces backends OneDS tournent rapidement, chaque couple FQDN/IP reste actif
pendant 24 heures après sa dernière observation DNS. Sa chaîne CNAME,
`firstSeen`, `lastSeen` et ses sources d'observation sont conservées. Une
adresse Microsoft/Azure observée dans les journaux n'est jamais ajoutée si
aucune de ces cibles officielles ne la retourne.

Les autres dépendances Windows Update et Delivery Optimization résolues par le
workflow sont placées dans `microsoft-edge-windows-services-ipv4.txt`. Aucun
préfixe Azure générique ni aucune plage AS8075 n'est ajouté.

### Apple

Les quatre listes Apple proviennent de
[Use Apple products on enterprise networks](https://support.apple.com/101555).
Le générateur isole strictement les tableaux **Software updates**, **Apps and
additional content**, **Device setup** et **Device management**, puis résout
leurs enregistrements A en `/32`. `apple-device-services-ipv4.txt` regroupe les
deux sections appareil et les trois relais Private Cloud Compute exacts
`apple-relay.cloudflare.com`, `apple-relay.fastly-edge.com` et
`cp4.cloudflare.com`, validés dans le tableau **Apple Intelligence, Siri, and
Search**. Les deux hôtes décrits par Apple pour les composants
téléchargeables Xcode (`devimages-cdn.apple.com` et
`download.developer.apple.com`) sont isolés dans
`apple-xcode-developer-ipv4.txt` et retirés de la liste App Store générique. Les
cibles concrètes APNs sont validées contre la documentation Apple Developer
officielle.

Les quatre EDL Apple conservent pendant 24 heures les couples FQDN/IP
officiellement dérivés qu'elles ont réellement observés. Pour Xcode, le workflow
effectue huit résolutions par FQDN avec le résolveur système et huit observations
par FQDN depuis chacune de deux vues DNS françaises contrôlées via Google DNS
over HTTPS (`82.64.0.0/11` et `82.66.0.0/16` en EDNS Client Subnet). Il agrège
uniquement les A publics retournés pour les deux FQDN Apple autorisés. Chaque
couple FQDN/IP est supprimé automatiquement 24 heures après sa dernière
observation. Cette fenêtre absorbe les
rotations DNS rapides sans autoriser un préfixe Apple ou CDN.

Les trois relais Private Cloud Compute sont eux aussi observés huit fois depuis
chacune des deux vues DNS françaises. Une adresse Cloudflare ou Fastly n'entre
donc dans l'EDL Apple que si elle est réellement renvoyée par l'un de ces trois
FQDN officiels ; aucune plage CDN globale n'est importée.

Le préfixe global `17.0.0.0/8` n'est jamais utilisé. Lorsqu'un FQDN Apple est
hébergé par un CDN, seule l'IPv4 obtenue par sa résolution est conservée. Les
wildcards ne sont pas exhaustivement convertibles : une EDL Domain/URL et une
exemption d'inspection TLS restent nécessaires pour une couverture Apple
complète.

Apple indique que l'interception HTTPS peut empêcher ses services de
fonctionner. Les FQDN Apple autorisés doivent donc être exemptés du déchiffrement
TLS, en complément des EDL IP dynamiques.

### Ubuntu Pro APT News / MOTD

`ubuntu-motd-ipv4.txt` valide le FQDN `motd.ubuntu.com` contre le fichier
[`uaclient/defaults.py`](https://github.com/canonical/ubuntu-pro-client/blob/main/uaclient/defaults.py)
du client Ubuntu Pro officiel, où l'URL APT News est définie. Le workflow
effectue huit résolutions système et huit observations depuis chacune des deux
vues DNS françaises, puis conserve uniquement les IPv4 publiques réellement
observées pendant 24 heures. Aucune plage AWS, EC2 ou CloudFront n'est ajoutée.

### GitHub

`github-ipv4.txt` utilise l'[API Meta GitHub](https://api.github.com/meta) et
uniquement les champs `web`, `api`, `git` et `pages`. Les champs `actions`,
`actions_macos`, `hooks`, `dependabot`, `packages` et `importer` sont exclus.
GitHub précise que cette API n'est pas exhaustive pour certains services,
notamment LFS et Packages ; une politique FQDN reste préférable pour ces usages.

`github-actions-ipv4.txt` reste volontairement séparée. Le générateur lit les
domaines Actions publiés par la même API Meta dans `domains.actions` et
`domains.actions_inbound`, exige la présence du wildcard officiel
`*.actions.githubusercontent.com`, puis ne résout que les FQDN concrets sous ce
suffixe. Cela inclut notamment `tokenghub.actions.githubusercontent.com` et
`results-receiver.actions.githubusercontent.com`, tous deux exigés comme
canaris documentaires.

Chaque FQDN Actions est résolu huit fois. Seuls ses A records IPv4 publics sont
conservés pendant 24 heures avec chaîne CNAME, `firstSeen` et `lastSeen`.
L'adresse `20.85.108.33` n'est donc couverte que si elle est réellement obtenue
depuis un FQDN officiel — actuellement via
`tokenghub.actions.githubusercontent.com` — et n'est jamais ajoutée comme `/32`
manuel. Le champ CIDR `actions` de l'API Meta, les plages Azure globales et les
adresses déduites de l'ASN sont explicitement exclus de cette EDL.

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
`downloads.dell.com`. Le workflow récupère et valide le catalogue officiel
`CatalogPC.cab` directement sur ce FQDN, puis en publie uniquement les A records
courants. Aucun réseau Dell global n'est ajouté et un PTR sous `dell.com` ne
suffit pas, à lui seul, à autoriser une adresse.

### Microsoft Edge et services Windows

La liste complémentaire Microsoft résout un ensemble audité de FQDN provenant
des documentations officielles
[Microsoft Edge](https://learn.microsoft.com/deployedge/microsoft-edge-security-endpoints)
et [Windows 11](https://learn.microsoft.com/windows/privacy/manage-windows-11-endpoints).
Elle couvre Edge Update, les téléchargements Edge, Windows Update, Store,
certificats/révocation, SmartScreen et les services de diagnostic retenus.

Pour Windows Update et Delivery Optimization, le générateur valide puis résout
les familles officielles `*.prod.do.dsp.mp.microsoft.com`,
`*.dl.delivery.mp.microsoft.com`, `*.delivery.mp.microsoft.com`,
`*.update.microsoft.com` et `*.windowsupdate.com`, ainsi que
`tsfe.trafficshaping.dsp.mp.microsoft.com`. Les wildcards sont représentés par
des cibles concrètes auditées, notamment `array504`, `array508`, `array516`,
`array808`, des instances `disc` et `kv`, les variantes `geo`/`geover`, ainsi
que les services de téléchargement. Les familles sont aussi validées contre le
[workflow Delivery Optimization](https://learn.microsoft.com/windows/deployment/do/delivery-optimization-workflow)
officiel. Les réponses DNS changent avec les backends Microsoft et sont donc
recalculées à chaque exécution, sans `/32` manuel.

Les FQDN officiels `settings.data.microsoft.com`,
`settings-win.data.microsoft.com` et `config.edge.skype.com` sont en plus
observés huit fois depuis chacune des deux vues DNS françaises contrôlées. Les
couples FQDN/IP, leur chaîne CNAME et leurs sources d'observation sont conservés
24 heures. Cette fenêtre couvre les rotations géographiques sans ajouter
`edge.skype.com`, un wildcard `*.pipe.aria.microsoft.com` non concrétisé, ni un
préfixe Microsoft global.

Les `/32` déjà couverts par une EDL Microsoft existante sont retirés de cette
nouvelle liste. Aucun range Azure global ni AS8075 n'est utilisé.

### CDN mutualisés

Aucune EDL globale Akamai, CloudFront, Cloudflare ou Fastly n'est créée. Les
préfixes CDN partagés ne sont jamais autorisés globalement. Une IP
de CDN n'est publiée que lorsqu'elle résulte au moment de la génération d'un
FQDN officiel appartenant à Apple, Dell, Microsoft ou un autre service ciblé.

### Log4Shell / Log4j — IOC historiques

`log4j-ipv4.txt` et `log4j-domains.txt` sont des listes historiques,
conservatrices et reproductibles. Elles ne copient pas aveuglément les grandes
listes de scanners publiées pendant la crise Log4Shell. Le générateur retient
uniquement :

- les objets STIX IPv4 et domaines de deux incidents confirmés publiés par la
  CISA : [AA22-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a)
  et [AA22-174A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-174a) ;
- les indicateurs déneutralisés présents dans trois sections payload/C2
  explicitement auditées de l'analyse
  [Unit 42](https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/) :
  V8 password stealer, Happy Everyday/Cobalt Strike et coinminer.

Les sections Unit 42 consacrées aux scanners de masse et à la découverte de
serveurs vulnérables sont hors périmètre. Sont également évaluées mais non
importées : la liste de scanners citée par CISA AA21-356A, l'échantillon
Microsoft Sentinel, le catalogue NCSC-NL non vérifié et les pages CERT ne
fournissant pas de feed structuré. `transfer.sh` est rejeté explicitement car
ce service légitime mutualisé ne peut pas être bloqué comme un domaine C2.

La provenance complète, le statut des sources, leurs empreintes SHA-256, les
rejets et les sources de chaque indicateur sont publiés dans
[`metadata/log4j.json`](https://hove-io.github.io/m365-edl/metadata/log4j.json).
Les adresses sont validées avec `ipaddress`, limitées aux IPv4 publiques,
normalisées, dédupliquées et triées numériquement. Les domaines sont validés,
normalisés et triés. Une source absente, vide, illisible ou une baisse de plus
de 50 % bloque atomiquement toute nouvelle publication.

La génération initiale du 23 août 2026 contient **18 IPv4 uniques** et
**2 domaines**. La date UTC exacte et les compteurs de la dernière génération
sont toujours ceux de `metadata/log4j.json` ; ils sont recalculés par le
workflow hebdomadaire.

> [!CAUTION]
> Ces IOC sont historiques : leur présence ne prouve pas une activité
> malveillante actuelle et leur absence ne prouve pas qu'un flux est sain. Ils
> ne remplacent pas la mise à jour de Log4j, les signatures IPS, la segmentation
> des systèmes vulnérables ni le contrôle des sorties LDAP/RMI inattendues.

## Génération et garde-fous

Le workflow `.github/workflows/update-edl.yml` s'exécute toutes les heures et
peut être lancé manuellement. Le workflow Log4Shell dédié
`.github/workflows/update-log4j-edl.yml` s'exécute chaque lundi et peut aussi
être lancé manuellement. Aucun secret externe n'est requis.

Il applique les contrôles suivants à chaque liste :

1. validation explicite des JSON et des sections/tableaux des documentations
   officielles ;
2. validation Python `ipaddress` de chaque réseau ;
3. IPv4 publiques uniquement, triées et dédupliquées ;
4. refus de `0.0.0.0/0`, RFC1918, loopback, multicast, link-local, réseaux
   réservés, non spécifiés ou non globaux ;
5. refus de tout fichier vide ;
6. blocage d'une baisse de plus de 50 % du nombre d'entrées ;
7. jusqu'à huit résolutions DNS par FQDN Microsoft dynamique et GitHub Actions
   (trois pour les autres sources ; huit résolutions système et huit observations
   par vue DNS contrôlée pour Xcode), avec un court intervalle entre les requêtes, agrégation des A et
   journalisation de chaque mapping FQDN → chaîne CNAME → IPv4 ;
8. génération atomique de l'ensemble ;
9. commit et publication uniquement lorsqu'une EDL ou une observation DNS
   persistante (`last_seen`) a changé.

Des tests de régression vérifient les deux structures Microsoft Learn pour
Teams Media et confirment qu'une plage commerciale inattendue reste bloquée.
Ils vérifient également le parsing séparé des blocs FQDN/CIDR Intune et la
sélection contrôlée des familles DNS Microsoft.

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
Chaque entrée expose aussi `sourcePalo` (`paloSource` reste un alias
rétrocompatible), `officialSource`, `category`,
`confidence`, `cname_chain` et `source_documentation` ; une chaîne vide reste
explicite lorsque le FQDN répond directement. Les alias explicites
`officialFqdn`, `cnameChain`, `firstSeen`, `lastSeen` et `targetEdl` facilitent
également l'audit automatique des canaris sans supprimer le schéma historique.
Le bloc `currentInternetOnlyAudit` recense les destinations de la passe
post-refresh courante et les classe exactement dans `COVERED_OFFICIAL`,
`OFFICIAL_BUT_NOT_CURRENTLY_RESOLVED`, `CDN_SHARED_UNATTRIBUTED`,
`OWNER_ONLY_UNATTRIBUTED` ou `INTENTIONALLY_UNCOVERED`.
Pour les quatre EDL Apple, l'EDL Ubuntu MOTD et l'EDL GitHub Actions,
`first_seen`, `last_seen` et `observation_sources` documentent en plus la
fenêtre glissante. Le détail
persistant se trouve dans le bloc `dnsHistory` du fichier concerné dans
`sources.json`. Le rapport distingue également `owner`, `suspectedService` et
`verified` : la propriété d'une IP Apple, Azure, Akamai ou Cloudflare ne vaut
jamais autorisation de service.

Le rapport Log4Shell public
[`metadata/log4j.json`](https://hove-io.github.io/m365-edl/metadata/log4j.json)
est indépendant de `sources.json`. Il contient les CVE associées, les sources
utilisées ou écartées, les compteurs bruts/acceptés/rejetés, les hashes des
sorties et la provenance multi-source par indicateur.

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
EDL-APPLE-XCODE-DEVELOPER-IPV4
EDL-UBUNTU-MOTD-IPV4
EDL-GITHUB-IPV4
EDL-GITHUB-ACTIONS-IPV4
EDL-DROPBOX-IPV4
EDL-DELL-UPDATE-IPV4
EDL-MICROSOFT-EDGE-WINDOWS-SERVICES-IPV4
EDL-LOG4J-HISTORICAL-IPV4
```

Créer séparément `EDL-LOG4J-HISTORICAL-DOMAINS` comme **Domain List** si la
politique PAN-OS consomme aussi les deux domaines historiques publiés. Une
fréquence de rafraîchissement quotidienne ou hebdomadaire suffit pour ces IOC ;
ce feed n'est pas une réputation temps réel.

Pour HTTPS, associer un **Certificate Profile** faisant confiance à la chaîne
de certification présentée par GitHub Pages.

> [!WARNING]
> Ne jamais éditer manuellement les fichiers TXT générés dans `docs/`. Toute
> modification doit provenir du générateur et des sources officielles.
