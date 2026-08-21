# Microsoft IPv4 EDLs

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

## Génération et garde-fous

Le workflow `.github/workflows/update-edl.yml` s'exécute toutes les heures et
peut être lancé manuellement. Aucun token Microsoft ni secret n'est requis.

Il applique les contrôles suivants à chaque liste :

1. validation explicite du JSON, des tableaux Markdown Microsoft et de la
   section Teams Direct Routing ;
2. validation Python `ipaddress` de chaque réseau ;
3. IPv4 publiques uniquement, triées et dédupliquées ;
4. refus de `0.0.0.0/0`, RFC1918, loopback, multicast, link-local, réseaux
   réservés, non spécifiés ou non globaux ;
5. refus de tout fichier vide ;
6. blocage d'une baisse de plus de 50 % du nombre d'entrées ;
7. résolution complète de tous les FQDN Defender sélectionnés ou échec ;
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

## Exploitation Palo Alto

Créer des EDL de type **IP List** avec un rafraîchissement horaire, notamment :

```text
EDL-M365-COMMON-IPV4
EDL-M365-EXCHANGE-IPV4
EDL-M365-SHAREPOINT-IPV4
EDL-M365-TEAMS-IPV4
EDL-MICROSOFT-DEFENDER-IPV4
EDL-MICROSOFT-TEAMS-MEDIA-IPV4
```

Pour HTTPS, associer un **Certificate Profile** faisant confiance à la chaîne
de certification présentée par GitHub Pages.

> [!WARNING]
> Ne jamais éditer manuellement les fichiers TXT générés dans `docs/`. Toute
> modification doit provenir du générateur et des sources officielles Microsoft.
