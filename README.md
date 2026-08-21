# Microsoft 365 IPv4 EDLs

Listes IPv4 publiques générées automatiquement pour être consommées comme
External Dynamic Lists (**IP List**) par un pare-feu Palo Alto Networks.

## EDL publiées

| Fichier | `serviceArea` Microsoft | URL |
|---|---|---|
| `m365-common-ipv4.txt` | `Common` | https://hove-io.github.io/m365-edl/m365-common-ipv4.txt |
| `m365-exchange-ipv4.txt` | `Exchange` | https://hove-io.github.io/m365-edl/m365-exchange-ipv4.txt |
| `m365-sharepoint-ipv4.txt` | `SharePoint` | https://hove-io.github.io/m365-edl/m365-sharepoint-ipv4.txt |
| `m365-teams-ipv4.txt` | `Skype` | https://hove-io.github.io/m365-edl/m365-teams-ipv4.txt |

Microsoft expose officiellement les zones `Common`, `Exchange`, `SharePoint`
et `Skype`. La zone `Skype` alimente ici la liste Teams/Skype, conformément au
modèle du web service Microsoft 365.

## Source officielle

Les données proviennent exclusivement du web service officiel Microsoft 365 :

```text
https://endpoints.office.com/endpoints/worldwide
```

Documentation : [Microsoft 365 IP Address and URL web service](https://learn.microsoft.com/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide)

Chaque appel utilise un `ClientRequestId` UUID et ne nécessite aucun token ni
secret. Seul le champ `ips` des enregistrements correspondant aux quatre
`serviceArea` est traité.

## Génération et garde-fous

Le workflow `.github/workflows/update-edl.yml` s'exécute toutes les heures et
peut être lancé manuellement. Il :

1. récupère le JSON Microsoft ;
2. valide explicitement son format ;
3. conserve uniquement les CIDR IPv4 valides ;
4. ignore les CIDR IPv6 ;
5. trie et déduplique chaque liste ;
6. refuse `0.0.0.0/0`, les réseaux privés RFC1918, loopback, multicast,
   link-local, réservés, non spécifiés ou non publics ;
7. refuse tout fichier vide ;
8. bloque une baisse de plus de 50 % du nombre de CIDR d'une liste ;
9. commit et publie uniquement lorsqu'une liste a changé.

Une erreur HTTP, un JSON invalide, un changement inattendu du schéma ou un
échec de validation arrête le workflow avant le remplacement des fichiers. La
dernière publication valide reste donc disponible.

Les nombres de CIDR produits sont affichés dans les logs GitHub Actions.

## Provenance

Le fichier public [`sources.json`](https://hove-io.github.io/m365-edl/sources.json)
documente la source, la date de génération, le `ClientRequestId`, les filtres et
le nombre de CIDR par fichier. Il s'agit de métadonnées et non d'une EDL Palo
Alto.

## Exploitation Palo Alto

Créer quatre EDL de type **IP List** avec un rafraîchissement horaire :

```text
EDL-M365-COMMON-IPV4
EDL-M365-EXCHANGE-IPV4
EDL-M365-SHAREPOINT-IPV4
EDL-M365-TEAMS-IPV4
```

Pour HTTPS, associer un **Certificate Profile** faisant confiance à la chaîne
de certification présentée par GitHub Pages.

> [!WARNING]
> Ne jamais éditer manuellement les fichiers TXT générés dans `docs/`. Toute
> modification doit provenir du générateur et de la source officielle Microsoft.
