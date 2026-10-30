# AKUMA ADB / Polygon — jeu de preuves public expurgé

**Date : 30 octobre 2026 (UTC) — préparation pour relecture, non publié.**

Ce jeu de pièces complète l'enquête sur l'échantillon Linux x86_64 SHA256
`d5de7f84a8547f8ef0213890850aaac5840f168ffeb6bca34cb0870fc9854817`.
Il ne contient **ni binaire malveillant, ni script d'infection, ni capture SSH**.

## Contenu

| Fichier | Nature | Précaution d'interprétation |
| --- | --- | --- |
| `AKUMA_PUBLIC_EVIDENCE_2026-10-28.json` | 12 événements ADB sélectionnés, deux calldata Polygon, observations confinées et résultats Suricata | Sélection éditoriale, pas export de journaux bruts ; transaction et timestamps à recouper indépendamment. |
| `AKUMA_PUBLIC_DECODE_20261030.py` | Décodage **sans réseau et sans ELF** des deux champs `input` publics | Clé de 32 octets issue de l'analyse statique *déjà publiée* ; ne prouve pas son extraction depuis le binaire. |
| `akuma-adb-x64.rules` | Règle Suricata `sid:9001001`, révision 1 | Détection ciblée sur le check-in `akuma.adb` x86_64 ; aucune mesure indépendante du taux de faux positifs. |
| `AKUMA_C2_ANONYMIZED_20261030.pcap` | **17 paquets réels** du test avec **faux C2 privé**, anonymisés | Ce n'est **pas** un trafic C2 public. Les adresses/MAC/TCP timestamps et entêtes IP ont été réécrits ; la charge utile TCP et la segmentation sont conservées. |
| `AKUMA_PUBLIC_SHA256SUMS_20261030.txt` | Empreintes des quatre fichiers précédents | Contrôle local d'intégrité seulement ; n'authentifie pas les observations à lui seul. |

## Méthode et protection des données

- Capture source filtrée : 17 trames Ethernet de TCP/25565 issues d'une capture
  du serveur C2 simulé, SHA256 source
  `26c947551f9ff74c7993ce5c8bc0a4c1ad54d0a163743bf43f199673d143d7bd`.
- Seules deux adresses IPv4 documentaires figurent comme extrémités réseau :
  `192.0.2.10` (victime de test) et `192.0.2.20` (faux C2). Adresses MAC
  localement administrées de démonstration ; checksums IPv4/TCP recalculés.
- L'export a rejeté les paquets hors du flux TCP/25565 attendu : aucune trame
  SSH, ARP, DNS, RPC ou provenant d'une autre session n'a été reprise.
- Les **horodatages UTC de la capture du test sont conservés**, car ils sont
  nécessaires à l'étude des intervalles entre enregistrement et heartbeats.
  La PCAP s'arrête avant le cinquième heartbeat : elle contient 34 octets
  applicatifs, contre 36 octets dans le journal privé du faux C2.
- Les originaux (PCAP complète, NFLOG, journaux système, archive Suricata et
  ELF) restent conservés séparément **en privé** avec leurs empreintes.

## Reproduction locale sans exécuter le malware

Avec Python 3 (bibliothèque standard) :

```bash
python3 AKUMA_PUBLIC_DECODE_20261030.py AKUMA_PUBLIC_EVIDENCE_2026-10-28.json
sha256sum -c AKUMA_PUBLIC_SHA256SUMS_20261030.txt
```

Résultats attendus : deux sorties `45.205.1.121:25565` et
`191.217.203.232:25565`, une répétition triple des quatre octets IPv4,
vérification du préfixe de 21 octets `akuma.adb`, puis `PASS`.

Pour examiner la capture dans Wireshark ou Suricata : uniquement **hors ligne**.
La règle Suricata a produit une alerte le **30 octobre** sur **la capture
Ethernet originale de 334 paquets**, au rejeu avec `-k none`, et zéro alerte
sur un témoin interne de 27 paquets. **Cette PCAP anonymisée de 17 paquets
n'a pas été retestée par le moteur Suricata après la réécriture de ses
en-têtes**. Les checksums de ses 17 trames ont été validés par un contrôle
Python indépendant de la génération ; le résultat moteur exact est à tester
sur le système du lecteur avant toute affirmation supplémentaire.

## Limites et provenance

1. Il s'agit du comportement d'un **faux C2 confiné**, pas d'une prise de
   contact avec les adresses criminelles reconstruites depuis Polygon.
2. Deux appels setter avec `status=0x1` et un getter `latest` concordant ont
   été archivés. Les états historiques complets au bloc précédent/suivant
   ne sont **pas** archivés ; les résultats sont limités aux valeurs des appels.
3. Le script public contient la clé publiée. La vérification de l'extraction
   indépendante de cette clé nécessite le binaire d'origine et l'outil
   forensique privé, non inclus ici ; ne pas confondre ces deux niveaux de
   reproduction.
4. Le JSON est une **sélection** de données originales attestées en interne ;
   il n'est ni signé par un tiers ni un export natif d'explorateur blockchain.
5. Le test Suricata positif/contrôle témoins ne caractérise ni les variantes
   de la famille, ni les faux positifs dans du trafic bénin indépendant.
6. Aucune exécution de malware et aucune connexion externe ne sont
   nécessaires pour consulter les pièces de cette archive.

**État éditorial :** prêt pour examen final et hébergement éventuel sur
validation explicite du responsable de l'enquête ; **aucune publication
automatique** et aucune notification externe.
