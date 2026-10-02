# Envoyer les alertes vers un SIEM

Un SIEM (Security Information and Event Management) centralise les journaux de toutes les sources d'une entreprise (pare-feu, serveurs, EDR, IDS...) pour les corréler et les investiguer. En SOC, c'est l'outil principal de l'analyste. WiFi Guardian peut y envoyer ses alertes et ses incidents.

Rien de tout cela n'est obligatoire : WiFi Guardian fonctionne seul. Ce guide sert à t'entraîner avec les outils utilisés en entreprise.

## Ce que WiFi Guardian envoie

Chaque alerte et chaque incident (créé, aggravé ou changé de statut) devient un événement JSON au format **ECS** (Elastic Common Schema), le vocabulaire de champs le plus répandu :

| Champ | Exemple | Sens |
| --- | --- | --- |
| `@timestamp` | `2025-03-14T21:05:12.431Z` | Heure de l'événement (UTC) |
| `event.dataset` | `wifi_guardian.alert` ou `wifi_guardian.incident` | Type d'événement |
| `event.action` | `arp_spoofing` | Type d'alerte |
| `event.severity` | `95` | Gravité de 0 à 100 |
| `log.level` | `critical` | Gravité en texte |
| `source.ip`, `source.mac`, `destination.ip` | `192.168.1.66` | Machines concernées |
| `threat.technique.id` | `["T1557.002"]` | Technique MITRE ATT&CK |
| `threat.tactic.name` | `["credential-access"]` | Tactique MITRE ATT&CK |
| `wifi_guardian.evidence` | `{...}` | Preuves détaillées |

Deux moyens de transport, utilisables ensemble :

- **Fichier JSON Lines** (`SIEM_JSON_FILE`) : une ligne par événement, avec rotation automatique. Un agent (Wazuh, Filebeat, Fluent Bit) lit le fichier. C'est la méthode la plus fiable.
- **Syslog** (`SIEM_SYSLOG_HOST`) en UDP ou TCP, avec un contenu JSON ou **CEF** (format ArcSight, compris par presque tous les SIEM). En mode CEF, seules les alertes sont en CEF : les incidents restent en JSON, car CEF décrit mal un regroupement d'alertes.

## Étape 0 : vérifier l'envoi sans SIEM

```bash
# Terminal 1 : un faux serveur syslog
nc -klu 5514

# .env
SIEM_SYSLOG_HOST=127.0.0.1
SIEM_SYSLOG_PORT=5514
SIEM_SYSLOG_FORMAT=cef
SIEM_JSON_FILE=data/siem/alerts.jsonl
```

Relance WiFi Guardian : chaque alerte s'affiche dans le terminal 1 et s'ajoute à `data/siem/alerts.jsonl`. `/api/health` montre les compteurs dans la section `siem`.

Pour générer des alertes sans attaquer ton réseau, rejoue une capture :

```bash
python -m moniwifi.replay capture.pcap --siem-json data/siem/replay.jsonl
```

## Option 1 : Wazuh (gratuit, open source, très utilisé)

### Installer Wazuh avec Docker

Il faut environ 8 Go de RAM libres. Remplace `vX.Y.Z` par la dernière version publiée sur <https://github.com/wazuh/wazuh-docker/releases>.

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b vX.Y.Z
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Le tableau de bord est sur <https://localhost>. Les identifiants par défaut sont indiqués dans la documentation Wazuh de ta version : change-les tout de suite.

### Faire lire le fichier par l'agent Wazuh

Installe l'agent Wazuh sur la machine qui fait tourner WiFi Guardian (voir « Deploy new agent » dans le tableau de bord), puis ajoute dans `/var/ossec/etc/ossec.conf` de l'agent :

```xml
<localfile>
  <log_format>json</log_format>
  <location>/chemin/vers/VEAS_NETWORK/data/siem/alerts.jsonl</location>
</localfile>
```

Puis `sudo systemctl restart wazuh-agent`.

### Écrire des règles Wazuh

Wazuh ne crée une alerte que si une règle correspond. Sur le manager, ajoute dans `/var/ossec/etc/rules/local_rules.xml` :

```xml
<group name="wifi_guardian,">
  <!-- Tout événement WiFi Guardian -->
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="event.module">wifi_guardian</field>
    <description>WiFi Guardian: $(message)</description>
  </rule>

  <!-- Gravité moyenne -->
  <rule id="100501" level="7">
    <if_sid>100500</if_sid>
    <field name="log.level">^medium$</field>
    <description>WiFi Guardian (moyen): $(message)</description>
  </rule>

  <!-- Gravité haute ou critique : visible en priorité dans le tableau de bord -->
  <rule id="100502" level="12">
    <if_sid>100500</if_sid>
    <field name="log.level" type="pcre2">^(high|critical)$</field>
    <description>WiFi Guardian (grave): $(message)</description>
  </rule>

  <!-- Exemple de règle dédiée avec sa technique MITRE -->
  <rule id="100510" level="13">
    <if_sid>100500</if_sid>
    <field name="event.action">^arp_spoofing$</field>
    <description>WiFi Guardian: usurpation ARP de la passerelle ($(source.ip))</description>
    <mitre>
      <id>T1557.002</id>
    </mitre>
  </rule>
</group>
```

Teste tes règles avant de redémarrer : lance `/var/ossec/bin/wazuh-logtest` sur le manager et colle une ligne de `alerts.jsonl`. La sortie indique le décodeur utilisé et la règle déclenchée. Redémarre ensuite le manager (`docker compose restart wazuh.manager` en Docker). Les alertes apparaissent dans « Threat Hunting », et la vue MITRE ATT&CK de Wazuh les place sur la matrice.

Écrire, tester et ajuster ces règles, c'est exactement le travail d'un *detection engineer*.

## Option 2 : Elastic (Elasticsearch + Kibana) avec Filebeat

Dans `filebeat.yml` :

```yaml
filebeat.inputs:
  - type: filestream
    id: wifi-guardian
    paths:
      - /chemin/vers/VEAS_NETWORK/data/siem/alerts.jsonl
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
```

Comme les champs suivent déjà ECS, les vues « Security » de Kibana reconnaissent `source.ip`, `threat.technique.id`, etc.

## Option 3 : Splunk, Graylog, QRadar...

Utilise Syslog. Choisis `SIEM_SYSLOG_FORMAT=cef` pour les SIEM qui ont un analyseur CEF (ArcSight, QRadar, Splunk avec l'add-on CEF), sinon `json`. Préfère `SIEM_SYSLOG_PROTOCOL=tcp` hors d'un labo : l'UDP peut perdre des messages sans prévenir.

## Réglages

| Variable | Défaut | Rôle |
| --- | --- | --- |
| `SIEM_JSON_FILE` | vide | Chemin du fichier JSON Lines (vide = désactivé) |
| `SIEM_JSON_MAX_MB` / `SIEM_JSON_BACKUPS` | `50` / `5` | Rotation du fichier |
| `SIEM_SYSLOG_HOST` / `SIEM_SYSLOG_PORT` | vide / `514` | Destination Syslog (vide = désactivé) |
| `SIEM_SYSLOG_PROTOCOL` | `udp` | `udp` ou `tcp` (trame RFC 6587 à comptage d'octets) |
| `SIEM_SYSLOG_FORMAT` | `json` | `json` (ECS) ou `cef` |
| `SIEM_MIN_SEVERITY` | `low` | Gravité minimale envoyée |
| `SIEM_INCLUDE_INCIDENTS` | `true` | Envoyer aussi les incidents |
