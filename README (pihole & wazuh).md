# Home Network DNS Monitoring: Pi-hole + Wazuh SIEM

A home lab that blocks unwanted DNS lookups with **Pi-hole**, forwards the Pi-hole log to a **Wazuh** SIEM, and raises a custom alert every time a domain is blocked. Everything runs in VirtualBox on a single PC.

**What this shows:** DNS filtering, Linux server setup, log forwarding with an agent, writing a custom Wazuh decoder and rule, and troubleshooting a multi-service pipeline end to end.

---

## Architecture

```
Laptop (DNS = Pi-hole)
        │  DNS query
        ▼
Pi-hole VM  ──blocks ad/tracker domains──►  /var/log/pihole/pihole.log
(Debian 13)                                        │
        │  Wazuh agent reads the log               │
        ▼                                          ▼
Wazuh Manager VM  ──►  custom decoder + rule 100101  ──►  Filebeat  ──►  Wazuh Indexer  ──►  Dashboard
(Ubuntu Server)
```

| VM | OS | Role |
|---|---|---|
| `pihole` | Debian 13 (netinst, no desktop, SSH server) | DNS filtering, Wazuh agent |
| `wazuh` | Ubuntu Server, 4 GB RAM, bridged networking | Wazuh manager, indexer, Filebeat, dashboard |

Wazuh version 4.14.8. Both VMs use bridged networking so the laptop can reach them directly.

---

## Setup summary

### 1. Pi-hole
1. Created a Debian 13 netinst VM in VirtualBox (no desktop environment, SSH server enabled).
2. Ran the Pi-hole installer on it.
3. Pointed the laptop's DNS at the Pi-hole VM (Windows: Settings → Network & internet → Wi-Fi → DNS server assignment → Manual → Preferred DNS = Pi-hole IP, Alternative DNS left empty so lookups can't bypass Pi-hole).
4. Confirmed blocking by visiting a blocked domain (`doubleclick.net`) and checking the Pi-hole **Query Log**.

### 2. Wazuh
1. Created a second VM (`wazuh`) and installed Wazuh (manager, indexer, dashboard, Filebeat) using the official installation guide.
2. Installed the Wazuh agent on the `pihole` VM and enrolled it with the manager.
3. Added a `<localfile>` block to the agent's `/var/ossec/etc/ossec.conf` so it reads the Pi-hole log:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/pihole/pihole.log</location>
</localfile>
```

### 3. Custom decoder and rule

**Decoder** (`/var/ossec/etc/decoders/pihole_decoders.xml`)

```xml
<decoder name="pihole">
  <prematch type="pcre2">query\[\w+\] \S+ from |gravity blocked \S+ is </prematch>
</decoder>

<decoder name="pihole-query">
  <parent>pihole</parent>
  <regex type="pcre2">query\[(\w+)\] (\S+) from (\S+)</regex>
  <order>query_type, domain, srcip</order>
</decoder>
```

**Rule** (`/var/ossec/etc/rules/pihole_rules.xml`)

```xml
<group name="pihole,">
  <rule id="100100" level="0">
    <decoded_as>pihole</decoded_as>
    <description>Pi-hole DNS event</description>
  </rule>

  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <match>gravity blocked</match>
    <description>Pi-hole blocked a domain lookup</description>
  </rule>
</group>
```

Rule `100100` is level 0 on purpose, so normal DNS lookups don't flood the alerts. Only blocked domains raise rule `100101` (level 5).

---

## Testing

### Test the decoder and rule without waiting for real traffic

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a sample log line:

```
Oct 21 00:58:30 dnsmasq[752]: gravity blocked doubleclick.net is 0.0.0.0
```

Expected: Phase 3 shows rule `100101`, level 5, "Alert to be generated".

### Test end to end

1. On the laptop, open `http://doubleclick.net`. It fails to load (blocked).
2. Pi-hole Query Log shows the lookup as blocked.
3. In the Wazuh dashboard, open **Explore → Discover**, index pattern `wazuh-alerts-*`, search `rule.id:100101`.

**Result:** 103 alerts, each with the agent name (`pihole`), the log file location, and the full log line showing the blocked domain.

> Screenshots: add them to a `screenshots/` folder and link them here.
>
> `![Pi-hole query log](screenshots/pihole-query-log.png)`
> `![Wazuh Discover alerts](screenshots/wazuh-discover.png)`

---

## Troubleshooting log

This is the part I learned the most from. The alerts did not show up on the first try, and the cause was several separate problems stacked together.

| Symptom | Cause | Fix |
|---|---|---|
| Wazuh indexer failed to start after restoring a VirtualBox snapshot | The `/var/log/wazuh-indexer` directory was missing | `sudo systemd-tmpfiles --create`, then recreated the directory with correct ownership, then started the service |
| Manager and dashboard inactive | They depended on the indexer being up | Started in order: indexer, manager, dashboard |
| Decoder test in the dashboard said "No decoder matched" | The dashboard test session was stale | Used `wazuh-logtest` in the terminal, where the decoder matched |
| Rules file rejected with "XML syntax error" | Saved from the **Decoders** page instead of the **Rules** page | Re-saved in the Rules section |
| Agent not sending logs | Agent was still pointed at the old manager IP (`192.168.0.207`) | Updated the server address in the agent's `ossec.conf` and restarted the agent |
| Alerts in `alerts.log` but nothing in the dashboard | Filebeat was stopped and disabled | `sudo systemctl enable filebeat` and `sudo systemctl start filebeat` |
| Dashboard still empty for "Last 24 hours" | The laptop clock was wrong (synced from a stale private time server), so alert timestamps looked like they were in the future | Reset the Windows time server to `time.windows.com` |

### Useful checks

```bash
# Services (wazuh VM)
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard filebeat --no-pager

# Config test, silent means no errors (wazuh VM)
sudo /var/ossec/bin/wazuh-analysisd -t

# Agents connected (wazuh VM)
sudo /var/ossec/bin/agent_control -l

# Alerts being generated by the rule (wazuh VM)
sudo grep -i "rule: 10010[1]" /var/ossec/logs/alerts/alerts.log | tail -3

# Is the agent reading the Pi-hole log? (pihole VM)
sudo grep -i "pihole.log" /var/ossec/logs/ossec.log | tail -5

# Is Filebeat shipping to the indexer? (wazuh VM)
sudo tail -20 /var/log/filebeat/filebeat
sudo filebeat test output
```

---

## Lessons learned

- Take a VirtualBox snapshot every time something works, and before every risky change.
- Check each stage of a pipeline in order (source, agent, manager, Filebeat, indexer, dashboard) instead of guessing.
- Use the terminal test tool (`wazuh-logtest`) to separate "my rule is wrong" from "the data never arrives".
- DHCP addresses change. A VM that moves to a new IP silently breaks agents and DNS settings, so reserve fixed addresses.
- A wrong system clock can make a working pipeline look broken.

## Known limitations and next steps

- The blocked-domain field is not extracted into its own field, so the domain only appears in the `full_log` of each alert. Improving the decoder is the next job.
- Add a frequency rule to flag a device that triggers many blocks in a short time.
- Reserve fixed IPs for both VMs in the router.
- Build a dashboard of top blocked domains and top clients.
