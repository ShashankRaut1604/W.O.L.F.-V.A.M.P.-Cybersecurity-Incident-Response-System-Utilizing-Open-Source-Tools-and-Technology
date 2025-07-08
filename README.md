**W\.O.L.F. – Watchdog Operations for Lethal Frameworks |**
**V.A.M.P. – Vulnerability Assessment and Mitigation Protocol**

A fully integrated, open-source Security Operations Center (SOC) framework developed using industry-standard tools for real-time detection, alerting, and response to cybersecurity threats. The system provides centralized logging, behavioral monitoring, malware detection, and dynamic dashboards for visual analysis.

---

## ⚙️ Architecture Overview

```
Ubuntu (W.O.L.F. V.A.M.P.)
├── Zeek
├── Suricata
├── ClamAV
├── Auditd
├── Filebeat, Metricbeat
├── OSQuery
├── Elasticsearch, Logstash, Kibana

Windows 11 & Windows Server
├── Sysmon
├── Winlogbeat
├── OSSEC/Wazuh Agent

Parrot OS
├── Attack Simulation Tools (Nmap, Gobuster, Hydra, Nikto, etc.)
```

---

## ✅ Installed Tools and Usage

### 🔎 Zeek

* Network traffic analysis and protocol inspection.
* Logs stored at `/opt/zeek/logs/current/`.
* Automatically captures HTTP, DNS, SSL, connection, and file activity.

### 🚦 Suricata

* IDS/IPS engine performing real-time traffic inspection.
* Rule-based alert generation and packet logging.

### 🐧 Auditd

* Tracks system calls and file accesses on Linux.
* Key events captured for system integrity and user behavior.

### 📜 OSQuery

* Used to query system state like SQL.
* Provides live monitoring of processes, users, and system events.

### 📈 Metricbeat & Filebeat

* Metricbeat monitors system and service health.
* Filebeat forwards Zeek, Suricata, audit logs to Elasticsearch.

### 🦠 ClamAV

* Scans files and directories for malware signatures.
* Configured to work with scheduled scans and update jobs.

### 💾 Elasticsearch

* Central log storage engine receiving logs from Filebeat and Winlogbeat.
* Supports structured search and correlation.

### 📊 Kibana

* Visualizes logs and alerts in real-time dashboards.
* Dashboards created for Zeek, Suricata, Auditd, Wazuh, and Sysmon logs.

### 🧠 Wazuh Manager + Dashboard

* Manages agents on endpoints and performs log analysis and rule matching.
* Integrated with Kibana for centralized security monitoring.

### 🖥️ Sysmon (Windows)

* Monitors Windows system activity (process creation, file changes, etc.).
* Logs shipped via Winlogbeat to Elasticsearch.

### 📤 Winlogbeat (Windows)

* Ships Windows event logs and Sysmon logs to ELK Stack.

---

## ⚔️ Attack Simulation (Red Team Lab)

Attacks were simulated from **Parrot OS** against Windows and Ubuntu devices to test detection capabilities:

* **Nmap** – Port scan detection via Zeek and Suricata.
* **Gobuster/Nikto** – Web directory fuzzing detected in Zeek logs.
* **Hydra** – Brute force login attempts flagged by Suricata.
* **Manual Suspicious File Uploads** – Detected by ClamAV and logged by Auditd.
* **Privilege escalation events** – Logged by OSQuery and Auditd.

These events were all successfully **detected, logged, and visualized** in Kibana.

---

## 🧩 Folder Structure

```
WOLF-VAMP/
├── config/
│   ├── zeek/
│   ├── suricata/
│   ├── sysmonconfig.xml
│   └── filebeat.yml
├── docs/
│   ├── SOC_Architecture.png
│   ├── User_Manual.pdf
│   └── Attack_Simulation.md
├── logs/
│   ├── test.log
├── scripts/
│   ├── zeek-start.sh
│   ├── install-sysmon.ps1
├── README.md
```

## 💡 Features Achieved

* [x] Multi-device endpoint detection using Sysmon, OSSEC, Wazuh Agents.
* [x] Real-time log aggregation from Linux and Windows devices.
* [x] Full packet inspection via Suricata and protocol analysis via Zeek.
* [x] Visualization of security events in Kibana dashboards.
* [x] Malware and anomaly detection using ClamAV and Auditd.
* [x] Red team simulations with successful detection and logging.
* [x] Integrated open-source stack deployable on low-budget infrastructure.

