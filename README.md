# NightEagle (APT-Q-95) — Threat Actor Briefing

> **TLP:CLEAR** · Curated CTI reference · Last updated: 2026-06-12
> Sector focus: Quantum technology, semiconductors, AI/LLM, military-industrial
> Maintainer: _Eliza / elizacommit5_

A standing intelligence reference on **NightEagle**, the suspected APT
notable for being the only publicly named threat actor with **quantum technology listed
as a discrete target vertical**. This page also catalogues the broader set of APTs that
target the quantum sector under wider "high-tech IP theft" mandates, so the claim above
is presented with the caveat it deserves.

---

## 1. At a glance

| Field | Detail |
|---|---|
| **Primary name** | NightEagle (夜鹰) |
| **Aliases** | APT-Q-95 (QiAnXin internal designation), APT-C-78 |
| **First public disclosure** | 4 July 2025 (CYDES 2025, Malaysia, 1–3 July 2025) |
| **Disclosing vendor** | QiAnXin Technology — RedDrip Team & PanGu Lab |
| **Assessed origin** | North America (likely US West Coast / Pacific time zone) |
| **Assessed sponsorship** | State-sponsored — *moderate confidence* |
| **Active since** | At least 2023 (≈2 years undetected before disclosure) |
| **Primary motivation** | Strategic espionage / intelligence collection |
| **Primary victim geography** | People's Republic of China |
| **Signature capability** | Suspected Microsoft Exchange zero-day exploit chain |
| **Status** | No confirmed new public reporting since 2025 disclosure; treat as active |

---

## 2. Attribution

Attribution here is **inverted from the usual pattern** — a Chinese vendor naming a
*Western* state actor, where most public APT reporting names Chinese, Russian, Iranian or
North Korean groups. Worth keeping that framing in mind when weighing the assessment.

The North America attribution rests primarily on **operational tempo analysis**:

- Activity occurred exclusively between **21:00 and 06:00 Beijing time**, with no overtime
  and no out-of-hours data theft.
- That window maps cleanly to a **09:00–18:00 US Pacific workday**, leading RedDrip to place
  the operators on the **US West Coast** — without formally calling them American or Canadian.
- QiAnXin characterised the actor as fast, accurate, and disciplined, and assessed
  state-level funding from the volume of VPS/domain infrastructure procured.

**Confidence note:** Time-zone inference is circumstantial and can be spoofed. The disclosing
vendor is a Chinese commercial firm operating in a geopolitically charged space; the
underlying technical findings (zero-day Exchange abuse, fileless implants, Chisel variant) are
well-evidenced, but the *nationality* conclusion should be held at moderate confidence.
**Microsoft reviewed the report and stated it had not identified any new actionable
vulnerabilities** as of its response, with its investigation ongoing.

---

## 3. Timeline

| Date | Event |
|---|---|
| **2023** | Earliest assessed NightEagle activity. Begins long-dwell Exchange exploitation against Chinese strategic-tech targets. |
| **2023 – 2025** | Sustained, low-profile email exfiltration; ~1 year of continuous mailbox theft observed at one victim. Per-victim dedicated infrastructure; rapid IP rotation. Targeting shifts toward AI/LLM firms as China's AI sector expands. |
| **(Trigger)** | QiAnXin's Tianyan NDR flags an anomalous DNS request to `synologyupdates.com` on a customer endpoint — the thread that unraveled the campaign. |
| **1–3 Jul 2025** | Findings presented at **CYDES 2025** (Malaysia's National Cyber Defence & Security Exhibition and Conference). |
| **4 Jul 2025** | RedDrip publishes technical disclosure to GitHub (`RedDrip7/NightEagle_Disclose`), including a detection tool (`apt-q-95_checktool.exe`). |
| **Jul 2025** | Broad secondary coverage (The Hacker News, Dark Reading, SC Media, etc.). Microsoft responds: no new vulnerabilities identified to date. |
| **2026** | No confirmed new public attribution or campaign reporting. Quantum/AI/semiconductor collection priorities remain valid; treat the actor as active and unattributed at nation-state level. |

---

## 4. Targeting

NightEagle's victimology is a tight cluster of **strategic national-value technology sectors
in China**:

- **Quantum technology** ← the distinguishing vertical
- Semiconductors / chip manufacturing
- Artificial intelligence, including large language model (LLM) developers
- Military-industrial / defense
- Broader "high-tech" entities

Beyond email, observed collection targets included **source-code repositories** and
**backup storage systems** — consistent with IP theft and deep technical intelligence
collection rather than short-term access.

Targeting tracked **geopolitical developments** — e.g. intensified focus on LLM/AI firms as
China's AI market grew — implying a tasked, requirements-driven operation rather than
opportunistic compromise.

---

## 5. Tradecraft (kill chain)

NightEagle blends a suspected zero-day, fileless in-memory implants, and a customized
open-source tunneler. The chain as reconstructed by QiAnXin and corroborating analysts:

1. **Initial access — Exchange zero-day → machineKey theft.**
   The actor obtains the Exchange server's **`machineKey`** via an undisclosed mechanism
   (assessed zero-day). With the key, they forge serialized payloads that the server
   deserializes, yielding **remote code execution**. The full exploit chain was not
   recovered; only the post-key-theft stages were observed.

2. **Implant — fileless .NET loader in IIS.**
   A custom **.NET loader is embedded into the IIS service** on the Exchange server. It is
   **memory-resident ("memory horse")**, named in the pattern **`App_Web_cn*.dll`**
   (e.g. `App_Web_cn274.aspx.dll`), and **never lands on disk** — it executes only when its
   corresponding virtual URL endpoint is requested, defeating file-based AV.

3. **Tunneling — customized Go Chisel.**
   A modified build of the open-source **Chisel** tunneler, disguised as
   **`SynologyUpdate.exe`**, is deployed with hardcoded credentials/parameters. It opens a
   **SOCKS connection over port 443** to C2 and is **re-triggered every 4 hours via a
   scheduled task** for persistence.

4. **Proxy / lateral movement — ReGeorg.**
   **ReGeorg** web-shell SOCKS proxies are used to pivot through compromised servers without
   direct external exposure.

5. **Collection & exfiltration.**
   Remote, on-demand reading of **any mailbox** on the compromised Exchange server, plus
   theft from source-code repos and backups. Email is exfiltrated in a sustained, low-noise
   fashion (observed ~1 year at one victim).

6. **Anti-attribution / OPSEC.**
   Unique domain per victim; **disposable infrastructure with rapid IP flipping** (often
   within hours); domains masquerade as legitimate update/CDN services; **log clearing and
   indicator removal**; C2 domains resolve to dead-end IPs (`127.0.0.1`, `0.0.0.0`,
   `114.114.114.114`) when dormant — live only during the operator's active window.

---

## 6. MITRE ATT&CK mapping

> Derived from QiAnXin's disclosure and third-party technical analysis (e.g. Inception
> Security). Treat as an analyst-assembled mapping, not an official ATT&CK group entry.

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Suspected Exchange zero-day |
| Credential Access | Unsecured Credentials | T1552 | `machineKey` theft |
| Execution | Command and Scripting / Deserialization-driven RCE | T1059 | Forged serialized payloads |
| Persistence | Scheduled Task/Job | T1053.005 | Chisel re-launch every 4h |
| Persistence | Server Software Component: Web Shell | T1505.003 | ReGeorg; IIS module |
| Defense Evasion | Reflective / In-Memory Code Loading | T1620 | Fileless `App_Web_cn*.dll` |
| Defense Evasion | Masquerading | T1036 | `SynologyUpdate.exe`; fake update domains |
| Defense Evasion | Indicator Removal on Host | T1070 | Log clearing, infra rotation |
| Command & Control | Protocol Tunneling | T1572 | Customized Chisel, SOCKS/443 |
| Command & Control | Proxy | T1090 | ReGeorg |
| Collection | Email Collection | T1114 | Mailbox exfiltration |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Via Chisel tunnel |

---

## 7. Indicators of Compromise (IOCs)

> **Source caveat:** IOCs below are from the 2025 RedDrip disclosure and secondary reporting.
> Infrastructure indicators (domains/IPs) are **disposable and likely stale** — NightEagle
> rotates per-victim. Prioritise the **behavioral** indicators for hunting. Pull the
> authoritative, complete set (hashes, full domain list) from the RedDrip GitHub repo.

### Domains (per-victim, masquerading as update/CDN/mail services)
```
synologyupdates.com      # fake Synology NAS update service (initial detection thread)
comfyupdate.org          # AI-tooling themed lure
coremailtech.com
fastapi-cdn.com
```

### Dormant-state resolution (C2 "parked" indicators)
```
127.0.0.1
0.0.0.0
114.114.114.114
```

### Host / file artifacts
```
SynologyUpdate.exe                 # customized Go Chisel tunneler
App_Web_cn*.dll                    # fileless in-memory .NET loader (e.g. App_Web_cn274.aspx.dll)
Scheduled task re-launching the Chisel binary every 4 hours
SOCKS-over-443 outbound from an Exchange/IIS host to a single dedicated domain
```

### Infrastructure TTPs (for pivoting)
```
Registrar:       Tucows
Hosting:         DigitalOcean, Akamai, The Constant Company (Vultr)
Pattern:         one domain per victim; rapid IP rotation (sub-day); live only 21:00–06:00 CST
```

### Behavioral hunt ideas
- Anomalous DNS from internal hosts to lookalike "update/CDN" domains not in vendor allowlists.
- IIS worker (`w3wp.exe`) spawning unexpected child processes or loading unsigned/odd
  `App_Web_*.dll` modules that have no on-disk source.
- Scheduled tasks on Exchange/IIS hosts re-launching a binary on a strict N-hour cadence.
- Outbound SOCKS/443 from a mail server to a single low-reputation domain.
- Off-hours-only beaconing aligned to a foreign business-day window.

---

## 8. Detection & mitigation

- **Patch & harden Exchange.** Keep Exchange fully current; the assessed initial vector is an
  Exchange exploit chain. Minimise internet exposure of OWA/ECP; front with strong auth.
- **Rotate `machineKey`** and treat it as a high-value secret; monitor for deserialization
  abuse. Investigate any unexpected `machineKey` access.
- **Hunt fileless IIS modules.** Inventory loaded IIS/.NET assemblies; flag in-memory
  `App_Web_cn*.dll` with no corresponding source, and unusual virtual-endpoint hits.
- **Egress control on mail servers.** Mail/IIS hosts should not be opening arbitrary
  SOCKS/443 tunnels; alert on Chisel-like traffic patterns.
- **Run the RedDrip checker.** QiAnXin published `apt-q-95_checktool(_en).exe` in their repo
  (validate the checksum; run in a controlled environment per your own policy).
- **Behavioral > signature.** Per-victim infra and fileless implants defeat IOC-only
  detection — weight scheduled-task cadence, off-hours beaconing, and IIS anomaly hunting.

---

## 9. References (primary first)

- **RedDrip / QiAnXin — original disclosure & detection tool (GitHub):**
  https://github.com/RedDrip7/NightEagle_Disclose
- The Hacker News — *NightEagle APT Exploits Microsoft Exchange Flaw…* (10 Jul 2025):
  https://thehackernews.com/2025/07/nighteagle-apt-exploits-microsoft.html
- Dark Reading — *North American APT Uses Exchange Zero-Day to Attack China*:
  https://www.darkreading.com/cyberattacks-data-breaches/north-american-apt-exchange-zero-day-attacks-china
- CyberSecurityNews — *NightEagle APT Attacking Industrial Systems…* (IOCs):
  https://cybersecuritynews.com/nighteagle-apt-exploiting-0-days/
- GBHackers — *NightEagle APT Unleashes Custom Malware…*:
  https://gbhackers.com/nighteagle-apt-unleashes-custom-malware/
- Inception Security — *Deep Dive into NightEagle APT* (ATT&CK mapping):
  https://www.inceptionsecurity.com/post/deep-dive-into-nighteagle-apt-technical-breakdown-of-the-zero-day-microsoft-exchange-exploitation
- CSO Online — *NightEagle hackers exploit Microsoft Exchange flaw…*:
  https://www.csoonline.com/article/4018080/
- Risky.biz — *Chinese researchers claim to find new North American APT*:
  https://news.risky.biz/risky-bulletin-chinese-researchers-claim-to-find-new-north-american-apt/

---
---

# Quantum-Sector Targeting — The Wider APT Landscape

**Is NightEagle the only APT targeting quantum?**
**Short answer:** It is the only *named* APT with **quantum listed as a discrete target
vertical** in public reporting. It is **not** the only actor whose collection touches the
quantum industry. Quantum R&D is a documented strategic-collection priority — most notably
for the PRC ecosystem — but other groups fold it into broad "advanced-technology IP theft"
without naming it separately. Publish the claim with that nuance.

### The national-campaign context
- **FBI** assesses the PRC runs a *well-resourced, systematic* campaign to acquire strategic
  technologies named in its Five-Year Plan and "Made in China 2025" — **quantum computing is
  explicitly on that list**, alongside semiconductors, AI, and aerospace. Methods span cyber
  intrusion, insider/illicit transfer, and front companies. The DOJ's **Disruptive Technology
  Strike Force (2023)** was created in part to protect quantum and similar tech.
- **Australia's** security services have publicly warned its nascent quantum industry is
  already a foreign-espionage target.
- **Iran / Russia procurement angle:** documented efforts to acquire *quantum-capable
  hardware* (e.g. cryogenic/cooling equipment with dual-use quantum-lab applications) via
  procurement networks and export-control evasion — a hardware-acquisition threat distinct
  from cyber intrusion.

> **No specific quantum *company* has been publicly named as breached** by the groups below
> with "quantum" called out — which is exactly why NightEagle stands out. For the others,
> quantum exposure is inferred from their stated high-tech / advanced-tech IP-theft mandates.

---

## Adjacent threat actors with quantum-relevant collection

### APT41 (Double Dragon / Winnti / Wicked Panda / Barium / Bronze Atlas)
- **Nexus:** China. **Dual mandate** — state espionage *and* financially motivated crime.
- **Relevance to quantum:** Prolific IP theft across high-tech, healthcare, telecom; pioneer
  of **supply-chain compromise** (trojanized software updates) — a plausible delivery route
  into quantum vendors and their suppliers.
- **Notable TTPs:** spear-phishing, zero-day exploitation (e.g. Log4Shell, USAHerds),
  code-signing-cert theft, custom malware ecosystem, covert C2 (incl. Google Calendar).
- **Note:** Multiple members indicted by the US (2019–2020); on the FBI most-wanted list.

### APT31 (Violet Typhoon / Judgement Panda / Zirconium / RedBravo)
- **Nexus:** China; active since ≥2010.
- **Relevance to quantum:** Collection for PRC political/economic/military advantage across
  high-tech, aerospace & defense, government. In **2024–2025 targeted Russia's IT sector**
  (contractors/integrators for government) — notable China-on-Russia activity, and a reminder
  that "allied" geography is not off-limits.
- **Notable TTPs:** application-layer exploitation (historically Java/Flash), cloud-service
  abuse for stealthy C2.

### APT27 (Emissary Panda / LuckyMouse)
- **Nexus:** China. Long history of **IP theft** focused on projects/research data.
- **Relevance to quantum:** Targets high-tech, government, defense, aerospace, energy globally;
  exploits remote-access/public-facing vulns. Advanced-tech research falls squarely in scope.

### APT10 (Stone Panda / MenuPass)
- **Nexus:** China; active since ≈2009.
- **Relevance to quantum:** Known for **MSP / supply-chain** intrusions to reach many
  downstream IP-rich victims at once — a structural risk for quantum firms reliant on
  third-party providers.

### Jewelbug (REF7707 / CL-STA-0049 / Earth Alux)
- **Nexus:** China. Espionage + long-dwell stealth.
- **Relevance to quantum:** Recent activity against a **Russian IT service provider**
  (code repos / build systems → supply-chain potential) and targets across South America,
  South Asia, Taiwan. Demonstrates current China-nexus appetite for tech-supply-chain access.

---

## Analyst bottom line

- **Publish NightEagle as: "the only named APT with quantum technology as an explicitly
  enumerated target vertical"** — accurate and defensible.
- **Do not publish: "the only APT targeting quantum"** — the PRC ecosystem (APT41/31/27/10,
  Jewelbug) targets quantum R&D under broad high-tech IP-theft mandates, and quantum is a
  named *national* collection priority per the FBI. NightEagle is distinctive for *specificity
  and inverted attribution*, not for being alone in the space.
- **Collection gap:** No public reporting names a breached quantum company by these other
  groups. That is an intelligence gap, not evidence of absence — worth a dedicated collection
  effort if quantum is in your remit.

### Quantum-landscape references
- FBI — *Protecting Quantum Science and Technology*:
  https://www.fbi.gov/news/stories/protecting-quantum-science-and-technology
- PostQuantum — *Quantum Tech and Espionage*:
  https://postquantum.com/post-quantum/espionage-quantum/
- Symantec/Security.com — *Jewelbug: Chinese APT Widens Reach to Russia*:
  https://www.security.com/threat-intelligence/jewelbug-apt-russia
- The Hacker News — *China-Linked APT31… targets Russian IT*:
  https://thehackernews.com/2025/11/china-linked-apt31-launches-stealthy.html
- Google Cloud (Mandiant) — *APT groups and threat actors*:
  https://cloud.google.com/security/resources/insights/apt-groups

---

*Compiled from open sources for defensive CTI use. Verify IOCs against the primary RedDrip
disclosure before operationalising. Attribution to North America is moderate-confidence and
rests significantly on time-zone analysis.*
