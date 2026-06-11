# Ground Truth — The Case of the Stolen Szechuan Sauce (DFIRmadness Case 001)

This file is the scoring base for `docs/accuracy-report.md` (checklist item 11).
Every row is a published, scorable fact about the case. VERDICT's findings from the
full run are graded **found / partially found / missed** against these rows — see
the Scoring protocol at the bottom.

## Sources

| ID | Source | URL |
|----|--------|-----|
| S1 | Case page (evidence downloads, scenario, question list) | <https://dfirmadness.com/the-stolen-szechuan-sauce/> |
| S2 | Official answers post: "Answers to the Szechuan Case 001" | <https://dfirmadness.com/answers-to-szechuan-case-001/> |
| S2a | Official tutorial: Case 001 Memory Analysis (filename/PID/C2 confirmations) | <https://dfirmadness.com/case-001-memory-analysis/> |
| S2b | Official tutorials: PCAP Analysis · Autoruns Analysis · Triage Disk Analysis · The Timing of it All · Super Timeline Analysis | linked from S1 |
| S3 | The evidence itself (DC01/DESKTOP-SDN1RPT images, memory, pcap) — used only to *pin* fuzzy specifics (exact timestamps/PIDs), never to invent rows | `scripts/get-dataset.sh` |

**Source-verification status:** S1, S2, and S2a were fetched live on 2026-06-11 and
the rows below were pinned against them (exact timestamps, PID, filename spelling,
domain name, timezone all corrected/confirmed from the official posts). Remaining
pins that need the evidence itself (S3) or the S2b tutorials are marked inline:
per-host C2 port, exact domain FQDN, desktop-side artifact specifics. Re-verify any
remaining `partial-credit` row before item 11 scores against this file.

Confidence legend: **confirmed** = stable, widely published core fact of the case;
**partial-credit** = the core fact is established but a specific (exact timestamp,
PID, port, path) is fuzzy — score the core, pin the specific from S2/S3.

## Environment / baseline

| ID | Stage | Fact | Confidence | Source |
|----|-------|------|------------|--------|
| GT-01 | baseline | Victim environment is the Active Directory domain **`CITADEL`** with two in-scope hosts: **`CITADEL-DC01`** (domain controller; memory image `citadeldc01.mem`) and **`DESKTOP-SDN1RPT`** (workstation). Exact FQDN: pin from the SYSTEM hive / evtx (S3). | confirmed (FQDN: partial-credit) | S2, S2a |
| GT-02 | baseline | `DC01` runs **Windows Server 2012 R2 x64**, internal IP `10.42.85.10`. | confirmed | S2, S2a |
| GT-03 | baseline | `DESKTOP-SDN1RPT` runs Windows 10, internal IP `10.42.85.115`. | confirmed (exact build/edition: partial-credit) | S2 |
| GT-04 | baseline | The intrusion occurs on **2020-09-19 (UTC)**, anchored 02:19–02:45 UTC: first successful logon 02:21 → desktop persistence ~02:41; evidence acquired 2020-09-19. All timeline anchors below fall in this window. | confirmed | S2 |
| GT-05 | baseline | The organization is in **Colorado, US Mountain time — local offset UTC-6** at the incident (the answers post labels it "Mountain Standard Time (UTC-6)"; September is technically MDT). The answers post notes the VMs' clocks were incorrectly set to UTC-7 — UTC vs. local-time confusion is a deliberate trap and one of the case's official questions ("The Timing of it All"). | confirmed (the UTC-7 VM quirk: partial-credit) | S1, S2 |

## Initial access

| ID | Stage | Fact | Confidence | Source |
|----|-------|------|------------|--------|
| GT-06 | initial access | `DC01` exposed RDP (TCP 3389) directly to the internet; initial access was an **RDP brute-force attack** (ATT&CK T1110) followed by use of the valid `Administrator` account (T1078). | confirmed | S1, S2 |
| GT-07 | initial access | Brute-force / attacker source IP: **`194.61.24.102`**. | confirmed | S2 |
| GT-08 | initial access | `DC01` `Security.evtx` contains a high-volume burst of **Event ID 4625** failed logons from `194.61.24.102` immediately preceding the success — the brute-force signature. | confirmed | S2 |
| GT-09 | initial access | First successful attacker logon: **Event ID 4624, LogonType 10 (RemoteInteractive), account `Administrator` (CITADEL domain), source `194.61.24.102`, at 02:21 UTC on 2020-09-19**. Pin the exact second from `Security.evtx` (S3). | confirmed (exact second: partial-credit) | S2, S3 |

## Execution / malware

| ID | Stage | Fact | Confidence | Source |
|----|-------|------|------------|--------|
| GT-10 | execution | Malicious binary **`coreupdater.exe`** placed at **`C:\Windows\System32\coreupdater.exe`** on `DC01`. | confirmed | S2 |
| GT-11 | execution | `coreupdater.exe` is a **Metasploit / Meterpreter** payload (widely corroborated via VirusTotal and string/IAT analysis in S2). | confirmed | S2 |
| GT-12 | execution | The binary was downloaded via **Internet Explorer over HTTP at 02:24:06 UTC** during the attacker's interactive RDP session on `DC01` (browser/web history artifacts + pcap). Exact download URL/host: pin from S2b (PCAP Analysis). | confirmed (URL/host: partial-credit) | S2 |
| GT-13 | execution | Program-execution artifacts on the victims record `coreupdater.exe` (Amcache/ShimCache on `DC01`; prefetch is available on the Windows 10 desktop, where workstation policy enables it). | partial-credit (which artifact on which host) | S2 |
| GT-14 | execution | The `coreupdater.exe` process is present in the DC01 memory capture — **PID 3644** (pslist/pstree; malfind corroborates injection). | confirmed | S2a, S3 |

## Persistence

| ID | Stage | Fact | Confidence | Source |
|----|-------|------|------------|--------|
| GT-15 | persistence | A **Windows service named `coreupdater`** was installed on `DC01` at **02:27:49 UTC** — `System.evtx` **Event ID 7045**, ImagePath `C:\Windows\System32\coreupdater.exe` (ATT&CK **T1543.003**, Windows Service). The answers post characterizes persistence as "registry and as a Service". | confirmed | S2 |
| GT-16 | persistence | The service is set to auto-start: SYSTEM hive `ControlSet001\Services\coreupdater` with `Start` = 2 (Automatic). | confirmed (value detail: partial-credit) | S2 |
| GT-17 | persistence | The same `coreupdater.exe` malware + service persistence is also present on **`DESKTOP-SDN1RPT`**, installed **~02:41 UTC** — the attacker replicated the implant on the workstation. | confirmed | S2 |

## Command and control

| ID | Stage | Fact | Confidence | Source |
|----|-------|------|------------|--------|
| GT-18 | C2 | C2 server IP: **`203.78.103.109`** (geolocates to Thailand). | confirmed (geo: partial-credit) | S2 |
| GT-19 | C2 | Meterpreter C2 traffic from the victims to `203.78.103.109` is observed on TCP **443 and/or 4444** (pcap + memory network artifacts). Which port serves which host/session: pin from S2. | core confirmed; per-host port partial-credit | S2, S3 |
| GT-20 | C2 | Memory network scan (netscan/netstat) ties the established connection to `203.78.103.109` to the **`coreupdater.exe` process** — the disk↔memory correlation this case is built around. | confirmed | S2 |

## Lateral movement

| ID | Stage | Fact | Confidence | Source |
|----|-------|------|------------|--------|
| GT-21 | lateral movement | The attacker moved laterally **from `DC01` (10.42.85.10) to `DESKTOP-SDN1RPT` (10.42.85.115) via RDP at ~02:35 UTC** using the `Administrator` account — desktop `Security.evtx` logon events (4624, LogonType 10 and/or 3) with source `10.42.85.10`. | confirmed (event specifics: partial-credit) | S2 |
| GT-22 | lateral movement | Order of compromise: `DC01` first (internet-exposed entry point), `DESKTOP-SDN1RPT` second, within the same GT-04 window. | confirmed | S2 |

## Exfil / impact

| ID | Stage | Fact | Confidence | Source |
|----|-------|------|------------|--------|
| GT-23 | exfil-impact | The case's crown jewels — the **Szechuan sauce recipe file** — resided on `DC01`'s file share and was **accessed at 02:32:21 UTC**; the answers post states it was taken as part of **`secret.zip`** (staged ~02:31). Exact file path and exfil channel: pin from S2/S2b before scoring; if exfil stays unproven (encrypted C2), score this row on *access + staging*, not exfiltration. | confirmed (path/channel: partial-credit) | S1, S2 |
| GT-24 | exfil-impact | All attacker activity used the built-in `Administrator` account — no separate attacker account was created (absence of 4720 user-creation events for attacker accounts). | partial-credit | S2 |

24 rows. Core kill chain (GT-06…GT-22) is fully covered; the fuzzy rows are
deliberately marked rather than padded with invented precision.

## Scoring protocol (for item 11, `docs/accuracy-report.md`)

1. **Pin first, score second.** Before scoring, confirm S1/S2 live, replace every
   "pin from S2/S3" placeholder with the exact published value, and re-mark
   confidence. A row that cannot be defended from a cited source is struck (and the
   strike is recorded in the accuracy report — honesty over volume).
2. **Per-row grades** against VERDICT's final report (VERIFIED + UNCONFIRMED
   findings only; REFUTED/appendix items never earn credit):
   - **found** — a finding asserts the row's core fact with correct specifics
     (IPs, filenames, event IDs, technique exact; timestamps within ±5 minutes of
     the pinned value, or anywhere inside the stated window for window-style rows).
   - **partially found** — the core fact is asserted but a key specific is missing
     or wrong (e.g. "RDP brute force occurred" without the source IP), or the fact
     appears only with materially weaker scope than published.
   - **missed** — neither.
   For `partial-credit` rows, only the **core fact** is graded; the fuzzy specific
   cannot cause a miss (it can still upgrade partial→found when matched).
3. **Score** = (found + 0.5 × partially found) / total rows, reported as a
   percentage **with every miss named** (`prd.md > Judge Experience`: a credible
   85% with named misses beats a suspicious 100%).
4. **Extra findings** (reported by VERDICT but absent from this table) are counted
   and listed separately, each classified true-positive-outside-ground-truth /
   benign-fact / false-positive where determinable. Extras never add to the score.
5. The accuracy report quotes this file's row IDs (GT-01…GT-24) so judges can trace
   every grade to a published fact and its source.
