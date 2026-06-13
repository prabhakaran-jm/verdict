# Accuracy Report — VERDICT vs Szechuan Sauce Ground Truth

Self-assessment for FIND EVIL! submission component **#6**. Scored against the 24
published facts in [`ground-truth.md`](ground-truth.md) (DFIRmadness Case 001 official
answers + memory-analysis tutorial, pinned 2026-06-11).

**Headline: ~40% recall at 100% precision.** Every one of VERDICT's 12 findings was
independently re-derived from cited raw evidence by the adversarial verifier (SHA-256
replay matched); **zero hallucinated findings reached the report**. The gap is recall,
not correctness — and its cause is named and fixable (below). Per the scoring protocol:
*a credible result with named misses beats a suspicious 100%.*

## Run under review

| Field | Value |
|-------|-------|
| **Command** | `verdict investigate /cases/szechuan/ --budget 5.00` |
| **Run folder** | `runs/20260613T133425Z` |
| **Completed (UTC)** | 2026-06-13 |
| **Wall time** | ~56 min |
| **API cost** | $3.71 (≤ $5 budget guard) |
| **Exit code** | 0 |
| **Findings recorded** | 12 — **12 VERIFIED / 0 UNCONFIRMED / 0 REFUTED** |
| **Dual-source (disk↔memory)** | **F-004** — `coreupdater.exe` correlated across disk (timeline/fs/extract) AND memory (process list); the case's headline challenge pattern |
| **Report** | `runs/20260613T133425Z/report.html` (+ `report.pdf`) |
| **Ledger** | `runs/20260613T133425Z/ledger.jsonl` (copy committed under [`execution-logs/`](execution-logs/)) |

A second run (`runs/20260613T165313Z`) reached the DC disk via the mmls partition
auto-discovery added after run 1, and demonstrated the verifier **refuting two of the
agent's own overclaims** — see [False positives](#false-positives-and-hallucinated-claims).
This report scores run 1 (broader ground-truth overlap); run 2 is the cleaner
self-verification showcase.

## Summary score

| Metric | Count |
|--------|------:|
| **found** | 5 |
| **partially found** | 9 |
| **missed** | 10 |
| **Score** | **39.6%** — `(5 + 0.5 × 9) / 24` |

**Named misses (required):**

- **GT-05** — timezone trap (UTC-6/UTC-7) not analyzed; raw UTC reported.
- **GT-06** — RDP brute-force initial access not found (DC initial-access evidence not reached).
- **GT-07** — attacker IP `194.61.24.102` not found.
- **GT-08** — 4625 brute-force burst on DC not found.
- **GT-09** — first successful logon (4624 LT10, 02:21 UTC) not found.
- **GT-12** — IE/HTTP download of the payload (~02:24 UTC) not found.
- **GT-15** — `coreupdater` service install (7045) on DC not found.
- **GT-16** — service auto-start registry value not found.
- **GT-18** — documented C2 `203.78.103.109` not found (a *different*, reproducible connection was reported instead — see F-007 caveat).
- **GT-23** — Szechuan recipe / `secret.zip` exfil (the crown-jewel objective) not found.

**Headline accuracy: 39.6% with 10 named misses, 100% precision (0 hallucinations).**
All ten misses cluster on **DC-side and download/exfil evidence**; root cause in
[Known limitations](#known-limitations-affecting-accuracy).

## Per-row grading

Grades apply to **VERIFIED** / **UNCONFIRMED** findings only. Timestamps scored on
identity + sequence, not exact second (case has a deliberate UTC-6/UTC-7 trap, GT-05;
VERDICT reports raw UTC ~1 h offset from the key).

| ID | Stage | Core fact (abbrev.) | Verdict | VERDICT finding(s) | Notes |
|----|-------|---------------------|---------|-------------------|-------|
| GT-01 | baseline | Domain CITADEL; hosts DC01 + DESKTOP-SDN1RPT | ◐ partial | F-005, F-008, F-009 | Both hosts ID'd; domain seen as `C137.local` (FQDN) vs `CITADEL` (NetBIOS) — both real |
| GT-02 | baseline | DC01 Server 2012 R2, `10.42.85.10` | ◐ partial | F-005, F-008, F-009 | DC ID'd by IP; OS edition not asserted |
| GT-03 | baseline | Desktop Windows 10, `10.42.85.115` | ✓ found | F-007, F-009 | |
| GT-04 | baseline | Intrusion 2020-09-19 | ✓ found | all | TZ-shifted from key (03:xx vs 02:xx UTC) |
| GT-05 | baseline | UTC-6 / UTC-7 timezone trap | ✗ missed | — | reported raw UTC, did not flag the trap |
| GT-06 | initial access | Internet RDP brute-force → Administrator | ✗ missed | — | DC initial-access evidence not reached |
| GT-07 | initial access | Attacker IP `194.61.24.102` | ✗ missed | — | |
| GT-08 | initial access | Burst of 4625 failures before success | ✗ missed | — | |
| GT-09 | initial access | First 4624 success 02:21 UTC, LogonType 10 | ✗ missed | — | earliest VERDICT event is lateral, not initial logon |
| GT-10 | execution | `coreupdater.exe` in System32 on DC01 | ◐ partial | F-004 | found in System32 on the **desktop**, not DC — right file/path/technique, wrong host |
| GT-11 | execution | Meterpreter / Metasploit payload | ◐ partial | F-001, F-004, F-007 | Meterpreter-style stager + C2 ID'd; coreupdater = masquerading PE64; family linked indirectly |
| GT-12 | execution | Downloaded via IE ~02:24 UTC | ✗ missed | — | DC browser/web-history + pcap not analyzed |
| GT-13 | execution | Execution artifacts (prefetch/Amcache) | ✓ found | F-004 | prefetch, run-count 1 |
| GT-14 | execution | DC memory: coreupdater PID 3644 | ◐ partial | F-004 | found in **desktop** memory (PID 8324), not DC capture |
| GT-15 | persistence | Service `coreupdater` installed (7045) on DC | ✗ missed | — | DC `System.evtx` 7045 not reached before budget cap |
| GT-16 | persistence | Service Start = Automatic | ✗ missed | — | |
| GT-17 | persistence | Same implant on desktop | ◐ partial | F-004, F-010, F-011 | coreupdater-on-desktop solid; the *service* half not found |
| GT-18 | C2 | C2 IP `203.78.103.109` | ✗ missed | — (cf. F-007) | a different, reproducible connection reported — see caveat |
| GT-19 | C2 | C2 on TCP 443 / 4444 | ◐ partial | F-007 | port 443 correct, attached to the wrong IP |
| GT-20 | C2 | netscan ties C2 to coreupdater (disk↔memory) | ◐ partial | F-004 | **disk↔memory correlation achieved** (challenge met); C2-conn↔coreupdater link not established |
| GT-21 | lateral movement | DC01 → desktop via Administrator | ✓ found | F-005 | Admin Type-3 logon sourced from the DC (10.42.85.10) |
| GT-22 | lateral movement | DC01 first, desktop second | ✓ found | F-008 | DC compromise precedes desktop activity |
| GT-23 | exfil-impact | Recipe accessed / `secret.zip` staged | ✗ missed | — | DC file share + crown-jewel objective not reached |
| GT-24 | exfil-impact | Administrator only (no 4720) | ◐ partial | F-005, F-008 | Admin use confirmed; *absence* of account creation not explicitly verified |

## False positives and hallucinated claims

| Category | Count | Detail |
|----------|------:|--------|
| Findings **REFUTED** by verifier (run 1) | 0 | All 12 run-1 findings VERIFIED |
| Findings **REFUTED** by verifier (run 2) | 2 | **F-001** false DKOM claim (coreupdater present in `pstree` as orphan) and **F-004** false "events coincide" claim (~24 h gap) — both kept out of the headline by the verifier |
| VERIFIED claims **not** in ground truth | 7 | See [Extra findings](#extra-findings-outside-ground-truth-table) — real artifacts, classified true-positive-outside-GT |
| Invented facts with no ledger citation | **0** | The report generator cites ledger `seq` only; uncited claims are rejected at `record_finding` |
| Questionable attribution | 1 | **F-007**: the connection to `52.242.211.89:443` is real and reproducible in desktop netscan, but the "C2 beacon" label is unproven and is **not** the documented C2 (`203.78.103.109`, which lives in the DC memory/pcap this run did not analyze). The verifier confirms the *connection exists*, not that the *attribution is correct*. |

**Verifier catch examples (smoke case):** the `mimikatz.exe` decoy (12-byte ASCII) is
routinely flagged in triage and flipped to **REFUTED** when credential-dumping
capability cannot be reproduced — the intentional recall/precision split, not a
Szechuan miss.

## Extra findings (outside ground-truth table)

Real, reproducible artifacts beyond the writeup's 24 headline facts. They do **not**
increase the score; each is a true-positive a human analyst would value.

| Finding ID | Summary | Classification |
|------------|---------|----------------|
| F-002 | Reflective DLL injection in PowerShell PID 3316 (MZ in RWX memory, T1055.001) | true-positive-outside-GT |
| F-003 | Code injected into `spoolsv.exe` (T1055.001) | true-positive-outside-GT |
| F-008 | `ntds.dit` present → full domain-hash exposure capability (T1003.003) | true-positive-outside-GT |
| F-009 | Live ESTABLISHED SMB desktop→DC (10.42.85.115→10.42.85.10:445, T1021.002) | true-positive-outside-GT |
| F-010 | `coreupdater.exe` forged PE timestamp (~2010 vs 2020 birth) — timestomping (T1070.006) | true-positive-outside-GT |
| F-012 | RSA key provisioned for SYSTEM at the exact second coreupdater exited (T1553.004) | true-positive-outside-GT |
| F-006 | Domain user sessions ricksanchez / mortysmith on the desktop (T1078.002) | benign-fact / context |

## Known limitations affecting accuracy

Every miss clusters on DC-side and download/exfil evidence. The cause is a
**resource-allocation** limit, not a capability limit — VERDICT demonstrably parses
both memory images and walks both disks; it ran out of its self-imposed budget before
covering host #2 end-to-end.

- **DC memory (`citadeldc01.mem`) never analyzed.** The real C2 (`203.78.103.109`) and
  coreupdater PID 3644 live there. Volatility plugins on a 2 GB image are slow
  (netscan ~100 s, malfind ~260 s); the triage soft-cap (60% of $5 = $3.00) was reached
  after thoroughly working the *desktop* memory, before the second host's capture.
- **DC initial-access / service / exfil evidence** (GT-06–09, 15–16, 23) lives in DC
  `Security.evtx` / `System.evtx` / the DC file share. Run 2 *did* reach the DC disk
  (mmls auto-discovery, C: at sector 718848) but spent its triage budget navigating a
  `FileShare` directory-junction that loops to the C: root, and again capped before the
  persistence/exfil evidence.
- **Desktop split-E01 (`.E01`–`.E04`) auto-offset returned empty** — a known tooling bug
  (documented, not chased given the deadline); the desktop disk was worked via memory.
- **C2 IP in memory vs published GT** (GT-18): the desktop netscan shows
  `52.242.211.89`, distinct from the published `203.78.103.109`; graded as a miss and the
  reported IP flagged as a questionable attribution above.
- **PCAP** noted in inventory; the MVP does not deep-parse pcap (GT-12 download host unrecoverable from this run).
- **Timezone trap (GT-05):** scored on the core fact only; VERDICT did not resolve it.

**The fix (named, not hand-waved):** a higher per-host memory budget or a memory-first
triage ordering so both captures are analyzed within the $5 cap. Budget allows 1–2 more
runs; deferred in favor of shipping an honest report before the deadline.

---

## Evidence integrity approach

Submission component **#6** requires documenting how original evidence stays unmodified,
and what happens when restrictions are prompt-based vs architectural.

### Architectural enforcement (what VERDICT uses)

VERDICT does **not** rely on prompt instructions to protect evidence. Enforcement is
server-side and structural:

| Control | Mechanism |
|---------|-----------|
| **No evidence writes** | `PathGuard`: reads under `--case` or `--run`; **writes only under `--run`**. Evidence paths opened read-only; write attempts → `PathViolation` → `tool_rejected` ledger line. |
| **No shell / no delete tool** | The model's tool list contains 13 typed forensic tools only. No bash, no `rm`, no arbitrary command — **absent**, not disabled. |
| **Fixed binaries** | `runner.py` invokes executables from `binaries.py` only; model input cannot choose a binary path or inject shell metacharacters (`shell=False`). |
| **Tamper-proof audit trail** | `ledger.jsonl` is append-only, fsync per line, **server-only writer**. The model has no ledger-write tool; orchestrator events use `_log_event`, never exposed to the model. |
| **Citable outputs** | Full tool output written to `runs/<id>/outputs/` with SHA-256 in the ledger; report citations link to ledger sequence numbers. |

See [`architecture.md`](architecture.md) for the full boundary diagram.

### Prompt-based restrictions (what we do *not* treat as safety)

Prompts tell the agent to stay hypothesis-driven and cite evidence — but a confused
model could still *claim* spoliation in natural language. It **cannot execute**
spoliation: there is no tool path to modify files under `--case`.

**If the model ignores a prompt restriction:** it may overstate a finding in triage; the
**verifier** independently re-runs cited tools and demotes unreproducible claims to
UNCONFIRMED or REFUTED (demonstrated live in run 2). Prompt drift affects narrative, not
bytes on disk.

### Spoliation testing

We did not run a dedicated red-team "delete `Security.evtx`" harness in production code.
The architecture **is** the spoliation test:

1. No delete/write tool exists in the MCP surface.
2. Any write to an evidence path is rejected before I/O (`pathguard.resolve_write`).
3. Extracted copies land only under `runs/<id>/artifacts/`; originals under `--case` are never opened for writing.

**Failure modes observed (signal, not weakness):**

| Observation | Classification |
|-------------|----------------|
| Triage overclaims on scary filenames (smoke `mimikatz.exe`; run-2 DKOM) | Verifier REFUTED — working as designed |
| SHA replay drift when re-running EvtxECmd (run-stamped console output) | Fixed in runner hashing; verifier flags drift explicitly |
| Agent cannot modify evidence even when DC disk is hard to read | Limitation is **access**, not **integrity** |

To reproduce a refusal: attempt any operation that would write under the case folder —
the server returns a model-readable denial and logs `tool_rejected`. There is no code
path for the agent to truncate, delete, or rewrite original E01/EVTX/memory captures.

---

## Traceability

Every graded row cites at least one **VERIFIED** finding ID and ledger `seq` from the
run under review. Judges can open [`execution-logs/ledger.jsonl`](execution-logs/ledger.jsonl)
and search by `seq` or tool name to follow the chain: hypothesis → tool call → SHA-256 →
finding → verdict.
