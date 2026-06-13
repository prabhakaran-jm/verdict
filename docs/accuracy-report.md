# Accuracy Report — VERDICT vs Szechuan Sauce Ground Truth

Self-assessment for FIND EVIL! submission component **#6**. Scored against the 24
published facts in [`ground-truth.md`](ground-truth.md) (DFIRmadness Case 001 official
answers + memory-analysis tutorial, pinned 2026-06-11).

> **Status:** scaffold — fill verdict columns after the final `verdict investigate
> /cases/szechuan/` run completes. Replace `TBD` placeholders with finding IDs and
> ledger citations from `runs/<run-id>/findings.json` and `report.html`.

## Run under review

| Field | Value |
|-------|-------|
| **Command** | `verdict investigate /cases/szechuan/ --budget 5.00` |
| **Run folder** | `runs/TBD` |
| **Completed (UTC)** | TBD |
| **Wall time** | TBD |
| **API cost** | TBD |
| **Exit code** | TBD |
| **Findings recorded** | TBD (VERIFIED / UNCONFIRMED / REFUTED counts) |
| **Report** | `runs/TBD/report.html` |
| **Ledger** | `runs/TBD/ledger.jsonl` (copy committed under [`execution-logs/`](execution-logs/)) |

## Summary score

| Metric | Count |
|--------|------:|
| **found** | TBD |
| **partially found** | TBD |
| **missed** | TBD |
| **Score** | **TBD%** — `(found + 0.5 × partial) / 24` |

**Named misses (required):** TBD — list every `GT-XX` graded **missed** with one-line reason.

**Headline accuracy:** TBD% with TBD misses — *update honestly; a credible 85% with named
misses beats a suspicious 100%.*

## Per-row grading

Grades apply to **VERIFIED** and **UNCONFIRMED** findings only. REFUTED / appendix
findings never earn credit. See scoring protocol in [`ground-truth.md`](ground-truth.md).

| ID | Stage | Core fact (abbrev.) | Verdict | VERDICT finding(s) | Notes |
|----|-------|---------------------|---------|-------------------|-------|
| GT-01 | baseline | Domain **CITADEL**; hosts DC01 + DESKTOP-SDN1RPT | TBD | TBD | |
| GT-02 | baseline | DC01 Server 2012 R2, `10.42.85.10` | TBD | TBD | |
| GT-03 | baseline | Desktop Windows 10, `10.42.85.115` | TBD | TBD | |
| GT-04 | baseline | Intrusion window 2020-09-19 ~02:19–02:45 UTC | TBD | TBD | |
| GT-05 | baseline | Colorado / Mountain time (UTC-6); VM clock trap | TBD | TBD | |
| GT-06 | initial access | Internet RDP brute-force → valid Administrator | TBD | TBD | |
| GT-07 | initial access | Attacker source **`194.61.24.102`** | TBD | TBD | |
| GT-08 | initial access | Burst of 4625 failures before success | TBD | TBD | |
| GT-09 | initial access | First 4624 success 02:21 UTC, LogonType 10 | TBD | TBD | |
| GT-10 | execution | **`coreupdater.exe`** in System32 on DC01 | TBD | TBD | |
| GT-11 | execution | Meterpreter / Metasploit payload | TBD | TBD | |
| GT-12 | execution | Downloaded via IE ~02:24:06 UTC on DC01 | TBD | TBD | |
| GT-13 | execution | Execution artifacts (Amcache/prefetch) | TBD | TBD | partial-credit row |
| GT-14 | execution | DC memory: coreupdater PID **3644** | TBD | TBD | |
| GT-15 | persistence | Service **coreupdater** installed 02:27:49 UTC (7045) | TBD | TBD | |
| GT-16 | persistence | Service Start = Automatic (registry) | TBD | TBD | |
| GT-17 | persistence | Same implant on desktop ~02:41 UTC | TBD | TBD | |
| GT-18 | C2 | C2 IP **`203.78.103.109`** | TBD | TBD | |
| GT-19 | C2 | C2 on TCP 443 / 4444 | TBD | TBD | |
| GT-20 | C2 | netscan ties C2 to **coreupdater.exe** process | TBD | TBD | disk↔memory row |
| GT-21 | lateral movement | RDP DC01 → desktop ~02:35 UTC | TBD | TBD | |
| GT-22 | lateral movement | DC01 first, desktop second | TBD | TBD | |
| GT-23 | exfil-impact | Recipe accessed / **secret.zip** staged | TBD | TBD | score access+staging if exfil unproven |
| GT-24 | exfil-impact | Attacker used Administrator only (no 4720) | TBD | TBD | partial-credit row |

## False positives and hallucinated claims

| Category | Count | Detail |
|----------|------:|--------|
| Findings **REFUTED** by verifier | TBD | List finding IDs + one-line refutation reason |
| VERIFIED claims **not** in ground truth | TBD | See extra findings table below |
| Invented facts with no ledger citation | TBD | Expected: **0** (report generator cites ledger seq only) |

**Verifier catch examples (smoke case):** the `mimikatz.exe` decoy (12-byte ASCII) is
routinely flagged in triage and flipped to **REFUTED** when credential-dumping capability
cannot be reproduced — this is intentional recall/precision split, not a Szechuan miss.

## Extra findings (outside ground-truth table)

Findings VERDICT reported that are **not** one of GT-01…GT-24. Extras do not increase
the score; classify each honestly.

| Finding ID | Summary | Classification | Notes |
|------------|---------|----------------|-------|
| TBD | TBD | true-positive-outside-GT / benign-fact / false-positive | |

## Known limitations affecting accuracy

Document run-specific gaps here after scoring (examples from prior runs — confirm against
final run):

- **DC01 E01 partition access:** wrong offset blocked full DC disk walk; agent routed via
  desktop disk + memory + extracted EVTX + artifact bundles.
- **C2 IP in memory vs published GT:** session artifacts may show infrastructure IPs
  distinct from published **`203.78.103.109`** — grade GT-18 against published answers,
  note any memory-only IPs as extras or partial.
- **PCAP:** noted in inventory; MVP does not deep-parse pcap (GT-12 URL/host may stay partial).
- **Timezone trap (GT-05):** case deliberately confuses UTC vs local; score core fact only unless VERDICT explicitly resolved it.

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
| **Fixed binaries** | `runner.py` invokes executables from `binaries.py` only; model input cannot choose binary path or inject shell metacharacters (`shell=False`). |
| **Tamper-proof audit trail** | `ledger.jsonl` is append-only, fsync per line, **server-only writer**. The model has no ledger-write tool; orchestrator control events use `_log_event`, never exposed to the model. |
| **Citable outputs** | Full tool output written to `runs/<id>/outputs/` with SHA-256 in the ledger; report citations link to ledger sequence numbers. |

See [`architecture.md`](architecture.md) for the full boundary diagram.

### Prompt-based restrictions (what we do *not* treat as safety)

Prompts tell the agent to stay hypothesis-driven and cite evidence — but a confused model
could still *claim* spoliation in natural language. It **cannot execute** spoliation:
there is no tool path to modify files under `--case`.

**If the model ignores a prompt restriction:** it may overstate a finding in triage; the
**verifier** must independently re-run cited tools and demote un reproducible claims to
UNCONFIRMED or REFUTED. Prompt drift affects narrative, not bytes on disk.

### Spoliation testing

We did not run a dedicated red-team "delete `Security.evtx`" harness in production code.
The architecture **is** the spoliation test:

1. No delete/write tool exists in the MCP surface.
2. Any write to an evidence path is rejected before I/O (`pathguard.resolve_write`).
3. Extracted copies land only under `runs/<id>/artifacts/`; originals under `--case` are never opened for writing.

**Failure modes observed (signal, not weakness):**

| Observation | Classification |
|-------------|----------------|
| Triage overclaims on scary filenames (smoke `mimikatz.exe`) | Verifier REFUTED — working as designed |
| SHA replay drift when re-running EvtxECmd (run-stamped console output) | Fixed in runner hashing; verifier flags drift explicitly |
| Agent cannot modify evidence even when DC disk is hard to read | Limitation is **access**, not **integrity** |

To reproduce a refusal: attempt any operation that would write under the case folder — the
server returns a model-readable denial and logs `tool_rejected`. There is no code path for
the agent to truncate, delete, or rewrite original E01/EVTX/memory captures.

---

## Traceability

Every graded row should cite at least one **VERIFIED** or **UNCONFIRMED** finding ID and
ledger `seq` from the run under review. Judges can open [`execution-logs/ledger.jsonl`](execution-logs/ledger.jsonl)
and search by `seq` or tool name to follow the chain: hypothesis → tool call → hash → finding → verdict.
