# Dataset Documentation

(Provenance + download/verify steps for the Szechuan Sauce primary dataset and the
bundled smoke case are filled in by later checklist items; `scripts/get-dataset.sh`
is the executable download/verify record in the meantime.)

## Smoke case artifact licensing (spec Open Issue #3)

**Question:** may VERDICT redistribute sample `.evtx` files from
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
inside `cases/smoke/`?

**Finding (verified live 2026-06-11 via `gh api
repos/sbousseaden/EVTX-ATTACK-SAMPLES/license`):** the repository is licensed
**GPL-3.0** (`LICENSE.GPL` at the repo root). Redistribution is therefore
permitted — but only under GPL-3.0 terms, and VERDICT is Apache-2.0: bundling
GPL-licensed sample files inside this repo would create mixed-licensing friction
for a hackathon submission that advertises a clean Apache-2.0 license.

**Decision (per spec Open Issue #3 fallback):** item 5 does **not** redistribute
EVTX-ATTACK-SAMPLES content. The smoke case's `Security.evtx`/`System.evtx`
(type-3 logons + Event ID 7045 service install) are **generated on the Windows 11
build host** — synthetic events produced locally, exported with `wevtutil`, and
sanitized. This also gives the smoke case cleaner provenance: every artifact in
`cases/smoke/` is either created by us or exported from our own machine, so the
provenance section (item 5) can state ownership outright with zero third-party
licensing caveats.

## Smoke case provenance (`cases/smoke/`)

The smoke case is a few MB of loose, sanitized artifacts that exercise the full
VERDICT pipeline (survey → triage → verify → report) in ~3 minutes for pennies.
Every file is either authored by the VERDICT project or exported from the
author's own Windows 11 machine — **nothing is redistributed from a third-party
dataset** (see the licensing decision above). The smoke story is a single
intrusion: a service named like a benign updater is installed from
`C:\Users\Public\update.exe`, that path is also pinned in a Run key for
persistence, the binary was executed (prefetch proves it), and type-3 network
logons surround the activity — plus a filename decoy (`mimikatz.exe`) that the
verifier refutes.

Artifacts split into two halves by **how they are produced**:

### Half A — committed by checklist item 5 (built unelevated, in this repo)

| Artifact | How produced | Why safe / sanitized |
|---|---|---|
| `mimikatz.exe` | Authored: written as exactly **12 bytes of ASCII** (`hello world\n`) by item 5. | Not an executable at all — 12 bytes of text. No PE header, no payload. It is **the decoy**: triage flags the alarming filename, the verifier reads the content (`read_artifact`) and yara-scans it, finds plain text, and flips the finding to `REFUTED`. Marked `-text` in `.gitattributes` so it stays exactly 12 bytes on every checkout. |
| `invoice_2020.txt` | Authored: a benign-looking invoice that embeds one inert, high-entropy marker string. | Contains no real data and no payload — the marker (`VERDICT-SMOKE-TEST-MARKER-…`) is an EICAR-style test token defined by `rules/smoke.yar`. It is the **YARA positive control**: scanning the folder produces exactly one deterministic match, proving the scan + ruleset-discovery + citation path work. |
| `rules/smoke.yar` (in `rules/`, not `cases/`) | Authored: a real YARA rule matching only the marker above. | Inert test rule; `yara_scan` derives its `smoke` ruleset enum from this file's stem at server start. |

### Half B — produced by `scripts/make-smoke-case.ps1` (run once, elevated, on the host)

These four are **not** in the item-5 commit. Generating real Windows event
records, a real prefetch file, and a valid registry hive requires Administrator
(SysMain/Prefetch, the Security log, `SeBackupPrivilege` for `reg save`), and the
build shell is intentionally unelevated. The learner runs the script once
(`Run as administrator`); the orchestrator commits its outputs afterward. The
script is self-checking, idempotent, verbose, cleans up after itself, and only
ever creates/deletes objects named `VerdictSmoke*` — it never touches an existing
service, account, or setting, and never disables Defender or reboots.

| Artifact | How produced | Why safe / sanitized |
|---|---|---|
| `Security.evtx` | `wevtutil epl Security` filtered by XPath to **only Event IDs 4624/4625 at/after the script's start time**. The script creates a throwaway local user `VerdictSmoke`, does a loopback `net use \\127.0.0.1\IPC$` to generate a type-3 (network) logon 4624 plus one wrong-password 4625, then deletes the user. | Time-window-filtered export of synthetic events the script just generated — **never the whole Security log** (a full export would leak unrelated host activity; this is a deliberate privacy constraint). |
| `System.evtx` | `wevtutil epl System` filtered to **only Event ID 7045 at/after start**. The script runs `sc.exe create VerdictSmokeSvc binPath= C:\Users\Public\update.exe start= demand` (and never starts it) to emit the 7045 service-install record, then `sc.exe delete`. | Same time-window filtering; only the one service-install record this run created is exported. |
| `NTUSER.DAT` | A scratch key `HKCU\VerdictSmokeHive` is built with `…\CurrentVersion\Run` value `Updater = C:\Users\Public\update.exe`, then `reg.exe save` writes it to a valid `regf` hive named `NTUSER.DAT` (so `registry_query run_keys` recognises the layout); the scratch key is deleted. | A purpose-built hive containing one benign Run value — no real user profile data is exported. |
| `UPDATE.EXE-*.pf` | A copy of the benign, signed `C:\Windows\System32\where.exe` is placed at `C:\Users\Public\update.exe` and **actually executed once**; the real prefetch SysMain writes (`UPDATE.EXE-<hash>.pf`) is copied out. | A genuine prefetch file whose embedded executable name matches `UPDATE.EXE` — **not** a renamed foreign prefetch (which a verifier would catch as a name/hash mismatch). The underlying binary is just Windows' own `where.exe`. |

**Disclosed by design — host identifiers are visible.** Because the EVTX records
and the prefetch are *real* artifacts generated on the author's machine, they
contain the build host's computer name and the local account name(s) used during
generation (e.g. the `VerdictSmoke` user and the host's hostname appear in 4624/
4625 records; the executing user appears in prefetch metadata). This is
**intentional and documented**: it keeps the artifacts authentic (a forensic tool
should be tested on real records, not hand-faked JSON), and the data exposed is
limited to the author's own non-sensitive build-host identifiers within a tight
time window. No third-party, customer, or sensitive data is present. The exports
are filtered to the script's run window precisely so that nothing else from the
host's logs is carried along.

**Total size budget:** the whole of `cases/smoke/` stays well under 5 MB; the
elevated script verifies the summed size before declaring success.

**Regenerating Half B (only if missing):** the repo normally ships the four
host-exported files already committed. If they are absent after a partial clone,
run `scripts/make-smoke-case.ps1` **once, elevated**, on Windows 11, then commit
or copy the outputs into `cases/smoke/`. See the script header for safety
constraints (only `VerdictSmoke*` objects touched).

### Clean case (`cases/clean/`)

A handful of obviously benign files — `readme.txt`, `app.log`, `config.ini` —
authored by item 5. `evidence_inventory` classifies them as `other`, and an
honest investigation reports the folder clean with **zero invented findings**
(the standing empty-case test, `prd.md > Failure & Empty-Case Behavior`). They
contain no indicators: no `update.exe`, no service installs, no YARA marker.

---

## Primary dataset — The Case of the Stolen Szechuan Sauce

DFIRmadness **Case 001** — the hackathon's accuracy benchmark and full
autonomous-run target.

### Provenance

| Field | Value |
|-------|-------|
| **Case name** | The Case of the Stolen Szechuan Sauce |
| **Publisher** | DFIRmadness / SANS community case series |
| **Case page** | <https://dfirmadness.com/the-stolen-szechuan-sauce/> |
| **Official answers** | <https://dfirmadness.com/answers-to-szechuan-case-001/> |
| **Memory analysis tutorial** | <https://dfirmadness.com/case-001-memory-analysis/> |
| **Scenario** | Active Directory domain **CITADEL** — internet-exposed RDP on **CITADEL-DC01** (`10.42.85.10`), lateral movement to **DESKTOP-SDN1RPT** (`10.42.85.115`); Meterpreter implant **`coreupdater.exe`**, C2, recipe exfiltration |
| **Ground truth for scoring** | `docs/ground-truth.md` (24 scorable rows pinned from S1/S2/S2a) |
| **Accuracy report** | `docs/accuracy-report.md` (checklist item 11 — scored after the full run) |

Evidence is **not redistributed in this repository** (`.gitignore` excludes
images, memory, pcap). Download on the SIFT VM with the script below.

### What you get (11 archives)

| Archive | Contents (approx.) |
|---------|-------------------|
| `DC01-E01.zip` | Domain controller disk image (E01) |
| `DC01-memory.zip` | DC memory capture (`citadeldc01.mem`) |
| `DC01-pagefile.zip` | DC pagefile |
| `DC01-autorunsc.zip` | Autoruns export (DC) |
| `DC01-ProtectedFiles.zip` | Protected files bundle (DC) |
| `DESKTOP-E01.zip` | Workstation disk image (E01) |
| `DESKTOP-SDN1RPT-memory.zip` | Desktop memory capture |
| `Desktop-SDN1RPT-pagefile.zip` | Desktop pagefile |
| `DESKTOP-SDN1RPT-autorunsc.zip` | Autoruns export (desktop) |
| `DESKTOP-SDN1RPT-Protected Files.zip` | Protected files (desktop) |
| `case001-pcap.zip` | Network capture (referenced; MVP does not deep-parse pcap) |

**Download size:** ~13.5 GB zipped · **Extracted:** ~25–30 GB on disk.

### Download and verify

**On the SIFT Workstation VM** (recommended path):

```bash
git clone https://github.com/prabhakaran-jm/verdict.git
cd verdict
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install volatility3    # memory tools use the venv vol binary

# Default target: /cases/szechuan/  (create with sudo if needed)
sudo mkdir -p /cases/szechuan && sudo chown "$USER" /cases/szechuan
./scripts/get-dataset.sh
```

`scripts/get-dataset.sh`:

- Downloads from `https://dfirmadness.com/case001/` (URLs verified live 2026-06-11)
- Verifies each archive against the **published MD5** from the case page
- Is **idempotent and resume-safe** (`curl -C -` / `wget -c`; skips verified files)
- Computes **SHA-256** of every archive into `SHA256SUMS.txt` under the target dir
- Extracts each zip once (marker files prevent re-extraction)

**Full Day-1 gate** (binaries + dataset + Vol3 pslist on both memory images):

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # not required for steps 1–3
./scripts/day1-gate.sh /cases/szechuan
```

Gate artifacts land in `runs/day1-gate/` (binaries JSON, pslist smoke outputs).

### Published MD5 checksums (verification record)

These are the hashes `get-dataset.sh` enforces (from the case page, 2026-06-11):

| File | MD5 |
|------|-----|
| `case001-pcap.zip` | `422046B753CF8A4DF49D2C4CE892DB16` |
| `DC01-E01.zip` | `E57FC636E833C5F1AB58DFACE873BBDE` |
| `DC01-memory.zip` | `64A4E2CB47138084A5C2878066B2D7B1` |
| `DC01-pagefile.zip` | `964EEAF0009D08CC101DE4A83A4E5D23` |
| `DC01-autorunsc.zip` | `964F2D710687D170C77C94947DA29E66` |
| `DC01-ProtectedFiles.zip` | `AD29830A583EFE49C8C1C35FAFFD264F` |
| `DESKTOP-E01.zip` | `71C5C3509331F472ABCDF81EB6EFFF07` |
| `DESKTOP-SDN1RPT-memory.zip` | `CF31E2635C77811AAA1BB04A92A721E2` |
| `Desktop-SDN1RPT-pagefile.zip` | `45C096F2688A0B5DE0346FB72391B245` |
| `DESKTOP-SDN1RPT-autorunsc.zip` | `3627DCAFA54E1365489A4EC0CC3D6A1C` |
| `DESKTOP-SDN1RPT-Protected Files.zip` | `3E1A358D50003A9351AC2160AE6F0495` |

SHA-256 sums are computed at download time (not published by the case author) and
written to `/cases/szechuan/SHA256SUMS.txt` for your local record.

### Running an investigation

```bash
source .venv/bin/activate
export ANTHROPIC_API_KEY=sk-ant-...
verdict investigate /cases/szechuan/ --budget 5.00
```

Expect ~30–60 minutes wall-clock and ≤ $5 API spend (budget guard enforced).
Outputs: `runs/<UTC-timestamp>/report.html`, `report.pdf`, `findings.json`,
`ledger.jsonl`.

### Known constraints (document honestly)

- **Volatility 3 on Server 2012 R2 DC memory** can be slow or symbol-heavy; use
  the venv `vol` binary, not a bare system install. Desktop memory is the primary
  validation path in `day1-gate.sh`.
- **Partition offsets** on E01 images vary; VERDICT auto-discovers partitions via
  `mmls` when `partition_offset` is omitted (see `verdict_mcp/tools/_image_helpers.py`).
- **Ground-truth C2 IP** in published answers is **`203.78.103.109`**; score against
  `docs/ground-truth.md`, not against memory-only artifacts that may show session-specific
  infrastructure.
