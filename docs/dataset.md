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
