// VERDICT smoke-case YARA rule (checklist item 5).
//
// EICAR-style: an inert, high-entropy marker string that no benign file
// contains by accident. The smoke case ships exactly one file that carries
// this marker (cases/smoke/invoice_2020.txt), so a yara_scan of the smoke
// folder produces one deterministic hit - the positive control that proves
// the scan engine, ruleset discovery (rules/*.yar -> the `smoke` enum), and
// the citing/ledger path all work end to end.
//
// This rule is NOT the decoy. The decoy (cases/smoke/mimikatz.exe) is 12
// bytes of ASCII text and deliberately does NOT match this rule: triage
// flags it by filename, the verifier reads its content + yara-scans it,
// gets no malware match, and flips the finding to REFUTED.
//
// Keep this filename `smoke.yar`: yara_scan derives its ruleset enum from
// rules/*.yar at server start, so the stem becomes the `smoke` ruleset.

rule verdict_smoke_eicar
{
    meta:
        description = "VERDICT smoke-case test marker (EICAR-style, inert)"
        author      = "verdict"
        reference   = "cases/smoke/invoice_2020.txt"
        is_test     = "true"
    strings:
        // Unique marker + high-entropy tail so it cannot collide with a real
        // sample. Authored by VERDICT; carries no real malicious payload.
        $marker = "VERDICT-SMOKE-TEST-MARKER-2b9f4e7a1c6d8035e4" ascii
    condition:
        $marker
}
