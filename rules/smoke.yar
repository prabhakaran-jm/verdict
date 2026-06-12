// Placeholder so the yara_scan ruleset enum is non-empty before checklist
// item 5 writes the real smoke-case rule. Matches a marker string no
// benign file contains by accident.

rule smoke_placeholder
{
    meta:
        description = "VERDICT smoke-case placeholder rule (replaced by item 5)"
        author = "verdict"
    strings:
        $marker = "VERDICT-SMOKE-MARKER"
    condition:
        $marker
}
