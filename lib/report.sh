#!/bin/sh
# sandprobe: report header and footer.
# SPDX-License-Identifier: 0BSD

sp_emit_header() {
    _rule='==============================================================================='
    printf '%s\n' "$_rule"
    printf 'sandprobe %s  report of a Linux sandbox\n' "$SP_VERSION"
    printf '%s\n' "$_rule"
    sp_kv "generated_utc" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    sp_kv "host_kernel" "$(uname -srm 2>/dev/null)"
    sp_kv "probing_user" "$(id -un 2>/dev/null):$(id -u 2>/dev/null)"
    sp_kv "probe_pid" "$$"
    sp_kv "budget_seconds" "$SP_BUDGET"
    sp_kv "redaction" "$([ "${SP_REDACT:-1}" -eq 1 ] && echo 'ON: credential values replaced with REDACTED' || echo 'OFF: --no-redact was given, credential values are printed verbatim')"

    printf '\n## HOW TO READ THIS REPORT\n\n'
    printf '%s\n' "Structured records are tab separated:" '    SECTION <TAB> TARGET <TAB> VERDICT <TAB> DETAIL'
    printf '%s\n' '' "A VERDICT is only ever one of these five, and only when the probe"
    printf '%s\n' "actually observed it:" ''
    printf '%s\n' "  ALLOW     the operation was permitted and it succeeded"
    printf '%s\n' "  DENY      refused by the kernel or a policy; DETAIL carries the errno"
    printf '%s\n' "  ABSENT    the object does not exist on this host; not a refusal"
    printf '%s\n' "  UNKNOWN   could not be measured; DETAIL says why"
    printf '%s\n' "  TIMEOUT   did not answer inside the budget; cause not distinguishable"
    printf '%s\n' '' "The network section adds three more, because collapsing them into"
    printf '%s\n' "each other would be a false claim:" ''
    printf '%s\n' "  UNRESOLVED  the name did not resolve"
    printf '%s\n' "  REFUSED     the peer sent a reset: it is reachable and said no"
    printf '%s\n' "  DROPPED     no answer at all: filtered or blackholed"
    printf '%s\n' '' "MISSING in the tool tables means not installed, which is never a denial."
    printf '%s\n' "ABSENT and MISSING are reported separately so that a tool this host"
    printf '%s\n' "does not carry is never mistaken for a tool it refused to run."
    printf '%s\n' '' "Redaction: names denoting secrets are replaced with REDACTED, and so"
    printf '%s\n' "are documented credential token shapes found inside otherwise normal"
    printf '%s\n' "values. Everything else, including URLs, paths, counts, addresses,"
    printf '%s\n' "hashes and version strings, is the real measured value."
    printf '\n%s\n\n' "$_rule"
}

sp_emit_footer() {
    _rule='==============================================================================='
    printf '\n%s\n' "$_rule"
    printf 'end of report\n'
    sp_kv "finished_utc" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    sp_kv "probe_elapsed_seconds" "$SP_ELAPSED"
    printf '%s\n' "$_rule"
}

# Verdict tally over the assembled report body.
#
# A report of several thousand lines is not actionable on its own, so the
# counts are summarised. The summary states its own limits: it counts records,
# it does not weigh them, and UNKNOWN is called out separately precisely
# because it is where the report's own uncertainty lives.
sp_emit_summary() {
    _body="$SP_WORK/report.body"
    [ -r "$_body" ] || return 0
    printf '\n## VERDICT TALLY\n\n'
    printf '%s\n' "# Counts of structured records by verdict. This is a count of"
    printf '%s\n' "# records, not a risk assessment: one DENY and one ALLOW are not"
    printf '%s\n' "# comparable in importance. UNKNOWN is listed because that is where"
    printf '%s\n' "# this report's own uncertainty lives."

    awk -F'\t' '
        $1 ~ /^(discover|host|security|fs|env|net|exec|escalation|escape-surface|procfs|procfs-traverse|device|credsfile|config|loopback|routes|tool)$/ {
            seen[$3]++
        }
        END {
            n = 0
            for (k in seen) { printf "  %-12s %d\n", k, seen[k]; n += seen[k] }
            printf "  %-12s %d\n", "TOTAL", n
        }
    ' "$_body" | LC_ALL=C sort

    printf '\n%s\n' "# UNKNOWN records, in full. These are the questions this run could not"
    printf '%s\n' "# answer, and they are the first place to look if the report is"
    printf '%s\n' "# incomplete."
    awk -F'\t' '$3 == "UNKNOWN" { printf "  %s :: %s :: %s\n", $1, $2, $4 }' "$_body" | head -60

    printf '\n%s\n' "# DENY records under the escalation and escape-surface sections, which are"
    printf '%s\n' "# the security-relevant refusals."
    awk -F'\t' \
        '($1 == "escalation" || $1 == "escape-surface" || $1 == "procfs-traverse") && $3 == "DENY" {
            printf "  %s :: %s\n", $2, substr($4, 1, 110)
         }' "$_body" | head -60

    printf '\n%s\n' "# ALLOW records under those same sections, because an unexpected"
    printf '%s\n' "# ALLOW is as interesting as an unexpected DENY."
    awk -F'\t' \
        '($1 == "escalation" || $1 == "escape-surface" || $1 == "procfs-traverse") && $3 == "ALLOW" {
            printf "  %s :: %s\n", $2, substr($4, 1, 110)
         }' "$_body" | head -60
}
