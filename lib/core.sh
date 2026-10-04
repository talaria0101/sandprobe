#!/bin/sh
# sandprobe core: verdict vocabulary, redaction, hermetic workdir, probe helpers.
# Sourced by the top-level script. Not executable on its own.
# SPDX-License-Identifier: 0BSD

SP_VERSION="1.0.0"

# Directory holding the library, resolved once so every section can find the
# bundled helpers regardless of the caller's working directory.
SP_LIB_DIR=${SP_LIB_DIR:-$(CDPATH= cd -- "$(dirname -- "${0}")" 2>/dev/null && pwd)}
# The scrubber program. Resolved without relying on $0, because this file is
# sourced by the driver and by the self-tests from different directories, and
# $0 then names whichever script is running rather than this file. The search
# walks up from the current directory so both callers find it. A missing
# scrubber is fatal to redaction, so it must be loud rather than silently
# reduce every value to nothing.
SP_SCRUB_AWK=""
for _cand in \
    "${SP_LIB_DIR:-}/scrub.awk" \
    "${SP_LIB_DIR:-}/lib/scrub.awk" \
    "./lib/scrub.awk" \
    "./scrub.awk" \
    "../lib/scrub.awk" \
    "../sandprobe/lib/scrub.awk"
do
    [ -n "$_cand" ] || continue
    if [ -f "$_cand" ]; then
        SP_SCRUB_AWK="$_cand"
        break
    fi
done

# ---------------------------------------------------------------------------
# Verdict vocabulary. Nothing outside this list may appear in a VERDICT field.
# ---------------------------------------------------------------------------
V_ALLOW="ALLOW"      # the operation was permitted and succeeded
V_DENY="DENY"        # refused by kernel/policy; errno recorded
V_ABSENT="ABSENT"    # the probed object does not exist on this host
V_UNKNOWN="UNKNOWN"  # could not measure; reason recorded
V_TIMEOUT="TIMEOUT"  # did not answer in budget; cause not distinguishable

# ---------------------------------------------------------------------------
# Runtime layout. One temp root, created once, removed by trap.
# ---------------------------------------------------------------------------
SP_WORK=""
SP_STARTED=""
SP_REPORT=""
SP_BUDGET="${SANDPROBE_BUDGET:-10}"
SP_OUT=""
SP_RC=0

sp_cleanup() {
    [ -n "$SP_WORK" ] && [ -d "$SP_WORK" ] && rm -rf "$SP_WORK"
    return 0
}

sp_init() {
    SP_WORK=$(mktemp -d "${TMPDIR:-/tmp}/sandprobe.XXXXXX") || {
        echo "sandprobe: cannot create work directory" >&2
        exit 70
    }
    SP_STARTED=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    mkdir -p "$SP_WORK/out"
}

sp_set_report() {
    case "$1" in
        -)  SP_REPORT="" ;;
        "") echo "sandprobe: report path must not be empty" >&2; exit 64 ;;
        *)  SP_REPORT="$1" ;;
    esac
}

# ---------------------------------------------------------------------------
# Redaction. Only credential material is removed. Everything else in the
# report is the real measured value.
#
# Two layers:
#   1. by-name  : field names that denote a secret
#   2. by-shape : documented credential formats and PEM blocks in free text
#
# Anything matched by neither rule is emitted verbatim.
# ---------------------------------------------------------------------------

# Credential redaction.
#
# The by-shape and by-name layers are implemented in lib/scrub.awk rather than
# as one sed expression. Three sed shapes failed in ways recorded in that file:
# a [_ -] class is a character RANGE that swallowed the separator, the GNU I
# flag is not portable and conflicts with explicit case classes, and alternation
# is leftmost-first so PASSWORD shadowed PASSPHRASE. In the awk version, gsub
# returns a count rather than a string, so `line = gsub(...)` replaced every
# line of the report with a number.
#
# The two pattern lists live here in the shell and travel in the environment,
# because a value containing newlines does not survive awk -v intact.

# Name fragments. A name is secret-bearing if it CONTAINS any of these, case
# folded, which is what makes a compound such as AWS_SECRET_ACCESS_KEY match on
# the SECRET inside it.
SP_KW='token|secret|password|passwd|passphrase|api_key|api-key|apikey|access_key|secret_key|session_key|token_key|auth_token|access_token|id_token|bearer|client_secret|credential|credentials|license|encryption_key|signing_key|hmac|private_key'

# Token shapes: documented credential formats, matched anywhere in the text.
SP_SHAPES='gh[pousr]_[A-Za-z0-9]{16,}
github_pat_[A-Za-z0-9_]{20,}
glpat-[A-Za-z0-9_-]{16,}
(AKIA|ASIA|AROA|AGPA)[A-Z0-9]{16}
sk-ant-[A-Za-z0-9_-]{16,}
sk-(proj-)?[A-Za-z0-9_-]{20,}
sk_(live|test)_[A-Za-z0-9]{16,}
(rk|pk)_(live|test)_[A-Za-z0-9]{16,}
(xox[baprse]|xapp)-[A-Za-z0-9-]{10,}
shpat_[A-Za-z0-9]{16,}
hvs\.[A-Za-z0-9_-]{16,}
AIza[A-Za-z0-9_-]{30,}
ya29\.[A-Za-z0-9_-]{20,}
npm_[A-Za-z0-9]{30,}
hf_[A-Za-z0-9]{30,}
r8_[A-Za-z0-9]{30,}
dop_v1_[A-Za-z0-9]{30,}
eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'

# Redact credential material in arbitrary text.
#
# A scrubber that fails must not look like a scrubber that found nothing. An
# earlier version ended in 2>/dev/null, so a missing sed, or a sed without -E,
# produced empty output and the caller wrote an empty report with exit 0. The
# stderr is no longer discarded, and a non-zero status is surfaced so a broken
# environment is diagnosable rather than silently lossy.
sp_scrub() {
    if [ ! -f "$SP_SCRUB_AWK" ]; then
        printf 'sandprobe: credential scrubber missing at %s\n' "$SP_SCRUB_AWK" >&2
        return 1
    fi
    SANDPROBE_KEYWORDS="$SP_KW" SANDPROBE_SHAPES="$SP_SHAPES" \
        awk -f "$SP_SCRUB_AWK"
}

# Names denoting a secret, for the by-name layer on structured fields.
# Case folded and matched as a substring, so a compound such as DB_PASSWORD is
# recognised. GIT_AUTHOR_NAME and SSH_AUTH_SOCK are deliberately not caught:
# neither holds a credential.
sp_secret_name() {
    case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
        *token*|*secret*|*password*|*passwd*|*passphrase*|*api_key*|*api-key*|*apikey*|\
        *access_key*|*secret_key*|*session_key*|*auth_token*|*access_token*|*id_token*|\
        *bearer*|*client_secret*|*credential*|*private_key*|*encryption_key*|*signing_key*)
            return 0 ;;
    esac
    return 1
}

# Collapse a PEM private key block.
#
# The BEGIN marker is matched generically rather than as a fixed
# "PRIVATE KEY" phrase, because real blocks are labelled RSA PRIVATE KEY,
# EC PRIVATE KEY, OPENSSH PRIVATE KEY, ENCRYPTED PRIVATE KEY,
# PGP PRIVATE KEY BLOCK, PGP SECRET KEY BLOCK and SSH2 ENCRYPTED PRIVATE KEY,
# and a pattern admitting only letters and spaces between BEGIN and PRIVATE
# matched some of those and missed the rest.
#
# The body is bounded to a line count. An unterminated BEGIN otherwise swallowed
# everything to end of input, which once reduced a report by nine sections and
# silently deleted its own verdict tally.
sp_scrub_pem() {
    awk '
        /^-----BEGIN [A-Z0-9 ]*(PRIVATE|SECRET) KEY( BLOCK)?-----/ {
            if (!begun) print "[REDACTED_PRIVATE_KEY]"
            begun = 1
            n = 0
            next
        }
        /^-----END [A-Z0-9 ]*(PRIVATE|SECRET) KEY( BLOCK)?-----/ {
            # A stray END without a BEGIN is real content, so keep it.
            if (begun) begun = 0
            else print
            next
        }
        begun {
            # Only a base64-shaped line continues a key body. An unterminated
            # BEGIN otherwise consumed the rest of the document: a four-line
            # input lost two lines, and a whole report lost its verdict tally
            # and footer while still exiting 0.
            if (length($0) <= 76 && $0 ~ /^[A-Za-z0-9+\/=]+$/) next
            begun = 0
            print "[REDACTED_PRIVATE_KEY: unterminated marker, body ends here]"
            print
            next
        }
        { print }
    '
}

# A key/value line. The value is flattened to a single line and its separators
# neutralised before printing.
#
# This is not cosmetic. Records are tab separated and the report is read line
# by line, so a value containing a newline silently splits one record into two
# and a reader parsing the report sees one measurement where there were none.
# Two bugs of that shape shipped before this guard existed: `id -un 2>&1`
# captured a complaint and a uid together, and `grep -c ... || echo 0` produced
# the value "0\n0".
sp_kv() {
    __sp_key="$1"; __sp_val="${2-}"
    if sp_secret_name "$__sp_key"; then
        printf '%s = REDACTED\n' "$__sp_key"
        return 0
    fi
    __sp_flat=$(printf '%s' "$__sp_val" | tr '\n\r\t' '   ' | sp_scrub)
    printf '%s = %s\n' "$__sp_key" "$__sp_flat"
    return 0
}

sp_raw() {
    printf '%s\n' "$1" | sp_scrub
}

# Structured record, tab separated so the report stays machine readable:
#   SEC <TAB> id <TAB> VERDICT <TAB> detail
# An unrecognised verdict degrades to UNKNOWN with a loud detail rather than
# silently inventing a value.
sp_rec() {
    __sp_sec="$1"; __sp_id="$2"; __sp_verdict="$3"; __sp_detail="${4-}"
    case "$__sp_verdict" in
        ALLOW|DENY|ABSENT|UNKNOWN|TIMEOUT|EXHAUSTED|UNRESOLVED|REFUSED|DROPPED) ;;
        *) __sp_verdict="UNKNOWN"
           __sp_detail="INTERNAL BUG: invalid verdict '$__sp_verdict' in '$__sp_sec/$__sp_id'" ;;
    esac
    __sp_detail=$(printf '%s' "$__sp_detail" | tr '\t\n' '  ' | sp_scrub)
    printf '%s\t%s\t%s\t%s\n' "$__sp_sec" "$__sp_id" "$__sp_verdict" "$__sp_detail"
}

# ---------------------------------------------------------------------------
# Verdict classification.
#
# Only a refusal string proves a refusal. A missing file proves absence.
# Anything else means we did not learn the answer, so it must be UNKNOWN.
# ---------------------------------------------------------------------------
sp_verdict_from_err() {
    # Normalise case first. Real refusals arrive as "Permission denied",
    # "permission denied.", "Operation not permitted" and "os error 13"
    # depending on which tool produced them, and a case-sensitive match
    # silently turns a refusal into UNKNOWN or, worse, into ALLOW upstream.
    __sp_lc=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    case "$__sp_lc" in
        *"read-only file system"*|*"permission denied"*|*"operation not permitted"*|\
        *"not permitted"*|*"access denied"*|*"must be root"*|*"os error 13"*|\
        *"operation not allowed"*|*"you must be root"*|*"permission is denied"*|\
        *"not allowed"*|*"prohibited"*)
            # Every pattern here is a phrase a kernel or a tool uses to state a
            # refusal. A bare "denied" is deliberately NOT matched: an English
            # sentence like "mount denied because the filesystem is nosuid" is a
            # note about policy, not a refusal by this process, and classifying
            # it as DENY would be a false claim.
            printf 'DENY' ;;
        *"no such file"*|*"not a directory"*|*"nonexistent"*|*"no such device"*|\
        *"os error 2"*|*"os error 19"*|*"no such process"*|*"no such user"*|\
        *"no such host"*)
            printf 'ABSENT' ;;
        *"timed out"*|*"timeout"*|*"connection timed out"*)
            printf 'TIMEOUT' ;;
        *"too many open files"*|*"cannot allocate memory"*|*"out of memory"*|\
        *"no space left on device"*|*"text file busy"*|*"resource busy"*|\
        *"too many processes"*|*"quota exceeded"*|*"i/o error"*|*"input/output error"*|\
        *"no space left"*)
            # Exhaustion, not policy. Calling these DENY would blame a
            # sandbox boundary for a full disk or an open file limit.
            printf 'EXHAUSTED' ;;
        *)
            printf 'UNKNOWN' ;;
    esac
}

# Strip trailing slashes from a path so we never build "//name" when the
# directory is "/". Done with sed because dash cannot trim a positional
# parameter directly.
sp_trim_slash() {
    [ -n "$1" ] || { printf '/'; return 0; }
    __sp_t=$(printf '%s' "$1" | sed -e 's:/*$::')
    [ -n "$__sp_t" ] || __sp_t="/"
    printf '%s' "$__sp_t"
}

sp_try_write() {
    __sp_p=$(sp_trim_slash "$1")
    # Build the probe path without ever producing "//name": appending a
    # separator to a path that is already "/" would give a doubled slash.
    case "$__sp_p" in
        /)  __sp_f="/.sandprobe-write-probe.$$" ;;
        *)  __sp_f="$__sp_p/.sandprobe-write-probe.$$" ;;
    esac
    # The create happens in a child shell, never in this one. A POSIX shell
    # treats a redirection failure on a simple command as fatal and exits, so
    # "> file" against an unwritable path in this shell would abort the entire
    # probe run with status 2 instead of recording a refusal.
    __sp_err=$(sh -c ': > "$1"' sh "$__sp_f" 2>&1)
    if [ -e "$__sp_f" ]; then
        if { rm -f "$__sp_f"; } 2>/dev/null && [ ! -e "$__sp_f" ]; then
            sp_rec "$SP_CUR" "write:$__sp_p" "ALLOW" "created and removed a probe file"
        else
            sp_rec "$SP_CUR" "write:$__sp_p" "ALLOW" "created a probe file but could NOT remove $__sp_f"
        fi
        return 0
    fi
    sp_rec "$SP_CUR" "write:$__sp_p" "$(sp_verdict_from_err "$__sp_err")" "$__sp_err"
    return 0
}

# Read probe. Directory listing distinguishes absent from refused.
sp_try_read() {
    __sp_p=$(sp_trim_slash "$1")
    __sp_err=$( { ls -1 -- "$__sp_p" >/dev/null; } 2>&1 )
    if [ -z "$__sp_err" ]; then
        __sp_n=$(ls -1 -- "$__sp_p" 2>/dev/null | wc -l | tr -d ' ')
        sp_rec "$SP_CUR" "read:$__sp_p" "ALLOW" "$__sp_n entries listed"
        return 0
    fi
    sp_rec "$SP_CUR" "read:$__sp_p" "$(sp_verdict_from_err "$__sp_err")" "$__sp_err"
    return 0
}

# Existence probe for a single file, used where listing makes no sense.
sp_try_exists() {
    __sp_p="$1"
    if [ -e "$__sp_p" ]; then
        sp_rec "$SP_CUR" "exists:$__sp_p" "ALLOW" "present"
    else
        sp_rec "$SP_CUR" "exists:$__sp_p" "ABSENT" "no such file or directory"
    fi
    return 0
}

# Exec probe: present, then runnable. Absent is not a denial.
sp_try_exec() {
    __sp_f="$1"
    if [ ! -e "$__sp_f" ]; then
        sp_rec "$SP_CUR" "exec:$__sp_f" "ABSENT" "no such file"
        return 0
    fi
    __sp_e1=$(timeout "$SP_BUDGET" sh -c '{ "$1" --version >/dev/null; } 2>&1' sh "$__sp_f")
    if [ -z "$__sp_e1" ]; then
        sp_rec "$SP_CUR" "exec:$__sp_f" "ALLOW" "executed successfully"
        return 0
    fi
    # "--version" is not universally supported. Fall back to -h so a working
    # binary with unusual flags is not reported as a denial.
    __sp_e2=$(timeout "$SP_BUDGET" sh -c '{ "$1" -h >/dev/null; } 2>&1' sh "$__sp_f")
    if [ -z "$__sp_e2" ]; then
        sp_rec "$SP_CUR" "exec:$__sp_f" "ALLOW" "executed (via -h, --version unsupported)"
        return 0
    fi
    case "$__sp_e1 $__sp_e2" in
        *[Pp]ermission\ denied*|*"not permitted"*|*"cannot execute"*|*"cannot execute binary file"*)
            sp_rec "$SP_CUR" "exec:$__sp_f" "DENY" "$__sp_e1 | $__sp_e2" ;;
        *)
            sp_rec "$SP_CUR" "exec:$__sp_f" "UNKNOWN" "both --version and -h errored: $__sp_e1 | $__sp_e2" ;;
    esac
    return 0
}

# Tool availability: is this helper present and working on this host.
sp_have() {
    command -v "$1" >/dev/null 2>&1
}

# Require a helper. If missing, record UNKNOWN and return 1 so the caller
# skips rather than guessing. This is the rule that prevents false DENY.
sp_need() {
    if sp_have "$1"; then
        return 0
    fi
    sp_rec "$SP_CUR" "tool:$1" "UNKNOWN" "helper not present on this host; dependent probes skipped"
    return 1
}