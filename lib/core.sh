#!/bin/sh
# sandprobe core: verdict vocabulary, redaction, hermetic workdir, probe helpers.
# Sourced by the top-level script. Not executable on its own.
# SPDX-License-Identifier: 0BSD

SP_VERSION="1.0.0"

# Directory holding the library, resolved once so every section can find the
# bundled helpers regardless of the caller's working directory.
SP_LIB_DIR=${SP_LIB_DIR:-$(CDPATH= cd -- "$(dirname -- "${0}")" 2>/dev/null && pwd)}

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

# Names denoting a secret. Anchored on word boundaries via case globs so that
# GIT_AUTHOR_NAME is not mistaken for an auth credential.
sp_secret_name() {
    case "$1" in
        TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|\
        CREDENTIAL|CREDENTIALS|AUTH_TOKEN|BEARER|SESSION_TOKEN|CLIENT_SECRET|\
        SIGNING_KEY|ENCRYPTION_KEY|LICENSE_KEY|HMAC|SALT|\
        *_TOKEN|*_TOKEN_*|*_SECRET|*_SECRET_*|*_PASSWORD|*_PASSWD|\
        *_API_KEY|*_APIKEY|*_ACCESS_KEY|*_PRIVATE_KEY|*_CREDENTIAL|*_CREDENTIALS|\
        *_AUTH_TOKEN|*_BEARER|*_SESSION_TOKEN|*_CLIENT_SECRET|*_SIGNING_KEY|\
        *_ENCRYPTION_KEY|*_LICENSE_KEY|*_HMAC|*_SALT|\
        *_TOKEN_|*_SECRET_|*_PASSWORD_|*_API_KEY_|*_CREDENTIAL_*)
            return 0 ;;
    esac
    return 1
}

# Redact token-shaped substrings in arbitrary text, stdin to stdout.
# Each pattern below is a documented credential format. Narrow on purpose so
# that ordinary hashes, UUIDs, addresses and prose are never touched.
sp_scrub() {
    sed -E \
        -e 's/gh[pousr]_[A-Za-z0-9]{16,}/REDACTED/g' \
        -e 's/github_pat_[A-Za-z0-9_]{20,}/REDACTED/g' \
        -e 's/glpat-[A-Za-z0-9_-]{16,}/REDACTED/g' \
        -e 's/(AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}/REDACTED/g' \
        -e 's/sk-ant-[A-Za-z0-9_-]{16,}/REDACTED/g' \
        -e 's/sk-[A-Za-z0-9]{20,}/REDACTED/g' \
        -e 's/xox[baprse]-[A-Za-z0-9-]{10,}/REDACTED/g' \
        -e 's/AIza[A-Za-z0-9_-]{30,}/REDACTED/g' \
        -e 's/ya29\.[A-Za-z0-9_-]{20,}/REDACTED/g' \
        -e 's/npm_[A-Za-z0-9]{30,}/REDACTED/g' \
        -e 's/hf_[A-Za-z0-9]{30,}/REDACTED/g' \
        -e 's/r8_[A-Za-z0-9]{30,}/REDACTED/g' \
        -e 's/dop_v1_[A-Za-z0-9]{30,}/REDACTED/g' \
        -e 's/SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/REDACTED/g' \
        -e 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/REDACTED/g' \
        -e 's/([Aa]uthorization:[[:space:]]*(Bearer|Basic|Token|Digest)[[:space:]]+)[A-Za-z0-9._~+\/=-]{8,}/\1REDACTED/g' \
        -e 's/(([Pp]assword|[Pp]asswd|[Ss]ecret|[Tt]oken|[Aa]pi[_-]?[Kk]ey|[Ss]ecret[_-]?[Kk]ey)[=:][[:space:]]*)[^[:space:]&;"'"'"']{6,}/\1REDACTED/g' \
        2>/dev/null
}

# Scrub a PEM private key block, collapsing it to a marker.
sp_scrub_pem() {
    awk '
        /-----BEGIN [A-Z ]*PRIVATE KEY-----/ {
            inblock = 1
            print "[REDACTED_PRIVATE_KEY]"
            next
        }
        /-----END [A-Z ]*PRIVATE KEY-----/ { inblock = 0; next }
        inblock { next }
        { print }
    '
}

# Key/value line. Redacted wholesale when the key denotes a secret, otherwise
# the value is scrubbed for embedded token shapes.
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