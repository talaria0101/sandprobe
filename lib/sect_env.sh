#!/bin/sh
# sandprobe section: environment variables, argv, config files, git identity.
# SPDX-License-Identifier: 0BSD

SP_ENV_SENSITIVE_HINT="redaction applies to names denoting secrets, and to
documented credential token shapes found inside otherwise normal values.
Every other variable value is reported verbatim, including URLs, hostnames,
paths and counts."

sp_section_env() {
    SP_CUR="env"

    printf '\n## ENVIRONMENT\n\n'
    sp_raw "# redacted: names denoting secrets, plus credential token shapes."
    sp_raw "# verbatim: every other value, including proxy URLs and paths."
    sp_raw "# ---"
    # env may be absent in a stripped environment; fall back to /proc/self/environ.
    if sp_have env; then
        env 2>/dev/null | LC_ALL=C sort | while IFS= read -r line; do
            _name=${line%%=*}
            case "$line" in
                *=*) sp_kv "$_name" "${line#*=}" ;;
                *)   sp_raw "$line" ;;
            esac
        done
    elif [ -r "/proc/$$/environ" ]; then
        sp_rec "$SP_CUR" "env_source" "UNKNOWN" "env(1) absent; fell back to /proc/self/environ"
        tr '\0' '\n' < "/proc/$$/environ" 2>/dev/null | LC_ALL=C sort | while IFS= read -r line; do
            _name=${line%%=*}
            case "$line" in
                *=*) sp_kv "$_name" "${line#*=}" ;;
                *)   sp_raw "$line" ;;
            esac
        done
    else
        sp_rec "$SP_CUR" "environment" "UNKNOWN" "neither env(1) nor /proc/self/environ readable"
    fi

    printf '\n## SECRET-BEARING VARIABLE INVENTORY\n\n'
    sp_raw "# Names only. Values are never printed here."
    _found=0
    for n in $(env 2>/dev/null | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' | LC_ALL=C sort); do
        if sp_secret_name "$n"; then
            sp_kv "secret_var_present" "$n"
            _found=1
        fi
    done
    [ "$_found" -eq 0 ] && sp_raw "# no variable name in this environment denotes a secret"

    printf '\n## TOKEN SHAPES PRESENT IN ENVIRONMENT\n\n'
    sp_raw "# Presence only. This proves the redaction layer has work to do and"
    sp_raw "# that the layer did it, without disclosing any value."
    _hits=$(env 2>/dev/null | sed -n 's/^[A-Za-z_][A-Za-z0-9_]*=//p' | grep -oE \
        'gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9]{20,}|xox[baprse]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{30,}|ya29\.[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{30,}|r8_[A-Za-z0-9]{30,}|dop_v1_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' \
        2>/dev/null | sed -E 's/^(gh[pousr]|github_pat|glpat|AKIA|sk|xox|AIza|ya29|npm|hf|r8|dop_v1|SG|eyJ).*/\1.../' | LC_ALL=C sort -u)
    if [ -n "$_hits" ]; then
        printf '%s\n' "$_hits" | while IFS= read -r h; do
            sp_kv "token_shape_present" "$h"
        done
    else
        sp_raw "# no recognised credential token shape found in environment values"
    fi

    printf '\n## ARGV AND PARENT CHAIN\n\n'
    sp_kv "self_argv" "$(tr '\0' ' ' < "/proc/$$/cmdline" 2>/dev/null)"
    # pid 1 is often a supervisor carrying a very large argument vector.
    #
    # Truncation is on the byte stream, not per line. `cut -c1-300` applies to
    # each line independently, and because NUL-to-space conversion turns this
    # cmdline into many lines, an earlier version emitted 12,089 bytes from a
    # "300 character" limit and inlined the supervisor's whole prompt into a
    # report intended to be shared.
    #
    # head -c bounds the input before any conversion, so the result is
    # genuinely bounded. The total size is reported alongside, so nothing is
    # hidden, only not inlined.
    sp_kv "pid1_executable" "$(tr '\0' '\n' < /proc/1/cmdline 2>/dev/null | head -1 || echo UNREADABLE)"
    sp_kv "pid1_argc" "$(tr '\0' '\n' < /proc/1/cmdline 2>/dev/null | grep -c . || echo UNREADABLE)"
    sp_kv "pid1_argv_bytes" "$(wc -c < /proc/1/cmdline 2>/dev/null | tr -d ' ' || echo UNREADABLE)"
    sp_kv "pid1_argv_prefix_120b" "$(head -c 120 /proc/1/cmdline 2>/dev/null | tr '\0' ' ' || echo UNREADABLE)"
    sp_kv "pid1_argv_truncated" "$(
        _tot=$(wc -c < /proc/1/cmdline 2>/dev/null | tr -d ' ')
        if [ -n "$_tot" ] && [ "$_tot" -gt 120 ]; then
            printf 'yes: %s bytes of argv, 120 inlined; the remainder is deliberately not copied into the report\n' "$_tot"
        else
            printf 'no: argv is %s bytes\n' "${_tot:-unknown}"
        fi
    )"
    sp_kv "pid1_exe" "$(readlink /proc/1/exe 2>/dev/null || echo UNREADABLE)"
    sp_kv "self_exe" "$(readlink "/proc/$$/exe" 2>/dev/null || echo UNREADABLE)"
    sp_kv "self_cwd" "$(readlink "/proc/$$/cwd" 2>/dev/null || echo UNREADABLE)"
    sp_kv "pid1_cwd" "$(readlink /proc/1/cwd 2>/dev/null || echo UNREADABLE)"
    sp_kv "ppid_comm" "$(cat "/proc/$(awk '/^PPid/{print $2}' /proc/$$/status 2>/dev/null)/comm" 2>/dev/null || echo UNREADABLE)"
    # Walk the ancestry, bounded, so a host-side supervisor chain is visible
    # when it is visible at all.
    _p=$$
    _depth=0
    while [ "$_p" -gt 0 ] && [ "$_depth" -lt 12 ] 2>/dev/null; do
        _c=$(cat "/proc/$_p/comm" 2>/dev/null || echo "?")
        sp_kv "ancestor_$_depth" "pid=$_p comm=$_c"
        _p=$(awk '/^PPid/{print $2}' "/proc/$_p/status" 2>/dev/null || echo 0)
        _depth=$((_depth+1))
    done

    printf '\n## RESOLVER AND NETWORK CONFIG FILES\n\n'
    for f in /etc/resolv.conf /etc/hosts /etc/host.conf /etc/nsswitch.conf /etc/services /etc/protocols /etc/gai.conf; do
        if [ -r "$f" ]; then
            sp_rec "$SP_CUR" "config:$f" "ALLOW" "readable"
            sp_raw "# --- $f"
            cat "$f" 2>/dev/null | sp_scrub
        elif [ -e "$f" ]; then
            sp_rec "$SP_CUR" "config:$f" "DENY" "present but not readable"
        else
            sp_rec "$SP_CUR" "config:$f" "ABSENT" "not present"
        fi
    done

    printf '\n## LOCALE AND TIMEZONE\n\n'
    sp_kv "locale" "$(locale 2>&1 | tr '\n' ' ' || echo 'locale(1) absent')"
    sp_kv "timezone_link" "$(readlink /etc/localtime 2>/dev/null || echo 'absent or unreadable')"
    if [ -r /etc/localtime ]; then
        sp_rec "$SP_CUR" "localtime_file" "ALLOW" "present"
    fi

    printf '\n## GIT IDENTITY AND CREDENTIAL CONFIG\n\n'
    for f in "${HOME:-/nonexistent}/.gitconfig" "${HOME:-/nonexistent}/.config/git/config" /etc/gitconfig /usr/etc/gitconfig; do
        if [ -r "$f" ]; then
            sp_rec "$SP_CUR" "gitconfig:$f" "ALLOW" "readable"
            sp_raw "# --- $f  (credential helper lines are shown; no secret is stored here)"
            cat "$f" 2>/dev/null | sp_scrub
        elif [ -e "$f" ]; then
            sp_rec "$SP_CUR" "gitconfig:$f" "DENY" "present but not readable"
        else
            sp_rec "$SP_CUR" "gitconfig:$f" "ABSENT" "not present"
        fi
    done
    sp_kv "git_config_system" "$(git config --system --list 2>/dev/null | tr '\n' ' ' || echo 'git absent or system config unreadable')"
    sp_kv "git_config_global" "$(git config --global --list 2>/dev/null | tr '\n' ' ' || echo 'git absent or global config unreadable')"

    printf '\n## CREDENTIAL STORES: EXISTENCE ONLY\n\n'
    sp_raw "# Existence is recorded. Contents are never read or printed."
    # Derived: every discovered home plus the system-wide stores.
    : > "$SP_WORK/credstores"
    for b in .git-credentials .netrc .npmrc .pypirc .docker/config.json \
             .aws/credentials .config/gh/hosts.yml .kube/config \
             .cargo/credentials .gnupg; do
        printf '/etc/%s\n' "$b" >> "$SP_WORK/credstores"
    done
    printf '%s\n' "$SP_SENSITIVE_BASENAMES" | tr ' ' '\n' | grep -v '^$' \
        | while IFS= read -r b; do
            printf '%s/%s\n' "${HOME:-/nonexistent}" "$b" >> "$SP_WORK/credstores"
        done
    printf '%s\n' "$SP_CANDIDATE_HOMES" | sed '/^$/d' \
        | while IFS= read -r h; do
            printf '%s/.git-credentials\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.netrc\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.npmrc\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.pypirc\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.docker/config.json\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.aws/credentials\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.config/gh/hosts.yml\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.kube/config\n' "$h" >> "$SP_WORK/credstores"
            printf '%s/.cargo/credentials\n' "$h" >> "$SP_WORK/credstores"
        done
    printf '%s\n' /etc/shadow /etc/gshadow /etc/sudoers >> "$SP_WORK/credstores"
    LC_ALL=C sort -u "$SP_WORK/credstores" | grep -v '^$' | while IFS= read -r f; do
        if [ -e "$f" ]; then
            if [ -r "$f" ]; then
                sp_rec "$SP_CUR" "credsfile:$f" "ALLOW" "PRESENT AND READABLE (contents not printed)"
            else
                sp_rec "$SP_CUR" "credsfile:$f" "DENY" "present, not readable"
            fi
        else
            sp_rec "$SP_CUR" "credsfile:$f" "ABSENT" "not present"
        fi
    done

    printf '\n## PATH RESOLUTION\n\n'
    _oldifs=$IFS
    IFS=:
    for d in ${PATH:-}; do
        [ -n "$d" ] || d="(empty entry)"
        if [ -d "$d" ]; then
            if [ -w "$d" ]; then
                sp_kv "path_dir" "$d  [exists, WRITABLE]"
            else
                sp_kv "path_dir" "$d  [exists, read-only]"
            fi
        else
            sp_kv "path_dir" "$d  [DOES NOT EXIST]"
        fi
    done
    IFS=$_oldifs
}