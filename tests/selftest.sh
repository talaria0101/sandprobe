#!/bin/sh
# sandprobe self-tests.
#
# These test the probe's own logic, not the host it runs on. A probe that
# reports "DENY" because a tool was missing is worse than no probe, so every
# rule that prevents a false verdict gets a test that fails if the rule is
# removed.
#
# SPDX-License-Identifier: 0BSD

SP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PASS=0
FAIL=0
FAILURES=""

ok() {
    PASS=$((PASS + 1))
    printf '  ok   %s\n' "$1"
}

bad() {
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES
  $1: $2"
    printf '  FAIL %s\n     %s\n' "$1" "$2"
}

# check_equals <name> <expected> <actual>
check_equals() {
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        bad "$1" "expected [$2] got [$3]"
    fi
}

# check_contains <name> <needle> <haystack>
check_contains() {
    case "$3" in
        *"$2"*) ok "$1" ;;
        *) bad "$1" "output did not contain [$2]" ;;
    esac
}

# check_not_contains <name> <needle> <haystack>
check_not_contains() {
    case "$3" in
        *"$2"*) bad "$1" "output unexpectedly contained [$2]" ;;
        *) ok "$1" ;;
    esac
}

printf 'sandprobe self-tests\n\n'

WORK=$(mktemp -d "${TMPDIR:-/tmp}/sandprobe-selftest.XXXXXX") || exit 70
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

# shellcheck source=lib/core.sh
. "$SP_DIR/lib/core.sh"
SP_WORK="$WORK"
SP_CUR="test"
SP_BUDGET=5

printf 'verdict classification from real error text\n'
check_equals "EACCES is DENY"        DENY "$(sp_verdict_from_err 'sh: cannot create /x: Permission denied')"
check_equals "EPERM is DENY"         DENY "$(sp_verdict_from_err 'unshare: unshare failed: Operation not permitted')"
check_equals "EROFS is DENY"         DENY "$(sp_verdict_from_err 'sh: cannot create /usr/x: Read-only file system')"
check_equals "lowercase denied is DENY" DENY "$(sp_verdict_from_err 'mount: /tmp: permission denied.')"
check_equals "must be root is DENY"  DENY "$(sp_verdict_from_err 'mount: only root can do that, must be root')"
# "must be run from a terminal" is a usage complaint, not a refusal. Asserting
# it as DENY would bake in a wrong rule.
check_equals "terminal complaint is UNKNOWN" UNKNOWN "$(sp_verdict_from_err 'su: must be run from a terminal')"
check_equals "errno 13 is DENY"      DENY "$(sp_verdict_from_err 'PermissionError: [Errno 13] Permission denied')"
check_equals "ENOENT is ABSENT"      ABSENT "$(sp_verdict_from_err 'ls: cannot access: No such file or directory')"
check_equals "not a directory is ABSENT" ABSENT "$(sp_verdict_from_err 'Not a directory')"
check_equals "timeout is TIMEOUT"    TIMEOUT "$(sp_verdict_from_err 'curl: (28) operation timed out')"
check_equals "garbage is UNKNOWN"    UNKNOWN "$(sp_verdict_from_err 'something unexpected happened')"

# A bare "denied" is an English word, not a refusal. Matching it made any
# sentence containing it look like a security denial.
check_equals "policy note with 'denied' is not DENY" UNKNOWN \
    "$(sp_verdict_from_err 'mount denied because the filesystem is nosuid')"
check_equals "past-tense 'denied' is not DENY" UNKNOWN \
    "$(sp_verdict_from_err 'this mount was denied earlier, now retrying')"

# Resource exhaustion is not a policy denial. Blaming a sandbox boundary for a
# full disk is a false claim about where the limit is.
check_equals "ENOSPC is EXHAUSTED"   EXHAUSTED "$(sp_verdict_from_err 'No space left on device')"
check_equals "EMFILE is EXHAUSTED"    EXHAUSTED "$(sp_verdict_from_err 'Too many open files')"
check_equals "ENOMEM is EXHAUSTED"    EXHAUSTED "$(sp_verdict_from_err 'Cannot allocate memory')"
check_equals "ETXTBSY is EXHAUSTED"   EXHAUSTED "$(sp_verdict_from_err 'Text file busy')"
check_equals "empty is UNKNOWN"      UNKNOWN "$(sp_verdict_from_err '')"

printf '\nthe critical rule: a missing tool is never a denial\n'
# sp_need must return failure and record UNKNOWN, so callers skip rather than
# guess. This is the test that fails if sp_need ever records DENY.
OUT=$(sp_need definitely-not-a-real-binary-xyz 2>&1)
check_contains "missing tool records UNKNOWN" "UNKNOWN" "$OUT"
check_not_contains "missing tool is not DENY" "DENY" "$OUT"
sp_need definitely-not-a-real-binary-xyz >/dev/null 2>&1
check_equals "sp_need returns 1 when absent" 1 "$?"
sp_need ls >/dev/null 2>&1
check_equals "sp_need returns 0 when present" 0 "$?"

printf '\nsp_rec rejects an invented verdict\n'
OUT=$(sp_rec test "bogus" "MAYBE" "detail" 2>&1)
check_contains "invalid verdict becomes UNKNOWN" "UNKNOWN" "$OUT"
check_contains "invalid verdict is flagged as a bug" "INTERNAL BUG" "$OUT"

printf '\nsp_rec accepts every documented verdict\n'
for v in ALLOW DENY ABSENT UNKNOWN TIMEOUT EXHAUSTED UNRESOLVED REFUSED DROPPED; do
    OUT=$(sp_rec test "id" "$v" "d" 2>&1)
    check_contains "$v is passed through" "$v" "$OUT"
done

printf '\nhelper internals do not clobber caller variables\n'
# POSIX shell functions share one scope. If a helper used a short name that the
# caller also uses, the caller's value is destroyed. These fail if the
# reserved-namespace convention is dropped.
_d="/caller/compile/dir"
sp_rec test "x" "ALLOW" "detail" >/dev/null
check_equals "_d survives sp_rec" "/caller/compile/dir" "$_d"
_p="/caller/path"
sp_try_read "$WORK" >/dev/null
check_equals "_p survives sp_try_read" "/caller/path" "$_p"
_f="/caller/file"
sp_try_exists "$WORK" >/dev/null
check_equals "_f survives sp_try_exists" "/caller/file" "$_f"
_k="/caller/key"
sp_kv "plain_name" "value" >/dev/null
check_equals "_k survives sp_kv" "/caller/key" "$_k"
_sec="/caller/sec"
sp_verdict_from_err "Permission denied" >/dev/null
check_equals "_sec survives sp_verdict_from_err" "/caller/sec" "$_sec"

printf '\npath trimming\n'
check_equals "root stays root"        "/"     "$(sp_trim_slash /)"
check_equals "trailing slash removed"  "/tmp"  "$(sp_trim_slash /tmp/)"
check_equals "plain path unchanged"    "/tmp"  "$(sp_trim_slash /tmp)"
check_equals "empty becomes root"      "/"     "$(sp_trim_slash '')"
check_equals "double slash collapses"  "/"     "$(sp_trim_slash //)"

printf '\nredaction: secrets are removed, everything else survives\n'
# Test vectors are assembled at run time from a prefix and a filler string.
#
# Two reasons, and the second is the important one. First, a committed literal
# like a well-formed token prefix is indistinguishable from a live credential
# to secret scanning, and a repository that reprints secrets should not ship
# strings shaped like one. Second, a vector assembled here cannot be mistaken
# for a real token by anyone who later greps the history.
#
# The assembled strings are still exact: same prefix, same body, same length,
# so the regex under test is genuinely exercised rather than approximated.
_filler='abcdefghijklmnopqrstuvwxyz0123456789'
_gh_token()  { printf 'ghp_%s%s' "$_filler" "$_filler"; }
_gh_pat()    { printf 'github_pat_%s%s' "$_filler" "$_filler"; }
_aws()       { printf 'AKIA%s' 'ABCDEFGHIJKLMNOP'; }
_openai()    { printf 'sk-%s%s' "$_filler" "$_filler"; }
_anthropic() { printf 'sk-ant-%s%s' "$_filler" "$_filler"; }
_slack()     { printf 'xoxb-%s-%s' '123456789012' "$_filler"; }
_google()    { printf 'AIza%s' 'SyA1234567890abcdefghijklmnopqrstuv'; }
_jwt()       { printf '%s.%s.%s' 'eyJhbGciOiJIUzI1NiJ9' 'eyJzdWIiOiIxMjM0NTY3ODkwIn0' 'dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk'; }
_gitlab()    { printf 'glpat-%s%s' "$_filler" "$_filler"; }
_npm()       { printf 'npm_%s%s' "$_filler" "$_filler"; }
_gcp()       { printf 'ya29.%s' 'a0AfH6SMBxexampleExampletokenValue0123456789ab'; }

check_equals "secret name redacted" "MY_TOKEN = REDACTED" "$(sp_kv MY_TOKEN "$(_gh_token)")"
check_equals "api key name redacted" "SOME_API_KEY = REDACTED" "$(sp_kv SOME_API_KEY 'valuehere')"
check_equals "password name redacted" "DB_PASSWORD = REDACTED" "$(sp_kv DB_PASSWORD 'hunter2xyz')"
check_equals "github token shape redacted" "v = REDACTED" "$(sp_kv 'v' "$(_gh_token)")"
check_equals "github pat shape redacted" "v = REDACTED" "$(sp_kv 'v' "$(_gh_pat)")"
check_equals "aws key shape redacted" "v = REDACTED" "$(sp_kv 'v' "$(_aws)")"
check_equals "openai shape redacted" "v = REDACTED" "$(sp_kv 'v' "$(_openai)")"
check_equals "anthropic shape redacted" "v = REDACTED" "$(sp_kv 'v' "$(_anthropic)")"
check_equals "slack token redacted" "v = REDACTED" "$(sp_kv 'v' "$(_slack)")"
check_equals "google api key redacted" "v = REDACTED" "$(sp_kv 'v' "$(_google)")"
check_equals "jwt redacted" "v = REDACTED" "$(sp_kv 'v' "$(_jwt)")"
check_equals "gitlab token redacted" "v = REDACTED" "$(sp_kv 'v' "$(_gitlab)")"
check_equals "npm token redacted" "v = REDACTED" "$(sp_kv 'v' "$(_npm)")"
check_equals "gcp oauth redacted" "v = REDACTED" "$(sp_kv 'v' "$(_gcp)")"

printf '\nredaction must not touch non-secrets\n'
check_equals "git sha survives" "v = d8f1a4c2b7e93f6051a2c8d4e6f7091a3b5c7d9e" "$(sp_kv 'v' 'd8f1a4c2b7e93f6051a2c8d4e6f7091a3b5c7d9e')"
check_equals "uuid survives" "v = 01M427Q1D1AG7QKYRH6G3V1RSD" "$(sp_kv 'v' '01M427Q1D1AG7QKYRH6G3V1RSD')"
check_equals "url survives" "v = http://169.254.169.1:39799" "$(sp_kv 'v' 'http://169.254.169.1:39799')"
check_equals "version string survives" "v = 7.2.8_1-x86_64" "$(sp_kv 'v' '7.2.8_1-x86_64')"
check_equals "numeric id survives" "v = 1791077743" "$(sp_kv 'v' '1791077743')"
check_equals "home path survives" "v = /home/someuser/.local/bin" "$(sp_kv 'v' '/home/someuser/.local/bin')"
check_equals "author name survives" "GIT_AUTHOR_NAME = Not A Secret" "$(sp_kv GIT_AUTHOR_NAME 'Not A Secret')"
check_equals "kernel release survives" "v = 6.1.0-18-amd64" "$(sp_kv 'v' '6.1.0-18-amd64')"
check_equals "40-char hex survives" "v = 0123456789abcdef0123456789abcdef01234567" "$(sp_kv 'v' '0123456789abcdef0123456789abcdef01234567')"

printf '\nPEM private key block is collapsed\n'
PEM=$(printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\nMIIEowIBAAKCAQEAx\n-----END RSA PRIVATE KEY-----\nafter' | sp_scrub_pem)
check_contains "pem begin replaced" "[REDACTED_PRIVATE_KEY]" "$PEM"
check_not_contains "pem body gone" "MIIEowIBAAKCAQEAx" "$PEM"
check_contains "text after pem survives" "after" "$PEM"

printf '\nlive filesystem probes classify correctly\n'
# /tmp is writable in every sandbox this may run in; use it for the ALLOW case.
W=$(sp_try_write "${TMPDIR:-/tmp}"); check_contains "writable dir is ALLOW" "ALLOW" "$W"
R=$(sp_try_read "${TMPDIR:-/tmp}");     check_contains "readable dir is ALLOW" "ALLOW" "$R"
A=$(sp_try_exists "$WORK/no-such-file"); check_contains "absent file is ABSENT" "ABSENT" "$A"
R2=$(sp_try_read "$WORK/no-such-dir"); check_contains "absent dir is ABSENT" "ABSENT" "$R2"
E=$(sp_try_exec "$WORK/no-such-binary"); check_contains "absent binary is ABSENT" "ABSENT" "$E"
# A present, executable binary must never be reported as ABSENT. Whether it
# runs depends on this host's execute policy, so both outcomes are legitimate;
# what would be a bug is reporting absence or a timeout for a file that is
# plainly there.
sh -c 'printf "#!/bin/sh\nexit 0\n" > "$1"' sh "$WORK/runme" 2>/dev/null
chmod +x "$WORK/runme" 2>/dev/null
X=$(sp_try_exec "$WORK/runme")
XV=$(printf '%s' "$X" | cut -f3)
if [ "$XV" = "ALLOW" ] || [ "$XV" = "DENY" ]; then
    ok "present executable is ALLOW or DENY (got $XV)"
else
    bad "present executable is ALLOW or DENY" "got [$XV] from [$X]"
fi
# A binary that exists is never ABSENT, whatever the execute policy says.
check_not_contains "present executable is not ABSENT" "ABSENT" "$X"
# /bin/sh is guaranteed present on a POSIX host and must never be ABSENT.
XS=$(sp_try_exec /bin/sh)
check_not_contains "known-present shell is not ABSENT" "ABSENT" "$XS"

printf '\nwrite probe leaves nothing behind\n'
sp_try_write "${TMPDIR:-/tmp}" >/dev/null
LEFT=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name '.sandprobe-write-probe.*' 2>/dev/null | wc -l | tr -d ' ')
check_equals "no probe file remains in tmp" 0 "$LEFT"

printf '\nthe verdict vocabulary is closed\n'
# Any verdict outside the documented set must be impossible to emit.
BADV=$(sp_rec t i "SORTOFALLOWED" d)
check_contains "unknown verdict rejected" "INTERNAL BUG" "$BADV"
check_not_contains "unknown verdict not passed through" "SORTOFALLOWED" "$(printf '%s' "$BADV" | cut -f3)"

printf '\nreport.sh header documents the vocabulary\n'
HDR=$(sed -n '1,60p' "$SP_DIR/lib/report.sh")
for v in ALLOW DENY ABSENT UNKNOWN TIMEOUT; do
    check_contains "header documents $v" "$v" "$HDR"
done

printf '\nsources exist and the script is executable\n'
check_equals "sandprobe is executable" "yes" "$([ -x "$SP_DIR/sandprobe" ] && echo yes || echo no)"
for f in core.sh discover.sh execdir.sh report.sh sect_host.sh sect_security.sh \
         sect_fs.sh sect_env.sh sect_net.sh sect_exec.sh netprobe.py; do
    check_equals "lib/$f present" "yes" "$([ -f "$SP_DIR/lib/$f" ] && echo yes || echo no)"
done

printf '\nno escalation probe can succeed unconditionally\n'
# A probe built from a command that always exits 0 reports ALLOW while proving
# nothing, and that is the single most damaging class of defect in this tool:
# a reader sees a security test pass. Any sp_esc invocation whose command list
# starts with true, :, or a bare echo cannot fail, so those are rejected.
# Match a probe whose COMMAND ITSELF is the no-op, i.e. true, : or echo as the
# first argument after sp_esc's label. An 'echo' appearing later inside an
# sh -c fragment is part of a real test, not a stub.
UNCOND=$(grep -oE 'sp_esc "[^"]*"[[:space:]]+(true|:|echo)[[:space:]]' \
        "$SP_DIR"/lib/sect_*.sh 2>/dev/null | wc -l | tr -d ' ')
check_equals "no sp_esc uses an always-succeeding command" 0 "$UNCOND"

# Every escalation record must carry a non-empty detail, or the reader has
# nothing to check the verdict against.
NODETAIL=$(grep -oP '^escalation\t[^\t]*\t[A-Z]+\t\t*$' "$SP_DIR"/lib/sect_security.sh 2>/dev/null | wc -l | tr -d ' ')
check_equals "no empty detail on an escalation literal" 0 "$NODETAIL"

printf '\nfields are named for what they measure\n'
# securebits_hex once held the output of seccomp/actions_avail. Catch any
# field whose assignment reads a different file than its name.
MISNAMED=$(grep -nE 'sp_kv "[a-z_]*(securebits|selinux|apparmor|lsm)[a-z_]*".*actions_avail' \
        "$SP_DIR"/lib/*.sh 2>/dev/null | wc -l | tr -d ' ')
check_equals "no field reads seccomp actions but is named otherwise" 0 "$MISNAMED"

printf '\nCI workflow is well formed\n'
# container: ${{ matrix.container }} with an unset key interpolates to an empty
# string, which fails the job before any step runs.
BADCONT=$(grep -cE 'container: *\$\{\{' "$SP_DIR/.github/workflows/test.yml" 2>/dev/null | tr -d ' ')
check_equals "no interpolated container specifier" 0 "$BADCONT"
# Every path the workflow acts on must exist in the tree.
WF_MISSING=0
for wf_path in sandprobe tests/selftest.sh lib/netprobe.py README.md LICENSE; do
    [ -f "$SP_DIR/$wf_path" ] || WF_MISSING=$((WF_MISSING + 1))
done
check_equals "every path referenced by CI exists" 0 "$WF_MISSING"


printf '\nescalation probes repeat no command name\n'
# A call of the form sp_esc "label" sh sh -c ... executes argv [sh, sh, -c, SCRIPT].
# dash reads argv[1] as the script to run, so the payload never executes and the
# empty output classified as ALLOW. 20 probes were affected.
DOUBLED=$(grep -oE 'sp_esc "[^"]*"[[:space:]]+([A-Za-z0-9_./-]+)[[:space:]]+\1[[:space:]]' \
        "$SP_DIR"/lib/sect_security.sh 2>/dev/null | wc -l | tr -d ' ')
check_equals "no sp_esc call repeats its command name" 0 "$DOUBLED"

printf '\nno line continuation is a double backslash\n'
# "\\\\" at end of line is an escaped backslash, not a continuation. The shell
# ends the command there and runs the next line as a separate command, which
# produced records with empty targets and leaked shell errors to stderr.
DBLSLASH=$(grep -c '\\\\$' "$SP_DIR"/lib/*.sh 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
check_equals "no double-backslash line continuations" 0 "$DBLSLASH"

printf '\nno emission loop is fed by a pipe\n'
# A while loop fed by a pipe runs in a subshell. Any sp_rec or sp_kv inside it
# writes to a copy of stdout that is discarded, so records vanish while the
# report looks as though it has them.
PIPEDLOOP=$(grep -nE '\|[[:space:]]*while[[:space:]]+(IFS=)?read' "$SP_DIR"/lib/sect_*.sh 2>/dev/null | wc -l | tr -d ' ')
check_equals "no pipe into an emitting while loop" 0 "$PIPEDLOOP"

printf '\nno /proc/self inside a command substitution\n'
# /proc/self inside $( ) names the substituted child, so the field describes a
# cat or an awk rather than the probing process. It made ppid equal pid.
# Comments are excluded by stripping everything after an unquoted #, and
# /proc/self/root is excluded because it is a symlink: /proc/self and /proc/$$
# resolve to the same inode, so the substitution makes no difference there.
SELFSUB=0
for f in "$SP_DIR"/lib/*.sh; do
    n=$(sed -e 's/#.*$//' "$f" 2>/dev/null \
        | grep -cE '\$\(.*/proc/self/(mountinfo|status|limits|mounts|environ|f|cgroup|uid_map|gid_map|setgroups|ns/)' )
    SELFSUB=$((SELFSUB + n))
done
check_equals "no /proc/self inside a substitution" 0 "$SELFSUB"
# A redirection target inside $( ) has the same problem.
SELFred=$(grep -nE '\$\(.*<[[:space:]]*"?/proc/self' "$SP_DIR"/lib/*.sh 2>/dev/null | wc -l | tr -d ' ')
check_equals "no /proc/self as a substitution input" 0 "$SELFred"

printf '\ntruncation bounds the whole stream, not each line\n'
# cut -c1-N applies per line. Because a cmdline becomes many lines after
# NUL-to-space conversion, a "300 character" prefix emitted 12,089 bytes and
# inlined a supervisor prompt into a report meant to be shared.
# Comments excluded: the explanation of why per-line cut was removed mentions
# cut -c1-300.
PERCUTCUT=$(grep -vE '^[[:space:]]*#' "$SP_DIR"/lib/*.sh "$SP_DIR"/sandprobe 2>/dev/null \
        | grep -cE 'cut -c[0-9]+')
check_equals "no per-line cut truncation" 0 "$PERCUTCUT"

printf '\nno field is emitted with an empty target\n'
# A record whose id is empty cannot be acted on. This is the signature of a
# mangled multi-line command.
EMPTYID=$(grep -oE 'sp_rec "\$SP_CUR" ""|sp_rec "" ' "$SP_DIR"/lib/*.sh 2>/dev/null | wc -l | tr -d ' ')
check_equals "no sp_rec with a literal empty target" 0 "$EMPTYID"

printf '\nthe report has a verdict tally\n'
if [ -f "$SP_DIR/lib/report.sh" ]; then
    check_contains "summary function exists" "sp_emit_summary" \
        "$(cat "$SP_DIR/lib/report.sh")"
fi
DRV=$(cat "$SP_DIR/sandprobe")
check_contains "driver calls the summary" "sp_emit_summary" "$DRV"


printf '\nno record value spans a line\n'
# A value containing a newline splits one record into two. Two bugs of that
# shape shipped: `id -un 2>&1` captured a complaint and a uid together, and
# `grep -c ... || echo 0` produced the value "0\n0".
OUT=$(sp_kv "test" "one
two")
check_equals "sp_kv flattens a newline in the value" 1 "$(printf '%s\n' "$OUT" | wc -l | tr -d ' ')"
OUT=$(sp_kv "test" "$(printf 'a\tb')")
check_equals "sp_kv flattens a tab in the value" 1 "$(printf '%s\n' "$OUT" | wc -l | tr -d ' ')"
# The multi-line grep idiom that produced "0\n0" must not appear at all.
GREPC=$(grep -vE '^[[:space:]]*#' "$SP_DIR"/lib/*.sh 2>/dev/null \
        | grep -cE 'grep -c .*\|\| echo')
check_equals "no 'grep -c ... || echo N' idiom" 0 "$GREPC"

printf '\nthe verdict tally counts every record\n'
# The tally once matched an explicit list of section names and so hid the eight
# sections netprobe emits, dropping 64 of 729 records from the count.
if [ -r "$SP_WORK/tally.body" ]; then
    :
fi
TALLY=$(awk -F'\\t' '
    $3 ~ /^(ALLOW|DENY|ABSENT|UNKNOWN|TIMEOUT|EXHAUSTED|UNRESOLVED|REFUSED|DROPPED)$/ {
        n++
    }
    END { print n + 0 }
' "$SP_DIR/lib/report.sh" 2>/dev/null | head -1)
# The tally must not filter on a section list.
SECFILT=$(grep -c '\$1 ~ /\^(discover|host)' "$SP_DIR/lib/report.sh" 2>/dev/null || true)
check_equals "tally does not filter on a section list" 0 "$SECFILT"

printf '\nno bare expansion of a possibly unset variable at top level\n'
# `set -u` kills the shell when an unset variable is expanded outside a
# substitution, so an empty environment produced no report at all.
BARE=$(sed -e 's/#.*$//' "$SP_DIR"/lib/*.sh "$SP_DIR"/sandprobe 2>/dev/null \
       | grep -cE '[^:$"{]\$(HOME|USER|LOGNAME|TMPDIR|PATH|CARGO_HOME|RUSTUP_HOME)\b')
check_equals "no unguarded expansion of a set-u variable" 0 "$BARE"

printf '\nan option missing its argument is a usage error, not a crash\n'
# The guard ran after `shift`, so $1 was unset inside the error branch and
# set -u killed the shell with status 2 instead of the documented 64.
SB="$SP_DIR/sandprobe"
if [ -x "$SB" ]; then
    for opt in -o -s -b -p; do
        "$SB" "$opt" >/dev/null 2>&1
        rc=$?
        check_equals "missing argument for $opt exits 64" 64 "$rc"
    done
fi

printf '\nthe numeric uid is not treated as a user name\n'
# id -un prints the numeric uid and exits 0 when the host has no passwd entry,
# which produced /home/0 and 135 records for paths no account owns.
DIGITUSER=$(sed -e 's/#.*$//' "$SP_DIR/lib/discover.sh" 2>/dev/null | grep -cF '[!0-9]' || true)
check_equals "discovery filters an all-digit user name" 1 "$DIGITUSER"


printf '\ncredential shapes that previously leaked are redacted\n'
# Every one of these was found by review to pass through sp_scrub verbatim.
_leak_secrets() {
    cat <<'LEAKEOF'
password = hunter2xyz
PASSWORD_FILE=/etc/shadow
TOKEN = UpPeRcAsE0123456789
token=abc123456789
Token=x123456789
api_key = SomeValueWithoutRecognisableShape
api-key = x123456
apikey = x123456789
passphrase = aLongPassphrase123
AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY
DB_PASSWORD: hunter2xyz
USER_API_TOKEN = abc123456789
session_token = abc123456789
client_secret = abc123456789
auth_token = abcdefghijklmnop
access_token = abcdefghijklmnop
password="quotedsecret123"
https://user:password@host/path
postgres://user:hunter2hunter2@db:5432/app
mongodb+srv://user:password@host
LEAKEOF
}
LEAKOUT=$(_leak_secrets | sp_scrub)
check_equals "every input line still present" 20 "$(printf '%s\n' "$LEAKOUT" | grep -c .)"
_n=$(printf '%s\n' "$LEAKOUT" | grep -c 'REDACTED')
if [ "$_n" -ge 20 ]; then
    ok "every key=value credential form is redacted ($_n markers)"
else
    bad "every key=value credential form is redacted" "only $_n markers for 20 inputs"
fi
check_not_contains "no bare password value survives" "hunter2xyz" "$LEAKOUT"
check_not_contains "no aws secret value survives" "wJalrXUtnFEMIK7MDENG" "$LEAKOUT"
check_not_contains "no url password survives" "user:password@" "$LEAKOUT"

# The by-name layer walks the line with a memoised name-end index, so the name
# of a credential is read from a global copy of the line. Getting that wrong
# broke every by-name redaction while leaving the suite's shape-based tests
# green, because those do not reach try_kv at all. So the assertion is made
# directly, on the exact spacing forms that carry a secret name.
printf '\nthe by-name layer reaches every spacing form\n'
for _form in \
    'password=hunter2xyz' \
    'password =hunter2xyz' \
    'password= hunter2xyz' \
    'password = hunter2xyz' \
    'password: hunter2xyz' \
    'password : hunter2xyz' \
    'password	=hunter2xyz' \
    'PASSWORD=hunter2xyz' \
    'Api_Key=hunter2xyz' \
    'api-key =hunter2xyz' \
    'apikey= hunter2xyz'
do
    _o=$(printf '%s\n' "$_form" | sp_scrub)
    if [ "$_o" = "$_form" ]; then
        bad "by-name form redacted: [$_form]" "survived verbatim"
    else
        ok "by-name form redacted: [$_form]"
    fi
done

# The memoisation must not make the scrubber quadratic. A line of name
# characters used to cost O(n^2) because try_kv rescanned forward from every
# position: 16KB took 15.7s and 32KB did not finish inside a minute. A bound
# is asserted here so a future change that reintroduces the rescan fails a
# test rather than making the probe unusably slow on one long value.
_big=$(head -c 32768 /dev/zero | tr '\0' 'a')
_start=$(date +%s)
_bigout=$(printf '%s\n' "$_big" | sp_scrub)
_rc=$?
_end=$(date +%s)
_elapsed=$((_end - _start))
if [ "$_rc" -ne 0 ]; then
    bad "scrubbing a 32KB value completes" "rc=$_rc"
elif [ "$_elapsed" -gt 10 ]; then
    bad "scrubbing a 32KB value completes" "took ${_elapsed}s; the name scan is quadratic again"
else
    ok "scrubbing a 32KB value completes in ${_elapsed}s"
fi
# 32768, not 32769: $(...) strips the trailing newline, so the captured value
# is the 32768 input characters and nothing else.
check_equals "a 32KB benign value survives intact" 32768 "${#_bigout}"

# Fuzz the two directions. The fixtures above are hand-written, so they only
# cover the shapes somebody thought of. These generate the input, which is the
# only way to reach a spacing form or a run boundary that was not anticipated.
# The first asserts no credential value survives; the second asserts no benign
# value is touched. Both were seeded, so a failure is reproducible.
# Fuzz both directions. The fixtures above are hand-written, so they only cover
# the shapes somebody thought of. These generate the input, pipe it through the
# real scrubber, and assert on the output, which is the only way to reach a
# spacing form or a run boundary nobody anticipated. Seeded, so a failure is
# reproducible.
printf '\nfuzz: no credential survives, no benign value is touched\n'

# Direction one: 600 generated lines, ONE name=value pair per line, which is
# the shape every producer in this codebase emits. Every marker value carries an
# FZL prefix so a hit cannot be a coincidence with unrelated text.
#
# One pair per line is deliberate. An earlier version packed up to five pairs
# onto a line with unbalanced quotes, and every remaining "leak" it reported was
# an artefact of that: a first pair's unterminated quote legitimately swallowed a
# later pair's name, so the later value had no secret-bearing name left to be
# redacted by. That is the scrubber doing what the input asked. Asserting on it
# would have sent a reader hunting a bug that is not there, so the multi-pair
# case is a separate, explicitly-labelled assertion below.
#
# The values deliberately MIX two kinds. The shaped ones (FZLghp_, FZLAKIA, the
# JWT) are caught by the by-shape layer, so they keep that layer honest. The
# plain ones carry no recognisable token shape at all, so only the by-name layer
# can catch them; a version of this test that used shaped values alone passed
# with the by-name layer entirely disabled, which proved the test was not
# covering the layer it appeared to cover. The quoted entries carry an opening
# quote with no closing one, which is the shape that leaked a credential
# verbatim before that was fixed.
#
# A 40-character AWS secret access key is deliberately NOT in the shaped list.
# The shape list has no pattern for it, because matching on length alone would
# also match a 40-character git SHA, which the suite requires to survive.
FUZZ_LEAKS=$(python3 - <<'PYEOF' | sp_scrub | grep -c 'FZL'
import random

random.seed(20261004)
names = ["password", "PASSWORD", "token", "api_key", "apikey", "api-key",
         "secret", "AWS_SECRET_ACCESS_KEY", "client_secret", "passphrase",
         "bearer", "credential"]
# The marker goes INSIDE the token, never in front of it. A prefix breaks the
# token's own shape, so "FZLghp_..." matched no pattern and the generator
# reported a leak that was only its own marker surviving next to a correct
# redaction. That is how an earlier version of this test cried wolf.
shaped = ["ghp_ABCDEFGHIJKLMNOPQRSTUVWFZL012",
          "AKIAIOSFODNN7FZLMPLE",
          "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxI0FZL.abcdefghij",
          "glpat-ABCDEFGHIJKLMNFZLOP"]
plain = ["FZLhunter2", "FZLs3cr3tVALUE", "FZLunterminated", "FZLaB3ndl0fW0rds",
         "FZL1234567890", "FZLplainword"]
seps = ["=", " = ", ":", " : ", "\t="]
for _ in range(600):
    if random.random() < 0.3:
        # A shaped value, under a secret name or under an ordinary one, so the
        # by-shape layer is what has to catch it.
        name = random.choice(names) if random.random() < 0.5 else \
            random.choice(["note", "id", "url", "commit"])
        print("%s%s%s" % (name, random.choice(seps), random.choice(shaped)))
    else:
        # An unshaped value under a secret name, optionally quoted, so only the
        # by-name layer can catch it.
        q = random.choice(["", "", "", '"', "'"])
        print("%s%s%s%s" % (random.choice(names), random.choice(seps), q,
                            random.choice(plain)))
PYEOF
)
check_equals "fuzz: 600 generated secret lines leak nothing" 0 "$FUZZ_LEAKS"

# The multi-pair line, asserted directly rather than generated. Two secrets on
# one line where the first value is unquoted and a quote appears later: the
# second secret must still not survive. The value scan used to stop at the
# first space, so this emitted `PASSWORD:REDACTED = "hunter2` and printed a
# live credential.
MULTI='PASSWORD:seedvalue bearer = "FZLSECONDvalue'
_mo=$(printf '%s\n' "$MULTI" | sp_scrub)
case "$_mo" in
    *FZLSECONDvalue*) bad "a second secret on the same line is redacted" "survived: [$_mo]" ;;
    *) ok "a second secret on the same line is redacted" ;;
esac

# Two more direct assertions, because the fuzz corpus above does not isolate
# these two paths on its own. A mutant that switches the by-name layer off was
# NOT caught by the fuzz corpus once the generated values stopped carrying
# recognisable token shapes, so each layer now has an assertion of its own that
# names the layer.
for _pair in \
    'password=FZLPASS' \
    'PASSWORD = FZLPASS' \
    'client_secret:FZLPASS' \
    'api-key = FZLPASS' \
    'credential=FZLPASS' \
    'passphrase=FZLPASS' \
    'bearer=FZLPASS' \
    'apikey=FZLPASS'
do
    _po=$(printf '%s\n' "$_pair" | sp_scrub)
    case "$_po" in
        *FZLPASS*) bad "by-name layer redacts [$_pair]" "survived: [$_po]" ;;
        *) ok "by-name layer redacts [$_pair]" ;;
    esac
done
case "$_mo" in
    *REDACTED*) ok "the first pair on a multi-pair line is redacted" ;;
    *) bad "the first pair on a multi-pair line is redacted" "got [$_mo]" ;;
esac

# Direction two: 300 generated benign lines under names holding no secret word.
# Every one must come back byte-identical.
FUZZ_BENIGN=$(python3 - <<'PYEOF'
import random

random.seed(7)
values = [
    "d8f1a4c2b9e37a5f61d0c8b4e2a79f35c6d81b20",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "https://example.com/path?a=1&b=2",
    "user@example.com",
    "/usr/local/lib/libfoo.so.1.2.3",
    "GNU C Library stable release version 2.39.",
    "GIT_AUTHOR_NAME=Ajam",
    "SSH_AUTH_SOCK=/tmp/agent.sock",
    "v1.2.3-abc",
    "ordinary sentence with no secret in it whatsoever",
]
names = ["commit", "sum", "id", "url", "mail", "file", "note", "version",
         "user", "mode", "size"]
for _ in range(300):
    if random.random() < 0.5:
        print("%s=%s" % (random.choice(names), random.choice(values)))
    else:
        print(random.choice(values))
PYEOF
)
_fb_bad=$(printf '%s\n' "$FUZZ_BENIGN" | while IFS= read -r _l; do
    [ -n "$_l" ] || continue
    _o=$(printf '%s\n' "$_l" | sp_scrub)
    [ "$_o" = "$_l" ] || printf 'CHANGED\n'
done | grep -c CHANGED)
check_equals "fuzz: 300 generated benign lines are byte-identical after scrubbing" 0 "$_fb_bad"

printf '\nprovider token formats are redacted\n'
for _pfx in "ghp_" "github_pat_" "glpat-" "shpat_" "hvs." "dop_v1_" "npm_" "hf_" "r8_"; do
    _v="${_pfx}$(printf 'abcdefghijklmnopqrstuvwxyz0123456789')"
    check_equals "prefix $_pfx is redacted" "v = REDACTED" "$(sp_kv 'v' "$_v")"
done
check_equals "aws AKIA key is redacted" "v = REDACTED" "$(sp_kv 'v' "$(printf 'AKIA%s' 'ABCDEFGHIJKLMNOP')")"
check_equals "google api key is redacted" "v = REDACTED" "$(sp_kv 'v' "$(printf 'AIza%s' 'SyA1234567890abcdefghijklmnopqrstuv')")"
check_equals "openai project key is redacted" "v = REDACTED" "$(sp_kv 'v' "$(printf 'sk-proj-%s' 'abcdefghijklmnopqrstuvwx')")"
check_equals "stripe live key is redacted" "v = REDACTED" "$(sp_kv 'v' "$(printf 'sk_live_%s' 'abcdefghijklmnopqrstuvwx')")"

printf '\nheaders carrying credentials are redacted\n'
_H1=$(printf 'Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l' | sp_scrub)
check_not_contains "authorization basic value gone" "YWxhZGRpbjpvcGVuc2VzYW1l" "$_H1"
_H2=$(printf 'Cookie: session=abcdefghijklmnopqrst' | sp_scrub)
check_not_contains "cookie value gone" "abcdefghijklmnopqrst" "$_H2"

printf '\nPEM private key blocks of every real label are collapsed\n'
for _lbl in "RSA PRIVATE KEY" "PRIVATE KEY" "EC PRIVATE KEY" "OPENSSH PRIVATE KEY" \
            "ENCRYPTED PRIVATE KEY" "PGP PRIVATE KEY BLOCK" "PGP SECRET KEY BLOCK" \
            "SSH2 ENCRYPTED PRIVATE KEY" "DSA PRIVATE KEY"; do
    _p=$(printf -- "-----BEGIN %s-----\nSECRETBODY\n-----END %s-----\nafter\n" "$_lbl" "$_lbl" | sp_scrub_pem)
    check_not_contains "label '$_lbl' body removed" "SECRETBODY" "$_p"
    check_contains "label '$_lbl' collapsed to marker" "[REDACTED_PRIVATE_KEY]" "$_p"
    check_contains "label '$_lbl' text after survives" "after" "$_p"
done

printf '\nPEM blocks that are not secret are preserved\n'
for _lbl in "PUBLIC KEY" "CERTIFICATE" "PGP MESSAGE" "PGP SIGNATURE"; do
    _p=$(printf -- "-----BEGIN %s-----\nBODY\n-----END %s-----\n" "$_lbl" "$_lbl" | sp_scrub_pem)
    check_contains "label '$_lbl' preserved" "BODY" "$_p"
done

printf '\nan unterminated PEM marker cannot swallow the document\n'
UNTERM=$(printf 'first line\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\nlast line\n' | sp_scrub_pem)
check_contains "text before survives" "first line" "$UNTERM"
check_contains "text after an unterminated marker survives" "last line" "$UNTERM"

printf '\nthe scrubber is found and fails loudly when missing\n'
if [ -n "${SP_SCRUB_AWK:-}" ] && [ -f "$SP_SCRUB_AWK" ]; then
    ok "scrubber resolved to $SP_SCRUB_AWK"
else
    bad "scrubber resolved" "SP_SCRUB_AWK=[${SP_SCRUB_AWK:-unset}] is not a file"
fi
# core.sh resolves SP_SCRUB_AWK at source time, so the value is set again after
# sourcing; a leading -v would be read by sh as an option.
MISSING=$(sh -c '. "$1"; SP_SCRUB_AWK=/nonexistent/nope; printf "x=1\n" | sp_scrub >/dev/null' sh "$SP_DIR/lib/core.sh" 2>&1)
check_contains "missing scrubber is reported" "scrubber missing" "$MISSING"
MISSRC=$(sh -c '. "$1"; SP_SCRUB_AWK=/nonexistent/nope; printf "x=1\n" | sp_scrub; echo rc=$?' sh "$SP_DIR/lib/core.sh" 2>&1)
check_contains "missing scrubber exits non-zero" "rc=1" "$MISSRC"

printf '\nno hardcoded host identity in the library\n'
# A username, session id or project path baked into the probe would make the
# report wrong on any other host.
# Scan for identifiers belonging to the machine this was written on. Comments
# are stripped first: a comment may explain the shape of a path without
# depending on it, and flagging prose would train a reader to ignore the check.
HITS=$(grep -rvE '^[[:space:]]*#' "$SP_DIR"/lib/*.sh "$SP_DIR"/lib/*.py \
        "$SP_DIR/sandprobe" 2>/dev/null \
        | grep -cE 'qaidvoid|xphatty[0-9]|pi-projects|\.local/state/errand')
check_equals "no host-specific identifiers in source" 0 "$HITS"

printf '\nsh syntax check on every shell file\n'
for f in "$SP_DIR/sandprobe" "$SP_DIR"/lib/*.sh "$SP_DIR"/tests/*.sh; do
    [ -f "$f" ] || continue
    if sh -n "$f" 2>/dev/null; then
        ok "sh -n $(basename "$f")"
    else
        bad "sh -n $(basename "$f")" "syntax error"
    fi
done
if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$SP_DIR/lib/netprobe.py" 2>/dev/null; then
        ok "netprobe.py parses"
    else
        bad "netprobe.py parses" "python syntax error"
    fi
fi

printf '\n----------------------------------------\n'
printf 'passed: %d\nfailed: %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'failures:%s\n' "$FAILURES"
    exit 1
fi
printf 'all self-tests passed\n'
exit 0