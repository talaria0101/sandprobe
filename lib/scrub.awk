#!/usr/bin/env awk -f
#
# sandprobe credential scrubber.
#
# Written in awk rather than one sed expression because the job needs three
# things POSIX ERE does not give:
#
#   * case folding without the non-portable I flag, and without the conflict
#     between an I flag and explicit per-character case classes
#   * a substring test on a captured name, so a compound such as
#     AWS_SECRET_ACCESS_KEY is recognised by containing SECRET
#   * delimiters spelled out rather than written as a character range
#
# Failures of earlier attempts, recorded so the ground is not covered again:
#
#   * A sed class such as [_ -] is a RANGE from _ to space. It matched
#     punctuation and swallowed the separator, so several forms stopped being
#     redacted at all.
#   * The GNU I flag is not portable and conflicted with explicit case classes.
#   * sed alternation is leftmost-first, so listing PASSWORD before PASSPHRASE
#     meant PASSWORD matched the first seven characters of PASSPHRASE.
#   * awk's gsub returns a count, not the string, so `line = gsub(...)` replaced
#     every line of the report with a number.
#   * Matching in place and re-scanning truncated the matcher's own output,
#     because the replacement was fed back into the pattern.
#
# Approach: the line is walked once, left to right. At each position either a
# URL is consumed whole, or a name=value pair is consumed, or the character is
# copied through. Nothing is matched in place and re-scanned.
#
# One line in, one line out. No state carries between lines.

BEGIN {
    nkey = split(ENVIRON["SANDPROBE_KEYWORDS"], KEYW, "|")
    nshape = split(ENVIRON["SANDPROBE_SHAPES"], SHAPE, "\n")
}

# Is any keyword a substring of this name? Case folded.
function secret_name(n,   l, i) {
    l = tolower(n)
    for (i = 1; i <= nkey; i++) {
        if (KEYW[i] == "") continue
        if (index(l, KEYW[i]) > 0) return 1
    }
    return 0
}

# Replace every occurrence of a documented token shape with REDACTED.
function redact_shapes(s,   i, pat, result) {
    result = s
    for (i = 1; i <= nshape; i++) {
        pat = SHAPE[i]
        if (pat == "") continue
        while (match(result, pat) > 0) {
            result = substr(result, 1, RSTART - 1) "REDACTED" substr(result, RSTART + RLENGTH)
        }
    }
    return result
}

# Consume a URL at the start of s. Replaces the password in the authority when
# one is present. Sets URL_OUT and URL_LEN. Returns 0 when s is not a URL.
#
# The URL is consumed whole so that no later pass can read part of its
# authority as a name/value pair. That is what truncated these before:
# `postgres://app:REDACTED@host` was read as name `postgres://app` and value
# `REDACTED@host`, and everything after the @ was discarded.
function scrub_url(s,   n, i, start, scheme, authority, rest_of, at, colon, out, user, hostport) {
    n = length(s)
    i = 1
    if (substr(s, i, 1) !~ /[A-Za-z]/) return 0
    while (i <= n && substr(s, i, 1) ~ /[A-Za-z0-9+.-]/) i++
    scheme = substr(s, 1, i - 1)
    if (substr(s, i, 3) != "://") return 0
    i += 3
    start = i
    while (i <= n && substr(s, i, 1) !~ /[/?#]/) i++
    authority = substr(s, start, i - start)
    if (authority == "") return 0

    at = index(authority, "@")
    if (at > 0) {
        user = substr(authority, 1, at - 1)
        hostport = substr(authority, at + 1)
        colon = index(user, ":")
        if (colon > 0) user = substr(user, 1, colon - 1) ":REDACTED"
        out = scheme "://" user "@" hostport
    } else {
        out = scheme "://" authority
    }
    # The path, query and fragment are copied unchanged.
    out = out substr(s, i)
    URL_OUT = out
    # The span of the INPUT that was consumed, which is not the length of the
    # output: redaction shortens the text, so advancing by length(out) re-read
    # the tail and duplicated it.
    URL_CONSUMED = length(s)
    return 1
}

# Consume a name=value pair at position start. Sets KV_OUT and KV_LEN.
# Returns 0 when there is no secret-bearing pair there.
function try_kv(s, start,   n, i, c, name, sep, j, value, tail) {
    n = length(s)

    # The name may not follow ':' or '/', so the authority inside a URL is never
    # read as a name. The URL pass runs first, so this is belt and braces.
    if (start > 1) {
        c = substr(s, start - 1, 1)
        if (c == ":" || c == "/") return 0
    }
    if (substr(s, start, 1) !~ /[A-Za-z0-9_]/) return 0

    i = start
    while (i <= n && substr(s, i, 1) ~ /[A-Za-z0-9_.-]/) i++
    name = substr(s, start, i - start)

    j = i
    while (j <= n && substr(s, j, 1) ~ /[ \t]/) j++
    if (j > n) return 0
    c = substr(s, j, 1)
    if (c != "=" && c != ":") return 0
    if (c == ":") {
        # A colon that opens "://" is a URL, not a separator.
        if (substr(s, j, 3) == "://") return 0
        sep = ":"
    } else {
        sep = "="
    }
    j++
    while (j <= n && substr(s, j, 1) ~ /[ \t]/) {
        sep = sep " "
        j++
    }

    if (!secret_name(name)) return 0
    if (j > n) return 0
    c = substr(s, j, 1)
    if (c ~ /[ \t]/) return 0

    # A quoted value keeps its quotes and loses only its content.
    q = ""
    if (substr(s, j, 1) == "\"" || substr(s, j, 1) == "'") {
        q = substr(s, j, 1)
        j++
        startq = j
        while (j <= n && substr(s, j, 1) != q) j++
        if (j > n) return 0
        value = substr(s, startq, j - startq)
        j++
        KV_OUT = name sep q "REDACTED" q
        KV_CONSUMED = j - start
        return 1
    }

    value = ""
    tail = ""
    while (j <= n && substr(s, j, 1) !~ /[ \t]/) {
        c = substr(s, j, 1)
        # A closing bracket or brace delimits the value rather than belonging
        # to it, so it is preserved.
        if (c ~ /[),\]}>;]/) {
            tail = c
            j++
            break
        }
        value = value c
        j++
    }
    if (value == "") return 0
    KV_OUT = name sep "REDACTED" tail
    # Input span consumed, which differs from the output length for the same
    # reason as URL_CONSUMED.
    KV_CONSUMED = j - start
    return 1
}

{
    s = $0
    out = ""
    i = 1
    n = length(s)

    while (i <= n) {
        if (substr(s, i, 6) ~ /^[A-Za-z][A-Za-z0-9+.-]*:/) {
            u = substr(s, i)
            if (scrub_url(u)) {
                out = out URL_OUT
                i += URL_CONSUMED
                continue
            }
        }
        if (try_kv(s, i)) {
            out = out KV_OUT
            i += KV_CONSUMED
            continue
        }
        out = out substr(s, i, 1)
        i++
    }

    line = out

    line = redact_shapes(line)

    # Authorization style headers carrying a scheme word.
    while (match(line, /([Aa]uthorization|[Pp]roxy-[Aa]uthorization)[ \t]*:[ \t]*(Bearer|Basic|Token|Digest)[ \t]+[^ \t;]+/) > 0) {
        m = substr(line, RSTART, RLENGTH)
        p = index(m, ":")
        tail = substr(m, p + 1)
        sub(/^[ \t]*/, "", tail)
        w = substr(tail, 1, index(tail, " ") - 1)
        line = substr(line, 1, RSTART - 1) substr(m, 1, p) " " w " REDACTED" \
               substr(line, RSTART + RLENGTH)
        break
    }

    # Cookie headers.
    while (match(line, /([Cc]ookie|[Ss]et-[Cc]ookie)[ \t]*:[ \t]*[^ \t]+/) > 0) {
        m = substr(line, RSTART, RLENGTH)
        p = index(m, ":")
        line = substr(line, 1, RSTART - 1) substr(m, 1, p) " REDACTED" \
               substr(line, RSTART + RLENGTH)
        break
    }

    print line
}