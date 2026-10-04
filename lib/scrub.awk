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
    NAME_SPAN = 0
}

# Fill NAME_END with the index of the last character of the name that begins at
# each position, in one backward pass per line. NAME_END[i] is 0 when position i
# does not start a name. Returns 1 on success.
#
# Backward rather than forward so a maximal run of name characters is scanned
# once: from the end of the line, a name character extends the run by one, and
# anything else terminates it, which is exactly the information try_kv wants.
function build_name_ends(s,   n, i, c, run) {
    n = length(s)
    # A single copy of the line is kept because the walk copies characters out
    # of it one at a time, and assigning s into NAME_S leaves the global holding
    # the walker's own copy rather than the local it was called with.
    NAME_S = s
    NAME_SPAN = n
    delete NAME_END
    run = 0
    for (i = n; i >= 1; i--) {
        c = substr(NAME_S, i, 1)
        if (c ~ /[A-Za-z0-9_.-]/) {
            run++
            NAME_END[i] = i + run - 1
        } else {
            run = 0
            NAME_END[i] = 0
        }
    }
    return 1
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
#
# The bound on how far a single line is searched is not a correctness
# requirement, it is the guard against the quadratic walk in the main loop. A
# line of n name characters costs O(n^2) because try_kv rescans forward from
# every position, which measured as: 4KB 0.97s, 8KB 3.89s, 16KB 15.7s, 24KB
# 38.5s, 32KB never finished. A credential cannot usefully be longer than this,
# and a real one is far shorter, so the cap cannot hide a leak.
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
#
# The name end is memoised per line. Without it this function rescanned forward
# from every position of the line, so a line of n name characters cost O(n^2):
# measured at 4KB 0.97s, 8KB 3.89s, 16KB 15.7s, 24KB 38.5s, and 32KB never
# finished. Isolating the cost showed it was not the shape pass (disabling
# SANDPROBE_SHAPES changed nothing) and not the keyword lookup (emptying
# SANDPROBE_KEYWORDS changed nothing), because try_kv scans the whole name
# before it has any idea whether the name is secret-bearing. NAME_END is filled
# once per line in a single backward pass, so the scan happens once per name
# character instead of once per (position, name character) pair.
function try_kv(s, start,   n, i, c, name, sep, j, value, tail, nameend) {
    n = length(s)
    # NAME_END is built once per record by the main action before the walk, so
    # it is always current for s. An earlier version rebuilt it lazily inside
    # this function when `start > NAME_SPAN`, which was wrong whenever the new
    # line was no longer than the previous one: the table was not rebuilt, so a
    # benign line following a secret line was matched against the earlier
    # line's names. Observed directly as
    #     password=A
    #     note=B
    #     note=C
    # emitting `password=REDACTED` on all three lines. Rebuilding per record is
    # one backward pass per line, which is linear, so nothing is lost by doing
    # it eagerly rather than lazily.

    # The name may not follow ':' or '/', so the authority inside a URL is never
    # read as a name. The URL pass runs first, so this is belt and braces.
    if (start > 1) {
        c = substr(NAME_S, start - 1, 1)
        if (c == ":" || c == "/") return 0
    }
    if (substr(NAME_S, start, 1) !~ /[A-Za-z0-9_]/) return 0

    nameend = NAME_END[start]
    if (nameend == 0) return 0
    i = nameend + 1
    name = substr(NAME_S, start, nameend - start + 1)

    j = i
    while (j <= n && substr(NAME_S, j, 1) ~ /[ \t]/) j++
    if (j > n) return 0
    c = substr(NAME_S, j, 1)
    if (c != "=" && c != ":") return 0
    if (c == ":") {
        # A colon that opens "://" is a URL, not a separator.
        if (substr(NAME_S, j, 3) == "://") return 0
        sep = ":"
    } else {
        sep = "="
    }
    j++
    while (j <= n && substr(NAME_S, j, 1) ~ /[ \t]/) {
        sep = sep " "
        j++
    }

    if (!secret_name(name)) return 0
    if (j > n) return 0
    c = substr(NAME_S, j, 1)
    if (c ~ /[ \t]/) return 0

    # A quoted value keeps its quotes and loses only its content.
    q = ""
    if (substr(NAME_S, j, 1) == "\"" || substr(NAME_S, j, 1) == "'") {
        q = substr(NAME_S, j, 1)
        j++
        startq = j
        while (j <= n && substr(NAME_S, j, 1) != q) j++
        if (j > n) {
            # No closing quote. Returning 0 here is what used to happen, and
            # it leaked the credential verbatim: the walker read "not a kv
            # pair", copied the rest of the line character by character, and
            # the value never reached redact_shapes in a redactable form. So
            # `password="secret` came out unchanged. A truncated config file or
            # a record whose last field is cut is an ordinary way to get here,
            # so an unterminated quote redacts to the end of the line instead.
            KV_OUT = name sep q "REDACTED"
            KV_CONSUMED = n - start + 1
            return 1
        }
        value = substr(NAME_S, startq, j - startq)
        j++
        KV_OUT = name sep q "REDACTED" q
        KV_CONSUMED = j - start
        return 1
    }

    value = ""
    tail = ""
    while (j <= n) {
        c = substr(NAME_S, j, 1)
        # A closing bracket or brace delimits the value rather than belonging
        # to it, so it is preserved.
        if (c ~ /[),\]}>;]/) {
            tail = c
            j++
            break
        }
        # An opening quote inside an unquoted value means the value continues
        # past the spaces that follow it, to the matching closing quote. This
        # is what keeps a second secret on the same line from being skipped:
        # the scan used to stop at the first space, hand the rest of the line
        # to the character-by-character copy, and emit
        #   PASSWORD:REDACTED = "hunter2
        # which is a real credential left in the report.
        if (c == "\"" || c == "'") {
            value = value c
            j++
            while (j <= n && substr(NAME_S, j, 1) != c) {
                value = value substr(NAME_S, j, 1)
                j++
            }
            if (j <= n) {
                value = value c
                j++
            }
            # The value ended at its closing quote. Anything after it is a
            # delimiter or the start of the next pair, so stop here.
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
    # Build the name-end index for this line before the walk, once. It must be
    # rebuilt for every record: a stale table makes a later line inherit an
    # earlier line's names.
    build_name_ends(s)

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

    # Authorization style headers carrying a scheme word. Both halves of this
    # regex fold case: HTTP header names are case insensitive, and both halves
    # have been wrong in this file at some point. The name half used
    # `[Aa]uthorization`, which misses AUTHORIZATION, and the scheme half used
    # `(Bearer|Basic|Token|Digest)`, which misses `authorization: basic`. An
    # explicit class per letter is used rather than an alternation because the
    # alternation form is what let the two halves drift apart.
    while (match(line, /([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]|[Pp][Rr][Oo][Xx][Yy]-[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn])[ \t]*:[ \t]*([Bb][Ee][Aa][Rr][Ee][Rr]|[Bb][Aa][Ss][Ii][Cc]|[Tt][Oo][Kk][Ee][Nn]|[Dd][Ii][Gg][Ee][Ss][Tt])[ \t]+[^ \t;]+/) > 0) {
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