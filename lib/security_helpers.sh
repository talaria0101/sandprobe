#!/bin/sh
# sandprobe: small helpers used by more than one section.
# SPDX-License-Identifier: 0BSD

# First setuid binary found in the usual locations, or empty.
# Kept as a function because three call sites need it and the search is not
# cheap, and because a bare command substitution into an unbound name is a
# shell error that aborts the run.
SP_SETUID_CACHE=""
sp_first_setuid() {
    if [ -n "$SP_SETUID_CACHE" ]; then
        printf '%s' "$SP_SETUID_CACHE"
        return 0
    fi
    SP_SETUID_CACHE=$(timeout 30 find /usr/bin /usr/sbin /bin /sbin -xdev \
        -perm -4000 -type f 2>/dev/null | LC_ALL=C sort | head -1)
    printf '%s' "$SP_SETUID_CACHE"
    return 0
}

# Count of setuid binaries, cached.
SP_SETUID_COUNT=""
sp_setuid_count() {
    if [ -n "$SP_SETUID_COUNT" ]; then
        printf '%s' "$SP_SETUID_COUNT"
        return 0
    fi
    SP_SETUID_COUNT=$(timeout 30 find /usr/bin /usr/sbin /bin /sbin -xdev \
        -perm -4000 -type f 2>/dev/null | wc -l | tr -d ' ')
    printf '%s' "$SP_SETUID_COUNT"
    return 0
}
