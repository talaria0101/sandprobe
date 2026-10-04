#!/bin/sh
# sandprobe: dynamic target discovery.
#
# Nothing here hardcodes a username, a session id, or a path that only exists
# on one particular host. Every probed candidate is derived at run time from
# one of these sources:
#
#   1. /proc/self/mountinfo   mount targets, sources, recovered bind subpaths
#   2. $HOME / $USER / $LOGNAME
#   3. the passwd database    whichever copy is readable, if any
#   4. directory listings     home roots, when readable
#   5. a fixed universal set  paths that mean something on any POSIX host
#   6. operator input         --probe-path and SANDPROBE_EXTRA_PATHS
#
# A hardcoded path yields two classes of error: a false ABSENT on a host where
# it does not exist, and a silent false negative on a host where the
# interesting path has a different name. Both are avoided by deriving.
# SPDX-License-Identifier: 0BSD

SP_MOUNT_RECORDS=""    # tab separated: target <TAB> fstype <TAB> source <TAB> opts
SP_HOST_SUBPATHS=""    # host-visible subpaths recovered from bind mount sources
SP_CANDIDATE_DIRS=""   # newline separated, deduped
SP_CANDIDATE_FILES=""  # newline separated, deduped
SP_CANDIDATE_USERS=""  # newline separated, deduped
SP_CANDIDATE_HOMES=""  # newline separated, deduped

# Decode mountinfo octal escapes: \040 space, \011 tab, \012 newline, \134 backslash.
_sp_unescape() {
    printf '%s' "$1" | sed -e 's/\\040/ /g' -e 's/\\011/	/g' \
                           -e 's/\\012/\n/g' -e 's/\\134/\\/g'
}

# Parse /proc/self/mountinfo into SP_MOUNT_RECORDS and recover bind subpaths.
sp_discover_mounts() {
    SP_MOUNT_RECORDS=""
    SP_HOST_SUBPATHS=""
    if [ ! -r /proc/self/mountinfo ]; then
        sp_rec "discover" "mountinfo" "UNKNOWN" "/proc/self/mountinfo unreadable; mount-derived targets were not probed"
        return 0
    fi
    awk '
        {
            sep = 0
            for (i = 7; i <= NF; i++) if ($i == "-") { sep = i; break }
            if (sep == 0) next
            root   = $4
            target = $5
            opts   = $6
            fstype = $(sep + 1)
            source = (sep + 2 <= NF) ? $(sep + 2) : ""
            print target "\t" fstype "\t" source "\t" opts
            # Host path leakage has two shapes in mountinfo, and missing
            # either produces a false "the sandbox revealed nothing" claim.
            #
            # 1. The root field ($4). For a bind mount of a subdirectory this
            #    is the path of that subdirectory on the backing filesystem,
            #    for example /home/<user>/.local/state/<service>/<id>. That
            #    names a host directory the sandbox may not have meant to
            #    disclose. The example is deliberately generic.
            # 2. A source of the form pool[/sub/path], used by ZFS, Btrfs
            #    subvolumes and some bind mounts.
            if (root != "/" && root != "") print "subpath\t" root
            if (match(source, /\[/)) {
                inner = substr(source, RSTART + 1)
                if (match(inner, /\]/)) inner = substr(inner, 1, RSTART - 1)
                print "subpath\t" inner
            }
        }
    ' /proc/self/mountinfo 2>/dev/null > "$SP_WORK/mountinfo.parsed"

    grep -v '^subpath	' "$SP_WORK/mountinfo.parsed" 2>/dev/null \
        > "$SP_WORK/mountinfo.rows"
    SP_MOUNT_RECORDS=$(cat "$SP_WORK/mountinfo.rows" 2>/dev/null)

    _subs=$(grep '^subpath	' "$SP_WORK/mountinfo.parsed" 2>/dev/null | cut -f2)
    if [ -n "$_subs" ]; then
        # Each recovered subpath and every ancestor is a candidate host path.
        # Ancestors matter: knowledge of /home/u/.local/share/rustup implies
        # /home/u exists as far as this sandbox is concerned.
        printf '%s\n' "$_subs" | while IFS= read -r p; do
            [ -n "$p" ] || continue
            _d=$(_sp_unescape "$p")
            while [ -n "$_d" ] && [ "$_d" != "/" ]; do
                printf '%s\n' "$_d"
                _d=$(dirname "$_d")
            done
            printf '/\n'
        done | LC_ALL=C sort -u > "$SP_WORK/subpaths.ancestors"
        SP_HOST_SUBPATHS=$(cat "$SP_WORK/subpaths.ancestors" 2>/dev/null)
    fi
    return 0
}

# Recover user names from whatever identity sources this host offers.
sp_discover_users() {
    # A name that is entirely digits is not a user. `id -un` falls back to
    # printing the numeric uid, and it exits 0 while doing so, when the host
    # has no passwd entry for that uid. Taking that as a name produced /home/0
    # and 135 records for paths that no account owns.
    for v in "${USER:-}" "${LOGNAME:-}" "$(id -un 2>/dev/null)"; do
        [ -n "$v" ] || continue
        [ "$v" = "UNKNOWN" ] && continue
        case "$v" in
            *[!0-9]*) : ;;
            *) continue ;;
        esac
        printf '%s\n' "$v"
    done > "$SP_WORK/users.env"

    : > "$SP_WORK/users.passwd"
    for pw in /etc/passwd /etc/passwd-; do
        [ -r "$pw" ] || continue
        cut -d: -f1 "$pw" 2>/dev/null \
            | grep -vE '^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|_apt|systemd|messagebus|sshd|polkitd|usbmux|dnsmasq|avahi)$' \
            | grep -v '^$' \
            >> "$SP_WORK/users.passwd"
    done

    : > "$SP_WORK/users.home"
    for hr in /home /Users /var/home; do
        [ -d "$hr" ] || continue
        ls -1 "$hr" 2>/dev/null | grep -v '^lost+found$' >> "$SP_WORK/users.home"
    done
    printf '%s\n' "$SP_HOST_SUBPATHS" 2>/dev/null \
        | sed -n -e 's#^/home/\([^/]*\)/.*#\1#p' -e 's#^/Users/\([^/]*\)/.*#\1#p' \
        >> "$SP_WORK/users.home"

    cat "$SP_WORK/users.env" "$SP_WORK/users.passwd" "$SP_WORK/users.home" 2>/dev/null \
        | grep -vE '^(root|bin|sbin|lib|usr|etc|var|tmp|proc|sys|dev|boot|lib64|media|mnt|srv|opt)$' \
        | grep -v '^$' \
        | LC_ALL=C sort -u > "$SP_WORK/users.all"
    SP_CANDIDATE_USERS=$(cat "$SP_WORK/users.all" 2>/dev/null)
    return 0
}

# Home directories implied by the discovered users, plus $HOME itself.
sp_discover_homes() {
    : > "$SP_WORK/homes.0"
    [ -n "${HOME:-}" ] && printf '%s\n' "${HOME:-}" >> "$SP_WORK/homes.0"
    printf '%s\n' "$SP_CANDIDATE_USERS" | sed '/^$/d' \
        | while IFS= read -r u; do
            for hr in /home /Users /var/home; do
                printf '%s/%s\n' "$hr" "$u"
            done
        done > "$SP_WORK/homes.fromusers"
    cat "$SP_WORK/homes.0" "$SP_WORK/homes.fromusers" 2>/dev/null \
        | grep -v '^$' | LC_ALL=C sort -u > "$SP_WORK/homes.all"
    # Drop /root for a non-root user so the report does not print a misleading
    # DENY about a path the sandbox was never going to grant.
    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        grep -v '^/root$' "$SP_WORK/homes.all" > "$SP_WORK/homes.final" 2>/dev/null
    else
        cp "$SP_WORK/homes.all" "$SP_WORK/homes.final" 2>/dev/null
    fi
    SP_CANDIDATE_HOMES=$(cat "$SP_WORK/homes.final" 2>/dev/null)
    return 0
}
# Directories worth probing, in a deterministic order.
sp_discover_dirs() {
    _t="$SP_WORK/cand.dirs"
    : > "$_t"
    for d in / /tmp /var/tmp /var/log /var/run /run /etc /usr /usr/bin /usr/local \
             /usr/local/bin /usr/sbin /usr/lib /usr/lib64 /bin /sbin /lib /lib64 \
             /opt /srv /mnt /media /boot /dev /dev/shm /dev/pts /sys /sys/fs \
             /sys/kernel /sys/class /sys/devices /proc /proc/sys /proc/self; do
        printf '%s\n' "$d" >> "$_t"
    done
    # Every mount target plus its ancestors. A mount target is something the
    # sandbox creator thought worth exposing, so it is always worth probing.
    printf '%s\n' "$SP_MOUNT_RECORDS" | cut -f1 | sed '/^$/d' \
        | while IFS= read -r m; do
            printf '%s\n' "$m" >> "$_t"
            _d=$(dirname "$m")
            while [ -n "$_d" ] && [ "$_d" != "/" ]; do
                printf '%s\n' "$_d" >> "$_t"
                _d=$(dirname "$_d")
            done
        done
    # Home directories and their conventional config children.
    printf '%s\n' "$SP_CANDIDATE_HOMES" | sed '/^$/d' \
        | while IFS= read -r h; do
            printf '%s\n' "$h" >> "$_t"
            for s in .local .cache .config .ssh .gnupg .aws .npm .cargo .rustup; do
                printf '%s/%s\n' "$h" "$s" >> "$_t"
            done
        done
    # Host paths recovered from bind sources. Probing these is the leakage
    # test: on a correct sandbox every one of them is absent.
    printf '%s\n' "$SP_HOST_SUBPATHS" | sed '/^$/d' >> "$_t"
    # Operator supplied extras.
    printf '%s\n' "${SANDPROBE_EXTRA_PATHS:-}" 2>/dev/null | sed '/^$/d' >> "$_t"
    LC_ALL=C sort -u "$_t" 2>/dev/null | grep -v '^$' > "$SP_WORK/cand.dirs.sorted"
    SP_CANDIDATE_DIRS=$(cat "$SP_WORK/cand.dirs.sorted" 2>/dev/null)
    return 0
}

# Sensitive basenames. Constants are correct here: credential files are
# conventionally named. The home they are joined to is discovered, never
# assumed. Space separated.
SP_SENSITIVE_BASENAMES=".ssh .ssh/id_ed25519 .ssh/id_rsa .ssh/id_ecdsa .ssh/id_dsa .ssh/authorized_keys .ssh/known_hosts .ssh/config .git-credentials .netrc .npmrc .pypirc .gitconfig .bashrc .bash_history .profile .env .aws/credentials .aws/config .config/gh/hosts.yml .docker/config.json .kube/config .gnupg .cargo/credentials .cargo/config.toml"

# Files worth probing: a universal set plus per-home sensitive filenames.
sp_discover_files() {
    _t="$SP_WORK/cand.files"
    : > "$_t"
    for f in /etc/passwd /etc/shadow /etc/shadow- /etc/group /etc/gshadow \
             /etc/sudoers /etc/sudoers.d /etc/hosts /etc/host.conf /etc/resolv.conf \
             /etc/os-release /etc/machine-id /etc/hostname /etc/fstab /etc/cron.allow \
             /etc/ssh/sshd_config /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ed25519_key \
             /etc/skel/.bashrc /etc/default/grub /etc/kernel/cmdline \
             /boot/config- /boot/initrd.img- \
             /dev/mem /dev/kmem /dev/sda /dev/sdb /dev/nvme0n1 /dev/kvm /dev/fuse \
             /dev/ptmx /dev/tty /dev/console /dev/initctl /dev/watchdog \
             /proc/1/environ /proc/1/maps /proc/1/mem /proc/1/root /proc/version \
             /proc/kcore /proc/kallsyms /proc/modules; do
        printf '%s\n' "$f" >> "$_t"
    done
    printf '%s\n' "$SP_CANDIDATE_HOMES" | sed '/^$/d' \
        | while IFS= read -r h; do
            printf '%s\n' "$SP_SENSITIVE_BASENAMES" | tr ' ' '\n' | grep -v '^$' \
                | while IFS= read -r b; do
                    printf '%s/%s\n' "$h" "$b" >> "$_t"
                done
        done
    # The literal backing-store paths behind bind mounts. On a host exposing
    # only the sandbox root these are ABSENT, which is the expected result.
    printf '%s\n' "$SP_HOST_SUBPATHS" | sed '/^$/d' >> "$_t"
    printf '%s\n' "${SANDPROBE_EXTRA_PATHS:-}" 2>/dev/null | sed '/^$/d' >> "$_t"
    LC_ALL=C sort -u "$_t" 2>/dev/null | grep -v '^$' > "$SP_WORK/cand.files.sorted"
    SP_CANDIDATE_FILES=$(cat "$SP_WORK/cand.files.sorted" 2>/dev/null)
    return 0
}

# Device nodes to probe and the subset that may be written without harm are
# both built by sp_discover_devices, one entry per line in $SP_WORK/dev.nodes
# and $SP_WORK/dev.write, so the consumers in sect_fs.sh can read them with
# `while IFS= read -r` instead of word-splitting a space separated variable.

sp_discover_devices() {
    _t="$SP_WORK/dev.nodes"
    : > "$_t"
    # Written one entry per line rather than space separated, so the consumer
    # reads them with `while IFS= read -r`. A space separated list consumed by
    # an unquoted expansion word-splits, so a path containing a space or a glob
    # becomes two probes for paths that do not exist. These particular lists
    # are literals so the bug cannot fire here, but the pattern was wrong and
    # the next entry added to either list would inherit it.
    printf '%s\n' /dev/null /dev/zero /dev/full /dev/random /dev/urandom \
        /dev/tty /dev/ptmx /dev/console /dev/shm /dev/mem /dev/kmem \
        /dev/sda /dev/sdb /dev/nvme0n1 /dev/kvm /dev/fuse /dev/initctl \
        /dev/watchdog /dev/net/tun /dev/dri/card0 /dev/snd/controlC0 \
        | LC_ALL=C sort -u > "$_t"
    SP_DEVICE_NODES=$(cat "$_t" 2>/dev/null)

    _t="$SP_WORK/dev.write"
    : > "$_t"
    # Writing to these is harmless by construction: /dev/null discards,
    # /dev/zero and /dev/full have no backing store, and /dev/random and
    # /dev/urandom are entropy sources with no write side. Every other device
    # is probed for existence only.
    printf '%s\n' /dev/null /dev/zero /dev/full /dev/random /dev/urandom \
        | LC_ALL=C sort -u > "$_t"
    SP_DEVICE_WRITE_SAFE=$(cat "$_t" 2>/dev/null)
    return 0
}

sp_discover_all() {
    sp_discover_mounts
    sp_discover_users
    sp_discover_homes
    sp_discover_dirs
    sp_discover_files
    sp_discover_devices
    return 0
}

sp_section_discover() {
    SP_CUR="discover"
    printf '\n## DISCOVERY BASIS\n\n'
    sp_raw "# Every probed target in this report was derived from these sources."
    sp_raw "# No path was hardcoded to one particular host."
    sp_kv "home_env" "${HOME:-UNSET}"
    sp_kv "user_env" "${USER:-UNSET}"
    sp_kv "logname_env" "${LOGNAME:-UNSET}"
    # id -un prints the complaint on stderr and the numeric uid on stdout, so
    # capturing 2>&1 produced a two-line value that split one record across two
    # report lines. Capture each stream separately.
    _idun=$(id -un 2>/dev/null)
    _idun_err=$(id -un 2>&1 >/dev/null)
    sp_kv "id_un" "${_idun:-UNRESOLVED}"
    if [ -n "$_idun_err" ]; then
        sp_kv "id_un_diagnostic" "$_idun_err"
    fi
    # Reflects whether the parsed copy exists, which is the same fact this
    # section went on to use. Reading /proc/self/mountinfo here would test the
    # substituted child's procfs rather than this process's.
    if [ -s "$SP_WORK/mountinfo.parsed" ]; then
        sp_kv "mountinfo_readable" "yes"
    else
        sp_kv "mountinfo_readable" "no"
    fi
    sp_kv "mount_records" "$(printf '%s\n' "$SP_MOUNT_RECORDS" | grep -c . 2>/dev/null)"
    sp_kv "users_discovered" "$(printf '%s\n' "$SP_CANDIDATE_USERS" | grep -c . 2>/dev/null)"
    sp_kv "homes_discovered" "$(printf '%s\n' "$SP_CANDIDATE_HOMES" | grep -c . 2>/dev/null)"
    sp_kv "dirs_discovered" "$(printf '%s\n' "$SP_CANDIDATE_DIRS" | grep -c . 2>/dev/null)"
    sp_kv "files_discovered" "$(printf '%s\n' "$SP_CANDIDATE_FILES" | grep -c . 2>/dev/null)"
    sp_kv "extra_paths_env" "${SANDPROBE_EXTRA_PATHS:-none}"

    printf '\n## MOUNT TABLE AS PARSED\n\n'
    sp_raw "# target <TAB> fstype <TAB> source <TAB> mount options"
    printf '%s\n' "$SP_MOUNT_RECORDS" 2>/dev/null | sp_scrub

    printf '\n## HOST SUBPATHS RECOVERED FROM BIND SOURCES\n\n'
    sp_raw "# Recovered from mount sources of the form pool[/sub/path]. These are"
    sp_raw "# real paths on the backing pool. On a sandbox that hides the host"
    sp_raw "# filesystem they should be unreachable, which the filesystem section"
    sp_raw "# tests directly."
    if [ -n "$SP_HOST_SUBPATHS" ]; then
        printf '%s\n' "$SP_HOST_SUBPATHS" | sed '/^$/d' | sp_scrub
    else
        sp_raw "# none: no bracketed bind subpath present in any mount source"
    fi

    printf '\n## DISCOVERED USERS\n\n'
    sp_raw "# From USER, the passwd database, home directory listings, and bind"
    sp_raw "# mount source paths. Each entry is a candidate, not a claim."
    if [ -n "$SP_CANDIDATE_USERS" ]; then
        printf '%s\n' "$SP_CANDIDATE_USERS" | sed '/^$/d'
    else
        sp_raw "# none discovered"
    fi

    printf '\n## DISCOVERED HOME DIRECTORIES\n\n'
    if [ -n "$SP_CANDIDATE_HOMES" ]; then
        printf '%s\n' "$SP_CANDIDATE_HOMES" | sed '/^$/d'
    else
        sp_raw "# none discovered"
    fi

    printf '\n## DISCOVERED DIRECTORY TARGETS\n\n'
    sp_raw "# Union of: the universal POSIX set, every mount target and its"
    sp_raw "# ancestors, discovered homes and their config children, recovered"
    sp_raw "# host subpaths, and any --probe-path / SANDPROBE_EXTRA_PATHS."
    if [ -n "$SP_CANDIDATE_DIRS" ]; then
        printf '%s\n' "$SP_CANDIDATE_DIRS" | sed '/^$/d'
    else
        sp_raw "# none discovered"
    fi

    printf '\n## DISCOVERED FILE TARGETS\n\n'
    if [ -n "$SP_CANDIDATE_FILES" ]; then
        printf '%s\n' "$SP_CANDIDATE_FILES" | sed '/^$/d'
    else
        sp_raw "# none discovered"
    fi
}
