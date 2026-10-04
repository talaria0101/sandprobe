#!/bin/sh
# sandprobe section: mounts, filesystem write/read matrix, devices, disk.
# SPDX-License-Identifier: 0BSD

# Directories probed for read and write. Chosen to cover the paths a sandbox
# typically either permits wholesale or withholds wholesale, plus the paths
# that must never be writable from inside.
sp_section_fs() {
    SP_CUR="fs"

    printf '\n## MOUNTS (/proc/mounts)\n\n'
    sp_raw "# source target fstype options dump pass"
    if [ -r /proc/mounts ]; then
        cat /proc/mounts 2>/dev/null | sp_scrub
        sp_kv "mount_count" "$(grep -c '^[a-z]' /proc/mounts 2>/dev/null)"
    else
        sp_rec "fs" "mounts" "UNKNOWN" "/proc/mounts unreadable"
    fi

    printf '\n## MOUNTPOINTS (tree)\n\n'
    if sp_need findmnt; then
        findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 | sp_scrub
    else
        sp_rec "fs" "findmnt" "UNKNOWN" "findmnt not present; /proc/mounts above is authoritative"
    fi

    printf '\n## ROOT FILESYSTEM\n\n'
    sp_kv "root_fstype" "$(stat -f -c '%T' / 2>/dev/null || echo UNREADABLE)"
    sp_kv "root_block_size" "$(stat -f -c '%s' / 2>/dev/null || echo UNREADABLE)"
    sp_kv "root_total_blocks" "$(stat -f -c '%b' / 2>/dev/null || echo UNREADABLE)"
    sp_kv "root_free_blocks" "$(stat -f -c '%f' / 2>/dev/null || echo UNREADABLE)"
    sp_kv "root_total_inodes" "$(stat -f -c '%c' / 2>/dev/null || echo UNREADABLE)"
    sp_kv "root_free_inodes" "$(stat -f -c '%d' / 2>/dev/null || echo UNREADABLE)"
    sp_kv "root_name_length" "$(stat -f -c '%l' / 2>/dev/null || echo UNREADABLE)"

    printf '\n## DISK USAGE\n\n'
    if sp_need df; then
        timeout 30 df -h 2>&1 | sp_scrub
        printf '\n'
        timeout 30 df -i 2>&1 | sp_scrub
        printf '\n'
        timeout 30 df -a 2>&1 | sp_scrub
    else
        sp_rec "fs" "df" "UNKNOWN" "df not present"
    fi

    printf '\n## BLOCK DEVICES VISIBLE\n\n'
    if [ -d /sys/block ]; then
        sp_kv "sys_block_devices" "$(timeout 15 ls -1 /sys/block 2>/dev/null | sort | tr '\n' ' ')"
    else
        sp_rec "fs" "block_devices" "ABSENT" "/sys/block not mounted; no block device visibility"
    fi
    if [ -r /proc/partitions ]; then
        sp_raw "# /proc/partitions"
        cat /proc/partitions 2>/dev/null | sp_scrub
    fi

    printf '\n## INODES AND OPEN FILE LIMITS\n\n'
    sp_kv "fs_file_max" "$(cat /proc/sys/fs/file-max 2>/dev/null || echo UNREADABLE)"
    sp_kv "fs_nr_open" "$(cat /proc/sys/fs/nr_open 2>/dev/null || echo UNREADABLE)"
    sp_kv "fs_inotify_max_user_watches" "$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo UNREADABLE)"
    sp_kv "fs_mqueue_msgsize_max" "$(cat /proc/sys/fs/mqueue/msg_max 2>/dev/null || echo UNREADABLE)"
    sp_kv "fs_aio_max_nr" "$(cat /proc/sys/fs/aio-max-nr 2>/dev/null || echo UNREADABLE)"
    sp_kv "fs_pid_max" "$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo UNREADABLE)"

    printf '\n## DIRECTORY WRITE MATRIX\n\n'
    sp_raw "# probe: create and delete a uniquely named file in each directory"
    for d in $SP_CANDIDATE_DIRS; do
        sp_try_write "$d"
    done

    printf '\n## DIRECTORY READ MATRIX\n\n'
    for d in $SP_CANDIDATE_DIRS; do
        sp_try_read "$d"
    done

    printf '\n## FILE READ MATRIX\n\n'
    for f in $SP_CANDIDATE_FILES; do
        if [ ! -e "$f" ]; then
            sp_rec "$SP_CUR" "read:$f" "ABSENT" "not present on this host"
            continue
        fi
        # Directories are not readable as a byte stream. Probing one produced
        # "Is a directory", which matched no classification and reported
        # UNKNOWN for something whose answer is plainly not unknown.
        if [ -d "$f" ]; then
            sp_rec "$SP_CUR" "read:$f" "ABSENT" \
                "is a directory; the directory read matrix above is the measurement that applies"
            continue
        fi
        _err=$(timeout "$SP_BUDGET" sh -c "head -c 1 '$f' >/dev/null" 2>&1)
        _rc=$?
        if [ -z "$_err" ] && [ "$_rc" -eq 0 ]; then
            sp_rec "$SP_CUR" "read:$f" "ALLOW" "first byte readable"
        elif [ "$_rc" -eq 124 ]; then
            sp_rec "$SP_CUR" "read:$f" "TIMEOUT" "no byte available within ${SP_BUDGET}s"
        else
            sp_rec "$SP_CUR" "read:$f" "$(sp_verdict_from_err "$_err")" "$_err"
        fi
    done

    printf '\n## DEVICE ACCESS\n\n'
    for d in $SP_DEVICE_NODES; do
        if [ ! -e "$d" ]; then
            sp_rec "$SP_CUR" "device:$d" "ABSENT" "device node not present"
            continue
        fi
        _perm=$(stat -c '%A %U:%G' "$d" 2>/dev/null)
        # Read one byte; proves the node is genuinely openable rather than
        # merely statable.
        # A directory in the device list is not readable as a byte stream.
        if [ -d "$d" ]; then
            sp_rec "$SP_CUR" "read:$d" "ABSENT" \
                "is a directory; directory access is measured by the directory matrices"
            continue
        fi
        # Character devices may block with no data available: /dev/tty waits
        # forever when there is no controlling terminal, and a fifo waits for
        # a writer. A read with no budget is a hang, so every device read is
        # bounded. A read that times out is reported as TIMEOUT, which is the
        # truth, rather than silently recorded as a refusal.
        _err=$(timeout "$SP_BUDGET" sh -c "head -c 1 '$d' >/dev/null" 2>&1)
        _rc=$?
        if [ -z "$_err" ] && [ "$_rc" -eq 0 ]; then
            sp_rec "$SP_CUR" "read:$d" "ALLOW" "opened and read 1 byte, perms $_perm"
        elif [ "$_rc" -eq 124 ]; then
            sp_rec "$SP_CUR" "read:$d" "TIMEOUT" \
                "opened but no byte available within ${SP_BUDGET}s (perms $_perm); it blocked rather than refused"
        else
            sp_rec "$SP_CUR" "read:$d" "$(sp_verdict_from_err "$_err")" "$_err, perms $_perm"
        fi
    done

    printf '\n## DEVICE WRITE ACCESS\n\n'
    for d in $SP_DEVICE_WRITE_SAFE; do
        if [ ! -e "$d" ]; then
            sp_rec "$SP_CUR" "device-write:$d" "ABSENT" "device node not present"
            continue
        fi
        _err=$(timeout "$SP_BUDGET" sh -c "printf x > '$d'" 2>&1)
        _rc=$?
        if [ -z "$_err" ] && [ "$_rc" -eq 0 ]; then
            sp_rec "$SP_CUR" "device-write:$d" "ALLOW" "wrote 1 byte"
        elif [ "$_rc" -eq 124 ]; then
            sp_rec "$SP_CUR" "device-write:$d" "TIMEOUT" "write blocked for more than ${SP_BUDGET}s"
        else
            sp_rec "$SP_CUR" "device-write:$d" "$(sp_verdict_from_err "$_err")" "$_err"
        fi
    done
    sp_raw "# note: writing to /dev/zero, /dev/null and /dev/full is harmless."
    sp_raw "# /dev/tty writes are reported as observed, not suppressed."

    printf '\n## TMPFS AND SHARED MEMORY\n\n'
    sp_kv "dev_shm_mount" "$(grep ' /dev/shm ' /proc/mounts 2>/dev/null || echo 'not a separate mount')"
    if [ -d /dev/shm ]; then
        sp_kv "dev_shm_entries" "$(ls -A /dev/shm 2>/dev/null | wc -l | tr -d ' ')"
        _err=$(timeout 30 sh -c 'dd if=/dev/zero of=/dev/shm/.sandprobe-shm.$$ bs=1M count=4 2>/dev/null && rm -f /dev/shm/.sandprobe-shm.$$ && echo ok' 2>&1)
        case "$_err" in
            ok) sp_rec "$SP_CUR" "shm_write_4mb" "ALLOW" "wrote and removed 4 MiB" ;;
            *) sp_rec "$SP_CUR" "shm_write_4mb" "$(sp_verdict_from_err "$_err")" "$_err" ;;
        esac
    fi
    sp_kv "dev_shm_size_bytes" "$(df -B1 /dev/shm 2>/dev/null | awk 'NR==2{print $2}' || echo UNREADABLE)"
    sp_kv "tmp_size_bytes" "$(df -B1 "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2{print $2}' || echo UNREADABLE)"

    printf '\n## FILE DESCRIPTOR STATE\n\n'
    sp_kv "open_fds" "$(ls "/proc/$$/fd" 2>/dev/null | wc -l | tr -d ' ')"
    sp_kv "fd_targets" "$(ls -l "/proc/$$/fd" 2>/dev/null | sed 's/.*-> //' | sort | tr '\n' ' ')"
    sp_kv "fd_soft_limit" "$(awk '/Max open files/{print $4}' /proc/$$/limits 2>/dev/null)"
    sp_kv "fd_hard_limit" "$(awk '/Max open files/{print $5}' /proc/$$/limits 2>/dev/null)"
    # The value the shell itself reports, for comparison with the empirical
    # count below. The empirical count does not depend on it.
    _n=$(sh -c 'ulimit -n' 2>/dev/null)
    sp_kv "ulimit_n_reported" "${_n:-unknown}"

    # Confirm the soft limit by exhausting it, rather than quoting it.
    #
    # The portable way to do this is a loop of redirections, but the obvious
    # shell forms are not portable in the way they look:
    #
    #   exec $i</dev/null inside eval   dash parses the number as a command
    #                                    name and exits 127; bash opens the fd
    #   the same loop with exec {fd}    dash aborts
    #   the same loop under a subshell  dash opens 1 descriptor and stops,
    #                                    bash opens 1015
    #
    # So the count comes from a language whose descriptor semantics are
    # defined, and when that is unavailable the verdict is UNKNOWN rather than
    # a number that would differ by three orders of magnitude between shells.
    _fdmax="unknown"
    _fderrno=""
    if command -v python3 >/dev/null 2>&1; then
        _fdout=$(timeout 60 python3 - <<'PYFDPROBE' 2>/dev/null
import os, resource, errno
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
fds, opened = [], 0
err = None
try:
    for _ in range(soft + 16):
        fds.append(os.open(os.devnull, os.O_RDONLY))
        opened += 1
except OSError as exc:
    err = exc.errno
finally:
    for f in fds:
        try:
            os.close(f)
        except OSError:
            pass
print("opened=%d soft=%d hard=%d errno=%s" % (
    opened, soft, hard, errno.errorcode.get(err, "none")))
PYFDPROBE
)
        case "$_fdout" in
            *opened=*)
                _fdmax=$(printf '%s' "$_fdout" | sed -n 's/.*opened=\([0-9]*\).*/\1/p')
                _fderrno=$(printf '%s' "$_fdout" | sed -n 's/.*errno=\([A-Za-z]*\).*/\1/p')
                ;;
        esac
    fi
    sp_kv "fd_empirical_max_opened" "$_fdmax"
    sp_kv "fd_refused_with_errno" "${_fderrno:-not-measured}"
    sp_kv "fd_soft_limit_reported" "$_n"
    sp_kv "fd_hard_limit_reported" "$(awk '/Max open files/{print $5}' "/proc/$$/limits" 2>/dev/null)"
    if [ "$_fdmax" = "unknown" ]; then
        sp_rec "$SP_CUR" "fd_soft_limit_empirically_confirmed" "UNKNOWN" \
            "no portable way to exhaust descriptors on this host; the reported soft limit $_n is quoted from /proc/$$/limits and was NOT confirmed empirically. Shell-only probes were rejected because dash and bash disagree by three orders of magnitude on the same loop."
    elif [ "$_fdmax" -ge 100 ]; then
        sp_rec "$SP_CUR" "fd_soft_limit_empirically_confirmed" "ALLOW" \
            "opened $_fdmax descriptors before refusal with $_fderrno, against a quoted soft limit of $_n"
    else
        sp_rec "$SP_CUR" "fd_soft_limit_empirically_confirmed" "DENY" \
            "only $_fdmax descriptors could be opened, well below the quoted soft limit of $_n"
    fi

    printf '\n## LARGE FILE AND SPARSE FILE BEHAVIOUR\n\n'
    _err=$(timeout 60 sh -c "dd if=/dev/zero of='${TMPDIR:-/tmp}/.sandprobe-100m' bs=1M count=100 2>&1 | tail -1")
    case "$_err" in
        *copied*) sp_rec "$SP_CUR" "write_100mb_to_tmp" "ALLOW" "$_err" ;;
        *) sp_rec "$SP_CUR" "write_100mb_to_tmp" "$(sp_verdict_from_err "$_err")" "$_err" ;;
    esac
    rm -f "${TMPDIR:-/tmp}/.sandprobe-100m" 2>/dev/null
    sp_rec "$SP_CUR" "tmp_cleanup_after_100mb" \
        "$( [ -e "${TMPDIR:-/tmp}/.sandprobe-100m" ] && echo UNKNOWN || echo ALLOW )" \
        "$( [ -e "${TMPDIR:-/tmp}/.sandprobe-100m" ] && echo 'probe file still present' || echo 'probe file removed' )"

    printf '\n## SYMLINK AND HARDLINK SEMANTICS\n\n'
    _s="${TMPDIR:-/tmp}/.sandprobe-link.$$"
    _t="${TMPDIR:-/tmp}/.sandprobe-target.$$"
    sh -c ': > "$1"' sh "$_t" 2>/dev/null && ln -s "$_t" "$_s" 2>/dev/null
    sp_kv "symlink_creatable_in_tmp" "$( [ -L "$_s" ] && echo yes || echo no )"
    sp_kv "symlink_target" "$(readlink "$_s" 2>/dev/null || echo NONE)"
    rm -f "$_s" "$_t" 2>/dev/null
    sp_kv "hardlink_protected" "$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null || echo UNREADABLE)"
    sp_kv "symlink_protected" "$(cat /proc/sys/fs/protected_symlinks 2>/dev/null || echo UNREADABLE)"
}