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
        _err=$(timeout "$SP_BUDGET" sh -c "head -c 1 '$f' >/dev/null" 2>&1)
        if [ ! -e "$f" ]; then
            sp_rec "$SP_CUR" "read:$f" "ABSENT" "not present on this host"
        elif [ -z "$_err" ]; then
            sp_rec "$SP_CUR" "read:$f" "ALLOW" "first byte readable"
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
    sp_kv "open_fds" "$(ls /proc/self/fd 2>/dev/null | wc -l | tr -d ' ')"
    sp_kv "fd_targets" "$(ls -l /proc/self/fd 2>/dev/null | sed 's/.*-> //' | sort | tr '\n' ' ')"
    sp_kv "fd_soft_limit" "$(awk '/Max open files/{print $4}' /proc/self/limits 2>/dev/null)"
    sp_kv "fd_hard_limit" "$(awk '/Max open files/{print $5}' /proc/self/limits 2>/dev/null)"
    # Prove the soft limit is real rather than quoted.
    _n=$(sh -c 'ulimit -n' 2>/dev/null)
    sp_kv "ulimit_n_reported" "$_n"
    _err=$(timeout 30 sh -c 'i=0; while [ $i -lt 5000 ]; do eval "exec $i</dev/null" 2>/dev/null || break; i=$((i+1)); done; echo $i' 2>&1)
    sp_kv "fd_empirical_max" "$_err"
    sp_rec "$SP_CUR" "fd_soft_limit_reaches_limit" \
        "$( [ "${_err:-0}" -ge 400 ] 2>/dev/null && echo ALLOW || echo UNKNOWN )" \
        "empirically opened $_err descriptors before refusal (soft limit $_n)"

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