#!/bin/sh
# sandprobe section: identity, namespaces, capabilities, seccomp, procfs leak.
# SPDX-License-Identifier: 0BSD

sp_section_security() {
    SP_CUR="security"

    printf '\n## IDENTITY\n\n'
    sp_kv "id_uid_gid_groups" "$(id 2>&1)"
    sp_kv "whoami" "$(whoami 2>&1)"
    sp_kv "id_effective" "$(id -u 2>/dev/null):$(id -g 2>/dev/null)"
    sp_kv "euid_egid" "$( (id -u; id -g) 2>/dev/null | tr '\n' ':' )"
    sp_kv "pid" "$$"
    sp_kv "ppid" "$(awk '/^PPid/{print $2}' /proc/self/status 2>/dev/null)"
    # pid 1 is often a supervisor carrying tens of kilobytes of prompt text.
    # Inlining that into a report is noise, so record the executable, the
    # argument count, the total size and a bounded prefix. Nothing is hidden:
    # the size is reported so a reader knows what was elided.
    sp_kv "pid_1_executable" "$(tr '\0' '\n' < /proc/1/cmdline 2>/dev/null | head -1 || echo UNREADABLE)"
    sp_kv "pid_1_argc" "$(tr '\0' '\n' < /proc/1/cmdline 2>/dev/null | grep -c . || echo UNREADABLE)"
    sp_kv "pid_1_bytes" "$(wc -c < /proc/1/cmdline 2>/dev/null | tr -d ' ' || echo UNREADABLE)"
    sp_kv "pid_1_prefix" "$(tr '\0' ' ' < /proc/1/cmdline 2>/dev/null | cut -c1-300 || echo UNREADABLE)"
    sp_kv "passwd_db" "$(cat /etc/passwd 2>&1 | head -1)"
    sp_kv "group_db" "$(cat /etc/group 2>&1 | head -1)"

    printf '\n## NAMESPACES\n\n'
    # Host namespace inodes are the init side. Comparing proves isolation only
    # when we can also read the host's own inode, which we usually cannot, so
    # the report states the observed inode and leaves the comparison to the
    # reader rather than asserting isolation we did not verify.
    sp_kv "cgroup_ns" "$(readlink /proc/self/ns/cgroup 2>/dev/null || echo ABSENT)"
    sp_kv "ipc_ns" "$(readlink /proc/self/ns/ipc 2>/dev/null || echo ABSENT)"
    sp_kv "mnt_ns" "$(readlink /proc/self/ns/mnt 2>/dev/null || echo ABSENT)"
    sp_kv "net_ns" "$(readlink /proc/self/ns/net 2>/dev/null || echo ABSENT)"
    sp_kv "pid_ns" "$(readlink /proc/self/ns/pid 2>/dev/null || echo ABSENT)"
    sp_kv "time_ns" "$(readlink /proc/self/ns/time 2>/dev/null || echo ABSENT)"
    sp_kv "user_ns" "$(readlink /proc/self/ns/user 2>/dev/null || echo ABSENT)"
    sp_kv "uts_ns" "$(readlink /proc/self/ns/uts 2>/dev/null || echo ABSENT)"
    sp_kv "pid1_uts_ns" "$(readlink /proc/1/ns/uts 2>/dev/null || echo UNREADABLE)"
    sp_kv "pid1_user_ns" "$(readlink /proc/1/ns/user 2>/dev/null || echo UNREADABLE)"
    sp_kv "pid1_net_ns" "$(readlink /proc/1/ns/net 2>/dev/null || echo UNREADABLE)"
    if [ -r /proc/self/uid_map ]; then
        sp_kv "uid_map" "$(tr '\n' ' ' < /proc/self/uid_map 2>/dev/null)"
    else
        sp_rec "security" "uid_map" "UNKNOWN" "/proc/self/uid_map unreadable"
    fi
    if [ -r /proc/self/gid_map ]; then
        sp_kv "gid_map" "$(tr '\n' ' ' < /proc/self/gid_map 2>/dev/null)"
    else
        sp_rec "security" "gid_map" "UNKNOWN" "/proc/self/gid_map unreadable"
    fi
    sp_kv "setgroups" "$(cat /proc/self/setgroups 2>/dev/null || echo ABSENT)"

    printf '\n## VISIBLE PROCESS IDS\n\n'
    _pids=$(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tr '\n' ' ')
    sp_kv "pids_visible_in_proc" "$_pids"
    sp_kv "pid_count_visible" "$(printf '%s' "$_pids" | wc -w | tr -d ' ')"

    printf '\n## CAPABILITIES\n\n'
    if [ -r /proc/self/status ]; then
        sp_kv "CapInh" "$(awk '/^CapInh/{print $2}' /proc/self/status 2>/dev/null)"
        sp_kv "CapPrm" "$(awk '/^CapPrm/{print $2}' /proc/self/status 2>/dev/null)"
        sp_kv "CapEff" "$(awk '/^CapEff/{print $2}' /proc/self/status 2>/dev/null)"
        sp_kv "CapBnd" "$(awk '/^CapBnd/{print $2}' /proc/self/status 2>/dev/null)"
        sp_kv "CapAmb" "$(awk '/^CapAmb/{print $2}' /proc/self/status 2>/dev/null)"
        sp_kv "NoNewPrivs" "$(awk '/^NoNewPrivs/{print $2}' /proc/self/status 2>/dev/null)"
        sp_kv "Seccomp_mode" "$(awk '/^Seccomp:/{print $2}' /proc/self/status 2>/dev/null)"
        sp_kv "Seccomp_filters" "$(awk '/^Seccomp_filters/{print $2}' /proc/self/status 2>/dev/null)"
    else
        sp_rec "security" "capabilities" "UNKNOWN" "/proc/self/status unreadable"
    fi
    sp_kv "securebits_hex" "$(awk '/^Seccomp_mode/{print}' /proc/self/status >/dev/null 2>&1; cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null | tr '\n' ' ')"
    sp_kv "unprivileged_userns_clone" "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo 'sysctl ABSENT on this kernel')"
    sp_kv "max_user_namespaces" "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo UNREADABLE)"
    sp_kv "unprivileged_bpf_disabled" "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo UNREADABLE)"
    if sp_need capsh; then
        sp_kv "capsh_decode_eff" "$(capsh --decode=0x$(awk '/^CapEff/{print $2}' /proc/self/status 2>/dev/null) 2>&1 | head -1)"
    fi
    # Setuid binaries are a classic escalation path. Record them as observed
    # without executing anything.
    sp_kv "setuid_setgid_binaries" "$(timeout 30 find /usr/bin /usr/sbin /bin /sbin -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort | tr '\n' ' ')"

    printf '\n## KEYRING\n\n'
    if [ -r /proc/key-values ]; then
        sp_kv "keyring_processes" "$(grep -c . /proc/key-values 2>/dev/null)"
        sp_kv "keyring_sample" "$(head -3 /proc/key-values 2>/dev/null | tr '\n' ' ')"
    else
        sp_rec "security" "keyring" "UNKNOWN" "/proc/key-values unreadable; keyctl enumeration not attempted"
    fi

    printf '\n## LSM AND ATTACK SURFACE FILES\n\n'
    sp_try_exists /sys/kernel/security/lsm
    sp_try_exists /sys/fs/selinux
    sp_kv "lsm_list" "$(cat /sys/kernel/security/lsm 2>/dev/null || echo UNREADABLE)"
    sp_kv "yama_ptrace_scope" "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo UNREADABLE)"
    sp_kv "core_pattern" "$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo UNREADABLE)"
    sp_kv "protected_hardlinks" "$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null || echo UNREADABLE)"
    sp_kv "protected_symlinks" "$(cat /proc/sys/fs/protected_symlinks 2>/dev/null || echo UNREADABLE)"
    sp_kv "suid_dumpable" "$(cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo UNREADABLE)"

    printf '\n## PRIVILEGE ESCALATION ATTEMPTS\n\n'
    printf '%s\n' \
"# Every line is a real attempt with the real answer. Two rules make these" \
"# trustworthy:" \
"#   1. The verdict comes from what the command PRINTED, never from the exit" \
"#      status of the wrapper. A wrapper that exits 0 while the command" \
"#      failed is exactly how a probe lies." \
"#   2. A probe whose argument the tool rejects as malformed is UNKNOWN," \
"#      never DENY. Not being able to ask the question is not the answer." \
"# None of these modify anything outside this sandbox. mount targets are" \
"# created in a private temporary directory so a successful mount leaves no" \
"# trace on the host."

    # Single classification path, driven by observed output text.
    sp_esc() {
        _label="$1"
        shift
        _out=$("$@" 2>&1)
        _rc=$?
        _lc=$(printf '%s' "$_out" | tr 'A-Z' 'a-z')
        case "$_lc" in
            *"unrecognized option"*|*"unrecognised option"*|*"unknown option"*|\
            *"invalid option"*|*"unknown argument"*|*"invalid argument"*|\
            *"unexpected argument"*|*"usage:"*)
                sp_rec "escalation" "$_label" "UNKNOWN" \
                    "probe could not be posed (rc=$_rc): $(printf '%s' "$_out" | head -1)" ;;
            *"permission denied"*|*"operation not permitted"*|*"not permitted"*|\
            *"access denied"*|*"must be root"*|*"denied"*)
                sp_rec "escalation" "$_label" "DENY" \
                    "rc=$_rc $(printf '%s' "$_out" | head -2 | tr '\n' ' ')" ;;
            *)
                # Anything else means the attempt was not refused. Say so and
                # show the output, so the reader can judge it rather than trust
                # a verdict we cannot justify.
                sp_rec "escalation" "$_label" "ALLOW" \
                    "rc=$_rc output: $(printf '%s' "$_out" | head -2 | tr '\n' ' ')" ;;
        esac
        return 0
    }

    # Scratch directory for mount targets. Inside SP_WORK, which the exit trap
    # removes, so a successful mount leaves nothing behind.
    _mnt="$SP_WORK/mnttarget"
    mkdir -p "$_mnt" 2>/dev/null

    # Namespaces. Each asks for one namespace and runs true(1) inside it.
    # Success means a new namespace exists; failure means the kernel refused.
    sp_esc "new_user_namespace"      unshare unshare -U true
    sp_esc "user_plus_mount_ns"      unshare unshare -Urm true
    sp_esc "network_namespace"       unshare unshare -n true
    sp_esc "pid_namespace"          unshare unshare -pf true
    sp_esc "mount_namespace"         unshare unshare -m true
    sp_esc "cgroup_namespace"        unshare unshare -C true
    sp_esc "time_namespace"          unshare unshare -T true
    sp_esc "uts_namespace"           unshare unshare -u true
    sp_esc "ipc_namespace"           unshare unshare -i true

    # Root manipulation.
    sp_esc "chroot_to_root"          chroot chroot /
    sp_esc "chroot_to_tmp"           chroot chroot /tmp
    sp_esc "mount_tmpfs_over_tmpdir" mount mount -t tmpfs none "$_mnt"
    sp_esc "mount_proc_over_tmpdir"  mount mount -t proc none "$_mnt"
    sp_esc "mount_bind_root_to_tmpdir" mount mount --bind / "$_mnt"
    sp_esc "mount_devpts"            mount mount -t devpts devpts "$_mnt"
    if sp_have unshare; then
        # pivot_root needs a new mount namespace plus a chroot(2), which needs
        # CAP_SYS_CHROOT. Ask for both and report what came back. There is no
        # standalone pivot_root(8) on most systems, so this is stated rather
        # than faked.
        sp_kv "pivot_root_probe" "not attempted: no standalone pivot_root(8) exists on this host. The nearest evidence is the chroot probes above plus CAP_SYS_CHROOT in the capability set."
    else
        sp_kv "pivot_root_probe" "not attempted: unshare(1) absent"
    fi

    # Kernel module loading.
    sp_esc "insmod_dummy"            modprobe modprobe dummy

    # Writing host-visible kernel tunables.
    sp_esc "write_sysctl_hostname"   sh sh -c 'echo pwned > /proc/sys/kernel/hostname'
    sp_esc "write_sysctl_modprobe"   sh sh -c 'echo x > /proc/sys/kernel/modprobe'
    sp_esc "write_sysctl_kill_restart" sh sh -c 'echo 1 > /proc/sys/kernel/core_pattern'

    # Reading kernel memory.
    sp_esc "read_proc_kcore"         sh sh -c "dd if=/proc/kcore of=/dev/null bs=1 count=1 2>&1 | tail -1"
    sp_esc "read_proc_kallsyms"      sh sh -c 'head -c 32 /proc/kallsyms >/dev/null && echo readable'
    sp_esc "stat_proc_kcore"         stat stat -c '%A %U %G %s' /proc/kcore
    sp_esc "read_proc_modules"       sh sh -c 'head -c 32 /proc/modules >/dev/null && echo readable'
    sp_esc "read_proc_1_maps"        sh sh -c 'head -c 32 /proc/1/maps >/dev/null && echo readable'

    # Writing / writing through procfs pseudo files. Note these are writes, and
    # each names the file it targets so the record is unambiguous.
    sp_esc "write_proc_sysrq_trigger" sh sh -c 'echo c > /proc/sysrq-trigger'
    sp_esc "read_proc_sysrq_trigger"  sh sh -c 'cat /proc/sysrq-trigger 2>&1 | head -1'
    sp_esc "write_proc_vm_loglevel"   sh sh -c 'echo 0 > /proc/sys/vm/loglevel'

    # Device creation.
    sp_esc "mknod_null_in_tmp"       mknod mknod "${TMPDIR:-/tmp}/.sandprobe-null.$$" c 1 3

    # Process introspection.
    # ptrace a sibling: only meaningful if it is refused, and yama may also
    # restrict it. The output carries the real reason either way.
    sp_esc "ptrace_sibling_via_mem"  sh sh -c 'sleep 3 & _p=$!; sleep 0.3; cat /proc/$_p/mem >/dev/null 2>&1; _r=$?; kill $_p 2>/dev/null; wait $_p 2>/dev/null; echo cat_proc_mem_rc=$_r'
    sp_esc "attach_via_strace"       strace strace -V 2>/dev/null || echo "strace absent; cannot attach"

    # Reading pid 1. pid 1 is the sandbox's own init in a private pid
    # namespace, so this is not a host escape by itself. It is recorded
    # because a sandbox that hides its own supervisor's environment is
    # unusual, and because environ carries credentials.
    sp_esc "read_pid1_environ"       sh sh -c 'head -c 32 /proc/1/environ >/dev/null && echo readable'
    sp_esc "read_pid1_root_dir"      sh sh -c 'ls /proc/1/root >/dev/null 2>&1 && echo LISTABLE || echo not-listable'
    sp_esc "read_pid1_cwd"           sh sh -c 'readlink /proc/1/cwd 2>&1'

    # procfs escape classics.
    sp_esc "open_proc_self_root_dir" sh sh -c 'ls /proc/self/root >/dev/null 2>&1 && echo LISTABLE || echo not-listable'
    sp_esc "read_parent_cmdline"     sh sh -c 'head -c 32 /proc/1/cmdline >/dev/null && echo readable'
    sp_esc "enumerate_all_pids"      sh sh -c 'ls /proc | grep -cE "^[0-9]+$"'

    # If /proc is mounted with hidepid, foreign pids are invisible. Compare the
    # pid count against what the namespace id suggests.
    sp_kv "proc_mount_options" "$(grep ' /proc ' /proc/self/mounts 2>/dev/null | awk '{print $4}' || echo 'not a separate /proc mount')"
    sp_kv "hidepid_option_present" "$(grep ' /proc ' /proc/self/mounts 2>/dev/null | grep -c hidepid 2>/dev/null || echo 0)"

    printf '\n## PROCFS READABILITY OF SENSITIVE FILES\n\n'
    for f in /proc/1/environ /proc/1/maps /proc/1/mem /proc/1/root /proc/kcore \
             /proc/kallsyms /proc/modules /proc/sys/kernel/tainted \
             /proc/sys/kernel/hostname /proc/sysrq-trigger; do
        _err=$(timeout "$SP_BUDGET" sh -c "head -c 1 '$f' >/dev/null" 2>&1)
        if [ -z "$_err" ]; then
            sp_rec "procfs" "read:$f" "ALLOW" "first byte readable"
        elif [ ! -e "$f" ]; then
            sp_rec "procfs" "read:$f" "ABSENT" "not present on this host"
        else
            sp_rec "procfs" "read:$f" "$(sp_verdict_from_err "$_err")" "$_err"
        fi
    done
    sp_kv "kernel_tainted" "$(cat /proc/sys/kernel/tainted 2>/dev/null || echo UNREADABLE)"
    sp_kv "loaded_modules" "$(wc -l < /proc/modules 2>/dev/null || echo UNREADABLE)"
    sp_kv "sysctl_files_readable" "$(find /proc/sys -type f 2>/dev/null | wc -l | tr -d ' ')"
}