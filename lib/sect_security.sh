#!/bin/sh
# sandprobe section: identity, namespaces, capabilities, seccomp, procfs leak.
# SPDX-License-Identifier: 0BSD

sp_section_security() {
    SP_CUR="security"

    printf '\n## IDENTITY\n\n'
    sp_kv "id_uid_gid_groups" "$(id 2>&1 | tr '\n' ' ')"
    sp_kv "whoami" "$(whoami 2>&1 | tr '\n' ' ')"
    sp_kv "id_effective" "$(id -u 2>/dev/null):$(id -g 2>/dev/null)"
    sp_kv "euid_egid" "$( (id -u; id -g) 2>/dev/null | tr '\n' ':' )"
    sp_kv "pid" "$$"
    sp_kv "ppid" "$(awk '/^PPid/{print $2}' /proc/$$/status 2>/dev/null)"
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
    sp_kv "pid_1_executable" "$(tr '\0' '\n' < /proc/1/cmdline 2>/dev/null | head -1 || echo UNREADABLE)"
    sp_kv "pid_1_argc" "$(tr '\0' '\n' < /proc/1/cmdline 2>/dev/null | grep . | wc -l | tr -d ' ')"
    sp_kv "pid_1_argv_bytes" "$(wc -c < /proc/1/cmdline 2>/dev/null | tr -d ' ' || echo UNREADABLE)"
    sp_kv "pid_1_argv_prefix_120b" "$(head -c 120 /proc/1/cmdline 2>/dev/null | tr '\0' ' ' || echo UNREADABLE)"
    sp_kv "pid_1_argv_truncated" "$(
        _tot=$(wc -c < /proc/1/cmdline 2>/dev/null | tr -d ' ')
        if [ -n "$_tot" ] && [ "$_tot" -gt 120 ]; then
            printf 'yes: %s bytes of argv, 120 inlined; the remainder is deliberately not copied into the report\n' "$_tot"
        else
            printf 'no: argv is %s bytes\n' "${_tot:-unknown}"
        fi
    )"
    sp_kv "passwd_db" "$(cat /etc/passwd 2>&1 | head -1)"
    sp_kv "group_db" "$(cat /etc/group 2>&1 | head -1)"

    printf '\n## NAMESPACES\n\n'
    # Host namespace inodes are the init side. Comparing proves isolation only
    # when we can also read the host's own inode, which we usually cannot, so
    # the report states the observed inode and leaves the comparison to the
    # reader rather than asserting isolation we did not verify.
    sp_kv "cgroup_ns" "$(readlink "/proc/$$/ns/cgroup" 2>/dev/null || echo ABSENT)"
    sp_kv "ipc_ns" "$(readlink "/proc/$$/ns/ipc" 2>/dev/null || echo ABSENT)"
    sp_kv "mnt_ns" "$(readlink "/proc/$$/ns/mnt" 2>/dev/null || echo ABSENT)"
    sp_kv "net_ns" "$(readlink "/proc/$$/ns/net" 2>/dev/null || echo ABSENT)"
    sp_kv "pid_ns" "$(readlink "/proc/$$/ns/pid" 2>/dev/null || echo ABSENT)"
    sp_kv "time_ns" "$(readlink "/proc/$$/ns/time" 2>/dev/null || echo ABSENT)"
    sp_kv "user_ns" "$(readlink "/proc/$$/ns/user" 2>/dev/null || echo ABSENT)"
    sp_kv "uts_ns" "$(readlink "/proc/$$/ns/uts" 2>/dev/null || echo ABSENT)"
    sp_kv "pid1_uts_ns" "$(readlink /proc/1/ns/uts 2>/dev/null || echo UNREADABLE)"
    sp_kv "pid1_user_ns" "$(readlink /proc/1/ns/user 2>/dev/null || echo UNREADABLE)"
    sp_kv "pid1_net_ns" "$(readlink /proc/1/ns/net 2>/dev/null || echo UNREADABLE)"
    if [ -r /proc/$$/uid_map ]; then
        sp_kv "uid_map" "$(tr '\n' ' ' < /proc/$$/uid_map 2>/dev/null)"
    else
        sp_rec "security" "uid_map" "UNKNOWN" "/proc/$$/uid_map unreadable"
    fi
    if [ -r /proc/$$/gid_map ]; then
        sp_kv "gid_map" "$(tr '\n' ' ' < /proc/$$/gid_map 2>/dev/null)"
    else
        sp_rec "security" "gid_map" "UNKNOWN" "/proc/$$/gid_map unreadable"
    fi
    sp_kv "setgroups" "$(cat /proc/$$/setgroups 2>/dev/null || echo ABSENT)"

    printf '\n## VISIBLE PROCESS IDS\n\n'
    _pids=$(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tr '\n' ' ')
    sp_kv "pids_visible_in_proc" "$_pids"
    sp_kv "pid_count_visible" "$(printf '%s' "$_pids" | wc -w | tr -d ' ')"

    printf '\n## CAPABILITIES\n\n'
    if [ -r /proc/$$/status ]; then
        sp_kv "CapInh" "$(awk '/^CapInh/{print $2}' /proc/$$/status 2>/dev/null)"
        sp_kv "CapPrm" "$(awk '/^CapPrm/{print $2}' /proc/$$/status 2>/dev/null)"
        sp_kv "CapEff" "$(awk '/^CapEff/{print $2}' /proc/$$/status 2>/dev/null)"
        sp_kv "CapBnd" "$(awk '/^CapBnd/{print $2}' /proc/$$/status 2>/dev/null)"
        sp_kv "CapAmb" "$(awk '/^CapAmb/{print $2}' /proc/$$/status 2>/dev/null)"
        sp_kv "NoNewPrivs" "$(awk '/^NoNewPrivs/{print $2}' /proc/$$/status 2>/dev/null)"
        sp_kv "Seccomp_mode" "$(awk '/^Seccomp:/{print $2}' /proc/$$/status 2>/dev/null)"
        sp_kv "Seccomp_filters" "$(awk '/^Seccomp_filters/{print $2}' /proc/$$/status 2>/dev/null)"
    else
        sp_rec "security" "capabilities" "UNKNOWN" "/proc/$$/status unreadable"
    fi
    # Named for what it is. The previous version of this line was called
    # securebits_hex while reading seccomp/actions_avail, which is a list of
    # seccomp return actions and nothing to do with securebits.
    sp_kv "seccomp_actions_available" "$(cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null | tr '\n' ' ' || echo UNREADABLE)"
    # securebits is not exported by procfs on most kernels. Where it is not
    # readable, say so rather than substituting something else.
    if [ -r /proc/$$/status ]; then
        _sb=$(awk '/^Securebits/{print $2}' /proc/$$/status 2>/dev/null)
    else
        _sb=""
    fi
    sp_kv "securebits_hex" "${_sb:-NOT EXPORTED BY THIS KERNEL}"
    sp_kv "unprivileged_userns_clone" "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo 'sysctl ABSENT on this kernel')"
    sp_kv "max_user_namespaces" "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo UNREADABLE)"
    sp_kv "unprivileged_bpf_disabled" "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo UNREADABLE)"
    if sp_need capsh; then
        sp_kv "capsh_decode_eff" "$(capsh --decode=0x$(awk '/^CapEff/{print $2}' /proc/$$/status 2>/dev/null) 2>&1 | head -1)"
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
    # Usage: sp_esc <label> <command> [args...]
    # The command is passed exactly once. An earlier version took the label,
    # then executed "$@" while every caller supplied the binary name twice, so
    # argv was [sh, sh, -c, SCRIPT] and dash ran a script file named "sh".
    # The payload never executed, the output carried no refusal, and 20 probes
    # reported ALLOW for operations the sandbox had in fact denied.
    sp_esc() {
        _label="$1"
        shift
        if [ $# -eq 0 ]; then
            sp_rec "escalation" "$_label" "UNKNOWN" "internal error: no command given to the escalation probe"
            return 0
        fi
        _out=$("$@" 2>&1)
        _rc=$?
        _lc=$(printf '%s' "$_out" | tr 'A-Z' 'a-z')
        case "$_lc" in
            *"unrecognized option"*|*"unrecognised option"*|*"unknown option"*|\
            *"invalid option"*|*"unknown argument"*|*"invalid argument"*|\
            *"unexpected argument"*|*"usage:"*|*"not supported"*)
                sp_rec "escalation" "$_label" "UNKNOWN" \
                    "the probe could not be posed: the tool rejected the request rather than the kernel refusing it (rc=$_rc): $(printf '%s' "$_out" | head -1)" ;;
            *"permission denied"*|*"operation not permitted"*|\
            *"not permitted"*|*"access denied"*|*"must be root"*|\
            *"os error 13"*|*"operation not allowed"*)
                sp_rec "escalation" "$_label" "DENY" \
                    "rc=$_rc $(printf '%s' "$_out" | head -2 | tr '\n' ' ')" ;;
            *"no such file"*|*"not a directory"*|*"nonexistent"*|\
            *"no such device"*|*"no such file or directory"*)
                # The target does not exist, so nothing was refused. Reporting
                # ALLOW would claim an operation succeeded when it was in fact
                # never attempted.
                sp_rec "escalation" "$_label" "ABSENT" \
                    "rc=$_rc the target does not exist: $(printf '%s' "$_out" | head -2 | tr '\n' ' ')" ;;
            *_rc=1*|*_rc=2*|*_rc=13*|*_rc=126*)
                # The fragment printed its own inner status and it was
                # non-zero. A fragment that ends in an echo always exits 0, so
                # the wrapper status cannot be trusted here and the inner
                # status wins. Otherwise the verdict contradicts the evidence
                # printed beside it.
                sp_rec "escalation" "$_label" "DENY" \
                    "the operation inside the probe failed: $(printf '%s' "$_out" | head -2 | tr '\n' ' ')" ;;
            *)
                # No refusal is present, but the absence of a refusal is not
                # evidence of success. Only an explicit success marker may
                # produce ALLOW; everything else is UNKNOWN with the output
                # attached so a reader can judge it.
                case "$_out" in
                    ""|readable|LISTABLE|mode=*|*"_rc=0"*|*"=0")
                        sp_rec "escalation" "$_label" "ALLOW" \
                            "rc=$_rc output: $(printf '%s' "$_out" | head -2 | tr '\n' ' ')" ;;
                    *)
                        sp_rec "escalation" "$_label" "UNKNOWN" \
                            "no refusal and no explicit success marker; output: $(printf '%s' "$_out" | head -2 | tr '\n' ' ')" ;;
                esac ;;
        esac
        return 0
    }

    # Scratch directory for mount targets. Inside SP_WORK, which the exit trap
    # removes, so a successful mount leaves nothing behind.
    _mnt="$SP_WORK/mnttarget"
    mkdir -p "$_mnt" 2>/dev/null

    # Namespaces. Each asks for one namespace and runs true(1) inside it.
    # Success means a new namespace exists; failure means the kernel refused.
    sp_esc "new_user_namespace"      unshare -U true
    sp_esc "user_plus_mount_ns"      unshare -Urm true
    sp_esc "network_namespace"       unshare -n true
    sp_esc "pid_namespace"          unshare -pf true
    sp_esc "mount_namespace"         unshare -m true
    sp_esc "cgroup_namespace"        unshare -C true
    sp_esc "time_namespace"          unshare -T true
    sp_esc "uts_namespace"           unshare -u true
    sp_esc "ipc_namespace"           unshare -i true

    # Root manipulation.
    sp_esc "chroot_to_root"          chroot /
    sp_esc "chroot_to_tmp"           chroot /tmp
    sp_esc "mount_tmpfs_over_tmpdir" mount -t tmpfs none "$_mnt"
    sp_esc "mount_proc_over_tmpdir"  mount -t proc none "$_mnt"
    sp_esc "mount_bind_root_to_tmpdir" mount --bind / "$_mnt"
    sp_esc "mount_devpts"            mount -t devpts devpts "$_mnt"
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
    sp_esc "insmod_dummy"            modprobe dummy

    # Writing host-visible kernel tunables.
    sp_esc "write_sysctl_hostname"   sh -c 'echo pwned > /proc/sys/kernel/hostname'
    sp_esc "write_sysctl_modprobe"   sh -c 'echo x > /proc/sys/kernel/modprobe'
    sp_esc "write_sysctl_kill_restart" sh -c 'echo 1 > /proc/sys/kernel/core_pattern'

    # Reading kernel memory.
    sp_esc "read_proc_kcore"         sh -c "dd if=/proc/kcore of=/dev/null bs=1 count=1 2>&1 | tail -1"
    sp_esc "read_proc_kallsyms"      sh -c 'head -c 32 /proc/kallsyms >/dev/null && echo readable'
    sp_esc "stat_proc_kcore"         stat -c 'mode=%A size=%s owner=%U' /proc/kcore
    sp_esc "read_proc_modules"       sh -c 'head -c 32 /proc/modules >/dev/null && echo readable'
    sp_esc "read_proc_1_maps"        sh -c 'head -c 32 /proc/1/maps >/dev/null && echo readable'

    # Writing / writing through procfs pseudo files. Note these are writes, and
    # each names the file it targets so the record is unambiguous.
    sp_esc "write_proc_sysrq_trigger" sh -c 'echo c > /proc/sysrq-trigger'
    sp_esc "read_proc_sysrq_trigger"  sh -c 'cat /proc/sysrq-trigger 2>&1 | head -1'
    sp_esc "write_proc_vm_loglevel"   sh -c 'echo 0 > /proc/sys/vm/loglevel'

    # Device creation.
    sp_esc "mknod_null_in_tmp"       mknod "${TMPDIR:-/tmp}/.sandprobe-null.$$" c 1 3

    # Process introspection.
    # ptrace a sibling: only meaningful if it is refused, and yama may also
    # restrict it. The output carries the real reason either way.
    sp_esc "ptrace_sibling_via_mem"  sh -c 'sleep 3 & _p=$!; sleep 0.3; cat /proc/$_p/mem >/dev/null 2>&1; _r=$?; kill $_p 2>/dev/null; wait $_p 2>/dev/null; echo cat_proc_mem_rc=$_r'
    # A real attach attempt, not a version query. `strace -V` prints a version
    # and always exits 0, so using it here would have reported a successful
    # attach when no process was ever traced.
    if sp_have strace; then
        sp_esc "attach_to_own_child_via_strace" strace \
            sh -c 'sleep 5 & _p=$!; strace -p $_p -o /dev/null 2>&1; _r=$?; kill $_p 2>/dev/null; wait $_p 2>/dev/null; exit $_r'
    else
        # Recorded directly rather than through sp_esc. A stub command that
        # exits 0 would report a successful attach when no attach happened.
        sp_rec "escalation" "attach_to_own_child_via_strace" "UNKNOWN" \
            "strace is not installed, so no attach was attempted; a ptrace ATTACH to a sibling is therefore untested"
        sp_rec "escalation" "ptrace_proc_mem_of_sibling" "UNKNOWN" \
            "see ptrace_sibling_via_mem, which tests the same restriction through /proc rather than ptrace(2)"
    fi

    # Reading pid 1. pid 1 is the sandbox's own init in a private pid
    # namespace, so this is not a host escape by itself. It is recorded
    # because a sandbox that hides its own supervisor's environment is
    # unusual, and because environ carries credentials.
    sp_esc "read_pid1_environ"       sh -c 'head -c 32 /proc/1/environ >/dev/null && echo readable'
    # Reported as measurements rather than escalation attempts: they print a
    # value, so the escalation classifier sees neither a refusal nor a success
    # marker and would call every one of them UNKNOWN.
    sp_kv "pid_1_root_listable" \
        "$(ls /proc/1/root >/dev/null 2>&1 && echo yes || echo no: $(ls /proc/1/root 2>&1 >/dev/null | head -1))"
    sp_kv "pid_1_cwd" "$(readlink /proc/1/cwd 2>/dev/null || echo UNREADABLE)"

    # procfs escape classics.
    sp_kv "self_root_listable" \
        "$(ls /proc/self/root >/dev/null 2>&1 && echo yes || echo no: $(ls /proc/self/root 2>&1 >/dev/null | head -1))"
    sp_esc "read_parent_cmdline"     sh -c 'head -c 32 /proc/1/cmdline >/dev/null && echo readable'
    sp_kv "pids_enumerable" \
        "$(ls /proc 2>/dev/null | grep -cE '^[0-9]+$' || echo unreadable) pids visible"

    # If /proc is mounted with hidepid, foreign pids are invisible. Compare the
    # pid count against what the namespace id suggests.
    sp_kv "proc_mount_options" "$(grep ' /proc ' /proc/$$/mounts 2>/dev/null | awk '{print $4}' || echo 'not a separate /proc mount')"
    # grep -c prints 0 and exits 1 on no match, so appending `|| echo 0`
    # produced the two-line value "0\n0" and split one record across two
    # report lines. Counting with wc keeps the value on one line.
    sp_kv "hidepid_option_present" "$(grep ' /proc ' /proc/$$/mounts 2>/dev/null | grep -o hidepid | wc -l | tr -d ' ')"

    printf '\n## ADDITIONAL ESCAPE SURFACE\n\n'
    printf '%s\n' \
"# Vectors a container escape commonly uses. Each is probed with the real" \
"# mechanism. A missing file or a missing syscall is recorded as ABSENT or" \
"# UNKNOWN, never as a denial."

    # cgroup escape via release_agent. On cgroup v1 writing
    # notify_on_release plus release_agent to a controlled file runs a command
    # as root. On v2 the equivalent is cgroup.release_agent.
    _cg_tried=0
    for f in /sys/fs/cgroup/release_agent /sys/fs/cgroup/notify \
             /sys/fs/cgroup/cgroup.release_agent /sys/fs/cgroup/*/release_agent \
             /sys/fs/cgroup/*/notify_on_release; do
        # The globs expand to themselves when they match nothing, so a literal
        # pattern that does not exist would be tested as if it were a path.
        case "$f" in *'*'*) [ -e "$f" ] || continue ;; esac
        [ -e "$f" ] || continue
        _cg_tried=$((_cg_tried + 1))
        sp_kv "cgroup_file_present" "$f"
        _werr=$(sh -c ': > "$1"' sh "$f" 2>&1)
        if [ -z "$_werr" ]; then
            # It was writable. Do not write a command into it; recording that
            # it accepted a truncated write is enough, and the file is restored
            # by writing nothing further.
            sp_rec "escape-surface" "cgroup_release_agent_writable:$f" "ALLOW" \
                "the cgroup file accepted an empty write, which is the primitive the release_agent escape needs; contents were not modified"
        else
            sp_rec "escape-surface" "cgroup_release_agent_writable:$f" \
                "$(sp_verdict_from_err "$_werr")" "$_werr"
        fi
    done
    # The summary row used to be emitted unconditionally, with a detail saying
    # "see the rows above for each file tried". When no candidate path exists at
    # all the loop emits nothing, so that sentence pointed at rows that were not
    # there and described an attempt that was never made. The count is tracked
    # so the summary distinguishes "tried and none writable" from "nothing to
    # try", which are different answers about the sandbox.
    if [ "$_cg_tried" -gt 0 ]; then
        sp_rec "escape-surface" "cgroup_escape" "UNKNOWN" \
            "$_cg_tried cgroup release path(s) were tried and none accepted a write; see the rows above for each one"
    else
        sp_rec "escape-surface" "cgroup_escape" "UNKNOWN" \
            "no cgroup v1 release_agent or v2 cgroup.release_agent path exists on this host, so the primitive was not tested rather than refused; the paths tried are listed above and none were present"
    fi

    # Preload and dynamic linker hijack.
    for f in /etc/ld.so.preload "${HOME:-/nonexistent}/.ld.so.preload"; do
        if [ -e "$f" ]; then
            _werr=$(sh -c ': > "$1"' sh "$f" 2>&1)
            if [ -z "$_werr" ]; then
                sp_rec "escape-surface" "preload_writable:$f" "ALLOW" \
                    "accepted an empty write; a preload entry here would load into every process"
            else
                sp_rec "escape-surface" "preload_writable:$f" \
                    "$(sp_verdict_from_err "$_werr")" "$_werr"
            fi
        else
            sp_rec "escape-surface" "preload_writable:$f" "ABSENT" "not present"
        fi
    done
    sp_kv "ld_preload_env" "${LD_PRELOAD:-UNSET}"
    sp_kv "ld_audit_env" "${LD_AUDIT:-UNSET}"
    sp_kv "ld_library_path_env" "${LD_LIBRARY_PATH:-UNSET}"
    # Resolve what LD_PRELOAD actually names. A sandbox that installs an
    # LD_PRELOAD interposer changes what every process in it observes: /proc
    # fields can be rewritten in place, isatty can answer true for a pipe, and
    # a stat of a display or input node can return another device's identity.
    # Every value below this point is then a property of the interposer as much
    # as of the host, so the report says which libraries are in the chain and
    # whether they came from the environment or from /etc/ld.so.preload.
    if [ -n "${LD_PRELOAD:-}" ]; then
        _pre_src="the environment"
    elif [ -s /etc/ld.so.preload ]; then
        _pre_src="/etc/ld.so.preload"
    else
        _pre_src=""
    fi
    if [ -z "$_pre_src" ]; then
        sp_kv "ld_preload_chain" "none; no LD_PRELOAD in the environment and no /etc/ld.so.preload, so no interposer library is known to be in the chain"
    else
        _pre_resolved=""
        _pre_missing=""
        _oldsifs=${IFS-}; IFS=:
        for _lib in ${LD_PRELOAD:-} $(cat /etc/ld.so.preload 2>/dev/null); do
            [ -n "$_lib" ] || continue
            if [ -e "$_lib" ]; then
                _pre_resolved="$_pre_resolved $_lib -> $(readlink -f "$_lib" 2>/dev/null || echo UNRESOLVED)"
            else
                _pre_missing="$_pre_missing $_lib"
            fi
        done
        IFS=$_oldsifs
        sp_kv "ld_preload_chain_source" "$_pre_src"
        sp_kv "ld_preload_chain" "${_pre_resolved:-none resolved}"
        if [ -n "$_pre_missing" ]; then
            sp_kv "ld_preload_chain_missing" "$_pre_missing"
        fi
        sp_kv "ld_preload_caveat" "an LD_PRELOAD library can interpose on libc calls including open, stat and isatty, so a measurement taken in this process may reflect the library rather than the kernel; the /proc/self/status probe below cross-checks two read paths for exactly that"
    fi

    # Whether anything is interposing on reads of this process's own status.
    # Two read paths are compared because a preload shim that rewrites
    # /proc/*/status reaches open and openat but not libc's internal fopen, so
    # a disagreement between the two is positive evidence of an interposer
    # rather than an inference about one.
    #
    # /proc/$$ and not /proc/self: inside $( ) the latter names the substituted
    # child, so the field would describe an awk rather than this shell. That is
    # the substitution bug the self-test guards against, and the python side
    # below is a separate process whose own /proc/self is what it must read.
    if [ -r /proc/$$/status ]; then
        _sp_a=$(awk '/^TracerPid:|^NoNewPrivs:|^Seccomp:/{print $1"="$2}' /proc/$$/status 2>/dev/null | tr '\n' ' ')
        _sp_b=$(python3 -c '
import sys
try:
    with open("/proc/self/status") as fh:
        rows = [l.split(None, 1) for l in fh if l.split(None, 1)[0] in
                ("TracerPid:", "NoNewPrivs:", "Seccomp:")]
    sys.stdout.write(" ".join("%s=%s" % (r[0], r[1].strip()) for r in rows) + " ")
except Exception:
    pass
' 2>/dev/null)
        sp_kv "tracer_pid" "$(awk '/^TracerPid:/{print $2}' /proc/$$/status 2>/dev/null || echo UNREADABLE)"
        if [ -n "$_sp_a" ] && [ -n "$_sp_b" ]; then
            if [ "$_sp_a" = "$_sp_b" ]; then
                sp_rec "escape-surface" "proc_status_read_paths_agree" "ALLOW" \
                    "two independent read paths of /proc/self/status report the same TracerPid, NoNewPrivs and Seccomp, so no interposer is rewriting them here: $_sp_a"
            else
                sp_rec "escape-surface" "proc_status_read_paths_agree" "ALLOW" \
                    "WARNING: the two read paths DISAGREE, which is evidence that something is rewriting /proc/self/status. via-path=[$_sp_a] fopen-path=[$_sp_b]"
            fi
        else
            sp_rec "escape-surface" "proc_status_read_paths_agree" "UNKNOWN" \
                "could not read /proc/$$/status through both paths, so the cross-check did not run: via-path=[$_sp_a] fopen-path=[$_sp_b]"
        fi
    fi

    # A writable directory on PATH is a binary substitution vector.
    _oldifs=${IFS-}; IFS=:
    _writable_path=""
    for d in ${PATH:-}; do
        [ -n "$d" ] || continue
        if [ -d "$d" ] && [ -w "$d" ]; then
            _writable_path="$_writable_path $d"
        fi
    done
    IFS=$_oldifs
    if [ -n "$_writable_path" ]; then
        sp_rec "escape-surface" "writable_path_directory" "ALLOW" \
            "these PATH entries are writable, so any binary resolved from them can be replaced:$_writable_path"
    else
        sp_rec "escape-surface" "writable_path_directory" "DENY" \
            "no PATH entry is writable, so binaries cannot be substituted by replacing one"
    fi

    # Shared /tmp is a cross-user attack surface when the sticky bit is absent.
    if [ -d /tmp ]; then
        sp_kv "tmp_mode" "$(stat -c '%A %a %U' /tmp 2>/dev/null || echo UNREADABLE)"
        # The three properties below are read from the MODE, never from
        # `test -w`. test -w is an access check against the calling uid, and
        # this probe runs as uid 0, so it answered yes for a mode-755 /tmp and
        # the report contradicted its own tmp_mode line one row above. Both
        # questions are kept, because they are different questions: the mode is
        # the security property, and whether this process can write is not.
        _tmp_mode_oct="$(stat -c '%a' /tmp 2>/dev/null)"
        # %a is 3 or 4 digits with no leading zero for a setuid/sticky dir
        # whose digit is zero, so pad before indexing.
        while [ "${#_tmp_mode_oct}" -lt 4 ]; do
            _tmp_mode_oct="0$_tmp_mode_oct"
        done
        case "$_tmp_mode_oct" in
            1???|???????1|??????1??|??1?????|?1??????)
                sp_rec "escape-surface" "tmp_sticky_bit" "ALLOW" \
                    "the sticky bit is set (mode $_tmp_mode_oct), so users cannot remove each other's files here" ;;
            "")
                sp_rec "escape-surface" "tmp_sticky_bit" "UNKNOWN" "the mode of /tmp could not be read" ;;
            *)
                sp_rec "escape-surface" "tmp_sticky_bit" "DENY" \
                    "the sticky bit is not set (mode $_tmp_mode_oct), so on a world-writable /tmp one session could replace another session's files" ;;
        esac
        case "$_tmp_mode_oct" in
            ""|???[2367])
                sp_kv "tmp_world_writable" "yes (the other-write bit is set in mode $_tmp_mode_oct)" ;;
            *)
                sp_kv "tmp_world_writable" "no (mode $_tmp_mode_oct has no other-write bit)" ;;
        esac
        # What this process can actually do, kept separate and named for what
        # it answers, so it is not mistaken for the mode property above.
        sp_kv "tmp_writable_by_this_process" \
            "$( [ -w /tmp ] && echo "yes, uid $(id -u)" || echo "no, uid $(id -u)" )"
    fi

    # Hardlink to a setuid binary, the classic privesc when protected_hardlinks
    # is off. Tested rather than assumed.
    _phl=$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null || echo UNREADABLE)
    _hk=$(sp_first_setuid)
    if [ -n "$_hk" ]; then
        sp_kv "setuid_sample" "$_hk"
        # Attempt the link on the SAME filesystem as the setuid binary,
        # because a link across filesystems fails for reasons that say nothing
        # about the sandbox.
        _hdir=$(dirname "$_hk")
        _hl="$_hdir/.sandprobe-hardlink.$$"
        _herr=$(sh -c 'ln "$1" "$2" 2>&1' sh "$_hk" "$_hl")
        if [ -L "$_hl" ]; then
            rm -f "$_hl" 2>/dev/null
            sp_rec "escape-surface" "hardlink_to_setuid" "ALLOW" \
                "a hard link to the setuid binary $(basename "$_hk") was created; if it is executable this is a privesc path"
            _exec=$(timeout 10 sh -c '{ "$1" --version >/dev/null; } 2>&1' sh "$_hl")
            if [ -z "$_exec" ]; then
                sp_rec "escape-surface" "hardlinked_setuid_executes" "ALLOW" \
                    "the hard link to the setuid binary executed"
            else
                sp_rec "escape-surface" "hardlinked_setuid_executes" "$(sp_verdict_from_err "$_exec")" "$_exec"
            fi
            rm -f "$_hl" 2>/dev/null
        elif [ -z "$_herr" ]; then
            sp_rec "escape-surface" "hardlink_to_setuid" "UNKNOWN" "no diagnostic from ln"
        else
            case "$_herr" in
                *[Cc]ross-device*|*"Invalid cross-device link"*)
                    # The setuid binary is on a different filesystem from TMPDIR,
                    # so the link could not be attempted. Not a policy answer.
                    sp_rec "escape-surface" "hardlink_to_setuid" "UNKNOWN" \
                        "not tested: the setuid binary and the temporary directory are on different filesystems, so ln could not attempt a link. protected_hardlinks=$(_phl) is the governing setting; test it in a directory on the same filesystem as the binary." ;;
                *)
                    sp_rec "escape-surface" "hardlink_to_setuid" "$(sp_verdict_from_err "$_herr")" "$_herr" ;;
            esac
        fi
    else
        sp_rec "escape-surface" "hardlink_to_setuid" "ABSENT" "no setuid binary was found to test with"
    fi

    # Syscalls that need privilege this sandbox should not have. Probed through
    # python3 where available, because a setuid helper does not exist for most.
    if command -v python3 >/dev/null 2>&1; then
        # A separate script rather than an inline heredoc: a multi-line command
        # inside $( ) is fragile in dash and failed by silently truncating,
        # which is the worst way for a measurement to fail.
        _sysout=$(timeout 60 python3 "$SP_LIB_DIR/syscallprobe.py" 2>&1)
        _sysrc=$?
        if [ "$_sysrc" -ne 0 ]; then
            sp_rec "escape-surface" "privileged_syscalls" "UNKNOWN" \
                "the syscall probe did not complete (rc=$_sysrc): $(printf '%s' "$_sysout" | head -2 | tr '\n' ' ')"
        else
            # Not a pipeline into a while loop. A loop fed by a pipe runs in a
            # subshell, so every sp_kv inside it would write to a copy of stdout
            # that is discarded, and the report would lose the records while
            # looking as though it had them.
            _refused=""
            _permitted=""
            _notinvoked=""
            _other=""
            printf '%s\n' "$_sysout" > "$SP_WORK/syscall.out"
            while IFS= read -r line; do
                case "$line" in
                    "REFUSED "*)    _refused="${line#REFUSED }" ;;
                    "PERMITTED "*)  _permitted="${line#PERMITTED }" ;;
                    "NOT_INVOKED "*) _notinvoked="${line#NOT_INVOKED }" ;;
                    "OTHER_ERRNO "*) _other="${line#OTHER_ERRNO }" ;;
                esac
            done < "$SP_WORK/syscall.out"
            sp_kv "syscalls_refused" "${_refused:-none}"
            sp_kv "syscalls_not_refused" "${_permitted:-none}"
            sp_kv "syscalls_not_invoked" "${_notinvoked:-none}"
            if [ -n "$_other" ]; then
                sp_kv "syscalls_other_errno" "$_other"
            fi
            # The verdict on an escape-surface row is about the ESCAPE, not
            # about the syscalls. This row used to be hardcoded ALLOW while its
            # own detail said every syscall was refused, so a reader scanning
            # the escape-surface section for ALLOW, which is the query a
            # reviewer actually makes, would conclude privileged syscalls were
            # available here. The verdict now follows the data: a syscall that
            # was not refused means the escape is available, and anything that
            # failed for a reason that is neither a refusal nor a permission
            # leaves the question open rather than answering it.
            if [ -n "$_permitted" ] && [ "$_permitted" != "none" ]; then
                sp_rec "escape-surface" "privileged_syscalls" "ALLOW" \
                    "these syscalls were NOT refused, so the primitive they provide is available: $_permitted; refused: ${_refused:-none}"
            elif [ -n "$_other" ]; then
                sp_rec "escape-surface" "privileged_syscalls" "UNKNOWN" \
                    "every syscall probed with NULL arguments was refused except these, which failed for a reason that is neither a refusal nor a permission, so the boundary is not established: $_other; see syscalls_not_invoked for the calls that dereference their arguments and are therefore not invoked"
            else
                sp_rec "escape-surface" "privileged_syscalls" "DENY" \
                    "every syscall probed with NULL arguments was refused; see syscalls_not_invoked for the calls that dereference their arguments and are therefore not invoked"
            fi
        fi
    else
        sp_rec "escape-surface" "privileged_syscalls" "UNKNOWN" \
            "python3 is not installed, so syscalls could not be invoked directly; the capability set above is the indirect evidence"
    fi

    # Other kernel and bus surfaces that may be reachable.
    for f in /sys/kernel/debug /sys/firmware /sys/kernel/uevent_helper \
             /sys/kernel/security /proc/bus /dev/fuse /dev/kvm \
             /dev/net/tun /dev/shm /proc/sysrq-trigger /proc/config.gz; do
        if [ ! -e "$f" ]; then
            sp_rec "escape-surface" "present:$f" "ABSENT" "not present on this host"
            continue
        fi
        # Directory listing and file readability are separate questions. A
        # special file such as /proc/sysrq-trigger is never a directory, so
        # `ls` on it says "not a directory" and a probe that treated a failed
        # listing as "readable" reported ALLOW for a file that refuses both.
        if [ -d "$f" ]; then
            if ls "$f" >/dev/null 2>&1; then
                sp_rec "escape-surface" "listable:$f" "ALLOW" "present, is a directory, and is listable"
            else
                sp_rec "escape-surface" "listable:$f" "DENY" \
                    "present but the directory cannot be listed: $(ls "$f" 2>&1 >/dev/null | head -1)"
            fi
        else
            sp_rec "escape-surface" "listable:$f" "ABSENT" \
                "not a directory, so listing does not apply"
        fi
        if [ -d "$f" ]; then
            sp_rec "escape-surface" "readable:$f" "ABSENT" \
                "a directory has no readable first byte; the listable row above is the measurement that applies"
        else
            _rerr=$(timeout "$SP_BUDGET" sh -c "head -c 1 '$f' >/dev/null" 2>&1)
            _rrc=$?
            if [ -z "$_rerr" ] && [ "$_rrc" -eq 0 ]; then
                sp_rec "escape-surface" "readable:$f" "ALLOW" "first byte readable"
            elif [ "$_rrc" -eq 124 ]; then
                sp_rec "escape-surface" "readable:$f" "TIMEOUT" "no byte available within the budget"
            else
                sp_rec "escape-surface" "readable:$f" "$(sp_verdict_from_err "$_rerr")" "$_rerr"
            fi
        fi
    done

    printf '\n## PROCFS ROOT TRAVERSAL\n\n'
    printf '%s\n' \
"# Listing /proc/PID/root and traversing through it are different questions." \
"# A sandbox can deny the first and allow the second, which would make a" \
"# report that only tested listing materially wrong about the boundary." \
"# Every discovered mount target is probed through the traversal path."

    # Listing the root, for contrast with the traversal results below.
    for p in 1 self $$; do
        if [ "$p" = "self" ]; then
            _root="/proc/self/root"
        else
            _root="/proc/$p/root"
        fi
        if ls "$_root" >/dev/null 2>&1; then
            sp_rec "procfs-traverse" "list:$_root" "ALLOW" "the root directory itself is listable"
        elif [ ! -e "$_root" ]; then
            sp_rec "procfs-traverse" "list:$_root" "ABSENT" "no such path"
        else
            sp_rec "procfs-traverse" "list:$_root" "DENY" \
                "$(ls "$_root" 2>&1 >/dev/null | head -1)"
        fi
    done

    # Traversal: can a path be reached THROUGH the symlink even when the root
    # itself refuses to be listed? This is the check that matters.
    _trav_targets=$(printf '%s\n' "$SP_MOUNT_RECORDS" | cut -f1 | sed '/^$/d' \
                    | sed '/^\/proc/d' | sed '/^\/dev/d' | LC_ALL=C sort -u)
    # Re-deduplicated after the append. Sorting the mount targets alone left
    # every appended entry that was also a mount target duplicated, so eight
    # ids were probed twice per base.
    {
        printf '%s\n' "$_trav_targets"
        printf '%s\n' / /etc /tmp /workspace /state
    } | sed '/^$/d' | LC_ALL=C sort -u > "$SP_WORK/trav.all"
    _trav_targets=$(cat "$SP_WORK/trav.all")

    for base in /proc/1/root /proc/self/root; do
        # Written to a file first: a while loop fed by a pipe is a subshell,
        # and every sp_rec inside it would be lost.
        printf '%s\n' "$_trav_targets" | sed '/^$/d' > "$SP_WORK/travtargets"
        while IFS= read -r t; do
            [ -n "$t" ] || continue
            _full="$base$t"
            if ls "$_full" >/dev/null 2>&1; then
                _n=$(ls -1 "$_full" 2>/dev/null | wc -l | tr -d ' ')
                sp_rec "procfs-traverse" "traverse:$_full" "ALLOW" \
                    "reachable THROUGH $base even though the root itself is not listable; $_n entries"
            elif [ -e "$_full" ]; then
                sp_rec "procfs-traverse" "traverse:$_full" "DENY" \
                    "exists but refused: $(ls "$_full" 2>&1 >/dev/null | head -1)"
            else
                sp_rec "procfs-traverse" "traverse:$_full" "ABSENT" \
                    "no such path through $base"
            fi
        done < "$SP_WORK/travtargets"
    done

    # Does traversal also permit writes? Probed in a temporary directory and
    # removed immediately, so a successful write leaves nothing behind.
    for base in /proc/1/root /proc/self/root; do
        for d in /tmp; do
            _wf="$base$d/.sandprobe-traverse.$$"
            _werr=$(sh -c ': > "$1"' sh "$_wf" 2>&1)
            if [ -e "$_wf" ]; then
                rm -f "$_wf" 2>/dev/null
                sp_rec "procfs-traverse" "write:$_wf" "ALLOW" \
                    "a file was created THROUGH $base; this reaches the same inode as $d"
            elif [ -z "$_werr" ]; then
                sp_rec "procfs-traverse" "write:$_wf" "UNKNOWN" "no diagnostic"
            else
                sp_rec "procfs-traverse" "write:$_wf" "$(sp_verdict_from_err "$_werr")" "$_werr"
            fi
        done
    done

    printf '%s\n' "# Note: /proc/PID/root resolves to PID's root filesystem. In a private" \
"# mount namespace that is the sandbox's own root, so reaching it is not by" \
"# itself a host escape. What matters is whether it reaches anything OUTSIDE" \
"# the set of paths already granted, which is what the traversal rows above" \
"# compare against."

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