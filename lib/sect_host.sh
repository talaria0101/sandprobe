#!/bin/sh
# sandprobe section: host identity, kernel, CPU, memory, time, resources.
# SPDX-License-Identifier: 0BSD

sp_section_host() {
    SP_CUR="host"

    printf '\n## HOST IDENTITY\n\n'
    sp_kv "hostname_sysctl" "$(cat /proc/sys/kernel/hostname 2>/dev/null || echo UNREADABLE)"
    sp_kv "uts_nodename" "$(uname -n 2>/dev/null)"
    sp_kv "kernel_release" "$(uname -r 2>/dev/null)"
    sp_kv "kernel_version" "$(uname -v 2>/dev/null)"
    sp_kv "machine" "$(uname -m 2>/dev/null)"
    sp_kv "system" "$(uname -s 2>/dev/null)"
    sp_kv "processor" "$(uname -p 2>/dev/null)"
    sp_kv "proc_version" "$(cat /proc/version 2>/dev/null || echo UNREADABLE)"
    sp_kv "proc_cmdline" "$(cat /proc/cmdline 2>/dev/null || echo UNREADABLE)"
    sp_kv "os_release" "$(cat /etc/os-release 2>/dev/null | tr '\n' ' ' || echo ABSENT)"
    sp_kv "libc" "$(ls -l /lib/libc.so.6 2>/dev/null || echo ABSENT)"

    printf '\n## TIME\n\n'
    sp_kv "utc_now" "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
    sp_kv "local_now" "$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)"
    sp_kv "timezone" "$(date '+%Z%z' 2>/dev/null)"
    sp_kv "epoch_seconds" "$(date '+%s' 2>/dev/null)"
    sp_kv "uptime_seconds" "$(cut -d. -f1 /proc/uptime 2>/dev/null)"

    printf '\n## CPU\n\n'
    if [ -r /proc/cpuinfo ]; then
        sp_kv "model_name" "$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "vendor" "$(grep -m1 '^vendor_id' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "cpu_family" "$(grep -m1 '^cpu family' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "model_number" "$(grep -m1 '^model[[:space:]]*:' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "microcode" "$(grep -m1 '^microcode' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "logical_cpus_in_cpuinfo" "$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
        sp_kv "physical_ids" "$(grep -m1 '^physical id' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "siblings" "$(grep -m1 '^siblings' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "cpu_cores" "$(grep -m1 '^cpu cores' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
        sp_kv "flags" "$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
    else
        sp_rec "host" "cpuinfo" "UNKNOWN" "/proc/cpuinfo unreadable"
    fi
    if sp_need nproc; then
        sp_kv "nproc_reported" "$(nproc 2>/dev/null)"
        sp_kv "nproc_affinity" "$(nproc --all 2>/dev/null)"
        sp_kv "cpu_online" "$(cat /sys/devices/system/cpu/online 2>/dev/null || echo UNREADABLE)"
    fi
    sp_kv "Cpus_allowed_list" "$(awk '/^Cpus_allowed_list/{print $2}' /proc/self/status 2>/dev/null)"

    printf '\n## MEMORY\n\n'
    if [ -r /proc/meminfo ]; then
        while IFS= read -r line; do
            sp_kv "mem_${line%%:*}" "$(printf '%s' "$line" | sed 's/^[^:]*:[[:space:]]*//')"
        done <<EOF
$(grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Dirty|Writeback|AnonPages|Mapped|Shmem|SReclaimable|Slab|KernelStack|PageTables|SecPageTables|CommitLimit|Committed_AS|VmallocTotal|VmallocUsed|VmallocChunk|Percpu|HugePages_Total|HugePages_Free|Hugepagesize|HugePagesizeAnon|HugePagesizeShmem|NUMA_Hit|NUMA_miss)' /proc/meminfo 2>/dev/null)
EOF
    else
        sp_rec "host" "meminfo" "UNKNOWN" "/proc/meminfo unreadable"
    fi

    printf '\n## PRESSURE AND THROTTLING\n\n'
    sp_kv "loadavg_1_5_15" "$(cat /proc/loadavg 2>/dev/null)"
    sp_kv "pressure_cpu" "$(cat /proc/pressure/cpu 2>/dev/null || echo ABSENT)"
    sp_kv "pressure_memory" "$(cat /proc/pressure/memory 2>/dev/null || echo ABSENT)"
    sp_kv "pressure_io" "$(cat /proc/pressure/io 2>/dev/null || echo ABSENT)"

    printf '\n## CGROUP LIMITS\n\n'
    sp_kv "self_cgroup" "$(cat /proc/self/cgroup 2>/dev/null | tr '\n' ' ')"
    if [ -d /sys/fs/cgroup ]; then
        sp_kv "cgroup_version" "v2 unified at /sys/fs/cgroup"
        sp_kv "cgroup_cpu_max" "$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo UNSET)"
        sp_kv "cgroup_memory_max" "$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo UNSET)"
        sp_kv "cgroup_memory_current" "$(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo UNSET)"
        sp_kv "cgroup_pids_max" "$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo UNSET)"
        sp_kv "cgroup_pids_current" "$(cat /sys/fs/cgroup/pids.current 2>/dev/null || echo UNSET)"
        sp_kv "cgroup_io_max" "$(cat /sys/fs/cgroup/io.max 2>/dev/null || echo UNSET)"
    else
        sp_kv "cgroup_version" "v1 or not mounted (no /sys/fs/cgroup)"
    fi

    printf '\n## RLIMIT OF THE PROBING PROCESS\n\n'
    if [ -r /proc/self/limits ]; then
        sp_raw "# each row: limit soft hard unit"
        cat /proc/self/limits 2>/dev/null | sp_scrub
    else
        sp_rec "host" "rlimits" "UNKNOWN" "/proc/self/limits unreadable"
    fi
    sp_kv "umask" "$(awk '/^Umask/{print $2}' /proc/self/status 2>/dev/null)"
}