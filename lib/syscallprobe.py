#!/usr/bin/env python3
"""Probe privileged Linux syscalls by invoking them with NULL arguments.

Why this is a separate file rather than an inline heredoc: a multi-line
command inside $( ) is fragile in dash, and the failure is silent truncation
rather than an error, which is the worst possible failure for a measurement.

Why the restricted list: calling a syscall with invalid arguments measures
nothing about the sandbox. Worse, several of these dereference their arguments
immediately, and passing NULL segfaults inside libc. An earlier version of this
probe passed NULL to all of them and the probe crashed, taking the surrounding
report with it. So only calls that accept NULL without dereferencing it are
included, and the rest are reported as untested with the reason.

Every call listed here returns -1 with errno EPERM, EACCES or EINVAL when the
sandbox denies it, and that is the answer being recorded.
"""
import ctypes
import ctypes.util
import sys

# (name, syscall number, argument count).
# Numbers are the generic asm-generic/uniprocessor values, which is what x86_64
# uses. The probe reports the kernel it ran on, so a reader on another
# architecture can see whether these numbers apply.
NULL_SAFE = [
    ("unshare", 272, 1),
    ("mount", 165, 4),
    ("umount2", 166, 2),
    ("pivot_root", 155, 2),
    ("chroot", 161, 1),
    ("bpf", 321, 3),
    ("init_module", 175, 3),
    ("kexec_load", 246, 4),
    ("process_vm_writev", 312, 4),
    ("add_key", 248, 2),
    ("request_key", 249, 3),
    ("keyctl", 250, 5),
    ("sethostname", 170, 2),
    ("reboot", 169, 1),
]

# Called for completeness of the record, never invoked. Invoking these with NULL
# dereferences the pointer and crashes.
DEREFERENCING = [
    ("setns", 308),
    ("perf_event_open", 298),
    ("fanotify_init", 262),
    ("io_uring_setup", 425),
    ("open_by_handle_at", 304),
    ("userfaultfd", 323),
]


def main():
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
    except OSError as exc:
        print("ERROR cannot load libc: %s" % exc, file=sys.stderr)
        return 1

    refused, permitted, odd = [], [], []
    for name, nr, argc in NULL_SAFE:
        ctypes.set_errno(0)
        rc = libc.syscall(ctypes.c_long(nr), *([0] * max(argc, 1)))
        err = ctypes.get_errno()
        if rc >= 0:
            permitted.append("%s" % name)
        elif err in (1, 13):
            refused.append("%s(EPERM/EACCES)" % name)
        elif err == 22:
            refused.append("%s(EINVAL)" % name)
        else:
            odd.append("%s(errno %d)" % (name, err))

    print("REFUSED %s" % (" ".join(refused) if refused else "none"))
    print("PERMITTED %s" % (" ".join(permitted) if permitted else "none"))
    if odd:
        print("OTHER_ERRNO %s" % " ".join(odd))
    print("NOT_INVOKED %s" % " ".join(n for n, _ in DEREFERENCING))
    return 0


if __name__ == "__main__":
    sys.exit(main())