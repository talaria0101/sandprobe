#!/bin/sh
# sandprobe: locating a directory where a created file can also be executed.
#
# A sandbox may permit writes in a directory and still refuse to execute from
# it. Two real examples from the machine this was developed on: /tmp accepted a
# written file but execve returned EACCES, while the project directory accepted
# both. A probe that compiles into a mktemp directory and then claims the
# binary ran is therefore a false positive, so the destination is discovered
# rather than assumed.
# SPDX-License-Identifier: 0BSD

# Candidate directories, most preferred first. The session work directory
# comes first because it is private and cleaned up by the exit trap.
sp_exec_candidates() {
    printf '%s\n' \
        "$SP_WORK" \
        "${SANDPROBE_EXEC_DIR:-}" \
        "$(pwd 2>/dev/null)" \
        "/workspace" \
        "${HOME:-}" \
        "/var/tmp" \
        "/dev/shm" \
        "${TMPDIR:-/tmp}"
}

# Find the first candidate that accepts a written, executable file.
# Sets SP_EXEC_DIR. Returns 1 if none does, so callers can report UNKNOWN
# rather than pretending a run happened.
SP_EXEC_DIR=""
SP_EXEC_DIR_EVIDENCE=""
sp_find_exec_dir() {
    SP_EXEC_DIR=""
    SP_EXEC_DIR_EVIDENCE=""
    for d in $(sp_exec_candidates); do
        [ -n "$d" ] || continue
        [ -d "$d" ] || continue
        [ -w "$d" ] || continue
        _probe="$d/.sandprobe-exectest.$$"
        # Create and mark executable in a child shell: a redirection failure
        # is fatal to this shell if attempted here.
        if sh -c 'printf "#!/bin/sh\nexit 0\n" > "$1" && chmod +x "$1"' sh "$_probe" 2>/dev/null; then
            _out=$(timeout 10 "$_probe" 2>&1)
            _rc=$?
            rm -f "$_probe" 2>/dev/null
            if [ "$_rc" -eq 0 ]; then
                SP_EXEC_DIR="$d"
                SP_EXEC_DIR_EVIDENCE="wrote, chmod +x and executed a script in $d"
                return 0
            fi
            # Keep the first refusal as evidence; it is the interesting answer.
            if [ -z "$SP_EXEC_DIR_EVIDENCE" ]; then
                SP_EXEC_DIR_EVIDENCE="$d accepts writes but refused to execute (rc=$_rc)"
            fi
        else
            if [ -z "$SP_EXEC_DIR_EVIDENCE" ]; then
                SP_EXEC_DIR_EVIDENCE="$d refused to create the probe file"
            fi
        fi
    done
    return 1
}

# Compile-and-run probe. Reports compile status and run status separately,
# because a compile that succeeds while the run is refused is the interesting
# case and must never be reported as a successful run.
# Usage: sp_compile_run "<label>" <compiler> [compiler args...]
sp_compile_run() {
    __cr_label="$1"; shift
    if [ -z "$SP_EXEC_DIR" ]; then
        sp_rec "$SP_CUR" "$__cr_label" "UNKNOWN" \
            "no directory found where a written file can be executed. Evidence: $SP_EXEC_DIR_EVIDENCE"
        return 0
    fi
    __cr_dir="$SP_EXEC_DIR/sandprobe-build.$$"
    mkdir -p "$__cr_dir" 2>/dev/null
    if [ ! -d "$__cr_dir" ]; then
        sp_rec "$SP_CUR" "$__cr_label" "UNKNOWN" "could not create a build directory under $SP_EXEC_DIR"
        return 0
    fi
    "$@" -o "$__cr_dir/prog" 2>"$__cr_dir/err" || true
    if [ ! -f "$__cr_dir/prog" ]; then
        __cr_msg=$(head -2 "$__cr_dir/err" 2>/dev/null | tr '\n' ' ')
        sp_rec "$SP_CUR" "$__cr_label" "$(sp_verdict_from_err "$__cr_msg")" \
            "compile failed: ${__cr_msg:-no diagnostic}"
        return 0
    fi
    __cr_out=$(timeout 20 "$__cr_dir/prog" 2>&1)
    __cr_rc=$?
    if [ "$__cr_rc" -eq 0 ]; then
        sp_rec "$SP_CUR" "$__cr_label" "ALLOW" \
            "compiled in $SP_EXEC_DIR and the binary ran (exit 0${__cr_out:+: $__cr_out})"
    elif [ "$__cr_rc" -eq 126 ] || [ "$__cr_rc" -eq 127 ]; then
        sp_rec "$SP_CUR" "$__cr_label" "DENY" \
            "compiled successfully but the kernel refused to execute the binary (exit $__cr_rc)"
    else
        sp_rec "$SP_CUR" "$__cr_label" "ALLOW" \
            "compiled and executed; program exited $__cr_rc${__cr_out:+: $__cr_out}"
    fi
    rm -rf "$__cr_dir" 2>/dev/null
    return 0
}