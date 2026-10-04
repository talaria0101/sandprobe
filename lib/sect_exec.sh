#!/bin/sh
# sandprobe section: installed tooling, build capability, execution policy.
# SPDX-License-Identifier: 0BSD

# Tool families probed for presence and runnability. Names are constants
# because the question "is this build toolchain available" is the question.
# Resolution is dynamic: PATH is searched, then common prefixes.
SP_TOOL_NAMES="sh bash dash zsh env cat sed awk grep tr sort uniq cut head tail \
wc find stat df mount umount ls du id uname date sleep timeout dd printf test \
mktemp rm mkdir rmdir chmod chown ln cp mv touch install realpath readlink \
flock xargs seq expr od hexdump base64 nproc getconf tee diff patch cmp split \
tar gzip bzip2 xz zip unzip file strings ldd nm objdump readelf ar strip \
pkg-config make cmake meson ninja autoconf automake libtool gperf bison flex \
cc gcc g++ clang clang++ ld as ar rustc cargo rustup go ghc stack cabal \
python python2 python3 pip pip3 node npm yarn pnpm deno bun ruby gem perl \
java javac mvn gradle dotnet mono gh glab jq rg fd bat ag exa nc ncat socat \
curl wget openssl ssh ssh-keygen gpg gpg2 rsync git jj docker podman \
kubectl strace ltrace gdb lldb valgrind perf bpftrace nix nix-env guix \
busybox toybox setarch unshare nsenter chroot capsh getent hosts dig nslookup \
ip ss netstat ifconfig route ping traceroute dig nmap telnet ftp tftp"

SP_TOOL_PREFIXES="/usr/bin /bin /usr/local/bin /sbin /usr/sbin /opt/bin /usr/local/sbin"

sp_section_exec() {
    SP_CUR="exec"

    printf '\n## TOOL RESOLUTION\n\n'
    sp_raw "# Each name is looked up on PATH, then in the common prefixes."
    sp_raw "# MISSING means not installed, which is not a denial."
    _found=0; _missing=0
    printf '%s\n' "$SP_TOOL_NAMES" | tr ' ' '\n' | sed '/^$/d' | LC_ALL=C sort -u \
    | while IFS= read -r t; do
        _p=$(command -v "$t" 2>/dev/null)
        if [ -n "$_p" ]; then
            printf 'present\t%-18s %s\n' "$t" "$_p"
        else
            _p=""
            for d in $SP_TOOL_PREFIXES; do
                if [ -x "$d/$t" ]; then _p="$d/$t"; break; fi
            done
            if [ -n "$_p" ]; then
                printf 'present-offpath\t%-18s %s\n' "$t" "$_p"
            else
                printf 'missing\t%s\n' "$t"
            fi
        fi
    done > "$SP_WORK/toolres"
    _found=$(grep -c '^present' "$SP_WORK/toolres" 2>/dev/null || echo 0)
    _missing=$(grep -c '^missing' "$SP_WORK/toolres" 2>/dev/null || echo 0)
    sp_kv "tools_present" "$_found"
    sp_kv "tools_missing" "$_missing"
    sp_raw "# present:"
    grep '^present' "$SP_WORK/toolres" 2>/dev/null | cut -f2 | tr '\n' ' '
    printf '\n'
    sp_raw "# missing:"
    grep '^missing' "$SP_WORK/toolres" 2>/dev/null | cut -f2 | tr '\n' ' '
    printf '\n'
    sp_raw "# full resolution table:"
    cat "$SP_WORK/toolres" 2>/dev/null | sp_scrub

    printf '\n## VERSIONS OF COMPILERS AND RUNTIMES THAT ARE PRESENT\n\n'
    for t in cc gcc g++ clang python3 node ruby perl go rustc cargo java git gh jq; do
        _p=$(command -v "$t" 2>/dev/null) || continue
        _v=$(timeout 5 "$_p" --version 2>&1 | head -1)
        if [ -z "$_v" ]; then
            _v=$(timeout 5 "$_p" -version 2>&1 | head -1)
        fi
        if [ -z "$_v" ]; then
            _v=$(timeout 5 "$_p" version 2>&1 | head -1)
        fi
        sp_kv "version:$t" "${_v:-(no version output)}"
    done

    printf '\n## COMPILATION PROBE\n\n'
    sp_raw "# The question is whether a real compile and a real execution work"
    sp_raw "# here, so both are attempted. A compile that succeeds while the run is"
    sp_raw "# refused is reported as its own outcome and never as a successful run."
    if sp_find_exec_dir; then
        sp_kv "exec_capable_dir" "$SP_EXEC_DIR"
        sp_kv "exec_capable_evidence" "$SP_EXEC_DIR_EVIDENCE"
    else
        sp_rec "$SP_CUR" "exec_capable_dir" "DENY" \
            "no probed directory allows a written file to be executed: $SP_EXEC_DIR_EVIDENCE"
        sp_kv "exec_capable_dir" "NONE FOUND"
    fi

    if sp_have cc || sp_have gcc; then
        _cc=$(command -v cc 2>/dev/null || command -v gcc 2>/dev/null)
        _cv=$(timeout 10 "$_cc" --version 2>&1 | head -1)
        if [ -n "$SP_EXEC_DIR" ]; then
            _cd="$SP_EXEC_DIR/sandprobe-c.$$"
            mkdir -p "$_cd" 2>/dev/null
            sh -c 'printf "int main(void){return 0;}\n" > "$1"' sh "$_cd/t.c" 2>/dev/null
            if timeout 120 "$_cc" "$_cd/t.c" -o "$_cd/t" 2>"$_cd/err"; then
                _co=$(timeout 20 "$_cd/t" 2>&1); _cr=$?
                if [ "$_cr" -eq 0 ]; then
                    sp_rec "$SP_CUR" "c_compile_and_run" "ALLOW" "$_cv compiled and the binary ran"
                elif [ "$_cr" -eq 126 ] || [ "$_cr" -eq 127 ]; then
                    sp_rec "$SP_CUR" "c_compile_and_run" "DENY" "$_cv compiled but the kernel refused to execute the binary (exit $_cr)"
                else
                    sp_rec "$SP_CUR" "c_compile_and_run" "ALLOW" "$_cv compiled; the binary ran and exited $_cr"
                fi
            else
                _ce=$(head -2 "$_cd/err" 2>/dev/null | tr '\n' ' ')
                sp_rec "$SP_CUR" "c_compile_and_run" "$(sp_verdict_from_err "$_ce")" "$_cv failed to compile: $_ce"
            fi
            rm -rf "$_cd" 2>/dev/null
        else
            sp_rec "$SP_CUR" "c_compile_and_run" "UNKNOWN" "$_cv is present but no directory allows execution"
        fi
    else
        sp_rec "$SP_CUR" "c_compile_and_run" "UNKNOWN" "no C compiler found on PATH or in common prefixes"
    fi

    if sp_have rustc; then
        _rc2=$(command -v rustc)
        _rv=$(timeout 10 "$_rc2" --version 2>&1 | head -1)
        if [ -n "$SP_EXEC_DIR" ]; then
            _rd="$SP_EXEC_DIR/sandprobe-rust.$$"
            mkdir -p "$_rd" 2>/dev/null
            sh -c 'printf "fn main(){println!(\"ok\");}\n" > "$1"' sh "$_rd/t.rs" 2>/dev/null
            if timeout 180 "$_rc2" "$_rd/t.rs" -o "$_rd/prog" 2>"$_rd/err"; then
                _ro=$(timeout 20 "$_rd/prog" 2>&1); _rrc=$?
                if [ "$_rrc" -eq 0 ]; then
                    sp_rec "$SP_CUR" "rust_compile_and_run" "ALLOW" "$_rv compiled and ran: $_ro"
                elif [ "$_rrc" -eq 126 ] || [ "$_rrc" -eq 127 ]; then
                    sp_rec "$SP_CUR" "rust_compile_and_run" "DENY" "$_rv compiled but the kernel refused to execute the binary (exit $_rrc)"
                else
                    sp_rec "$SP_CUR" "rust_compile_and_run" "ALLOW" "$_rv compiled; the binary ran and exited $_rrc"
                fi
            else
                _re=$(head -2 "$_rd/err" 2>/dev/null | tr '\n' ' ')
                sp_rec "$SP_CUR" "rust_compile_and_run" "$(sp_verdict_from_err "$_re")" "$_rv failed to compile: $_re"
            fi
            rm -rf "$_rd" 2>/dev/null
        else
            sp_rec "$SP_CUR" "rust_compile_and_run" "UNKNOWN" "$_rv is present but no directory allows execution"
        fi
    else
        sp_rec "$SP_CUR" "rust_compile_and_run" "UNKNOWN" "rustc not found"
    fi

    if sp_have go; then
        _gc=$(command -v go)
        _gv=$(timeout 10 "$_gc" version 2>&1 | head -1)
        if [ -n "$SP_EXEC_DIR" ]; then
            _gd="$SP_EXEC_DIR/sandprobe-go.$$"
            mkdir -p "$_gd" 2>/dev/null
            sh -c 'printf "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"ok\")}\n" > "$1"' sh "$_gd/main.go" 2>/dev/null
            if (cd "$_gd" && GOFLAGS= GO111MODULE=off GO111MODULE=off timeout 180 "$_gc" build -o prog main.go) 2>"$_gd/err"; then
                _go=$(timeout 20 "$_gd/prog" 2>&1); _grc=$?
                if [ "$_grc" -eq 0 ]; then
                    sp_rec "$SP_CUR" "go_compile_and_run" "ALLOW" "$_gv compiled and ran: $_go"
                elif [ "$_grc" -eq 126 ] || [ "$_grc" -eq 127 ]; then
                    sp_rec "$SP_CUR" "go_compile_and_run" "DENY" "$_gv compiled but the kernel refused to execute the binary (exit $_grc)"
                else
                    sp_rec "$SP_CUR" "go_compile_and_run" "ALLOW" "$_gv compiled; the binary ran and exited $_grc"
                fi
            else
                _ge=$(head -2 "$_gd/err" 2>/dev/null | tr '\n' ' ')
                sp_rec "$SP_CUR" "go_compile_and_run" "$(sp_verdict_from_err "$_ge")" "$_gv failed to build: $_ge"
            fi
            rm -rf "$_gd" 2>/dev/null
        else
            sp_rec "$SP_CUR" "go_compile_and_run" "UNKNOWN" "$_gv is present but no directory allows execution"
        fi
    else
        sp_rec "$SP_CUR" "go_compile_and_run" "UNKNOWN" "go not found"
    fi

    if sp_have python3; then
        _pv=$(timeout 10 python3 --version 2>&1 | head -1)
        if timeout 20 python3 -c 'print(1+1)' >/dev/null 2>&1; then
            sp_rec "$SP_CUR" "python_execute" "ALLOW" "$_pv executes"
        else
            sp_rec "$SP_CUR" "python_execute" "DENY" "python3 present but could not execute a trivial program"
        fi
    fi

    printf '\n## INTERPRETER MODULE VISIBILITY\n\n'
    sp_raw "# Recorded because a sandbox that hides interpreters usually does so by"
    sp_raw "# withholding binaries, which the table above already shows."
    _pyp=$(timeout 10 python3 -c 'import sys; print(sys.prefix)' 2>/dev/null || echo UNKNOWN)
    _pypath=$(timeout 10 python3 -c 'import sys; print(sys.path)' 2>/dev/null | tr '\n' ' ' || echo UNKNOWN)
    _pystd=$(timeout 20 python3 -c 'import os,sys,json,ssl,socket,ctypes,subprocess; print("yes")' 2>/dev/null || echo no)
    sp_kv "python3_prefix" "$_pyp"
    sp_kv "python3_path" "$_pypath"
    sp_kv "python3_stdlib_importable" "$_pystd"
    sp_kv "ld_library_path" "${LD_LIBRARY_PATH:-UNSET}"
    sp_kv "ld_preload" "${LD_PRELOAD:-UNSET}"
    sp_kv "ld_so_preload_from_etc" "$(cat /etc/ld.so.preload 2>/dev/null || echo 'no /etc/ld.so.preload')"

    printf '\n## EXECUTE-BIT AND SETUID SURFACE\n\n'
    sp_kv "nosuid_mounts" "$(grep 'nosuid' /proc/$$/mounts 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    sp_kv "noexec_mounts" "$(grep 'noexec' /proc/$$/mounts 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    sp_kv "nodev_mounts" "$(grep 'nodev' /proc/$$/mounts 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    sp_kv "no_new_privs" "$(awk '/^NoNewPrivs/{print $2}' /proc/$$/status 2>/dev/null)"
    sp_kv "setuid_binaries_count" "$(timeout 30 find /usr/bin /usr/sbin /bin /sbin -xdev -perm -4000 2>/dev/null | wc -l | tr -d ' ')"
    sp_kv "setgid_binaries_count" "$(timeout 30 find /usr/bin /usr/sbin /bin /sbin -xdev -perm -2000 2>/dev/null | wc -l | tr -d ' ')"
    sp_raw "# setuid and setgid binaries, by name:"
    timeout 30 find /usr/bin /usr/sbin /bin /sbin -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null | LC_ALL=C sort | sp_scrub
    # A setuid binary with NoNewPrivs=1 cannot gain privilege. Confirm the
    # kernel agrees rather than asserting it.
    sp_kv "no_new_privs_means_setuid_inert" \
        "$([ "$(awk '/^NoNewPrivs/{print $2}' /proc/$$/status 2>/dev/null)" = "1" ] && echo 'yes, per NoNewPrivs=1' || echo 'no, NoNewPrivs is not 1')"

    printf '\n## WRITE+EXECUTE ON THE SAME FILESYSTEM\n\n'
    sp_raw "# The classic escape is writing an executable where execution is allowed."
    for d in /tmp "${TMPDIR:-}" "${HOME:-}" /workspace /dev/shm; do
        [ -n "$d" ] || continue
        _wd="$d/.sandprobe-exec-probe.$$"
        _err=$(sh -c "printf '#!/bin/sh\necho ran\n' > '$_wd' && chmod +x '$_wd' && '$_wd'" 2>&1)
        case "$_err" in
            ran)  sp_rec "$SP_CUR" "write_exec:$d" "ALLOW" "wrote, chmod +x, and executed" ;;
            *)    sp_rec "$SP_CUR" "write_exec:$d" "$(sp_verdict_from_err "$_err")" "$(printf '%s' "$_err" | tr '\n' ' ')" ;;
        esac
        rm -f "$_wd" 2>/dev/null
    done

    printf '\n## INTERPRETERS PRESENT BUT NOT ON PATH\n\n'
    sp_kv "rustup_toolchains" "$(ls -1 "${RUSTUP_HOME:-/nonexistent}/toolchains" 2>/dev/null | tr '\n' ' ')"
    sp_kv "cargo_bin_dir" "$(command -v cargo 2>/dev/null || echo 'cargo not on PATH')"
    sp_kv "cargo_home" "${CARGO_HOME:-UNSET}"
    if [ -n "${CARGO_HOME:-}" ] && [ ! -d "$CARGO_HOME" ]; then
        sp_rec "$SP_CUR" "cargo_home_dir" "ABSENT" "CARGO_HOME points at $CARGO_HOME, which does not exist; cargo cannot cache here"
    elif [ -n "${CARGO_HOME:-}" ]; then
        if [ -w "$CARGO_HOME" ]; then
            sp_rec "$SP_CUR" "cargo_home_dir" "ALLOW" "CARGO_HOME $CARGO_HOME exists and is writable"
        else
            sp_rec "$SP_CUR" "cargo_home_dir" "DENY" "CARGO_HOME $CARGO_HOME exists but is not writable; cargo cannot cache here"
        fi
    else
        sp_rec "$SP_CUR" "cargo_home_dir" "UNKNOWN" "CARGO_HOME unset"
    fi
}