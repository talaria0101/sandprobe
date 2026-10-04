#!/bin/sh
# sandprobe section: interfaces, routes, resolver, direct egress, proxies.
#
# Accuracy rule for this section: a name that does not resolve, a refused
# connection and a silent drop are three different answers and are reported
# as three different verdicts. "No DNS" never collapses into "no network".
# SPDX-License-Identifier: 0BSD

# Probe targets for egress. Hosts are constants because they are public
# well-known names whose resolution behaviour is the thing under test; the
# ports under test come from the environment so an operator can widen the
# matrix without editing the script.
SP_NET_HOSTS="${SANDPROBE_NET_HOSTS:-example.com github.com api.github.com registry.npmjs.org pypi.org crates.io 1.1.1.1}"
SP_NET_PORTS="${SANDPROBE_NET_PORTS:-53 80 443 22 8443}"

# Endpoints discovered from proxy configuration in the environment. Derived,
# never hardcoded, so the section works unchanged on a host with no proxy.
sp_discover_proxies() {
    SP_PROXY_ENDPOINTS=""
    for v in "${http_proxy:-}" "${https_proxy:-}" "${HTTP_PROXY:-}" "${HTTPS_PROXY:-}" \
             "${all_proxy:-}" "${ALL_PROXY:-}"; do
        [ -n "$v" ] || continue
        # Strip any scheme, then keep host:port.
        u=${v#*://}
        u=${u%%/*}
        u=${u##*@}
        printf '%s\n' "$u"
    done | grep -v '^$' | LC_ALL=C sort -u > "$SP_WORK/proxyeps"
    SP_PROXY_ENDPOINTS=$(cat "$SP_WORK/proxyeps" 2>/dev/null)
    # NO_PROXY names are recorded too: they are destinations deliberately
    # excluded from the proxy, so reaching them directly is meaningful.
    SP_NOPROXY_LIST="${no_proxy:-${NO_PROXY:-}}"
    return 0
}

sp_section_net() {
    SP_CUR="net"

    printf '\n## NETWORK INTERFACES\n\n'
    if sp_need ip; then
        sp_raw "# ip -o addr"
        ip -o addr 2>&1 | sp_scrub
        printf '\n'
        sp_raw "# ip route"
        ip route 2>&1 | sp_scrub
        printf '\n'
        sp_raw "# ip -brief link"
        ip -brief link 2>&1 | sp_scrub
    else
        sp_rec "$SP_CUR" "ip_tool" "UNKNOWN" "iproute2 absent; falling back to /proc/net"
        if [ -r /proc/net/dev ]; then
            sp_raw "# /proc/net/dev"
            cat /proc/net/dev 2>/dev/null | sp_scrub
        else
            sp_rec "$SP_CUR" "interfaces" "UNKNOWN" "neither ip(8) nor /proc/net/dev readable"
        fi
        if [ -r /proc/net/route ]; then
            sp_raw "# /proc/net/route (hex)"
            cat /proc/net/route 2>/dev/null | sp_scrub
        fi
    fi

    printf '\n## LISTENING SOCKETS\n\n'
    if sp_need ss; then
        sp_raw "# ss -tulnp"
        ss -tulnp 2>&1 | sp_scrub
        printf '\n'
        sp_raw "# ss -s (summary)"
        ss -s 2>&1 | sp_scrub
    elif sp_need netstat; then
        netstat -tulnp 2>&1 | sp_scrub
    else
        sp_rec "$SP_CUR" "listening_sockets" "UNKNOWN" "neither ss(8) nor netstat(8) present; /proc/net/tcp below is the fallback"
    fi
    for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 /proc/net/unix; do
        if [ -r "$f" ]; then
            sp_kv "proc_net_$(basename "$f")_lines" "$(wc -l < "$f" 2>/dev/null | tr -d ' ')"
        else
            sp_rec "$SP_CUR" "read:$f" "UNKNOWN" "not readable"
        fi
    done

    printf '\n## HOST RESOLUTION\n\n'
    sp_kv "resolv_conf_nameservers" "$(grep -h '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    sp_kv "resolv_conf_options" "$(grep -h '^options' /etc/resolv.conf 2>/dev/null | tr '\n' ' ')"
    sp_kv "resolv_conf_search" "$(grep -h '^search\|^domain' /etc/resolv.conf 2>/dev/null | tr '\n' ' ')"
    sp_kv "resolv_conf_present" "$([ -r /etc/resolv.conf ] && echo yes || echo no)"

    sp_discover_proxies
    sp_kv "proxy_endpoints_discovered" "$(printf '%s\n' "$SP_PROXY_ENDPOINTS" | tr '\n' ' ')"
    sp_kv "no_proxy_list" "$SP_NOPROXY_LIST"

    if sp_need python3; then
        # The matrix runs many independent connects, each bounded internally by
        # SANDPROBE_BUDGET. Its own outer deadline is therefore a function of
        # how many connects there are, not of the single-probe budget: reusing
        # SP_BUDGET here killed the whole matrix and discarded every record it
        # had produced, which is how a whole section can vanish from a report.
        _np_hosts=$(printf '%s' "$SP_NET_HOSTS" | wc -w | tr -d ' ')
        _np_ports=$(printf '%s' "$SP_NET_PORTS" | wc -w | tr -d ' ')
        # Worst case if every connect uses its full budget, plus a fixed
        # allowance for DNS, TLS and setup. Threads overlap, so this is a
        # ceiling rather than a prediction.
        _np_deadline=$(( SP_BUDGET * 4 + 30 ))
        SP_OUT=$(timeout "$_np_deadline" python3 "$SP_LIB_DIR/netprobe.py" 2>&1)
        SP_RC=$?
        if [ "$SP_RC" -eq 124 ]; then
            sp_rec "$SP_CUR" "network_matrix" "TIMEOUT" \
                "the probe exceeded its ${_np_deadline}s deadline (${_np_hosts} hosts x ${_np_ports} ports x ${SP_BUDGET}s); records below are partial"
        elif [ "$SP_RC" -ne 0 ]; then
            sp_rec "$SP_CUR" "network_matrix" "UNKNOWN" \
                "the probe exited $SP_RC; records below may be incomplete"
        else
            sp_rec "$SP_CUR" "network_matrix" "ALLOW" \
                "probe completed within its ${_np_deadline}s deadline"
        fi
        printf '%s\n' "$SP_OUT"
    else
        sp_rec "$SP_CUR" "network_matrix" "UNKNOWN" "python3 absent; the direct/connect/TLS matrix was not run. Use curl-based manual probing."
        # Still exercise what is available so the section is not empty.
        for u in http://example.com/ https://example.com/; do
            if sp_need curl; then
                _code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$SP_BUDGET" "$u" 2>/dev/null)
                if [ "$_code" = "200" ]; then
                    sp_rec "$SP_CUR" "curl:GET $u" "ALLOW" "HTTP $_code"
                elif [ "$_code" = "000" ]; then
                    sp_rec "$SP_CUR" "curl:GET $u" "UNKNOWN" "no HTTP status returned (timeout, DNS failure, or refusal; curl cannot tell us which)"
                else
                    sp_rec "$SP_CUR" "curl:GET $u" "ALLOW" "HTTP $_code"
                fi
            fi
        done
    fi
    return 0
}