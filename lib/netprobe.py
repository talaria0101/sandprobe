#!/usr/bin/env python3
"""sandprobe network matrix.

Emits tab separated records: id <TAB> VERDICT <TAB> detail

The whole point of this module is to keep three distinct failures distinct:
  - a name that does not resolve            -> UNRESOLVED
  - a connection the peer refused           -> REFUSED
  - a connection that produced no answer   -> DROPPED (filter or blackhole)

Collapsing any of those into "network denied" is a false claim, so this
module never does. Every record carries the observed errno or status line.
"""
import os
import socket
import ssl
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor

ALLOW, DENY, ABSENT, UNKNOWN, TIMEOUT = (
    "ALLOW", "DENY", "ABSENT", "UNKNOWN", "TIMEOUT")
UNRESOLVED, REFUSED, DROPPED = "UNRESOLVED", "REFUSED", "DROPPED"

BUDGET = float(os.environ.get("SANDPROBE_BUDGET", "10"))

# Concurrency for independent probes. A high value is safe because every task
# opens its own socket and closes it; there is no shared state to race on.
WORKERS = int(os.environ.get("SANDPROBE_NET_WORKERS", "24"))


_QUEUE = []
_LOCK = threading.Lock()


def rec(sec, ident, verdict, detail):
    """Append a record. Buffered so concurrent workers cannot interleave lines."""
    detail = " ".join(str(detail).split())
    with _LOCK:
        _QUEUE.append("%s\t%s\t%s\t%s" % (sec, ident, verdict, detail))


def flush():
    """Emit buffered records in order, then return the ordered task list."""
    for line in _QUEUE:
        print(line)
    _QUEUE[:] = []


def hosts():
    return [h for h in os.environ.get(
        "SANDPROBE_NET_HOSTS",
        "example.com github.com api.github.com registry.npmjs.org pypi.org 1.1.1.1"
    ).split() if h]


def ports():
    out = []
    for p in os.environ.get("SANDPROBE_NET_PORTS", "53 80 443 22 8443").split():
        try:
            out.append(int(p))
        except ValueError:
            pass
    return out


def proxy_endpoints():
    seen = []
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                 "all_proxy", "ALL_PROXY"):
        v = os.environ.get(name)
        if not v:
            continue
        u = v.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
        if u and u not in seen:
            seen.append(u)
    return seen


def classify(e):
    """Map a socket exception to a verdict. Never collapses distinct failures."""
    # The TLS branch comes FIRST, ahead of every errno test, because
    # ssl.SSLError carries errno 1 and would otherwise be caught by the
    # PermissionError and EPERM branches below and reported as DENY. That is
    # the worst possible misreading for this branch: a certificate that does
    # not verify, or a TLS session that ends unexpectedly, means the peer
    # ANSWERED. Reporting it as a denial tells the reader the sandbox blocked
    # the connection, when in fact something is on the far end and the
    # evidence is exactly what an intercepting proxy looks like.
    if isinstance(e, ssl.SSLCertVerificationError):
        return UNKNOWN, ("the peer presented a certificate that did not "
                         "verify against the system trust store, so the "
                         "connection was established and the certificate is "
                         "wrong: this is interception evidence, not a refusal: "
                         "%s" % e)
    if isinstance(e, ssl.SSLError):
        return UNKNOWN, "TLS error after the connection was established: %s" % e
    if isinstance(e, socket.gaierror):
        return UNRESOLVED, "DNS: %s" % e
    if isinstance(e, ConnectionRefusedError):
        return REFUSED, "RST from peer: %s" % e
    if isinstance(e, ConnectionResetError):
        return REFUSED, "connection reset by peer: %s" % e
    if isinstance(e, PermissionError):
        return DENY, "errno %s: %s" % (e.errno, e)
    if isinstance(e, socket.timeout):
        return DROPPED, "no answer within %.1fs (filter or blackhole)" % BUDGET
    if isinstance(e, OSError) and e.errno in (101, 113, 10051):
        return DROPPED, "errno %s %s: no route or unreachable" % (e.errno, e)
    if isinstance(e, OSError) and e.errno in (1, 13):
        return DENY, "errno %s: %s" % (e.errno, e)
    if isinstance(e, OSError) and e.errno in (111,):
        return REFUSED, "errno 111: %s" % e
    return UNKNOWN, "%s: %s" % (type(e).__name__, e)


def tcp_task(host, port, label):
    """One direct TCP connect attempt. Returns a record tuple."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=BUDGET)
        peer = sock.getpeername()
        local = sock.getsockname()
        return ("ALLOW", "connected to %s:%d from local %s" % (peer[0], peer[1], local[0]))
    except Exception as exc:
        verdict, detail = classify(exc)
        return (verdict, detail)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def udp_task(ip):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(BUDGET)
        query = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x03www\x07example\x03com\x00\x00\x01\x00\x01")
        sock.sendto(query, (ip, 53))
        data, _ = sock.recvfrom(512)
        return ("ALLOW", "DNS reply of %d bytes" % len(data))
    except Exception as exc:
        return classify(exc)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def dns_task(host):
    start = time.time()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        return ("ALLOW", "%d address(es): %s (%.3fs)"
                % (len(addrs), " ".join(addrs), time.time() - start))
    except Exception as exc:
        return classify(exc)


def connect_task(endpoint, target, tport):
    """HTTP CONNECT through a proxy endpoint."""
    sock = None
    try:
        sock = socket.create_connection((endpoint[0], endpoint[1]), timeout=BUDGET)
        sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                      % (target, tport, target, tport)).encode())
        resp = sock.recv(512)
        line = resp.split(b"\r\n")[0].decode("latin-1", "replace")
        if " 200" in line:
            return ("ALLOW", line)
        return ("DENY", "proxy refused: %s" % line)
    except Exception as exc:
        return classify(exc)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def tls_task(host, endpoint):
    """TLS through a proxy, recording the certificate that answered."""
    sock = None
    wrapped = None
    try:
        if endpoint:
            sock = socket.create_connection((endpoint[0], endpoint[1]), timeout=BUDGET)
            sock.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s\r\n\r\n"
                          % (host, host)).encode())
            hdr = sock.recv(512)
            if b" 200" not in hdr.split(b"\r\n")[0]:
                return ("DENY", "proxy refused CONNECT: %s"
                        % hdr.split(b"\r\n")[0].decode("latin-1", "replace"))
        ctx = ssl.create_default_context()
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        cert = wrapped.getpeercert() or {}
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        detail = ("CN=%s issuer=%s notAfter=%s protocol=%s"
                  % (subject.get("commonName"), issuer.get("organizationName"),
                     cert.get("notAfter"), wrapped.version()))
        try:
            wrapped.sendall(("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                             % host).encode())
            line = wrapped.recv(400).decode("latin-1", "replace").split("\r\n")[0]
            detail += " | HTTP over TLS: %s" % line
        except Exception as exc:
            detail += " | HEAD failed: %s" % exc
        return ("ALLOW", detail)
    except Exception as exc:
        return classify(exc)
    finally:
        for h in (wrapped, sock):
            if h:
                try:
                    h.close()
                except OSError:
                    pass


def main():
    endpoints = []
    for ep in proxy_endpoints():
        if ":" in ep:
            h, _, pt = ep.rpartition(":")
            try:
                endpoints.append((h, int(pt)))
            except ValueError:
                pass
        else:
            endpoints.append((ep, 8080))
    primary = endpoints[0] if endpoints else None

    # Build the whole work list first, then run the independent connect-shaped
    # tasks concurrently. Records are buffered by rec() and printed in
    # submission order, so the report stays byte-stable across runs.
    pool = ThreadPoolExecutor(max_workers=WORKERS)
    futures = []

    for h in hosts():
        futures.append(("dns", "resolve:%s" % h, pool.submit(dns_task, h)))

    for h in hosts():
        for p in ports():
            futures.append(("tcp-direct", "%s:%d" % (h, p),
                            pool.submit(tcp_task, h, p, None)))

    for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        for p in (53, 443):
            futures.append(("tcp-direct-ip", "%s:%d" % (ip, p),
                            pool.submit(tcp_task, ip, p, None)))

    for ip in ("1.1.1.1", "8.8.8.8"):
        futures.append(("udp-direct", "%s:53" % ip, pool.submit(udp_task, ip)))

    for hp in ("127.0.0.1:1", "127.0.0.1:53"):
        host, _, port = hp.rpartition(":")
        futures.append(("loopback", hp,
                        pool.submit(tcp_task, host, int(port), None)))

    for ip in ("169.254.169.254", "169.254.169.253", "100.100.100.200"):
        futures.append(("metadata", "%s:80" % ip, pool.submit(tcp_task, ip, 80, None)))

    for ep in endpoints:
        for target, tport in [("example.com", 443), ("example.com", 80),
                              ("example.com", 8443), ("example.com", 22),
                              ("example.com", 25), ("127.0.0.1", 22),
                              ("169.254.169.254", 80), ("10.255.255.1", 80)]:
            futures.append(("proxy", "%s:%d CONNECT %s:%d"
                            % (ep[0], ep[1], target, tport),
                            pool.submit(connect_task, ep, target, tport)))

    for h in hosts():
        if h[0].isdigit():
            continue
        futures.append(("tls", h, pool.submit(tls_task, h, primary)))

    # Wait for every task, then emit in submission order.
    results = []
    for sec, ident, fut in futures:
        try:
            verdict, detail = fut.result()
        except Exception as exc:
            verdict, detail = "UNKNOWN", "probe raised %s: %s" % (type(exc).__name__, exc)
        rec(sec, ident, verdict, detail)
    pool.shutdown(wait=True)
    flush()

    if not endpoints:
        rec("proxy", "discovery", "UNKNOWN",
            "no proxy endpoint in the environment; the proxy matrix could not run")
    else:
        rec("proxy", "discovery", "ALLOW",
            "proxy endpoints found: %s" % " ".join("%s:%d" % e for e in endpoints))

    # Raw sockets. Opening one needs CAP_NET_RAW, so its absence is a direct
    # statement about the sandbox.
    for name, fam, typ, proto in (
            ("icmp", socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
            ("raw-tcp", socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)):
        sock = None
        try:
            sock = socket.socket(fam, typ, proto)
            rec("raw-socket", name, "ALLOW", "raw socket opened (needs CAP_NET_RAW)")
        except Exception as exc:
            verdict, detail = classify(exc)
            rec("raw-socket", name, verdict, detail)
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
    sock = None
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        rec("raw-socket", "af_packet", "ALLOW",
            "AF_PACKET opened; other hosts' frames would be visible")
    except AttributeError:
        rec("raw-socket", "af_packet", "ABSENT", "AF_PACKET not defined in this build")
    except Exception as exc:
        verdict, detail = classify(exc)
        rec("raw-socket", "af_packet", verdict, detail)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    for fn in ("/proc/net/route", "/proc/net/ipv6_route", "/proc/net/tcp"):
        try:
            with open(fn) as fh:
                rec("routes", fn, "ALLOW", "%d lines" % sum(1 for _ in fh))
        except Exception as exc:
            rec("routes", fn, "UNKNOWN", str(exc))

    flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())