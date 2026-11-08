"""Run inside a disposable container, never in the deployed proxy.

Exercises the deployed image's firewall without real WireGuard credentials.
Requires NET_ADMIN, SETUID, SETGID and the image's normal networking tools.
"""

import os
import pwd
import socket
import ssl
import sys

sys.path.insert(0, "/opt/proxy")
from config import Settings, WG_MARK
from service import install_firewall, install_rules, run


def https_succeeds(uid, gid):
    result = run(["curl", "--noproxy", "*", "--ipv4", "--fail", "--silent",
                  "--connect-timeout", "2", "--max-time", "3", "--output", "/dev/null",
                  "https://1.1.1.1/cdn-cgi/trace"],
                 uid=uid, gid=gid, timeout=5, check=False)
    return result.returncode == 0


def dns_query(server, transport, uid, gid):
    return run(["dig", f"@{server}", "example.com", "A", transport,
                "+time=1", "+tries=1"], uid=uid, gid=gid, timeout=4, check=False)


def check_blocked(account, phase, reachable_dns):
    for uid, gid in ((account.pw_uid, account.pw_gid), (0, 0)):
        assert not https_succeeds(uid, gid), f"HTTPS escaped during {phase} (uid={uid})"
        for server, transport in reachable_dns:
            result = dns_query(server, transport, uid, gid)
            assert result.returncode != 0, f"DNS escaped during {phase} (uid={uid})"
    print(f"PASS: HTTPS and both DNS transports blocked for Squid and root: {phase}", flush=True)


def main():
    if os.environ.get("DISPOSABLE_FIREWALL_TEST") != "1":
        raise RuntimeError("Refusing to run outside an explicitly marked disposable test container")
    assert not os.path.exists("/run/wireguard/supervisor.pid"), "Never run in the deployed proxy"
    account = pwd.getpwnam("proxy")
    assert https_succeeds(account.pw_uid, account.pw_gid), "Baseline Internet unavailable; test inconclusive"
    # Host networks may restrict individual public resolvers. Only claim that
    # the firewall blocked DNS paths proven usable before installing its rules.
    reachable_dns = []
    for server in ("1.1.1.1", "8.8.8.8"):
        for transport in ("+notcp", "+tcp"):
            result = dns_query(server, transport, account.pw_uid, account.pw_gid)
            if result.returncode == 0 and "status: NOERROR" in result.stdout:
                reachable_dns.append((server, transport))
    assert {transport for _, transport in reachable_dns} == {"+notcp", "+tcp"}, "Baseline UDP/TCP DNS unavailable; test inconclusive"
    print(f"Baseline reachable DNS paths: {reachable_dns}", flush=True)
    # Hold a real established TLS connection open before installing the guard.
    existing = ssl.create_default_context().wrap_socket(
        socket.create_connection(("1.1.1.1", 443), timeout=5), server_hostname="one.one.one.one")
    settings = Settings.from_env({"PROXY_USERNAME": "test", "PROXY_PASSWORD": "disposable-test-password"})
    install_firewall(settings, account.pw_uid)
    install_rules()
    run(["ip", "link", "add", "wg0", "type", "wireguard"])
    run(["ip", "address", "add", "10.254.254.2/32", "dev", "wg0"])
    run(["ip", "link", "set", "wg0", "up"])
    run(["ip", "route", "add", "default", "dev", "wg0", "metric", "100", "table", str(WG_MARK)])
    # No peer or keys: wg0 exists, but has no usable tunnel. This must fail closed.
    check_blocked(account, "WireGuard present without a working peer", reachable_dns)
    run(["ip", "link", "del", "wg0"])
    run(["ip", "route", "del", "unreachable", "default", "metric", "32767", "table", str(WG_MARK)])
    check_blocked(account, "interface deleted and Docker default route available", reachable_dns)
    try:
        existing.settimeout(2)
        existing.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        response = existing.recv(4096)
        assert not response, "A pre-existing Internet connection bypassed the guard"
    except (TimeoutError, ConnectionError, OSError):
        pass
    finally:
        existing.close()
    print("PASS: pre-existing Internet connection cannot bypass the guard", flush=True)
    for server, transport in reachable_dns:
        result = dns_query(server, transport, 10001, 10001)
        assert result.returncode == 0 and "status: NOERROR" in result.stdout, "Bootstrap DNS exception failed"
    print("PASS: dedicated endpoint resolver can still use UDP/TCP DNS", flush=True)


if __name__ == "__main__":
    main()
