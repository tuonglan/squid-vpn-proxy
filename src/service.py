#!/usr/bin/env python3
"""Container supervisor. Networking fails closed independently of health checks."""

import ipaddress
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import threading
import time

from config import DNS_UID, WG_MARK, Settings, WireGuard, firewall, squid_config

RUNTIME = Path("/run/proxy")
PRIVATE = Path("/run/wireguard")
READY = PRIVATE / "ready"
PROBE_HOST = "www.cloudflare.com"
STOP = False
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/run/proxy"}


def log(message):
    print(f"vpn-proxy: {message}", flush=True)


def run(args, *, input=None, uid=None, gid=None, timeout=20, check=True):
    options = {}
    if uid is not None:
        options.update(user=uid, group=gid if gid is not None else uid, extra_groups=[])
    result = subprocess.run(args, input=input, text=True, capture_output=True,
                            env=CLEAN_ENV, timeout=timeout, **options)
    if check and result.returncode:
        # Do not echo command arguments, stdin, or stderr: they may contain keys.
        name = Path(args[0]).name
        # These two tools only receive validated addresses and generated policy,
        # never credentials. Their diagnostics are useful for kernel support errors.
        detail = f": {result.stderr.strip()}" if name in {"ip", "nft"} else ""
        raise RuntimeError(f"{name} failed (exit {result.returncode}){detail}")
    return result


def stop(_signum, _frame):
    global STOP
    STOP = True


def sleep(seconds):
    deadline = time.monotonic() + seconds
    while not STOP and time.monotonic() < deadline:
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def resolve(host, servers, *, bootstrap=False):
    try:
        address = ipaddress.IPv4Address(host)
        return str(address)
    except ipaddress.AddressValueError:
        pass
    for server in servers:
        result = run(["dig", f"@{server}", host, "A", "+short", "+time=2", "+tries=1"],
                     uid=DNS_UID if bootstrap else None, timeout=8, check=False)
        if result.returncode:
            continue
        for line in result.stdout.splitlines():
            try:
                address = ipaddress.IPv4Address(line.strip())
                if address.is_global:
                    return str(address)
            except ipaddress.AddressValueError:
                continue
    raise RuntimeError("IPv4 DNS lookup failed")


def install_firewall(settings, proxy_uid):
    exists = run(["nft", "list", "table", "inet", "vpn_guard"], check=False).returncode == 0
    prefix = "delete table inet vpn_guard\n" if exists else ""
    run(["nft", "-f", "-"], input=prefix + firewall(settings, proxy_uid))


def install_rules():
    # The Docker/main default route is retained for outer UDP and client replies.
    # Remove only the priorities owned by this application on a container restart.
    for priority in (100, 110, 120, 200):
        while run(["ip", "-4", "rule", "del", "priority", str(priority)], check=False).returncode == 0:
            pass
    run(["ip", "-4", "rule", "add", "priority", "100", "fwmark", str(WG_MARK), "lookup", "main"])
    # These selectors work at the FIRST route lookup, before nft OUTPUT runs.
    # Marking bootstrap DNS only in OUTPUT would fail against the unreachable
    # default when the tunnel is absent. Firewall rules still restrict both paths.
    run(["ip", "-4", "rule", "add", "priority", "110", "ipproto", "tcp", "sport", "3128", "lookup", "main"])
    run(["ip", "-4", "rule", "add", "priority", "120", "uidrange", f"{DNS_UID}-{DNS_UID}", "lookup", "main"])
    run(["ip", "-4", "rule", "add", "priority", "200", "lookup", str(WG_MARK)])
    # A missing wg0 route must not fall through to main, even before firewall checks.
    run(["ip", "-4", "route", "replace", "unreachable", "default", "metric", "32767", "table", str(WG_MARK)])


def set_endpoint(ip, port):
    ip = str(ipaddress.IPv4Address(ip))
    # Replace the allow-list atomically. There is never an allow-any UDP window.
    run(["nft", "-f", "-"], input=(
        "flush set inet vpn_guard endpoints\n"
        f"add element inet vpn_guard endpoints {{ {ip} . {int(port)} }}\n"))


def start_wireguard(config, endpoint):
    run(["ip", "link", "del", "wg0"], check=False)
    run(["ip", "link", "add", "wg0", "type", "wireguard"])
    path = PRIVATE / "wg0.conf"
    path.write_text(config.render(endpoint))
    path.chmod(0o600)
    try:
        run(["wg", "setconf", "wg0", str(path)])
    finally:
        path.unlink(missing_ok=True)
    for address in config.addresses:
        run(["ip", "-4", "address", "add", address, "dev", "wg0"])
    run(["ip", "link", "set", "wg0", "mtu", str(config.mtu), "up"])
    run(["ip", "-4", "route", "replace", "default", "dev", "wg0", "metric", "100", "table", str(WG_MARK)])


def probe(settings, proxy_uid, proxy_gid):
    """Active DNS + HTTPS over the tunnel; no dependency on Docker's resolver."""
    try:
        address = resolve(PROBE_HOST, settings.dns)
        result = run(["curl", "--noproxy", "*", "--ipv4", "--fail", "--silent",
                      "--connect-timeout", "4", "--max-time", "8", "--output", "/dev/null",
                      "--resolve", f"{PROBE_HOST}:443:{address}",
                      f"https://{PROBE_HOST}/cdn-cgi/trace"],
                     uid=proxy_uid, gid=proxy_gid, timeout=10, check=False)
        return result.returncode == 0
    except (RuntimeError, subprocess.TimeoutExpired):
        return False


def handshake_age():
    result = run(["wg", "show", "wg0", "latest-handshakes"])
    timestamps = [int(line.split()[1]) for line in result.stdout.splitlines()]
    return time.time() - max(timestamps, default=0)


def prepare_squid(settings, proxy_uid, proxy_gid):
    RUNTIME.mkdir(mode=0o750, exist_ok=True)
    os.chown(RUNTIME, proxy_uid, proxy_gid)
    if settings.access_log:
        fifo = RUNTIME / "access.pipe"
        fifo.unlink(missing_ok=True)
        os.mkfifo(fifo, mode=0o600)
        os.chown(fifo, proxy_uid, proxy_gid)
        # A pipe avoids unbounded log files and reopening root-owned Docker FDs
        # from Squid's unprivileged process. Docker rotates the forwarded output.
        fd = os.open(fifo, os.O_RDWR)

        def forward_access_log():
            with os.fdopen(fd, "rb", buffering=0) as stream:
                while chunk := stream.read(4096):
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()

        threading.Thread(target=forward_access_log, daemon=True).start()
    credentials = run(["htpasswd", "-niB", "-C", "10", settings.username],
                      input=settings.password + "\n").stdout
    settings.password = ""
    os.environ.pop("PROXY_PASSWORD", None)
    for name, contents in (("passwd", credentials), ("squid.conf", squid_config(settings))):
        path = RUNTIME / name
        path.write_text(contents)
        path.chmod(0o600)
        os.chown(path, proxy_uid, proxy_gid)
    # Inherit stdout/stderr so configuration errors remain diagnosable.
    result = subprocess.run(["squid", "-k", "parse", "-f", str(RUNTIME / "squid.conf")],
                            env=CLEAN_ENV, user=proxy_uid, group=proxy_gid, extra_groups=[])
    if result.returncode:
        raise RuntimeError("Squid configuration validation failed")


def healthcheck():
    try:
        if time.time() - READY.stat().st_mtime > 100:
            return 1
        with socket.create_connection(("127.0.0.1", 3128), timeout=2):
            return 0
    except OSError:
        return 1


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    child = None
    try:
        settings = Settings.from_env(os.environ)
        config = WireGuard.parse(Path("/etc/wireguard/client.conf").read_text())
        account = pwd.getpwnam("proxy")
        PRIVATE.mkdir(mode=0o700, exist_ok=True)
        (PRIVATE / "supervisor.pid").write_text(str(os.getpid()))
        READY.unlink(missing_ok=True)
        for name in ("all", "default"):
            if Path(f"/proc/sys/net/ipv6/conf/{name}/disable_ipv6").read_text().strip() != "1":
                raise RuntimeError("IPv6 must be disabled by the Compose sysctls")
        install_firewall(settings, account.pw_uid)
        install_rules()
        prepare_squid(settings, account.pw_uid, account.pw_gid)
        log("Firewall active; resolving WireGuard endpoint with the restricted bootstrap resolver")
        while not STOP:
            try:
                endpoint = resolve(config.endpoint_host, settings.bootstrap_dns, bootstrap=True)
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                log("Endpoint DNS unavailable; retrying in 15 seconds (proxy remains stopped)")
                sleep(15)
        if STOP:
            return 0
        set_endpoint(endpoint, config.endpoint_port)
        start_wireguard(config, endpoint)
        config.private_key = config.preshared_key = ""
        was_healthy = None
        last_resolve = time.monotonic()
        while not STOP:
            if child is not None and child.poll() is not None:
                raise RuntimeError("Squid exited; restarting the container")
            # Missing interface causes container restart; the firewall remains installed.
            age = handshake_age()
            healthy = probe(settings, account.pw_uid, account.pw_gid)
            if healthy and child is None:
                child = subprocess.Popen(["squid", "-N", "-d", "1", "-f", str(RUNTIME / "squid.conf")],
                                         env=CLEAN_ENV, user=account.pw_uid,
                                         group=account.pw_gid, extra_groups=[])
            if healthy:
                READY.touch(mode=0o600)
            else:
                READY.unlink(missing_ok=True)
            if healthy != was_healthy:
                log("VPN DNS and HTTPS probe succeeded; proxy ready" if healthy else
                    "VPN probe failed; Internet egress remains restricted to WireGuard")
                was_healthy = healthy
            # WireGuard does not periodically resolve endpoint hostnames itself.
            if not healthy and age > 180 and time.monotonic() - last_resolve >= 60:
                try:
                    endpoint = resolve(config.endpoint_host, settings.bootstrap_dns, bootstrap=True)
                    set_endpoint(endpoint, config.endpoint_port)
                    run(["wg", "set", "wg0", "peer", config.public_key,
                         "endpoint", f"{endpoint}:{config.endpoint_port}"])
                    log("Refreshed WireGuard endpoint after connectivity loss")
                except (RuntimeError, subprocess.TimeoutExpired):
                    log("Endpoint refresh failed; keeping traffic blocked outside the tunnel")
                last_resolve = time.monotonic()
            sleep(30)
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        # Never print subprocess output, exception arguments, or configuration data.
        log(f"Startup/runtime failure: {error}" if isinstance(error, (ValueError, RuntimeError))
            else f"Startup/runtime failure ({type(error).__name__})")
        return 1
    finally:
        READY.unlink(missing_ok=True)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        # Never flush the firewall or restore an unrestricted route on shutdown.


if __name__ == "__main__":
    sys.exit(healthcheck() if sys.argv[1:] == ["healthcheck"] else main())
