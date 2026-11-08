#!/usr/bin/env python3
"""Explicit, disruptive test for a disposable dev deployment. Restart afterwards."""

import os
from pathlib import Path
import pwd
import signal
import subprocess

from config import Settings, WG_MARK
from service import run


def https(uid, gid):
    return run(["curl", "--noproxy", "*", "--ipv4", "--fail", "--silent",
                "--connect-timeout", "3", "--max-time", "5", "--output", "/dev/null",
                "https://1.1.1.1/cdn-cgi/trace"], uid=uid, gid=gid, timeout=7, check=False).returncode == 0


def main():
    account = pwd.getpwnam("proxy")
    settings = Settings.from_env(os.environ)
    if not https(account.pw_uid, account.pw_gid):
        raise RuntimeError("Baseline tunnel HTTPS failed; kill-switch result would be inconclusive")
    pid = int(Path("/run/wireguard/supervisor.pid").read_text())
    os.kill(pid, signal.SIGSTOP)
    try:
        run(["ip", "link", "del", "wg0"])
        # Also remove the routing safety net, proving the firewall blocks fallback
        # through the still-present Docker/main default route on its own.
        run(["ip", "-4", "route", "del", "unreachable", "default", "metric", "32767", "table", str(WG_MARK)])
        for uid, gid in ((account.pw_uid, account.pw_gid), (0, 0)):
            if https(uid, gid):
                raise RuntimeError("FAIL: HTTPS escaped via the Docker default route")
            for server in settings.dns:
                for transport in ("+notcp", "+tcp"):
                    result = run(["dig", f"@{server}", "example.com", "A", transport,
                                  "+time=1", "+tries=1"], uid=uid, gid=gid, timeout=5, check=False)
                    if result.returncode == 0:
                        raise RuntimeError("FAIL: application DNS escaped outside the tunnel")
        print("PASS: HTTPS and UDP/TCP DNS blocked for Squid and root after wg0 deletion and route fallback", flush=True)
    finally:
        os.kill(pid, signal.SIGCONT)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
