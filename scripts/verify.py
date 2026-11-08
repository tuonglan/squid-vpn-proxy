#!/usr/bin/env python3
"""Read-only live checks against a running proxy; credentials never enter argv."""

import argparse
import base64
import http.client
import ipaddress
import ssl

from manage import ROOT, read_env


def request(host, port, target, authorization=None, tls=False):
    headers = {"Proxy-Authorization": authorization} if authorization else {}
    if tls:
        connection = http.client.HTTPSConnection(host, port, timeout=20, context=ssl.create_default_context())
        connection.set_tunnel(target, 443, headers=headers)
        connection.request("GET", "/", headers={"Host": target})
    else:
        connection = http.client.HTTPConnection(host, port, timeout=20)
        connection.request("GET", f"http://{target}/", headers=headers)
    try:
        response = connection.getresponse()
        return response.status, response.read(65536).decode(errors="replace")
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", help="Proxy host; defaults to PROXY_BIND_ADDRESS")
    parser.add_argument("--expected-ip", help="Optional expected VPN exit IPv4 address")
    args = parser.parse_args()
    env = read_env(ROOT / ".env")
    host = args.host or env.get("PROXY_BIND_ADDRESS", "127.0.0.1")
    if host == "0.0.0.0":
        host = "127.0.0.1"
    port = int(env.get("PROXY_PORT", "3128"))
    authorization = "Basic " + base64.b64encode(
        f"{env['PROXY_USERNAME']}:{env['PROXY_PASSWORD']}".encode()).decode()
    wrong = "Basic " + base64.b64encode(b"invalid:invalid").decode()
    for credentials in (None, wrong):
        status, _ = request(host, port, "example.com", credentials)
        if status != 407:
            raise RuntimeError(f"Expected authentication rejection (407), received {status}")
    status, _ = request(host, port, "example.com", authorization)
    if not 200 <= status < 400:
        raise RuntimeError(f"Authenticated HTTP failed ({status})")
    for destination in ("127.0.0.1", "169.254.169.254", "10.0.0.1"):
        status, _ = request(host, port, destination, authorization)
        if status != 403:
            raise RuntimeError(f"Private destination was not rejected ({status})")
    status, body = request(host, port, "api.ipify.org", authorization, tls=True)
    if status != 200:
        raise RuntimeError(f"Authenticated HTTPS failed ({status})")
    exit_ip = str(ipaddress.IPv4Address(body.strip()))
    if args.expected_ip and exit_ip != str(ipaddress.IPv4Address(args.expected_ip)):
        raise RuntimeError("Proxy exit IP differs from --expected-ip")
    print(f"PASS: authentication, HTTP, HTTPS, private destination denial. Proxy exit IPv4: {exit_ip}")
    if not args.expected_ip:
        print("Compare this with the VPN's expected exit IP; pass --expected-ip to assert it.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, http.client.HTTPException) as error:
        raise SystemExit(f"Verification failed: {error}")
