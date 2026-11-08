"""Strict configuration parsing and deterministic network policy rendering."""

import base64
import configparser
import ipaddress
import re
from dataclasses import dataclass, field

WG_MARK = 51820
REPLY_MARK = 51821
DNS_UID = 10001
BLOCKED = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)


def ipv4_list(value):
    addresses = [str(ipaddress.IPv4Address(x.strip())) for x in value.split(",")]
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError("DNS resolvers must be public IPv4 addresses")
    return list(dict.fromkeys(addresses))


@dataclass
class Settings:
    username: str
    password: str = field(repr=False)
    clients: list[str]
    dns: list[str]
    bootstrap_dns: list[str]
    access_log: bool

    @classmethod
    def from_env(cls, env):
        username = env.get("PROXY_USERNAME", "")
        password = env.get("PROXY_PASSWORD", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
            raise ValueError("PROXY_USERNAME must contain 1-64 letters, digits, _, . or -")
        if not 16 <= len(password.encode()) <= 72 or any(c in password for c in "\r\n\x00"):
            raise ValueError("PROXY_PASSWORD must be 16-72 bytes without line breaks or NUL")
        if password == "replace-with-a-random-base64-password":
            raise ValueError("Replace the example proxy password")
        clients = [str(ipaddress.IPv4Network(x.strip(), strict=False)) for x in env.get(
            "PROXY_ALLOWED_CIDRS", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
        ).split(",")]
        access_log = env.get("PROXY_ACCESS_LOG", "false").lower()
        if access_log not in ("true", "false"):
            raise ValueError("PROXY_ACCESS_LOG must be true or false")
        return cls(username, password, clients,
                   ipv4_list(env.get("PROXY_DNS_SERVERS", "1.1.1.1,8.8.8.8")),
                   ipv4_list(env.get("WG_BOOTSTRAP_DNS_SERVERS", "1.1.1.1,8.8.8.8")),
                   access_log == "true")


def key(value):
    try:
        if len(base64.b64decode(value, validate=True)) == 32:
            return value
    except (ValueError, TypeError):
        pass
    raise ValueError("Invalid WireGuard key (expected 32 bytes encoded as base64)")


@dataclass
class WireGuard:
    private_key: str = field(repr=False)
    public_key: str
    preshared_key: str = field(repr=False)
    addresses: list[str]
    endpoint_host: str
    endpoint_port: int
    mtu: int
    keepalive: int
    listen_port: int

    @classmethod
    def parse(cls, text):
        parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
        try:
            parser.read_string(text)
        except configparser.Error:
            raise ValueError("Malformed WireGuard configuration") from None
        if parser.defaults() or set(parser.sections()) != {"Interface", "Peer"}:
            raise ValueError("Exactly one [Interface] and one [Peer] are required")
        interface, peer = parser["Interface"], parser["Peer"]
        allowed = {"privatekey", "address", "mtu", "dns", "listenport"}
        if set(interface) - allowed:
            raise ValueError("Unsupported Interface fields; hooks, Table, FwMark and SaveConfig are not accepted")
        if set(peer) - {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}:
            raise ValueError("Unsupported Peer fields")
        try:
            addresses = [str(ipaddress.IPv4Interface(x.strip())) for x in interface["address"].split(",")]
            networks = [ipaddress.IPv4Network(x.strip()) for x in peer["allowedips"].split(",")]
            if networks != [ipaddress.IPv4Network("0.0.0.0/0")]:
                raise ValueError("AllowedIPs must be exactly 0.0.0.0/0")
            host, port = peer["endpoint"].rsplit(":", 1)
            if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?", host):
                raise ValueError("Endpoint must use an IPv4 address or DNS hostname")
            port = int(port)
            mtu = int(interface.get("mtu", "1420"))
            keepalive = int(peer.get("persistentkeepalive", "25"))
            listen_port = int(interface.get("listenport", "0"))
            if not (1 <= port <= 65535 and 576 <= mtu <= 1500 and 0 <= keepalive <= 65535 and 0 <= listen_port <= 65535):
                raise ValueError("Invalid port, MTU, or keepalive")
            return cls(key(interface["privatekey"]), key(peer["publickey"]),
                       key(peer["presharedkey"]) if peer.get("presharedkey") else "",
                       addresses, host, port, mtu, keepalive, listen_port)
        except KeyError:
            raise ValueError("Missing required WireGuard field") from None

    def render(self, endpoint_ip):
        endpoint_ip = str(ipaddress.IPv4Address(endpoint_ip))
        psk = f"PresharedKey = {self.preshared_key}\n" if self.preshared_key else ""
        return (f"[Interface]\nPrivateKey = {self.private_key}\nFwMark = {WG_MARK}\n"
                f"ListenPort = {self.listen_port}\n[Peer]\nPublicKey = {self.public_key}\n"
                f"{psk}AllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint_ip}:{self.endpoint_port}\n"
                f"PersistentKeepalive = {self.keepalive}\n")


def firewall(settings, proxy_uid):
    """No unqualified established-output accept: old connections cannot fall back."""
    return f"""table inet vpn_guard {{
  set endpoints {{ type ipv4_addr . inet_service; }}
  set bootstrap_dns {{ type ipv4_addr; elements = {{ {', '.join(settings.bootstrap_dns)} }}; }}
  set clients {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {', '.join(settings.clients)} }}; }}
  set blocked {{ type ipv4_addr; flags interval; elements = {{ {', '.join(BLOCKED)} }}; }}
  chain ingress_mark {{
    type filter hook prerouting priority mangle; policy accept;
    iifname "eth0" ip saddr @clients tcp dport 3128 ct state new ct mark set {REPLY_MARK}
  }}
  chain input {{
    type filter hook input priority filter; policy drop;
    meta nfproto ipv6 drop
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "eth0" ip saddr @clients tcp dport 3128 accept
  }}
  chain output {{
    type filter hook output priority filter; policy drop;
    meta nfproto ipv6 drop
    oifname "lo" ct direction reply tcp sport 3128 ct state established accept
    oifname "eth0" ct mark {REPLY_MARK} ct direction reply tcp sport 3128 ct state established accept
    meta skuid {proxy_uid} ip daddr @blocked drop
    oifname "lo" accept
    oifname "eth0" meta mark {WG_MARK} ip daddr . udp dport @endpoints accept
    oifname "eth0" meta skuid {DNS_UID} ip daddr @bootstrap_dns udp dport 53 accept
    oifname "eth0" meta skuid {DNS_UID} ip daddr @bootstrap_dns tcp dport 53 accept
    oifname "wg0" ip daddr @blocked drop
    oifname "wg0" accept
  }}
  chain forward {{ type filter hook forward priority filter; policy drop; }}
}}
"""


def squid_config(settings):
    return f"""http_port 0.0.0.0:3128
visible_hostname squid-vpn-proxy
pid_filename /run/proxy/squid.pid
cache_effective_user proxy
cache_effective_group proxy
cache_log /dev/null
cache_store_log none
access_log {'stdio:/run/proxy/access.pipe' if settings.access_log else 'none'}
logfile_rotate 0
cache deny all
cache_mem 0 MB
coredump_dir /run/proxy
shutdown_lifetime 3 seconds
pinger_enable off
netdb_filename none
forwarded_for delete
via off
dns_nameservers {' '.join(settings.dns)}
auth_param basic program /usr/lib/squid/basic_ncsa_auth /run/proxy/passwd
auth_param basic realm Private VPN proxy
auth_param basic credentialsttl 1 minute
acl authenticated proxy_auth REQUIRED
acl clients src {' '.join(settings.clients)}
acl blocked dst {' '.join(BLOCKED)}
acl safe_ports port 80 443
acl tls_ports port 443
http_access deny manager
http_access deny !clients
http_access deny !safe_ports
http_access deny CONNECT !tls_ports
http_access deny !authenticated
http_access deny blocked
http_access allow authenticated
http_access deny all
"""
