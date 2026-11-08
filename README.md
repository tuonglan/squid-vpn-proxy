# Squid + WireGuard proxy

An authenticated HTTP forward proxy in one Ubuntu 26.04 container. HTTP requests
and HTTPS CONNECT tunnels leave through WireGuard. Destination services see the
VPN server's public exit address. Applications must explicitly use the proxy;
this does not route the host's other traffic.

The initial implementation targets trusted private networks. The proxy listener
uses HTTP, including when tunnelling HTTPS websites. Website TLS stays end to end,
but the proxy credentials themselves are not encrypted on the client-to-proxy hop.

## Requirements

- Native Linux with kernel WireGuard, nftables, and policy routing support.
- Docker Engine 28+ and Compose 2.36+ (for explicit interface naming and
  interface-specific sysctls), plus Buildx for publishing.
- Python 3.10+ on the host for the scripts, with no third-party Python dependencies.
- `sudo docker` access. The scripts consistently use this form.
- For Raspberry Pi 4: a **64-bit** OS/kernel (`uname -m` should show `aarch64`).
  The published platforms are `linux/amd64` and `linux/arm64`, not 32-bit ARM.

Use a separate WireGuard peer configuration on each host. Running the same client
key concurrently on amd64 and the Pi can make the VPN server switch the peer's
endpoint between the two machines.

## Configure

```sh
cp .env.example .env
chmod 600 .env
openssl rand -base64 32
```

Put the generated string in `PROXY_PASSWORD` and choose `PROXY_USERNAME`.
Use single-line dotenv assignments; quote paths containing spaces. Literal `$`
characters must be single-quoted. Scripts do not execute or `source` `.env`.
The password must be 16–72 bytes (bcrypt's upper limit); 32 random bytes encoded as
base64 fit comfortably. This is Basic authentication; the random password acts
as an API key. OAuth/JWT/Bearer authentication is not implemented.

Set `WG_CONFIG_PATH` to the supplied file, for example
`./data/Squid-proxy.conf`. The bind mount is read-only and startup fails if the file
is absent. Restrict its host permissions with `chmod 600 data/Squid-proxy.conf`.
Its keys stay in that file; they are not duplicated into `.env`.

The default bind address, `127.0.0.1`, permits host-local access. For other private
network clients, set `PROXY_BIND_ADDRESS` to this host's LAN IPv4 address and
narrow `PROXY_ALLOWED_CIDRS` to the client subnet(s). Host connections may appear
with the Docker bridge gateway as their source, so include that address/subnet
if needed. The default allow-list accepts loopback and RFC1918 source ranges.
This is independent of destination filtering: private destinations are denied.

Credentials, runtime state, and `data/` are excluded from the image build context
and Git. Docker administrators can still inspect container environment values.
Registry credentials in `.env` are used only by the build/push script.

## WireGuard configuration

Supported input is a standard configuration with exactly one `[Interface]` and
one `[Peer]`:

```ini
[Interface]
PrivateKey = <client private key>
Address = 10.20.0.2/32
MTU = 1420

[Peer]
PublicKey = <server public key>
PresharedKey = <optional preshared key>
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

Remove the `PresharedKey` line when unused. `ListenPort` is optional. MTU defaults
to 1420 and keepalive to 25 seconds. IPv6 addresses, IPv6 endpoints, split tunnels,
multiple peers, shell hooks, `Table`, `FwMark`, and `SaveConfig` are rejected.
The configuration is parsed as data; it is never run through a shell or wg-quick.
A temporary private `wg setconf` file in `/run` is removed after setup.

An imported `DNS` line is ignored, including IPv6 resolvers. Squid explicitly uses
`PROXY_DNS_SERVERS` (default `1.1.1.1,8.8.8.8`) through the VPN. The runtime's
connectivity checks also query these resolvers directly, avoiding Docker's
embedded DNS. There is no application DNS fallback outside WireGuard.

Endpoint hostnames need an initial DNS lookup before the tunnel is usable. A
dedicated unprivileged resolver identity can contact only
`WG_BOOTSTRAP_DNS_SERVERS` on UDP/TCP port 53 outside the tunnel. Only endpoint
resolution uses that identity. This deliberately exposes the **endpoint hostname**
to those resolvers; proxied destination lookups stay inside the VPN. Bootstrap
resolvers must be reachable public IPv4 servers. Endpoint DNS should have an A
record. The endpoint is re-resolved after a stale handshake and failed connectivity
probe; endpoint changes update the firewall allow-list atomically. The endpoint
IP/port is pinned to DNS/configuration, so unsolicited peer roaming to another
address/port is not accepted until the configured endpoint is refreshed.

The VPN server must permit outbound IPv4 forwarding/NAT and access to the chosen
public DNS resolvers. The container's Ubuntu version does not supply the host's
kernel module. If needed, load WireGuard on the host with `sudo modprobe wireguard`.

## Development deployment

```sh
./scripts/compose.sh dev up -d --build
./scripts/compose.sh dev ps
./scripts/compose.sh dev logs -f proxy
```

`compose.yml` defines runtime settings. `compose.dev.yml` adds the local build;
`compose.prd.yml` specifies registry pulls. The wrapper combines the appropriate
files and loads both `.env` and `VERSION`, including across sudo's environment
filtering. Run commands from any directory using the script's absolute path.

No credentials are supplied as build arguments. Startup first installs the
firewall, initializes WireGuard, and tests DNS and HTTPS through the VPN. Squid
only starts after that test succeeds. The active probe uses
`https://www.cloudflare.com/cdn-cgi/trace` approximately every 30 seconds. This
external dependency can mark the container unhealthy even if some other
destinations still work. Later probe failures leave the firewall in force.
Docker health status alone does not restart containers. A missing interface or
Squid process causes supervisor exit and the restart policy takes effect.

## Build and publish both architectures

Set the desired release in `VERSION`, for example `0.1.0`, and set
`DOCKERHUB_USERNAME` and a push-capable `DOCKERHUB_TOKEN` in `.env`. Existing root
Docker login credentials may be used by leaving the token blank.

```sh
./scripts/build-push.sh
```

The script creates/reuses a `docker-container` Buildx builder and runs the
equivalent of:

```sh
sudo docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.1.0 \
  --tag tuonglan/squid-vpn-proxy:0.1.0 --push .
```

One tag points to both platform images. Each deployment automatically pulls its
native variant. There is no `latest` tag. Update `VERSION` for each release; the
registry does not enforce tag immutability for you. Login via the script stores
credentials in root's Docker configuration, as `sudo docker login` normally does.

Cross-platform builds need either working BuildKit/QEMU emulation or native nodes
for both architectures. Inspect available platforms with:

```sh
sudo docker buildx inspect squid-vpn-proxy --bootstrap
```

If emulation is unavailable, configure it following the
[Docker multi-platform guide](https://docs.docker.com/build/building/multi-platform/),
or use a multi-node builder with amd64 and arm64 Docker contexts. The publishing
script does not install privileged emulation components automatically.

## Production deployment

Copy the Compose files, `VERSION`, `scripts/compose.sh`, `scripts/manage.py`, your
host-specific `.env`, and its WireGuard configuration to each machine. Then:

```sh
./scripts/compose.sh prd up -d
./scripts/compose.sh prd ps
```

Production pulls `tuonglan/squid-vpn-proxy:<VERSION>` without building. If the
Docker Hub repository is private, authenticate with `sudo docker login` on each
deployment host first. After changing passwords, bind settings, or configuration
mounts, recreate the container:

```sh
./scripts/compose.sh prd up -d --force-recreate
```

Changing a mounted WireGuard file also requires recreation/restart; it is not
watched for live reloads. To stop a deployment, use `./scripts/compose.sh prd down`.

## Client examples

Curl prompts for the password when only the username is supplied:

```sh
curl --noproxy '' --proxy http://127.0.0.1:3128 \
  --proxy-user proxyuser https://api.ipify.org
```

For Python applications using Requests, populate the application environment
with the credentials, then URL-encode them (base64 passwords can contain `/`,
`+`, and `=`):

```python
import os
from urllib.parse import quote
import requests

user = quote(os.environ["PROXY_USERNAME"], safe="")
password = quote(os.environ["PROXY_PASSWORD"], safe="")
proxy = f"http://{user}:{password}@127.0.0.1:3128"
with requests.Session() as session:
    session.trust_env = False  # Avoid NO_PROXY silently bypassing the proxy.
    session.proxies = {"http": proxy, "https": proxy}
    response = session.get("https://api.ipify.org", timeout=30)
    response.raise_for_status()
    print(response.text)
```

Both proxy URLs use `http://`; HTTPS websites use CONNECT within that connection.
Chrome can use the host/port as its HTTP proxy and prompt for credentials.
The proxy supports TCP HTTP/HTTPS, not UDP/QUIC or SOCKS. Client software that
ignores the proxy is outside this container's kill-switch protection.

## Network isolation and kill switch

- The root supervisor configures networking; Squid and its auth helper run as the
  unprivileged `proxy` user. There is no privileged container or host networking.
- IPv6 is disabled by container sysctls and denied by the firewall.
- Outbound traffic defaults to `wg0`, with an unreachable fallback route.
- The Docker interface permits only marked WireGuard UDP to its pinned endpoint,
  endpoint-bootstrap DNS from the dedicated UID, and tracked replies to accepted
  proxy clients. No generic established-output bypass is allowed.
- Client-reply routing selects the proxy's source port before tunnel routing;
  the firewall further requires an inbound connection's mark and reply direction.
- Proxy requests to private, loopback, link-local, multicast, and reserved IPv4
  networks are denied by Squid and the firewall. Destination ports are restricted
  to 80 and 443, with CONNECT restricted to 443. LAN client replies are explicitly
  allowed before destination filtering.
- Shutdown never removes the firewall. Tunnel loss blocks traffic even if the
  Docker default route remains. This does not protect against a privileged host
  administrator or a compromised root supervisor that can rewrite the firewall.

Caching and request access logs default to off. `PROXY_ACCESS_LOG=true` streams
access logs to Docker; they may contain request URLs. Administrative messages also
go to Docker logs, which are size-limited by Compose. Runtime credentials are in
tmpfs; the password is stored there as a bcrypt hash. Recreating the container
clears the authentication cache when rotating credentials.

## Verification

Offline unit checks:

```sh
python3 -m unittest discover -s tests -v
```

With the proxy running, verify authentication, HTTP, HTTPS, and private destination
denials. Supply the VPN's expected exit address for an explicit egress assertion:

```sh
python3 scripts/verify.py --expected-ip YOUR_VPN_EXIT_IPV4
```

Omit `--expected-ip` to print the observed address for manual comparison. The test
contacts example.com and api.ipify.org. `--host` overrides the bind address when
testing from a different machine. It reads `.env` without placing credentials in
command arguments and does not inherit environment proxy settings.

The following **disrupts the dev proxy** and then restarts it:

```sh
./scripts/test-killswitch.sh --disrupt-dev
```

It first requires working tunnel HTTPS, pauses the supervisor, deletes `wg0`,
removes the unreachable route to force default-route fallback, and verifies that
new HTTPS and UDP/TCP DNS requests fail for both Squid's UID and root. It excludes
the deliberately allowed endpoint-resolver UID. The wrapper always requests a
restart, including when the test fails. Run this on a disposable dev deployment.

Before production use, also capture packets on the container's `eth0` while
making requests and interrupting the VPN endpoint. Expect only encrypted
WireGuard UDP, endpoint-bootstrap DNS, and proxy-client connections. Check active
CONNECT sessions, cold startup, shutdown/restart, endpoint IP changes, and both
architectures. The automated deletion test does not prove all of those cases.

To exercise the deployed image's firewall without interrupting the proxy or
reusing its WireGuard keys, run the isolated integration test from this repository:

```sh
sudo docker run --rm --pull never --read-only \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --sysctl net.ipv6.conf.default.disable_ipv6=1 \
  --env DISPOSABLE_FIREWALL_TEST=1 \
  --mount "type=bind,source=$(pwd)/tests/integration_firewall.py,target=/test.py,readonly" \
  --entrypoint python3 "tuonglan/squid-vpn-proxy:$(cat VERSION)" /test.py
```

This test first verifies direct Internet/DNS availability. It then checks an
unusable WireGuard interface, interface deletion with default-route fallback,
an established Internet connection, and the dedicated endpoint-resolver exception.
It needs no actual VPN configuration and removes its container afterwards. DNS
paths unavailable before the firewall is installed are excluded from its claims.

## Current validation status

Verified on 2026-11-08 against the operator-built amd64 image running Squid 7.7:

- The offline configuration/control suite passed 15 tests; shell syntax and YAML
  parsing checks passed during implementation.
- The running deployment was healthy with zero restarts. Authentication rejection,
  authenticated HTTP/HTTPS, and private-destination denial passed through the
  host's published port, 3129.
- The observed proxy exit IP matched a separate request through WireGuard and
  differed from the host's direct public IP.
- Both configured resolvers answered UDP/TCP queries through WireGuard. IPv6 was
  disabled on all checked interfaces, the VPN file was mounted read-only, and
  Squid ran as its unprivileged user.
- The isolated firewall integration test passed all four checks described above.
  The deployed proxy was not stopped, restarted, or disconnected for these tests.

On this host, direct DNS to 1.1.1.1 timed out even without the container firewall;
8.8.8.8 worked, including through the endpoint-bootstrap exception. The configured
resolver fallback therefore matters. Both servers worked inside the VPN.

Logs contain non-fatal warnings about deliberately disabled IPv6, `via off`, and
a denied `setuid(0)` attempt during authentication-helper startup. The authenticated
requests passed despite that helper warning. Native arm64 execution, publication
of a multi-platform manifest, packet captures, and a real VPN-server outage or
endpoint change remain unverified. No image has been published by this agent.
