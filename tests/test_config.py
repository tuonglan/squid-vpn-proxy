import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from config import Settings, WireGuard, firewall, squid_config

KEY = base64.b64encode(bytes(range(32))).decode()
CONFIG = f"""[Interface]
PrivateKey = {KEY}
Address = 10.20.0.2/32
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = 1420
[Peer]
PublicKey = {KEY}
PresharedKey = {KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"""


class ConfigurationTests(unittest.TestCase):
    def settings(self, **changes):
        return Settings.from_env({"PROXY_USERNAME": "test", "PROXY_PASSWORD": "a" * 44, **changes})

    def test_provider_config_is_normalized_without_dns_or_secret_repr(self):
        config = WireGuard.parse(CONFIG)
        self.assertEqual(config.endpoint_host, "vpn.example.com")
        self.assertEqual(config.addresses, ["10.20.0.2/32"])
        rendered = config.render("1.2.3.4")
        self.assertIn("Endpoint = 1.2.3.4:51820", rendered)
        self.assertIn("PresharedKey =", rendered)
        self.assertNotIn("DNS =", rendered)
        # Public key is intentionally visible in repr; private/PSK fields are not.
        self.assertNotIn("private_key=", repr(config))
        self.assertNotIn("preshared_key=", repr(config))

    def test_rejects_executable_and_route_overrides(self):
        for field in ("PostUp = touch /tmp/pwned", "PreDown = true", "Table = off", "SaveConfig = true", "FwMark = 7"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                WireGuard.parse(CONFIG.replace("MTU = 1420", field))

    def test_requires_single_ipv4_full_tunnel(self):
        for old, new in (("0.0.0.0/0", "10.0.0.0/8"), ("0.0.0.0/0", "0.0.0.0/0, ::/0"),
                         ("10.20.0.2/32", "10.20.0.2/32, fd00::2/128"),
                         ("vpn.example.com:51820", "[::1]:51820")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                WireGuard.parse(CONFIG.replace(old, new))
        with self.assertRaises(ValueError):
            WireGuard.parse(CONFIG + "\n[Peer]\nPublicKey = invalid")

    def test_malformed_config_does_not_echo_key(self):
        try:
            WireGuard.parse(CONFIG + f"\nsecret-{KEY}")
        except ValueError as error:
            self.assertNotIn(KEY, str(error))
        else:
            self.fail("Malformed config was accepted")

    def test_rejects_endpoint_injection_and_invalid_key(self):
        for host in ("vpn.example.com;id:51820", "$(id):51820", "vpn.example.com:0"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                WireGuard.parse(CONFIG.replace("vpn.example.com:51820", host))
        with self.assertRaises(ValueError):
            WireGuard.parse(CONFIG.replace(f"PrivateKey = {KEY}", "PrivateKey = invalid"))

    def test_credentials_are_validated_and_never_rendered_into_config(self):
        for password in ("short", "a" * 15, "a" * 73, "a" * 30 + "\n", "replace-with-a-random-base64-password"):
            with self.subTest(length=len(password)), self.assertRaises(ValueError):
                self.settings(PROXY_PASSWORD=password)
        with self.assertRaises(ValueError):
            self.settings(PROXY_USERNAME="user\nhttp_access allow all")
        settings = self.settings(PROXY_PASSWORD="a+/=" * 10)
        self.assertNotIn(settings.password, squid_config(settings))
        self.assertNotIn(settings.password, repr(settings))

    def test_accepts_password_length_boundaries(self):
        for size in (16, 72):
            with self.subTest(size=size):
                settings = self.settings(PROXY_PASSWORD="a" * size)
                self.assertEqual(len(settings.password), size)

    def test_rejects_ipv6_and_nonpublic_resolvers(self):
        for address in ("::1", "127.0.0.1", "192.168.1.1", "1.1.1.1; accept", ""):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.settings(PROXY_DNS_SERVERS=address)

    def test_input_cannot_inject_firewall_rules(self):
        with self.assertRaises(ValueError):
            self.settings(PROXY_ALLOWED_CIDRS="10.0.0.0/8 }; accept")
        rules = firewall(self.settings(), 13)
        # Established OUTBOUND connections must not survive through eth0 if wg0 disappears.
        output = rules.split("chain output", 1)[1].split("chain forward", 1)[0]
        self.assertNotIn("ct state established,related accept", output)
        self.assertIn('oifname "eth0" ct mark 51821 ct direction reply', output)
        self.assertIn('oifname "eth0" meta skuid 10001', output)
        # LAN client replies must pass BEFORE denying private outbound destinations.
        self.assertLess(output.index('oifname "eth0" ct mark'), output.index('meta skuid 13 ip daddr @blocked drop'))


if __name__ == "__main__":
    unittest.main()
