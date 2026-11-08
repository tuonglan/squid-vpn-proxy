from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]
import service
from manage import read_env


class ServiceTests(unittest.TestCase):
    def test_endpoint_dns_uses_separate_identity_and_ignores_cnames(self):
        answer = subprocess.CompletedProcess([], 0, "alias.example.com.\n1.2.3.4\n", "")
        with patch.object(service, "run", return_value=answer) as run:
            self.assertEqual(service.resolve("vpn.example.com", ["1.1.1.1"], bootstrap=True), "1.2.3.4")
            self.assertEqual(run.call_args.kwargs["uid"], 10001)

    def test_application_dns_never_uses_bootstrap_identity(self):
        answer = subprocess.CompletedProcess([], 0, "1.2.3.4\n", "")
        with patch.object(service, "run", return_value=answer) as run:
            service.resolve("example.com", ["8.8.8.8"])
            self.assertIsNone(run.call_args.kwargs["uid"])

    def test_dns_failure_falls_back_only_to_explicit_resolvers(self):
        answers = [subprocess.CompletedProcess([], 1, "", ""), subprocess.CompletedProcess([], 0, "10.0.0.1\n", "")]
        with patch.object(service, "run", side_effect=answers) as run:
            with self.assertRaises(RuntimeError):
                service.resolve("example.com", ["1.1.1.1", "8.8.8.8"], bootstrap=True)
            self.assertEqual(run.call_count, 2)

    def test_subprocess_errors_do_not_disclose_credentials(self):
        failed = subprocess.CompletedProcess([], 1, "private", "secret")
        with patch.object(service.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "wg failed") as error:
                service.run(["wg", "secret"], input="private")
            self.assertNotIn("secret", str(error.exception))
            self.assertNotIn("private", str(error.exception))

    def test_bootstrap_and_reply_rules_work_before_output_hook(self):
        # With an unreachable tunnel default, output-only packet marking cannot
        # rescue bootstrap traffic. Initial lookup must use UID/source-port rules.
        def command(args, **kwargs):
            return subprocess.CompletedProcess(args, 1 if "del" in args else 0, "", "")
        with patch.object(service, "run", side_effect=command) as run:
            service.install_rules()
            calls = [call.args[0] for call in run.call_args_list]
            self.assertTrue(any("uidrange" in c and "10001-10001" in c for c in calls))
            self.assertTrue(any("sport" in c and "3128" in c for c in calls))
            self.assertTrue(any("unreachable" in c for c in calls))

    def test_dotenv_is_literal_and_supports_base64_and_quoted_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / ".env"
            path.write_text("PASSWORD='abc+/=='\nWG_CONFIG_PATH='./data/a b.conf'\nTOKEN='$(touch /tmp/should-not-exist)'\n")
            values = read_env(path)
            self.assertEqual(values["PASSWORD"], "abc+/==")
            self.assertEqual(values["WG_CONFIG_PATH"], "./data/a b.conf")
            self.assertEqual(values["TOKEN"], "$(touch /tmp/should-not-exist)")
            path.write_text("TOKEN=$(command)\n")
            with self.assertRaises(ValueError):
                read_env(path)


if __name__ == "__main__":
    unittest.main()
