#!/usr/bin/env python3
"""Offline smoke test of app.sh's real run_xray argument -> JSON bridge.

Run with Python 3 from any directory. The extraction boundary is the complete
top-level shell function, not a rewritten copy of its conditionals. Only UCI,
JSON serialization, Lua and service boundaries are substituted; no service runs.
"""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "luci-app-passwall/root/usr/share/passwall/app.sh"
UTILS = ROOT / "luci-app-passwall/root/usr/share/passwall/utils.sh"


def function_source(path, name):
    source = path.read_text()
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", source, re.M | re.S)
    if not match:
        raise AssertionError("Shell function extraction boundary changed: " + name)
    return match.group()


SHIM = r'''
forbidden() { printf '%s\n' 'unexpected external operation' >&2; exit 97; }
ln_run() { forbidden; }
echolog() { forbidden; }
config_n_get() {
    case "$2" in
        local_dns_passthrough) printf '%s' "$FAKE_UCI_OPT_IN" ;;
        loglevel) printf warning ;;
        *) forbidden ;;
    esac
}
json_init() { JSON_VALUES=; }
json_add_string() {
    # All fixture values are simple ASCII scalars. Python parses the final JSON.
    JSON_VALUES="${JSON_VALUES}${JSON_VALUES:+,}\"$1\":\"$2\""
}
json_dump() { printf '{%s}' "$JSON_VALUES"; }
lua() {
    [ "$#" = 3 ] && [ "$1" = synthetic-util ] && [ "$2" = gen_config ] || forbidden
    printf '%s\n' "$3"
}
UTIL_XRAY=synthetic-util
XRAY_BIN=forbidden
'''


def bridge(option=None, inherited=None, uci="1", flag="global"):
    arguments = ["type=xray", "flag=" + flag, "node=synthetic-shunt", "no_run=1",
                 "dns_listen_port=15353",
                 "direct_dns_tcp_server=127.0.0.1#5533", "remote_dns_protocol=tcp",
                 "remote_dns_tcp_server=127.0.0.1#5533", "remote_dns_query_strategy=UseIP"]
    if option is not None:
        arguments.append("local_dns_passthrough=" + option)
    program = SHIM + function_source(UTILS, "eval_set_val") + function_source(APP, "run_xray")
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_UCI_OPT_IN": uci}
    if inherited is not None:
        environment["local_dns_passthrough"] = inherited
    with tempfile.TemporaryDirectory(prefix="xray-bridge-") as temporary:
        output = Path(temporary) / "config.json"
        arguments.append("config_file=" + str(output))
        program += "\nrun_xray " + " ".join(map(shlex.quote, arguments)) + "\n"
        result = subprocess.run(["/bin/sh", "-c", program], env=environment,
                                capture_output=True, text=True, timeout=10)
        if result.returncode or result.stderr:
            raise AssertionError("Shell bridge failed: " + result.stderr.strip())
        return json.loads(output.read_text())


def global_selection(protocol, dns_shunt, opt_in):
    # Deliberately smaller seam: execute the actual opt-in statement from the
    # global Xray arm, without mocking the complete service orchestration stack.
    caller = function_source(APP, "start_global")
    branch = caller.split("\n\txray)\n", 1)[1].split("\n\t;;", 1)[0]
    match = re.search(r'^\t\t\[ "\$protocol"[^\n]*&& \[ "\$DNS_SHUNT".*?\n(?=\t\t_args=)',
                      branch, re.M | re.S)
    if not match:
        raise AssertionError("Global Xray selection extraction boundary changed")
    program = SHIM + "\n_args=\n" + match.group() + '\nprintf "%s" "$_args"\n'
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "protocol": protocol, "DNS_SHUNT": dns_shunt, "FAKE_UCI_OPT_IN": opt_in}
    result = subprocess.run(["/bin/sh", "-c", program], env=environment,
                            capture_output=True, text=True, timeout=10)
    if result.returncode or result.stderr:
        raise AssertionError("Global selector failed: " + result.stderr.strip())
    return result.stdout.split()


class XrayBridgeTests(unittest.TestCase):
    def test_explicit_opt_in_reaches_gen_config(self):
        result = bridge(option="1", uci="0")
        self.assertEqual(result["local_dns_passthrough"], "1")
        self.assertEqual(result["direct_dns_tcp_server"], "127.0.0.1")
        self.assertEqual(result["remote_dns_tcp_server"], "127.0.0.1")
        self.assertEqual(result["direct_dns_port"], "5533")
        self.assertEqual(result["remote_dns_tcp_port"], "5533")
        self.assertEqual(result["no_run"], "1")

    def test_missing_argument_does_not_read_global_uci(self):
        for flag in ("global", "acl_synthetic", "url_test_synthetic"):
            with self.subTest(flag=flag):
                self.assertNotIn("local_dns_passthrough", bridge(flag=flag))

    def test_missing_argument_does_not_inherit_environment(self):
        for flag in ("global", "acl_synthetic", "url_test_synthetic"):
            with self.subTest(flag=flag):
                self.assertNotIn("local_dns_passthrough", bridge(inherited="1", flag=flag))

    def test_explicit_zero_is_not_serialized(self):
        self.assertNotIn("local_dns_passthrough", bridge(option="0", inherited="1"))

    def test_global_caller_requires_shunt_dnsmasq_and_explicit_opt_in(self):
        for protocol in ("_shunt", "socks", "_balancing"):
            for dns_shunt in ("dnsmasq", "chinadns-ng", "smartdns"):
                for opt_in in ("0", "1"):
                    with self.subTest(protocol=protocol, dns_shunt=dns_shunt, opt_in=opt_in):
                        expected = ["local_dns_passthrough=1"] if (
                            protocol == "_shunt" and dns_shunt == "dnsmasq" and opt_in == "1") else []
                        self.assertEqual(global_selection(protocol, dns_shunt, opt_in), expected)


if __name__ == "__main__":
    unittest.main()
