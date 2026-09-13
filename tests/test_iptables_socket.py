#!/usr/bin/env python3
"""Exercise real IPv4/IPv6 firewall generation and reload with no root/network."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCRIPT = FIXTURES.parents[1] / "luci-app-passwall/root/usr/share/passwall/iptables.sh"
DIVERT_RULE = ["-p", "tcp", "-m", "socket", "--transparent", "-j", "PSW_DIVERT"]


class FirewallFixture:
    def __init__(self, proxy_way="redirect"):
        sed = shutil.which("gsed") or shutil.which("sed")
        if not sed:
            raise RuntimeError("Missing test dependency: GNU or BusyBox sed")
        probe = subprocess.run([sed, r"s/^\(a\|b\)$/ok/"], input="a\n",
                               capture_output=True, text=True, check=True)
        if probe.stdout != "ok\n":
            raise RuntimeError("These OpenWrt scripts require GNU or BusyBox sed; use gsed on macOS")
        self.directory = tempfile.TemporaryDirectory(prefix="passwall-socket-")
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.rules = self.root / "rules"
        self.rules.mkdir()
        for name in ("chnroute", "chnroute6"):
            (self.rules / name).touch()
        # A closed PATH prevents accidental execution of real networking tools.
        for name in ("awk", "cat", "cut", "dirname", "grep", "head", "ls", "sed", "seq", "sort", "tr"):
            command = sed if name == "sed" else shutil.which(name)
            if not command:
                raise RuntimeError("Missing test dependency: " + name)
            (self.bin / name).symlink_to(command)
        (self.bin / "python3").symlink_to(sys.executable)
        mock = self.bin / "mock"
        shutil.copyfile(FIXTURES / "iptables-socket-mock.py", mock)
        mock.chmod(0o755)
        for name in ("uci", "lsmod", "ipset", "ip"):
            (self.bin / name).symlink_to(mock)
        for name in ("iptables-legacy", "ip6tables-legacy"):
            for suffix in ("", "-save", "-restore"):
                (self.bin / (name + suffix)).symlink_to(mock)
        self.driver = self.root / "driver.sh"
        shutil.copyfile(FIXTURES / "iptables-socket-driver.sh", self.driver)
        self.driver.chmod(0o755)
        self.env = {
            "PATH": str(self.bin), "LC_ALL": "C", "TEST_DRIVER": str(self.driver),
            "TEST_IPTABLES_SCRIPT": str(SCRIPT), "TEST_RULES": str(self.rules),
            "TEST_INCLUDE": str(self.root / "firewall.include"), "TEST_TMP": str(self.root),
            "TEST_RESTORES": str(self.root / "restores.jsonl"),
            "TEST_PROXY_WAY": proxy_way,
        }
        for family in ("4", "6"):
            path = self.root / ("state" + family + ".json")
            self.env["TEST_STATE_" + family] = str(path)
            state = {table: {chain: [] for chain in ("PREROUTING", "OUTPUT", "FORWARD")}
                     for table in ("filter", "nat", "mangle")}
            state["mangle"]["PREROUTING"] = [["-j", "mwan3"]]
            state["mangle"]["mwan3"] = []
            path.write_text(json.dumps(state))

    def run(self, action):
        process = subprocess.run(["/bin/sh", str(self.driver), action], env=self.env,
                                 capture_output=True, text=True, timeout=30)
        if process.returncode or process.stderr:
            raise AssertionError(process.stdout + process.stderr)

    def state(self, family):
        return json.loads(Path(self.env["TEST_STATE_" + family]).read_text())

    def close(self):
        self.directory.cleanup()


class SocketRulesTest(unittest.TestCase):
    def test_start_matches_only_transparent_tcp_sockets_in_both_families(self):
        for proxy_way in ("redirect", "tproxy"):
            fixture = FirewallFixture(proxy_way)
            self.addCleanup(fixture.close)
            fixture.run("start")
            for family in ("4", "6"):
                with self.subTest(proxy_way=proxy_way, family=family):
                    rules = fixture.state(family)["mangle"]["PREROUTING"]
                    divert = [rule for rule in rules if "PSW_DIVERT" in rule]
                    self.assertEqual(divert, [DIVERT_RULE])

    def test_include_does_not_export_manually_reinserted_socket_hooks(self):
        fixture = FirewallFixture()
        self.addCleanup(fixture.close)
        fixture.run("start")
        # Also feed the exporter legacy save output, as during an upgrade.
        for name in ("iptables-legacy", "ip6tables-legacy"):
            subprocess.run([str(fixture.bin / name), "-t", "mangle", "-A", "PREROUTING",
                            "-p", "tcp", "-m", "socket", "-j", "PSW_DIVERT"],
                           env=fixture.env, check=True, capture_output=True, text=True)
        fixture.run("include")
        include = Path(fixture.env["TEST_INCLUDE"]).read_text()
        exported_hooks = [line.strip() for line in include.splitlines()
                          if line.lstrip().startswith(("-A ", "-I ")) and "-j PSW_DIVERT" in line]
        self.assertEqual(exported_hooks, [])
        self.assertEqual(include.count(":PSW_DIVERT - [0:0]"), 2)

    def test_reload_keeps_one_transparent_hook_before_passwall_in_both_families(self):
        fixture = FirewallFixture()
        self.addCleanup(fixture.close)
        fixture.run("start")
        before = {family: fixture.state(family) for family in ("4", "6")}
        for reload_number in (1, 2):
            fixture.run("reload")
            for family in ("4", "6"):
                with self.subTest(reload=reload_number, family=family):
                    state = fixture.state(family)
                    self.assertEqual(state["mangle"]["PREROUTING"], [
                        DIVERT_RULE, ["-j", "PSW"], ["-j", "mwan3"],
                    ])
                    # Keep the mark/accept chain and both DNS transports intact.
                    self.assertEqual(state["mangle"]["PSW_DIVERT"],
                                     before[family]["mangle"]["PSW_DIVERT"])
                    dns = state["nat"]["PSW_DNS"]
                    self.assertEqual(dns, before[family]["nat"]["PSW_DNS"])
                    for protocol in ("tcp", "udp"):
                        self.assertIn(["-p", protocol, "--dport", "53", "-j", "REDIRECT",
                                       "--to-ports", "1053"], [rule[-8:] for rule in dns])


if __name__ == "__main__":
    unittest.main()
