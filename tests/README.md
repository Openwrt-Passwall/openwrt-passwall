# Firewall rule regression tests

Run from the repository root:

```sh
python3 tests/test_iptables_socket.py -v
```

Requirements: Python 3.8+, `/bin/sh`, standard shell utilities, and GNU or
BusyBox-compatible `sed`. On macOS, `gsed` is selected if available; BSD sed
cannot interpret the existing OpenWrt script's basic-regex alternation.
These files are development tests and are not installed in the LuCI package.

The socket tests execute the real `start`, `gen_include`, generated firewall
include, and insertion helpers. They check:

- IPv4/IPv6 transparent TCP DIVERT hooks in redirect and tproxy modes;
- export filtering of both legacy and option-bearing socket hooks;
- two successive reloads with exactly one DIVERT hook before the PSW/mwan3
  jumps, retaining DIVERT mark/accept rules and TCP/UDP DNS redirection.

Safety and scope: a private temporary directory and closed PATH supply fake
iptables/ip6tables, save/restore, UCI, ipset, module and routing commands.
The `/proc` sysctl helper is neutralized; synthetic configuration replaces
device discovery. No rule-generation/export/insertion logic is replaced.
The fake records rule lists and replays restore input without deduplicating
rules. It does not implement kernel socket matching or validate the complete
iptables grammar. These are rule-output regressions, not live packet/DNS
integration tests; they require neither root nor network access.
