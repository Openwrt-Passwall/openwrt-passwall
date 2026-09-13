#!/usr/bin/env python3
"""Small command-boundary fake for firewall generation/restore tests.

This stores rule lists, not a packet-filter or socket-matching implementation.
Unsupported commands fail instead of reaching host networking utilities.
"""

import json
import os
from pathlib import Path
import shlex
import sys


name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "uci":
    if args == ["-q", "get", "firewall.passwall.path"]:
        print(os.environ["TEST_INCLUDE"])
    sys.exit(0)
if name == "lsmod":
    print("ip6table_nat 1 0\nip6table_mangle 1 0")
    sys.exit(0)
if name == "ipset":
    if "-R" in args:
        sys.stdin.read()
    sys.exit(0)
if name == "ip":
    sys.exit(0)
if not name.startswith(("iptables", "ip6tables")):
    raise SystemExit("Unsupported mock command: " + name)

family = "6" if name.startswith("ip6tables") else "4"
path = Path(os.environ["TEST_STATE_" + family])
state = json.loads(path.read_text())
table = "filter"
if "-t" in args:
    index = args.index("-t")
    table = args[index + 1]
    del args[index:index + 2]
args = [arg for arg in args if arg != "-w"]


def apply_rule(table_name, tokens):
    operation, chain, *rule = tokens
    chains = state[table_name]
    if operation == "-N":
        if chain in chains:
            raise SystemExit("Chain already exists: " + chain)
        chains[chain] = []
    elif operation == "-A":
        chains[chain].append(rule)
    elif operation == "-I":
        index = int(rule.pop(0)) - 1 if rule[0].isdigit() else 0
        chains[chain].insert(index, rule)
    else:
        raise SystemExit("Unsupported rule operation: " + operation)


if name.endswith("-save"):
    for table_name in [table] if "-t" in sys.argv else state:
        print("*" + table_name)
        for chain in state[table_name]:
            print(":" + chain + " - [0:0]")
        for chain, rules in state[table_name].items():
            for rule in rules:
                print(shlex.join(["-A", chain] + rule))
        print("COMMIT")
elif name.endswith("-restore"):
    text = sys.stdin.read()
    with Path(os.environ["TEST_RESTORES"]).open("a") as stream:
        stream.write(json.dumps({"family": family, "args": args, "input": text}) + "\n")
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            if "-n" not in args:
                state[table] = {}
        elif line.startswith(":"):
            state[table][line.split()[0][1:]] = []
        elif line != "COMMIT":
            apply_rule(table, shlex.split(line))
    path.write_text(json.dumps(state))
elif "-L" in args:
    chain = args[args.index("-L") + 1]
    for index, rule in enumerate(state[table][chain], 1):
        print(index, shlex.join(rule))
else:
    apply_rule(table, args)
    path.write_text(json.dumps(state))
