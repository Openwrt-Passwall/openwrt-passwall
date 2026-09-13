# Local DNS passthrough regression

Run from the repository root with Lua 5.1:

```sh
lua tests/test_xray_local_dns.lua
```

The test loads the real Xray `gen_config(var)` in a fresh environment for each
case. Synthetic UCI records and the LuCI API boundary replace router services;
JSON serialization returns the generated table for comparison. Shell writes,
service calls and filesystem operations fail the test. No DNS queries, proxy
credentials, OpenWrt image or root privileges are required.

The initial passthrough assertion fails on the unpatched generator because the
DNS outbound still targets a public resolver rather than the configured local
endpoint. The suite checks complete generated configurations, ordered DNS
policy, unchanged node DNS, default-off compatibility and rejected conflicts.
This is a configuration-generation test, not a Linux packet-path or Xray wire
protocol integration test.

## Opt-in behavior

The **Local DNS passthrough** option is for the global Xray shunt node with
Dnsmasq. It is disabled by default and does not propagate to independent ACL,
SOCKS or other-core instances. For example, both direct and remote DNS may be
configured as TCP `127.0.0.1:5533`, with a separately managed local resolver
already listening there. The implementation does not require MosDNS or fix the
upstream port to a particular value.

Requirements:

- Xray 26.4.25 or newer, no FakeDNS, and no default blackhole.
- Both DNS endpoints are the same TCP loopback address and port. Supported
  loopback literals are `127.0.0.1` and `::1` (including bracketed/expanded IPv6).
- Disable **Filter Proxy Host IPv6** and leave **EDNS Client Subnet** empty.
  Both generated DNS query strategies must be `UseIP`; filtering and caching
  for client queries are the local resolver's responsibility.
- Do not use port 53, the Xray DNS listener port, or another DNS frontend that
  forwards back to PassWall. The generator rejects the first two direct loops;
  it cannot inspect an external resolver's configuration to detect indirect loops.

An unsupported explicit configuration fails generation instead of silently
falling back to the public DNS outbound. Disabling the option retains existing
generation, including FakeDNS and address-family selection.

When enabled, ordinary A/AAAA queries use `direct` instead of being reconstructed
by Xray's built-in DNS. Other record types use the same configured TCP resolver.
Existing `domain`, `qType`, rule order and explicit `return` policies are retained;
this is not an instruction to bypass blocking rules. Xray's internal/node DNS,
hosts and normal traffic routing are unchanged. The frontend dnsmasq still
handles local names and domain-to-IP set population.
