# TESTING

## Overview
This document defines the testing structure, frameworks, and patterns observed in the `openwrt-passwall` codebase.

## Frameworks & Structure
- Currently, **there are no apparent automated CI unit testing or integration testing frameworks** implemented strictly within the repository (e.g., no `busted` tests for parsing logic, or `shunit2` for script testing).
- Testing is traditionally expected to be manual compilation in an OpenWrt SDK or Buildroot, followed by flashing to a hardware router/virtual machine and visually/functionally evaluating network flow metrics and log emissions.
- Changes made to the LuCI interface generally require a local OpenWrt environment to evaluate UI rendering properly.

## Local Configuration Mocking
- Given the system relies on standard OpenWrt interfaces (`ip`, `uci`, `iptables`, `dnsmasq`), functional behaviors are typically "mocked" by developers adjusting UCI configs manually.
- The `/etc/config/passwall` file serves as the main test bench parameter set.

## Code Coverage
- No explicit automated coverage tracking exists. Code changes are verified against major functionality blocks (e.g., ensuring DNS does not leak, TCP intercepts route through Xray properly). 
- Pull requests are largely tested functionally by community members before merging.

## Best Practices (Future Considerations)
- For testing shell commands, a dockerized snapshot of OpenWrt x86_64 would enable running the init scripts out of the box and parsing the generated nat-chains.
- Utilizing `busted` for Lua components could provide a significant improvement to CI stability.
- Add GitHub Actions tests to verify Makefile compilation targets without needing full device flash processes.
