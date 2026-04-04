# ARCHITECTURE

## Overview
This document outlines the architecture and data flow for the openwrt-passwall program, which acts as an advanced proxy routing orchestrator on OpenWrt.

## Pattern & Layers
- **Presentation Layer (LuCI)**: Handled by Lua modules situated in `luci-app-passwall/luasrc/`. It adheres to OpenWrt's CBI (Configuration Binding Interface) to map HTML form abstractions to CLI UCI commands.
- **Service Layer (Shell)**: Upon applying settings via LuCI, OpenWrt reloads the service via `luci-app-passwall/root/etc/init.d/passwall`. This layer reads UCI configurations and builds out dynamic rulesets.
- **Network Layer**: Utilizing iptables/nftables and routing policies to intercept internet-bound traffic, categorize it (e.g., LAN, WAN, IP proxies), and reroute correctly through proxy binaries.

## Data Flow
1. **User Input**: A user modifies a proxy subscription or rule on the router's web interface (served by LuCI).
2. **UCI Commit**: Changes are committed to `/etc/config/passwall`.
3. **Init Script Trigger**: The system triggers `/etc/init.d/passwall reload`.
4. **Configuration Generation**: Shell scripts parse the new UCI values and generate the native JSON/YAML/INI configs for the respective engines (Xray, Sing-Box, Shadowsocks).
5. **Rule Loading**: Iptables chains or nftables rules are dynamically rewritten to enforce the proxy rules on incoming TCP/UDP connections.

## Abstractions & Entry Points
- Web Entry: `luci-app-passwall/luasrc/controller/passwall.lua`
- System Service: `/etc/init.d/passwall`
- Data Models: `luci-app-passwall/luasrc/model/cbi/passwall/`
- Rule Generation: Located within `/usr/share/passwall/` scripts.
