# STACK

## Overview
This document maps the technology stack for the openwrt-passwall codebase.

## Languages
- **Lua**: Used extensively for the LuCI web interface plugin. Found in `luci-app-passwall/luasrc/`.
- **Shell (Bash/Ash)**: Used for service initialization, iptables/nftables scripts, and build processes. Located in `luci-app-passwall/root/etc/init.d/` and `luci-app-passwall/root/usr/share/passwall/`.
- **Make**: Used for OpenWrt buildroot package generation, found in `luci-app-passwall/Makefile`.
- **HTML/JS** (Potentially): As part of LuCI views if not strictly Lua-based templates. Used in `luci-app-passwall/luasrc/view/`.

## Frameworks & Runtimes
- **LuCI**: The OpenWrt web UI framework utilizing the MVC structure.
- **OpenWrt Buildroot**: The environment used to compile this package.

## Core Packages & Dependencies
The package relies on several ecosystem tools specific to OpenWrt and proxy routing:
- iptables / nftables (for transparent proxying)
- ipset (IP tracking)
- dnsmasq-full (DNS routing and management)
- curl, chinadns-ng, dns2socks
- Various proxy clients specified as optional/include flags: config flags for Xray, Sing-Box, Shadowsocks (libev, rust), ShadowsocksR, Trojan-Plus, Hysteria, NaiveProxy, tuic-client.

## Configuration Formats
- UCI (Unified Configuration Interface): OpenWrt's standard configuration format. Found in `/etc/config/passwall` and `/etc/config/passwall_server`.
- Makefile variables configurations (e.g., `PKG_NAME:=luci-app-passwall`).
