# CONVENTIONS

## Overview
This document analyzes the coding conventions, patterns, and style of the `openwrt-passwall` project.

## Code Style
- **Lua (LuCI)**: Follows the LuCI CBI (Configuration Binding Interface) format which builds forms dynamically by subclassing `Map`, `Section`, `Value`, `ListValue`, etc. Naming conventions use `m`, `s`, `o` for Maps, Sections, and Options. Formatting is relatively standard for OpenWrt modules.
- **Shell Scripts**: The project relies heavily on ash/bash syntax. Variables are often uppercase for globals, maintaining standard openwrt POSIX-compliant scripting conventions for widespread platform compatibility (avoiding advanced bash-only features when possible so smaller runtimes like ash/busybox are compatible). Local variables should be declared as `local var="value"`.
- **Makefile**: Defines build targets and configure arguments following the standard `include $(TOPDIR)/rules.mk` and `include $(TOPDIR)/feeds/luci/luci.mk` patterns. Heavily utilizes OpenWrt `define Package/...` syntax. Tabs are strictly used for indentation in Makefile rules.

## Patterns
- **Transparent Proxy Toggle**: There is a dynamic dependency injection model in the `Makefile` (e.g. `CONFIG_PACKAGE_luci-app-passwall_INCLUDE_Xray`). This conditionally pulls in required proxy binaries only when compiled into the firmware, keeping image size down.
- **Rules Definitions**: The routing logic dynamically writes rules out to system config via variables mapped in `/usr/share/passwall/rules/`. IP/Domain ranges are read from text files inside these directories and fed directly into `ipset` arrays for massive O(1) matching against the proxy filter lists.
- **Component Modularity**: Views are strictly separated from models, but models often contain inline logic for data validation before pushing to UCI configurations.

## Error Handling
- Being fundamentally a script-based system, most error handling revolves around checking if daemon process PIDs exist and standard OpenWrt `procd` validation (service respawns, instance definition failures).
- GUI validation logic exists within the Lua models to ensure IP addresses, hostnames, and TCP port ranges are correctly shaped before hitting UCI.
- Shell scripts use standard `$?` exit codes checking, but could benefit from more strict `set -e` blocks.
