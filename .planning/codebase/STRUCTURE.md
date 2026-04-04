# STRUCTURE

## Overview
This document outlines the directory layout and modularization strategy for openwrt-passwall.

## Root Level
- `luci-app-passwall/`: Contains the actual source code for the LuCI interface and system components.
- `README.md`: Basic instructions on compiling and integrating the core passwall-packages and this luci plugin.
- `Makefile`: Used by the OpenWrt Buildroot to compile the `luci-app-passwall` ipk file. Defines paths, permissions, and dependencies for iptables/nftables transparent proxy setups, plus dynamic boolean flags to statically bundle various VPN clients.

## luci-app-passwall/
- `Makefile`: Specifies dependencies and configuration logic for OpenWrt build wrapper.
- `luasrc/`: Provides the OpenWrt web interface logic.
  - `controller/`: Defines the web routes/URLs for Passwall.
  - `model/`: The logic for configuring proxy nodes, balancing, rule-lists through LuCI CBI.
  - `view/`: The layout and templating logic associated with UI components unique to Passwall.
- `root/`: Represents the Unix filesystem layout mapping that will be merged into the router's OS root (`/`).
  - `etc/config/`: Initial default configurations representing the package state (`passwall` and `passwall_server`).
  - `etc/init.d/`: Service initialization script (`passwall`), defining startup sequencing.
  - `usr/share/passwall/`: Deep internal implementation of traffic control, iptables definitions, updating rules, script templates, and direct host IPs.
- `htdocs/`: Assets for the web interfaces (CSS, JS, icons).
- `po/`: Gettext catalogs containing all standard application localization files (e.g., Chinese, English).
