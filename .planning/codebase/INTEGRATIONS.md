# INTEGRATIONS

## Overview
This document lists the external services, protocols, APIs, and systems integrated within the `openwrt-passwall` codebase.

## Proxy Protocols & Core Engines
The codebase serves as a front-end unified wrapper over several popular proxy routing protocols:
- **Shadowsocks Ecosystem**: Interacts with `shadowsocks-libev`, `shadowsocks-rust`, and `shadowsocksr-libev` for standard SS/SSR proxying.
- **Xray & V2Ray**: Supports Xray core and V2ray plugins, managing Xray's JSON configurations and managing V2ray geo-data assets (e.g., `v2ray-geodata`).
- **Sing-Box**: Integrates with Sing-Box, adapting to its rule-set requirements (e.g., using `geoview` to generate rule sets).
- **Other Protocols**: Hysteria, NaiveProxy, Trojan-Plus, Haproxy, Shadow-TLS, and tuic-client are directly supported through plugin configurations.

## System Interfaces
- **iptables / nftables / tproxy**: Low-level integration with Linux kernel networking to implement transparent proxy capabilities. 
- **dnsmasq / chinadns-ng / dns2socks**: DNS layer integration to prevent DNS poisoning and intelligently route internal vs. external domain queries. 
- **UCI (Unified Configuration Interface)**: The core system API OpenWrt uses. `passwall` bridges user interactions from LuCI directly into UCI states in `/etc/config/passwall`.

## Content Distro & Feeds
- **GitHub**: Source code feeds integration with OpenWrt package feeds (`src-git passwall_packages https://github.com/Openwrt-Passwall/openwrt-passwall-packages.git;main`).
- **SourceForge**: Mentioned externally for package binary fetching (relevant to connectivity issues).
