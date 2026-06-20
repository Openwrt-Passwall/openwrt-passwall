# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2025 xiaorouji
# Copyright (C) 2026 Openwrt-Passwall Organization
#
# This is free software, licensed under the GNU General Public License v3.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall
PKG_VERSION:=26.6.2
PKG_RELEASE:=1
PKG_PO_VERSION:=$(PKG_VERSION)

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Geoview \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Haproxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Simple_Obfs \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_SingBox \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Geodata \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Plugin \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Xray \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Xray_Plugin

LUCI_TITLE:=LuCI support for PassWall
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+coreutils +coreutils-base64 +coreutils-nohup +coreutils-timeout +curl \
	+chinadns-ng +dns2socks +dnsmasq-full +ip-full \
	+libuci-lua +lua +luci-compat +luci-lib-jsonc \
	+microsocks +resolveip +tcping +lyaml

define Package/$(PKG_NAME)/config
menu "Configuration"
	depends on PACKAGE_$(PKG_NAME)

config PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy
	bool "Iptables Transparent Proxy"
	select PACKAGE_ipset
	select PACKAGE_ipt2socks
	select PACKAGE_iptables
	select PACKAGE_iptables-zz-legacy
	select PACKAGE_iptables-mod-conntrack-extra
	select PACKAGE_iptables-mod-iprange
	select PACKAGE_iptables-mod-socket
	select PACKAGE_iptables-mod-tproxy
	select PACKAGE_kmod-ipt-nat
	default y if ! PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy
	bool "Nftables Transparent Proxy"
	select PACKAGE_ipt2socks
	select PACKAGE_nftables
	select PACKAGE_kmod-nft-socket
	select PACKAGE_kmod-nft-tproxy
	select PACKAGE_kmod-nft-nat
	default y if PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_INCLUDE_Geoview
	bool "Include Geoview"
	select PACKAGE_geoview
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Haproxy
	bool "Include Haproxy"
	select PACKAGE_haproxy
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria
	bool "Include Hysteria"
	select PACKAGE_hysteria
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy
	bool "Include NaiveProxy"
	depends on !(arc||armeb||loongarch64||mips||mips64||powerpc||TARGET_gemini)
	select PACKAGE_naiveproxy
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
	bool "Include Shadowsocks Rust Client"
	depends on !i386
	select PACKAGE_shadowsocks-rust-sslocal
	default y if aarch64||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server
	bool "Include Shadowsocks Rust Server"
	depends on !i386
	select PACKAGE_shadowsocks-rust-ssserver
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client
	bool "Include ShadowsocksR Libev Client"
	select PACKAGE_shadowsocksr-libev-ssr-local
	select PACKAGE_shadowsocksr-libev-ssr-redir
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
	bool "Include ShadowsocksR Libev Server"
	select PACKAGE_shadowsocksr-libev-ssr-server
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS
	bool "Include Shadow-TLS"
	select PACKAGE_shadow-tls
	depends on aarch64||arm||x86_64
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Simple_Obfs
	bool "Include Simple-Obfs (Shadowsocks Plugin)"
	select PACKAGE_simple-obfs-client
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_SingBox
	bool "Include Sing-Box"
	select PACKAGE_sing-box
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Geodata
	bool "Include V2ray_Geodata"
	select PACKAGE_v2ray-geoip
	select PACKAGE_v2ray-geosite
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Plugin
	bool "Include V2ray-Plugin (Shadowsocks Plugin)"
	select PACKAGE_v2ray-plugin
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Xray
	bool "Include Xray"
	select PACKAGE_xray-core
	select PACKAGE_unzip
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Xray_Plugin
	bool "Include Xray-Plugin (Shadowsocks Plugin)"
	select PACKAGE_xray-plugin
	default n

endmenu
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/passwall
/etc/config/passwall_server
/usr/share/passwall/rules/direct_host
/usr/share/passwall/rules/direct_ip
/usr/share/passwall/rules/proxy_host
/usr/share/passwall/rules/proxy_ip
/usr/share/passwall/rules/block_host
/usr/share/passwall/rules/block_ip
/usr/share/passwall/rules/lanlist_ipv4
/usr/share/passwall/rules/lanlist_ipv6
/usr/share/passwall/rules/domains_excluded
endef

define Package/$(PKG_NAME)/postrm
#!/bin/sh
rm -f $${IPKG_INSTROOT}/usr/share/passwall/rules/*.nft
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
