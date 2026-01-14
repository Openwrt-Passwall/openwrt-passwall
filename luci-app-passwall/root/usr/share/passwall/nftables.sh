#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh
NFTABLE_NAME="inet passwall"
NFTSET_LOCAL="passwall_local"
NFTSET_WAN="passwall_wan"
NFTSET_LAN="passwall_lan"
NFTSET_VPS="passwall_vps"
NFTSET_SHUNT="passwall_shunt"
NFTSET_GFW="passwall_gfw"
NFTSET_CHN="passwall_chn"
NFTSET_BLACK="passwall_black"
NFTSET_WHITE="passwall_white"
NFTSET_BLOCK="passwall_block"

NFTSET_LOCAL6="passwall_local6"
NFTSET_WAN6="passwall_wan6"
NFTSET_LAN6="passwall_lan6"
NFTSET_VPS6="passwall_vps6"
NFTSET_SHUNT6="passwall_shunt6"
NFTSET_GFW6="passwall_gfw6"
NFTSET_CHN6="passwall_chn6"
NFTSET_BLACK6="passwall_black6"
NFTSET_WHITE6="passwall_white6"
NFTSET_BLOCK6="passwall_block6"

FORCE_INDEX=0

USE_SHUNT_TCP=0
USE_SHUNT_UDP=0

. /lib/functions/network.sh

FWI=$(uci -q get firewall.passwall.path 2>/dev/null)
FAKE_IP="198.18.0.0/15"
FAKE_IP_6="fc00::/18"

factor() {
	local ports="$1"
	if [ -z "$1" ] || [ -z "$2" ] || [ "$ports" = "1:65535" ]; then
		echo ""
	# acl mac address
	elif echo "$1" | grep -qE '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}'; then
		echo "$2 {$1}"
	else
		ports=$(echo "$ports" | tr -d ' ' | sed 's/:/-/g' | tr ',' '\n' | awk '!a[$0]++' | grep -v '^$')
		[ -z "$ports" ] && { echo ""; return; }
		if echo "$ports" | grep -q '^1-65535$'; then
			echo ""
			return
		fi
		local port
		local port_list=""
		for port in $ports; do
			port_list="${port_list},$port"
		done
		port_list="${port_list#,}"
		echo "$2 {$port_list}"
	fi
}

insert_rule_before() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

insert_rule_after() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "索引列举方式不正确（nftables），终止执行！"
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="counter redirect"
	[ -n "$1" ] && {
		local s="$s to :$1"
		[ "$2" == "MARK" ] && s="counter meta mark set $1"
		[ "$2" == "TPROXY" ] && {
			s="counter meta mark 1 tproxy to :$1"
		}
		[ "$2" == "TPROXY4" ] && {
			s="counter meta mark 1 tproxy ip to :$1"
		}
		[ "$2" == "TPROXY6" ] && {
			s="counter meta mark 1 tproxy ip6 to :$1"
		}

	}
	echo $s
}

destroy_nftset() {
	for i in "$@"; do
		nft flush set $NFTABLE_NAME $i 2>/dev/null
		nft delete set $NFTABLE_NAME $i 2>/dev/null
	done
}

gen_nft_tables() {
	if ! nft list table "$NFTABLE_NAME" >/dev/null 2>&1; then
		nft -f - <<-EOF
		table $NFTABLE_NAME {
			chain dstnat {
				type nat hook prerouting priority dstnat - 1; policy accept;
			}
			chain mangle_prerouting {
				type filter hook prerouting priority mangle - 1; policy accept;
			}
			chain mangle_output {
				type route hook output priority mangle - 1; policy accept;
			}
			chain nat_output {
				type nat hook output priority -1; policy accept;
			}
		}
		EOF
	fi
}

insert_nftset() {
	local nftset_name="${1}"; shift
	local timeout_argument="${1}"; shift
	local default_timeout="365d"
	local suffix=""

	if [ -n "$nftset_name" ] && { [ $# -gt 0 ] || [ ! -t 0 ]; }; then
		case "$timeout_argument" in
			"-1") suffix="" ;;
			 "0") suffix=" timeout $default_timeout" ;;
			   *) suffix=" timeout $timeout_argument" ;;
		esac
		{
		if [ $# -gt 0 ]; then
			echo "add element $NFTABLE_NAME $nftset_name { "
			printf "%s\n" "$@" | awk -v s="$suffix" '{if (NR > 1) printf ",\n";printf "%s%s", $0, s}'
			echo " }"
		else
			local first_line
			if IFS= read -r first_line; then
				echo "add element $NFTABLE_NAME $nftset_name { "
				{ echo "$first_line"; cat; } | awk -v s="$suffix" '{if (NR > 1) printf ",\n";printf "%s%s", $0, s}'
				echo " }"
			fi
		fi
		} | nft -f -
	fi
}

gen_nftset() {
	local nftset_name="${1}"; shift
	local ip_type="${1}"; shift
	#  0 - don't set defalut timeout
	local timeout_argument_set="${1}"; shift
	#  0 - don't let element timeout(365 days) when set's timeout parameters be seted
	# -1 - follow the set's timeout parameters
	local timeout_argument_element="${1}"; shift
	local gc_interval_time="1h"

	if ! nft list set $NFTABLE_NAME $nftset_name >/dev/null 2>&1; then
		if [ "$timeout_argument_set" == "0" ]; then
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; auto-merge; }"
		else
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; timeout $timeout_argument_set; gc-interval $gc_interval_time; auto-merge; }"
		fi
	fi
	[ $# -gt 0 ] || [ ! -t 0 ] && insert_nftset "$nftset_name" "$timeout_argument_element" "$@"
}

get_jump_ipt() {
	case "$1" in
	direct)
		echo "mark != 1 counter return"
		;;
	proxy)
		if [ -n "$2" ] && [ -n "$(echo $2 | grep "^counter")" ]; then
			echo "$2"
		else
			echo "$(REDIRECT $2 $3)"
		fi
		;;
	esac
}

gen_lanlist() {
	cat $RULES_PATH/lanlist_ipv4 | tr -s '\n' | grep -v "^#"
}

gen_lanlist_6() {
	cat $RULES_PATH/lanlist_ipv6 | tr -s '\n' | grep -v "^#"
}

get_wan_ips() {
	local family="$1"
	local NET_ADDR
	local iface
	local INTERFACES=$(ubus call network.interface dump | jsonfilter -e '@.interface[@.route[0]].interface')
	for iface in $INTERFACES; do
		local addr
		if [ "$family" = "ip6" ]; then
			network_get_ipaddr6 addr "$iface"
			case "$addr" in
				""|fe80*) continue ;;
			esac
		else
			network_get_ipaddr addr "$iface"
			case "$addr" in
				""|"0.0.0.0") continue ;;
			esac
		fi

		case " $NET_ADDR " in
			*" $addr "*) ;;
			*) NET_ADDR="${NET_ADDR:+$NET_ADDR }$addr" ;;
		esac
	done
	echo "$NET_ADDR"
}

load_acl() {
	([ "$ENABLED_ACLS" == 1 ] || ([ "$ENABLED_DEFAULT_ACL" == 1 ] && [ "$CLIENT_PROXY" == 1 ])) && echolog "  - 访问控制："
	[ "$ENABLED_ACLS" == 1 ] && {
		acl_app
		for sid in $(ls -F ${TMP_ACL_PATH} | grep '/$' | awk -F '/' '{print $1}' | grep -v 'default'); do
			eval $(uci -q show "${CONFIG}.${sid}" | cut -d'.' -sf 3-)

			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			use_global_config=${use_global_config:-0}
			tcp_proxy_drop_ports=${tcp_proxy_drop_ports:-default}
			udp_proxy_drop_ports=${udp_proxy_drop_ports:-default}
			tcp_redir_ports=${tcp_redir_ports:-default}
			udp_redir_ports=${udp_redir_ports:-default}
			use_direct_list=${use_direct_list:-1}
			use_proxy_list=${use_proxy_list:-1}
			use_block_list=${use_block_list:-1}
			use_gfw_list=${use_gfw_list:-1}
			chn_list=${chn_list:-direct}
			tcp_proxy_mode=${tcp_proxy_mode:-proxy}
			udp_proxy_mode=${udp_proxy_mode:-proxy}
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_proxy_drop_ports" = "default" ] && tcp_proxy_drop_ports=$TCP_PROXY_DROP_PORTS
			[ "$udp_proxy_drop_ports" = "default" ] && udp_proxy_drop_ports=$UDP_PROXY_DROP_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS

			[ -n "$(get_cache_var "ACL_${sid}_tcp_node")" ] && tcp_node=$(get_cache_var "ACL_${sid}_tcp_node")
			[ -n "$(get_cache_var "ACL_${sid}_tcp_redir_port")" ] && tcp_port=$(get_cache_var "ACL_${sid}_tcp_redir_port")
			[ -n "$(get_cache_var "ACL_${sid}_udp_node")" ] && udp_node=$(get_cache_var "ACL_${sid}_udp_node")
			[ -n "$(get_cache_var "ACL_${sid}_udp_redir_port")" ] && udp_port=$(get_cache_var "ACL_${sid}_udp_redir_port")
			[ -n "$(get_cache_var "ACL_${sid}_dns_port")" ] && dns_redirect_port=$(get_cache_var "ACL_${sid}_dns_port")
			[ -n "$tcp_node" ] && {
				if is_socks_wrap "$tcp_node"; then
					tcp_node_remark="Socks 配置($(config_n_get ${tcp_node#Socks_} port) 端口)"
				else
					tcp_node_remark=$(config_n_get $tcp_node remarks)
				fi
			}
			[ -n "$udp_node" ] && {
				if is_socks_wrap "$udp_node"; then
					udp_node_remark="Socks 配置($(config_n_get ${udp_node#Socks_} port) 端口)"
				else
					udp_node_remark=$(config_n_get $udp_node remarks)
				fi
			}
			use_shunt_tcp=0
			use_shunt_udp=0
			[ -n "$tcp_node" ] && [ "$(config_n_get $tcp_node protocol)" = "_shunt" ] && use_shunt_tcp=1
			[ -n "$udp_node" ] && [ "$(config_n_get $udp_node protocol)" = "_shunt" ] && use_shunt_udp=1

			[ "${use_global_config}" = "1" ] && { 
				if is_socks_wrap "$TCP_NODE"; then
					tcp_node_remark="Socks 配置($(config_n_get ${TCP_NODE#Socks_} port) 端口)"
				else
					tcp_node_remark=$(config_n_get $TCP_NODE remarks)
				fi
				if is_socks_wrap "$UDP_NODE"; then
					udp_node_remark="Socks 配置($(config_n_get ${UDP_NODE#Socks_} port) 端口)"
				else
					udp_node_remark=$(config_n_get $UDP_NODE remarks)
				fi
				use_direct_list=${USE_DIRECT_LIST}
				use_proxy_list=${USE_PROXY_LIST}
				use_block_list=${USE_BLOCK_LIST}
				use_gfw_list=${USE_GFW_LIST}
				chn_list=${CHN_LIST}
				tcp_proxy_mode=${TCP_PROXY_MODE}
				udp_proxy_mode=${UDP_PROXY_MODE}
				use_shunt_tcp=${USE_SHUNT_TCP}
				use_shunt_udp=${USE_SHUNT_UDP}
				dns_redirect_port=${DNS_REDIRECT_PORT}
				black_set_name=${NFTSET_BLACK}
				black6_set_name=${NFTSET_BLACK6}
				gfw_set_name=${NFTSET_GFW}
				gfw6_set_name=${NFTSET_GFW6}
				shunt_set_name=${NFTSET_SHUNT}
				shunt6_set_name=${NFTSET_SHUNT6}
			}

			_acl_list=${TMP_ACL_PATH}/${sid}/source_list

			for i in $(cat $_acl_list); do
				local _ipt_source _ipv4
				local msg
				if [ -n "${interface}" ]; then
					. /lib/functions/network.sh
					local gateway device
					network_get_gateway gateway "${interface}"
					network_get_device device "${interface}"
					[ -z "${device}" ] && device="${interface}"
					_ipt_source="iifname ${device} "
					msg="源接口【${device}】，"
				else
					msg="源接口【所有】，"
				fi
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "${_ipt_source}ip saddr")
					msg="${msg}IP range【${_iprange}】，"
					_ipv4="1"
					unset _iprange
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					_ipt_source="${_ipt_source}ip saddr @${_ipset}"
					msg="${msg}NFTset【${_ipset}】，"
					unset _ipset
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "${_ipt_source}ip saddr")
					msg="${msg}IP【${_ip}】，"
					_ipv4="1"
					unset _ip
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "${_ipt_source}ether saddr")
					msg="${msg}MAC【${_mac}】，"
					unset _mac
				elif [ -n "$(echo ${i} | grep '^any')" ]; then
					msg="${msg}所有设备，"
				else
					continue
				fi
				msg="【$remarks】，${msg}"
				
				[ "$tcp_no_redir_ports" != "disable" ] && {
					if ! has_1_65535 "$tcp_no_redir_ports"; then
						nft "add rule $NFTABLE_NAME $nft_prerouting_chain ${_ipt_source} ip protocol tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ${_ipt_source} meta l4proto tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						echolog "     - ${msg}不代理 TCP 端口[${tcp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						unset tcp_port
						echolog "     - ${msg}不代理所有 TCP 端口"
					fi
				}
				
				[ "$udp_no_redir_ports" != "disable" ] && {
					if ! has_1_65535 "$udp_no_redir_ports"; then
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\""
						[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\"" 2>/dev/null
						echolog "     - ${msg}不代理 UDP 端口[${udp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						unset udp_port
						echolog "     - ${msg}不代理所有 UDP 端口"
					fi
				}

				local dns_redirect
				[ $(config_t_get global dns_redirect "1") = "1" ] && dns_redirect=53
				if ([ -n "$tcp_port" ] && [ -n "${tcp_proxy_mode}" ]) || ([ -n "$udp_port" ] && [ -n "${udp_proxy_mode}" ]); then
					[ "${use_proxy_list}" = "1" ] && {
						[ "${use_global_config}" = "0" ] && {
							black_set_name="passwall_${sid}_black"
							black6_set_name="passwall_${sid}_black6"
							gen_nftset $black_set_name ipv4_addr "2d" 0
							gen_nftset $black6_set_name ipv6_addr "2d" 0
						}
					}
					[ "${use_gfw_list}" = "1" ] && {
						[ "${use_global_config}" = "0" ] && {
							gfw_set_name="passwall_${sid}_gfw"
							gfw6_set_name="passwall_${sid}_gfw6"
							gen_nftset $gfw_set_name ipv4_addr "2d" 0
							gen_nftset $gfw6_set_name ipv6_addr "2d" 0
						}
					}
					[ "${use_shunt_tcp}" = "1" -o "${use_shunt_udp}" = "1" ] && {
						[ "${use_global_config}" = "0" ] && {
							shunt_set_name="passwall_${sid}_shunt"
							shunt6_set_name="passwall_${sid}_shunt6"
							gen_nftset $shunt_set_name ipv4_addr "2d" 0
							gen_nftset $shunt6_set_name ipv6_addr "2d" 0
						}
					}
					[ -n "${dns_redirect_port}" ] && dns_redirect=${dns_redirect_port}
				else
					[ -n "${DIRECT_DNSMASQ_PORT}" ] && dns_redirect=${DIRECT_DNSMASQ_PORT}
				fi
				if [ -n "${dns_redirect}" ]; then
					nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} udp dport 53 counter return comment \"$remarks\""
					[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} udp dport 53 counter return comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} tcp dport 53 counter return comment \"$remarks\""
					[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} tcp dport 53 counter return comment \"$remarks\""
					#nft "add rule $NFTABLE_NAME PSW_DNS ip protocol udp ${_ipt_source} udp dport 53 counter redirect to :${dns_redirect} comment \"$remarks\""
					#nft "add rule $NFTABLE_NAME PSW_DNS ip protocol tcp ${_ipt_source} tcp dport 53 counter redirect to :${dns_redirect} comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW_DNS meta l4proto udp ${_ipt_source} udp dport 53 counter redirect to :${dns_redirect} comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW_DNS meta l4proto tcp ${_ipt_source} tcp dport 53 counter redirect to :${dns_redirect} comment \"$remarks\""
					[ -z "$(get_cache_var "ACL_${sid}_tcp_default")" ] && echolog "     - ${msg}使用与全局配置不相同节点，已将DNS强制重定向到专用 DNS 服务器。"
				fi

				[ -n "$tcp_port" -o -n "$udp_port" ] && {
					[ "${use_block_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ${_ipt_source} ip daddr @$NFTSET_BLOCK counter drop comment \"$remarks\""
					[ "${use_block_list}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ${_ipt_source} ip daddr @$NFTSET_BLOCK counter drop comment \"$remarks\""
					[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ${_ipt_source} ip daddr @$NFTSET_WHITE counter return comment \"$remarks\""
					[ "${use_direct_list}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ${_ipt_source} ip daddr @$NFTSET_WHITE counter return comment \"$remarks\""
					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
						[ "${use_block_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ${_ipt_source} ip6 daddr @$NFTSET_BLOCK6 counter drop comment \"$remarks\""
						[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ${_ipt_source} ip6 daddr @$NFTSET_WHITE6 counter return comment \"$remarks\""
					}
					
					[ "$tcp_proxy_drop_ports" != "disable" ] && {
						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr $FAKE_IP_6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$black6_set_name counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$gfw6_set_name counter drop comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\"" 2>/dev/null
							[ "${use_shunt_tcp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$shunt6_set_name counter drop comment \"$remarks\"" 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") counter drop comment \"$remarks\"" 2>/dev/null
						}
						nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr $FAKE_IP counter drop comment \"$remarks\""
						[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$black_set_name counter drop comment \"$remarks\""
						[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$gfw_set_name counter drop comment \"$remarks\""
						[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\""
						[ "${use_shunt_tcp}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$shunt_set_name counter drop comment \"$remarks\""
						[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") counter drop comment \"$remarks\""
						echolog "     - ${msg}屏蔽代理 TCP 端口[${tcp_proxy_drop_ports}]"
					}
					
					[ "$udp_proxy_drop_ports" != "disable" ] && {
						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr $FAKE_IP_6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$black6_set_name counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$gfw6_set_name counter drop comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\"" 2>/dev/null
							[ "${use_shunt_udp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$shunt6_set_name counter drop comment \"$remarks\"" 2>/dev/null
							[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") counter drop comment \"$remarks\"" 2>/dev/null
						}
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr $FAKE_IP counter drop comment \"$remarks\"" 2>/dev/null
						[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$black_set_name counter drop comment \"$remarks\"" 2>/dev/null
						[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$gfw_set_name counter drop comment \"$remarks\"" 2>/dev/null
						[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\"" 2>/dev/null
						[ "${use_shunt_udp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$shunt_set_name counter drop comment \"$remarks\"" 2>/dev/null
						[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") counter drop comment \"$remarks\"" 2>/dev/null
						echolog "     - ${msg}屏蔽代理 UDP 端口[${udp_proxy_drop_ports}]"
					}
				}

				[ -n "$tcp_port" ] && {
					if [ -n "${tcp_proxy_mode}" ]; then
						msg2="${msg}使用 TCP 节点[$tcp_node_remark]"
						if [ -n "${is_tproxy}" ]; then
							msg2="${msg2}(TPROXY:${tcp_port})"
							nft_chain="PSW_MANGLE"
							nft_j="counter jump PSW_RULE"
						else
							msg2="${msg2}(REDIRECT:${tcp_port})"
							nft_chain="PSW_NAT"
							nft_j="$(REDIRECT $tcp_port)"
						fi
						
						[ "$accept_icmp" = "1" ] && {
							[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_WHITE counter return comment \"$remarks\""
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT) comment \"$remarks\""
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$black_set_name $(REDIRECT) comment \"$remarks\""
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$gfw_set_name $(REDIRECT) comment \"$remarks\""
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list}) comment \"$remarks\""
							[ "${use_shunt_tcp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$shunt_set_name $(REDIRECT) comment \"$remarks\""
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} $(REDIRECT) comment \"$remarks\""
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} return comment \"$remarks\""
						}

						[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_WHITE6 counter return comment \"$remarks\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr $FAKE_IP_6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$black6_set_name $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$gfw6_set_name $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list}) comment \"$remarks\"" 2>/dev/null
							[ "${use_shunt_tcp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$shunt6_set_name $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} return comment \"$remarks\"" 2>/dev/null
						}

						nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} ip daddr $FAKE_IP ${nft_j} comment \"$remarks\""
						[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$black_set_name ${nft_j} comment \"$remarks\" "
						[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$gfw_set_name ${nft_j} comment \"$remarks\" "
						[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "${nft_j}") comment \"$remarks\" "
						[ "${use_shunt_tcp}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$shunt_set_name ${nft_j} comment \"$remarks\""
						[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ${nft_j} comment \"$remarks\""
						[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY4) comment \"$remarks\""

						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW_RULE comment \"$remarks\""
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$black6_set_name counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$gfw6_set_name counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter jump PSW_RULE") comment \"$remarks\" "
							[ "${use_shunt_tcp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$shunt6_set_name counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY) comment \"$remarks\"" 2>/dev/null
						}
					else
						msg2="${msg}不代理 TCP"
					fi
					echolog "     - ${msg2}"
				}

				nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} counter return comment \"$remarks\""
				[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null

				[ -n "$udp_port" ] && {
					if [ -n "${udp_proxy_mode}" ]; then
						msg2="${msg}使用 UDP 节点[$udp_node_remark]"
						msg2="${msg2}(TPROXY:${udp_port})"

						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW_RULE comment \"$remarks\""
						[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$black_set_name counter jump PSW_RULE comment \"$remarks\""
						[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$gfw_set_name counter jump PSW_RULE comment \"$remarks\""
						[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "counter jump PSW_RULE") comment \"$remarks\""
						[ "${use_shunt_udp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$shunt_set_name counter jump PSW_RULE comment \"$remarks\""
						[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW_RULE comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(REDIRECT $udp_port TPROXY4) comment \"$remarks\""

						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW_RULE comment \"$remarks\""
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$black6_set_name counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$gfw6_set_name counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter jump PSW_RULE") comment \"$remarks\"" 2>/dev/null
							[ "${use_shunt_udp}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$shunt6_set_name counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(REDIRECT $udp_port TPROXY) comment \"$remarks\"" 2>/dev/null
						}
					else
						msg2="${msg}不代理 UDP"
					fi
					echolog "     - ${msg2}"
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} counter return comment \"$remarks\""
				[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null
				unset nft_chain nft_j _ipt_source msg msg2 _ipv4
			done
			unset enabled sid remarks sources use_global_config use_direct_list use_proxy_list use_block_list use_gfw_list chn_list tcp_proxy_mode udp_proxy_mode dns_redirect_port tcp_no_redir_ports udp_no_redir_ports tcp_proxy_drop_ports udp_proxy_drop_ports tcp_redir_ports udp_redir_ports tcp_node udp_node interface
			unset tcp_port udp_port tcp_node_remark udp_node_remark _acl_list use_shunt_tcp use_shunt_udp dns_redirect
		done
	}

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && [ "$CLIENT_PROXY" == 1 ] && {
		msg="【默认】，"
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"默认\""
			if ! has_1_65535 "$TCP_NO_REDIR_PORTS"; then
				echolog "     - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset TCP_PROXY_MODE
				echolog "     - ${msg}不代理所有 TCP 端口"
			fi
		}

		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 counter meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"默认\""
			if ! has_1_65535 "$UDP_NO_REDIR_PORTS"; then
				echolog "     - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				unset UDP_PROXY_MODE
				echolog "     - ${msg}不代理所有 UDP 端口"
			fi
		}

		local DNS_REDIRECT
		[ $(config_t_get global dns_redirect "1") = "1" ] && DNS_REDIRECT=53
		if ([ -n "$TCP_NODE" ] && [ -n "${TCP_PROXY_MODE}" ]) || ([ -n "$UDP_NODE" ] && [ -n "${UDP_PROXY_MODE}" ]); then
			[ -n "${DNS_REDIRECT_PORT}" ] && DNS_REDIRECT=${DNS_REDIRECT_PORT}
		else
			[ -n "${DIRECT_DNSMASQ_PORT}" ] && DNS_REDIRECT=${DIRECT_DNSMASQ_PORT}
		fi

		if [ -n "${DNS_REDIRECT}" ]; then
			nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp udp dport 53 counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp udp dport 53 counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp tcp dport 53 counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp tcp dport 53 counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_DNS ip protocol udp udp dport 53 counter redirect to :${DNS_REDIRECT} comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_DNS ip protocol tcp tcp dport 53 counter redirect to :${DNS_REDIRECT} comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_DNS meta l4proto udp udp dport 53 counter redirect to :${DNS_REDIRECT} comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_DNS meta l4proto tcp tcp dport 53 counter redirect to :${DNS_REDIRECT} comment \"默认\""
		fi

		[ -n "${TCP_PROXY_MODE}" -o -n "${UDP_PROXY_MODE}" ] && {
			[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_BLOCK counter drop comment \"默认\""
			[ "${USE_BLOCK_LIST}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_BLOCK counter drop comment \"默认\""
			[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_WHITE counter return comment \"默认\""
			[ "${USE_DIRECT_LIST}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_WHITE counter return comment \"默认\""
			[ "$PROXY_IPV6" == "1" ] && {
				[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_BLOCK6 counter drop comment \"默认\""
				[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_WHITE6 counter return comment \"默认\""
			}
			
			[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr $FAKE_IP_6 counter drop comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_BLACK6 counter drop comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_GFW6 counter drop comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
					[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_SHUNT6 counter drop comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop comment \"默认\""
				}

				nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr $FAKE_IP counter drop comment \"默认\""
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_BLACK counter drop comment \"默认\""
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_GFW counter drop comment \"默认\""
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
				[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_SHUNT counter drop comment \"默认\""
				[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop comment \"默认\""
				echolog "     - ${msg}屏蔽代理 TCP 端口[${TCP_PROXY_DROP_PORTS}]"
			}
			
			[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr $FAKE_IP_6 counter drop comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_BLACK6 counter drop comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_GFW6 counter drop comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
					[ "${USE_SHUNT_UDP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_SHUNT6 counter drop comment \"默认\""
					[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop comment \"默认\""
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr $FAKE_IP counter drop comment \"默认\""
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_BLACK counter drop comment \"默认\""
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_GFW counter drop comment \"默认\""
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
				[ "${USE_SHUNT_UDP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_SHUNT counter drop comment \"默认\""
				[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop comment \"默认\""
				echolog "     - ${msg}屏蔽代理 UDP 端口[${UDP_PROXY_DROP_PORTS}]"
			}
		}

		#  加载TCP默认代理模式
		if [ -n "${TCP_PROXY_MODE}" ]; then
			[ -n "$TCP_NODE" ] && {
				if is_socks_wrap "$TCP_NODE"; then
					msg2="${msg}使用 TCP 节点[Socks 配置($(config_n_get ${TCP_NODE#Socks_} port) 端口)]"
				else
					msg2="${msg}使用 TCP 节点[$(config_n_get $TCP_NODE remarks)]"
				fi
				if [ -n "${is_tproxy}" ]; then
					msg2="${msg2}(TPROXY:${TCP_REDIR_PORT})"
					nft_chain="PSW_MANGLE"
					nft_j="counter jump PSW_RULE"
				else
					msg2="${msg2}(REDIRECT:${TCP_REDIR_PORT})"
					nft_chain="PSW_NAT"
					nft_j="$(REDIRECT $TCP_REDIR_PORT)"
				fi
				
				[ "$accept_icmp" = "1" ] && {
					[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip daddr @$NFTSET_WHITE counter return comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr $FAKE_IP $(REDIRECT) comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_BLACK $(REDIRECT) comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_GFW $(REDIRECT) comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST}) comment \"默认\""
					[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_SHUNT $(REDIRECT) comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp $(REDIRECT) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp return comment \"默认\""
				}

				[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
					[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_WHITE6 counter return comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr $FAKE_IP_6 $(REDIRECT) comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_BLACK6 $(REDIRECT) comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_GFW6 $(REDIRECT) comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST}) comment \"默认\""
					[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_SHUNT6 $(REDIRECT) comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 $(REDIRECT) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 return comment \"默认\""
				}

				nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr $FAKE_IP ${nft_j} comment \"默认\""
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_BLACK ${nft_j} comment \"默认\""
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_GFW ${nft_j} comment \"默认\""
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "${nft_j}") comment \"默认\""
				[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_SHUNT ${nft_j} comment \"默认\""
				[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j} comment \"默认\""
				[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(REDIRECT $TCP_REDIR_PORT TPROXY4) comment \"默认\""
				nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp counter return comment \"默认\""

				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ip6 daddr $FAKE_IP_6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_BLACK6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_GFW6 counter jump PSW_RULE comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE") comment \"默认\""
					[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_SHUNT6 counter jump PSW_RULE comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp counter return comment \"默认\""
				}

				echolog "     - ${msg2}"
			}
		fi

		#  加载UDP默认代理模式
		if [ -n "${UDP_PROXY_MODE}" ]; then
			[ -n "$UDP_NODE" -o "$TCP_UDP" = "1" ] && {
				if is_socks_wrap "$UDP_NODE"; then
					msg2="${msg}使用 UDP 节点[Socks 配置($(config_n_get ${UDP_NODE#Socks_} port) 端口)](TPROXY:${UDP_REDIR_PORT})"
				else
					msg2="${msg}使用 UDP 节点[$(config_n_get $UDP_NODE remarks)](TPROXY:${UDP_REDIR_PORT})"
				fi

				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW_RULE comment \"默认\""
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_BLACK counter jump PSW_RULE comment \"默认\""
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_GFW counter jump PSW_RULE comment \"默认\""
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE") comment \"默认\""
				[ "${USE_SHUNT_UDP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_SHUNT counter jump PSW_RULE comment \"默认\""
				[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(REDIRECT $UDP_REDIR_PORT TPROXY4) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp counter return comment \"默认\""

				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ip6 daddr $FAKE_IP_6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_BLACK6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_GFW6 counter jump PSW_RULE comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE") comment \"默认\""
					[ "${USE_SHUNT_UDP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_SHUNT6 counter jump PSW_RULE comment \"默认\""
					[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp counter return comment \"默认\""
				}

				echolog "     - ${msg2}"
			}
		fi
	}
}

filter_haproxy() {
	for item in ${haproxy_items}; do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		insert_nftset $NFTSET_VPS "-1" $ip
	done
	echolog "  - [$?]加入负载均衡的节点到nftset[$NFTSET_VPS]直连完成"
}

filter_vps_addr() {
	for server_host in $@; do
		local vps_ip4=$(get_host_ip "ipv4" ${server_host})
		local vps_ip6=$(get_host_ip "ipv6" ${server_host})
		[ -n "$vps_ip4" ] && insert_nftset $NFTSET_VPS "-1" $vps_ip4
		[ -n "$vps_ip6" ] && insert_nftset $NFTSET_VPS6 "-1" $vps_ip6
	done
}

filter_vpsip() {
	uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$" | sed -e "/^$/d" | insert_nftset $NFTSET_VPS "-1"
	echolog "  - [$?]加入所有IPv4节点到nftset[$NFTSET_VPS]直连完成"
	uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d" | insert_nftset $NFTSET_VPS6 "-1"
	echolog "  - [$?]加入所有IPv6节点到nftset[$NFTSET_VPS6]直连完成"
}

filter_server_port() {
	local address=${1}
	local port=${2}
	local stream=${3}
	stream=$(echo ${3} | tr 'A-Z' 'a-z')
	local _is_tproxy
	_is_tproxy=${is_tproxy}
	[ "$stream" == "udp" ] && _is_tproxy="TPROXY"

	for _ipt in 4 6; do
		[ "$_ipt" == "4" ] && _ip_type=ip
		[ "$_ipt" == "6" ] && _ip_type=ip6
		nft "list chain $NFTABLE_NAME $nft_output_chain" 2>/dev/null | grep -q "${address}:${port}"
		if [ $? -ne 0 ]; then
			nft "insert rule $NFTABLE_NAME $nft_output_chain meta l4proto $stream $_ip_type daddr $address $stream dport $port return comment \"${address}:${port}\"" 2>/dev/null
		fi
	done
}

filter_node() {
	local node=${1}
	local stream=${2}
	if [ -n "$node" ]; then
		local address=$(config_n_get $node address)
		local port=$(config_n_get $node port)
		[ -z "$address" ] && [ -z "$port" ] && {
			return 1
		}
		filter_server_port $address $port $stream
		filter_server_port $address $port $stream
	fi
}

filter_direct_node_list() {
	[ ! -s "$TMP_PATH/direct_node_list" ] && return
	for _node_id in $(cat $TMP_PATH/direct_node_list | awk '!seen[$0]++'); do
		filter_node "$_node_id" TCP
		filter_node "$_node_id" UDP
		unset _node_id
	done
}

add_firewall_rule() {
	echolog "开始加载 nftables 防火墙规则..."
	gen_nft_tables
	gen_nftset $NFTSET_WAN ipv4_addr 0 "-1"
	gen_nftset $NFTSET_VPS ipv4_addr 0 "-1"
	gen_nftset $NFTSET_GFW ipv4_addr "2d" 0
	gen_nftset $NFTSET_LOCAL ipv4_addr 0 "-1"
	gen_nftset $NFTSET_LAN ipv4_addr 0 "-1" $(gen_lanlist)
	if [ -f $RULES_PATH/chnroute.nft ] && [ -s $RULES_PATH/chnroute.nft ] && [ $(awk 'END{print NR}' $RULES_PATH/chnroute.nft) -ge 8 ]; then
		#echolog "使用缓存加载chnroute..."
		nft -f $RULES_PATH/chnroute.nft
	else
		cat $RULES_PATH/chnroute | tr -s '\n' | grep -v "^#" | gen_nftset $NFTSET_CHN ipv4_addr "2d" 0 
	fi
	gen_nftset $NFTSET_BLACK ipv4_addr "2d" 0
	gen_nftset $NFTSET_WHITE ipv4_addr "2d" 0
	gen_nftset $NFTSET_BLOCK ipv4_addr "2d" 0
	gen_nftset $NFTSET_SHUNT ipv4_addr "2d" 0

	gen_nftset $NFTSET_WAN6 ipv6_addr 0 "-1"
	gen_nftset $NFTSET_VPS6 ipv6_addr 0 "-1"
	gen_nftset $NFTSET_GFW6 ipv6_addr "2d" 0
	gen_nftset $NFTSET_LOCAL6 ipv6_addr 0 "-1"
	gen_nftset $NFTSET_LAN6 ipv6_addr 0 "-1" $(gen_lanlist_6)
	if [ -f $RULES_PATH/chnroute6.nft ] && [ -s $RULES_PATH/chnroute6.nft ] && [ $(awk 'END{print NR}' $RULES_PATH/chnroute6.nft) -ge 8 ]; then
		#echolog "使用缓存加载chnroute6..."
		nft -f $RULES_PATH/chnroute6.nft
	else
		cat $RULES_PATH/chnroute6 | tr -s '\n' | grep -v "^#" | gen_nftset $NFTSET_CHN6 ipv6_addr "2d" 0
	fi
	gen_nftset $NFTSET_BLACK6 ipv6_addr "2d" 0
	gen_nftset $NFTSET_WHITE6 ipv6_addr "2d" 0
	gen_nftset $NFTSET_BLOCK6 ipv6_addr "2d" 0
	gen_nftset $NFTSET_SHUNT6 ipv6_addr "2d" 0

	#导入规则列表、分流规则中的IP列表
	local USE_SHUNT_NODE=0
	local USE_PROXY_LIST_ALL=${USE_PROXY_LIST}
	local USE_DIRECT_LIST_ALL=${USE_DIRECT_LIST}
	local USE_BLOCK_LIST_ALL=${USE_BLOCK_LIST}
	local _TCP_NODE=$(config_t_get global tcp_node)
	local _UDP_NODE=$(config_t_get global udp_node)
	local USE_GEOVIEW=$(config_t_get global_rules enable_geoview)

	[ -n "$_TCP_NODE" ] && [ "$(config_n_get $_TCP_NODE protocol)" = "_shunt" ] && USE_SHUNT_TCP=1 && USE_SHUNT_NODE=1
	[ -n "$_UDP_NODE" ] && [ "$(config_n_get $_UDP_NODE protocol)" = "_shunt" ] && USE_SHUNT_UDP=1 && USE_SHUNT_NODE=1
	[ "$_UDP_NODE" = "tcp" ] && USE_SHUNT_UDP=$USE_SHUNT_TCP

	for acl_section in $(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
		[ "$(config_n_get $acl_section enabled)" != "1" ] && continue
		[ "$(config_n_get $acl_section use_global_config 0)" != "1" ] && {
			[ "$(config_n_get $acl_section use_direct_list 1)" = "1" ] && USE_PROXY_LIST_ALL=1
			[ "$(config_n_get $acl_section use_proxy_list 1)" = "1" ] && USE_DIRECT_LIST_ALL=1
			[ "$(config_n_get $acl_section use_block_list 1)" = "1" ] && USE_BLOCK_LIST_ALL=1
		}
		for _node in $(config_n_get $acl_section tcp_node) $(config_n_get $acl_section udp_node); do
			local node_protocol=$(config_n_get $_node protocol)
			[ "$node_protocol" = "_shunt" ] && { USE_SHUNT_NODE=1; break; }
		done
	done

	#直连列表
	[ "$USE_DIRECT_LIST_ALL" = "1" ] && {
		insert_nftset $NFTSET_WHITE "0" $(cat $RULES_PATH/direct_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
		insert_nftset $NFTSET_WHITE6 "0" $(cat $RULES_PATH/direct_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		[ "$USE_GEOVIEW" = "1" ] && {
			local GEOIP_CODE=$(cat $RULES_PATH/direct_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
			if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
				get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $NFTSET_WHITE "0"
				get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $NFTSET_WHITE6 "0"
				echolog "  - [$?]解析并加入[直连列表] GeoIP 到 NFTSET 完成"
			fi
		}
	}

	#代理列表
	[ "$USE_PROXY_LIST_ALL" = "1" ] && {
		insert_nftset $NFTSET_BLACK "0" $(cat $RULES_PATH/proxy_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
		insert_nftset $NFTSET_BLACK6 "0" $(cat $RULES_PATH/proxy_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		[ "$USE_GEOVIEW" = "1" ] && {
			local GEOIP_CODE=$(cat $RULES_PATH/proxy_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
			if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
				get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $NFTSET_BLACK "0"
				get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $NFTSET_BLACK6 "0"
				echolog "  - [$?]解析并加入[代理列表] GeoIP 到 NFTSET 完成"
			fi
		}
	}

	#屏蔽列表
	[ "$USE_BLOCK_LIST_ALL" = "1" ] && {
		insert_nftset $NFTSET_BLOCK "0" $(cat $RULES_PATH/block_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
		insert_nftset $NFTSET_BLOCK6 "0" $(cat $RULES_PATH/block_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		[ "$USE_GEOVIEW" = "1" ] && {
			local GEOIP_CODE=$(cat $RULES_PATH/block_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
			if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
				get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $NFTSET_BLOCK "0"
				get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $NFTSET_BLOCK6 "0"
				echolog "  - [$?]解析并加入[屏蔽列表] GeoIP 到 NFTSET 完成"
			fi
		}
	}

	#分流列表
	[ "$USE_SHUNT_NODE" = "1" ] && {
		local GEOIP_CODE=""
		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $NFTSET_SHUNT "0"
			config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $NFTSET_SHUNT6 "0"
			[ "$USE_GEOVIEW" = "1" ] && {
				local geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
				[ -n "$geoip_code" ] && GEOIP_CODE="${GEOIP_CODE:+$GEOIP_CODE,}$geoip_code"
			}
		done
		if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
			get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $NFTSET_SHUNT "0"
			get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $NFTSET_SHUNT6 "0"
			echolog "  - [$?]解析并加入[分流节点] GeoIP 到 NFTSET 完成"
		fi
	}

	ip address show | grep -w "inet" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/ /\n/g" | insert_nftset $NFTSET_LOCAL "-1"
	ip address show | grep -w "inet6" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/ /\n/g" | insert_nftset $NFTSET_LOCAL6 "-1"

	# 忽略特殊IP段
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#echolog "本机IPv4网段互访直连：${lan_ip}"
		#echolog "本机IPv6网段互访直连：${lan_ip6}"

		[ -n "$lan_ip" ] && insert_nftset $NFTSET_LAN "-1" $(echo $lan_ip | sed -e "s/ /\n/g")
		[ -n "$lan_ip6" ] && insert_nftset $NFTSET_LAN6 "-1" $(echo $lan_ip6 | sed -e "s/ /\n/g")
	}

	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP DNS 例外..."
		for ispip in $ISP_DNS; do
			insert_nftset $NFTSET_WHITE 0 $ispip
			echolog "  - [$?]追加ISP IPv4 DNS到白名单：${ispip}"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		#echolog "处理 ISP IPv6 DNS 例外..."
		for ispip6 in $ISP_DNS6; do
			insert_nftset $NFTSET_WHITE6 0 $ispip6
			echolog "  - [$?]追加ISP IPv6 DNS到白名单：${ispip6}"
		done
	}

	#  过滤所有节点IP
	filter_vpsip > /dev/null 2>&1 &
	# filter_haproxy > /dev/null 2>&1 &
	# Prevent some conditions
	filter_vps_addr $(config_n_get $TCP_NODE address) $(config_n_get $UDP_NODE address) > /dev/null 2>&1 &
	filter_vps_addr $(config_n_get $TCP_NODE download_address) $(config_n_get $UDP_NODE download_address) > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	if [ "${TCP_PROXY_WAY}" = "redirect" ]; then
		unset is_tproxy
		nft_prerouting_chain="PSW_NAT"
		nft_output_chain="PSW_OUTPUT_NAT"
	elif [ "${TCP_PROXY_WAY}" = "tproxy" ]; then
		is_tproxy="TPROXY"
		nft_prerouting_chain="PSW_MANGLE"
		nft_output_chain="PSW_OUTPUT_MANGLE"
	fi

	nft "add chain $NFTABLE_NAME PSW_DIVERT"
	nft "flush chain $NFTABLE_NAME PSW_DIVERT"
	nft "add rule $NFTABLE_NAME PSW_DIVERT meta l4proto tcp socket transparent 1 mark set 1 counter accept"

	nft "add chain $NFTABLE_NAME PSW_DNS"
	nft "flush chain $NFTABLE_NAME PSW_DNS"
	if [ $(config_t_get global dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		nft "insert rule $NFTABLE_NAME dstnat ip daddr @${NFTSET_LOCAL} jump PSW_DNS"
		nft "insert rule $NFTABLE_NAME dstnat ip6 daddr @${NFTSET_LOCAL6} jump PSW_DNS"
	else
		nft "insert rule $NFTABLE_NAME dstnat jump PSW_DNS"
	fi

	# for ipv4 ipv6 tproxy mark
	nft "add chain $NFTABLE_NAME PSW_RULE"
	nft "flush chain $NFTABLE_NAME PSW_RULE"
	nft "add rule $NFTABLE_NAME PSW_RULE meta mark set ct mark counter"
	nft "add rule $NFTABLE_NAME PSW_RULE meta mark 1 counter return"
	nft "add rule $NFTABLE_NAME PSW_RULE tcp flags &(fin|syn|rst|ack) == syn meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule $NFTABLE_NAME PSW_RULE meta l4proto udp ct state new meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule $NFTABLE_NAME PSW_RULE ct mark set mark counter"

	#ipv4 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW_MANGLE"
	nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_LAN counter return"
	nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_VPS counter return"

	nft "add chain $NFTABLE_NAME PSW_OUTPUT_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW_OUTPUT_MANGLE"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_LAN counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_VPS counter return"

	[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_BLOCK counter drop"
	[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_WHITE counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta mark 0xff counter return"

	# jump chains
	nft "add rule $NFTABLE_NAME mangle_prerouting counter jump PSW_DIVERT"
	nft "add rule $NFTABLE_NAME mangle_prerouting ip protocol udp counter jump PSW_MANGLE"
	[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME mangle_prerouting ip protocol tcp counter jump PSW_MANGLE"

	#ipv4 tcp redirect mode
	[ -z "${is_tproxy}" ] && {
		nft "add chain $NFTABLE_NAME PSW_NAT"
		nft "flush chain $NFTABLE_NAME PSW_NAT"
		nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_LAN counter return"
		nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_VPS counter return"
		nft "add rule $NFTABLE_NAME dstnat ip protocol tcp counter jump PSW_NAT"

		nft "add chain $NFTABLE_NAME PSW_OUTPUT_NAT"
		nft "flush chain $NFTABLE_NAME PSW_OUTPUT_NAT"
		nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_LAN counter return"
		nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_VPS counter return"
		[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_BLOCK counter drop"
		[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_WHITE counter return"
		nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT meta mark 0xff counter return"
	}

	#icmp ipv6-icmp redirect
	if [ "$accept_icmp" = "1" ]; then
		nft "add chain $NFTABLE_NAME PSW_ICMP_REDIRECT"
		nft "flush chain $NFTABLE_NAME PSW_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip daddr @$NFTSET_LAN counter return"
		nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip daddr @$NFTSET_VPS counter return"

		[ "$accept_icmpv6" = "1" ] && {
			nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_LAN6 counter return"
			nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_VPS6 counter return"
		}

		nft "add rule $NFTABLE_NAME dstnat meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME nat_output meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
	fi

	WAN_IP=$(get_wan_ips ip4)
	if [ -n "${WAN_IP}" ]; then
		nft flush set $NFTABLE_NAME $NFTSET_WAN
		insert_nftset $NFTSET_WAN "-1" $WAN_IP
		[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_WAN counter return comment \"WAN_IP_RETURN\""
		nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_WAN counter return comment \"WAN_IP_RETURN\""
		for wan_ip in $WAN_IP; do
			echolog "  - [$?]加入WAN IPv4到nftset[$NFTSET_WAN]：${wan_ip}"
		done
	fi
	unset WAN_IP wan_ip

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	#ipv6 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_LAN6 counter return"
	nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_VPS6 counter return"

	nft "add chain $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_LAN6 counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_VPS6 counter return"
	[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_BLOCK6 counter drop"
	[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_WHITE6 counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta mark 0xff counter return"

	[ -n "$IPT_APPEND_DNS" ] && {
		local local_dns dns_address dns_port
		for local_dns in $(echo $IPT_APPEND_DNS | tr ',' ' '); do
			dns_address=$(echo "$local_dns" | sed -E 's/(@|\[)?([0-9a-fA-F:.]+)(@|#|$).*/\2/')
			dns_port=$(echo "$local_dns" | sed -nE 's/.*#([0-9]+)$/\1/p')
			if echo "$dns_address" | grep -q -v ':'; then
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr ${dns_address} $(factor ${dns_port:-53} "udp dport") counter return"
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr ${dns_address} $(factor ${dns_port:-53} "tcp dport") counter return"
				echolog "  - [$?]追加直连DNS到nftables：${dns_address}:${dns_port:-53}"
			else
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr ${dns_address} $(factor ${dns_port:-53} "udp dport") counter return"
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr ${dns_address} $(factor ${dns_port:-53} "tcp dport") counter return"
				echolog "  - [$?]追加直连DNS到nftables：[${dns_address}]:${dns_port:-53}"
			fi
		done
	}

	# jump chains
	[ "$PROXY_IPV6" == "1" ] && {
		nft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto {ipv6} counter jump PSW_MANGLE_V6"
		nft "add rule $NFTABLE_NAME mangle_output meta nfproto {ipv6} counter jump PSW_OUTPUT_MANGLE_V6 comment \"PSW_OUTPUT_MANGLE\""

		WAN6_IP=$(get_wan_ips ip6)
		[ -n "${WAN6_IP}" ] && {
			nft flush set $NFTABLE_NAME $NFTSET_WAN6
			insert_nftset $NFTSET_WAN6 "-1" $WAN6_IP
			nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_WAN6 counter return comment \"WAN6_IP_RETURN\""
			for wan6_ip in $WAN6_IP; do
				echolog "  - [$?]加入WAN IPv6到nftset[$NFTSET_WAN6]：${wan6_ip}"
			done
		}
		unset WAN6_IP wan6_ip

		ip -6 rule add fwmark 1 table 100
		ip -6 route add local ::/0 dev lo table 100
	}
	
	[ "$TCP_UDP" = "1" ] && [ -z "$UDP_NODE" ] && UDP_NODE=$TCP_NODE

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		msg="【路由器本机】，"
		
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
			nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
			if ! has_1_65535 "$TCP_NO_REDIR_PORTS"; then
				echolog "  - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset LOCALHOST_TCP_PROXY_MODE
				echolog "  - ${msg}不代理所有 TCP 端口"
			fi
		}
		
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return"
			nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return"
			if ! has_1_65535 "$UDP_NO_REDIR_PORTS"; then
				echolog "  - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				unset LOCALHOST_UDP_PROXY_MODE
				echolog "  - ${msg}不代理所有 UDP 端口"
			fi
		}

		if ([ -n "$TCP_NODE" ] && [ -n "${LOCALHOST_TCP_PROXY_MODE}" ]) || ([ -n "$UDP_NODE" ] && [ -n "${LOCALHOST_UDP_PROXY_MODE}" ]); then
			[ -n "$DNS_REDIRECT_PORT" ] && {
				nft "add rule $NFTABLE_NAME nat_output ip protocol udp oif lo udp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW_DNS\""
				nft "add rule $NFTABLE_NAME nat_output ip protocol tcp oif lo tcp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW_DNS\""
				nft "add rule $NFTABLE_NAME nat_output meta l4proto udp oif lo udp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW_DNS\""
				nft "add rule $NFTABLE_NAME nat_output meta l4proto tcp oif lo tcp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW_DNS\""
			}
		fi

		[ -n "${LOCALHOST_TCP_PROXY_MODE}" -o -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
			[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
				nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr $FAKE_IP $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "${USE_PROXY_LIST}" = "1" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_BLACK $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "${USE_GFW_LIST}" = "1" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_GFW $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "${CHN_LIST}" != "0" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_CHN $(factor $TCP_PROXY_DROP_PORTS "tcp dport") $(get_jump_ipt ${CHN_LIST} "counter drop")
				[ "${USE_SHUNT_TCP}" = "1" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_SHUNT $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				echolog "  - ${msg}屏蔽代理 TCP 端口[${TCP_PROXY_DROP_PORTS}]"
			}
			
			[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
				nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				[ "${USE_PROXY_LIST}" = "1" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_BLACK $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				[ "${USE_GFW_LIST}" = "1" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_GFW $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				[ "${CHN_LIST}" != "0" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_CHN $(factor $UDP_PROXY_DROP_PORTS "udp dport") $(get_jump_ipt ${CHN_LIST} "counter drop")
				[ "${USE_SHUNT_UDP}" = "1" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_SHUNT $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE counter ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				echolog "  - ${msg}屏蔽代理 UDP 端口[${UDP_PROXY_DROP_PORTS}]"
			}
		}

		# 加载路由器自身代理 TCP
		if [ -n "$TCP_NODE" ]; then
			_proxy_tcp_access() {
				[ -n "${2}" ] || return 0
				if echo "${2}" | grep -q -v ':'; then
					nft "get element $NFTABLE_NAME $NFTSET_LAN {${2}}" &>/dev/null
					[ $? -eq 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 TCP 代理转发对该服务器 TCP/${3} 端口的访问"
						return 0
					}
					if [ -z "${is_tproxy}" ]; then
						nft insert rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp ip daddr ${2} tcp dport ${3} $(REDIRECT $TCP_REDIR_PORT)
					else
						nft insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr ${2} tcp dport ${3} counter jump PSW_RULE
						nft insert rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp iif lo tcp dport ${3} ip daddr ${2} $(REDIRECT $TCP_REDIR_PORT TPROXY4) comment \"本机\"
					fi
					echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 TCP 转发链"
				else
					nft "get element $NFTABLE_NAME $NFTSET_LAN6 {${2}}" &>/dev/null
					[ $? -eq 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 TCP 代理转发对该服务器 TCP/${3} 端口的访问"
						return 0
					}
					nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr ${2} tcp dport ${3} counter jump PSW_RULE"
					nft "insert rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp iif lo tcp dport ${3} ip6 daddr ${2} $(REDIRECT $TCP_REDIR_PORT TPROXY6) comment \"本机\""
					echolog "  - [$?]将上游 DNS 服务器 [${2}]:${3} 加入到路由器自身代理的 TCP 转发链，请确保您的节点支持IPv6，并开启IPv6透明代理！"
				fi
			}
			[ "$TCP_PROXY_DNS" == 1 ] && hosts_foreach REMOTE_DNS _proxy_tcp_access 53

			[ "$accept_icmp" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr $FAKE_IP counter redirect"
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_BLACK counter redirect"
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_GFW counter redirect"
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST})"
				[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_SHUNT counter redirect"
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && [ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp counter redirect"
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp counter return"
			}

			[ "$accept_icmpv6" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr $FAKE_IP_6 counter redirect"
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_BLACK6 counter redirect"
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_GFW6 counter redirect"
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST})"
				[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_SHUNT6 counter redirect"
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && [ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter redirect"
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter return"
			}

			if [ -n "${is_tproxy}" ]; then
				nft_chain="PSW_OUTPUT_MANGLE"
				nft_j="counter jump PSW_RULE"
			else
				nft_chain="PSW_OUTPUT_NAT"
				nft_j="$(REDIRECT $TCP_REDIR_PORT)"
			fi

			[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && {
				nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr $FAKE_IP ${nft_j}"
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr @$NFTSET_BLACK $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j}"
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr @$NFTSET_GFW $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j}"
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr @$NFTSET_CHN $(factor $TCP_REDIR_PORTS "tcp dport") $(get_jump_ipt ${CHN_LIST} "${nft_j}")"
				[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr @$NFTSET_SHUNT $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j}"
				[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j}"
				[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp iif lo $(REDIRECT $TCP_REDIR_PORT TPROXY4) comment \"本机\""
			}
			[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp iif lo counter return comment \"本机\""
			[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME mangle_output ip protocol tcp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""
			[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME nat_output ip protocol tcp counter jump PSW_OUTPUT_NAT"

			[ "$PROXY_IPV6" == "1" ] && {
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && {
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr $FAKE_IP_6 counter jump PSW_RULE"
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_BLACK6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_GFW6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_CHN6 $(factor $TCP_REDIR_PORTS "tcp dport") $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE")"
					[ "${USE_SHUNT_TCP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_SHUNT6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp iif lo $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"本机\""
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp iif lo counter return comment \"本机\""
			}
		fi

		# 加载路由器自身代理 UDP
		if [ -n "$UDP_NODE" -o "$TCP_UDP" = "1" ]; then
			_proxy_udp_access() {
				[ -n "${2}" ] || return 0
				if echo "${2}" | grep -q -v ':'; then
					nft "get element $NFTABLE_NAME $NFTSET_LAN {${2}}" &>/dev/null
					[ $? == 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 UDP 代理转发对该服务器 UDP/${3} 端口的访问"
						return 0
					}
					nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr ${2} udp dport ${3} counter jump PSW_RULE"
					nft "insert rule $NFTABLE_NAME PSW_MANGLE ip protocol udp iif lo ip daddr ${2} $(REDIRECT $UDP_REDIR_PORT TPROXY4) comment \"本机\""
					echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 UDP 转发链"
				else
					nft "get element $NFTABLE_NAME $NFTSET_LAN6 {${2}}" &>/dev/null
					[ $? == 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 UDP 代理转发对该服务器 UDP/${3} 端口的访问"
						return 0
					}
					nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr ${2} udp dport ${3} counter jump PSW_RULE"
					nft "insert rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp iif lo ip6 daddr ${2} $(REDIRECT $UDP_REDIR_PORT TPROXY6) comment \"本机\""
					echolog "  - [$?]将上游 DNS 服务器 [${2}]:${3} 加入到路由器自身代理的 UDP 转发链，请确保您的节点支持IPv6，并开启IPv6透明代理！"
				fi
			}
			[ -n "${UDP_PROXY_DNS}" ] && hosts_foreach REMOTE_DNS _proxy_udp_access 53
			[ -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW_RULE"
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_BLACK $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_GFW $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_CHN $(factor $UDP_REDIR_PORTS "udp dport") $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE")"
				[ "${USE_SHUNT_UDP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_SHUNT $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp iif lo $(REDIRECT $UDP_REDIR_PORT TPROXY4) comment \"本机\""
			}
			nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp iif lo counter return comment \"本机\""
			nft "add rule $NFTABLE_NAME mangle_output ip protocol udp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""

			[ "$PROXY_IPV6" == "1" ] && {
				[ -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr $FAKE_IP_6 counter jump PSW_RULE"
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_BLACK6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_GFW6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_CHN6 $(factor $UDP_REDIR_PORTS "udp dport") $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE")"
					[ "${USE_SHUNT_UDP}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_SHUNT6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp iif lo $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"本机\""
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp iif lo counter return comment \"本机\""
			}
		fi

		nft "add rule $NFTABLE_NAME mangle_output oif lo counter return comment \"PSW_OUTPUT_MANGLE\""
		nft "add rule $NFTABLE_NAME mangle_output meta mark 1 counter return comment \"PSW_OUTPUT_MANGLE\""
	}

	#  加载ACLS
	load_acl

	[ -d "${TMP_IFACE_PATH}" ] && {
		for iface in $(ls ${TMP_IFACE_PATH}); do
			nft "insert rule $NFTABLE_NAME $nft_output_chain oif $iface counter return"
			nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 oif $iface counter return"
		done
	}

	filter_direct_node_list > /dev/null 2>&1 &

	echolog "防火墙规则加载完成！"
}

del_firewall_rule() {
	for nft in "dstnat" "srcnat" "nat_output" "mangle_prerouting" "mangle_output"; do
        local handles=$(nft -a list chain $NFTABLE_NAME ${nft} 2>/dev/null | grep -E "PSW_" | awk -F '# handle ' '{print$2}')
		for handle in $handles; do
			nft delete rule $NFTABLE_NAME ${nft} handle ${handle} 2>/dev/null
		done
	done

	for handle in $(nft -a list chains | grep -E "chain PSW_" | grep -v "PSW_RULE" | awk -F '# handle ' '{print$2}'); do
		nft delete chain $NFTABLE_NAME handle ${handle} 2>/dev/null
	done

	# Need to be removed at the end, otherwise it will show "Resource busy"
	nft delete chain $NFTABLE_NAME handle $(nft -a list chains | grep -E "PSW_RULE" | awk -F '# handle ' '{print$2}') 2>/dev/null

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	destroy_nftset $NFTSET_LOCAL
	destroy_nftset $NFTSET_WAN
	destroy_nftset $NFTSET_LAN
	destroy_nftset $NFTSET_VPS
	#destroy_nftset $NFTSET_SHUNT
	#destroy_nftset $NFTSET_GFW
	#destroy_nftset $NFTSET_CHN
	#destroy_nftset $NFTSET_BLACK
	destroy_nftset $NFTSET_BLOCK
	destroy_nftset $NFTSET_WHITE

	destroy_nftset $NFTSET_LOCAL6
	destroy_nftset $NFTSET_WAN6
	destroy_nftset $NFTSET_LAN6
	destroy_nftset $NFTSET_VPS6
	#destroy_nftset $NFTSET_SHUNT6
	#destroy_nftset $NFTSET_GFW6
	#destroy_nftset $NFTSET_CHN6
	#destroy_nftset $NFTSET_BLACK6
	destroy_nftset $NFTSET_BLOCK6
	destroy_nftset $NFTSET_WHITE6

	$DIR/app.sh echolog "删除 nftables 规则完成。"
}

flush_nftset() {
	$DIR/app.sh echolog "清空 NFTSet。"
	for _name in $(nft -a list sets | grep -E "passwall_" | awk -F 'set ' '{print $2}' | awk '{print $1}'); do
		destroy_nftset ${_name}
	done
}

flush_table() {
	nft flush table $NFTABLE_NAME
	nft delete table $NFTABLE_NAME
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	local nft_chain_file=$TMP_PATH/PSW_RULE.nft
	echo '#!/usr/sbin/nft -f' > $nft_chain_file
	nft list table $NFTABLE_NAME >> $nft_chain_file

	local __nft=" "
	__nft=$(cat <<- EOF
		[ -z "\$(nft list chain $NFTABLE_NAME mangle_prerouting | grep PSW_DIVERT)" ] && nft -f ${nft_chain_file}
		WAN_IP=\$(sh ${MY_PATH} get_wan_ips ip4)
		[ ! -z "\${WAN_IP}" ] && {
			nft flush set $NFTABLE_NAME $NFTSET_WAN
			sh ${MY_PATH} insert_nftset $NFTSET_WAN "-1" \$WAN_IP
		}
		[ "$PROXY_IPV6" == "1" ] && {
			WAN6_IP=\$(sh ${MY_PATH} get_wan_ips ip6)
			[ ! -z "\${WAN6_IP}" ] && {
				nft flush set $NFTABLE_NAME $NFTSET_WAN6
				sh ${MY_PATH} insert_nftset $NFTSET_WAN6 "-1" \$WAN6_IP
			}
		}
	EOF
	)

	cat <<-EOF >> $FWI
	${__nft}

	return 0
	EOF
	return 0
}

start() {
	[ "$ENABLED_DEFAULT_ACL" == 0 -a "$ENABLED_ACLS" == 0 ] && return
	add_firewall_rule
	gen_include
}

stop() {
	del_firewall_rule
	[ $(config_t_get global flush_set_on_reboot "0") = "1" -o $(config_t_get global flush_set "0") = "1" ] && {
		uci -q delete ${CONFIG}.@global[0].flush_set
		uci -q commit ${CONFIG}
		#flush_table
		flush_nftset
		rm -rf /tmp/etc/passwall_tmp/singbox*
		rm -rf /tmp/etc/passwall_tmp/dnsmasq*
	}
	flush_include
}

arg1=$1
shift
case $arg1 in
insert_nftset)
	insert_nftset "$@"
	;;
get_wan_ips)
	get_wan_ips "$@"
	;;
filter_direct_node_list)
	filter_direct_node_list
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
