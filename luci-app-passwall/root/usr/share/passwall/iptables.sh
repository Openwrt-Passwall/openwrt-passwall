#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/iptables.sh
IPSET_LOCAL="passwall_local"
IPSET_WAN="passwall_wan"
IPSET_LAN="passwall_lan"
IPSET_VPS="passwall_vps"
IPSET_SHUNT="passwall_shunt"
IPSET_GFW="passwall_gfw"
IPSET_CHN="passwall_chn"
IPSET_BLACK="passwall_black"
IPSET_WHITE="passwall_white"
IPSET_BLOCK="passwall_block"

IPSET_LOCAL6="passwall_local6"
IPSET_WAN6="passwall_wan6"
IPSET_LAN6="passwall_lan6"
IPSET_VPS6="passwall_vps6"
IPSET_SHUNT6="passwall_shunt6"
IPSET_GFW6="passwall_gfw6"
IPSET_CHN6="passwall_chn6"
IPSET_BLACK6="passwall_black6"
IPSET_WHITE6="passwall_white6"
IPSET_BLOCK6="passwall_block6"

FORCE_INDEX=2

USE_SHUNT_TCP=0
USE_SHUNT_UDP=0

. /lib/functions/network.sh

ipt=$(command -v iptables-legacy || command -v iptables)
ip6t=$(command -v ip6tables-legacy || command -v ip6tables)

ipt_n="$ipt -t nat -w"
ipt_m="$ipt -t mangle -w"
ip6t_n="$ip6t -t nat -w"
ip6t_m="$ip6t -t mangle -w"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_nat')" ] && ip6t_n="eval #$ip6t_n"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_mangle')" ] && ip6t_m="eval #$ip6t_m"
FWI=$(uci -q get firewall.passwall.path 2>/dev/null)
FAKE_IP="198.18.0.0/15"
FAKE_IP_6="fc00::/18"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

dst() {
	echo "-m set $2 --match-set $1 dst"
}

comment() {
	local name=$(echo $1 | sed 's/ /_/g')
	echo "-m comment --comment '$name'"
}

#解决端口超过15个ipt无效，支持单端口、端口范围
add_port_rules() {
	local ipt_cmd="$1"
	local port_list="$2"
	local target="$3"
	echo "$port_list" | grep -vq '[0-9]' && return
	port_list=$(echo "$port_list" | tr -d ' ' | sed 's/-/:/g' | tr ',' '\n' | awk '!a[$0]++' | grep -v '^$')
	[ -z "$port_list" ] && return
	if echo "$port_list" | grep -q '^1:65535$'; then
		eval "$ipt_cmd $target"
		return
	fi
	local multiport_ports=""
	local range_ports=""
	local count=0
	local port
	for port in $port_list; do
		if echo "$port" | grep -q ':'; then
			range_ports="$range_ports $port"
		else
			multiport_ports="$multiport_ports,$port"
			count=$((count + 1))
			if [ "$count" -eq 15 ]; then
				eval "$ipt_cmd -m multiport --dport ${multiport_ports#,} $target"
				multiport_ports=""
				count=0
			fi
		fi
	done
	if [ -n "$multiport_ports" ]; then
		eval "$ipt_cmd -m multiport --dport ${multiport_ports#,} $target"
	fi
	for port in $range_ports; do
		eval "$ipt_cmd --dport $port $target"
	done
}

destroy_ipset() {
	for i in "$@"; do
		ipset -q -F $i
		ipset -q -X $i
	done
}

insert_rule_before() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

insert_rule_after() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | awk 'END {print}' | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "索引列举方式不正确（iptables），终止执行！"
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local list="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$list" | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="-j REDIRECT"
	if [ -n "$1" ]; then
		s="$s --to-ports $1"
		if [ "$2" = "MARK" ]; then
			s="-j MARK --set-mark $1"
		elif [ "$2" = "TPROXY" ]; then
			local mark="-m mark --mark 1"
			s="${mark} -j TPROXY --tproxy-mark 1/1 --on-port $1"
		fi
	fi
	echo "$s"
}

get_jump_ipt() {
	case "$1" in
	direct)
		local mark="-m mark ! --mark 1"
		s="${mark} -j RETURN"
		echo $s
		;;
	proxy)
		if [ -n "$2" ] && [ -n "$(echo $2 | grep "^-")" ]; then
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
				black_set_name=${IPSET_BLACK}
				black6_set_name=${IPSET_BLACK6}
				gfw_set_name=${IPSET_GFW}
				gfw6_set_name=${IPSET_GFW6}
				shunt_set_name=${IPSET_SHUNT}
				shunt6_set_name=${IPSET_SHUNT6}
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
					_ipt_source="-i ${device} "
					msg="源接口【${device}】，"
				else
					msg="源接口【所有】，"
				fi
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "${_ipt_source}-m iprange --src-range")
					msg="${msg}IP range【${_iprange}】，"
					_ipv4="1"
					unset _iprange
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					msg="${msg}IPset【${_ipset}】，"
					ipset -q list ${_ipset} >/dev/null
					if [ $? -eq 0 ]; then
						_ipt_source="${_ipt_source}-m set --match-set ${_ipset} src"
						unset _ipset
					else
						echolog "  - 【$remarks】，${msg}不存在，忽略。"
						unset _ipset
						continue
					fi
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "${_ipt_source}-s")
					msg="${msg}IP【${_ip}】，"
					_ipv4="1"
					unset _ip
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "${_ipt_source}-m mac --mac-source")
					msg="${msg}MAC【${_mac}】，"
					unset _mac
				elif [ -n "$(echo ${i} | grep '^any')" ]; then
					msg="${msg}所有设备，"
				else
					continue
				fi
				msg="【$remarks】，${msg}"
				
				ipt_tmp=$ipt_n
				[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m

				[ "$tcp_no_redir_ports" != "disable" ] && {
					if ! has_1_65535 "$tcp_no_redir_ports"; then
						[ "$_ipv4" != "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p tcp" $tcp_no_redir_ports "-j RETURN" 2>/dev/null
						add_port_rules "$ipt_tmp -A PSW $(comment "$remarks") ${_ipt_source} -p tcp" $tcp_no_redir_ports "-j RETURN"
						echolog "     - ${msg}不代理 TCP 端口[${tcp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						unset tcp_port
						echolog "     - ${msg}不代理所有 TCP 端口"
					fi
				}
				
				[ "$udp_no_redir_ports" != "disable" ] && {
					if ! has_1_65535 "$udp_no_redir_ports"; then
						[ "$_ipv4" != "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp" $udp_no_redir_ports "-j RETURN" 2>/dev/null
						add_port_rules "$ipt_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp" $udp_no_redir_ports "-j RETURN"
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
							ipset -! create $black_set_name nethash maxelem 1048576 timeout 172800
							ipset -! create $black6_set_name nethash family inet6 maxelem 1048576 timeout 172800
						}
					}
					[ "${use_gfw_list}" = "1" ] && {
						[ "${use_global_config}" = "0" ] && {
							gfw_set_name="passwall_${sid}_gfw"
							gfw6_set_name="passwall_${sid}_gfw6"
							ipset -! create $gfw_set_name nethash maxelem 1048576 timeout 172800
							ipset -! create $gfw6_set_name nethash family inet6 maxelem 1048576 timeout 172800
						}
					}
					[ "${use_shunt_tcp}" = "1" -o "${use_shunt_udp}" = "1" ] && {
						[ "${use_global_config}" = "0" ] && {
							shunt_set_name="passwall_${sid}_shunt"
							shunt6_set_name="passwall_${sid}_shunt6"
							ipset -! create $shunt_set_name nethash maxelem 1048576 timeout 172800
							ipset -! create $shunt6_set_name nethash family inet6 maxelem 1048576 timeout 172800
						}
					}
					[ -n "${dns_redirect_port}" ] && dns_redirect=${dns_redirect_port}
				else
					[ -n "${DIRECT_DNSMASQ_PORT}" ] && dns_redirect=${DIRECT_DNSMASQ_PORT}
				fi
				if [ -n "${dns_redirect}" ]; then
					$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN
					[ "$_ipv4" != "1" ] && $ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
					$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN
					[ "$_ipv4" != "1" ] && $ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
					$ipt_n -A PSW_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports ${dns_redirect}
					[ "$_ipv4" != "1" ] && $ip6t_n -A PSW_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports ${dns_redirect} 2>/dev/null
					$ipt_n -A PSW_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports ${dns_redirect}
					[ "$_ipv4" != "1" ] && $ip6t_n -A PSW_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports ${dns_redirect} 2>/dev/null
					[ -z "$(get_cache_var "ACL_${sid}_tcp_default")" ] && echolog "     - ${msg}使用与全局配置不相同节点，已将DNS强制重定向到专用 DNS 服务器。"
				fi

				[ -n "$tcp_port" -o -n "$udp_port" ] && {
					[ "${use_block_list}" = "1" ] && $ipt_m -A PSW $(comment "$remarks") ${_ipt_source} $(dst $IPSET_BLOCK) -j DROP
					[ "${use_direct_list}" = "1" ] && $ipt_tmp -A PSW $(comment "$remarks") ${_ipt_source} $(dst $IPSET_WHITE) -j RETURN
					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
						[ "${use_block_list}" = "1" ] && $ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} $(dst $IPSET_BLOCK6) -j DROP 2>/dev/null
						[ "${use_direct_list}" = "1" ] && $ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} $(dst $IPSET_WHITE6) -j RETURN 2>/dev/null
					}

					[ "$tcp_proxy_drop_ports" != "disable" ] && {
						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "-d $FAKE_IP_6 -j DROP" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $black6_set_name) -j DROP" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $gfw6_set_name) -j DROP" 2>/dev/null
							[ "${chn_list}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $IPSET_CHN6) $(get_jump_ipt ${chn_list} "-j DROP")" 2>/dev/null
							[ "${use_shunt_tcp}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $shunt6_set_name) -j DROP" 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "-j DROP" 2>/dev/null
						}
						add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "-d $FAKE_IP -j DROP"
						[ "${use_proxy_list}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $black_set_name) -j DROP"
						[ "${use_gfw_list}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $gfw_set_name) -j DROP"
						[ "${chn_list}" != "0" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $IPSET_CHN) $(get_jump_ipt ${chn_list} "-j DROP")"
						[ "${use_shunt_tcp}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "$(dst $shunt_set_name) -j DROP"
						[ "${tcp_proxy_mode}" != "disable" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_proxy_drop_ports "-j DROP"
						echolog "     - ${msg}屏蔽代理 TCP 端口[${tcp_proxy_drop_ports}]"
					}

					[ "$udp_proxy_drop_ports" != "disable" ] && {
						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "-d $FAKE_IP_6 -j DROP" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $black6_set_name) -j DROP" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $gfw6_set_name) -j DROP" 2>/dev/null
							[ "${chn_list}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $IPSET_CHN6) $(get_jump_ipt ${chn_list} "-j DROP")" 2>/dev/null
							[ "${use_shunt_udp}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $shunt6_set_name) -j DROP" 2>/dev/null
							[ "${udp_proxy_mode}" != "disable" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "-j DROP" 2>/dev/null
						}
						add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "-d $FAKE_IP -j DROP"
						[ "${use_proxy_list}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $black_set_name) -j DROP"
						[ "${use_gfw_list}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $gfw_set_name) -j DROP"
						[ "${chn_list}" != "0" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $IPSET_CHN) $(get_jump_ipt ${chn_list} "-j DROP")"
						[ "${use_shunt_udp}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "$(dst $shunt_set_name) -j DROP"
						[ "${udp_proxy_mode}" != "disable" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_proxy_drop_ports "-j DROP"
						echolog "     - ${msg}屏蔽代理 UDP 端口[${udp_proxy_drop_ports}]"
					}
				}
				
				[ -n "$tcp_port" ] && {
					if [ -n "${tcp_proxy_mode}" ]; then
						msg2="${msg}使用 TCP 节点[$tcp_node_remark]"
						if [ -n "${is_tproxy}" ]; then
							msg2="${msg2}(TPROXY:${tcp_port})"
							ipt_tmp=$ipt_m
							ipt_j="-j PSW_RULE"
						else
							msg2="${msg2}(REDIRECT:${tcp_port})"
							ipt_j="$(REDIRECT $tcp_port)"
						fi
						
						[ "$accept_icmp" = "1" ] && {
							$ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} -d $FAKE_IP $(REDIRECT)
							[ "${use_proxy_list}" = "1" ] && $ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(dst $black_set_name) $(REDIRECT)
							[ "${use_gfw_list}" = "1" ] && $ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(dst $gfw_set_name) $(REDIRECT)
							[ "${chn_list}" != "0" ] && $ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(dst $IPSET_CHN) $(get_jump_ipt ${chn_list})
							[ "${use_shunt_tcp}" = "1" ] && $ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(dst $shunt_set_name) $(REDIRECT)
							[ "${tcp_proxy_mode}" != "disable" ] && $ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(REDIRECT)
						}
						
						[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							$ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} -d $FAKE_IP_6 $(REDIRECT) 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && $ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(dst $black6_set_name) $(REDIRECT) 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && $ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(dst $gfw6_set_name) $(REDIRECT) 2>/dev/null
							[ "${chn_list}" != "0" ] && $ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(dst $IPSET_CHN6) $(get_jump_ipt ${chn_list}) 2>/dev/null
							[ "${use_shunt_tcp}" = "1" ] && $ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(dst $shunt6_set_name) $(REDIRECT) 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && $ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(REDIRECT) 2>/dev/null
						}

						$ipt_tmp -A PSW $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP ${ipt_j}
						[ "${use_proxy_list}" = "1" ] && add_port_rules "$ipt_tmp -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $black_set_name) ${ipt_j}"
						[ "${use_gfw_list}" = "1" ] && add_port_rules "$ipt_tmp -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $gfw_set_name) ${ipt_j}"
						[ "${chn_list}" != "0" ] && add_port_rules "$ipt_tmp -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $IPSET_CHN) $(get_jump_ipt ${chn_list} "${ipt_j}")"
						[ "${use_shunt_tcp}" = "1" ] && add_port_rules "$ipt_tmp -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $shunt_set_name) ${ipt_j}"
						[ "${tcp_proxy_mode}" != "disable" ] && add_port_rules "$ipt_tmp -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "${ipt_j}"
						[ -n "${is_tproxy}" ] && $ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY)

						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP_6 -j PSW_RULE 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $black6_set_name) -j PSW_RULE" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $gfw6_set_name) -j PSW_RULE" 2>/dev/null
							[ "${chn_list}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $IPSET_CHN6) $(get_jump_ipt ${chn_list} "-j PSW_RULE")" 2>/dev/null
							[ "${use_shunt_tcp}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "$(dst $shunt6_set_name) -j PSW_RULE" 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "-j PSW_RULE" 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY) 2>/dev/null
						}
					else
						msg2="${msg}不代理 TCP"
					fi
					echolog "     - ${msg2}"
				}

				[ "$_ipv4" != "1" ] && $ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN 2>/dev/null
				$ipt_tmp -A PSW $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN

				[ -n "$udp_port" ] && {
					if [ -n "${udp_proxy_mode}" ]; then
						msg2="${msg}使用 UDP 节点[$udp_node_remark]"
						msg2="${msg2}(TPROXY:${udp_port})"

						$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP -j PSW_RULE
						[ "${use_proxy_list}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $black_set_name) -j PSW_RULE"
						[ "${use_gfw_list}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $gfw_set_name) -j PSW_RULE"
						[ "${chn_list}" != "0" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $IPSET_CHN) $(get_jump_ipt ${chn_list} "-j PSW_RULE")"
						[ "${use_shunt_udp}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $shunt_set_name) -j PSW_RULE"
						[ "${udp_proxy_mode}" != "disable" ] && add_port_rules "$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "-j PSW_RULE"
						$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $udp_port TPROXY)

						[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
							$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP_6 -j PSW_RULE 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $black6_set_name) -j PSW_RULE" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $gfw6_set_name) -j PSW_RULE" 2>/dev/null
							[ "${chn_list}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $IPSET_CHN6) $(get_jump_ipt ${chn_list} "-j PSW_RULE")" 2>/dev/null
							[ "${use_shunt_udp}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "$(dst $shunt6_set_name) -j PSW_RULE" 2>/dev/null
							[ "${udp_proxy_mode}" != "disable" ] && add_port_rules "$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "-j PSW_RULE" 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $udp_port TPROXY) 2>/dev/null
						}
					else
						msg2="${msg}不代理 UDP"
					fi
					echolog "     - ${msg2}"
				}
				[ "$_ipv4" != "1" ] && $ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp -j RETURN 2>/dev/null
				$ipt_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp -j RETURN
				unset ipt_tmp ipt_j _ipt_source msg msg2 _ipv4
			done
			unset enabled sid remarks sources use_global_config use_direct_list use_proxy_list use_block_list use_gfw_list chn_list tcp_proxy_mode udp_proxy_mode dns_redirect_port tcp_no_redir_ports udp_no_redir_ports tcp_proxy_drop_ports udp_proxy_drop_ports tcp_redir_ports udp_redir_ports tcp_node udp_node interface
			unset tcp_port udp_port tcp_node_remark udp_node_remark _acl_list use_shunt_tcp use_shunt_udp dns_redirect
		done
	}
	
	[ "$ENABLED_DEFAULT_ACL" == 1 ] && [ "$CLIENT_PROXY" == 1 ] && {
		msg="【默认】，"
		local ipt_tmp=$ipt_n
		[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m

		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_NO_REDIR_PORTS "-j RETURN"
			add_port_rules "$ipt_tmp -A PSW $(comment "默认") -p tcp" $TCP_NO_REDIR_PORTS "-j RETURN"
			if ! has_1_65535 "$TCP_NO_REDIR_PORTS"; then
				echolog "     - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset TCP_PROXY_MODE
				echolog "     - ${msg}不代理所有 TCP 端口"
			fi
		}
		
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_NO_REDIR_PORTS "-j RETURN"
			add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_NO_REDIR_PORTS "-j RETURN"
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
			$ipt_m -A PSW $(comment "默认") -p udp --dport 53 -j RETURN
			$ip6t_m -A PSW $(comment "默认") -p udp --dport 53 -j RETURN 2>/dev/null
			$ipt_m -A PSW $(comment "默认") -p tcp --dport 53 -j RETURN
			$ip6t_m -A PSW $(comment "默认") -p tcp --dport 53 -j RETURN 2>/dev/null
			$ipt_n -A PSW_DNS $(comment "默认") -p udp --dport 53 -j REDIRECT --to-ports ${DNS_REDIRECT}
			$ip6t_n -A PSW_DNS $(comment "默认") -p udp --dport 53 -j REDIRECT --to-ports ${DNS_REDIRECT} 2>/dev/null
			$ipt_n -A PSW_DNS $(comment "默认") -p tcp --dport 53 -j REDIRECT --to-ports ${DNS_REDIRECT}
			$ip6t_n -A PSW_DNS $(comment "默认") -p tcp --dport 53 -j REDIRECT --to-ports ${DNS_REDIRECT} 2>/dev/null
		fi

		[ -n "${TCP_PROXY_MODE}" -o -n "${UDP_PROXY_MODE}" ] && {
			[ "${USE_BLOCK_LIST}" = "1" ] && $ipt_m -A PSW $(comment "默认") $(dst $IPSET_BLOCK) -j DROP
			[ "${USE_DIRECT_LIST}" = "1" ] && $ipt_tmp -A PSW $(comment "默认") $(dst $IPSET_WHITE) -j RETURN
			[ "$PROXY_IPV6" == "1" ] && {
				[ "${USE_BLOCK_LIST}" = "1" ] && $ip6t_m -A PSW $(comment "默认") $(dst $IPSET_BLOCK6) -j DROP 2>/dev/null
				[ "${USE_DIRECT_LIST}" = "1" ] && $ip6t_m -A PSW $(comment "默认") $(dst $IPSET_WHITE6) -j RETURN 2>/dev/null
			}
			
			[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
				[ "$PROXY_IPV6" == "1" ] && {
					add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "-d $FAKE_IP_6 -j DROP"
					[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_BLACK6) -j DROP"
					[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_GFW6) -j DROP"
					[ "${CHN_LIST}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST} "-j DROP")"
					[ "${USE_SHUNT_TCP}" = "1" ] && $ip6t_m -A PSW $(comment "默认") -p tcp $TCP_PROXY_DROP_PORTS "$(dst $IPSET_SHUNT6) -j DROP"
					[ "${TCP_PROXY_MODE}" != "disable" ] && $ip6t_m -A PSW $(comment "默认") -p tcp $TCP_PROXY_DROP_PORTS "-j DROP"
				}
				add_port_rules "$ipt_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "-d $FAKE_IP -j DROP"
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_BLACK) -j DROP"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_GFW) -j DROP"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "-j DROP")"
				[ "${USE_SHUNT_TCP}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS $(dst $IPSET_SHUNT) "-j DROP"
				[ "${TCP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p tcp" $TCP_PROXY_DROP_PORTS "-j DROP"
				echolog "     - ${msg}屏蔽代理 TCP 端口[${TCP_PROXY_DROP_PORTS}]"
			}
			
			[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
				[ "$PROXY_IPV6" == "1" ] && {
					add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "-d $FAKE_IP_6 -j DROP"
					[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_BLACK6) -j DROP"
					[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_GFW6) -j DROP"
					[ "${CHN_LIST}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST} "-j DROP")"
					[ "${USE_SHUNT_TCP}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_SHUNT6) -j DROP"
					[ "${UDP_PROXY_MODE}" != "disable" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "-j DROP"
				}
				add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "-d $FAKE_IP -j DROP"
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_BLACK) -j DROP"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_GFW) -j DROP"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "-j DROP")"
				[ "${USE_SHUNT_UDP}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_SHUNT) -j DROP"
				[ "${UDP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_PROXY_DROP_PORTS "-j DROP"
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
					ipt_j="-j PSW_RULE"
				else
					msg2="${msg2}(REDIRECT:${TCP_REDIR_PORT})"
					ipt_j="$(REDIRECT $TCP_REDIR_PORT)"
				fi
				
				[ "$accept_icmp" = "1" ] && {
					$ipt_n -A PSW $(comment "默认") -p icmp -d $FAKE_IP $(REDIRECT)
					[ "${USE_PROXY_LIST}" = "1" ] && $ipt_n -A PSW $(comment "默认") -p icmp $(dst $IPSET_BLACK) $(REDIRECT)
					[ "${USE_GFW_LIST}" = "1" ] && $ipt_n -A PSW $(comment "默认") -p icmp $(dst $IPSET_GFW) $(REDIRECT)
					[ "${CHN_LIST}" != "0" ] && $ipt_n -A PSW $(comment "默认") -p icmp $(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST})
					[ "${USE_SHUNT_TCP}" = "1" ] && $ipt_n -A PSW $(comment "默认") -p icmp $(dst $IPSET_SHUNT) $(REDIRECT)
					[ "${TCP_PROXY_MODE}" != "disable" ] && $ipt_n -A PSW $(comment "默认") -p icmp $(REDIRECT)
				}
				
				[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
					$ip6t_n -A PSW $(comment "默认") -p ipv6-icmp -d $FAKE_IP_6 $(REDIRECT)
					[ "${USE_PROXY_LIST}" = "1" ] && $ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(dst $IPSET_BLACK6) $(REDIRECT)
					[ "${USE_GFW_LIST}" = "1" ] && $ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(dst $IPSET_GFW6) $(REDIRECT)
					[ "${CHN_LIST}" != "0" ] && $ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST})
					[ "${USE_SHUNT_TCP}" = "1" ] && $ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(dst $IPSET_SHUNT6) $(REDIRECT)
					[ "${TCP_PROXY_MODE}" != "disable" ] && $ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(REDIRECT)
				}

				$ipt_tmp -A PSW $(comment "默认") -p tcp -d $FAKE_IP ${ipt_j}
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_tmp -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_BLACK) ${ipt_j}"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_tmp -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_GFW) ${ipt_j}"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_tmp -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "${ipt_j}")"
				[ "${USE_SHUNT_TCP}" = "1" ] && add_port_rules "$ipt_tmp -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_SHUNT) ${ipt_j}"
				[ "${TCP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_tmp -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "${ipt_j}"
				[ -n "${is_tproxy}" ]&& $ipt_tmp -A PSW $(comment "默认") -p tcp $(REDIRECT $TCP_REDIR_PORT TPROXY)

				[ "$PROXY_IPV6" == "1" ] && {
					$ip6t_m -A PSW $(comment "默认") -p tcp -d $FAKE_IP_6 -j PSW_RULE
					[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_BLACK6) -j PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_GFW6) -j PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST} "-j PSW_RULE")"
					[ "${USE_SHUNT_TCP}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_SHUNT6) -j PSW_RULE"
					[ "${TCP_PROXY_MODE}" != "disable" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p tcp" $TCP_REDIR_PORTS "-j PSW_RULE"
					$ip6t_m -A PSW $(comment "默认") -p tcp $(REDIRECT $TCP_REDIR_PORT TPROXY)
				}

				echolog "     - ${msg2}"
			}
		fi
		$ipt_n -A PSW $(comment "默认") -p tcp -j RETURN
		$ipt_m -A PSW $(comment "默认") -p tcp -j RETURN
		$ip6t_m -A PSW $(comment "默认") -p tcp -j RETURN

		#  加载UDP默认代理模式
		if [ -n "${UDP_PROXY_MODE}" ]; then
			[ -n "$UDP_NODE" -o "$TCP_UDP" = "1" ] && {
				if is_socks_wrap "$UDP_NODE"; then
					msg2="${msg}使用 UDP 节点[Socks 配置($(config_n_get ${UDP_NODE#Socks_} port) 端口)](TPROXY:${UDP_REDIR_PORT})"
				else
					msg2="${msg}使用 UDP 节点[$(config_n_get $UDP_NODE remarks)](TPROXY:${UDP_REDIR_PORT})"
				fi

				$ipt_m -A PSW $(comment "默认") -p udp -d $FAKE_IP -j PSW_RULE
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_BLACK) -j PSW_RULE"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_GFW) -j PSW_RULE"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "-j PSW_RULE")"
				[ "${USE_SHUNT_UDP}" = "1" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_SHUNT) -j PSW_RULE"
				[ "${UDP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "-j PSW_RULE"
				$ipt_m -A PSW $(comment "默认") -p udp $(REDIRECT $UDP_REDIR_PORT TPROXY)

				[ "$PROXY_IPV6" == "1" ] && {
					$ip6t_m -A PSW $(comment "默认") -p udp -d $FAKE_IP_6 -j PSW_RULE
					[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_BLACK6) -j PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_GFW6) -j PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST} "-j PSW_RULE")"
					[ "${USE_SHUNT_UDP}" = "1" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_SHUNT6) -j PSW_RULE"
					[ "${UDP_PROXY_MODE}" != "disable" ] && add_port_rules "$ip6t_m -A PSW $(comment "默认") -p udp" $UDP_REDIR_PORTS "-j PSW_RULE"
					$ip6t_m -A PSW $(comment "默认") -p udp $(REDIRECT $UDP_REDIR_PORT TPROXY)
				}

				echolog "     - ${msg2}"
			}
		fi
		$ipt_m -A PSW $(comment "默认") -p udp -j RETURN
		$ip6t_m -A PSW $(comment "默认") -p udp -j RETURN
	}
}

filter_haproxy() {
	for item in ${haproxy_items}; do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		ipset -q add $IPSET_VPS $ip
	done
	echolog "  - [$?]加入负载均衡的节点到ipset[$IPSET_VPS]直连完成"
}

filter_vpsip() {
	uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPS &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	echolog "  - [$?]加入所有IPv4节点到ipset[$IPSET_VPS]直连完成"
	uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPS6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	echolog "  - [$?]加入所有IPv6节点到ipset[$IPSET_VPS6]直连完成"
}

filter_server_port() {
	local address=${1}
	local port=${2}
	local stream=${3}
	stream=$(echo ${3} | tr 'A-Z' 'a-z')
	local _is_tproxy ipt_tmp
	ipt_tmp=$ipt_n
	_is_tproxy=${is_tproxy}
	[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
	[ -n "${_is_tproxy}" ] && ipt_tmp=$ipt_m

	for _ipt in 4 6; do
		[ "$_ipt" == "4" ] && _ipt=$ipt_tmp
		[ "$_ipt" == "6" ] && _ipt=$ip6t_m
		$_ipt -n -L PSW_OUTPUT | grep -q "${address}:${port}"
		if [ $? -ne 0 ]; then
			$_ipt -I PSW_OUTPUT $(comment "${address}:${port}") -p $stream -d $address --dport $port -j RETURN 2>/dev/null
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
	echolog "开始加载 iptables 防火墙规则..."
	ipset -! create $IPSET_LOCAL nethash maxelem 1048576
	ipset -! create $IPSET_WAN nethash maxelem 1048576
	ipset -! create $IPSET_LAN nethash maxelem 1048576
	ipset -! create $IPSET_VPS nethash maxelem 1048576
	ipset -! create $IPSET_SHUNT nethash maxelem 1048576 timeout 172800
	ipset -! create $IPSET_GFW nethash maxelem 1048576 timeout 172800
	ipset -! create $IPSET_CHN nethash maxelem 1048576 timeout 172800
	ipset -! create $IPSET_BLACK nethash maxelem 1048576 timeout 172800
	ipset -! create $IPSET_WHITE nethash maxelem 1048576 timeout 172800
	ipset -! create $IPSET_BLOCK nethash maxelem 1048576 timeout 172800

	ipset -! create $IPSET_LOCAL6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_WAN6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_LAN6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_VPS6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_SHUNT6 nethash family inet6 maxelem 1048576 timeout 172800
	ipset -! create $IPSET_GFW6 nethash family inet6 maxelem 1048576 timeout 172800
	ipset -! create $IPSET_CHN6 nethash family inet6 maxelem 1048576 timeout 172800
	ipset -! create $IPSET_BLACK6 nethash family inet6 maxelem 1048576 timeout 172800
	ipset -! create $IPSET_WHITE6 nethash family inet6 maxelem 1048576 timeout 172800
	ipset -! create $IPSET_BLOCK6 nethash family inet6 maxelem 1048576 timeout 172800

	cat $RULES_PATH/chnroute | tr -s '\n' | grep -v "^#" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_CHN &/g" -e "s/$/ timeout 0/g" | ipset -! -R
	cat $RULES_PATH/chnroute6 | tr -s '\n' | grep -v "^#" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_CHN6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R

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
		cat $RULES_PATH/direct_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_WHITE &/g" -e "s/$/ timeout 0/g" | ipset -! -R
		cat $RULES_PATH/direct_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_WHITE6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
		[ "$USE_GEOVIEW" = "1" ] && {
			local GEOIP_CODE=$(cat $RULES_PATH/direct_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
			if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
				get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_WHITE &/g" -e "s/$/ timeout 0/g" | ipset -! -R
				get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_WHITE6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
				echolog "  - [$?]解析并加入[直连列表] GeoIP 到 IPSET 完成"
			fi
		}
	}

	#代理列表
	[ "$USE_PROXY_LIST_ALL" = "1" ] && {
		cat $RULES_PATH/proxy_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_BLACK &/g" -e "s/$/ timeout 0/g" | ipset -! -R
		cat $RULES_PATH/proxy_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_BLACK6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
		[ "$USE_GEOVIEW" = "1" ] && {
			local GEOIP_CODE=$(cat $RULES_PATH/proxy_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
			if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
				get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_BLACK &/g" -e "s/$/ timeout 0/g" | ipset -! -R
				get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_BLACK6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
				echolog "  - [$?]解析并加入[代理列表] GeoIP 到 IPSET 完成"
			fi
		}
	}

	#屏蔽列表
	[ "$USE_BLOCK_LIST_ALL" = "1" ] && {
		cat $RULES_PATH/block_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_BLOCK &/g" -e "s/$/ timeout 0/g" | ipset -! -R
		cat $RULES_PATH/block_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_BLOCK6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
		[ "$USE_GEOVIEW" = "1" ] && {
			local GEOIP_CODE=$(cat $RULES_PATH/block_ip | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
			if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
				get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_BLOCK &/g" -e "s/$/ timeout 0/g" | ipset -! -R
				get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_BLOCK6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
				echolog "  - [$?]解析并加入[屏蔽列表] GeoIP 到 IPSET 完成"
			fi
		}
	}

	#分流列表
	[ "$USE_SHUNT_NODE" = "1" ] && {
		local GEOIP_CODE=""
		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_SHUNT &/g" -e "s/$/ timeout 0/g" | ipset -! -R
			config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_SHUNT6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
			[ "$USE_GEOVIEW" = "1" ] && {
				local geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
				[ -n "$geoip_code" ] && GEOIP_CODE="${GEOIP_CODE:+$GEOIP_CODE,}$geoip_code"
			}
		done
		if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
			get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_SHUNT &/g" -e "s/$/ timeout 0/g" | ipset -! -R
			get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_SHUNT6 &/g" -e "s/$/ timeout 0/g" | ipset -! -R
			echolog "  - [$?]解析并加入[分流节点] GeoIP 到 IPSET 完成"
		fi
	}
	
	ipset -! -R <<-EOF
		$(ip address show | grep -w "inet" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/^/add $IPSET_LOCAL /")
	EOF

	ipset -! -R <<-EOF
		$(ip address show | grep -w "inet6" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/^/add $IPSET_LOCAL6 /")
	EOF

	#局域网IP列表
	ipset -! -R <<-EOF
		$(gen_lanlist | sed -e "s/^/add $IPSET_LAN /")
	EOF

	ipset -! -R <<-EOF
		$(gen_lanlist_6 | sed -e "s/^/add $IPSET_LAN6 /")
	EOF

	# 忽略特殊IP段
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#echolog "本机IPv4网段互访直连：${lan_ip}"
		#echolog "本机IPv6网段互访直连：${lan_ip6}"

		[ -n "$lan_ip" ] && ipset -! -R <<-EOF
			$(echo $lan_ip | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_LAN /")
		EOF

		[ -n "$lan_ip6" ] && ipset -! -R <<-EOF
			$(echo $lan_ip6 | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_LAN6 /")
		EOF
	}

	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP DNS 例外..."
		for ispip in $ISP_DNS; do
			ipset -! add $IPSET_WHITE $ispip timeout 0
			echolog "  - [$?]追加ISP IPv4 DNS到白名单：${ispip}"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		#echolog "处理 ISP IPv6 DNS 例外..."
		for ispip6 in $ISP_DNS6; do
			ipset -! add $IPSET_WHITE6 $ispip6 timeout 0
			echolog "  - [$?]追加ISP IPv6 DNS到白名单：${ispip6}"
		done
	}

	#  过滤所有节点IP
	filter_vpsip > /dev/null 2>&1 &
	# filter_haproxy > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	if [ "${TCP_PROXY_WAY}" = "redirect" ]; then
		unset is_tproxy
	elif [ "${TCP_PROXY_WAY}" = "tproxy" ]; then
		is_tproxy="TPROXY"
	fi

	$ipt_n -N PSW
	$ipt_n -A PSW $(dst $IPSET_LAN) -j RETURN
	$ipt_n -A PSW $(dst $IPSET_VPS) -j RETURN

	WAN_IP=$(get_wan_ips ip4)
	[ ! -z "${WAN_IP}" ] && {
		for wan_ip in $WAN_IP; do
			$ipt_n -A PSW $(comment "WAN_IP_RETURN") -d "${wan_ip}" -j RETURN
		done
	}
	
	[ "$accept_icmp" = "1" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW"
	[ -z "${is_tproxy}" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW"

	$ipt_n -N PSW_OUTPUT
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_LAN) -j RETURN
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_VPS) -j RETURN
	[ "${USE_DIRECT_LIST}" = "1" ] && $ipt_n -A PSW_OUTPUT $(dst $IPSET_WHITE) -j RETURN
	$ipt_n -A PSW_OUTPUT -m mark --mark 0xff -j RETURN

	$ipt_n -N PSW_DNS
	if [ $(config_t_get global dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ipt_n -I PREROUTING $(dst $IPSET_LOCAL) -j PSW_DNS
	else
		$ipt_n -I PREROUTING 1 -j PSW_DNS
	fi

	$ipt_m -N PSW_DIVERT
	$ipt_m -A PSW_DIVERT -j MARK --set-mark 1
	$ipt_m -A PSW_DIVERT -j ACCEPT

	$ipt_m -N PSW_RULE
	$ipt_m -A PSW_RULE -j CONNMARK --restore-mark
	$ipt_m -A PSW_RULE -m mark --mark 1 -j RETURN
	$ipt_m -A PSW_RULE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j MARK --set-xmark 1
	$ipt_m -A PSW_RULE -p udp -m conntrack --ctstate NEW -j MARK --set-xmark 1
	$ipt_m -A PSW_RULE -j CONNMARK --save-mark

	$ipt_m -N PSW
	$ipt_m -A PSW $(dst $IPSET_LAN) -j RETURN
	$ipt_m -A PSW $(dst $IPSET_VPS) -j RETURN
	
	[ ! -z "${WAN_IP}" ] && {
		ipset -F $IPSET_WAN
		for wan_ip in $WAN_IP; do
			ipset -! add $IPSET_WAN ${wan_ip}
			echolog "  - [$?]追加WAN IPv4到iptables：${wan_ip}"
		done
		$ipt_m -A PSW $(comment "WAN_IP_RETURN") $(dst $IPSET_WAN) -j RETURN
	}
	unset WAN_IP wan_ip

	insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW"
	insert_rule_before "$ipt_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT"

	$ipt_m -N PSW_OUTPUT
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_LAN) -j RETURN
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_VPS) -j RETURN

	[ -n "$IPT_APPEND_DNS" ] && {
		local local_dns dns_address dns_port
		for local_dns in $(echo $IPT_APPEND_DNS | tr ',' ' '); do
			dns_address=$(echo "$local_dns" | sed -E 's/(@|\[)?([0-9a-fA-F:.]+)(@|#|$).*/\2/')
			dns_port=$(echo "$local_dns" | sed -nE 's/.*#([0-9]+)$/\1/p')
			if echo "$dns_address" | grep -q -v ':'; then
				$ipt_m -A PSW_OUTPUT -p udp -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				$ipt_m -A PSW_OUTPUT -p tcp -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				echolog "  - [$?]追加直连DNS到iptables：${dns_address}:${dns_port:-53}"
			else
				$ip6t_m -A PSW_OUTPUT -p udp -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				$ip6t_m -A PSW_OUTPUT -p tcp -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				echolog "  - [$?]追加直连DNS到iptables：[${dns_address}]:${dns_port:-53}"
			fi
		done
	}

	[ "${USE_BLOCK_LIST}" = "1" ] && $ipt_m -A PSW_OUTPUT $(dst $IPSET_BLOCK) -j DROP
	[ "${USE_DIRECT_LIST}" = "1" ] && $ipt_m -A PSW_OUTPUT $(dst $IPSET_WHITE) -j RETURN
	$ipt_m -A PSW_OUTPUT -m mark --mark 0xff -j RETURN

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	[ "$accept_icmpv6" = "1" ] && {
		$ip6t_n -N PSW
		$ip6t_n -A PSW $(dst $IPSET_LAN6) -j RETURN
		$ip6t_n -A PSW $(dst $IPSET_VPS6) -j RETURN
		$ip6t_n -A PREROUTING -p ipv6-icmp -j PSW

		$ip6t_n -N PSW_OUTPUT
		$ip6t_n -A PSW_OUTPUT $(dst $IPSET_LAN6) -j RETURN
		$ip6t_n -A PSW_OUTPUT $(dst $IPSET_VPS6) -j RETURN
		[ "${USE_DIRECT_LIST}" = "1" ] && $ip6t_n -A PSW_OUTPUT $(dst $IPSET_WHITE6) -j RETURN
		$ip6t_n -A PSW_OUTPUT -m mark --mark 0xff -j RETURN
	}

	$ip6t_n -N PSW_DNS
	if [ $(config_t_get global dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ip6t_n -I PREROUTING $(dst $IPSET_LOCAL6) -j PSW_DNS
	else
		$ip6t_n -I PREROUTING 1 -j PSW_DNS
	fi

	$ip6t_m -N PSW_DIVERT
	$ip6t_m -A PSW_DIVERT -j MARK --set-mark 1
	$ip6t_m -A PSW_DIVERT -j ACCEPT

	$ip6t_m -N PSW_RULE
	$ip6t_m -A PSW_RULE -j CONNMARK --restore-mark
	$ip6t_m -A PSW_RULE -m mark --mark 1 -j RETURN
	$ip6t_m -A PSW_RULE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j MARK --set-xmark 1
	$ip6t_m -A PSW_RULE -p udp -m conntrack --ctstate NEW -j MARK --set-xmark 1
	$ip6t_m -A PSW_RULE -j CONNMARK --save-mark

	$ip6t_m -N PSW
	$ip6t_m -A PSW $(dst $IPSET_LAN6) -j RETURN
	$ip6t_m -A PSW $(dst $IPSET_VPS6) -j RETURN
	
	WAN6_IP=$(get_wan_ips ip6)
	[ ! -z "${WAN6_IP}" ] && {
		ipset -F $IPSET_WAN6
		for wan6_ip in $WAN6_IP; do
			ipset -! add $IPSET_WAN6 ${wan6_ip}
			echolog "  - [$?]追加WAN IPv6到iptables：${wan6_ip}"
		done
		$ip6t_m -A PSW $(comment "WAN6_IP_RETURN") $(dst $IPSET_WAN6) -j RETURN
	}
	unset WAN6_IP wan6_ip

	insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW"
	insert_rule_before "$ip6t_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT"

	$ip6t_m -N PSW_OUTPUT
	$ip6t_m -A PSW_OUTPUT -m mark --mark 0xff -j RETURN
	$ip6t_m -A PSW_OUTPUT $(dst $IPSET_LAN6) -j RETURN
	$ip6t_m -A PSW_OUTPUT $(dst $IPSET_VPS6) -j RETURN
	[ "${USE_BLOCK_LIST}" = "1" ] && $ip6t_m -A PSW_OUTPUT $(dst $IPSET_BLOCK6) -j DROP
	[ "${USE_DIRECT_LIST}" = "1" ] && $ip6t_m -A PSW_OUTPUT $(dst $IPSET_WHITE6) -j RETURN

	ip -6 rule add fwmark 1 table 100
	ip -6 route add local ::/0 dev lo table 100
	
	[ "$TCP_UDP" = "1" ] && [ -z "$UDP_NODE" ] && UDP_NODE=$TCP_NODE

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		local ipt_tmp=$ipt_n
		if [ -n "${is_tproxy}" ]; then
			ipt_tmp=$ipt_m
			ipt_j="-j PSW_RULE"
		else
			ipt_j="$(REDIRECT $TCP_REDIR_PORT)"
		fi
		
		msg="【路由器本机】，"
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			add_port_rules "$ipt_tmp -A PSW_OUTPUT -p tcp" $TCP_NO_REDIR_PORTS "-j RETURN"
			add_port_rules "$ip6t_m -A PSW_OUTPUT -p tcp" $TCP_NO_REDIR_PORTS "-j RETURN"
			if ! has_1_65535 "$TCP_NO_REDIR_PORTS"; then
				echolog "  - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset LOCALHOST_TCP_PROXY_MODE
				echolog "  - ${msg}不代理所有 TCP 端口"
			fi
		}
		
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_NO_REDIR_PORTS "-j RETURN"
			add_port_rules "$ip6t_m -A PSW_OUTPUT -p udp" $UDP_NO_REDIR_PORTS "-j RETURN"
			if ! has_1_65535 "$UDP_NO_REDIR_PORTS"; then
				echolog "  - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				unset LOCALHOST_UDP_PROXY_MODE
				echolog "  - ${msg}不代理所有 UDP 端口"
			fi
		}

		if ([ -n "$TCP_NODE" ] && [ -n "${LOCALHOST_TCP_PROXY_MODE}" ]) || ([ -n "$UDP_NODE" ] && [ -n "${LOCALHOST_UDP_PROXY_MODE}" ]); then
			[ -n "$DNS_REDIRECT_PORT" ] && {
				$ipt_n -A OUTPUT $(comment "PSW_DNS") -p udp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT
				$ip6t_n -A OUTPUT $(comment "PSW_DNS") -p udp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT 2>/dev/null
				$ipt_n -A OUTPUT $(comment "PSW_DNS") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT
				$ip6t_n -A OUTPUT $(comment "PSW_DNS") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT 2>/dev/null
			}
		fi

		[ -n "${LOCALHOST_TCP_PROXY_MODE}" -o -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
			[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
				add_port_rules "$ipt_m -A PSW_OUTPUT -p tcp" $TCP_PROXY_DROP_PORTS "-d $FAKE_IP -j DROP"
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_BLACK) -j DROP"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_GFW) -j DROP"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "-j DROP")"
				[ "${USE_SHUNT_TCP}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p tcp" $TCP_PROXY_DROP_PORTS "$(dst $IPSET_SHUNT) -j DROP"
				[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p tcp" $TCP_PROXY_DROP_PORTS "-j DROP"
				echolog "  - ${msg}屏蔽代理 TCP 端口[${TCP_PROXY_DROP_PORTS}]"
			}
			
			[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
				add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_PROXY_DROP_PORTS "-d $FAKE_IP -j DROP"
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_BLACK) -j DROP"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_GFW) -j DROP"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "-j DROP")"
				[ "${USE_SHUNT_UDP}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_PROXY_DROP_PORTS "$(dst $IPSET_SHUNT) -j DROP"
				[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_PROXY_DROP_PORTS "-j DROP"
				echolog "  - ${msg}屏蔽代理 UDP 端口[${UDP_PROXY_DROP_PORTS}]"
			}
		}

		# 加载路由器自身代理 TCP
		if [ -n "$TCP_NODE" ]; then
			_proxy_tcp_access() {
				[ -n "${2}" ] || return 0
				if echo "${2}" | grep -q -v ':'; then
					ipset -q test $IPSET_LAN ${2}
					[ $? -eq 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 TCP 代理转发对该服务器 TCP/${3} 端口的访问"
						return 0
					}
					if [ -z "${is_tproxy}" ]; then
						$ipt_n -I PSW_OUTPUT -p tcp -d ${2} --dport ${3} $(REDIRECT $TCP_REDIR_PORT)
					else
						$ipt_m -I PSW_OUTPUT -p tcp -d ${2} --dport ${3} -j PSW_RULE
						$ipt_m -I PSW $(comment "本机") -p tcp -i lo -d ${2} --dport ${3} $(REDIRECT $TCP_REDIR_PORT TPROXY)
					fi
					echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 TCP 转发链"
				else
					ipset -q test $IPSET_LAN6 ${2}
					[ $? -eq 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 TCP 代理转发对该服务器 TCP/${3} 端口的访问"
						return 0
					}
					$ip6t_m -I PSW_OUTPUT -p tcp -d ${2} --dport ${3} -j PSW_RULE
					$ip6t_m -I PSW $(comment "本机") -p tcp -i lo -d ${2} --dport ${3} $(REDIRECT $TCP_REDIR_PORT TPROXY)
					echolog "  - [$?]将上游 DNS 服务器 [${2}]:${3} 加入到路由器自身代理的 TCP 转发链，请确保您的节点支持IPv6，并开启IPv6透明代理！"
				fi
			}
			[ -n "${TCP_PROXY_DNS}" ] && hosts_foreach REMOTE_DNS _proxy_tcp_access 53

			[ "$accept_icmp" = "1" ] && {
				$ipt_n -A OUTPUT -p icmp -j PSW_OUTPUT
				$ipt_n -A PSW_OUTPUT -p icmp -d $FAKE_IP $(REDIRECT)
				[ "${USE_PROXY_LIST}" = "1" ] && $ipt_n -A PSW_OUTPUT -p icmp $(dst $IPSET_BLACK) $(REDIRECT)
				[ "${USE_GFW_LIST}" = "1" ] && $ipt_n -A PSW_OUTPUT -p icmp $(dst $IPSET_GFW) $(REDIRECT)
				[ "${CHN_LIST}" != "0" ] && $ipt_n -A PSW_OUTPUT -p icmp $(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST})
				[ "${USE_SHUNT_TCP}" = "1" ] && $ipt_n -A PSW_OUTPUT -p icmp $(dst $IPSET_SHUNT) $(REDIRECT)
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && [ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && $ipt_n -A PSW_OUTPUT -p icmp $(REDIRECT)
			}

			[ "$accept_icmpv6" = "1" ] && {
				$ip6t_n -A OUTPUT -p ipv6-icmp -j PSW_OUTPUT
				$ip6t_n -A PSW_OUTPUT -p ipv6-icmp -d $FAKE_IP_6 $(REDIRECT)
				[ "${USE_PROXY_LIST}" = "1" ] && $ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(dst $IPSET_BLACK6) $(REDIRECT)
				[ "${USE_GFW_LIST}" = "1" ] && $ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(dst $IPSET_GFW6) $(REDIRECT)
				[ "${CHN_LIST}" != "0" ] && $ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST})
				[ "${USE_SHUNT_TCP}" = "1" ] && $ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(dst $IPSET_SHUNT6) $(REDIRECT)
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && [ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && $ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(REDIRECT)
			}

			[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && {
				$ipt_tmp -A PSW_OUTPUT -p tcp -d $FAKE_IP ${ipt_j}
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_tmp -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_BLACK) ${ipt_j}"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_tmp -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_GFW) ${ipt_j}"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_tmp -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "${ipt_j}")"
				[ "${USE_SHUNT_TCP}" = "1" ] && add_port_rules "$ipt_tmp -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_SHUNT) ${ipt_j}"
				[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_tmp -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "${ipt_j}"
				[ -n "${is_tproxy}" ] && $ipt_m -A PSW $(comment "本机") -p tcp -i lo $(REDIRECT $TCP_REDIR_PORT TPROXY)
			}
			[ -z "${is_tproxy}" ] && $ipt_n -A OUTPUT -p tcp -j PSW_OUTPUT
			[ -n "${is_tproxy}" ] && {
				$ipt_m -A PSW $(comment "本机") -p tcp -i lo -j RETURN
				insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW) -p tcp -j PSW_OUTPUT"
			}

			[ "$PROXY_IPV6" == "1" ] && {
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && {
					$ip6t_m -A PSW_OUTPUT -p tcp -d $FAKE_IP_6 -j PSW_RULE
					[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_BLACK6) -j PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_GFW6) -j PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST} "-j PSW_RULE")"
					[ "${USE_SHUNT_TCP}" = "1" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "$(dst $IPSET_SHUNT6) -j PSW_RULE"
					[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p tcp" $TCP_REDIR_PORTS "-j PSW_RULE"
					$ip6t_m -A PSW $(comment "本机") -p tcp -i lo $(REDIRECT $TCP_REDIR_PORT TPROXY)
				}
				$ip6t_m -A PSW $(comment "本机") -p tcp -i lo -j RETURN
				insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW) -p tcp -j PSW_OUTPUT"
			}
		fi

		# 加载路由器自身代理 UDP
		if [ -n "$UDP_NODE" -o "$TCP_UDP" = "1" ]; then
			_proxy_udp_access() {
				[ -n "${2}" ] || return 0
				if echo "${2}" | grep -q -v ':'; then
					ipset -q test $IPSET_LAN ${2}
					[ $? == 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 UDP 代理转发对该服务器 UDP/${3} 端口的访问"
						return 0
					}
					$ipt_m -I PSW_OUTPUT -p udp -d ${2} --dport ${3} -j PSW_RULE
					$ipt_m -I PSW $(comment "本机") -p udp -i lo -d ${2} --dport ${3} $(REDIRECT $UDP_REDIR_PORT TPROXY)
					echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 UDP 转发链"
				else
					ipset -q test $IPSET_LAN6 ${2}
					[ $? == 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 UDP 代理转发对该服务器 UDP/${3} 端口的访问"
						return 0
					}
					$ip6t_m -I PSW_OUTPUT -p udp -d ${2} --dport ${3} -j PSW_RULE
					$ip6t_m -I PSW $(comment "本机") -p udp -i lo -d ${2} --dport ${3} $(REDIRECT $UDP_REDIR_PORT TPROXY)
					echolog "  - [$?]将上游 DNS 服务器 [${2}]:${3} 加入到路由器自身代理的 UDP 转发链，请确保您的节点支持IPv6，并开启IPv6透明代理！"
				fi
			}
			[ -n "${UDP_PROXY_DNS}" ] && hosts_foreach REMOTE_DNS _proxy_udp_access 53
			[ -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
				$ipt_m -A PSW_OUTPUT -p udp -d $FAKE_IP -j PSW_RULE
				[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_BLACK) -j PSW_RULE"
				[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_GFW) -j PSW_RULE"
				[ "${CHN_LIST}" != "0" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_CHN) $(get_jump_ipt ${CHN_LIST} "-j PSW_RULE")"
				[ "${USE_SHUNT_UDP}" = "1" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_SHUNT) -j PSW_RULE"
				[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && add_port_rules "$ipt_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "-j PSW_RULE"
				$ipt_m -A PSW $(comment "本机") -p udp -i lo $(REDIRECT $UDP_REDIR_PORT TPROXY)
			}
			$ipt_m -A PSW $(comment "本机") -p udp -i lo -j RETURN
			insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW) -p udp -j PSW_OUTPUT"

			[ "$PROXY_IPV6" == "1" ] && {
				[ -n "$LOCALHOST_UDP_PROXY_MODE" ] && {
					$ip6t_m -A PSW_OUTPUT -p udp -d $FAKE_IP_6 -j PSW_RULE
					[ "${USE_PROXY_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_BLACK6) -j PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_GFW6) -j PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_CHN6) $(get_jump_ipt ${CHN_LIST} "-j PSW_RULE")"
					[ "${USE_SHUNT_UDP}" = "1" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "$(dst $IPSET_SHUNT6) -j PSW_RULE"
					[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && add_port_rules "$ip6t_m -A PSW_OUTPUT -p udp" $UDP_REDIR_PORTS "-j PSW_RULE"
					$ip6t_m -A PSW $(comment "本机") -p udp -i lo $(REDIRECT $UDP_REDIR_PORT TPROXY)
				}
				$ip6t_m -A PSW $(comment "本机") -p udp -i lo -j RETURN
				insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW) -p udp -j PSW_OUTPUT"
			}
		fi

		$ipt_m -I OUTPUT $(comment "mangle-OUTPUT-PSW") -o lo -j RETURN
		insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW) -m mark --mark 1 -j RETURN"
		
		$ip6t_m -I OUTPUT $(comment "mangle-OUTPUT-PSW") -o lo -j RETURN
		insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW) -m mark --mark 1 -j RETURN"
	}

	#  加载ACLS
	load_acl

	[ -d "${TMP_IFACE_PATH}" ] && {
		for iface in $(ls ${TMP_IFACE_PATH}); do
			$ipt_n -I PSW_OUTPUT -o $iface -j RETURN
			$ipt_m -I PSW_OUTPUT -o $iface -j RETURN
		done
	}

	$ipt_n -I PREROUTING $(comment "PSW") -m mark --mark 1 -j RETURN
	$ip6t_n -I PREROUTING $(comment "PSW") -m mark --mark 1 -j RETURN

	filter_direct_node_list > /dev/null 2>&1 &

	echolog "防火墙规则加载完成！"
}

del_firewall_rule() {
	for ipt in "$ipt_n" "$ipt_m" "$ip6t_n" "$ip6t_m"; do
		for chain in "PREROUTING" "OUTPUT"; do
			for i in $(seq 1 $($ipt -nL $chain | grep -c PSW)); do
				local index=$($ipt --line-number -nL $chain | grep PSW | head -1 | awk '{print $1}')
				$ipt -D $chain $index 2>/dev/null
			done
		done
		for chain in "PSW" "PSW_OUTPUT" "PSW_DIVERT" "PSW_DNS" "PSW_RULE"; do
			$ipt -F $chain 2>/dev/null
			$ipt -X $chain 2>/dev/null
		done
	done

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	destroy_ipset $IPSET_LOCAL
	destroy_ipset $IPSET_WAN
	destroy_ipset $IPSET_LAN
	destroy_ipset $IPSET_VPS
	#destroy_ipset $IPSET_SHUNT
	#destroy_ipset $IPSET_GFW
	#destroy_ipset $IPSET_CHN
	#destroy_ipset $IPSET_BLACK
	destroy_ipset $IPSET_BLOCK
	destroy_ipset $IPSET_WHITE

	destroy_ipset $IPSET_LOCAL6
	destroy_ipset $IPSET_WAN6
	destroy_ipset $IPSET_LAN6
	destroy_ipset $IPSET_VPS6
	#destroy_ipset $IPSET_SHUNT6
	#destroy_ipset $IPSET_GFW6
	#destroy_ipset $IPSET_CHN6
	#destroy_ipset $IPSET_BLACK6
	destroy_ipset $IPSET_BLOCK6
	destroy_ipset $IPSET_WHITE6

	$DIR/app.sh echolog "删除 iptables 规则完成。"
}

flush_ipset() {
	$DIR/app.sh echolog "清空 IPSet。"
	for _name in $(ipset list | grep "Name: " | grep "passwall_" | awk '{print $2}'); do
		destroy_ipset ${_name}
	done
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	extract_rules() {
		local _ipt="${ipt}"
		[ "$1" == "6" ] && _ipt="${ip6t}"
		[ -z "${_ipt}" ] && return

		echo "*$2"
		${_ipt}-save -t $2 | grep "PSW" | grep -v "\-j PSW$" | grep -v "mangle\-OUTPUT\-PSW" | grep -v "socket \-j PSW_DIVERT$" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/"
		echo 'COMMIT'
	}
	local __ipt=""
	[ -n "${ipt}" ] && {
		__ipt=$(cat <<- EOF
			mangle_output_psw=\$(${ipt}-save -t mangle | grep "PSW" | grep "mangle\-OUTPUT\-PSW" | sed "s#-A OUTPUT ##g")
			$ipt-save -c | grep -v "PSW" | $ipt-restore -c
			$ipt-restore -n <<-EOT
			$(extract_rules 4 nat)
			$(extract_rules 4 mangle)
			EOT

			echo "\${mangle_output_psw}" | while read line; do
				\$(${MY_PATH} insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "\${line}")
			done

			[ "$accept_icmp" = "1" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW")
			[ -z "${is_tproxy}" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW")

			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW")
			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT")

			WAN_IP=\$(${MY_PATH} get_wan_ips ip4)
			[ ! -z "\${WAN_IP}" ] && {
				ipset -F $IPSET_WAN
				for wan_ip in \$WAN_IP; do
					ipset -! add $IPSET_WAN \${wan_ip}
				done
			}
			fi
		EOF
		)
	}
	local __ip6t=""
	[ -n "${ip6t}" ] && {
		__ip6t=$(cat <<- EOF
			mangle_output_psw=\$(${ip6t}-save -t mangle | grep "PSW" | grep "mangle\-OUTPUT\-PSW" | sed "s#-A OUTPUT ##g")
			$ip6t-save -c | grep -v "PSW" | $ip6t-restore -c
			$ip6t-restore -n <<-EOT
			$(extract_rules 6 nat)
			$(extract_rules 6 mangle)
			EOT

			echo "\${mangle_output_psw}" | while read line; do
				\$(${MY_PATH} insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "\${line}")
			done

			[ "$accept_icmpv6" = "1" ] && $ip6t_n -A PREROUTING -p ipv6-icmp -j PSW

			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW")
			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT")

			WAN6_IP=\$(${MY_PATH} get_wan_ips ip6)
			[ ! -z "\${WAN6_IP}" ] && {
				ipset -F $IPSET_WAN6
				for wan6_ip in \$WAN6_IP; do
					ipset -! add $IPSET_WAN6 \${wan6_ip}
				done
			}
		EOF
		)
	}
	cat <<-EOF >> $FWI
		${__ipt}
		
		${__ip6t}

		return 0
	EOF
	return 0
}

get_ipt_bin() {
	echo $ipt
}

get_ip6t_bin() {
	echo $ip6t
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
		flush_ipset
		rm -rf /tmp/etc/passwall_tmp/singbox*
		rm -rf /tmp/etc/passwall_tmp/dnsmasq*
	}
	flush_include
}

arg1=$1
shift
case $arg1 in
RULE_LAST_INDEX)
	RULE_LAST_INDEX "$@"
	;;
insert_rule_before)
	insert_rule_before "$@"
	;;
insert_rule_after)
	insert_rule_after "$@"
	;;
get_ipt_bin)
	get_ipt_bin
	;;
get_ip6t_bin)
	get_ip6t_bin
	;;
get_wan_ips)
	get_wan_ips
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
