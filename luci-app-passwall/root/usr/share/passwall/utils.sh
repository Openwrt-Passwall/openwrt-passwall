#!/bin/sh
# Copyright (C) 2022-2025 xiaorouji
# Copyright (C) 2026 Openwrt-Passwall Organization

CONFIG=passwall
APP_PATH=/usr/share/${CONFIG}
TMP_PATH=/tmp/etc/${CONFIG}
TMP_PATH2=${TMP_PATH}_tmp
LOCK_PATH=/tmp/lock
LOG_FILE=/tmp/log/${CONFIG}.log
TMP_ACL_PATH=${TMP_PATH}/acl
TMP_BIN_PATH=${TMP_PATH}/bin
TMP_IFACE_PATH=${TMP_PATH}/iface
TMP_ROUTE_PATH=${TMP_PATH}/route
TMP_SCRIPT_FUNC_PATH=${TMP_PATH}/script_func
RULES_PATH=/usr/share/${CONFIG}/rules

. /lib/functions/network.sh

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$LOG_FILE
}

clean_log() {
	logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	[ "$logsnum" -gt 1000 ] && {
		echo "" > $LOG_FILE
		echolog "日志文件过长，清空处理！"
	}
}

config_get_type() {
	local ret=$(uci -q get "${CONFIG}.${1}" 2>/dev/null)
	echo "${ret:=$2}"
}

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

config_t_get() {
	local index=${4:-0}
	local ret=$(uci -q get "${CONFIG}.@${1}[${index}].${2}" 2>/dev/null)
	echo "${ret:=${3}}"
}

config_t_set() {
	local index=${4:-0}
	local ret=$(uci -q set "${CONFIG}.@${1}[${index}].${2}=${3}" 2>/dev/null)
}

first_type() {
	[ "${1#/}" != "$1" ] && [ -x "$1" ] && echo "$1" && return
	for p in "/bin/$1" "/usr/bin/$1" "${TMP_BIN_PATH:-/tmp}/$1"; do
		[ -x "$p" ] && echo "$p" && return
	done
	command -v "$1" 2>/dev/null || command -v "$2" 2>/dev/null
}

get_enabled_anonymous_secs() {
	uci -q show "${CONFIG}" | grep "${1}\[.*\.enabled='1'" | cut -d '.' -sf2
}

get_geoip() {
	local geo_output_path="$TMP_PATH2/geo_output"
	mkdir -p ${geo_output_path}
	local geoip_code="$1"
	local geoip_type_flag=""
	local output_path="${geo_output_path}/geoip-${geoip_code}-$2"
	[ ! -s "${output_path}" ] && {
		local geoip_path="$(config_t_get global_rules v2ray_location_asset)"
		geoip_path="${geoip_path%*/}/geoip.dat"
		local bin="$(first_type $(config_t_get global_app geoview_file) geoview)"
		[ -n "$bin" ] && [ -s "$geoip_path" ] || { echo ""; return; }
		case "$2" in
			"ipv4") geoip_type_flag="-ipv6=false" ;;
			"ipv6") geoip_type_flag="-ipv4=false" ;;
		esac
		"$bin" -input "$geoip_path" -list "$geoip_code" $geoip_type_flag -lowmem=true -output ${output_path}
	}
	[ -s "${output_path}" ] && cat "${output_path}"
}

get_host_ip() {
	local host=$2
	local count=$3
	[ -z "$count" ] && count=3
	local isip=""
	local ip=""
	if [ "$1" == "ipv6" ]; then
		isip=$(echo $host | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		if [ -n "$isip" ]; then
			ip=$(echo "$host" | tr -d '[]')
		fi
	else
		isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
		[ -n "$isip" ] && ip=$isip
	fi
	[ -z "$isip" ] && {
		local t=4
		[ "$1" == "ipv6" ] && t=6
		local vpsrip=$(resolveip -$t -t $count $host | awk 'NR==1{print}')
		ip=$vpsrip
	}
	[ -n "$ip" ] && echo "$ip"
}

get_node_host_ip() {
	local ip
	local address=$(config_n_get $1 address)
	[ -n "$address" ] && {
		local use_ipv6=$(config_n_get $1 use_ipv6)
		local network_type="ipv4"
		[ "$use_ipv6" == "1" ] && network_type="ipv6"
		ip=$(get_host_ip $network_type $address)
	}
	echo $ip
}

get_ip_port_from() {
	local __host=${1}; shift 1
	local __ipv=${1}; shift 1
	local __portv=${1}; shift 1
	local __ucipriority=${1}; shift 1

	local val1 val2
	val2=$(echo "$__host" | sed -n '
		s/^[^#]*[#]\([0-9]*\)$/\1/p; t;
		s/^\(\[[^]]*\]\)[:]\([0-9]*\)$/\2/p; t;
		s/^.*[:#]\([0-9]*\)$/\1/p
	')
	if [ -n "${__ucipriority}" ]; then
		val2=$(config_n_get ${__host} port "${val2}")
		val1=$(config_n_get ${__host} address "${__host%%${val2:+[:#]${val2}*}}")
	else
		val1="${__host%%${val2:+[:#]${val2}*}}"
	fi
	eval "${__ipv}=\"$val1\"; ${__portv}=\"$val2\""
}

parse_doh() {
	local __doh=$1 __url_var=$2 __host_var=$3 __port_var=$4 __bootstrap_var=$5
	__doh=$(echo -e "$__doh" | tr -d ' \t\n')
	local __url=${__doh%%,*}
	local __bootstrap=${__doh#*,}
	local __host_port=$(lua_api "get_domain_from_url(\"${__url}\")")
	local __host __port
	if echo "${__host_port}" | grep -q '^\[.*\]:[0-9]\+$'; then
		__host=${__host_port%%]:*}]
		__port=${__host_port##*:}
	elif echo "${__host_port}" | grep -q ':[0-9]\+$'; then
		__host=${__host_port%:*}
		__port=${__host_port##*:}
	else
		__host=${__host_port}
		__port=443
	fi
	__host=${__host#[}
	__host=${__host%]}
	if [ "$(lua_api "is_ip(\"${__host}\")")" = "true" ]; then
		__bootstrap=${__host}
	fi
	__bootstrap=${__bootstrap#[}
	__bootstrap=${__bootstrap%]}
	eval "${__url_var}='${__url}' ${__host_var}='${__host}' ${__port_var}='${__port}' ${__bootstrap_var}='${__bootstrap}'"
}

host_from_url(){
	local f="${1}"

	## Remove protocol part of url  ##
	f="${f##http://}"
	f="${f##https://}"
	f="${f##ftp://}"
	f="${f##sftp://}"

	## Remove username and/or username:password part of URL  ##
	f="${f##*:*@}"
	f="${f##*@}"

	## Remove rest of urls ##
	f="${f%%/*}"
	echo "${f%%:*}"
}

hosts_foreach() {
	local __hosts
	eval "__hosts=\$${1}"; shift 1
	local __func=${1}; shift 1
	local __default_port=${1}; shift 1
	local __ret=1

	[ -z "${__hosts}" ] && return 0
	local __ip __port
	for __host in $(echo $__hosts | sed 's/[ ,]/\n/g'); do
		get_ip_port_from "$__host" "__ip" "__port"
		eval "$__func \"${__host}\" \"\${__ip}\" \"\${__port:-${__default_port}}\" \"$@\""
		__ret=$?
		[ ${__ret} -ge ${ERROR_NO_CATCH:-1} ] && return ${__ret}
	done
}

check_host() {
	local f=${1}
	a=$(echo $f | grep "\/")
	[ -n "$a" ] && return 1
	# 判断是否包含汉字~
	local tmp=$(echo -n $f | awk '{print gensub(/[!-~]/,"","g",$0)}')
	[ -n "$tmp" ] && return 1
	return 0
}

get_first_dns() {
	local __hosts_val=${1}; shift 1
	__first() {
		[ -z "${2}" ] && return 0
		echo "${2}#${3}"
		return 1
	}
	eval "hosts_foreach \"${__hosts_val}\" __first \"$@\""
}

get_last_dns() {
	local __hosts_val=${1}; shift 1
	local __first __last
	__every() {
		[ -z "${2}" ] && return 0
		__last="${2}#${3}"
		__first=${__first:-${__last}}
	}
	eval "hosts_foreach \"${__hosts_val}\" __every \"$@\""
	[ "${__first}" ==  "${__last}" ] || echo "${__last}"
}

check_port_exists() {
	local port=$1
	local protocol=$2
	[ -n "$protocol" ] || protocol="tcp,udp"
	local result=
	if [ "$protocol" = "tcp" ]; then
		result=$(netstat -tln | grep -c ":$port ")
	elif [ "$protocol" = "udp" ]; then
		result=$(netstat -uln | grep -c ":$port ")
	elif [ "$protocol" = "tcp,udp" ]; then
		result=$(netstat -tuln | grep -c ":$port ")
	fi
	echo "${result}"
}

get_new_port() {
	local default_start_port=2001
	local min_port=1025
	local max_port=49151
	local port="$1"
	local protocol=$(echo "$2" | tr 'A-Z' 'a-z')
	local LOCK_FILE="${LOCK_PATH}/${CONFIG}_get_prot.lock"
	while ! mkdir "$LOCK_FILE" 2>/dev/null; do
		sleep 0.05
	done
	if [ "$port" = "auto" ]; then
		local now last_time diff last_port
		now=$(date +%s 2>/dev/null)
		last_time=$(get_cache_var "last_get_new_port_time")
		if [ -n "$now" ] && [ -n "$last_time" ]; then
			diff=$(expr "$now" - "$last_time")
			[ "$diff" -lt 0 ] && diff=$(expr 0 - "$diff")
		else
			diff=999
		fi
		if [ "$diff" -gt 10 ]; then
			port=$default_start_port
		else
			last_port=$(get_cache_var "last_get_new_port_auto")
			if [ -n "$last_port" ]; then
				port=$(expr "$last_port" + 1)
			else
				port=$default_start_port
			fi
		fi
	fi
	[ "$port" -lt $min_port -o "$port" -gt $max_port ] && port=$default_start_port
	local start_port="$port"
	while :; do
		if [ "$(check_port_exists "$port" "$protocol")" = 0 ]; then
			break
		fi
		port=$(expr "$port" + 1)
		if [ "$port" -gt $max_port ]; then
			port=$min_port
		fi
		[ "$port" = "$start_port" ] && {
			rmdir "$LOCK_FILE" 2>/dev/null
			return 1
		}
	done
	if [ "$1" = "auto" ]; then
		set_cache_var "last_get_new_port_auto" "$port"
		[ -n "$now" ] && set_cache_var "last_get_new_port_time" "$now"
	fi
	rmdir "$LOCK_FILE" 2>/dev/null
	echo "$port"
}

check_ver() {
	local version1="$1"
	local version2="$2"
	local i v1 v1_1 v1_2 v1_3 v2 v2_1 v2_2 v2_3
	IFS='.'; set -- $version1; v1_1=${1:-0}; v1_2=${2:-0}; v1_3=${3:-0}
	IFS='.'; set -- $version2; v2_1=${1:-0}; v2_2=${2:-0}; v2_3=${3:-0}
	IFS=
	for i in 1 2 3; do
		eval v1=\$v1_$i
		eval v2=\$v2_$i
		if [ "$v1" -gt "$v2" ]; then
			# $1 大于 $2
			echo 0
			return
		elif [ "$v1" -lt "$v2" ]; then
			# $1 小于 $2
			echo 1
			return
		fi
	done
	# $1 等于 $2
	echo 255
}

eval_set_val() {
	for i in $@; do
		for j in $i; do
			eval $j
		done
	done
}

eval_unset_val() {
	for i in $@; do
		for j in $i; do
			eval unset $j
		done
	done
}

lua_api() {
	local func=${1}
	[ -z "${func}" ] && {
		echo "nil"
		return
	}
	echo $(lua -e "local api = require 'luci.passwall.api' print(api.${func})")
}

set_cache_var() {
	local key="${1}"
	shift 1
	local val="$@"
	[ -n "${key}" ] && [ -n "${val}" ] && {
		[ ! -d $TMP_PATH ] && mkdir -p $TMP_PATH
		sed -i "/${key}=/d" $TMP_PATH/var >/dev/null 2>&1
		echo "${key}=\"${val}\"" >> $TMP_PATH/var
		eval ${key}=\"${val}\"
	}
}

get_cache_var() {
	local key="${1}"
	[ -n "${key}" ] && [ -s "$TMP_PATH/var" ] && {
		echo $(cat $TMP_PATH/var | grep "^${key}=" | awk -F '=' '{print $2}' | tail -n 1 | awk -F'"' '{print $2}')
	}
}

eval_cache_var() {
	[ -s "$TMP_PATH/var" ] && eval $(cat "$TMP_PATH/var")
}

has_1_65535() {
	local val="$1"
	val=${val//:/-}
	case ",$val," in
		*,1-65535,*) return 0 ;;
		*) return 1 ;;
	esac
}

add_ip2route() {
	local ip=$(get_host_ip "ipv4" $1)
	[ -z "$ip" ] && {
		echolog "  - 无法解析[${1}]，路由表添加失败！"
		return 1
	}
	local remarks="${1}"
	[ "$remarks" != "$ip" ] && remarks="${1}(${ip})"

	local gateway device
	network_get_gateway gateway "$2"
	network_get_device device "$2"
	[ -z "${device}" ] && device=$(ubus call "network.interface.$2" status 2>/dev/null | jsonfilter -e '@.device' 2>/dev/null)
	[ -z "${device}" ] && [ -d "/sys/class/net/$2" ] && device="$2"
	[ -z "${device}" ] && device="$2"

	if [ -n "${gateway}" ]; then
		route add -host ${ip} gw ${gateway} dev ${device} >/dev/null 2>&1
		echo "$ip" >> $TMP_ROUTE_PATH/${device}
		echolog "  - [${remarks}]添加到接口[${device}]路由表成功！"
	else
		echolog "  - [${remarks}]添加到接口[${device}]路由表失功！原因是找不到[${device}]网关。"
	fi
}

delete_ip2route() {
	[ -d "${TMP_ROUTE_PATH}" ] && {
		local interface
		for interface in $(ls ${TMP_ROUTE_PATH}); do
			for ip in $(cat ${TMP_ROUTE_PATH}/${interface}); do
				route del -host ${ip} dev ${interface} >/dev/null 2>&1
			done
		done
	}
}

ln_run() {
	local file_func=${1}
	local ln_name=${2}
	local output=${3}

	shift 3;
	if [  "${file_func%%/*}" != "${file_func}" ]; then
		[ ! -L "${file_func}" ] && {
			ln -s "${file_func}" "${TMP_BIN_PATH}/${ln_name}" >/dev/null 2>&1
			file_func="${TMP_BIN_PATH}/${ln_name}"
		}
		[ -x "${file_func}" ] || echolog "  - $(readlink ${file_func}) 没有执行权限，无法启动：${file_func} $*"
	fi
	#echo "${file_func} $*" >&2
	[ -n "${file_func}" ] || echolog "  - 找不到 ${ln_name}，无法启动..."
	[ "${output}" != "/dev/null" ] && [ "${ln_name}" != "chinadns-ng" ] && {
		local persist_log_path=$(config_t_get global persist_log_path)
		local sys_log=$(config_t_get global sys_log "0")
	}
	if [ -z "$persist_log_path" ] && [ "$sys_log" != "1" ]; then
		${file_func:-echolog " - ${ln_name}"} "$@" >${output} 2>&1 &
	else
		[ "${output: -1, -7}" == "TCP.log" ] && local protocol="TCP"
		[ "${output: -1, -7}" == "UDP.log" ] && local protocol="UDP"
		if [ -n "${persist_log_path}" ]; then
			mkdir -p ${persist_log_path}
			local log_file=${persist_log_path}/passwall_${protocol}_${ln_name}_$(date '+%F').log
			echolog "记录到持久性日志文件：${log_file}"
			${file_func:-echolog " - ${ln_name}"} "$@" >> ${log_file} 2>&1 &
			sys_log=0
		fi
		if [ "${sys_log}" == "1" ]; then
			echolog "记录 ${ln_name}_${protocol} 到系统日志"
			${file_func:-echolog " - ${ln_name}"} "$@" 2>&1 | logger -t PASSWALL_${protocol}_${ln_name} &
		fi
	fi
	[ "$NO_REC_PROCESS" = "1" ] && return
	process_count=$(ls $TMP_SCRIPT_FUNC_PATH | wc -l)
	process_count=$((process_count + 1))
	echo "${file_func:-echolog "  - ${ln_name}"} $@ >${output}" > $TMP_SCRIPT_FUNC_PATH/$process_count
}

is_socks_wrap() {
	case "$1" in
		Socks_*) return 0 ;;
		*)       return 1 ;;
	esac
}

kill_all() {
	kill -9 $(pidof "$@") >/dev/null 2>&1
}

get_subscribe_host(){
	local line
	uci show "${CONFIG}" | grep "=subscribe_list" | while read -r line; do
		local section="$(echo "$line" | cut -d '.' -sf 2 | cut -d '=' -sf 1)"
		local url="$(config_n_get $section url)"
		[ -n "$url" ] || continue
		url="$(host_from_url "$url")"
		echo "$url"
	done
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
	local INTERFACES=$(ubus call network.interface dump | jsonfilter -e \
			'@.interface[!(@.interface ~ /lan/) && !(@.l3_device ~ /\./) && @.route[0]].interface')
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

get_local_ips() {
	local family="$1"
	local ALL_IPS WAN_IPS ip NET_ADDR
	if [ "$family" = "ip6" ]; then
		ALL_IPS=$(ip -o -6 addr show scope global | awk '{print $4}' | cut -d/ -f1)
		WAN_IPS=$(get_wan_ips ip6)
	else
		ALL_IPS=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1)
		WAN_IPS=$(get_wan_ips ip4)
	fi
	# 补充回环（scope global 不包含）
	[ "$family" = "ip6" ] && ALL_IPS="$ALL_IPS ::1"
	[ "$family" != "ip6" ] && ALL_IPS="$ALL_IPS 127.0.0.1"
	for ip in $ALL_IPS; do
		case "$ip" in
			""|0.0.0.0|::) continue ;;
		esac
		case " $WAN_IPS " in
			*" $ip "*) continue ;;
		esac
		case " $NET_ADDR " in
			*" $ip "*) ;;
			*) NET_ADDR="${NET_ADDR:+$NET_ADDR }$ip" ;;
		esac
	done
	for ip in $NET_ADDR; do
		echo "$ip"
	done
}
