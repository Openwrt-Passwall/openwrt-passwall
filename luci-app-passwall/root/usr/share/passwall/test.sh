#!/bin/sh

. /usr/share/passwall/utils.sh

test_url() {
	local url=$1
	local try=1
	[ -n "$2" ] && try=$2
	local timeout=2
	[ -n "$3" ] && timeout=$3
	local extra_params=$4
	local status
	local max_time=$((timeout + 3))
	local retry_max_time=$((max_time * (try + 1) + try))
	curl --help all | grep "\-\-retry-all-errors" > /dev/null
	[ $? == 0 ] && extra_params="--retry-all-errors ${extra_params}"
	status=$(/usr/bin/curl -I -o /dev/null -skL $extra_params --connect-timeout ${timeout} --max-time ${max_time} --retry ${try} --retry-delay 1 --retry-max-time ${retry_max_time} -w %{http_code} "$url") || status=000
	case "$status" in
		204|\
		200)
			status=200
		;;
	esac
	printf '%s' "$status"
}

test_proxy() {
	result=0
	status=$(test_url "https://www.google.com/generate_204" ${retry_num} ${connect_timeout})
	if [ "$status" = "200" ]; then
		result=0
	else
		status2=$(test_url "https://www.baidu.com" ${retry_num} ${connect_timeout})
		if [ "$status2" = "200" ]; then
			result=1
		else
			result=2
			ping -c 3 -W 1 223.5.5.5 > /dev/null 2>&1
			[ $? -eq 0 ] && {
				result=1
			}
		fi
	fi
	echo $result
}

node_probe() {
	local result=0
	local node_id=$1
	local probe_url=$2
	shift 2
	local test_flag="probe_${node_id}_$$"
	local _address _port curlx _username _password _tmp_port pid_file
	local _type=$(config_n_get "$node_id" type | tr 'A-Z' 'a-z')

	[ -n "${_type}" ] && {
		if [ "${_type}" == "socks" ]; then
			# 防止socks节点密码包含 #、% 等字符，将地址和认证信息分开传递
			_address=$(config_n_get "$node_id" address)
			_port=$(config_n_get "$node_id" port)
			[ -n "$_address" ] && [ -n "$_port" ] || { echo 0; return 1; }
			case "$_address" in
				\[*\]) ;;
				*:*) _address="[$_address]" ;;
			esac
			curlx="socks5h://${_address}:${_port}"
			_username=$(config_n_get "$node_id" username)
			_password=$(config_n_get "$node_id" password)
		else
			_tmp_port=$(get_new_port $((48900 + $$ % 201)) tcp,udp) || { echo 0; return 1; }
			NO_REC_PROCESS=1 /usr/share/${CONFIG}/app.sh run_socks flag="$test_flag" node="$node_id" bind=127.0.0.1 socks_port="$_tmp_port" config_file="${test_flag}.json"
			curlx="socks5h://127.0.0.1:${_tmp_port}"
		fi
		sleep 2s
		if [ "${_type}" == "socks" ] && [ -n "${_username}" ] && [ -n "${_password}" ]; then
			result=$(curl --connect-timeout 3 -o /dev/null -sk --proxy-user "${_username}:${_password}" -x "$curlx" "$@" "${probe_url}") || result=0
		else
			result=$(curl --connect-timeout 3 -o /dev/null -sk -x "$curlx" "$@" "${probe_url}") || result=0
		fi
		# 结束 SS 插件进程
		if [ "$_type" != "socks" ]; then
			pid_file="${TMP_PATH}/${test_flag}_plugin.pid"
			[ -s "$pid_file" ] && kill -9 "$(head -n 1 "$pid_file")" >/dev/null 2>&1
			busybox pgrep -af "${TMP_PATH}/${test_flag}[._]" | awk '! /test\.sh/{print $1}' | xargs -r kill -9 >/dev/null 2>&1
			rm -f "$TMP_PATH/${test_flag}".* "$TMP_PATH/${test_flag}"_*.*
		fi
	}
	printf '%s' "$result"
}

url_test_node() {
	local node_id=$1
	local probeUrl
	probeUrl=$(config_n_get @global_other[0] url_test_url https://www.google.com/generate_204)
	node_probe "$node_id" "$probeUrl" --max-time 5 -I -w "%{http_code}:%{time_pretransfer}:%{time_starttransfer}"
}

speed_test_node() {
	local node_id=$1
	# Cloudflare 测速文件 99MB（其 __down 端点 bytes 上限为 <100000000，超限返回 403）。
	# 千兆下约 0.8s 完成；--max-time 20 时最慢可测约 40Mbps，更慢节点 curl 超时（非 0 退出码）
	# 会被 node_probe 的 `|| result=0` 覆盖为 0，前端显示 Timeout 而不是部分速度。
	# 速度由 size_download / (time_total - time_starttransfer) 计算。
	node_probe "$node_id" "https://speed.cloudflare.com/__down?bytes=99000000" --max-time 20 -w "%{http_code}:%{size_download}:%{time_starttransfer}:%{time_total}"
}

arg1=$1
shift
case $arg1 in
test_url)
	test_url "$@"
	;;
url_test_node)
	url_test_node "$@"
	;;
speed_test_node)
	speed_test_node "$@"
	;;
esac
