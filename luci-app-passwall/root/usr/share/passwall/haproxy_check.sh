#!/bin/sh

export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/root/bin
. /usr/share/passwall/utils.sh

listen_address=$1
listen_port=$2
server_address=$3
server_port=$4

busybox pgrep -af "${CONFIG}/" | grep -E 'app\.sh.*(start|stop)|nftables\.sh|iptables\.sh|subscribe\.lua' >/dev/null && {
	# 特定任务执行中不检测
	exit 0
}

probeUrl=$(get_cache_var "HAPROXY_PROBE_URL")
probeUrl="${probeUrl:-https://www.google.com/generate_204}"

case "$server_address" in
	\[*\]) ;;
	*:*) server_address="[$server_address]" ;;
esac

# 每轮只探测一次，连续成功/失败由 HAProxy 的 rise/fall 判定。
status=$(/usr/bin/curl -q -I -o /dev/null -sk -A 'Mozilla/5.0' --noproxy "" -x "socks5h://${server_address}:${server_port}" --connect-timeout 3 --max-time 6 -w "%{http_code}" "$probeUrl") || exit 1

case "$status" in
	200|204)
		exit 0
	;;
	*)
		exit 1
	;;
esac
