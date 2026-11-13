#!/bin/sh
# Zray has no version command. Probe a private loopback listener with one slot;
# no upstream connection or DNS request is made. Never use the user's config.
binary="$1"
[ -x "$binary" ] || exit 1
probe_dir="$(mktemp -d /tmp/passwall_zray_probe.XXXXXX)" || exit 1
probe_pid=
cleanup() {
	if [ -n "$probe_pid" ]; then
		kill -KILL "$probe_pid" 2>/dev/null
		wait "$probe_pid" 2>/dev/null
	fi
	rm -rf "$probe_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
cat > "$probe_dir/config.json" <<EOF
{"listen":"127.0.0.1:0","sniff":false,"server":"127.0.0.1","port":443,"sni":"example.com","uuid":"00000000-0000-0000-0000-000000000000","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","max_connections":1,"bootstrap_dns":"","handshake_timeout_s":15,"connect_timeout_s":5,"idle_timeout_s":600,"sock_buf":0}
EOF
ZRAY_CRYPTO_BACKEND=off "$binary" "$probe_dir/config.json" > "$probe_dir/log" 2>&1 &
probe_pid=$!
attempt=0
while [ "$attempt" -lt 3 ]; do
	kill -0 "$probe_pid" 2>/dev/null || exit 1
	version="$(sed -n 's/^zray \([0-9][0-9A-Za-z.+_-]*\) .*/\1/p' "$probe_dir/log" | head -n 1)"
	if [ -n "$version" ]; then
		# OpenWrt's sleep may be built without fractional-second support.
		sleep 1
		kill -0 "$probe_pid" 2>/dev/null || exit 1
		printf '%s\n' "$version"
		exit 0
	fi
	sleep 1
	attempt=$((attempt + 1))
done
exit 1
