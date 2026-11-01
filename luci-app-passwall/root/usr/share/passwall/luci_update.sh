#!/bin/sh
CONFIG=passwall
dir="$1"
status="$2"
manager="$3"
force="$4"

acl_file="/usr/share/rpcd/acl.d/luci-app-${CONFIG}.json"
acl_md5_before=$(md5sum "$acl_file" 2>/dev/null | awk '{print $1}')

if [ "$manager" = apk ]; then
	extra=""
	[ "$force" = 1 ] && extra="--force-reinstall --force-overwrite"
	apk add --allow-untrusted $extra "$dir/luci-app-${CONFIG}.apk" "$dir/luci-i18n-${CONFIG}-zh-cn.apk"
	result=$?
else
	extra=""
	[ "$force" = 1 ] && extra="--force-reinstall"
	opkg install $extra "$dir/luci-app-${CONFIG}.ipk" "$dir/luci-i18n-${CONFIG}-zh-cn.ipk"
	result=$?
fi

rm -rf "$dir"
if [ "$result" = 0 ]; then
	rm -f "/tmp/etc/${CONFIG}_tmp/${CONFIG}_version" /tmp/luci-indexcache /tmp/luci-indexcache.*
	acl_md5_after=$(md5sum "$acl_file" 2>/dev/null | awk '{print $1}')
	# rpcd only reads ACL definitions at startup. Restart it only when the ACL
	# file actually changed, so in-place updates no longer drop the web session.
	if [ "$acl_md5_before" != "$acl_md5_after" ] && [ -x /etc/init.d/rpcd ]; then
		/etc/init.d/rpcd restart >/dev/null 2>&1
	fi
	if [ -x /etc/init.d/uhttpd ]; then
		/etc/init.d/uhttpd reload >/dev/null 2>&1
	fi
fi
[ "$result" = 0 ] && echo '{"code":0}' > "$status" || echo '{"code":1}' > "$status"
(sleep 60; rm -f "$status") >/dev/null 2>&1 &
