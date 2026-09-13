#!/bin/sh
# Run the real firewall script with synthetic configuration and host I/O stubs.
# No rule-generation, export, or insertion function is replaced.

action=$1
shift
set -- __load_only "$@"
. "$TEST_IPTABLES_SCRIPT"

# This helper writes directly to /proc; it is outside the rule-output seam.
set_tproxy_sysctl() { :; }
echolog() { :; }
first_type() { :; }
config_n_get() { echo "$3"; }
get_wan_ips() { :; }
get_local_ips() { :; }
get_subscribe_host() { :; }
gen_lanlist() { :; }
gen_lanlist_6() { :; }

MY_PATH=$TEST_DRIVER
CONFIG=passwall
RULES_PATH=$TEST_RULES
TMP_PATH=$TEST_TMP
TMP_IFACE_PATH=$TEST_TMP/iface
ENABLED_DEFAULT_ACL=1
ENABLED_ACLS=0
CLIENT_PROXY=1
PROXY_IPV6=1
USE_PROXY_LIST=0
USE_DIRECT_LIST=0
USE_BLOCK_LIST=0
USE_GFW_LIST=0
CHN_LIST=0
TCP_PROXY_WAY=${TEST_PROXY_WAY:-redirect}
TCP_NO_REDIR_PORTS=disable
UDP_NO_REDIR_PORTS=disable
TCP_PROXY_DROP_PORTS=disable
UDP_PROXY_DROP_PORTS=disable
DIRECT_DNSMASQ_PORT=1053
IPv4_REGEX='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
IPv6_REGEX=':'

case "$action" in
start)
	start
	wait
	;;
include)
	gen_include
	;;
reload)
	. "$FWI"
	;;
insert_rule_before)
	insert_rule_before "$@"
	;;
insert_rule_after)
	insert_rule_after "$@"
	;;
update_wan_sets)
	update_wan_sets "$@"
	;;
*)
	echo "Unsupported test action: $action" >&2
	exit 1
	;;
esac
