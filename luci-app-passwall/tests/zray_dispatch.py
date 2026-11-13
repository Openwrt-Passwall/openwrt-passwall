"""Exercise actual shell dispatch without installing services/firewall rules.

Run from luci-app-passwall: python3 tests/zray_dispatch.py
"""
import pathlib
import subprocess
import tempfile

source = pathlib.Path('root/usr/share/passwall/app.sh').read_text(encoding='utf-8')
functions = source[source.index('check_run_environment() {'):source.index('\nget_local_dns\n')]
with tempfile.TemporaryDirectory(prefix='passwall-zray-test-') as directory:
    prelude = r'''
TMP_PATH="$1"
TMP_ACL_PATH="$TMP_PATH/acl"
GLOBAL_ACL_PATH="$TMP_ACL_PATH/default"
mkdir -p "$GLOBAL_ACL_PATH"
ZRAY_BIN=/usr/bin/zray
UTIL_ZRAY=/usr/lib/lua/luci/passwall/util_zray.lua
config_n_get() {
    case "$1:$2" in
        test:type) echo Zray ;;
        test:address) echo example.com ;;
        test:port) echo 443 ;;
        test:remarks) echo test ;;
        *) echo "$3" ;;
    esac
}
config_get_type() { echo nodes; }
check_host() { return 0; }
eval_set_val() { for entry in "$@"; do eval "$entry"; done; }
json_init() { JSON=; }
json_add_string() { JSON="$JSON|$1=$2"; }
json_dump() { printf '%s' "$JSON"; }
echolog() { printf '%s\n' "$*" >> "$TMP_PATH/log"; }
lua() {
    printf '%s\n' "$*" >> "$TMP_PATH/generate"
    [ "${GEN_FAIL:-0}" = 1 ] && return 1
    printf '{}\n'
}
ln_run() { printf '%s\n' "$*" >> "$TMP_PATH/launch"; }
set_cache_var() { :; }
get_host_ip() { echo "$2"; }
first_type() { echo "$1"; }
'''
    cases = r'''
run_socks node=test bind=127.0.0.1 socks_port=1070 config_file=normal.json http_port=8080 || exit 10
run_socks node=test bind=127.0.0.1 socks_port=1071 config_file=probe.json no_run=1 || exit 11
GEN_FAIL=1
if run_socks node=test bind=127.0.0.1 socks_port=1072 config_file=bad.json; then exit 12; fi
GEN_FAIL=0
NODE=test
REDIR_PORT=1041
REDIRECT_LIST="socks xray"
TPROXY_LIST="socks xray"
TCP_PROXY_WAY=redirect
PROXY_IPV6=0
run_ipt2socks() { printf '%s\n' "$*" >> "$TMP_PATH/bridge"; }
start_global || exit 13
TCP_PROXY_WAY=tproxy
start_global || exit 14
ENABLED_DEFAULT_ACL=1
ENABLED_ACLS=0
UDP_PROXY_MODE=proxy
DNS_MODE=tcp
check_zray_nodes || exit 15
XRAY_BIN=
DNS_MODE=xray
if check_zray_nodes; then exit 16; fi
DNS_MODE=tcp
GEN_FAIL=1
if check_zray_nodes; then exit 17; fi
'''
    path = pathlib.Path(directory)
    script = path / 'dispatch.sh'
    script.write_text(prelude + functions + cases, encoding='utf-8')
    subprocess.check_call(['sh', str(script), directory])
    launches = (path / 'launch').read_text().splitlines()
    assert launches[0].startswith('/usr/bin/zray zray /dev/null ')
    assert launches[1].endswith('/normal_http.json')
    assert not any('probe.json' in line or 'bad.json' in line for line in launches)
    assert not (path / 'bad.json').exists()
    bridge = (path / 'bridge').read_text().splitlines()
    assert 'tcp_tproxy= ' in bridge[0] and 'socks_port=1070' in bridge[0]
    assert 'tcp_tproxy=1 ' in bridge[1]
    assert all('xray' not in line and 'sing-box' not in line for line in launches)
    assert 'proxy_udp=proxy' in (path / 'generate').read_text()
print('Zray SOCKS/HTTP/global REDIRECT/global TPROXY/preflight dispatch checks passed')
