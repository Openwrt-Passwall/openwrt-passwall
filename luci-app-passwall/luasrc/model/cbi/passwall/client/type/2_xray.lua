if not api.finded_com("xray") then
	return
end

-- [[ Xray ]]
local m, s1 = ...
local type_name = "Xray"

s1.fields["type"]:value(type_name, "Xray")
if not s1.fields["type"].default then
	s1.fields["type"].default = type_name
end

if s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "xray_"
api.set_type_cbi(s)

local ss_method_list = {
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local security_list = { "auto", "aes-128-gcm", "chacha20-poly1305" }

local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"
}

local xray_version = api.get_app_version("xray")

o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("socks", translate("Socks"))
o:value("http", translate("HTTP"))
o:value("vmess", translate("Vmess"))
o:value("vless", translate("VLESS"))
o:value("shadowsocks", translate("Shadowsocks"))
o:value("trojan", translate("Trojan"))
o:value("wireguard", translate("WireGuard"))
if api.compare_versions(xray_version, ">=", "26.1.13") then
	o:value("hysteria2", translate("Hysteria2"))
end
if api.compare_versions(xray_version, ">=", "1.8.12") then
	o:value("_balancing", translate("Balancing"))
end
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface"))
local protocol_val = m:get(s.section, "protocol")
local formvalue_proto = s.fields["protocol"]:formvalue(s.section)
if formvalue_proto then
	protocol_val = formvalue_proto
end

local load_balancing_options = protocol_val == "_balancing"
local load_shunt_options = protocol_val == "_shunt"
local load_iface_options = protocol_val == "_iface"
local load_normal_options = true
if load_balancing_options or load_shunt_options or load_iface_options then
	load_normal_options = nil
end

local netdev_list = api.get_network_devices()
local node_list = api.get_node_list()
local fallback_list = {}
local is_balancer = nil
for k, e in ipairs(node_list.balancing_list or {}) do
	if e.id ~= s.section then
		fallback_list[#fallback_list + 1] = {
			id = e["id"],
			remark = e["remark"],
			group = e["group"],
			fallback = e.o["fallback_node"],
		}
	else
		is_balancer = true
	end
end

if load_balancing_options then -- [[ Load balancing Start ]]
	o = s:option(ListValue, "node_add_mode", translate("Node Addition Method"))
	o:depends({ protocol = "_balancing" })
	o.default = "manual"
	o:value("manual", translate("Manual"))
	o:value("batch", translate("Batch"))

	o = s:option(MultiValue, "balancing_node", translate("Load balancing node list"), translate("Load balancing node list, <a target='_blank' href='https://xtls.github.io/config/routing.html#balancerobject'>document</a>"))
	o:depends({ node_add_mode = "manual" })
	o.widget = "checkbox"
	o.cast = "table"
	o.template = m:template_path("/cbi/nodes_multivalue")
	o.group = {}
	for k1, v1 in pairs(node_list) do
		if k1 == "socks_list" or k1 == "normal_list" then
			for i, v in ipairs(v1) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = v.group or ""
			end
		end
	end

	o = s:option(MultiValue, "node_group", translate("Select Group"))
	o:depends({ node_add_mode = "batch" })
	o.widget = "checkbox"
	o:value("default", translate("default"))
	for k, v in pairs(groups) do
		o:value(api.UrlEncode(k), k)
	end

	o = s:option(Value, "node_match_rule", translate("Node Matching Rules"))
	o:depends({ node_add_mode = "batch" })
	local descrStr = "Example: <code>^A && B && !C && D$</code><br>"
	descrStr = descrStr .. "This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>"
	descrStr = descrStr .. "Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>"
	descrStr = descrStr .. "Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>"
	descrStr = descrStr .. "Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D)."
	o.description = translate(descrStr)

	o = s:option(ListValue, "balancingStrategy", translate("Balancing Strategy"))
	o:depends({ protocol = "_balancing" })
	o:value("random")
	o:value("roundRobin")
	o:value("leastPing")
	o:value("leastLoad")
	o.default = "random"

	-- Fallback Node
	o = s:option(ListValue, "fallback_node", translate("Fallback Node"))
	o.group = {"",""}
	o:value("", translate("Close(Not use)"))
	o:value("_direct", translate("Direct Connection"))
	o:depends({ protocol = "_balancing" })
	o.template = m:template_path("/cbi/nodes_listvalue")
	-- 最大 fallback 套娃层数
	local MAX_FALLBACK_DEPTH = 3
	-- 检查是否会形成回环
	local function will_loop(start_id, target_id, depth)
		depth = depth or 0
		-- 超过最大深度后停止递归
		if depth >= MAX_FALLBACK_DEPTH then
			return false
		end
		for _, v in ipairs(fallback_list) do
			if v.id == target_id then
				local fb = v.fallback
				-- 没有 fallback
				if not fb or fb == "" or fb == "_direct" then
					return false
				end
				-- 检测到回环
				if fb == start_id then
					return true
				end
				-- 继续递归检查
				return will_loop(start_id, fb, depth + 1)
			end
		end
		return false
	end
	-- 获取 fallback 链深度
	local function get_fallback_depth(id, depth)
		depth = depth or 0
		if depth >= MAX_FALLBACK_DEPTH then
			return depth
		end
		for _, v in ipairs(fallback_list) do
			if v.id == id then
				local fb = v.fallback
				if not fb or fb == "" or fb == "_direct" then
					return depth
				end
				return get_fallback_depth(fb, depth + 1)
			end
		end
		return depth
	end
	for _, v in ipairs(fallback_list) do
		local depth = get_fallback_depth(v.id)
		-- 超过最大套娃层数后，不允许继续选择 balancer
		if depth < MAX_FALLBACK_DEPTH
			and not will_loop(s.section, v.id)
		then
			o:value(v.id, v.remark)
			o.group[#o.group + 1] = (v.group and v.group ~= "") and v.group or translate("default")
		end
	end
	for k1, v1 in pairs(node_list) do
		if k1 == "socks_list" or k1 == "normal_list" or k1 == "urltest_list" then
			for i, v in ipairs(v1) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			end
		end
	end

	-- 探测地址
	o = s:option(Flag, "useCustomProbeUrl", translate("Use Custom Probe URL"), translate("By default the built-in probe URL will be used, enable this option to use a custom probe URL."))
	o:depends({ protocol = "_balancing" })

	o = s:option(Value, "probeUrl", translate("Probe URL"))
	o:depends({ useCustomProbeUrl = true })
	o:value("https://cp.cloudflare.com/", "Cloudflare")
	o:value("https://www.gstatic.com/generate_204", "Gstatic")
	o:value("https://www.google.com/generate_204", "Google")
	o:value("https://www.youtube.com/generate_204", "YouTube")
	o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
	o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
	o:value("https://wifi.vivo.com.cn/generate_204", "VIVO (CN)")
	o.default = o.keylist[3]
	o.description = translate("The URL used to detect the connection status.")

	-- 探测间隔
	o = s:option(Value, "probeInterval", translate("Probe Interval"))
	o:depends({ protocol = "_balancing" })
	o.default = "1m"
	o.placeholder = "1m"
	o.description = translate("The interval between initiating probes.") .. "<br>" ..
			translate("The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.") .. "<br>" ..
			translate("When the unit is not filled in, it defaults to seconds.")

	o = s:option(Value, "expected", translate("Preferred Node Count"))
	o:depends({ balancingStrategy = "leastLoad" })
	o.datatype = "uinteger"
	o.default = "2"
	o.placeholder = "2"
	o.description = translate("The load balancer selects the optimal number of nodes, and traffic is randomly distributed among them.")

	o = s:option(Value, "tolerance", translate("Failure Tolerance (%)"))
	o:depends({ balancingStrategy = "leastLoad" })
	o.datatype = "uinteger"
	o.default = "10"
	o.placeholder = "10"
	o.description = translate("The maximum acceptable speed test failure rate. For example, 1 means allowing a 1% failure rate.")
end  -- [[ 负载均衡 End ]]

if load_iface_options then -- [[ 自定义接口 Start ]]
	o = s:option(Value, "iface", translate("Interface"))
	o:depends({ protocol = "_iface" })
	for _, d in ipairs(netdev_list) do
		o:value(d.name, d.label)
	end
end -- [[ 自定义接口 End ]]


if load_normal_options then

o = s:option(Value, "address", translate("Address (Support Domain Name)"))

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "uuid", translate("ID"))
o.password = true
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })

o = s:option(Value, "username", translate("Username"))
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })

o = s:option(Value, "password", translate("Password"))
o.password = true
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

o = s:option(ListValue, "security", translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ protocol = "vmess" })

o = s:option(Value, "encryption", translate("Encrypt Method") .. " (encryption)")
o.default = "none"
o.placeholder = "none"
o:depends({ protocol = "vless" })
o.validate = function(self, value)
	value = api.trim(value)
	return (value == "" and "none" or value)
end

o = s:option(ListValue, "ss_method", translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ protocol = "shadowsocks" })

o = s:option(ListValue, "flow", translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:value("xtls-rprx-vision-udp443")
o:depends({ protocol = "vless" })

---- [[hysteria2]]
o = s:option(Value, "hysteria2_hop", translate("Port hopping range"))
o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
o:depends({ protocol = "hysteria2", hysteria2_realms = false })

o = s:option(Value, "hysteria2_hop_interval", translate("Hop Interval(second)"), translate("Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5."))
o.datatype = "or(uinteger,portrange)"
o.placeholder = "30"
o.default = "30"
o:depends({ protocol = "hysteria2", hysteria2_realms = false })

o = s:option(Flag, "hysteria2_realms", translate("Realms"))
o.default = "0"
if api.compare_versions(xray_version, ">", "26.5.9") then
	o:depends({ protocol = "hysteria2"})
else
	o:depends({ protocol = "__hide"})
end

o = s:option(Value, "hysteria2_realm_url", translate("Realm URL"), translate("Example:") .. "realm://public@realm.hy2.io/your-realm-name")
o:depends({ hysteria2_realms = "1" })
o.validate = function(self, value)
	value = api.trim(value)
	local realm = api.parse_realm_uri(value)
	if realm then return value end
	return nil, translate("Invalid Realm URL.")
end

o = s:option(DynamicList, "hysteria2_realm_stun", translate("Realm STUN"))
o.default = { "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }
o:depends({ hysteria2_realms = "1" })

o = s:option(Flag, "hysteria2_realm_upnp", translate("Enable") .. " UPnP/NAT-PMP", translate("Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success."))
o.default = "0"
o:depends({ hysteria2_realms = "1" })

o = s:option(Value, "hysteria2_auth_password", translate("Auth Password"))
o.password = true
o:depends({ protocol = "hysteria2"})

o = s:option(ListValue, "hysteria2_obfs_type", translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:value("gecko")
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "hysteria2_obfs_password", translate("Obfs Password"))
o:depends({ hysteria2_obfs_type = "salamander" })
o:depends({ hysteria2_obfs_type = "gecko" })

o = s:option(Value, "hysteria2_obfs_MinPacketSize", translate("Gecko Packet Size (min)"))
o.datatype = "uinteger"
o.placeholder = "512"
o.default = "512"
o:depends({ hysteria2_obfs_type = "gecko" })

o = s:option(Value, "hysteria2_obfs_MaxPacketSize", translate("Gecko Packet Size (max)"))
o.datatype = "uinteger"
o.placeholder = "1200"
o.default = "1200"
o:depends({ hysteria2_obfs_type = "gecko" })

o = s:option(Value, "hysteria2_up_mbps", translate("Max upload Mbps"))
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "hysteria2_down_mbps", translate("Max download Mbps"))
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "hysteria2_stream_recv_win", translate("QUIC stream receive window"))
o.datatype = "uinteger"
o.placeholder = "8388608"
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "hysteria2_conn_recv_win", translate("QUIC connection receive window"))
o.datatype = "uinteger"
o.placeholder = "20971520"
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "hysteria2_idle_timeout", translate("Idle Timeout"), translate("Units:seconds") .. " (4~120)")
o.datatype = "range(4,120)"
o:depends({ protocol = "hysteria2"})

o = s:option(Value, "hysteria2_keep_alive_period", translate("QUIC KeepAlive interval"), translate("Units:seconds") .. " (2~60)")
o.datatype = "range(2,60)"
o:depends({ protocol = "hysteria2"})

o = s:option(Flag, "hysteria2_disable_mtu_discovery", translate("Disable MTU detection"))
o.default = "0"
o:depends({ protocol = "hysteria2"})
---- [[hysteria2 end]]

o = s:option(Flag, "tls", translate("TLS"))
o.default = 0
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "http" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "shadowsocks" })

o = s:option(Flag, "reality", translate("REALITY"), translate("Only recommend to use with VLESS-TCP-XTLS-Vision."))
o.default = 0
o:depends({ tls = true, transport = "raw" })
o:depends({ tls = true, transport = "ws" })
o:depends({ tls = true, transport = "grpc" })
o:depends({ tls = true, transport = "httpupgrade" })
o:depends({ tls = true, transport = "xhttp" })

o = s:option(ListValue, "alpn", translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ tls = true, reality = false })

-- o = s:option(Value, "minversion", translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
-- o:depends({ tls = true })

o = s:option(Value, "tls_serverName", "SNI " .. translate("Domain"))
o:depends({ tls = true })
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "tls_pinSHA256", translate("TLS Chain Fingerprint (SHA256)"))
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2" })
o.description = translate("Once set, connects only when the server’s chain fingerprint matches.") ..
		string.format("<a href='javascript:void(0)' onclick='javascript:fetchCertSha256(this)'>%s</a>", "→ " .. translate("Fetch Manually"))

o = s:option(Value, "tls_CertByName", translate("TLS Certificate Name (CertName)"), translate("TLS is used to verify the leaf certificate name."))
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2" })

o = s:option(Flag, "tls_certificate", translate("TLS Certificate (PEM)"))
o.default = "0"
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2" })

o = s:option(TextValue, "tls_certificate_pem", "　", translate("Full certificate (chain), PEM format."))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ tls_certificate = true })
o.cfgvalue = function(self, section)
	return (m:get(section, "tls_certificate_pem") or ""):gsub("\\n", "\n")
end
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("\r", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value:gsub("\n", "\\n")
end

o = s:option(Flag, "ech", translate("ECH"))
o.default = "0"
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2", hysteria2_realms = false })

o = s:option(TextValue, "ech_config", translate("ECH Config"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ ech = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

-- [[ REALITY部分 ]] --
o = s:option(Value, "reality_publicKey", translate("Public Key"))
o:depends({ tls = true, reality = true })

o = s:option(Value, "reality_shortId", translate("Short Id"))
o:depends({ tls = true, reality = true })

o = s:option(Value, "reality_spiderX", translate("Spider X"))
o.placeholder = "/"
o:depends({ tls = true, reality = true })

o = s:option(Flag, "utls", translate("uTLS"))
o.default = "0"
o:depends({ tls = true, reality = false })

o = s:option(ListValue, "fingerprint", translate("Finger Print"))
o:value("chrome")
o:value("firefox")
o:value("edge")
o:value("safari")
o:value("360")
o:value("qq")
o:value("ios")
o:value("android")
o:value("random")
o:value("randomized")
o:value("unsafe")
o.default = "chrome"
o:depends({ tls = true, utls = true })
o:depends({ tls = true, reality = true })

o = s:option(Value, "cipherSuites", translate("Cipher Suites"), '<a href="https://go.dev/src/crypto/tls/cipher_suites.go#L44" target="_blank">***</a>' .. " " .. translate("Configures the list of supported cipher suites, separated by :"))
o:depends({ tls = true, reality = false })

o = s:option(Flag, "use_mldsa65Verify", translate("ML-DSA-65"))
o.default = "0"
o:depends({ tls = true, reality = true })

o = s:option(TextValue, "reality_mldsa65Verify", "ML-DSA-65 " .. translate("Public key"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ use_mldsa65Verify = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

o = s:option(ListValue, "transport", translate("Transport"))
o:value("raw", "RAW (TCP)")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("grpc", "gRPC")
o:value("httpupgrade", "HttpUpgrade")
o:value("xhttp", "XHTTP")
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

o = s:option(Value, "wireguard_public_key", translate("Public Key"))
o:depends({ protocol = "wireguard" })

o = s:option(Value, "wireguard_secret_key", translate("Private Key"))
o:depends({ protocol = "wireguard" })

o = s:option(Value, "wireguard_preSharedKey", translate("Pre shared key"))
o:depends({ protocol = "wireguard" })

o = s:option(DynamicList, "wireguard_local_address", translate("Local Address"))
o:depends({ protocol = "wireguard" })

o = s:option(Value, "wireguard_mtu", translate("MTU"))
o.default = "1420"
o:depends({ protocol = "wireguard" })

if api.compare_versions(xray_version, ">=", "1.8.0") then
	o = s:option(Value, "wireguard_reserved", translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	o:depends({ protocol = "wireguard" })
end

o = s:option(Value, "wireguard_keepAlive", translate("Keep Alive"))
o.default = "0"
o:depends({ protocol = "wireguard" })

-- [[ RAW部分 ]]--

-- TCP伪装
o = s:option(ListValue, "tcp_guise", translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ transport = "raw" })

-- HTTP域名
o = s:option(DynamicList, "tcp_guise_http_host", translate("HTTP Host"))
o:depends({ tcp_guise = "http" })

-- HTTP路径
o = s:option(DynamicList, "tcp_guise_http_path", translate("HTTP Path"))
o.placeholder = "/"
o:depends({ tcp_guise = "http" })

-- [[ mKCP部分 ]]--

o = s:option(ListValue, "mkcp_guise", translate("Camouflage Type"), translate('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.'))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ transport = "mkcp" })

o = s:option(Value, "mkcp_domain", translate("Camouflage Domain"), translate("Use it together with the DNS disguised type. You can fill in any domain."))
o:depends({ mkcp_guise = "dns" })

o = s:option(Value, "mkcp_mtu", translate("KCP MTU"))
o.datatype = "uinteger"
o.default = 1350
o:depends({ transport = "mkcp" })

o = s:option(Value, "mkcp_seed", translate("KCP Seed"))
o:depends({ transport = "mkcp" })

-- [[ WebSocket部分 ]]--
o = s:option(Value, "ws_host", translate("WebSocket Host"))
o:depends({ transport = "ws" })

o = s:option(Value, "ws_path", translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ transport = "ws" })

o = s:option(Value, "ws_heartbeatPeriod", translate("HeartbeatPeriod(second)"))
o.datatype = "integer"
o:depends({ transport = "ws" })

-- [[ gRPC部分 ]]--
o = s:option(Value, "grpc_serviceName", "ServiceName")
o:depends({ transport = "grpc" })

o = s:option(ListValue, "grpc_mode", "gRPC " .. translate("Transfer mode"))
o:value("gun")
o:value("multi")
o:depends({ transport = "grpc" })

o = s:option(Flag, "grpc_health_check", translate("Health check"))
o:depends({ transport = "grpc" })

o = s:option(Value, "grpc_idle_timeout", translate("Idle timeout"))
o.default = "10"
o:depends({ grpc_health_check = true })

o = s:option(Value, "grpc_health_check_timeout", translate("Health check timeout"))
o.default = "20"
o:depends({ grpc_health_check = true })

o = s:option(Flag, "grpc_permit_without_stream", translate("Permit without stream"))
o.default = "0"
o:depends({ grpc_health_check = true })

o = s:option(Value, "grpc_initial_windows_size", translate("Initial Windows Size"))
o.default = "0"
o:depends({ transport = "grpc" })

-- [[ HttpUpgrade部分 ]]--
o = s:option(Value, "httpupgrade_host", translate("HttpUpgrade Host"))
o:depends({ transport = "httpupgrade" })

o = s:option(Value, "httpupgrade_path", translate("HttpUpgrade Path"))
o.placeholder = "/"
o:depends({ transport = "httpupgrade" })

-- [[ XHTTP部分 ]]--
o = s:option(ListValue, "xhttp_mode", "XHTTP " .. translate("Mode"))
o:depends({ transport = "xhttp" })
o.default = "auto"
o:value("auto")
o:value("packet-up")
o:value("stream-up")
o:value("stream-one")

o = s:option(Value, "xhttp_host", translate("XHTTP Host"))
o:depends({ transport = "xhttp" })

o = s:option(Value, "xhttp_path", translate("XHTTP Path"))
o.placeholder = "/"
o:depends({ transport = "xhttp" })

o = s:option(Flag, "use_xhttp_extra", translate("XHTTP Extra"))
o.default = "0"
o:depends({ transport = "xhttp" })

o = s:option(TextValue, "xhttp_extra", "　", translate("An XHttpObject in JSON format, used for sharing."))
o:depends({ use_xhttp_extra = true })
o.rows = 10
o.wrap = "off"
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	local v = o_validate(self, value)
	if v then return v end
	return nil, "XHTTP Extra " .. translate("Must be JSON text!")
end
o.cfgvalue = function(self, section, value)
	local raw = m:get(section, "xhttp_extra")
	if raw then
		return api.base64Decode(raw)
	end
end
o.write = function(self, section, value)
	m:set(section, "xhttp_extra", api.base64Encode(value) or "")
	local success, data = pcall(api.jsonc.parse, value)
	if success and data then
		local address = (data.extra and data.extra.downloadSettings and data.extra.downloadSettings.address)
			or (data.downloadSettings and data.downloadSettings.address)
		if address and address ~= "" then
			address = address:gsub("^%[", ""):gsub("%]$", "")
			m:set(section, "download_address", address)
		else
			m:del(section, "download_address")
		end
	else
		m:del(section, "download_address")
	end
end
o.remove = function(self, section, value)
	m:del(section, "xhttp_extra")
	m:del(section, "download_address")
end

-- [[ User-Agent ]]--
o = s:option(Value, "user_agent", translate("User-Agent"))
o.default = ""
o:value("", translate("default"))
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "chrome")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0", "firefox")
o:value("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15", "safari")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.70", "edge")
o:value("Go-http-client/1.1", "golang")
o:value("curl/7.68.0", "curl")
o:depends({ tcp_guise = "http" })
o:depends({ transport = "ws" })
o:depends({ transport = "httpupgrade" })
o:depends({ transport = "xhttp" })
o:depends({ transport = "grpc" })

-- [[ Mux.Cool ]]--
o = s:option(Flag, "mux", "Mux", translate("Enable Mux.Cool"))
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless", transport = "raw" })
o:depends({ protocol = "vless", transport = "ws" })
o:depends({ protocol = "vless", transport = "grpc" })
o:depends({ protocol = "vless", transport = "httpupgrade" })
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

o = s:option(Value, "mux_concurrency", translate("Mux concurrency"))
o.default = -1
o:depends({ mux = true })

o = s:option(Value, "xudp_concurrency", translate("XUDP Mux concurrency"))
o.default = 8
o:depends({ mux = true })

--[[FinalMask]]
o = s:option(Flag, "use_finalmask", "FinalMask")
o.default = "0"
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "wireguard" })
o:depends({ protocol = "hysteria2", hysteria2_realms = false })

o = s:option(TextValue, "finalmask", "　")
o:depends({ use_finalmask = true })
o.rows = 10
o.wrap = "off"
o.description = translate("An FinalMaskObject in JSON format, used for sharing.") .. "<br>" ..
		translate("Custom finalmask overrides mkcp, hysteria2, fragment, noise, and related settings.")
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	local v = o_validate(self, value)
	if v then return v end
	return nil, "FinalMask " .. translate("Must be JSON text!")
end
o.cfgvalue = function(self, section, value)
	local raw = m:get(section, "finalmask")
	if raw then
		return api.base64Decode(raw)
	end
end
o.write = function(self, section, value)
	m:set(section, "finalmask", api.base64Encode(value) or "")
end

--[[Fast Open]]
o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"), translate("Need node support required"))
o.default = 0

--[[tcpMptcp]]
o = s:option(Flag, "tcpMptcp", "tcpMptcp", translate("Enable Multipath TCP, need to be enabled in both server and client configuration."))
o.default = 0

o = s:option(ListValue, "domain_resolver", translate("Domain DNS Resolve"))
o.description = translate("If the node address is a domain name, this DNS will be used for resolution.") .. "<br>" .. string.format('<font color="red">%s</font>',
		translate("Note: For node-specific DNS only. Keep Auto to avoid extra overhead."))
o:value("", translate("Auto"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("https", "DoH")

o = s:option(Value, "domain_resolver_dns", "DNS")
o.datatype = "or(ipaddr,ipaddrport)"
o:value("114.114.114.114")
o:value("223.5.5.5:53")
o.default = o.keylist[1]
o:depends({ domain_resolver = "tcp" })
o:depends({ domain_resolver = "udp" })

o = s:option(Value, "domain_resolver_dns_https", "DNS")
o:value("https://120.53.53.53/dns-query", "DNSPod")
o:value("https://223.5.5.5/dns-query", "AliDNS")
o.default = o.keylist[1]
o:depends({ domain_resolver = "https" })

o = s:option(ListValue, "domain_strategy", translate("Domain Strategy"), translate("If is domain name, The requested domain name will be resolved to IP before connect."))
o.default = ""
o:value("", translate("Auto"))
o:value("UseIPv4v6", translate("Prefer IPv4"))
o:value("UseIPv6v4", translate("Prefer IPv6"))
o:value("UseIPv4", translate("IPv4 Only"))
o:value("UseIPv6", translate("IPv6 Only"))

o = s:option(Flag, "happy_eyeballs", translate("Enable Happy Eyeballs"), translate("Attempts IPv4 and IPv6 simultaneously; automatically uses the faster connection."))
o.default = 0

local protocols = s.fields["protocol"].keylist
if #protocols > 0 then
	for i, v in ipairs(protocols) do
		if not v:find("^_") then
			local depends_condition = { protocol = v }
			if v == "hysteria2" then
				depends_condition["hysteria2_realms"] = false
			end
			s.fields["address"]:depends(depends_condition)
			s.fields["port"]:depends(depends_condition)
			s.fields["domain_resolver"]:depends(depends_condition)
			s.fields["happy_eyeballs"]:depends(depends_condition)

			local strategy_depends = api.clone(depends_condition)
			strategy_depends["happy_eyeballs"] = false
			s.fields["domain_strategy"]:depends(strategy_depends)

			if v ~= "hysteria2" then
				s.fields["tcp_fast_open"]:depends({ protocol = v })
				s.fields["tcpMptcp"]:depends({ protocol = v })
			end
		end
	end
end
end
-- [[ Normal single node End ]]

if not load_shunt_options then
	o = s:option(ListValue, "chain_proxy", translate("Chain Proxy"))
	o:value("", translate("Close(Not use)"))
	if not (load_iface_options or load_balancing_options) then
		-- Special node cannot be use pre-proxy.
		o:value("1", translate("Preproxy Node"))
		o:value("3", translate("Outbound Interface"))
	end
	o:value("2", translate("Landing Node"))

	o1 = s:option(ListValue, "preproxy_node", translate("Preproxy Node"), translate("Only support a layer of proxy."))
	o1:depends({ chain_proxy = "1", hysteria2_realms = false })
	o1.template = m:template_path("/cbi/nodes_listvalue")
	o1.group = {}

	o3 = s:option(Value, "outbound_iface", translate("Outbound Interface"))
	o3:depends({ chain_proxy = "3" })
	o3:value("", translate("All"))
	for _, d in ipairs(netdev_list) do
		o3:value(d.name, d.label)
	end

	o2 = s:option(ListValue, "to_node", translate("Landing Node"), translate("Only support a layer of proxy."))
	o2:depends({ chain_proxy = "2", hysteria2_realms = false })
	o2.template = m:template_path("/cbi/nodes_listvalue")
	o2.group = {}

	for k1, v1 in pairs(node_list) do
		if k1 ~= "shunt_list" and k1 ~= "iface_list" then
			for i, v in ipairs(v1) do
				if v.id ~= s.section then
					o1:value(v.id, v.remark)
					o1.group[#o1.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					if k1 == "normal_list" then
						-- Landing Node not support use special node.
						o2:value(v.id, v.remark)
						o2.group[#o2.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					end
				end
			end
		end
	end
end

api.type_cbi_section(s1, s)

if load_shunt_options then
	local current_node = m:get(arg[1]) or {}
	local shunt_lua = loadfile("/usr/lib/lua/luci/model/cbi/passwall/client/include/shunt_options.lua")
	setfenv(shunt_lua, getfenv(1))(m, s1, {
		node = {
			[".name"] = s.section,
			type = type_name,
		},
		node_list = node_list,
	})
end
