local m, s = ...

if not api.finded_com("xray") then
	return
end

local jsonc = api.jsonc

type_name = "Xray"

-- [[ Xray ]]

s.fields["type"]:value(type_name, "Xray")
if not s.fields["type"].default then
	s.fields["type"].default = type_name
end

if s.val["type"] ~= type_name then
	return
end

local option_prefix = "xray_"

local function _n(name)
	return option_prefix .. name
end

local formvalue_key = "cbid." .. appname .. "." .. arg[1] .. "."
local formvalue_proto = luci.http.formvalue(formvalue_key .. _n("protocol"))

if formvalue_proto then s.val["protocol"] = formvalue_proto end

local arg_select_proto = luci.http.formvalue("select_proto") or ""

local ss_method_list = {
	"none", "plain", "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local security_list = { "none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero" }

local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"
}

local xray_version = api.get_app_version("xray")

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
o:value("vmess", translate("Vmess"))
o:value("vless", translate("VLESS"))
o:value("http", translate("HTTP"))
o:value("socks", translate("Socks"))
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
function o.custom_cfgvalue(self, section)
	if arg_select_proto ~= "" then
		return arg_select_proto
	else
		return m:get(section, self.option:sub(1 + #option_prefix))
	end
end

local load_balancing_options = s.val["protocol"] == "_balancing" or arg_select_proto == "_balancing"
local load_shunt_options = s.val["protocol"] == "_shunt" or arg_select_proto == "_shunt"
local load_iface_options = s.val["protocol"] == "_iface" or arg_select_proto == "_iface"
local load_normal_options = true
if load_balancing_options or load_shunt_options or load_iface_options then
	load_normal_options = nil
end
if not arg_select_proto:find("_") then
	load_normal_options = true
end

local nodes_list = {}
local balancing_list = {}
local fallback_list = {}
local iface_list = {}
local is_balancer = nil
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_list[#nodes_list + 1] = {
			id = e[".name"],
			remark = e["remark"],
			type = e["type"],
			address = e["address"],
			chain_proxy = e["chain_proxy"],
			group = e["group"]
		}
	end
	if e.protocol == "_balancing" then
		balancing_list[#balancing_list + 1] = {
			id = e[".name"],
			remark = e["remark"],
			group = e["group"]
		}
		if e[".name"] ~= arg[1] then
			fallback_list[#fallback_list + 1] = {
				id = e[".name"],
				remark = e["remark"],
				fallback = e["fallback_node"],
				group = e["group"]
			}
		else
			is_balancer = true
		end
	end
	if e.protocol == "_iface" then
		iface_list[#iface_list + 1] = {
			id = e[".name"],
			remark = e["remark"],
			group = e["group"]
		}
	end
end

local socks_list = {}
m.uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " " .. string.format("[%s %s]", s.port, translate("Port")),
			group = "Socks"
		}
	end
end)

if load_balancing_options then -- [[ 负载均衡 Start ]]
	o = s:option(ListValue, _n("node_add_mode"), translate("Node Addition Method"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o.default = "manual"
	o:value("manual", translate("Manual"))
	o:value("batch", translate("Batch"))

	o = s:option(MultiValue, _n("balancing_node"), translate("Load balancing node list"), translate("Load balancing node list, <a target='_blank' href='https://xtls.github.io/config/routing.html#balancerobject'>document</a>"))
	o:depends({ [_n("node_add_mode")] = "manual" })
	o.widget = "checkbox"
	o.template = appname .. "/cbi/nodes_multivalue"
	o.group = {}
	for k, v in pairs(socks_list) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = v.group or ""
	end
	for i, v in pairs(nodes_list) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = v.group or ""
	end
	-- 读取旧 DynamicList
	function o.cfgvalue(self, section)
		return m.uci:get_list(appname, section, "balancing_node") or {}
	end
	-- 写入保持 DynamicList
	function o.custom_write(self, section, value)
		local old = m.uci:get_list(appname, section, "balancing_node") or {}
		local new, set = {}, {}
		for v in value:gmatch("%S+") do
			new[#new + 1] = v
			set[v] = 1
		end
		for _, v in ipairs(old) do
			if not set[v] then
				m.uci:set_list(appname, section, "balancing_node", new)
				return
			end
			set[v] = nil
		end
		for _ in pairs(set) do
			m.uci:set_list(appname, section, "balancing_node", new)
			return
		end
	end

	o = s:option(MultiValue, _n("node_group"), translate("Select Group"))
	o:depends({ [_n("node_add_mode")] = "batch" })
	o.widget = "checkbox"
	o:value("default", translate("default"))
	for k, v in pairs(groups) do
		o:value(api.UrlEncode(k), k)
	end

	o = s:option(Value, _n("node_match_rule"), translate("Node Matching Rules"))
	o:depends({ [_n("node_add_mode")] = "batch" })
	local descrStr = "Example: <code>^A && B && !C && D$</code><br>"
	descrStr = descrStr .. "This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>"
	descrStr = descrStr .. "Conditions are joined by <code>&&</code>, and their order does not affect the result."
	o.description = translate(descrStr)

	o = s:option(ListValue, _n("balancingStrategy"), translate("Balancing Strategy"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o:value("random")
	o:value("roundRobin")
	o:value("leastPing")
	o:value("leastLoad")
	o.default = "random"

	-- Fallback Node
	o = s:option(ListValue, _n("fallback_node"), translate("Fallback Node"))
	o:value("", translate("Close(Not use)"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o.template = appname .. "/cbi/nodes_listvalue"
	o.group = {""}
	local function check_fallback_chain(fb)
		for k, v in pairs(fallback_list) do
			if v.fallback == fb then
				fallback_list[k] = nil
				check_fallback_chain(v.id)
			end
		end
	end
	-- 检查fallback链，去掉会形成闭环的balancer节点
	if is_balancer then
		check_fallback_chain(arg[1])
	end
	for k, v in pairs(socks_list) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(fallback_list) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(nodes_list) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end

	-- 探测地址
	o = s:option(Flag, _n("useCustomProbeUrl"), translate("Use Custom Probe URL"), translate("By default the built-in probe URL will be used, enable this option to use a custom probe URL."))
	o:depends({ [_n("protocol")] = "_balancing" })

	o = s:option(Value, _n("probeUrl"), translate("Probe URL"))
	o:depends({ [_n("useCustomProbeUrl")] = true })
	o:value("https://cp.cloudflare.com/", "Cloudflare")
	o:value("https://www.gstatic.com/generate_204", "Gstatic")
	o:value("https://www.google.com/generate_204", "Google")
	o:value("https://www.youtube.com/generate_204", "YouTube")
	o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
	o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
	o.default = o.keylist[3]
	o.description = translate("The URL used to detect the connection status.")

	-- 探测间隔
	o = s:option(Value, _n("probeInterval"), translate("Probe Interval"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o.default = "1m"
	o.placeholder = "1m"
	o.description = translate("The interval between initiating probes.") .. "<br>" ..
			translate("The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.") .. "<br>" ..
			translate("When the unit is not filled in, it defaults to seconds.")

	o = s:option(Value, _n("expected"), translate("Preferred Node Count"))
	o:depends({ [_n("balancingStrategy")] = "leastLoad" })
	o.datatype = "uinteger"
	o.default = "2"
	o.placeholder = "2"
	o.description = translate("The load balancer selects the optimal number of nodes, and traffic is randomly distributed among them.")
end  -- [[ 负载均衡 End ]]

if load_iface_options then -- [[ 自定义接口 Start ]]
	o = s:option(Value, _n("iface"), translate("Interface"))
	o.default = "eth1"
	o:depends({ [_n("protocol")] = "_iface" })
end -- [[ 自定义接口 End ]]


if load_normal_options then

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"

local protocols = s.fields[_n("protocol")].keylist
if #protocols > 0 then
	for index, value in ipairs(protocols) do
		if not value:find("_") then
			s.fields[_n("address")]:depends({ [_n("protocol")] = value })
			s.fields[_n("port")]:depends({ [_n("protocol")] = value })
		end
	end
end

o = s:option(Value, _n("username"), translate("Username"))
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(ListValue, _n("security"), translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(Value, _n("encryption"), translate("Encrypt Method") .. " (encryption)")
o.default = "none"
o.placeholder = "none"
o:depends({ [_n("protocol")] = "vless" })
o.validate = function(self, value)
	value = api.trim(value)
	return (value == "" and "none" or value)
end

o = s:option(ListValue, _n("ss_method"), translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("iv_check"), translate("IV Check"))
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "aes-128-gcm" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "aes-256-gcm" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "chacha20-poly1305" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "xchacha20-poly1305" })

o = s:option(Flag, _n("uot"), translate("UDP over TCP"))
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Value, _n("uuid"), translate("ID"))
o.password = true
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })

o = s:option(ListValue, _n("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ [_n("protocol")] = "vless" })

---- [[hysteria2]]
o = s:option(Value, _n("hysteria2_hop"), translate("Port hopping range"))
o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_hop_interval"), translate("Hop Interval"), translate("Example:") .. "30s (≥5s)")
o.placeholder = "30s"
o.default = "30s"
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_up_mbps"), translate("Max upload Mbps"))
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_down_mbps"), translate("Max download Mbps"))
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(ListValue, _n("hysteria2_obfs_type"), translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_obfs_password"), translate("Obfs Password"))
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_auth_password"), translate("Auth Password"))
o.password = true
o:depends({ [_n("protocol")] = "hysteria2"})

o = s:option(Value, _n("hysteria2_idle_timeout"), translate("Idle Timeout"), translate("Example:") .. "30s (4s-120s)")
o:depends({ [_n("protocol")] = "hysteria2"})

o = s:option(Flag, _n("hysteria2_disable_mtu_discovery"), translate("Disable MTU detection"))
o.default = "0"
o:depends({ [_n("protocol")] = "hysteria2"})
---- [[hysteria2 end]]

o = s:option(Flag, _n("tls"), translate("TLS"))
o.default = 0
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("reality"), translate("REALITY"), translate("Only recommend to use with VLESS-TCP-XTLS-Vision."))
o.default = 0
o:depends({ [_n("tls")] = true, [_n("transport")] = "raw" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "ws" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "grpc" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "httpupgrade" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "xhttp" })

o = s:option(ListValue, _n("alpn"), translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "hysteria2" })

-- o = s:option(Value, _n("minversion"), translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
-- o:depends({ [_n("tls")] = true })

o = s:option(Value, _n("tls_serverName"), translate("Domain"))
o:depends({ [_n("tls")] = true })
o:depends({ [_n("protocol")] = "hysteria2" })

if api.compare_versions(os.date("%Y.%m.%d"), "<", "2026.6.1") then
	o = s:option(Flag, _n("tls_allowInsecure"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
	o.default = "0"
	o:depends({ [_n("tls")] = true, [_n("reality")] = false })
	o:depends({ [_n("protocol")] = "hysteria2" })
end

if api.compare_versions(xray_version, ">=", "26.1.31") then
	o = s:option(Value, _n("tls_CertSha"), translate("TLS Chain Fingerprint (SHA256)"), translate("Once set, connects only when the server’s chain fingerprint matches."))
	o:depends({ [_n("tls")] = true, [_n("reality")] = false })
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(Value, _n("tls_CertByName"), translate("TLS Certificate Name (CertName)"), translate("TLS is used to verify the leaf certificate name."))
	o:depends({ [_n("tls")] = true, [_n("reality")] = false })
	o:depends({ [_n("protocol")] = "hysteria2" })
end

o = s:option(Flag, _n("ech"), translate("ECH"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(TextValue, _n("ech_config"), translate("ECH Config"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ [_n("ech")] = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

o = s:option(ListValue, _n("ech_ForceQuery"), translate("ECH Query Policy"), translate("Controls the policy used when performing DNS queries for ECH configuration."))
o.default = "none"
o:value("none")
o:value("half")
o:value("full")
o:depends({ [_n("ech")] = true })

-- [[ REALITY部分 ]] --
o = s:option(Value, _n("reality_publicKey"), translate("Public Key"))
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Value, _n("reality_shortId"), translate("Short Id"))
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Value, _n("reality_spiderX"), translate("Spider X"))
o.placeholder = "/"
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Flag, _n("utls"), translate("uTLS"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = false })

o = s:option(ListValue, _n("fingerprint"), translate("Finger Print"))
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
o.default = "chrome"
o:depends({ [_n("tls")] = true, [_n("utls")] = true })
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Flag, _n("use_mldsa65Verify"), translate("ML-DSA-65"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(TextValue, _n("reality_mldsa65Verify"), "ML-DSA-65 " .. translate("Public key"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ [_n("use_mldsa65Verify")] = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

o = s:option(ListValue, _n("transport"), translate("Transport"))
o:value("raw", "RAW (TCP)")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("grpc", "gRPC")
o:value("httpupgrade", "HttpUpgrade")
o:value("xhttp", "XHTTP")
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(Value, _n("wireguard_public_key"), translate("Public Key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_secret_key"), translate("Private Key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_preSharedKey"), translate("Pre shared key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(DynamicList, _n("wireguard_local_address"), translate("Local Address"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_mtu"), translate("MTU"))
o.default = "1420"
o:depends({ [_n("protocol")] = "wireguard" })

if api.compare_versions(xray_version, ">=", "1.8.0") then
	o = s:option(Value, _n("wireguard_reserved"), translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	o:depends({ [_n("protocol")] = "wireguard" })
end

o = s:option(Value, _n("wireguard_keepAlive"), translate("Keep Alive"))
o.default = "0"
o:depends({ [_n("protocol")] = "wireguard" })

-- [[ RAW部分 ]]--

-- TCP伪装
o = s:option(ListValue, _n("tcp_guise"), translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ [_n("transport")] = "raw" })

-- HTTP域名
o = s:option(DynamicList, _n("tcp_guise_http_host"), translate("HTTP Host"))
o:depends({ [_n("tcp_guise")] = "http" })

-- HTTP路径
o = s:option(DynamicList, _n("tcp_guise_http_path"), translate("HTTP Path"))
o.placeholder = "/"
o:depends({ [_n("tcp_guise")] = "http" })

-- [[ mKCP部分 ]]--

o = s:option(ListValue, _n("mkcp_guise"), translate("Camouflage Type"), translate('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.'))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_domain"), translate("Camouflage Domain"), translate("Use it together with the DNS disguised type. You can fill in any domain."))
o:depends({ [_n("mkcp_guise")] = "dns" })

o = s:option(Value, _n("mkcp_mtu"), translate("KCP MTU"))
o.default = "1350"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_tti"), translate("KCP TTI"))
o.default = "20"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_uplinkCapacity"), translate("KCP uplinkCapacity"))
o.default = "5"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_downlinkCapacity"), translate("KCP downlinkCapacity"))
o.default = "20"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Flag, _n("mkcp_congestion"), translate("KCP Congestion"))
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_readBufferSize"), translate("KCP readBufferSize"))
o.default = "1"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_writeBufferSize"), translate("KCP writeBufferSize"))
o.default = "1"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_seed"), translate("KCP Seed"))
o:depends({ [_n("transport")] = "mkcp" })

-- [[ WebSocket部分 ]]--
o = s:option(Value, _n("ws_host"), translate("WebSocket Host"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_path"), translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_heartbeatPeriod"), translate("HeartbeatPeriod(second)"))
o.datatype = "integer"
o:depends({ [_n("transport")] = "ws" })

-- [[ gRPC部分 ]]--
o = s:option(Value, _n("grpc_serviceName"), "ServiceName")
o:depends({ [_n("transport")] = "grpc" })

o = s:option(ListValue, _n("grpc_mode"), "gRPC " .. translate("Transfer mode"))
o:value("gun")
o:value("multi")
o:depends({ [_n("transport")] = "grpc" })

o = s:option(Flag, _n("grpc_health_check"), translate("Health check"))
o:depends({ [_n("transport")] = "grpc" })

o = s:option(Value, _n("grpc_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Value, _n("grpc_health_check_timeout"), translate("Health check timeout"))
o.default = "20"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Flag, _n("grpc_permit_without_stream"), translate("Permit without stream"))
o.default = "0"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Value, _n("grpc_initial_windows_size"), translate("Initial Windows Size"))
o.default = "0"
o:depends({ [_n("transport")] = "grpc" })

-- [[ HttpUpgrade部分 ]]--
o = s:option(Value, _n("httpupgrade_host"), translate("HttpUpgrade Host"))
o:depends({ [_n("transport")] = "httpupgrade" })

o = s:option(Value, _n("httpupgrade_path"), translate("HttpUpgrade Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "httpupgrade" })

-- [[ XHTTP部分 ]]--
o = s:option(ListValue, _n("xhttp_mode"), "XHTTP " .. translate("Mode"))
o:depends({ [_n("transport")] = "xhttp" })
o.default = "auto"
o:value("auto")
o:value("packet-up")
o:value("stream-up")
o:value("stream-one")

o = s:option(Value, _n("xhttp_host"), translate("XHTTP Host"))
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(Value, _n("xhttp_path"), translate("XHTTP Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(Flag, _n("use_xhttp_extra"), translate("XHTTP Extra"))
o.default = "0"
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(TextValue, _n("xhttp_extra"), " ", translate("An XHttpObject in JSON format, used for sharing."))
o:depends({ [_n("use_xhttp_extra")] = true })
o.rows = 15
o.wrap = "off"
o.custom_cfgvalue = function(self, section, value)
	local raw = m:get(section, "xhttp_extra")
	if raw then
		return api.base64Decode(raw)
	end
end
o.custom_write = function(self, section, value)
	m:set(section, "xhttp_extra", api.base64Encode(value))
	local success, data = pcall(jsonc.parse, value)
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
o.validate = function(self, value)
	value = value:gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	if value:sub(-1) == "\n" then
		value = value:sub(1, -2)
	end
	return value
end
o.custom_remove = function(self, section, value)
	m:del(section, "xhttp_extra")
	m:del(section, "download_address")
end

-- [[ User-Agent ]]--
o = s:option(Value, _n("user_agent"), translate("User-Agent"))
o:depends({ [_n("tcp_guise")] = "http" })
o:depends({ [_n("transport")] = "ws" })
o:depends({ [_n("transport")] = "httpupgrade" })
o:depends({ [_n("transport")] = "xhttp" })

-- [[ Mux.Cool ]]--
o = s:option(Flag, _n("mux"), "Mux", translate("Enable Mux.Cool"))
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "raw" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "ws" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "grpc" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "httpupgrade" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(Value, _n("mux_concurrency"), translate("Mux concurrency"))
o.default = -1
o:depends({ [_n("mux")] = true })

o = s:option(Value, _n("xudp_concurrency"), translate("XUDP Mux concurrency"))
o.default = 8
o:depends({ [_n("mux")] = true })

o = s:option(Flag, _n("tcp_fast_open"), "TCP " .. translate("Fast Open"))
o.default = 0

--[[tcpMptcp]]
o = s:option(Flag, _n("tcpMptcp"), "tcpMptcp", translate("Enable Multipath TCP, need to be enabled in both server and client configuration."))
o.default = 0

o = s:option(Value, _n("preconns"), translate("Pre-connections"), translate("Number of early established connections to reduce latency."))
o.datatype = "uinteger"
o.placeholder = 0
o:depends({ [_n("protocol")] = "vless" })

o = s:option(ListValue, _n("chain_proxy"), translate("Chain Proxy"))
o:value("", translate("Close(Not use)"))
o:value("1", translate("Preproxy Node"))
o:value("2", translate("Landing Node"))
for i, v in ipairs(s.fields[_n("protocol")].keylist) do
	if not v:find("_") then
		o:depends({ [_n("protocol")] = v })
	end
end

o1 = s:option(ListValue, _n("preproxy_node"), translate("Preproxy Node"), translate("Only support a layer of proxy."))
o1:depends({ [_n("chain_proxy")] = "1" })
o1.template = appname .. "/cbi/nodes_listvalue"
o1.group = {}

o2 = s:option(ListValue, _n("to_node"), translate("Landing Node"), translate("Only support a layer of proxy."))
o2:depends({ [_n("chain_proxy")] = "2" })
o2.template = appname .. "/cbi/nodes_listvalue"
o2.group = {}

for k, v in pairs(nodes_list) do
	if v.id ~= arg[1] and (not v.chain_proxy or v.chain_proxy == "") then
		o1:value(v.id, v.remark)
		o1.group[#o1.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
		o2:value(v.id, v.remark)
		o2.group[#o2.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end

for i, v in ipairs(s.fields[_n("protocol")].keylist) do
	if not v:find("_") and v ~= "hysteria2" then
		s.fields[_n("tcp_fast_open")]:depends({ [_n("protocol")] = v })
		s.fields[_n("tcpMptcp")]:depends({ [_n("protocol")] = v })
		s.fields[_n("chain_proxy")]:depends({ [_n("protocol")] = v })
	end
end

end
-- [[ Normal single node End ]]

api.luci_types(arg[1], m, s, type_name, option_prefix)

if load_shunt_options then
	local current_node = m.uci:get_all(appname, arg[1]) or {}
	local shunt_lua = loadfile("/usr/lib/lua/luci/model/cbi/passwall/client/include/shunt_options.lua")
	setfenv(shunt_lua, getfenv(1))(m, s, {
		node_id = arg[1],
		node = current_node,
		socks_list = socks_list,
		balancing_list = balancing_list,
		iface_list = iface_list,
		normal_list = nodes_list
	})
end
