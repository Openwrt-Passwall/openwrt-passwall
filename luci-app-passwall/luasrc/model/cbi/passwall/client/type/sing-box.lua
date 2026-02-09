local m, s = ...

local singbox_bin = api.finded_com("sing-box")

if not singbox_bin then
	return
end

type_name = "sing-box"

-- [[ sing-box ]]

s.fields["type"]:value(type_name, "Sing-Box")
if not s.fields["type"].default then
	s.fields["type"].default = type_name
end

if s.val["type"] ~= type_name then
	return
end

local option_prefix = "singbox_"

local function _n(name)
	return option_prefix .. name
end

local formvalue_key = "cbid." .. appname .. "." .. arg[1] .. "."
local formvalue_proto = luci.http.formvalue(formvalue_key .. _n("protocol"))

if formvalue_proto then s.val["protocol"] = formvalue_proto end

local arg_select_proto = luci.http.formvalue("select_proto") or ""

local ss_method_new_list = {
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local ss_method_old_list = {
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20",
}

local security_list = { "none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero" }

local local_version = api.get_app_version("sing-box")
local version_ge_1_12_0 = api.compare_versions(local_version:match("[^v]+"), ">=", "1.12.0")

local singbox_tags = luci.sys.exec(singbox_bin .. " version  | grep 'Tags:' | awk '{print $2}'")

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
o:value("socks", "Socks")
o:value("http", "HTTP")
o:value("shadowsocks", "Shadowsocks")
o:value("vmess", "Vmess")
o:value("trojan", "Trojan")
if singbox_tags:find("with_wireguard") then
	o:value("wireguard", "WireGuard")
end
if singbox_tags:find("with_quic") then
	o:value("hysteria", "Hysteria")
end
o:value("vless", "VLESS")
if singbox_tags:find("with_quic") then
	o:value("tuic", "TUIC")
end
if singbox_tags:find("with_quic") then
	o:value("hysteria2", "Hysteria2")
end
if version_ge_1_12_0 then
	o:value("anytls", "AnyTLS")
end
o:value("ssh", "SSH")
o:value("_urltest", translate("URLTest"))
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface"))
function o.custom_cfgvalue(self, section)
	if arg_select_proto ~= "" then
		return arg_select_proto
	else
		return m:get(section, self.option:sub(1 + #option_prefix))
	end
end

local load_urltest_options = s.val["protocol"] == "_urltest" or arg_select_proto == "_urltest"
local load_shunt_options = s.val["protocol"] == "_shunt" or arg_select_proto == "_shunt"
local load_iface_options = s.val["protocol"] == "_iface" or arg_select_proto == "_iface"
local load_normal_options = true
if load_urltest_options or load_shunt_options or load_iface_options then
	load_normal_options = nil
end
if not arg_select_proto:find("_") then
	load_normal_options = true
end

local nodes_list = {}
local iface_list = {}
local urltest_list = {}
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
	if e.protocol == "_iface" then
		iface_list[#iface_list + 1] = {
			id = e[".name"],
			remark = e["remark"],
			group = e["group"]
		}
	end
	if e.protocol == "_urltest" then
		urltest_list[#urltest_list + 1] = {
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

if load_urltest_options then -- [[ URLTest Start ]]
	o = s:option(ListValue, _n("node_add_mode"), translate("Node Addition Method"))
	o:depends({ [_n("protocol")] = "_urltest" })
	o.default = "manual"
	o:value("manual", translate("Manual"))
	o:value("batch", translate("Batch"))

	o = s:option(MultiValue, _n("urltest_node"), translate("URLTest node list"), translate("List of nodes to test, <a target='_blank' href='https://sing-box.sagernet.org/configuration/outbound/urltest'>document</a>"))
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
		return m.uci:get_list(appname, section, "urltest_node") or {}
	end
	-- 写入保持 DynamicList
	function o.custom_write(self, section, value)
		local old = m.uci:get_list(appname, section, "urltest_node") or {}
		local new, set = {}, {}
		for v in value:gmatch("%S+") do
			new[#new + 1] = v
			set[v] = 1
		end
		for _, v in ipairs(old) do
			if not set[v] then
				m.uci:set_list(appname, section, "urltest_node", new)
				return
			end
			set[v] = nil
		end
		for _ in pairs(set) do
			m.uci:set_list(appname, section, "urltest_node", new)
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

	o = s:option(Value, _n("urltest_url"), translate("Probe URL"))
	o:depends({ [_n("protocol")] = "_urltest" })
	o:value("https://cp.cloudflare.com/", "Cloudflare")
	o:value("https://www.gstatic.com/generate_204", "Gstatic")
	o:value("https://www.google.com/generate_204", "Google")
	o:value("https://www.youtube.com/generate_204", "YouTube")
	o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
	o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
	o.default = o.keylist[3]
	o.description = translate("The URL used to detect the connection status.")

	o = s:option(Value, _n("urltest_interval"), translate("Test interval"))
	o:depends({ [_n("protocol")] = "_urltest" })
	o.default = "3m"
	o.placeholder = "3m"
	o.description = translate("The interval between initiating probes.") .. "<br>" ..
			translate("The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.") .. "<br>" ..
			translate("When the unit is not filled in, it defaults to seconds.") .. "<br>" ..
			translate("Test interval must be less or equal than idle timeout.")

	o = s:option(Value, _n("urltest_tolerance"), translate("Test tolerance"), translate("The test tolerance in milliseconds."))
	o:depends({ [_n("protocol")] = "_urltest" })
	o.datatype = "uinteger"
	o.placeholder = "50"
	o.default = "50"

	o = s:option(Value, _n("urltest_idle_timeout"), translate("Idle timeout"))
	o:depends({ [_n("protocol")] = "_urltest" })
	o.placeholder = "30m"
	o.default = "30m"
	o.description = translate("The idle timeout.") .. "<br>" ..
			translate("The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.") .. "<br>" ..
			translate("When the unit is not filled in, it defaults to seconds.")

	o = s:option(Flag, _n("urltest_interrupt_exist_connections"), translate("Interrupt existing connections"))
	o:depends({ [_n("protocol")] = "_urltest" })
	o.default = "0"
	o.description = translate("Interrupt existing connections when the selected outbound has changed.") 
end -- [[ URLTest End ]]

if load_iface_options then -- [[ 自定义接口 Start ]]
	o = s:option(Value, _n("iface"), translate("Interface"))
	o.default = "eth1"
	o:depends({ [_n("protocol")] = "_iface" })
end


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
o:depends({ [_n("protocol")] = "ssh" })

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "anytls" })
o:depends({ [_n("protocol")] = "ssh" })

o = s:option(ListValue, _n("security"), translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(ListValue, _n("ss_method"), translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_new_list) do o:value(t) end
for a, t in ipairs(ss_method_old_list) do o:value(t) end
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("uot"), translate("UDP over TCP"))
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Value, _n("uuid"), translate("ID"))
o.password = true
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "tuic" })

o = s:option(Value, _n("alter_id"), "Alter ID")
o.datatype = "uinteger"
o.default = "0"
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(Flag, _n("global_padding"), "global_padding", translate("Protocol parameter. Will waste traffic randomly if enabled."))
o.default = "0"
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(Flag, _n("authenticated_length"), "authenticated_length", translate("Protocol parameter. Enable length block encryption."))
o.default = "0"
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(ListValue, _n("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ [_n("protocol")] = "vless", [_n("tls")] = true })

if singbox_tags:find("with_quic") then
	o = s:option(Value, _n("hysteria_hop"), translate("Port hopping range"))
	o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_hop_interval"), translate("Hop Interval"), translate("Example:") .. "30s (≥5s)")
	o.placeholder = "30s"
	o.default = "30s"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_obfs"), translate("Obfs Password"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(ListValue, _n("hysteria_auth_type"), translate("Auth Type"))
	o:value("disable", translate("Disable"))
	o:value("string", translate("STRING"))
	o:value("base64", translate("BASE64"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_auth_password"), translate("Auth Password"))
	o.password = true
	o:depends({ [_n("protocol")] = "hysteria", [_n("hysteria_auth_type")] = "string"})
	o:depends({ [_n("protocol")] = "hysteria", [_n("hysteria_auth_type")] = "base64"})

	o = s:option(Value, _n("hysteria_up_mbps"), translate("Max upload Mbps"))
	o.default = "10"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_down_mbps"), translate("Max download Mbps"))
	o.default = "50"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_recv_window_conn"), translate("QUIC stream receive window"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_recv_window"), translate("QUIC connection receive window"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Flag, _n("hysteria_disable_mtu_discovery"), translate("Disable MTU detection"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_alpn"), translate("QUIC TLS ALPN"))
	o:depends({ [_n("protocol")] = "hysteria" })
end

if singbox_tags:find("with_quic") then
	o = s:option(ListValue, _n("tuic_congestion_control"), translate("Congestion control algorithm"))
	o.default = "cubic"
	o:value("bbr", translate("BBR"))
	o:value("cubic", translate("CUBIC"))
	o:value("new_reno", translate("New Reno"))
	o:depends({ [_n("protocol")] = "tuic" })

	o = s:option(ListValue, _n("tuic_udp_relay_mode"), translate("UDP relay mode"))
	o.default = "native"
	o:value("native", translate("native"))
	o:value("quic", translate("QUIC"))
	o:depends({ [_n("protocol")] = "tuic" })

	--[[
	o = s:option(Flag, _n("tuic_udp_over_stream"), translate("UDP over stream"))
	o:depends({ [_n("protocol")] = "tuic" })
	]]--

	o = s:option(Flag, _n("tuic_zero_rtt_handshake"), translate("Enable 0-RTT QUIC handshake"))
	o.default = 0
	o:depends({ [_n("protocol")] = "tuic" })

	o = s:option(Value, _n("tuic_heartbeat"), translate("Heartbeat interval(second)"))
	o.datatype = "uinteger"
	o.default = "3"
	o:depends({ [_n("protocol")] = "tuic" })

	o = s:option(ListValue, _n("tuic_alpn"), translate("QUIC TLS ALPN"))
	o.default = "default"
	o:value("default", translate("Default"))
	o:value("h3")
	o:value("h2")
	o:value("h3,h2")
	o:value("http/1.1")
	o:value("h2,http/1.1")
	o:value("h3,h2,http/1.1")
	o:depends({ [_n("protocol")] = "tuic" })
end

if singbox_tags:find("with_quic") then
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
end

-- [[ SSH config start ]] --
o = s:option(Value, _n("ssh_priv_key"), translate("Private Key"))
o:depends({ [_n("protocol")] = "ssh" })

o = s:option(Value, _n("ssh_priv_key_pp"), translate("Private Key Passphrase"))
o.password = true
o:depends({ [_n("protocol")] = "ssh" })

o = s:option(DynamicList, _n("ssh_host_key"), translate("Host Key"), translate("Accept any if empty."))
o:depends({ [_n("protocol")] = "ssh" })

o = s:option(DynamicList, _n("ssh_host_key_algo"), translate("Host Key Algorithms"))
o:depends({ [_n("protocol")] = "ssh" })

o = s:option(Value, _n("ssh_client_version"), translate("Client Version"), translate("Random version will be used if empty."))
o:depends({ [_n("protocol")] = "ssh" })
-- [[ SSH config end ]] --

o = s:option(Flag, _n("tls"), translate("TLS"))
o.default = 0
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "anytls" })

o = s:option(ListValue, _n("alpn"), translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ [_n("tls")] = true })

o = s:option(Flag, _n("tls_disable_sni"), translate("Disable SNI"), translate("Do not send server name in ClientHello."))
o.default = "0"
o:depends({ [_n("tls")] = true })
o:depends({ [_n("protocol")] = "hysteria"})
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Value, _n("tls_serverName"), translate("Domain"))
o:depends({ [_n("tls")] = true })
o:depends({ [_n("protocol")] = "hysteria"})
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("tls_allowInsecure"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"
o:depends({ [_n("tls")] = true })
o:depends({ [_n("protocol")] = "hysteria"})
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("ech"), translate("ECH"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("flow")] = "", [_n("reality")] = false })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria" })
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(TextValue, _n("ech_config"), translate("ECH Config"))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ [_n("ech")] = true })
o.validate = function(self, value)
	value = value:gsub("^%s+", ""):gsub("%s+$","\n"):gsub("\r\n","\n"):gsub("[ \t]*\n[ \t]*", "\n")
	value = value:gsub("^%s*\n", "")
	if value:sub(-1) == "\n" then  
		value = value:sub(1, -2)  
	end
	return value
end

if singbox_tags:find("with_utls") then
	o = s:option(Flag, _n("utls"), translate("uTLS"))
	o.default = "0"
	o:depends({ [_n("tls")] = true })

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
	o:depends({ [_n("utls")] = true })

	-- [[ REALITY部分 ]] --
	o = s:option(Flag, _n("reality"), translate("REALITY"))
	o.default = 0
	o:depends({ [_n("protocol")] = "vless", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "vmess", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "shadowsocks", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "socks", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "trojan", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "anytls", [_n("tls")] = true })
	
	o = s:option(Value, _n("reality_publicKey"), translate("Public Key"))
	o:depends({ [_n("reality")] = true })
	
	o = s:option(Value, _n("reality_shortId"), translate("Short Id"))
	o:depends({ [_n("reality")] = true })
end

o = s:option(ListValue, _n("transport"), translate("Transport"))
o:value("tcp", "TCP")
o:value("http", "HTTP")
o:value("ws", "WebSocket")
o:value("httpupgrade", "HTTPUpgrade")
if singbox_tags:find("with_quic") then
	o:value("quic", "QUIC")
end
if singbox_tags:find("with_grpc") then
	o:value("grpc", "gRPC")
else o:value("grpc", "gRPC-lite")
end
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

if singbox_tags:find("with_wireguard") then
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

	o = s:option(Value, _n("wireguard_reserved"), translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	o:depends({ [_n("protocol")] = "wireguard" })
end

-- [[ TCP部分（模拟） ]]--
o = s:option(ListValue, _n("tcp_guise"), translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ [_n("transport")] = "tcp" })

o = s:option(DynamicList, _n("tcp_guise_http_host"), translate("HTTP Host"))
o:depends({ [_n("tcp_guise")] = "http" })

o = s:option(DynamicList, _n("tcp_guise_http_path"), translate("HTTP Path"))
o.placeholder = "/"
o:depends({ [_n("tcp_guise")] = "http" })

-- [[ HTTP部分 ]]--
o = s:option(DynamicList, _n("http_host"), translate("HTTP Host"))
o:depends({ [_n("transport")] = "http" })

o = s:option(Value, _n("http_path"), translate("HTTP Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "http" })

o = s:option(Flag, _n("http_h2_health_check"), translate("Health check"))
o:depends({ [_n("tls")] = true, [_n("transport")] = "http" })

o = s:option(Value, _n("http_h2_read_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [_n("tls")] = true, [_n("transport")] = "http", [_n("http_h2_health_check")] = true })

o = s:option(Value, _n("http_h2_health_check_timeout"), translate("Health check timeout"))
o.default = "15"
o:depends({ [_n("tls")] = true, [_n("transport")] = "http", [_n("http_h2_health_check")] = true })

-- [[ WebSocket部分 ]]--
o = s:option(Value, _n("ws_host"), translate("WebSocket Host"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_path"), translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "ws" })

o = s:option(Flag, _n("ws_enableEarlyData"), translate("Enable early data"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_maxEarlyData"), translate("Early data length"))
o.default = "1024"
o:depends({ [_n("ws_enableEarlyData")] = true })

o = s:option(Value, _n("ws_earlyDataHeaderName"), translate("Early data header name"), translate("Recommended value: Sec-WebSocket-Protocol"))
o:depends({ [_n("ws_enableEarlyData")] = true })

-- [[ HTTPUpgrade部分 ]]--
o = s:option(Value, _n("httpupgrade_host"), translate("HTTPUpgrade Host"))
o:depends({ [_n("transport")] = "httpupgrade" })

o = s:option(Value, _n("httpupgrade_path"), translate("HTTPUpgrade Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "httpupgrade" })

-- [[ gRPC部分 ]]--
o = s:option(Value, _n("grpc_serviceName"), "ServiceName")
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

-- [[ User-Agent ]]--
o = s:option(Value, _n("user_agent"), translate("User-Agent"))
o:depends({ [_n("tcp_guise")] = "http" })
o:depends({ [_n("transport")] = "http" })
o:depends({ [_n("transport")] = "ws" })
o:depends({ [_n("transport")] = "httpupgrade" })

-- [[ Mux ]]--
o = s:option(Flag, _n("mux"), translate("Mux"))
o.rmempty = false
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless", [_n("flow")] = "" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("uot")] = "" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(ListValue, _n("mux_type"), translate("Mux"))
o:value("smux")
o:value("yamux")
o:value("h2mux")
o:depends({ [_n("mux")] = true })

o = s:option(Value, _n("mux_concurrency"), translate("Mux concurrency"))
o.default = 4
o:depends({ [_n("mux")] = true, [_n("tcpbrutal")] = false })

o = s:option(Flag, _n("mux_padding"), translate("Padding"))
o.default = 0
o:depends({ [_n("mux")] = true })

-- [[ TCP Brutal ]]--
o = s:option(Flag, _n("tcpbrutal"), translate("TCP Brutal"))
o.default = 0
o:depends({ [_n("mux")] = true })

o = s:option(Value, _n("tcpbrutal_up_mbps"), translate("Max upload Mbps"))
o.default = "10"
o:depends({ [_n("tcpbrutal")] = true })

o = s:option(Value, _n("tcpbrutal_down_mbps"), translate("Max download Mbps"))
o.default = "50"
o:depends({ [_n("tcpbrutal")] = true })

o = s:option(Flag, _n("shadowtls"), "ShadowTLS")
o.default = 0
o:depends({ [_n("protocol")] = "vmess", [_n("tls")] = false })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("tls")] = false })

o = s:option(ListValue, _n("shadowtls_version"), "ShadowTLS " .. translate("Version"))
o.default = "1"
o:value("1", "ShadowTLS v1")
o:value("2", "ShadowTLS v2")
o:value("3", "ShadowTLS v3")
o:depends({ [_n("shadowtls")] = true })

o = s:option(Value, _n("shadowtls_password"), "ShadowTLS " .. translate("Password"))
o.password = true
o:depends({ [_n("shadowtls")] = true, [_n("shadowtls_version")] = "2" })
o:depends({ [_n("shadowtls")] = true, [_n("shadowtls_version")] = "3" })

o = s:option(Value, _n("shadowtls_serverName"), "ShadowTLS " .. translate("Domain"))
o:depends({ [_n("shadowtls")] = true })

if singbox_tags:find("with_utls") then
	o = s:option(Flag, _n("shadowtls_utls"), "ShadowTLS " .. translate("uTLS"))
	o.default = "0"
	o:depends({ [_n("shadowtls")] = true })

	o = s:option(ListValue, _n("shadowtls_fingerprint"), "ShadowTLS " .. translate("Finger Print"))
	o:value("chrome")
	o:value("firefox")
	o:value("edge")
	o:value("safari")
	-- o:value("360")
	o:value("qq")
	o:value("ios")
	-- o:value("android")
	o:value("random")
	-- o:value("randomized")
	o.default = "chrome"
	o:depends({ [_n("shadowtls")] = true, [_n("shadowtls_utls")] = true })
end

-- [[ SIP003 plugin ]]--
o = s:option(Flag, _n("plugin_enabled"), translate("plugin"))
o.default = 0
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(ListValue, _n("plugin"), "SIP003 " .. translate("plugin"))
o.default = "obfs-local"
o:depends({ [_n("plugin_enabled")] = true })
o:value("obfs-local")
o:value("v2ray-plugin")

o = s:option(Value, _n("plugin_opts"), translate("opts"))
o:depends({ [_n("plugin_enabled")] = true })

o = s:option(ListValue, _n("domain_strategy"), translate("Domain Strategy"), translate("If is domain name, The requested domain name will be resolved to IP before connect."))
o.default = ""
o:value("", translate("Auto"))
o:value("prefer_ipv4", translate("Prefer IPv4"))
o:value("prefer_ipv6", translate("Prefer IPv6"))
o:value("ipv4_only", translate("IPv4 Only"))
o:value("ipv6_only", translate("IPv6 Only"))
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "wireguard" })
o:depends({ [_n("protocol")] = "hysteria" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o:depends({ [_n("protocol")] = "anytls" })

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

for k, v in pairs(socks_list) do
	o1:value(v.id, v.remark)
	o1.group[#o1.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end

for k, e in ipairs(api.get_valid_nodes()) do
	if e[".name"] ~= arg[1] then
		if e.protocol ~= "_shunt" and e.protocol ~= "_iface" then
			o1:value(e[".name"], e["remark"])
			o1.group[#o1.group+1] = (e["group"] and e["group"] ~= "") and e["group"] or translate("default")
		end
		if not e.protocol:find("_") then
			-- Landing Node not support use special node.
			o2:value(e[".name"], e["remark"])
			o2.group[#o2.group+1] = (e["group"] and e["group"] ~= "") and e["group"] or translate("default")
		end
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
		urltest_list = urltest_list,
		iface_list = iface_list,
		normal_list = nodes_list
	})
end
