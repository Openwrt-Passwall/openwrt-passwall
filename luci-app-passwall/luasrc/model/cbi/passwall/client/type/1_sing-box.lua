local singbox_bin = api.finded_com("sing-box")

if not singbox_bin then
	return
end

-- [[ sing-box ]]
local m, s1 = ...
local type_name = "sing-box"

s1.fields["type"]:value(type_name, "Sing-Box")
if not s1.fields["type"].default then
	s1.fields["type"].default = type_name
end

if s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "server")
s.type_name = type_name
s.option_prefix = "singbox_"

local formvalue_proto = luci.http.formvalue(formvalue_key .. "protocol")

if formvalue_proto then s1.val["protocol"] = formvalue_proto end

local arg_select_proto = luci.http.formvalue("select_proto") or ""

local ss_method_new_list = {
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local ss_method_old_list = {
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20",
}

local security_list = { "none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero" }

local singbox_tags = luci.sys.exec(singbox_bin .. " version  | grep 'Tags:' | awk '{print $2}'")

local singbox_version = api.get_app_version("sing-box"):match("[^v]+")
local version_ge_1_14_0 = api.compare_versions(singbox_version, ">=", "1.14.0")

o = s:option(ListValue, "protocol", translate("Protocol"))
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
o:value("anytls", "AnyTLS")
o:value("ssh", "SSH")
if singbox_tags:find("with_naive_outbound") then
	o:value("naive", "NaïveProxy")
end
if version_ge_1_14_0 then
	o:value("snell", "Snell")
end
o:value("_urltest", translate("URLTest"))
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface"))
function o.custom_cfgvalue(self, section)
	if arg_select_proto ~= "" then
		return arg_select_proto
	else
		return m:get(section, self.config_option)
	end
end

local load_urltest_options = s1.val["protocol"] == "_urltest" or arg_select_proto == "_urltest"
local load_shunt_options = s1.val["protocol"] == "_shunt" or arg_select_proto == "_shunt"
local load_iface_options = s1.val["protocol"] == "_iface" or arg_select_proto == "_iface"
local load_normal_options = true
if load_urltest_options or load_shunt_options or load_iface_options then
	load_normal_options = nil
end
if not arg_select_proto:find("_") then
	load_normal_options = true
end

local netdev_list = api.get_network_devices()
local node_list = api.get_node_list()

if load_urltest_options then -- [[ URLTest Start ]]
	o = s:option(ListValue, "node_add_mode", translate("Node Addition Method"))
	o:depends({ protocol = "_urltest" })
	o.default = "manual"
	o:value("manual", translate("Manual"))
	o:value("batch", translate("Batch"))

	o = s:option(MultiValue, "urltest_node", translate("URLTest node list"), translate("List of nodes to test, <a target='_blank' href='https://sing-box.sagernet.org/configuration/outbound/urltest'>document</a>"))
	o:depends({ node_add_mode = "manual" })
	o.widget = "checkbox"
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
	-- 读取旧 DynamicList
	function o.custom_cfgvalue(self, section)
		return table.concat(m:get(section, "urltest_node") or {}, " ")
	end
	-- 写入保持 DynamicList
	function o.custom_write(self, section, value)
		local old = m:get(section, "urltest_node") or {}
		local new, set = {}, {}
		for v in value:gmatch("%S+") do
			new[#new + 1] = v
			set[v] = 1
		end
		for _, v in ipairs(old) do
			if not set[v] then
				m:set(section, "urltest_node", new)
				return
			end
			set[v] = nil
		end
		for _ in pairs(set) do
			m:set(section, "urltest_node", new)
			return
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

	o = s:option(Value, "urltest_url", translate("Probe URL"))
	o:depends({ protocol = "_urltest" })
	o:value("https://cp.cloudflare.com/", "Cloudflare")
	o:value("https://www.gstatic.com/generate_204", "Gstatic")
	o:value("https://www.google.com/generate_204", "Google")
	o:value("https://www.youtube.com/generate_204", "YouTube")
	o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
	o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
	o:value("https://wifi.vivo.com.cn/generate_204", "VIVO (CN)")
	o.default = o.keylist[3]
	o.description = translate("The URL used to detect the connection status.")

	o = s:option(Value, "urltest_interval", translate("Test interval"))
	o:depends({ protocol = "_urltest" })
	o.default = "3m"
	o.placeholder = "3m"
	o.description = translate("The interval between initiating probes.") .. "<br>" ..
			translate("The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.") .. "<br>" ..
			translate("When the unit is not filled in, it defaults to seconds.") .. "<br>" ..
			translate("Test interval must be less or equal than idle timeout.")

	o = s:option(Value, "urltest_tolerance", translate("Test tolerance"), translate("The test tolerance in milliseconds."))
	o:depends({ protocol = "_urltest" })
	o.datatype = "uinteger"
	o.placeholder = "50"
	o.default = "50"

	o = s:option(Value, "urltest_idle_timeout", translate("Idle timeout"))
	o:depends({ protocol = "_urltest" })
	o.placeholder = "30m"
	o.default = "30m"
	o.description = translate("The idle timeout.") .. "<br>" ..
			translate("The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.") .. "<br>" ..
			translate("When the unit is not filled in, it defaults to seconds.")

	o = s:option(Flag, "urltest_interrupt_exist_connections", translate("Interrupt existing connections"))
	o:depends({ protocol = "_urltest" })
	o.default = "0"
	o.description = translate("Interrupt existing connections when the selected outbound has changed.") 
end -- [[ URLTest End ]]

if load_iface_options then -- [[ 自定义接口 Start ]]
	o = s:option(Value, "iface", translate("Interface"))
	o:depends({ protocol = "_iface" })
	for _, d in ipairs(netdev_list) do
		o:value(d.name, d.label)
	end
end


if load_normal_options then

o = s:option(Value, "address", translate("Address (Support Domain Name)"))

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "uuid", translate("ID"))
o.password = true
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "tuic" })

o = s:option(Value, "username", translate("Username"))
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "ssh" })
o:depends({ protocol = "naive" })

o = s:option(Value, "password", translate("Password"))
o.password = true
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "tuic" })
o:depends({ protocol = "anytls" })
o:depends({ protocol = "ssh" })
o:depends({ protocol = "naive" })

if version_ge_1_14_0 then
	-- snell
	s.fields["password"]:depends({ protocol = "snell" })

	o = s:option(Value, "snell_psk", translate("Pre shared key"))
	o.rmempty = false
	o:depends({ protocol = "snell" })

	o = s:option(ListValue, "snell_version", translate("Version"))
	o:value("4")
	o:value("6")
	o:depends({ protocol = "snell" })

	o = s:option(Flag, "snell_reuse", translate("Connection Reuse"))
	o:depends({ protocol = "snell" })

	o = s:option(ListValue, "snell_network", translate("Transport"))
	o:value("", "TCP UDP")
	o:value("tcp", "TCP")
	o:value("udp", "UDP")
	o:depends({ protocol = "snell" })

	o = s:option(ListValue, "snell_obfs_mode", translate("Camouflage Type"))
	o:value("none")
	o:value("http")
	o:depends({ protocol = "snell", snell_version = "4" })

	o = s:option(Value, "snell_obfs_host", translate("HTTP Host"))
	o:depends({ protocol = "snell", snell_version = "4", snell_obfs_mode = "http" })

	o = s:option(ListValue, "snell_mode", translate("Mode"))
	o:value("default")
	o:value("unshaped")
	o:value("unsafe-raw")
	o:depends({ protocol = "snell", snell_version = "6" })
end

o = s:option(ListValue, "security", translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ protocol = "vmess" })

o = s:option(ListValue, "ss_method", translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_new_list) do o:value(t) end
for a, t in ipairs(ss_method_old_list) do o:value(t) end
o:depends({ protocol = "shadowsocks" })

o = s:option(Flag, "uot", translate("UDP over TCP"))
o:depends({ protocol = "socks" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "naive" })

o = s:option(Value, "alter_id", "Alter ID")
o.datatype = "uinteger"
o.default = "0"
o:depends({ protocol = "vmess" })

o = s:option(Flag, "global_padding", "global_padding", translate("Protocol parameter. Will waste traffic randomly if enabled."))
o.default = "0"
o:depends({ protocol = "vmess" })

o = s:option(Flag, "authenticated_length", "authenticated_length", translate("Protocol parameter. Enable length block encryption."))
o.default = "0"
o:depends({ protocol = "vmess" })

o = s:option(ListValue, "flow", translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ protocol = "vless", tls = true })

if singbox_tags:find("with_quic") then
	o = s:option(Value, "hysteria_hop", translate("Port hopping range"))
	o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_hop_interval", translate("Hop Interval(second)"), translate("Example:") .. "30 (≥5)")
	o.datatype = "uinteger"
	o.placeholder = "30"
	o.default = "30"
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_obfs", translate("Obfs Password"))
	o:depends({ protocol = "hysteria" })

	o = s:option(ListValue, "hysteria_auth_type", translate("Auth Type"))
	o:value("disable", translate("Disable"))
	o:value("string", translate("STRING"))
	o:value("base64", translate("BASE64"))
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_auth_password", translate("Auth Password"))
	o.password = true
	o:depends({ protocol = "hysteria", hysteria_auth_type = "string"})
	o:depends({ protocol = "hysteria", hysteria_auth_type = "base64"})

	o = s:option(Value, "hysteria_up_mbps", translate("Max upload Mbps"))
	o.default = "10"
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_down_mbps", translate("Max download Mbps"))
	o.default = "50"
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_recv_window_conn", translate("QUIC stream receive window"))
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_recv_window", translate("QUIC connection receive window"))
	o:depends({ protocol = "hysteria" })

	o = s:option(Flag, "hysteria_disable_mtu_discovery", translate("Disable MTU detection"))
	o:depends({ protocol = "hysteria" })
end

if singbox_tags:find("with_quic") then
	o = s:option(ListValue, "tuic_congestion_control", translate("Congestion control algorithm"))
	o.default = "cubic"
	o:value("bbr", translate("BBR"))
	o:value("cubic", translate("CUBIC"))
	o:value("new_reno", translate("New Reno"))
	o:depends({ protocol = "tuic" })

	o = s:option(ListValue, "tuic_udp_relay_mode", translate("UDP relay mode"))
	o.default = "native"
	o:value("native", translate("native"))
	o:value("quic", translate("QUIC"))
	o:depends({ protocol = "tuic" })

	--[[
	o = s:option(Flag, "tuic_udp_over_stream", translate("UDP over stream"))
	o:depends({ protocol = "tuic" })
	]]--

	o = s:option(Flag, "tuic_zero_rtt_handshake", translate("Enable 0-RTT QUIC handshake"))
	o.default = 0
	o:depends({ protocol = "tuic" })

	o = s:option(Value, "tuic_heartbeat", translate("Heartbeat interval(second)"))
	o.datatype = "uinteger"
	o.default = "3"
	o:depends({ protocol = "tuic" })

	o = s:option(ListValue, "tuic_alpn", translate("QUIC TLS ALPN"))
	o.default = "default"
	o:value("default", translate("Default"))
	o:value("h3")
	o:value("h2")
	o:value("h3,h2")
	o:value("http/1.1")
	o:value("h2,http/1.1")
	o:value("h3,h2,http/1.1")
	o:value("spdy/3.1")
	o:value("h3,spdy/3.1")
	o:depends({ protocol = "tuic" })
end

if singbox_tags:find("with_quic") then
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
	if version_ge_1_14_0 then
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

	o = s:option(Value, "hysteria2_idle_timeout", translate("Idle Timeout"), translate("Units:seconds") .. " (4~120)")
	o.datatype = "range(4,120)"
	o:depends({ protocol = "hysteria2"})

	o = s:option(Value, "hysteria2_keep_alive_period", translate("QUIC KeepAlive interval"), translate("Units:seconds") .. " (2~60)")
	o.datatype = "range(2,60)"
	o:depends({ protocol = "hysteria2"})

	o = s:option(Flag, "hysteria2_disable_mtu_discovery", translate("Disable MTU detection"))
	o.default = "0"
	o:depends({ protocol = "hysteria2"})
end

-- [[ SSH config start ]] --
o = s:option(TextValue, "ssh_priv_key", translate("Private Key"))
o.rows = 5
o.wrap = "off"
o:depends({ protocol = "ssh" })
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value
end

o = s:option(Value, "ssh_priv_key_pp", translate("Private Key Passphrase"))
o.password = true
o:depends({ protocol = "ssh" })

o = s:option(DynamicList, "ssh_host_key", translate("Host Key"), translate("Accept any if empty."))
o:depends({ protocol = "ssh" })

o = s:option(DynamicList, "ssh_host_key_algo", translate("Host Key Algorithms"))
o:depends({ protocol = "ssh" })

o = s:option(Value, "ssh_client_version", translate("Client Version"), translate("Random version will be used if empty."))
o:depends({ protocol = "ssh" })
-- [[ SSH config end ]] --

-- [[ naive start ]] --
o = s:option(Value, "naive_insecure_concurrency", translate("Concurrent Tunnels"))
o.datatype = "uinteger"
o.placeholder = "0"
o.default = "0"
o:depends({ protocol = "naive" })

o = s:option(Flag, "naive_quic", translate("QUIC"))
o.default = 0
o:depends({ protocol = "naive" })

o = s:option(ListValue, "naive_congestion_control", translate("Congestion control algorithm"))
o.default = "bbr"
o:value("bbr", translate("BBR"))
o:value("bbr2", translate("BBRv2"))
o:value("cubic", translate("CUBIC"))
o:value("reno", translate("New Reno"))
o:depends({ naive_quic = "1" })
-- [[ naive end ]] --

o = s:option(Flag, "tls", translate("TLS"))
o.default = 0
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "http" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "anytls" })

o = s:option(ListValue, "alpn", translate("ALPN"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ tls = true })
o:depends({ protocol = "hysteria" })

o = s:option(Flag, "tls_disable_sni", translate("Disable SNI"), translate("Do not send server name in ClientHello."))
o.default = "0"
o:depends({ tls = true })
o:depends({ protocol = "hysteria"})
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "tls_serverName", "SNI " .. translate("Domain"))
o:depends({ tls = true })
o:depends({ protocol = "hysteria"})
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria2" })
o:depends({ protocol = "naive" })

o = s:option(Flag, "tls_allowInsecure", translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"
o:depends({ tls = true })
o:depends({ protocol = "hysteria"})
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria2" })

o = s:option(Flag, "tls_certificate", translate("TLS Certificate (PEM)"))
o.default = "0"
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria"})
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria2" })
o:depends({ protocol = "naive" })

o = s:option(TextValue, "tls_certificate_pem", "　", translate("Full certificate (chain), PEM format."))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ tls_certificate = true })
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value
end

o = s:option(Value, "cipherSuites", translate("Cipher Suites"), '<a href="https://go.dev/src/crypto/tls/cipher_suites.go#L44" target="_blank">***</a>' .. " " .. translate("Configures the list of supported cipher suites, separated by :"))
o:depends({ tls = true })

o = s:option(Flag, "ech", translate("ECH"))
o.default = "0"
o:depends({ tls = true, flow = "", reality = false })
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria" })
o:depends({ protocol = "hysteria2", hysteria2_realms = false })
o:depends({ protocol = "naive" })

o = s:option(TextValue, "ech_config", translate("ECH Config"))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ ech = true })
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value
end

o = s:option(Value, "ech_query_server_name", translate("ECH Query Domain"), translate("Overrides the domain name used for ECH HTTPS record queries."))
o:depends({ ech = true })

if singbox_tags:find("with_utls") then
	o = s:option(Flag, "utls", translate("uTLS"))
	o.default = "0"
	o:depends({ tls = true })

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
	o.default = "chrome"
	o:depends({ utls = true })

	-- [[ REALITY部分 ]] --
	o = s:option(Flag, "reality", translate("REALITY"))
	o.default = 0
	o:depends({ protocol = "vless", tls = true })
	o:depends({ protocol = "vmess", tls = true })
	o:depends({ protocol = "shadowsocks", tls = true })
	o:depends({ protocol = "trojan", tls = true })
	o:depends({ protocol = "anytls", tls = true })

	o = s:option(Value, "reality_publicKey", translate("Public Key"))
	o:depends({ reality = true })

	o = s:option(Value, "reality_shortId", translate("Short Id"))
	o:depends({ reality = true })
end

o = s:option(ListValue, "transport", translate("Transport"))
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
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

if singbox_tags:find("with_wireguard") then
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

	o = s:option(Value, "wireguard_reserved", translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	o:depends({ protocol = "wireguard" })
end

-- [[ TCP部分（模拟） ]]--
o = s:option(ListValue, "tcp_guise", translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ transport = "tcp" })

o = s:option(DynamicList, "tcp_guise_http_host", translate("HTTP Host"))
o:depends({ tcp_guise = "http" })

o = s:option(DynamicList, "tcp_guise_http_path", translate("HTTP Path"))
o.placeholder = "/"
o:depends({ tcp_guise = "http" })

-- [[ HTTP部分 ]]--
o = s:option(DynamicList, "http_host", translate("HTTP Host"))
o:depends({ transport = "http" })

o = s:option(Value, "http_path", translate("HTTP Path"))
o.placeholder = "/"
o:depends({ transport = "http" })

o = s:option(Flag, "http_h2_health_check", translate("Health check"))
o:depends({ tls = true, transport = "http" })

o = s:option(Value, "http_h2_read_idle_timeout", translate("Idle timeout"))
o.default = "15"
o:depends({ http_h2_health_check = true })

o = s:option(Value, "http_h2_health_check_timeout", translate("Health check timeout"))
o.default = "15"
o:depends({ http_h2_health_check = true })

-- [[ WebSocket部分 ]]--
o = s:option(Value, "ws_host", translate("WebSocket Host"))
o:depends({ transport = "ws" })

o = s:option(Value, "ws_path", translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ transport = "ws" })

o = s:option(Flag, "ws_enableEarlyData", translate("Enable early data"))
o:depends({ transport = "ws" })

o = s:option(Value, "ws_maxEarlyData", translate("Early data length"))
o.default = "1024"
o:depends({ ws_enableEarlyData = true })

o = s:option(Value, "ws_earlyDataHeaderName", translate("Early data header name"), translate("Recommended value: Sec-WebSocket-Protocol"))
o:depends({ ws_enableEarlyData = true })

-- [[ HTTPUpgrade部分 ]]--
o = s:option(Value, "httpupgrade_host", translate("HTTPUpgrade Host"))
o:depends({ transport = "httpupgrade" })

o = s:option(Value, "httpupgrade_path", translate("HTTPUpgrade Path"))
o.placeholder = "/"
o:depends({ transport = "httpupgrade" })

-- [[ gRPC部分 ]]--
o = s:option(Value, "grpc_serviceName", "ServiceName")
o:depends({ transport = "grpc" })

o = s:option(Flag, "grpc_health_check", translate("Health check"))
o:depends({ transport = "grpc" })

o = s:option(Value, "grpc_idle_timeout", translate("Idle timeout"))
o.default = "15"
o:depends({ grpc_health_check = true })

o = s:option(Value, "grpc_health_check_timeout", translate("Health check timeout"))
o.default = "15"
o:depends({ grpc_health_check = true })

o = s:option(Flag, "grpc_permit_without_stream", translate("Permit without stream"))
o.default = "0"
o:depends({ grpc_health_check = true })

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
o:depends({ transport = "http" })
o:depends({ transport = "ws" })
o:depends({ transport = "httpupgrade" })
o:depends({ protocol = "naive" })

-- [[ Mux ]]--
o = s:option(Flag, "mux", translate("Mux"))
o.rmempty = false
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless", flow = "" })
o:depends({ protocol = "shadowsocks", uot = "" })
o:depends({ protocol = "trojan" })

o = s:option(ListValue, "mux_type", translate("Mux"))
o:value("smux")
o:value("yamux")
o:value("h2mux")
o:depends({ mux = true })

o = s:option(Value, "mux_concurrency", translate("Mux concurrency"))
o.default = 4
o:depends({ mux = true, tcpbrutal = false })

o = s:option(Flag, "mux_padding", translate("Padding"))
o.default = 0
o:depends({ mux = true })

-- [[ TCP Brutal ]]--
o = s:option(Flag, "tcpbrutal", translate("TCP Brutal"))
o.default = 0
o:depends({ mux = true })

o = s:option(Value, "tcpbrutal_up_mbps", translate("Max upload Mbps"))
o.default = "10"
o:depends({ tcpbrutal = true })

o = s:option(Value, "tcpbrutal_down_mbps", translate("Max download Mbps"))
o.default = "50"
o:depends({ tcpbrutal = true })

o = s:option(Flag, "shadowtls", "ShadowTLS")
o.default = 0
o:depends({ protocol = "vmess", tls = false })
o:depends({ protocol = "shadowsocks", tls = false })

o = s:option(ListValue, "shadowtls_version", "ShadowTLS " .. translate("Version"))
o.default = "1"
o:value("1", "ShadowTLS v1")
o:value("2", "ShadowTLS v2")
o:value("3", "ShadowTLS v3")
o:depends({ shadowtls = true })

o = s:option(Value, "shadowtls_password", "ShadowTLS " .. translate("Password"))
o.password = true
o:depends({ shadowtls = true, shadowtls_version = "2" })
o:depends({ shadowtls = true, shadowtls_version = "3" })

o = s:option(Value, "shadowtls_serverName", "ShadowTLS " .. translate("Domain"))
o:depends({ shadowtls = true })

if singbox_tags:find("with_utls") then
	o = s:option(Flag, "shadowtls_utls", "ShadowTLS " .. translate("uTLS"))
	o.default = "0"
	o:depends({ shadowtls = true })

	o = s:option(ListValue, "shadowtls_fingerprint", "ShadowTLS " .. translate("Finger Print"))
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
	o:depends({ shadowtls = true, shadowtls_utls = true })
end

-- [[ SIP003 plugin ]]--
o = s:option(Flag, "plugin_enabled", translate("plugin"))
o.default = 0
o:depends({ protocol = "shadowsocks" })

o = s:option(ListValue, "plugin", "SIP003 " .. translate("plugin"))
o.default = "obfs-local"
o:depends({ plugin_enabled = true })
o:value("obfs-local")
o:value("v2ray-plugin")

o = s:option(Value, "plugin_opts", translate("opts"))
o:depends({ plugin_enabled = true })

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
o:value("prefer_ipv4", translate("Prefer IPv4"))
o:value("prefer_ipv6", translate("Prefer IPv6"))
o:value("ipv4_only", translate("IPv4 Only"))
o:value("ipv6_only", translate("IPv6 Only"))


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
			s.fields["domain_strategy"]:depends(depends_condition)
		end
	end
end
end
-- [[ Normal single node End ]]

if not load_shunt_options then
	o = s:option(ListValue, "chain_proxy", translate("Chain Proxy"))
	o:value("", translate("Close(Not use)"))
	if not (load_iface_options or load_urltest_options) then
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
				if v.id ~= arg[1] then
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

api.luci_types(s1, s)

if load_shunt_options then
	local current_node = m:get(arg[1]) or {}
	local shunt_lua = loadfile("/usr/lib/lua/luci/model/cbi/passwall/client/include/shunt_options.lua")
	setfenv(shunt_lua, getfenv(1))(m, s1, {
		node_id = arg[1],
		node = current_node,
		node_list = node_list,
	})
end
