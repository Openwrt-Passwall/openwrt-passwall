local singbox_bin = api.finded_com("sing-box")

if not singbox_bin then
	return
end

-- [[ Sing-Box ]]
local m, s1 = ...
local type_name = "sing-box"

s1.fields["type"]:value(type_name, "Sing-Box")
if not s1.fields["type"].default then
	s1.fields["type"].default = type_name
end

if not s1.val["type"] then
	s1.val["type"] = type_name
end

if s1.val["type"] and s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "server")
s.type_name = type_name
s.option_prefix = "singbox_"

local singbox_tags = luci.sys.exec(singbox_bin .. " version  | grep 'Tags:' | awk '{print $2}'")

local ss_method_list = {
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

o = s:option(Flag, "custom", translate("Use Custom Config"))

o = s:option(TextValue, "custom_config", translate("Custom Config") .. " (JSON)")
o.rows = 10
o.wrap = "off"
o:depends({ custom = true })
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	local v = o_validate(self, value)
	if v then return v end
	return nil, translate("Custom Config") .. " " .. translate("Must be JSON text!")
end
o.custom_cfgvalue = function(self, section, value)
	local config_str = m:get(section, "config_str")
	if config_str then
		return api.base64Decode(config_str)
	end
end
o.custom_write = function(self, section, value)
	m:set(section, "config_str", api.base64Encode(value) or "")
end

o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("direct", "Direct")
o:value("mixed", "Mixed")
o:value("socks", "Socks")
o:value("http", "HTTP")
o:value("shadowsocks", "Shadowsocks")
o:value("vmess", "Vmess")
o:value("vless", "VLESS")
o:value("trojan", "Trojan")
if singbox_tags:find("with_naive_outbound") then
	o:value("naive", "Naive")
end
o:value("anytls", "AnyTLS")
o:depends({ custom = false })

o = s:option(Value, "port", translate("Listen Port"))
o.datatype = "port"
o:depends({ custom = false })

o = s:option(DynamicList, "users", translate("User"))
for i, v in ipairs(user_list) do
	o:value(v[".name"], v.username)
end
o:depends({ protocol = "mixed" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "http" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "naive" })
o:depends({ protocol = "anytls" })

if singbox_tags:find("with_quic") then
	-- hysteria
	s.fields["protocol"]:value("hysteria", "Hysteria")
	s.fields["users"]:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_obfs", translate("Obfs Password"))
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_up_mbps", translate("Max upload Mbps"))
	o.default = "100"
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_down_mbps", translate("Max download Mbps"))
	o.default = "100"
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_recv_window_conn", translate("QUIC stream receive window"))
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_recv_window_client", translate("QUIC connection receive window"))
	o:depends({ protocol = "hysteria" })

	o = s:option(Value, "hysteria_max_conn_client", translate("QUIC concurrent bidirectional streams"))
	o.default = "1024"
	o:depends({ protocol = "hysteria" })

	o = s:option(Flag, "hysteria_disable_mtu_discovery", translate("Disable MTU detection"))
	o:depends({ protocol = "hysteria" })
end

if singbox_tags:find("with_quic") then
	-- tuic
	s.fields["protocol"]:value("tuic", "TUIC")
	s.fields["users"]:depends({ protocol = "tuic" })

	o = s:option(ListValue, "tuic_congestion_control", translate("Congestion control algorithm"))
	o.default = "cubic"
	o:value("bbr", translate("BBR"))
	o:value("cubic", translate("CUBIC"))
	o:value("new_reno", translate("New Reno"))
	o:depends({ protocol = "tuic" })

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
	-- hysteria2
	s.fields["protocol"]:value("hysteria2", "Hysteria2")
	s.fields["users"]:depends({ protocol = "hysteria2" })

	o = s:option(Flag, "hysteria2_realms", translate("Realms"))
	o.default = "0"
	o:depends({ protocol = "hysteria2"})

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

	o = s:option(Flag, "hysteria2_ignore_client_bandwidth", translate("Client BBR Flow Control"), translate("Commands the client to use the BBR flow control algorithm"))
	o.default = 0
	o:depends({ protocol = "hysteria2" })

	o = s:option(Value, "hysteria2_up_mbps", translate("Max upload Mbps"))
	o:depends({ protocol = "hysteria2", hysteria2_ignore_client_bandwidth = false })

	o = s:option(Value, "hysteria2_down_mbps", translate("Max download Mbps"))
	o:depends({ protocol = "hysteria2", hysteria2_ignore_client_bandwidth = false })
end

o = s:option(ListValue, "d_protocol", translate("Destination protocol"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("tcp,udp", "TCP,UDP")
o:depends({ protocol = "direct" })

o = s:option(Value, "d_address", translate("Destination address"))
o:depends({ protocol = "direct" })

o = s:option(Value, "d_port", translate("Destination port"))
o.datatype = "port"
o:depends({ protocol = "direct" })

o = s:option(Value, "decryption", translate("Encrypt Method"))
o.default = "none"
o:depends({ protocol = "vless" })

o = s:option(ListValue, "ss_method", translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ protocol = "shadowsocks" })

o = s:option(Value, "ss_password", translate("Password"))
o:depends({ protocol = "shadowsocks" })

o = s:option(ListValue, "flow", translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ protocol = "vless" , tls = true })

o = s:option(Flag, "tls", translate("TLS"))
o.default = 0
o.validate = function(self, value, t)
	if value then
		local reality = s.fields["reality"] and s.fields["reality"]:formvalue(t) or nil
		if reality and reality == "1" then return value end
		if value == "1" then
			local ca = s.fields["tls_certificateFile"] and s.fields["tls_certificateFile"]:formvalue(t) or ""
			local key = s.fields["tls_keyFile"] and s.fields["tls_keyFile"]:formvalue(t) or ""
			if ca == "" or key == "" then
				return nil, translate("Public key and Private key path can not be empty!")
			end
		end
		return value
	end
end
o:depends({ protocol = "http" })
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "anytls" })

-- https://github.com/SagerNet/sing-box/commit/d2a04c4e41e6cef0937331cb6d10211f431caaab
if singbox_tags:find("with_utls") then
	-- [[ REALITY部分 ]] --
	o = s:option(Flag, "reality", translate("REALITY"))
	o.default = 0
	o:depends({ protocol = "http", tls = true })
	o:depends({ protocol = "vmess", tls = true })
	o:depends({ protocol = "vless", tls = true })
	o:depends({ protocol = "trojan", tls = true })
	o:depends({ protocol = "anytls", tls = true })

	o = s:option(Value, "reality_private_key", translate("Private Key"))
	o:depends({ reality = true })

	o = s:option(Value, "reality_shortId", translate("Short Id"))
	o:depends({ reality = true })

	o = s:option(Value, "reality_handshake_server", translate("Handshake Server"))
	o.default = "google.com"
	o:depends({ reality = true })

	o = s:option(Value, "reality_handshake_server_port", translate("Handshake Server Port"))
	o.datatype = "port"
	o.default = "443"
	o:depends({ reality = true })
end

o = s:option(ListValue, "alpn", translate("ALPN"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria" })

-- [[ TLS部分 ]] --

o = s:option(FileUpload, "tls_certificateFile", translate("Public key absolute path"), translate("as:") .. "/etc/ssl/fullchain.pem")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. arg[1] .. ".pem"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o:depends({ tls = true, reality = false })
o:depends({ protocol = "naive" })
o:depends({ protocol = "hysteria" })
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria2" })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not api.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(FileUpload, "tls_keyFile", translate("Private key absolute path"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. arg[1] .. ".key"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o:depends({ tls = true, reality = false })
o:depends({ protocol = "naive" })
o:depends({ protocol = "hysteria" })
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria2" })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not api.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(Flag, "ech", translate("ECH"))
o.default = "0"
o:depends({ tls = true, flow = "", reality = false })
o:depends({ protocol = "naive" })
o:depends({ protocol = "hysteria" })
o:depends({ protocol = "tuic" })
o:depends({ protocol = "hysteria2", hysteria2_realms = false })

o = s:option(TextValue, "ech_key", translate("ECH Key"))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ ech = true })
o.validate = function(self, value)
	value = value:gsub("^%s+", ""):gsub("%s+$","\n"):gsub("\r\n","\n"):gsub("[ \t]*\n[ \t]*", "\n")
	value = value:gsub("^%s*\n", "")
	if value:sub(-1) == "\n" then  
		value = value:sub(1, -2)  
	end
	return value
end

o = s:option(ListValue, "transport", translate("Transport"))
o:value("tcp", "TCP")
o:value("http", "HTTP")
o:value("ws", "WebSocket")
o:value("httpupgrade", "HTTPUpgrade")
o:value("quic", "QUIC")
o:value("grpc", "gRPC")
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "trojan" })

-- [[ HTTP部分 ]]--

o = s:option(DynamicList, "http_host", translate("HTTP Host"))
o:depends({ transport = "http" })

o = s:option(Value, "http_path", translate("HTTP Path"))
o:depends({ transport = "http" })

-- [[ WebSocket部分 ]]--

o = s:option(Value, "ws_host", translate("WebSocket Host"))
o:depends({ transport = "ws" })

o = s:option(Value, "ws_path", translate("WebSocket Path"))
o:depends({ transport = "ws" })

-- [[ HTTPUpgrade部分 ]]--

o = s:option(Value, "httpupgrade_host", translate("HTTPUpgrade Host"))
o:depends({ transport = "httpupgrade" })

o = s:option(Value, "httpupgrade_path", translate("HTTPUpgrade Path"))
o:depends({ transport = "httpupgrade" })

-- [[ gRPC部分 ]]--
o = s:option(Value, "grpc_serviceName", "ServiceName")
o:depends({ transport = "grpc" })

-- [[ Mux ]]--
o = s:option(Flag, "mux", translate("Mux"))
o.rmempty = false
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless", flow = "" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

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

if singbox_tags:find("with_wireguard") then
	-- wireguard
	s.fields["protocol"]:value("wireguard", "WireGuard")
	s.fields["users"]:depends({ protocol = "wireguard" })

	o = s:option(Flag, "wireguard_system_interface", translate("System interface"))
	o.default = 0
	o:depends({ protocol = "wireguard" })

	o = s:option(Value, "wireguard_mtu", "MTU")
	o.default = "1408"
	o:depends({ protocol = "wireguard" })

	o = s:option(DynamicList, "wireguard_local_address", translate("Local Address"))
	o:depends({ protocol = "wireguard" })

	o = s:option(Value, "wireguard_private_key", translate("Private Key"))
	o.datatype = "base64"
	o:depends({ protocol = "wireguard" })

	o = s:option(Value, "wireguard_public_key", translate("Public Key"))
	o.datatype = "base64"
	o:depends({ protocol = "wireguard" })

	o = s:option(DummyValue, "gen_wireguard_key")
	o.template = m:template_path("/server/gen_wireguard_key")
	o:depends({ protocol = "wireguard" })
end

o = s:option(Flag, "firewall_allow", translate("Firewall Allow"))
o.default = "0"
o:depends({ custom = false })

o = s:option(Value, "firewall_allow_src", translate("Source zone"))
o.rmempty = false
o.nocreate = true
o.allowany = true
o.default = "wan"
o.template = "cbi/firewall_zonelist"
o:depends({ custom = false, firewall_allow = true })

o = s:option(Flag, "accept_lan", translate("Accept LAN Access"), translate("When selected, it can accessed lan , this will not be safe!"))
o.default = "0"
o:depends({ custom = false })

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" and e.type == type_name then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remarks = e["remark"],
			group = e["group"]
		}
	end
end

o = s:option(ListValue, "outbound_node", translate("outbound node"))
o:value("", translate("Close"))
o:value("_socks", translate("Custom Socks"))
o:value("_http", translate("Custom HTTP"))
o:value("_iface", translate("Custom Interface"))
o.template = m:template_path("/cbi/nodes_listvalue")
o.group = {"","","",""}
for k, v in pairs(nodes_table) do
	o:value(v.id, v.remarks)
	o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end
o:depends({ custom = false })

o = s:option(Value, "outbound_node_address", translate("Address (Support Domain Name)"))
o:depends({ outbound_node = "_socks" })
o:depends({ outbound_node = "_http" })

o = s:option(Value, "outbound_node_port", translate("Port"))
o.datatype = "port"
o:depends({ outbound_node = "_socks" })
o:depends({ outbound_node = "_http" })

o = s:option(Value, "outbound_node_username", translate("Username"))
o:depends({ outbound_node = "_socks" })
o:depends({ outbound_node = "_http" })

o = s:option(Value, "outbound_node_password", translate("Password"))
o.password = true
o:depends({ outbound_node = "_socks" })
o:depends({ outbound_node = "_http" })

o = s:option(Value, "outbound_node_iface", translate("Interface"))
o:depends({ outbound_node = "_iface" })
local netdev_list = api.get_network_devices()
for _, d in ipairs(netdev_list) do
	o:value(d.name, d.label)
end

o = s:option(Flag, "log", translate("Log"))
o.default = "1"
o.rmempty = false

o = s:option(ListValue, "loglevel", translate("Log Level"))
o.default = "info"
o:value("debug")
o:value("info")
o:value("warn")
o:value("error")
o:depends({ log = true })

api.luci_types(s1, s)
