local m, s = ...

local singbox_bin = api.finded_com("sing-box")

if not singbox_bin then
	return
end

local type_name = "sing-box"

-- [[ Sing-Box ]]

s.fields["type"]:value(type_name, "Sing-Box")
if not s.fields["type"].default then
	s.fields["type"].default = type_name
end

if s.val["type"] and s.val["type"] ~= type_name then
	return
end

local option_prefix = "singbox_"

local function _n(name)
	return option_prefix .. name
end

local singbox_tags = luci.sys.exec(singbox_bin .. " version  | grep 'Tags:' | awk '{print $2}'")

local ss_method_list = {
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

o = s:option(Flag, _n("custom"), translate("Use Custom Config"))

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
o:value("mixed", "Mixed")
o:value("socks", "Socks")
o:value("http", "HTTP")
o:value("shadowsocks", "Shadowsocks")
o:value("vmess", "Vmess")
o:value("vless", "VLESS")
o:value("trojan", "Trojan")
o:value("naive", "Naive")
if singbox_tags:find("with_quic") then
	o:value("hysteria", "Hysteria")
end
if singbox_tags:find("with_quic") then
	o:value("tuic", "TUIC")
end
if singbox_tags:find("with_quic") then
	o:value("hysteria2", "Hysteria2")
end
o:value("anytls", "AnyTLS")
o:value("direct", "Direct")
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("port"), translate("Listen Port"))
o.datatype = "port"
o:depends({ [_n("custom")] = false })

o = s:option(DynamicList, _n("users"), translate("User"))
for i, v in ipairs(user_list) do
	o:value(v[".name"], v.username)
end
o:depends({ [_n("protocol")] = "mixed" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "naive" })
o:depends({ [_n("protocol")] = "hysteria" })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o:depends({ [_n("protocol")] = "anytls" })

if singbox_tags:find("with_quic") then
	o = s:option(Value, _n("hysteria_obfs"), translate("Obfs Password"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_up_mbps"), translate("Max upload Mbps"))
	o.default = "100"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_down_mbps"), translate("Max download Mbps"))
	o.default = "100"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_recv_window_conn"), translate("QUIC stream receive window"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_recv_window_client"), translate("QUIC connection receive window"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_max_conn_client"), translate("QUIC concurrent bidirectional streams"))
	o.default = "1024"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Flag, _n("hysteria_disable_mtu_discovery"), translate("Disable MTU detection"))
	o:depends({ [_n("protocol")] = "hysteria" })
end

if singbox_tags:find("with_quic") then
	o = s:option(ListValue, _n("tuic_congestion_control"), translate("Congestion control algorithm"))
	o.default = "cubic"
	o:value("bbr", translate("BBR"))
	o:value("cubic", translate("CUBIC"))
	o:value("new_reno", translate("New Reno"))
	o:depends({ [_n("protocol")] = "tuic" })

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
	o:value("spdy/3.1")
	o:value("h3,spdy/3.1")
	o:depends({ [_n("protocol")] = "tuic" })
end

if singbox_tags:find("with_quic") then
	o = s:option(Flag, _n("hysteria2_realms"), translate("Realms"))
	o.default = "0"
	o:depends({ [_n("protocol")] = "hysteria2"})

	o = s:option(Value, _n("hysteria2_realm_url"), translate("Realm URL"), translate("Example:") .. "realm://public@realm.hy2.io/your-realm-name")
	o:depends({ [_n("hysteria2_realms")] = "1" })
	o.validate = function(self, value)
		value = api.trim(value)
		local realm = api.parse_realm_uri(value)
		if realm then return value end
		return nil, translate("Invalid Realm URL.")
	end

	o = s:option(DynamicList, _n("hysteria2_realm_stun"), translate("Realm STUN"))
	o.default = { "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }
	o:depends({ [_n("hysteria2_realms")] = "1" })

	o = s:option(ListValue, _n("hysteria2_obfs_type"), translate("Obfs Type"))
	o:value("", translate("Disable"))
	o:value("salamander")
	o:value("gecko")
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(Value, _n("hysteria2_obfs_password"), translate("Obfs Password"))
	o:depends({ [_n("hysteria2_obfs_type")] = "salamander" })
	o:depends({ [_n("hysteria2_obfs_type")] = "gecko" })

	o = s:option(Value, _n("hysteria2_obfs_MinPacketSize"), translate("Gecko Packet Size (min)"))
	o.datatype = "uinteger"
	o.placeholder = "512"
	o.default = "512"
	o:depends({ [_n("hysteria2_obfs_type")] = "gecko" })

	o = s:option(Value, _n("hysteria2_obfs_MaxPacketSize"), translate("Gecko Packet Size (max)"))
	o.datatype = "uinteger"
	o.placeholder = "1200"
	o.default = "1200"
	o:depends({ [_n("hysteria2_obfs_type")] = "gecko" })

	o = s:option(Flag, _n("hysteria2_ignore_client_bandwidth"), translate("Client BBR Flow Control"), translate("Commands the client to use the BBR flow control algorithm"))
	o.default = 0
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(Value, _n("hysteria2_up_mbps"), translate("Max upload Mbps"))
	o:depends({ [_n("protocol")] = "hysteria2", [_n("hysteria2_ignore_client_bandwidth")] = false })

	o = s:option(Value, _n("hysteria2_down_mbps"), translate("Max download Mbps"))
	o:depends({ [_n("protocol")] = "hysteria2", [_n("hysteria2_ignore_client_bandwidth")] = false })
end

o = s:option(ListValue, _n("d_protocol"), translate("Destination protocol"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("tcp,udp", "TCP,UDP")
o:depends({ [_n("protocol")] = "direct" })

o = s:option(Value, _n("d_address"), translate("Destination address"))
o:depends({ [_n("protocol")] = "direct" })

o = s:option(Value, _n("d_port"), translate("Destination port"))
o.datatype = "port"
o:depends({ [_n("protocol")] = "direct" })

o = s:option(Value, _n("decryption"), translate("Encrypt Method"))
o.default = "none"
o:depends({ [_n("protocol")] = "vless" })

o = s:option(ListValue, _n("ss_method"), translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Value, _n("ss_password"), translate("Password"))
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(ListValue, _n("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ [_n("protocol")] = "vless" , [_n("tls")] = true })

o = s:option(Flag, _n("tls"), translate("TLS"))
o.default = 0
o.validate = function(self, value, t)
	if value then
		local reality = s.fields[_n("reality")] and s.fields[_n("reality")]:formvalue(t) or nil
		if reality and reality == "1" then return value end
		if value == "1" then
			local ca = s.fields[_n("tls_certificateFile")] and s.fields[_n("tls_certificateFile")]:formvalue(t) or ""
			local key = s.fields[_n("tls_keyFile")] and s.fields[_n("tls_keyFile")]:formvalue(t) or ""
			if ca == "" or key == "" then
				return nil, translate("Public key and Private key path can not be empty!")
			end
		end
		return value
	end
end
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "anytls" })

-- https://github.com/SagerNet/sing-box/commit/d2a04c4e41e6cef0937331cb6d10211f431caaab
if singbox_tags:find("with_utls") then
	-- [[ REALITY部分 ]] --
	o = s:option(Flag, _n("reality"), translate("REALITY"))
	o.default = 0
	o:depends({ [_n("protocol")] = "http", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "vmess", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "vless", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "trojan", [_n("tls")] = true })
	o:depends({ [_n("protocol")] = "anytls", [_n("tls")] = true })

	o = s:option(Value, _n("reality_private_key"), translate("Private Key"))
	o:depends({ [_n("reality")] = true })

	o = s:option(Value, _n("reality_shortId"), translate("Short Id"))
	o:depends({ [_n("reality")] = true })

	o = s:option(Value, _n("reality_handshake_server"), translate("Handshake Server"))
	o.default = "google.com"
	o:depends({ [_n("reality")] = true })

	o = s:option(Value, _n("reality_handshake_server_port"), translate("Handshake Server Port"))
	o.datatype = "port"
	o.default = "443"
	o:depends({ [_n("reality")] = true })
end

o = s:option(ListValue, _n("alpn"), translate("ALPN"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "hysteria" })

-- [[ TLS部分 ]] --

o = s:option(FileUpload, _n("tls_certificateFile"), translate("Public key absolute path"), translate("as:") .. "/etc/ssl/fullchain.pem")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. arg[1] .. ".pem"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "naive" })
o:depends({ [_n("protocol")] = "hysteria" })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(FileUpload, _n("tls_keyFile"), translate("Private key absolute path"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. arg[1] .. ".key"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "naive" })
o:depends({ [_n("protocol")] = "hysteria" })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(Flag, _n("ech"), translate("ECH"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("flow")] = "", [_n("reality")] = false })
o:depends({ [_n("protocol")] = "naive" })
o:depends({ [_n("protocol")] = "hysteria" })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2", [_n("hysteria2_realms")] = false })

o = s:option(TextValue, _n("ech_key"), translate("ECH Key"))
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

o = s:option(ListValue, _n("transport"), translate("Transport"))
o:value("tcp", "TCP")
o:value("http", "HTTP")
o:value("ws", "WebSocket")
o:value("httpupgrade", "HTTPUpgrade")
o:value("quic", "QUIC")
o:value("grpc", "gRPC")
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "trojan" })

-- [[ HTTP部分 ]]--

o = s:option(DynamicList, _n("http_host"), translate("HTTP Host"))
o:depends({ [_n("transport")] = "http" })

o = s:option(Value, _n("http_path"), translate("HTTP Path"))
o:depends({ [_n("transport")] = "http" })

-- [[ WebSocket部分 ]]--

o = s:option(Value, _n("ws_host"), translate("WebSocket Host"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_path"), translate("WebSocket Path"))
o:depends({ [_n("transport")] = "ws" })

-- [[ HTTPUpgrade部分 ]]--

o = s:option(Value, _n("httpupgrade_host"), translate("HTTPUpgrade Host"))
o:depends({ [_n("transport")] = "httpupgrade" })

o = s:option(Value, _n("httpupgrade_path"), translate("HTTPUpgrade Path"))
o:depends({ [_n("transport")] = "httpupgrade" })

-- [[ gRPC部分 ]]--
o = s:option(Value, _n("grpc_serviceName"), "ServiceName")
o:depends({ [_n("transport")] = "grpc" })

-- [[ Mux ]]--
o = s:option(Flag, _n("mux"), translate("Mux"))
o.rmempty = false
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless", [_n("flow")] = "" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

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

o = s:option(Flag, _n("bind_local"), translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
o.default = "0"
o:depends({ [_n("custom")] = false })

o = s:option(Flag, _n("accept_lan"), translate("Accept LAN Access"), translate("When selected, it can accessed lan , this will not be safe!"))
o.default = "0"
o:depends({ [_n("custom")] = false })

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

o = s:option(ListValue, _n("outbound_node"), translate("outbound node"))
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
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("outbound_node_address"), translate("Address (Support Domain Name)"))
o:depends({ [_n("outbound_node")] = "_socks" })
o:depends({ [_n("outbound_node")] = "_http" })

o = s:option(Value, _n("outbound_node_port"), translate("Port"))
o.datatype = "port"
o:depends({ [_n("outbound_node")] = "_socks" })
o:depends({ [_n("outbound_node")] = "_http" })

o = s:option(Value, _n("outbound_node_username"), translate("Username"))
o:depends({ [_n("outbound_node")] = "_socks" })
o:depends({ [_n("outbound_node")] = "_http" })

o = s:option(Value, _n("outbound_node_password"), translate("Password"))
o.password = true
o:depends({ [_n("outbound_node")] = "_socks" })
o:depends({ [_n("outbound_node")] = "_http" })

o = s:option(Value, _n("outbound_node_iface"), translate("Interface"))
o:depends({ [_n("outbound_node")] = "_iface" })
local netdev_list = api.get_network_devices()
for _, d in ipairs(netdev_list) do
	o:value(d.name, d.label)
end

o = s:option(TextValue, _n("custom_config"), translate("Custom Config") .. " (JSON)")
o.rows = 10
o.wrap = "off"
o:depends({ [_n("custom")] = true })
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

o = s:option(Flag, _n("log"), translate("Log"))
o.default = "1"
o.rmempty = false

o = s:option(ListValue, _n("loglevel"), translate("Log Level"))
o.default = "info"
o:value("debug")
o:value("info")
o:value("warn")
o:value("error")
o:depends({ [_n("log")] = true })

api.luci_types(arg[1], m, s, type_name, option_prefix)
