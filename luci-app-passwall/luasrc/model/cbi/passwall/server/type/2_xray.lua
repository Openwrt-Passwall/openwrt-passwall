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

if not s1.val["type"] then
	s1.val["type"] = type_name
end

if s1.val["type"] and s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "xray_"
api.set_type_cbi(s)

local ss_method_list = {
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"
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
o.cfgvalue = function(self, section, value)
	local config_str = m:get(section, "config_str")
	if config_str then
		return api.base64Decode(config_str)
	end
end
o.write = function(self, section, value)
	m:set(section, "config_str", api.base64Encode(value) or "")
end

o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("socks", "Socks")
o:value("http", "HTTP")
o:value("vmess", "Vmess")
o:value("vless", "VLESS")
o:value("shadowsocks", "Shadowsocks")
o:value("trojan", "Trojan")
o:value("hysteria2", "Hysteria2")
o:value("wireguard", "WireGuard")
o:value("tunnel", "Tunnel")
o:depends({ custom = false })

o = s:option(Value, "port", translate("Listen Port"))
o.datatype = "port"
o:depends({ custom = false })

o = s:option(DynamicList, "users", translate("User"))
for i, v in ipairs(user_list) do
	o:value(v[".name"], v.username)
end
o.validate = function(self, value, t)
	if type(value) == "string" then value = {value} end
	if type(value) == "table" then
		for _, u in ipairs(value) do
			local found = false
			for _, v in ipairs(user_list) do
				if u == v[".name"] then found = true; break end
			end
			if not found then
				return nil, translate("Please configure user info on the User Management page.")
			end
		end
	end
	return value
end
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "hysteria2" })
o:depends({ protocol = "wireguard" })

o = s:option(ListValue, "d_protocol", translate("Destination protocol"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("tcp,udp", "TCP,UDP")
o:depends({ protocol = "tunnel" })

o = s:option(Value, "d_address", translate("Destination address"))
o:depends({ protocol = "tunnel" })

o = s:option(Value, "d_port", translate("Destination port"))
o.datatype = "port"
o:depends({ protocol = "tunnel" })

o = s:option(Value, "decryption", translate("Encrypt Method") .. " (decryption)")
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

o = s:option(Value, "ss_password", translate("Password"))
o:depends({ protocol = "shadowsocks" })

o = s:option(ListValue, "ss_network", translate("Transport"))
o.default = "tcp,udp"
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("tcp,udp", "TCP,UDP")
o:depends({ protocol = "shadowsocks" })

o = s:option(Flag, "udp_forward", translate("UDP Forward"))
o.default = "1"
o.rmempty = false
o:depends({ protocol = "socks" })

o = s:option(ListValue, "flow", translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ protocol = "vless" })

---- [[ hysteria2 ]]
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

o = s:option(Flag, "hysteria2_ignore_client_bandwidth", translate("Client BBR Flow Control"))
o.default = 0
o:depends({ protocol = "hysteria2" })

o = s:option(Value, "hysteria2_up_mbps", translate("Max upload Mbps"))
o:depends({ protocol = "hysteria2", hysteria2_ignore_client_bandwidth = false })

o = s:option(Value, "hysteria2_down_mbps", translate("Max download Mbps"))
o:depends({ protocol = "hysteria2", hysteria2_ignore_client_bandwidth = false })

---- [[ TLS ]]
o = s:option(Flag, "tls", translate("TLS"))
o.default = 0
o.validate = function(self, value, t)
	if value then
		local reality = s.fields["reality"] and s.fields["reality"]:formvalue(t) or nil
		local use_pem = s.fields["tls_use_pem"] and s.fields["tls_use_pem"]:formvalue(t) or nil
		if reality and reality == "1" then return value end
		if value == "1" and use_pem ~= "1" then
			local ca = s.fields["tls_certificateFile"] and s.fields["tls_certificateFile"]:formvalue(t) or ""
			local key = s.fields["tls_keyFile"] and s.fields["tls_keyFile"]:formvalue(t) or ""
			if ca == "" or key == "" then
				return nil, translate("Certificate and Private key path can not be empty!")
			end
		elseif value == "1" and use_pem == "1" then
			local ca = s.fields["tls_certificate"] and s.fields["tls_certificate"]:formvalue(t) or ""
			local key = s.fields["tls_key"] and s.fields["tls_key"]:formvalue(t) or ""
			if ca == "" or key == "" then
				return nil, translate("Certificate and Private key PEM can not be empty!")
			end
		end
		return value
	end
end
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "http" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

-- [[ REALITY部分 ]] --
o = s:option(Flag, "reality", translate("REALITY"))
o.default = 0
o:depends({ tls = true, transport = "raw" })
o:depends({ tls = true, transport = "ws" })
o:depends({ tls = true, transport = "grpc" })
o:depends({ tls = true, transport = "httpupgrade" })
o:depends({ tls = true, transport = "xhttp" })

o = s:option(Value, "reality_private_key", translate("Private Key"))
o:depends({ reality = true })

o = s:option(DynamicList, "reality_shortId", translate("Short Id"))
o:depends({ reality = true })

o = s:option(Value, "reality_dest", translate("Dest"))
o.default = "google.com:443"
o:depends({ reality = true })

o = s:option(DynamicList, "reality_serverNames", translate("serverNames"))
o:depends({ reality = true })

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

o = s:option(Flag, "use_mldsa65Seed", translate("ML-DSA-65"))
o.default = "0"
o:depends({ reality = true })

o = s:option(TextValue, "reality_mldsa65Seed", "ML-DSA-65 " .. translate("Private Key"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ use_mldsa65Seed = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

-- o = s:option(Value, "minversion", translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
--o:depends({ tls = true })

-- [[ TLS部分 ]] --

o = s:option(Flag, "tls_use_pem", translate("Use PEM"), translate("Use certificate and private key PEM content."))
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2" })

o = s:option(FileUpload, "tls_certificateFile", translate("Path to the certificate file"), translate("as:") .. "/etc/ssl/fullchain.crt")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. s.section .. ".crt"
if o and o:formvalue(s.section) then o.default = o:formvalue(s.section) end
o:depends({ tls = true, reality = false, tls_use_pem = false })
o:depends({ protocol = "hysteria2", tls_use_pem = false })
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

o = s:option(FileUpload, "tls_keyFile", translate("Path to the private key file"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. s.section .. ".key"
if o and o:formvalue(s.section) then o.default = o:formvalue(s.section) end
o:depends({ tls = true, reality = false, tls_use_pem = false })
o:depends({ protocol = "hysteria2", tls_use_pem = false })
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

o = s:option(TextValue, "tls_certificate", "TLS Certificate (PEM)", translate("Full certificate (chain), PEM format."))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ tls_use_pem = true })
o.cfgvalue = function(self, section)
	return (m:get(section, "tls_certificate") or ""):gsub("\\n", "\n")
end
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("\r", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value:gsub("\n", "\\n")
end

o = s:option(TextValue, "tls_key", "TLS Private Key (PEM)", translate("Private key in PEM format."))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ tls_use_pem = true })
o.cfgvalue = function(self, section)
	return (m:get(section, "tls_key") or ""):gsub("\\n", "\n")
end
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("\r", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value:gsub("\n", "\\n")
end

o = s:option(Flag, "ech", translate("ECH"))
o.default = "0"
o:depends({ tls = true, reality = false })

o = s:option(TextValue, "ech_key", translate("ECH Key"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ ech = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

o = s:option(ListValue, "transport", translate("Transport"))
o:value("raw", "RAW")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("grpc", "gRPC")
o:value("httpupgrade", "HttpUpgrade")
o:value("xhttp", "XHTTP")
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

-- [[ WebSocket部分 ]]--

o = s:option(Value, "ws_host", translate("WebSocket Host"))
o:depends({ transport = "ws" })

o = s:option(Value, "ws_path", translate("WebSocket Path"))
o:depends({ transport = "ws" })

-- [[ HttpUpgrade部分 ]]--
o = s:option(Value, "httpupgrade_host", translate("HttpUpgrade Host"))
o:depends({ transport = "httpupgrade" })

o = s:option(Value, "httpupgrade_path", translate("HttpUpgrade Path"))
o.placeholder = "/"
o:depends({ transport = "httpupgrade" })

-- [[ XHTTP部分 ]]--
o = s:option(Value, "xhttp_host", translate("XHTTP Host"))
o:depends({ transport = "xhttp" })

o = s:option(Value, "xhttp_path", translate("XHTTP Path"))
o.placeholder = "/"
o:depends({ transport = "xhttp" })

o = s:option(Value, "xhttp_maxuploadsize", translate("maxUploadSize"))
o.default = "1000000"
o:depends({ transport = "xhttp" })

o = s:option(Value, "xhttp_maxconcurrentuploads", translate("maxConcurrentUploads"))
o.default = "10"
o:depends({ transport = "xhttp" })

-- [[ TCP部分 ]]--

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

-- [[ gRPC部分 ]]--
o = s:option(Value, "grpc_serviceName", "ServiceName")
o:depends({ transport = "grpc" })

--[[FinalMask]]
o = s:option(Flag, "use_finalmask", "FinalMask")
o.default = "0"
o:depends({ custom = false, protocol = "vmess" })
o:depends({ custom = false, protocol = "vless" })
o:depends({ custom = false, protocol = "trojan" })
o:depends({ custom = false, protocol = "shadowsocks" })
o:depends({ custom = false, protocol = "hysteria2", hysteria2_realms = false })

o = s:option(TextValue, "finalmask", "FinalMask JSON")
o:depends({ use_finalmask = true })
o.rows = 10
o.wrap = "off"
o.datatype = "json"
o.cfgvalue = function(self, section, value)
	local raw = m:get(section, "finalmask")
	if raw then
		return api.base64Decode(raw)
	end
end
o.write = function(self, section, value)
	m:set(section, "finalmask", api.base64Encode(value) or "")
end

--[[acceptProxyProtocol]]
o = s:option(Flag, "acceptProxyProtocol", translate("acceptProxyProtocol"), translate("Whether to receive PROXY protocol, when this node want to be fallback or forwarded by proxy, it must be enable, otherwise it cannot be used."))
o.default = "0"
o:depends({ transport = "raw" })
o:depends({ transport = "ws" })

--[[Fast Open]]
o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"))
o.default = "0"
o:depends({ protocol = "vmess", custom = false })
o:depends({ protocol = "vless", custom = false })
o:depends({ protocol = "shadowsocks", custom = false })
o:depends({ protocol = "trojan", custom = false })

-- [[ Fallback部分 ]]--
o = s:option(Flag, "fallback", translate("Fallback"))
o:depends({ protocol = "vless", transport = "raw" })
o:depends({ protocol = "trojan", transport = "raw" })

--[[
o = s:option(Value, "fallback_alpn", "Fallback alpn")
o:depends({ fallback = true })

o = s:option(Value, "fallback_path", "Fallback path")
o:depends({ fallback = true })

o = s:option(Value, "fallback_dest", "Fallback dest")
o:depends({ fallback = true })

o = s:option(Value, "fallback_xver", "Fallback xver")
o.default = 0
o:depends({ fallback = true })
]]--

o = s:option(DynamicList, "fallback_list", "Fallback", translate("format: dest,path,xver"))
o:depends({ fallback = true })

-- Not supported at present
--[[
o = s:option(Flag, "wireguard_system_interface", translate("System interface"))
o.default = 0
o:depends({ protocol = "wireguard" })
]]--

o = s:option(Value, "wireguard_mtu", "MTU")
o.default = "1420"
o:depends({ protocol = "wireguard" })

-- Not supported at present
--[[
o = s:option(DynamicList, "wireguard_local_address", translate("Local Address"))
o:depends({ protocol = "wireguard" })
]]--

o = s:option(Value, "wireguard_private_key", translate("Private Key"))
o.datatype = "base64"
o:depends({ protocol = "wireguard" })

o = s:option(Value, "wireguard_public_key", translate("Public Key"))
o.datatype = "base64"
o:depends({ protocol = "wireguard" })

o = s:option(DummyValue, "gen_wireguard_key")
o.template = m:template_path("/server/gen_wireguard_key")
o:depends({ protocol = "wireguard" })

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
o:depends({ outbound_node = "_socks"})
o:depends({ outbound_node = "_http"})

o = s:option(Value, "outbound_node_port", translate("Port"))
o.datatype = "port"
o:depends({ outbound_node = "_socks"})
o:depends({ outbound_node = "_http"})

o = s:option(Value, "outbound_node_username", translate("Username"))
o:depends({ outbound_node = "_socks"})
o:depends({ outbound_node = "_http"})

o = s:option(Value, "outbound_node_password", translate("Password"))
o.password = true
o:depends({ outbound_node = "_socks"})
o:depends({ outbound_node = "_http"})

o = s:option(Value, "outbound_node_iface", translate("Interface"))
o:depends({ outbound_node = "_iface"})
local netdev_list = api.get_network_devices()
for _, d in ipairs(netdev_list) do
	o:value(d.name, d.label)
end

o = s:option(Flag, "log", translate("Log"))
o.default = "1"
o.rmempty = false

o = s:option(ListValue, "loglevel", translate("Log Level"))
o.default = "warning"
o:value("debug")
o:value("info")
o:value("warning")
o:value("error")
o:depends({ log = true })

api.type_cbi_section(s1, s)
