if not api.finded_com("hysteria") then
	return
end

-- [[ Hysteria2 ]]
local m, s1 = ...
local type_name = "Hysteria2"

s1.fields["type"]:value(type_name, "Hysteria2")

if s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "hysteria2_"
api.set_type_cbi(s)

o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("udp", "UDP")

o = s:option(Value, "address", translate("Address (Support Domain Name)"))
o:depends({ realms = false })

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"
o:depends({ realms = false })

o = s:option(Value, "hop", translate("Port hopping range"))
o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
o.rewrite_option = o.option
o:depends({ realms = false })

o = s:option(Value, "hop_interval", translate("Hop Interval(second)"), translate("Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5."))
o.datatype = "or(uinteger,portrange)"
o.placeholder = "30"
o.default = "30"
o.rewrite_option = o.option
o:depends({ realms = false })

o = s:option(Flag, "realms", translate("Realms"))
o.default = "0"
o.rewrite_option = o.option

o = s:option(Value, "realm_url", translate("Realm URL"), translate("Example:") .. "realm://public@realm.hy2.io/your-realm-name")
o.rewrite_option = o.option
o:depends({ realms = "1" })
o.validate = function(self, value)
	value = api.trim(value)
	local realm = api.parse_realm_uri(value)
	if realm then return value end
	return nil, translate("Invalid Realm URL.")
end

o = s:option(DynamicList, "realm_stun", translate("Realm STUN"))
o.default = { "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }
o.rewrite_option = o.option
o:depends({ realms = "1" })

o = s:option(Flag, "realm_upnp", translate("Enable") .. " UPnP/NAT-PMP", translate("Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success."))
o.default = "0"
o.rewrite_option = o.option
o:depends({ realms = "1" })

o = s:option(Value, "auth_password", translate("Auth Password"))
o.password = true
o.rewrite_option = o.option

o = s:option(ListValue, "obfs_type", translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:value("gecko")
o.rewrite_option = o.option

o = s:option(Value, "obfs_password", translate("Obfs Password"))
o.rewrite_option = o.option
o:depends({ obfs_type = "salamander" })
o:depends({ obfs_type = "gecko" })

o = s:option(Value, "obfs_MinPacketSize", translate("Gecko Packet Size (min)"))
o.datatype = "uinteger"
o.placeholder = "512"
o.default = "512"
o:depends({ obfs_type = "gecko" })
o.rewrite_option = o.option

o = s:option(Value, "obfs_MaxPacketSize", translate("Gecko Packet Size (max)"))
o.datatype = "uinteger"
o.placeholder = "1200"
o.default = "1200"
o:depends({ obfs_type = "gecko" })
o.rewrite_option = o.option

o = s:option(Flag, "fast_open", translate("Fast Open"))
o.default = "0"

o = s:option(Value, "tls_serverName", translate("Domain"))

o = s:option(Flag, "tls_allowInsecure", translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"

o = s:option(Value, "tls_pinSHA256", translate("TLS Chain Fingerprint (SHA256)"))

o = s:option(Value, "up_mbps", translate("Max upload Mbps"))
o.rewrite_option = o.option

o = s:option(Value, "down_mbps", translate("Max download Mbps"))
o.rewrite_option = o.option

o = s:option(Value, "stream_recv_win", translate("QUIC stream receive window"))
o.datatype = "uinteger"
o.placeholder = "8388608"
o.rewrite_option = o.option

o = s:option(Value, "conn_recv_win", translate("QUIC connection receive window"))
o.datatype = "uinteger"
o.placeholder = "20971520"
o.rewrite_option = o.option

o = s:option(Value, "idle_timeout", translate("Idle Timeout"), translate("Units:seconds") .. " (4~120)")
o.datatype = "range(4,120)"
o.rewrite_option = o.option

o = s:option(Value, "keep_alive_period", translate("QUIC KeepAlive interval"), translate("Units:seconds") .. " (2~60)")
o.datatype = "range(2,60)"
o.rewrite_option = o.option

o = s:option(Flag, "disable_mtu_discovery", translate("Disable MTU detection"))
o.default = "0"
o.rewrite_option = o.option


o = s:option(Flag, "ech", translate("ECH"))
o.default = "0"
o:depends({ realms = false })

o = s:option(TextValue, "ech_config", translate("ECH Config"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ ech = "1" })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

o = s:option(Flag, "lazy_start", translate("Lazy Start"))
o.default = "0"
o.rewrite_option = o.option

api.type_cbi_section(s1, s)
