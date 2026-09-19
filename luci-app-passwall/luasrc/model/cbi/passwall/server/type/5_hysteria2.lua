if not api.finded_com("hysteria") then
	return
end

-- [[ Hysteria2 ]]
local m, s1 = ...
local type_name = "Hysteria2"

s1.fields["type"]:value(type_name, "Hysteria2")

if s1.val["type"] and s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "hysteria2_"
api.set_type_cbi(s)

o = s:option(Flag, "custom", translate("Use Custom Config"))

o = s:option(TextValue, "custom_config", translate("Custom Config"))
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

o = s:option(Value, "port", translate("Listen Port"))
o.datatype = "port"
o:depends({ custom = false })

o = s:option(DynamicList, "users", translate("User"))
for i, v in ipairs(user_list) do
	o:value(v[".name"], v.username)
end
o:depends({ custom = false })
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

o = s:option(Flag, "realms", translate("Realms"))
o.default = "0"
o.rewrite_option = o.option
o:depends({ custom = false })

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

o = s:option(ListValue, "obfs_type", translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:value("gecko")
o.rewrite_option = o.option
o:depends({ custom = false })

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

o = s:option(Flag, "udp", translate("UDP"))
o.default = "1"
o.rewrite_option = o.option
o:depends({ custom = false })

o = s:option(Value, "up_mbps", translate("Max upload Mbps"))
o.rewrite_option = o.option
o:depends({ custom = false })

o = s:option(Value, "down_mbps", translate("Max download Mbps"))
o.rewrite_option = o.option
o:depends({ custom = false })

o = s:option(Flag, "ignoreClientBandwidth", translate("ignoreClientBandwidth"))
o.default = "0"
o.rewrite_option = o.option
o:depends({ custom = false })

o = s:option(FileUpload, "tls_certificateFile", translate("Path to the certificate file"), translate("as:") .. "/etc/ssl/fullchain.crt")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. arg[1] .. ".crt"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
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
o:depends({ custom = false })

o = s:option(FileUpload, "tls_keyFile", translate("Path to the private key file"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. arg[1] .. ".key"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
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
o:depends({ custom = false })

o = s:option(FileUpload, "ech_keyFile", translate("Path to the ECH key file"), translate("as:") .. "/etc/ssl/ech.pem")
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
o:depends({ custom = false })

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

o = s:option(Flag, "log", translate("Log"))
o.default = "1"
o.rmempty = false

api.type_cbi_section(s1, s)
