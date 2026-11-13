if not api.finded_com("zray") then return end

local m, s1 = ...
local type_name = "Zray"
s1.fields["type"]:value(type_name, "Zray")
if s1.val["type"] ~= type_name then return end

local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "zray_"
api.set_type_cbi(s)

local o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("vless", "VLESS")
o.default = "vless"

o = s:option(Value, "address", translate("Address (Support Domain Name)"))
o.rmempty = false
o = s:option(Value, "port", translate("Port"))
o.datatype = "port"
o.default = 443
o.rmempty = false
o = s:option(Value, "uuid", translate("ID"))
o.password = true
o.rmempty = false

o = s:option(ListValue, "transport", translate("Transport"))
o:value("tcp", "TCP")
o:value("ws", "WebSocket")
o.default = "tcp"

o = s:option(ListValue, "flow", translate("flow"), translate("Zray UDP requires TCP with XTLS Vision. Other modes support TCP only."))
o:value("none", translate("Close"))
o:value("xtls-rprx-vision", "xtls-rprx-vision")
o.default = "xtls-rprx-vision"
function o.validate(self, value, section)
	if s.fields.transport:formvalue(section) == "ws" and value ~= "none" then
		return nil, translate("Zray WebSocket requires flow=none")
	end
	return value
end

o = s:option(Flag, "tls", translate("TLS"))
o.default = "1"
o.rmempty = false
function o.validate(self, value)
	if value ~= "1" then return nil, translate("Zray requires TLS or REALITY") end
	return value
end
o = s:option(Flag, "reality", translate("REALITY"))
o.default = "0"
o.rmempty = false
o = s:option(Value, "tls_serverName", "SNI " .. translate("Domain"))
o = s:option(Value, "reality_publicKey", translate("Public Key"))
o:depends({reality = true})
o.rmempty = false
o = s:option(Value, "reality_shortId", translate("Short Id"))
o:depends({reality = true})
o = s:option(Flag, "tls_allowInsecure", translate("allowInsecure"), translate("Zray TLS currently supports skipping certificate verification only. REALITY authenticates using its public key."))
o:depends({reality = false})
o.default = "0"
o.rmempty = false
function o.validate(self, value, section)
	if s.fields.reality:formvalue(section) ~= "1" and value ~= "1" then
		return nil, translate("Zray TLS requires explicit Allow insecure")
	end
	return value
end

o = s:option(Value, "ws_host", "WebSocket Host")
o:depends({transport = "ws"})
o = s:option(Value, "ws_path", "WebSocket " .. translate("Path"))
o.default = "/"
o:depends({transport = "ws"})

local zray = require "luci.passwall.util_zray"
local number_specs = {}
for _, spec in ipairs(zray.runtime_numbers) do number_specs[spec[1]] = spec end

local function advanced_option(class, name, title, description)
	local option = s:option(class, name, title, description)
	option.rewrite_option = "zray_" .. name
	option.zray_advanced = true
	return option
end

local function number_option(name, title, description)
	local spec = number_specs[name]
	local option = advanced_option(Value, name, title, description)
	option.default = tostring(spec[2])
	option.placeholder = option.default
	option.datatype = string.format("and(uinteger,range(%.0f,%.0f))", spec[3], spec[4])
	option.rmempty = false
	return option
end

number_option("workers", translate("Network workers"), translate("0 selects automatically (up to 4); 1 uses one worker; 2-16 requests that many workers. Limited by the connection count. A single connection is not split across workers."))
number_option("max_connections", translate("Maximum connections"), translate("Total connection slots per Zray process, shared by all workers. More slots reserve more memory at startup."))
number_option("handshake_timeout_s", translate("Handshake timeout (seconds)"))
number_option("connect_timeout_s", translate("Connect timeout (seconds)"), translate("Deadline for one upstream connection attempt; at least 1 second."))
number_option("idle_timeout_s", translate("Idle timeout (seconds)"), translate("Close connections that have no traffic for this long. 0 does not disable the timeout."))
number_option("sock_buf", translate("Socket buffer (bytes)"), translate("0 keeps the kernel defaults and automatic buffer tuning."))
number_option("stats_interval_s", translate("Statistics interval (seconds)"), translate("0 disables periodic statistics. Enable node logging to view the output."))

o = advanced_option(Value, "bootstrap_dns", translate("Bootstrap DNS"), translate("Resolve the proxy server using this DNS server at startup. Use an IP address, IPv4:port or [IPv6]:port. Empty uses the system resolver; a failed query also falls back to it."))
o.placeholder = "223.5.5.5:53"
function o.validate(self, value)
	return zray.validate_bootstrap_dns(value), translate("Invalid bootstrap DNS address.")
end

o = advanced_option(ListValue, "crypto_backend", translate("Kernel encryption backend"), translate("auto tries devcrypto, then AF_ALG, then software. Unavailable backends fall back to software. Vision direct traffic bypasses outer TLS encryption."))
o:value("off", translate("Disable"))
o:value("auto", translate("Auto"))
o:value("afalg", "AF_ALG")
o:value("devcrypto", "/dev/crypto")
o.default = "off"
o.rmempty = false

o = advanced_option(Flag, "crypto_async", translate("Asynchronous kernel encryption"), translate("When kernel encryption is enabled, use one encryption executor per network worker."))
o.default = "1"
o.rmempty = false

number_option("crypto_min_bytes", translate("Minimum encryption payload (bytes)"))
number_option("crypto_max_bytes", translate("Maximum encryption payload (bytes)"), translate("Only payloads within these inclusive bounds use the kernel backend. Require 1 <= minimum <= maximum <= 32768."))
for _, name in ipairs({"crypto_min_bytes", "crypto_max_bytes"}) do
	s.fields[name].validate = function(self, value, section)
		local valid = Value.validate(self, value, section)
		if not valid then return nil end
		local min_field, max_field = s.fields.crypto_min_bytes, s.fields.crypto_max_bytes
		local min = tonumber(min_field:formvalue(section) or min_field.default)
		local max = tonumber(max_field:formvalue(section) or max_field.default)
		if min and max and min > max then
			return nil, translate("Minimum encryption payload must not exceed maximum.")
		end
		return valid
	end
end

api.type_cbi_section(s1, s)

-- Register tabs on the real node section after the type-specific fields have
-- been attached, keeping link import, remarks and type in the basic tab.
s1:tab("basic", translate("Basic Settings"))
s1:tab("advanced", translate("Advanced parameters"), translate("These settings apply to each Zray process started for this node. Save and apply to restart with the new values."))
for _, option in ipairs(s1.children) do
	local tab = option.zray_advanced and "advanced" or "basic"
	table.insert(s1.tabs[tab].childs, option)
end
