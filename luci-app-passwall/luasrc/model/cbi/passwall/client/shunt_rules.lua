local api = require "luci.passwall.api"
api.set_default_cbi()

local datatypes = api.datatypes

m = Map()
m.redirect = api.url("rule")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

function m.on_before_save(self)
	self:set("@global[0]", "flush_set", "1")
end

-- Add inline CSS to map description
m.description = (m.description or "") .. "\n" .. [[
	<style>
		div[id^="cbid.passwall."] .cbi-value-field {
			display: flex;
			flex-wrap: wrap;
			gap: 1em;
		}
		div[id^="cbid.passwall."] .cbi-checkbox {
			display: inline-flex;
			align-items: center;
		}
	</style>
]]

function clean_text(text)
	local nbsp = string.char(0xC2, 0xA0) -- 不间断空格（U+00A0）
	local fullwidth_space = string.char(0xE3, 0x80, 0x80) -- 全角空格（U+3000）
	return text
		:gsub("\t", " ")
		:gsub(nbsp, " ")
		:gsub(fullwidth_space, " ")
		:gsub("^%s+", "")
		:gsub("%s+$", "\n")
		:gsub("\r\n", "\n")
		:gsub("[ \t]*\n[ \t]*", "\n")
end

local remarks_lookup = {}
local groups = {}
m:foreach("shunt_rules", function(s)
	if s[".name"] ~= arg[1] then
		if s.remarks then
			remarks_lookup[s.remarks] = s[".name"]
		end
		if s.group and s.group ~= "" then
			groups[s.group] = true
		end
	end
end)

s = m:section(NamedSection, arg[1], "shunt_rules", "Sing-Box/Xray " .. translate("Shunt Rule"))
s.addremove = false
s.dynamic = false

remarks = s:option(Value, "remarks", translate("Remarks"))
remarks.default = arg[1]
remarks.rmempty = false
remarks.validate = function(self, value, section)
	value = api.trim(value)
	if value == "" then
		return nil, translate("Remark cannot be empty.")
	end
	if remarks_lookup[value] then
		return nil, translate("This remark already exists, please change a new remark.")
	end
	return value
end

o = s:option(Value, "group", translate("Shunt Rule Group"))
o.default = ""
o:value("", translate("default"))
for k, v in pairs(groups) do
	o:value(k)
end
o.write = function(self, section, value)
	value = api.trim(value)
	local lower = value:lower()

	if lower == "" or lower == "default" then
		return m:del(section, self.option)
	end

	for _, v in ipairs(self.keylist or {}) do
		if v:lower() == lower then
			return m:set(section, self.option, v)
		end
	end
	m:set(section, self.option, value)
end

protocol = s:option(MultiValue, "protocol", translate("Protocol"))
protocol:value("http")
protocol:value("tls")
protocol:value("quic")
protocol:value("bittorrent")
protocol.widget = "checkbox"
protocol.default = nil

o = s:option(MultiValue, "inbound", translate("Inbound Tag"))
o:value("tproxy", translate("Transparent proxy"))
o:value("socks", "Socks")
o.widget = "checkbox"
o.default = nil

network = s:option(ListValue, "network", translate("Network"))
network:value("tcp,udp", "TCP UDP")
network:value("tcp", "TCP")
network:value("udp", "UDP")

source = s:option(DynamicList, "source", translate("Source"))
source.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li><li>" .. translate("GeoIP") .. ": geoip:private"
.. "</li></ul>"
source.cast = "string"
source.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local value2 = {}
			string.gsub(value, '[^' .. " " .. ']+', function(w) table.insert(value2, w) end)
			value = value2
		end
	end
	return value
end
source.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false and v:find("geoip:") and v:find("geoip:") == 1 then
			flag = true
		end

		if flag == false then
			err[#err + 1] = v
		end
	end

	if #err > 0 then
		self:add_error(t, "invalid", translate("Not true format, please re-enter!"))
		for _, v in ipairs(err) do
			self:add_error(t, "invalid", v)
		end
	end

	return value
end

--[[
-- Too low usage rate, hidden
sourcePort = s:option(Value, "sourcePort", translate("Source port"))
]]--

port = s:option(Value, "port", translate("port"))

domain_list = s:option(TextValue, "domain_list", translate("Domain"))
domain_list.rows = 10
domain_list.wrap = "off"
domain_list.validate = function(self, value)
	local hosts= {}
	value = clean_text(value)
	string.gsub(value, "[^\r\n]+", function(w) table.insert(hosts, w) end)
	for index, host in ipairs(hosts) do
		local flag = 1
		local tmp_host = host
		if not host:find("#") and host:find("%s") then
		elseif host:find("regexp:") and host:find("regexp:") == 1 then
			flag = 0
		elseif host:find("domain:.") and host:find("domain:.") == 1 then
			tmp_host = host:gsub("domain:", "")
		elseif host:find("full:.") and host:find("full:.") == 1 then
			tmp_host = host:gsub("full:", "")
		elseif host:find("geosite:") and host:find("geosite:") == 1 then
			flag = 0
		elseif host:find("ext:") and host:find("ext:") == 1 then
			flag = 0
		elseif host:find("rule-set:", 1, true) == 1 or host:find("rs:") == 1 then
			local w = host:sub(host:find(":") + 1, #host)
			if w:find("local:") == 1 or w:find("remote:") == 1 then
				flag = 0
			end
		elseif host:find("#") and host:find("#") == 1 then
			flag = 0
		end
		if flag == 1 then
			if not datatypes.hostname(tmp_host) then
				return nil, tmp_host .. " " .. translate("Not valid domain name, please re-enter!")
			end
		end
	end
	return value
end
domain_list.description = "<br /><ul>"
.. "<li>" .. translate("Plaintext: If this string matches any part of the targeting domain, this rule takes effet. Example: rule 'sina.com' matches targeting domain 'sina.com', 'sina.com.cn' and 'www.sina.com', but not 'sina.cn'.") .. "</li>"
.. "<li>" .. translate("Regular expression: Begining with 'regexp:', the rest is a regular expression. When the regexp matches targeting domain, this rule takes effect. Example: rule 'regexp:\\.goo.*\\.com$' matches 'www.google.com' and 'fonts.googleapis.com', but not 'google.com'.") .. "</li>"
.. "<li>" .. translate("Subdomain (recommended): Begining with 'domain:' and the rest is a domain. When the targeting domain is exactly the value, or is a subdomain of the value, this rule takes effect. Example: rule 'domain:v2ray.com' matches 'www.v2ray.com', 'v2ray.com', but not 'xv2ray.com'.") .. "</li>"
.. "<li>" .. translate("Full domain: Begining with 'full:' and the rest is a domain. When the targeting domain is exactly the value, the rule takes effect. Example: rule 'domain:v2ray.com' matches 'v2ray.com', but not 'www.v2ray.com'.") .. "</li>"
.. "<li>" .. translate("Pre-defined domain list: Begining with 'geosite:' and the rest is a name, such as geosite:google or geosite:cn.") .. "</li>"
.. "<li>"
	.. translate("Sing-Box is compatible with Geo rules and rule-set. rule-set begin with 'rule-set:remote:' or 'rule-set:local:'.")
	.. "<ul>"
		.. "<li>" .. translate("Such as:") .. "'rule-set:remote:https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs'" .. "</li>"
		.. "<li>" .. translate("Such as:") .. "'rule-set:local:/usr/share/sing-box/geosite-cn.srs'" .. "</li>"
	.. "</ul>"
.. "</li>"
.. "<li>" .. translate("Annotation: Begining with #") .. "</li>"
.. "</ul>"
ip_list = s:option(TextValue, "ip_list", "IP")
ip_list.rows = 10
ip_list.wrap = "off"
ip_list.validate = function(self, value)
	local ipmasks= {}
	value = clean_text(value)
	string.gsub(value, "[^\r\n]+", function(w) table.insert(ipmasks, w) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask:find("geoip:") and ipmask:find("geoip:") == 1 and not ipmask:find("%s") then
		elseif ipmask:find("ext:") and ipmask:find("ext:") == 1 and not ipmask:find("%s") then
		elseif ipmask:find("rule-set:", 1, true) == 1 or ipmask:find("rs:") == 1 then
			local w = ipmask:sub(ipmask:find(":") + 1, #ipmask)
			if w:find("local:") == 1 or w:find("remote:") == 1 then
				flag = 0
			end
		elseif ipmask:find("#") and ipmask:find("#") == 1 then
		else
			if not (datatypes.ipmask4(ipmask) or datatypes.ipmask6(ipmask)) then
				return nil, ipmask .. " " .. translate("Not valid IP format, please re-enter!")
			end
		end
	end
	return value
end
ip_list.description = "<br /><ul>"
.. "<li>" .. translate("IP: such as '127.0.0.1'.") .. "</li>"
.. "<li>" .. translate("CIDR: such as '127.0.0.0/8'.") .. "</li>"
.. "<li>" .. translate("GeoIP: such as 'geoip:cn'. It begins with geoip: (lower case) and followed by two letter of country code.") .. "</li>"
.. "<li>"
	.. translate("Sing-Box is compatible with Geo rules and rule-set. rule-set begin with 'rule-set:remote:' or 'rule-set:local:'.")
	.. "<ul>"
		.. "<li>" .. translate("Such as:") .. "'rule-set:remote:https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs'" .. "</li>"
		.. "<li>" .. translate("Such as:") .. "'rule-set:local:/usr/share/sing-box/geoip-cn.srs'" .. "</li>"
	.. "</ul>"
.. "</li>"
.. "<li>" .. translate("Annotation: Begining with #") .. "</li>"
.. "</ul>"

o = s:option(Flag, "invert", "Invert", translate("Invert match result.") .. " " .. translate("Only support Sing-Box."))

return api.return_map(m)
