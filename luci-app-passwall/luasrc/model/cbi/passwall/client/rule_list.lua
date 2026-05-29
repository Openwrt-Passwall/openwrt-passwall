local api = require "luci.passwall.api"
local appname = "passwall"
local fs = api.fs
local sys = api.sys
local uci = api.uci
local datatypes = api.datatypes
local path = string.format("/usr/share/%s/rules/", appname)
local gfwlist_path = "/usr/share/passwall/rules/gfwlist"
local chnlist_path = "/usr/share/passwall/rules/chnlist"
local chnroute_path = "/usr/share/passwall/rules/chnroute"

m = Map(appname)
api.set_apply_on_parse(m)

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

-- [[ Rule List Settings ]]--
s = m:section(TypedSection, "global_rules")
s.anonymous = true

s:tab("direct_list", translate("Direct List"))
s:tab("proxy_list", translate("Proxy List"))
s:tab("block_list", translate("Block List"))
s:tab("lan_ip_list", translate("Lan IP List"))
s:tab("route_hosts", translate("Route Hosts"))

---- Direct Hosts
local direct_host = path .. "direct_host"
o = s:taboption("direct_list", TextValue, "direct_host", "", "<font color='red'>" .. translate("Join the direct hosts list of domain names will not proxy.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(direct_host) or ""
end
o.write = function(self, section, value)
	fs.writefile(direct_host, value:gsub("\r\n", "\n"))
	sys.call("rm -rf /tmp/etc/passwall_tmp/dns_*")
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
	-- does not mean the user cleared the content
end
o.validate = function(self, value)
	local hosts= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(hosts, api.trim(w)) end)
	for index, host in ipairs(hosts) do
		if host ~= "" and not host:find("^#") and not host:find("^geosite:") then
			if not datatypes.hostname(host) then
				return nil, host .. " " .. translate("Not valid domain name, please re-enter!")
			end
		end
	end
	return value
end

---- Direct IP
local direct_ip = path .. "direct_ip"
o = s:taboption("direct_list", TextValue, "direct_ip", "", "<font color='red'>" .. translate("These had been joined ip addresses will not proxy. Please input the ip address or ip address segment,every line can input only one ip address. For example: 192.168.0.0/24 or 223.5.5.5.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(direct_ip) or ""
end
o.write = function(self, section, value)
	fs.writefile(direct_ip, value:gsub("\r\n", "\n"))
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end
o.validate = function(self, value)
	local ipmasks= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(ipmasks, api.trim(w)) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask ~= "" and not ipmask:find("^#") and not ipmask:find("^geoip:") then
			if not ( datatypes.ipmask4(ipmask) or datatypes.ipmask6(ipmask) ) then
				return nil, ipmask .. " " .. translate("Not valid IP format, please re-enter!")
			end
		end
	end
	return value
end

---- Proxy Hosts
local proxy_host = path .. "proxy_host"
o = s:taboption("proxy_list", TextValue, "proxy_host", "", "<font color='red'>" .. translate("These had been joined websites will use proxy. Please input the domain names of websites, every line can input only one website domain. For example: google.com.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(proxy_host) or ""
end
o.write = function(self, section, value)
	fs.writefile(proxy_host, value:gsub("\r\n", "\n"))
	sys.call("rm -rf /tmp/etc/passwall_tmp/dns_*")
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end
o.validate = function(self, value)
	local hosts= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(hosts, api.trim(w)) end)
	for index, host in ipairs(hosts) do
		if host ~= "" and not host:find("^#") and not host:find("^geosite:") then
			if not datatypes.hostname(host) then
				return nil, host .. " " .. translate("Not valid domain name, please re-enter!")
			end
		end
	end
	return value
end

---- Proxy IP
local proxy_ip = path .. "proxy_ip"
o = s:taboption("proxy_list", TextValue, "proxy_ip", "", "<font color='red'>" .. translate("These had been joined ip addresses will use proxy. Please input the ip address or ip address segment, every line can input only one ip address. For example: 35.24.0.0/24 or 8.8.4.4.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(proxy_ip) or ""
end
o.write = function(self, section, value)
	fs.writefile(proxy_ip, value:gsub("\r\n", "\n"))
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end
o.validate = function(self, value)
	local ipmasks= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(ipmasks, api.trim(w)) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask ~= "" and not ipmask:find("^#") and not ipmask:find("^geoip:") then
			if not ( datatypes.ipmask4(ipmask) or datatypes.ipmask6(ipmask) ) then
				return nil, ipmask .. " " .. translate("Not valid IP format, please re-enter!")
			end
		end
	end
	return value
end

---- Block Hosts
local block_host = path .. "block_host"
o = s:taboption("block_list", TextValue, "block_host", "", "<font color='red'>" .. translate("These had been joined websites will be block. Please input the domain names of websites, every line can input only one website domain. For example: twitter.com.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(block_host) or ""
end
o.write = function(self, section, value)
	fs.writefile(block_host, value:gsub("\r\n", "\n"))
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end
o.validate = function(self, value)
	local hosts= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(hosts, api.trim(w)) end)
	for index, host in ipairs(hosts) do
		if host ~= "" and not host:find("^#") and not host:find("^geosite:") then
			if not datatypes.hostname(host) then
				return nil, host .. " " .. translate("Not valid domain name, please re-enter!")
			end
		end
	end
	return value
end

---- Block IP
local block_ip = path .. "block_ip"
o = s:taboption("block_list", TextValue, "block_ip", "", "<font color='red'>" .. translate("These had been joined ip addresses will be block. Please input the ip address or ip address segment, every line can input only one ip address.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(block_ip) or ""
end
o.write = function(self, section, value)
	fs.writefile(block_ip, value:gsub("\r\n", "\n"))
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end
o.validate = function(self, value)
	local ipmasks= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(ipmasks, api.trim(w)) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask ~= "" and not ipmask:find("^#") and not ipmask:find("^geoip:") then
			if not ( datatypes.ipmask4(ipmask) or datatypes.ipmask6(ipmask) ) then
				return nil, ipmask .. " " .. translate("Not valid IP format, please re-enter!")
			end
		end
	end
	return value
end

---- Lan IPv4
local lanlist_ipv4 = path .. "lanlist_ipv4"
o = s:taboption("lan_ip_list", TextValue, "lanlist_ipv4", "", "<font color='red'>" .. translate("The list is the IPv4 LAN IP list, which represents the direct connection IP of the LAN. If you need the LAN IP in the proxy list, please clear it from the list. Do not modify this list by default.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(lanlist_ipv4) or ""
end
o.write = function(self, section, value)
	fs.writefile(lanlist_ipv4, value:gsub("\r\n", "\n"))
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end
o.validate = function(self, value)
	local ipmasks= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(ipmasks, api.trim(w)) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask ~= "" and not ipmask:find("^#") then
			if not datatypes.ipmask4(ipmask) then
				return nil, ipmask .. " " .. translate("Not valid IPv4 format, please re-enter!")
			end
		end
	end
	return value
end

---- Lan IPv6
local lanlist_ipv6 = path .. "lanlist_ipv6"
o = s:taboption("lan_ip_list", TextValue, "lanlist_ipv6", "", "<font color='red'>" .. translate("The list is the IPv6 LAN IP list, which represents the direct connection IP of the LAN. If you need the LAN IP in the proxy list, please clear it from the list. Do not modify this list by default.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(lanlist_ipv6) or ""
end
o.write = function(self, section, value)
	fs.writefile(lanlist_ipv6, value:gsub("\r\n", "\n"))
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end
o.validate = function(self, value)
	local ipmasks= {}
	value = clean_text(value)
	string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(ipmasks, api.trim(w)) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask ~= "" and not ipmask:find("^#") then
			if not datatypes.ipmask6(ipmask) then
				return nil, ipmask .. " " .. translate("Not valid IPv6 format, please re-enter!")
			end
		end
	end
	return value
end

---- Route Hosts
local hosts = "/etc/hosts"
o = s:taboption("route_hosts", TextValue, "hosts", "", "<font color='red'>" .. translate("Configure routing etc/hosts file, if you don't know what you are doing, please don't change the content.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section)
	return fs.readfile(hosts) or ""
end
o.write = function(self, section, value)
	fs.writefile(hosts, clean_text(value))
end
o.remove = function(self, section, value)
	-- no-op: field absent from POST due to JS-LuCI lazy tab loading
end

if fs.access(gfwlist_path) then
	s:tab("gfw_list", translate("GFW List"))
	o = s:taboption("gfw_list", DummyValue, "_gfw_fieldset")
	o.rawhtml = true
	o.default = string.format([[
		<div style="display: flex; align-items: center;">
			<input class="btn cbi-button cbi-button-add" type="button" onclick="read_gfw()" value="%s" />
			<label id="gfw_total_lines" style="margin-left: auto; margin-right: 10px;"></label>
		</div>
		<textarea id="gfw_textarea" class="cbi-input-textarea" style="width: 100%%; margin-top: 10px;" rows="40" wrap="off" readonly="readonly"></textarea>
	]], translate("Read List"))
end

if fs.access(chnlist_path) then
	s:tab("chn_list", translate("China List") .. "(" .. translate("Domain") .. ")")
	o = s:taboption("chn_list", DummyValue, "_chn_fieldset")
	o.rawhtml = true
	o.default = string.format([[
		<div style="display: flex; align-items: center;">
			<input class="btn cbi-button cbi-button-add" type="button" onclick="read_chn()" value="%s" />
			<label id="chn_total_lines" style="margin-left: auto; margin-right: 10px;"></label>
		</div>
		<textarea id="chn_textarea" class="cbi-input-textarea" style="width: 100%%; margin-top: 10px;" rows="40" wrap="off" readonly="readonly"></textarea>
	]], translate("Read List"))
end

if fs.access(chnroute_path) then
	s:tab("chnroute_list", translate("China List") .. "(IP)")
	o = s:taboption("chnroute_list", DummyValue, "_chnroute_fieldset")
	o.rawhtml = true
	o.default = string.format([[
		<div style="display: flex; align-items: center;">
			<input class="btn cbi-button cbi-button-add" type="button" onclick="read_chnroute()" value="%s" />
			<label id="chnroute_total_lines" style="margin-left: auto; margin-right: 10px;"></label>
		</div>
		<textarea id="chnroute_textarea" class="cbi-input-textarea" style="width: 100%%; margin-top: 10px;" rows="40" wrap="off" readonly="readonly"></textarea>
	]], translate("Read List"))
end

m:append(Template(appname .. "/rule_list/js"))

local geo_dir = (uci:get(appname, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"):match("^(.*)/")
local geosite_path = geo_dir .. "/geosite.dat"
local geoip_path = geo_dir .. "/geoip.dat"
if api.finded_com("geoview") and fs.access(geosite_path) and fs.access(geoip_path) then
	if api.compare_versions(api.get_app_version("geoview"), ">=", "0.1.0") then
		s:tab("geoview", translate("Geo View"))
		o = s:taboption("geoview", DummyValue, "_geoview_fieldset")
		o.rawhtml = true
		o.template = appname .. "/rule_list/geoview"
	end
end

m.on_before_save = function(self)
	m:set("@global[0]", "flush_set", "1")
end

return m
