local api = require "luci.passwall.api"
local appname = "passwall"
local datatypes = api.datatypes
local fs = api.fs
local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")
local has_gfwlist = fs.access("/usr/share/passwall/rules/gfwlist")
local has_chnlist = fs.access("/usr/share/passwall/rules/chnlist")
local has_chnroute = fs.access("/usr/share/passwall/rules/chnroute")

m = Map(appname)
api.set_apply_on_parse(m)

m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

local nodes_table = {}
for _, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local normal_list = {}
local balancing_list = {}
local urltest_list = {}
local shunt_list = {}
local iface_list = {}
for _, v in pairs(nodes_table) do
	if v.node_type == "normal" then
		normal_list[#normal_list + 1] = v
	end
	if v.protocol and v.protocol == "_balancing" then
		balancing_list[#balancing_list + 1] = v
	end
	if v.protocol and v.protocol == "_urltest" then
		urltest_list[#urltest_list + 1] = v
	end
	if v.protocol and v.protocol == "_shunt" then
		shunt_list[#shunt_list + 1] = v
	end
	if v.protocol and v.protocol == "_iface" then
		iface_list[#iface_list + 1] = v
	end
end

local socks_list = {}

local tcp_socks_server = "127.0.0.1" .. ":" .. (m:get("@global[0]", "tcp_node_socks_port") or "1070")
local socks_table = {}
socks_table[#socks_table + 1] = {
	id = tcp_socks_server,
	remark = tcp_socks_server .. " - " .. translate("TCP Node")
}
m.uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		local id, remark
		for k, n in pairs(nodes_table) do
			if (s.node == n.id) then
				remark = n["remark"]; break
			end
		end
		id = "127.0.0.1" .. ":" .. s.port
		socks_table[#socks_table + 1] = {
			id = id,
			remark = id .. " - " .. (remark or translate("Misconfigured"))
		}
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " " .. string.format("[%s %s]", s.port, translate("Port")),
			group = "Socks"
		}
	end
end)

local doh_validate = function(self, value, t)
	value = value:gsub("%s+", "")
	if value ~= "" then
		local flag = 0
		local util = require "luci.util"
		local val = util.split(value, ",")
		local url = val[1]
		val[1] = nil
		for i = 1, #val do
			local v = val[i]
			if v then
				if not datatypes.ipmask4(v) and not datatypes.ipmask6(v) then
					flag = 1
				end
			end
		end
		if flag == 0 then
			return value
		end
	end
	return nil, translatef("%s request address","DoH") .. " " .. translate("Format must be:") .. " URL,IP"
end

m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

---- TCP Node
o = s:taboption("Main", ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
o.template = appname .. "/cbi/nodes_listvalue"
o:value("", translate("Close"))
o.group = {""}

---- UDP Node
o = s:taboption("Main", ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
o.template = appname .. "/cbi/nodes_listvalue"
o:value("", translate("Close"))
o:value("tcp", translate("Same as the tcp node"))
o.group = {"",""}

o = s:taboption("Main", Value, "tcp_node_socks_port", translate("TCP Node") .. " Socks " .. translate("Listen Port"))
o.default = 1070
o.datatype = "port"
o:depends({ tcp_node = "", ["!reverse"] = true })
--[[
if has_singbox or has_xray then
	o = s:taboption("Main", Value, "tcp_node_http_port", translate("TCP Node") .. " HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	o.default = 0
	o.datatype = "port"
end
]]--
o = s:taboption("Main", Flag, "tcp_node_socks_bind_local", translate("TCP Node") .. " Socks " .. translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
o.default = "1"
o:depends({ tcp_node = "", ["!reverse"] = true })

-- Node → DNS Depends Settings
o = s:taboption("Main", DummyValue, "_node_sel_shunt", "")
o.template = appname .. "/cbi/hidevalue"
o.value = "1"
o:depends({ tcp_node = "__always__" })

o = s:taboption("Main", DummyValue, "_node_sel_other", "")
o.template = appname .. "/cbi/hidevalue"
o.value = "1"
o:depends({ _node_sel_shunt = "1",  ['!reverse'] = true })

-- [[ DNS Settings ]]--
s:tab("DNS", translate("DNS"))

o = s:taboption("DNS", ListValue, "dns_shunt", "DNS " .. translate("Shunt"))
o:value("dnsmasq", "Dnsmasq")
o:value("chinadns-ng", translate("ChinaDNS-NG (recommended)"))
if api.is_finded("smartdns") then
	o:value("smartdns", "SmartDNS")
	o = s:taboption("DNS", Value, "group_domestic", translate("Domestic group name"))
	o.placeholder = "local"
	o:depends("dns_shunt", "smartdns")
	o.description = translate("You only need to configure domestic DNS packets in SmartDNS, and fill in the domestic DNS group name here.")
end

o = s:taboption("DNS", ListValue, "direct_dns_mode", translate("Direct DNS") .. " " .. translate("Request protocol"))
o:value("", translate("Auto"))
o:value("udp", translatef("Requery DNS By %s", "UDP"))
o:value("tcp", translatef("Requery DNS By %s", "TCP"))
o:depends({dns_shunt = "dnsmasq"})
o:depends({dns_shunt = "chinadns-ng"})

o = s:taboption("DNS", Value, "direct_dns", translate("Direct DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "223.5.5.5"
o:value("223.5.5.5")
o:value("223.6.6.6")
o:value("180.184.1.1")
o:value("180.184.2.2")
o:value("114.114.114.114")
o:value("114.114.115.115")
o:value("119.28.28.28")
o:depends("direct_dns_mode", "udp")
o:depends("direct_dns_mode", "tcp")

o = s:taboption("DNS", Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"

-- TCP分流时dns过滤模式保存逻辑
function dns_mode_save(section)
	local f = s.fields["tcp_node"]
	local id_val = f and f:formvalue(section) or ""
	if id_val == "" then
		return
	end
	for _, v in pairs(shunt_list) do
		if v.id == id_val then
			local type_val = v.type
			if type_val and (type_val == "Xray" or type_val == "sing-box") then
				local dns_shunt_val = s.fields["dns_shunt"]:formvalue(section)
				local dns_mode_val = (dns_shunt_val ~= "smartdns") and "dns_mode" or "smartdns_dns_mode"
				local current_val = m:get(section, dns_mode_val) or ""
				local new_val = (type_val == "Xray") and "xray" or "sing-box"

				if current_val ~= new_val then
					m:set(section, dns_mode_val, new_val)
					m:del(section, (dns_mode_val == "dns_mode") and "smartdns_dns_mode" or "dns_mode")
				end

				local dns_field = s.fields[type_val == "Xray" and "xray_dns_mode" or "singbox_dns_mode"]
				local v2ray_dns_mode = dns_field and dns_field:formvalue(section)
				if v2ray_dns_mode and m:get(section, "v2ray_dns_mode") ~= v2ray_dns_mode then
					m:set(section, "v2ray_dns_mode", v2ray_dns_mode)
				end

				break
			end
		end
	end
end

---- DNS Forward Mode
o = s:taboption("DNS", ListValue, "dns_mode", translate("Filter Mode"))
o.default = "tcp"
o:value("udp", translatef("Requery DNS By %s", "UDP"))
o:value("tcp", translatef("Requery DNS By %s", "TCP"))
if api.is_finded("dns2socks") then
	o:value("dns2socks", "dns2socks")
end
if has_singbox then
	o:value("sing-box", "Sing-Box")
end
if has_xray then
	o:value("xray", "Xray")
end
o:depends({ dns_shunt = "chinadns-ng", _node_sel_other = "1" })
o:depends({ dns_shunt = "dnsmasq", _node_sel_other = "1" })
o.remove = function(self, section)
	local f = s.fields["smartdns_dns_mode"]
	if f and f:formvalue(section) then
		return m:del(section, self.option)
	end
	dns_mode_save(section)
end

---- SmartDNS Forward Mode
if api.is_finded("smartdns") then
	o = s:taboption("DNS", ListValue, "smartdns_dns_mode", translate("Filter Mode"))
	o:value("socks", "Socks")
	if has_singbox then
		o:value("sing-box", "Sing-Box")
	end
	if has_xray then
		o:value("xray", "Xray")
	end
	o:depends({ dns_shunt = "smartdns", _node_sel_other = "1" })
	o.remove = function(self, section)
		local f = s.fields["dns_mode"]
		if f and f:formvalue(section) then
			return m:del(section, self.option)
		end
		dns_mode_save(section)
	end

	o = s:taboption("DNS", DynamicList, "smartdns_remote_dns", translate("Remote DNS"))
	o:value("tcp://1.1.1.1")
	o:value("tcp://8.8.4.4")
	o:value("tcp://8.8.8.8")
	o:value("tcp://9.9.9.9")
	o:value("tcp://208.67.222.222")
	o:value("tls://1.1.1.1")
	o:value("tls://8.8.4.4")
	o:value("tls://8.8.8.8")
	o:value("tls://9.9.9.9")
	o:value("tls://208.67.222.222")
	o:value("https://1.1.1.1/dns-query")
	o:value("https://8.8.4.4/dns-query")
	o:value("https://8.8.8.8/dns-query")
	o:value("https://9.9.9.9/dns-query")
	o:value("https://208.67.222.222/dns-query")
	o:value("https://dns.adguard.com/dns-query,94.140.14.14")
	o:value("https://doh.libredns.gr/dns-query,116.202.176.26")
	o:value("https://doh.libredns.gr/ads,116.202.176.26")
	o:depends({ dns_shunt = "smartdns", smartdns_dns_mode = "socks" })
	o.cfgvalue = function(self, section)
		return m:get(section, self.option) or {"tcp://1.1.1.1"}
	end
	function o.write(self, section, value)
		local t = {}
		local t2 = {}
		if type(value) == "table" then
			local x
			for _, x in ipairs(value) do
				if x and #x > 0 then
					if not t2[x] then
						t2[x] = x
						t[#t+1] = x
					end
				end
			end
		else
			t = { value }
		end
		return DynamicList.write(self, section, t)
	end
end

o = s:taboption("DNS", ListValue, "xray_dns_mode", translate("Remote DNS") .. " " .. translate("Request protocol"))
o.default = "tcp"
o:value("udp", "UDP")
o:value("tcp", "TCP")
o:value("tcp+doh", "TCP + DoH (" .. translate("A/AAAA type") .. ")")
o:depends("dns_mode", "xray")
o:depends("smartdns_dns_mode", "xray")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if s.fields["dns_mode"]:formvalue(section) == "xray" or s.fields["smartdns_dns_mode"]:formvalue(section) == "xray" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

o = s:taboption("DNS", ListValue, "singbox_dns_mode", translate("Remote DNS") .. " " .. translate("Request protocol"))
o.default = "tcp"
o:value("udp", "UDP")
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:depends("dns_mode", "sing-box")
o:depends("smartdns_dns_mode", "sing-box")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if s.fields["dns_mode"]:formvalue(section) == "sing-box" or s.fields["smartdns_dns_mode"]:formvalue(section) == "sing-box" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

o = s:taboption("DNS", Value, "socks_server", translate("Socks Server"), translate("Make sure socks service is available on this address."))
for k, v in pairs(socks_table) do o:value(v.id, v.remark) end
o.default = socks_table[1].id
o.validate = function(self, value, t)
	if not datatypes.ipaddrport(value) then
		return nil, translate("Socks Server") .. " " .. translate("Not valid IP format, please re-enter!")
	end
	return value
end
o:depends({dns_mode = "dns2socks"})

---- DNS Forward
o = s:taboption("DNS", Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9)")
o:value("149.112.112.112", "149.112.112.112 (Quad9)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({dns_mode = "dns2socks"})
o:depends({dns_mode = "tcp"})
o:depends({dns_mode = "udp"})
o:depends({xray_dns_mode = "udp"})
o:depends({xray_dns_mode = "tcp"})
o:depends({xray_dns_mode = "tcp+doh"})
o:depends({singbox_dns_mode = "udp"})
o:depends({singbox_dns_mode = "tcp"})

---- DoH
o = s:taboption("DNS", Value, "remote_dns_doh", translate("Remote DNS DoH"))
o.default = "https://1.1.1.1/dns-query"
o:value("https://1.1.1.1/dns-query", "1.1.1.1 (CloudFlare)")
o:value("https://1.1.1.2/dns-query", "1.1.1.2 (CloudFlare-Security)")
o:value("https://8.8.4.4/dns-query", "8.8.4.4 (Google)")
o:value("https://8.8.8.8/dns-query", "8.8.8.8 (Google)")
o:value("https://9.9.9.9/dns-query", "9.9.9.9 (Quad9)")
o:value("https://149.112.112.112/dns-query", "149.112.112.112 (Quad9)")
o:value("https://208.67.222.222/dns-query", "208.67.222.222 (OpenDNS)")
o:value("https://dns.adguard.com/dns-query,94.140.14.14", "94.140.14.14 (AdGuard)")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "116.202.176.26 (LibreDNS)")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "116.202.176.26 (LibreDNS-NoAds)")
o.validate = doh_validate
o:depends({xray_dns_mode = "tcp+doh"})
o:depends({singbox_dns_mode = "doh"})

o = s:taboption("DNS", Value, "remote_dns_client_ip", translate("EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
		translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends({dns_mode = "sing-box"})
o:depends({dns_mode = "xray"})
o:depends("dns_shunt", "smartdns")
o:depends("_node_sel_shunt", "1")

o = s:taboption("DNS", Flag, "remote_fakedns", "FakeDNS", translate("Use FakeDNS work in the shunt domain that proxy."))
o.default = "0"
o:depends({dns_mode = "sing-box", dns_shunt = "dnsmasq"})
o:depends({dns_mode = "sing-box", dns_shunt = "chinadns-ng"})
o:depends({smartdns_dns_mode = "sing-box", dns_shunt = "smartdns"})
o:depends({dns_mode = "xray", dns_shunt = "dnsmasq"})
o:depends({dns_mode = "xray", dns_shunt = "chinadns-ng"})
o:depends({smartdns_dns_mode = "xray", dns_shunt = "smartdns"})
--o:depends("_node_sel_shunt", "1")
o.validate = function(self, value, t)
	if value and value == "1" then
		local _dns_mode = s.fields["dns_mode"]:formvalue(t)
		if not _dns_mode and s.fields["smartdns_dns_mode"] then
			_dns_mode = s.fields["smartdns_dns_mode"]:formvalue(t)
		end
		local _tcp_node = s.fields["tcp_node"]:formvalue(t)
		if _dns_mode and _tcp_node then
			if m:get(_tcp_node, "type"):lower() ~= _dns_mode then
				return nil, translatef("TCP node must be '%s' type to use FakeDNS.", _dns_mode)
			end
		end
	end
	return value
end

o = s:taboption("DNS", ListValue, "chinadns_ng_default_tag", translate("Default DNS"))
o.default = "none"
o:value("gfw", translate("Remote DNS"))
o:value("chn", translate("Direct DNS"))
o:value("none", translate("Smart, Do not accept no-ip reply from Direct DNS"))
o:value("none_noip", translate("Smart, Accept no-ip reply from Direct DNS"))
local desc = "<ul>"
		.. "<li>" .. translate("When not matching any domain name list:") .. "</li>"
		.. "<li>" .. translate("Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!") .. "</li>"
		.. "<li>" .. translate("Direct DNS: Internet experience may be better, but DNS will be leaked!") .. "</li>"
o.description = desc
		.. "<li>" .. translate("Smart: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China IP, then use the direct result, otherwise use the remote result.") .. "</li>"
		.. "<li>" .. translate("In smart mode, no-ip reply from Direct DNS:") .. "</li>"
		.. "<li>" .. translate("Do not accept: Wait and use Remote DNS Reply.") .. "</li>"
		.. "<li>" .. translate("Accept: Trust the Reply, using this option can improve DNS resolution speeds for some mainland IPv4-only sites.") .. "</li>"
		.. "</ul>"
o:depends({dns_shunt = "chinadns-ng", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:taboption("DNS", ListValue, "use_default_dns", translate("Default DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o.description = desc .. "</ul>"
o:depends({dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})
if api.is_finded("smartdns") then
	o:depends({dns_shunt = "smartdns", tcp_proxy_mode = "proxy", chn_list = "direct"})
end

o = s:taboption("DNS", Flag, "force_https_soa", translate("Force HTTPS SOA"), translate("Force queries with qtype 65 to respond with an SOA record."))
o.default = "1"
o.rmempty = false
o:depends({dns_shunt = "chinadns-ng"})
if api.is_finded("smartdns") then
	o:depends({dns_shunt = "smartdns"})
end

o = s:taboption("DNS", Flag, "dns_redirect", translate("DNS Redirect"), translate("Force special DNS server to need proxy devices."))
o.default = "1"
o.rmempty = false

local use_nft = m:get("@global_forwarding[0]", "use_nft") == "1"
local set_title = api.i18n.translate(use_nft and "Clear NFTSET on Reboot" or "Clear IPSET on Reboot")
o = s:taboption("DNS", Flag, "flush_set_on_reboot", set_title, translate("Clear IPSET/NFTSET on service reboot. This may increase reboot time."))
o.default = "0"

set_title = api.i18n.translate(use_nft and "Clear NFTSET" or "Clear IPSET")
o = s:taboption("DNS", DummyValue, "clear_ipset", set_title, translate("Try this feature if the rule modification does not take effect."))
o.rawhtml = true
function o.cfgvalue(self, section)
	return string.format(
		[[<button type="button" class="cbi-button cbi-button-remove" onclick="location.href='%s'">%s</button>]],
		api.url("flush_set") .. "?redirect=1&reload=1", set_title)
end

s:tab("Proxy", translate("Mode"))

o = s:taboption("Proxy", Flag, "use_direct_list", translatef("Use %s", translate("Direct List")))
o.default = "1"

o = s:taboption("Proxy", Flag, "use_proxy_list", translatef("Use %s", translate("Proxy List")))
o.default = "1"

o = s:taboption("Proxy", Flag, "use_block_list", translatef("Use %s", translate("Block List")))
o.default = "1"

if has_gfwlist then
	o = s:taboption("Proxy", Flag, "use_gfw_list", translatef("Use %s", translate("GFW List")))
	o.default = "1"
end

if has_chnlist or has_chnroute then
	o = s:taboption("Proxy", ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
end

---- TCP Default Proxy Mode
o = s:taboption("Proxy", ListValue, "tcp_proxy_mode", "TCP " .. translate("Default Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o.default = "proxy"

---- UDP Default Proxy Mode
o = s:taboption("Proxy", ListValue, "udp_proxy_mode", "UDP " .. translate("Default Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o.default = "proxy"

o = s:taboption("Proxy", DummyValue, "switch_mode", " ")
o.template = appname .. "/global/proxy"

---- Check the transparent proxy component
local handle = io.popen("lsmod")
local mods = ""
if handle then
	mods = handle:read("*a") or ""
	handle:close()
end

if (mods:find("REDIRECT") and mods:find("TPROXY")) or (mods:find("nft_redir") and mods:find("nft_tproxy")) then
	o = s:taboption("Proxy", Flag, "localhost_proxy", translate("Localhost Proxy"), translate("When selected, localhost can transparent proxy."))
	o.default = "1"
	o.rmempty = false

	o = s:taboption("Proxy", Flag, "client_proxy", translate("Client Proxy"), translate("When selected, devices in LAN can transparent proxy. Otherwise, it will not be proxy. But you can still use access control to allow the designated device to proxy."))
	o.default = "1"
	o.rmempty = false
else
	local html = string.format([[<div class="cbi-checkbox"><input class="cbi-input-checkbox" type="checkbox" disabled></div><div class="cbi-value-description"><font color="red">%s</font></div>]], translate("Missing components, transparent proxy is unavailable."))
	o = s:taboption("Proxy", DummyValue, "localhost_proxy", translate("Localhost Proxy"))
	o.rawhtml = true
	function o.cfgvalue(self, section)
		return html
	end

	o = s:taboption("Proxy", DummyValue, "client_proxy", translate("Client Proxy"))
	o.rawhtml = true
	function o.cfgvalue(self, section)
		return html
	end
end

o = s:taboption("Proxy", DummyValue, "_proxy_tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<a style="color: red" href="%s">%s</a>', api.url("acl"), translate("Want different devices to use different proxy modes/ports/nodes? Please use access control."))
end

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "log_tcp", translate("Enable") .. " " .. translatef("%s Node Log", "TCP"))
o.default = "0"
o.rmempty = false

o = s:taboption("log", Flag, "log_udp", translate("Enable") .. " " .. translatef("%s Node Log", "UDP"))
o.default = "0"
o.rmempty = false

o = s:taboption("log", ListValue, "loglevel", "Sing-Box/Xray " .. translate("Log Level"))
o.default = "warning"
o:value("debug")
o:value("info")
o:value("warning")
o:value("error")

o = s:taboption("log", ListValue, "trojan_loglevel", "Trojan " ..  translate("Log Level"))
o.default = "2"
o:value("0", "all")
o:value("1", "info")
o:value("2", "warn")
o:value("3", "error")
o:value("4", "fatal")

o = s:taboption("log", Flag, "advanced_log_feature", translate("Advanced log feature"), translate("For professionals only."))
o.default = "0"
o = s:taboption("log", Flag, "sys_log", translate("Logging to system log"), translate("Logging to the system log for more advanced functions. For example, send logs to a dedicated log server."))
o:depends("advanced_log_feature", "1")
o.default = "0"
o = s:taboption("log", Value, "persist_log_path", translate("Persist log file directory"), translate("The path to the directory used to store persist log files, the \"/\" at the end can be omitted. Leave it blank to disable this feature."))
o:depends({ ["advanced_log_feature"] = 1, ["sys_log"] = 0 })
o = s:taboption("log", Value, "log_event_filter", translate("Log Event Filter"), translate("Support regular expression."))
o:depends("advanced_log_feature", "1")
o = s:taboption("log", Value, "log_event_cmd", translate("Shell Command"), translate("Shell command to execute, replace log content with %s."))
o:depends("advanced_log_feature", "1")

o = s:taboption("log", Flag, "log_chinadns_ng", translate("Enable") .. " ChinaDNS-NG " .. translate("Log"))
o.default = "0"
o.rmempty = false

o = s:taboption("log", DummyValue, "_log_tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>', translate("It is recommended to disable logging during regular use to reduce system overhead."))
end

s:tab("faq", "FAQ")
o = s:taboption("faq", DummyValue, "")
o.template = appname .. "/global/faq"

s:tab("maintain", translate("Maintain"))
o = s:taboption("maintain", DummyValue, "")
o.template = appname .. "/global/backup"

-- [[ Socks Server ]]--
o = s:taboption("Main", Flag, "socks_enabled", "Socks " .. translate("Main switch"))
o.rmempty = false

s2 = m:section(TypedSection, "socks", translate("Socks Config"))
s2.template = "cbi/tblsection"
s2.anonymous = true
s2.addremove = true
s2.extedit = api.url("socks_config", "%s")
function s2.create(e, t)
	local uuid = api.gen_short_uuid()
	t = uuid
	TypedSection.create(e, t)
	luci.http.redirect(e.extedit:format(t))
end
function s2.remove(e, t)
	local socks = "Socks_" .. t
	local new_node = ""
	local node0 = m:get("@nodes[0]") or nil
	if node0 then
		new_node = node0[".name"]
	end
	if (m:get("@global[0]", "tcp_node") or "") == socks then
		m:set('@global[0]', "tcp_node", new_node)
	end
	if (m:get("@global[0]", "udp_node") or "") == socks then
		m:set('@global[0]', "udp_node", new_node)
	end
	m.uci:foreach(appname, "acl_rule", function(s)
		if s["tcp_node"] and s["tcp_node"] == socks then
			m:set(s[".name"], "tcp_node", "default")
		end
		if s["udp_node"] and s["udp_node"] == socks then
			m:set(s[".name"], "udp_node", "default")
		end
	end)
	m.uci:foreach(appname, "nodes", function(s)
		local list_name = s["urltest_node"] and "urltest_node" or (s["balancing_node"] and "balancing_node")
		if list_name then
			local nodes = m.uci:get_list(appname, s[".name"], list_name)
			if nodes then
				local changed = false
				local new_nodes = {}
				for _, node in ipairs(nodes) do
					if node ~= socks then
						table.insert(new_nodes, node)
					else
						changed = true
					end
				end
				if changed then
					m.uci:set_list(appname, s[".name"], list_name, new_nodes)
				end
			end
		end
		if s["fallback_node"] == socks then
			m:del(s[".name"], "fallback_node")
		end
	end)
	TypedSection.remove(e, t)
end

o = s2:option(DummyValue, "status", translate("Status"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<div class="_status" socks_id="%s"></div>', n)
end

---- Enable
o = s2:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

o = s2:option(ListValue, "node", translate("Socks Node"))
o.template = appname .. "/cbi/nodes_listvalue"
o.group = {}

o = s2:option(DummyValue, "now_node", translate("Current Node"))
o.rawhtml = true
o.cfgvalue = function(_, n)
	local current_node = api.get_cache_var("socks_" .. n)
	if current_node then
		local node = m:get(current_node)
		if node then
			return (api.get_node_remarks(node) or ""):gsub("(：)%[", "%1<br>[")
		end
	end
end

local n = 1
m.uci:foreach(appname, "socks", function(s)
	if s[".name"] == section then
		return false
	end
	n = n + 1
end)

o = s2:option(Value, "port", "Socks " .. translate("Listen Port"))
o.default = n + 1080
o.datatype = "port"
o.rmempty = false

if has_singbox or has_xray then
	o = s2:option(Value, "http_port", "HTTP " .. translate("Listen Port"))
	o.default = 0
	o.datatype = "port"
end

local tcp = s.fields["tcp_node"]
local udp = s.fields["udp_node"]
local socks = s2.fields["node"]
for k, v in pairs(socks_list) do
	tcp:value(v.id, v["remark"])
	tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	udp:value(v.id, v["remark"])
	udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end
for k, v in pairs(nodes_table) do
	if #normal_list == 0 then
		break
	end
	if v.protocol == "_shunt" then
		if has_singbox or has_xray then
			tcp:value(v.id, v["remark"])
			tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			udp:value(v.id, v["remark"])
			udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

			s.fields["_node_sel_shunt"]:depends({ tcp_node = v.id })
			if m:get(v.id, "type") == "Xray" then
				s.fields["xray_dns_mode"]:depends({ tcp_node = v.id })
			else
				s.fields["singbox_dns_mode"]:depends({ tcp_node = v.id })
			end
		end
	else
		tcp:value(v.id, v["remark"])
		tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
		udp:value(v.id, v["remark"])
		udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	if v.type == "Socks" then
		if has_singbox or has_xray then
			socks:value(v.id, v["remark"])
			socks.group[#socks.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
		end
	else
		socks:value(v.id, v["remark"])
		socks.group[#socks.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end

m:append(Template(appname .. "/global/footer"))

return m
