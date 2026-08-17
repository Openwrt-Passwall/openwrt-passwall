local api = require "luci.passwall.api"
api.set_default_cbi()

m = Map()
m.redirect = api.url("node_subscribe")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

function m.on_before_save(self)
	self:del(arg[1], "md5")
end

m:appendTemplate("/cbi/nodes_listvalue_com")

local has_ss_rust = api.is_finded("sslocal")
local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")
local has_hysteria2 = api.finded_com("hysteria")
local ss_type = {}
local trojan_type = {}
local vmess_type = {}
local vless_type = {}
local hysteria2_type = {}
local xray_version = api.get_app_version("xray")
if has_ss_rust then
	local s = "shadowsocks-rust"
	table.insert(ss_type, s)
end
if has_singbox then
	local s = "sing-box"
	table.insert(trojan_type, s)
	table.insert(ss_type, s)
	table.insert(vmess_type, s)
	table.insert(vless_type, s)
	table.insert(hysteria2_type, s)
end
if has_xray then
	local s = "xray"
	table.insert(trojan_type, s)
	table.insert(ss_type, s)
	table.insert(vmess_type, s)
	table.insert(vless_type, s)
	if api.compare_versions(xray_version, ">=", "26.1.13") then
		table.insert(hysteria2_type, s)
	end
end
if has_hysteria2 then
	local s = "hysteria2"
	table.insert(hysteria2_type, s)
end
local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			type = e["type"],
			add_mode = e["add_mode"],
			chain_proxy = e["chain_proxy"],
			group = e["group"]
		}
	end
end

s = m:section(NamedSection, arg[1])
s.addremove = false
s.dynamic = false

o = s:option(Value, "remark", translate("Subscribe Remark"))
o.rmempty = false
o.validate = function(self, value, section)
	value = api.trim(value)
	if value == "" then
		return nil, translate("Remark cannot be empty.")
	end
	local duplicate = false
	m:foreach("subscribe_list", function(e)
		if e[".name"] ~= section and e["remark"] and e["remark"]:lower() == value:lower() then
			duplicate = true
			return false
		end
	end)
	if duplicate or value:lower() == "default" then
		return nil, translate("This remark already exists, please change a new remark.")
	end
	return value
end
o.write = function(self, section, value)
	local old = m:get(section, self.option) or ""
	if old ~= value then
		m:foreach("nodes", function(e)
			if e["group"] and e["group"]:lower() == old:lower() then
				self.map:set(e[".name"], "group", value)
			end
			if e["protocol"] and (e["protocol"] == "_balancing" or e["protocol"] == "_urltest") and e["node_group"] then
				local gs = ""
				for g in e["node_group"]:gmatch("%S+") do
					if api.UrlEncode(old) == g then
						gs = gs .. " " .. api.UrlEncode(value)
					else
						gs = gs .. " " .. g
					end
				end
				gs = api.trim(gs)
				self.map:set(e[".name"], "node_group", gs)
			end
		end)
	end
	return Value.write(self, section, value)
end

o = s:option(TextValue, "url", translate("Subscribe URL"))
o.rows = 5
o.rmempty = false
o.validate = function(self, value)
	if not value or value == "" then
		return nil, translate("URL cannot be empty.")
	end
	return value:gsub("%s+", ""):gsub("%z", "")
end

o = s:option(ListValue, "domain_resolver", translate("Domain DNS Resolve"))
o.description = translate("If the node address is a domain name, this DNS will be used for resolution.") .. "<br>" ..
		translate("Supports only Xray or Sing-box node types.") .. "<br>" .. string.format('<font color="red">%s</font>',
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
o:value("UseIPv4v6", translate("Prefer IPv4"))
o:value("UseIPv6v4", translate("Prefer IPv6"))
o:value("UseIPv4", translate("IPv4 Only"))
o:value("UseIPv6", translate("IPv6 Only"))

o = s:option(Flag, "allowInsecure", translate("allowInsecure"))
o.default = "0"
o.rmempty = false
o.description = translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped.") .. "<br>" ..
		translate("Used when the node link does not include this parameter.")

o = s:option(ListValue, "filter_keyword_mode", translate("Filter keyword Mode"))
o.default = "5"
o:value("0", translate("Close"))
o:value("1", translate("Discard List"))
o:value("2", translate("Keep List"))
o:value("3", translate("Discard List,But Keep List First"))
o:value("4", translate("Keep List,But Discard List First"))
o:value("5", translate("Use global config"))

o = s:option(DynamicList, "filter_discard_list", translate("Discard List"))
o:depends("filter_keyword_mode", "1")
o:depends("filter_keyword_mode", "3")
o:depends("filter_keyword_mode", "4")

o = s:option(DynamicList, "filter_keep_list", translate("Keep List"))
o:depends("filter_keyword_mode", "2")
o:depends("filter_keyword_mode", "3")
o:depends("filter_keyword_mode", "4")

if #ss_type > 0 then
	o = s:option(ListValue, "ss_type", translatef("%s Node Use Type", "Shadowsocks"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(ss_type) do
		o:value(value)
	end
end

if #trojan_type > 0 then
	o = s:option(ListValue, "trojan_type", translatef("%s Node Use Type", "Trojan"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(trojan_type) do
		o:value(value)
	end
end

if #vmess_type > 0 then
	o = s:option(ListValue, "vmess_type", translatef("%s Node Use Type", "VMess"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(vmess_type) do
		o:value(value)
	end
end

if #vless_type > 0 then
	o = s:option(ListValue, "vless_type", translatef("%s Node Use Type", "VLESS"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(vless_type) do
		o:value(value)
	end
end

if #hysteria2_type > 0 then
	o = s:option(ListValue, "hysteria2_type", translatef("%s Node Use Type", "Hysteria2"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(hysteria2_type) do
		o:value(value)
	end

	o = s:option(Value, "hysteria_up_mbps", "Hy/Hy2 " .. translate("Max upload Mbps"))
	o.datatype = "uinteger"

	o = s:option(Value, "hysteria_down_mbps", "Hy/Hy2 " .. translate("Max download Mbps"))
	o.datatype = "uinteger"
end

o = s:option(Flag, "boot_update", translate("Update Once on Boot"), translate("Updates the subscription the first time PassWall runs automatically after each system boot."))
o.default = 0

o = s:option(ListValue, "update_week_mode", translate("Auto Update Mode"))
o:value("", translate("Disable"))
o:value(8, translate("Loop Mode"))
o:value(7, translate("Every day"))
o:value(1, translate("Every Monday"))
o:value(2, translate("Every Tuesday"))
o:value(3, translate("Every Wednesday"))
o:value(4, translate("Every Thursday"))
o:value(5, translate("Every Friday"))
o:value(6, translate("Every Saturday"))
o:value(0, translate("Every Sunday"))

o = s:option(Value, "update_time_mode", translate("Update Time"))
for t = 0, 23 do o:value(t .. ":00") end
o.default = "0:00"
o.datatype = "timehhmm"
o:depends("update_week_mode", "0")
o:depends("update_week_mode", "1")
o:depends("update_week_mode", "2")
o:depends("update_week_mode", "3")
o:depends("update_week_mode", "4")
o:depends("update_week_mode", "5")
o:depends("update_week_mode", "6")
o:depends("update_week_mode", "7")

o = s:option(ListValue, "update_interval_mode", translate("Update Interval(hour)"))
for t = 1, 24 do o:value(t, t .. " " .. translate("hour")) end
o.default = 2
o:depends("update_week_mode", "8")
o.rmempty = true

o = s:option(ListValue, "access_mode", translate("Subscribe URL Access Method"))
o.default = ""
o:value("", translate("Auto"))
o:value("direct", translate("Direct Connection"))
o:value("proxy", translate("Proxy"))

o = s:option(Value, "user_agent", translate("User-Agent"))
o.default = "passwall"
o:value("passwall", "PassWall")
o:value("v2rayN/9.99", "v2rayN")
o:value("clash.meta", "Clash.Meta")
o:value("Clash", "Clash")
o:value("curl", "Curl")
o:value("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0", "Edge for Linux")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0", "Edge for Windows")

o = s:option(ListValue, "chain_proxy", translate("Chain Proxy"))
o:value("", translate("Close(Not use)"))
o:value("1", translate("Preproxy Node"))
o:value("2", translate("Landing Node"))
o:value("3", translate("Outbound Interface"))

local descrStr = "Chained proxy works only with Xray or Sing-box nodes.<br>"
descrStr = descrStr .. "You can only use manual or imported nodes as chained nodes."
descrStr = translate(descrStr) .. "<br>" .. translate("Only support a layer of proxy.")

o1 = s:option(ListValue, "preproxy_node", translate("Preproxy Node"))
o1:depends({ ["chain_proxy"] = "1" })
o1.description = descrStr
o1.template = m:template_path("/cbi/nodes_listvalue")
o1.group = {}

o2 = s:option(ListValue, "to_node", translate("Landing Node"))
o2:depends({ ["chain_proxy"] = "2" })
o2.description = descrStr
o2.template = m:template_path("/cbi/nodes_listvalue")
o2.group = {}

o3 = s:option(Value, "outbound_iface", translate("Outbound Interface"))
o3:depends({ ["chain_proxy"] = "3" })
o3:value("", translate("All"))
local iface = api.get_network_devices()
for _, d in ipairs(iface) do
	o3:value(d.name, d.label)
end

for k, v in pairs(nodes_table) do
	if (v.type == "Xray" or v.type == "sing-box") and (not v.chain_proxy or v.chain_proxy == "") and v.add_mode ~= "2" then
		o1:value(v.id, v.remark)
		o1.group[#o1.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
		o2:value(v.id, v.remark)
		o2.group[#o2.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end

return api.return_map(m)
