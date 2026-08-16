local api = require "luci.passwall.api"
api.set_default_cbi()

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

m = Map()

function m.on_before_save(self)
	self:foreach("subscribe_list", function(e)
		self:del(e[".name"], "md5")
	end)
end

-- [[ Subscribe Settings ]]--
s = m:section(NamedSection, "@global_subscribe[0]", "global_subscribe")

o = s:option(ListValue, "filter_keyword_mode", translate("Filter keyword Mode"))
o:value("0", translate("Close"))
o:value("1", translate("Discard List"))
o:value("2", translate("Keep List"))
o:value("3", translate("Discard List,But Keep List First"))
o:value("4", translate("Keep List,But Discard List First"))

o = s:option(DynamicList, "filter_discard_list", translate("Discard List"))

o = s:option(DynamicList, "filter_keep_list", translate("Keep List"))

if #ss_type > 0 then
	o = s:option(ListValue, "ss_type", translatef("%s Node Use Type", "Shadowsocks"))
	o:value("", translate("Auto"))
	for key, value in pairs(ss_type) do
		o:value(value)
	end
end

if #trojan_type > 0 then
	o = s:option(ListValue, "trojan_type", translatef("%s Node Use Type", "Trojan"))
	o:value("", translate("Auto"))
	for key, value in pairs(trojan_type) do
		o:value(value)
	end
end

if #vmess_type > 0 then
	o = s:option(ListValue, "vmess_type", translatef("%s Node Use Type", "VMess"))
	o:value("", translate("Auto"))
	for key, value in pairs(vmess_type) do
		o:value(value)
	end
end

if #vless_type > 0 then
	o = s:option(ListValue, "vless_type", translatef("%s Node Use Type", "VLESS"))
	o:value("", translate("Auto"))
	for key, value in pairs(vless_type) do
		o:value(value)
	end
end

if #hysteria2_type > 0 then
	o = s:option(ListValue, "hysteria2_type", translatef("%s Node Use Type", "Hysteria2"))
	o:value("", translate("Auto"))
	for key, value in pairs(hysteria2_type) do
		o:value(value)
	end
end

if #ss_type > 0 or #trojan_type > 0 or #vmess_type > 0 or #vless_type > 0 or #hysteria2_type > 0 then
	o.description = string.format("<font color='red'>%s</font>",
			translate("The configured type also applies to the core specified when manually importing nodes."))
end

---- Subscribe Delete All
o = s:option(DummyValue, "_stop", translate("Delete All Subscribe Node"))
o.rawhtml = true
function o.cfgvalue(self, section)
	return string.format(
		[[<input type="button" class="btn cbi-button cbi-button-remove" onclick="return confirmDeleteAll()" value="%s" />]],
		translate("Delete All Subscribe Node"))
end

o = s:option(DummyValue, "_update", translate("Manual subscription All"))
o.rawhtml = true
o.cfgvalue = function(self, section)
    return string.format([[
        <input type="button" class="btn cbi-button cbi-button-apply" onclick="ManualSubscribeAll()" value="%s" />]],
	 translate("Manual subscription All"))
end

s = m:section(TypedSection, "subscribe_list", "", "<font color='red'>" .. translate("When adding a new subscription, please save and apply before manually subscribing. If you only change the subscription URL, you can subscribe manually, and the system will save it automatically.") .. "</font>")
s.addremove = true
s.anonymous = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = api.url("node_subscribe_config", "%s")
function s.create(e, t)
	local uid = "sub_" .. api.gen_random_char(5)
	TypedSection.create(e, uid)
	m:set(uid, "hysteria_up_mbps", "100")
	m:set(uid, "hysteria_down_mbps", "100")
	luci.http.redirect(e.extedit:format(uid))
end

o = s:option(Value, "remark", translate("Remarks"))
o.width = "auto"
o.rmempty = false
o.validate = function(self, value, section)
	value = api.trim(value)
	if value == "" then
		return nil, translate("Remark cannot be empty.")
	end
	local duplicate = false
	m:foreach(s.sectiontype, function(e)
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
				m:set(e[".name"], "group", value)
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
				m:set(e[".name"], "node_group", gs)
			end
		end)
	end
	return Value.write(self, section, value)
end

o = s:option(DummyValue, "_node_count", translate("Subscribe Info"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local remark = m:get(n, "remark") or ""
	local str = m:get(n, "rem_traffic") or ""
	local expired_date = m:get(n, "expired_date") or ""
	if expired_date ~= "" then
		str = str .. (str ~= "" and "/" or "") .. expired_date
	end
	str = str ~= "" and "<br>" .. str or ""
	local num = 0
	m:foreach("nodes", function(s)
		if s["group"] and s["group"]:lower() == remark:lower() then
			num = num + 1
		end
	end)
	return string.format("%s%s", translate("Node num") .. ": " .. num, str)
end

o = s:option(Value, "url", translate("Subscribe URL"))
o.width = "auto"
o.rmempty = false

o = s:option(DummyValue, "_remove", translate("Delete the subscribed node"))
o.rawhtml = true
function o.cfgvalue(self, section)
	local remark = m:get(section, "remark") or ""
	return string.format(
		[[<input type="button" class="btn cbi-button cbi-button-remove" onclick="return confirmDeleteNode('%s')" value="%s" />]],
		remark, translate("Delete the subscribed node"))
end

o = s:option(DummyValue, "_update", translate("Manual subscription"))
o.rawhtml = true
o.cfgvalue = function(self, section)
    return string.format([[
        <input type="button" class="btn cbi-button cbi-button-apply" onclick="ManualSubscribe('%s')" value="%s" />]],
	section, translate("Manual subscription"))
end

m:appendTemplate("/cbi/sortable", {sectiontype = s.sectiontype})

m:appendTemplate("/node_subscribe/js")

return api.return_map(m)
