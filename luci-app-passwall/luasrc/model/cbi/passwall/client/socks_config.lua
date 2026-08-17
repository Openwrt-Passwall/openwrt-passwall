local api = require "luci.passwall.api"
api.set_default_cbi()

m = Map()
m.redirect = api.url()

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:appendTemplate("/cbi/nodes_dynamiclist_com")
m:appendTemplate("/cbi/nodes_listvalue_com")

local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

s = m:section(NamedSection, arg[1], translate("Socks Config"), translate("Socks Config"))
s.addremove = false
s.dynamic = false

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

local auto_switch_tip
local current_node = api.get_cache_var(arg[1])
if current_node then
	local n = m:get(current_node)
	if n then
		if tonumber(m:get(arg[1], "enable_autoswitch") or 0) == 1 then
			if n then
				local remarks = api.get_node_remarks(n)
				local url = api.url("node_config", n[".name"])
				auto_switch_tip = translatef("Current node: %s", string.format('<a href="%s">%s</a>', url, remarks)) .. "<br />"
			end
		end
	end
end

socks_node = s:option(ListValue, "node", translate("Node"))
if auto_switch_tip then
	socks_node.description = auto_switch_tip
end
socks_node.template = m:template_path("/cbi/nodes_listvalue")
socks_node.group = {}

o = s:option(Flag, "bind_local", translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
o.default = "0"

local n = 1
m:foreach("socks", function(s)
	if s[".name"] == section then
		return false
	end
	n = n + 1
end)

o = s:option(Value, "port", "Socks " .. translate("Listen Port"))
o.default = n + 1080
o.datatype = "port"
o.rmempty = false

if has_singbox or has_xray then
	o = s:option(Value, "http_port", "HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	o.default = 0
	o.datatype = "port"
end

o = s:option(Flag, "log", translate("Enable") .. " " .. translate("Log"))
o.default = 1
o.rmempty = false

o = s:option(Flag, "enable_autoswitch", translate("Auto Switch"))
o.default = 0
o.rmempty = false

o = s:option(ListValue, "backup_node_add_mode", translate("Backup Node Addition Method"))
o:depends("enable_autoswitch", true)
o.default = "manual"
o:value("manual", translate("Manual"))
o:value("batch", translate("Batch"))

o = s:option(DynamicList, "autoswitch_backup_node", translate("List of backup nodes"))
o:depends("backup_node_add_mode", "manual")
o.template = m:template_path("/cbi/nodes_dynamiclist")
o.group = {}
o.write = function(self, section, value)
	local n = s.fields["node"]:formvalue(section)
	local v = type(value) == "table" and value or { value }
	local t = {}
	for _, x in ipairs(v) do
		if x and x ~= n then t[#t+1] = x end
	end
	return DynamicList.write(self, section, t)
end
for i, v in pairs(nodes_table) do
	if v.protocol ~= "_shunt" then
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
		s.fields["enable_autoswitch"]:depends({ node = v.id })
	end
	socks_node:value(v.id, v["remark"])
	socks_node.group[#socks_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end

o = s:option(MultiValue, "backup_node_group", translate("Select Group"))
o:depends("backup_node_add_mode", "batch")
o.widget = "checkbox"
o:value("default", translate("default"))
local groups = {}
m:foreach("nodes", function(s)
	if s.group and s.group ~= "" then
		groups[s.group] = true
	end
end)
for k, v in pairs(groups) do
	o:value(api.UrlEncode(k), k)
end

o = s:option(Value, "backup_node_match_rule", translate("Node Matching Rules"))
o:depends("backup_node_add_mode", "batch")
local descrStr = "Example: <code>^A && B && !C && D$</code><br>"
descrStr = descrStr .. "This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>"
descrStr = descrStr .. "Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>"
descrStr = descrStr .. "Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>"
descrStr = descrStr .. "Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D)."
o.description = translate(descrStr)

o = s:option(Value, "autoswitch_testing_time", translate("How often to test"), translate("Units:seconds"))
o.datatype = "min(10)"
o.default = 30
o:depends("enable_autoswitch", true)

o = s:option(Value, "autoswitch_connect_timeout", translate("Timeout seconds"), translate("Units:seconds"))
o.datatype = "range(3,10)"
o.default = 3
o:depends("enable_autoswitch", true)

o = s:option(Value, "autoswitch_retry_num", translate("Timeout retry num"))
o.datatype = "range(1,5)"
o.default = 1
o:depends("enable_autoswitch", true)
	
o = s:option(Flag, "autoswitch_restore_switch", translate("Restore Switch"), translate("Immediately switch back to the main node when it becomes available."))
o:depends("enable_autoswitch", true)

o = s:option(Value, "autoswitch_probe_url", translate("Probe URL"), translate("The URL used to detect the connection status."))
o:value("https://cp.cloudflare.com/", "Cloudflare")
o:value("https://www.gstatic.com/generate_204", "Gstatic")
o:value("https://www.google.com/generate_204", "Google")
o:value("https://www.youtube.com/generate_204", "YouTube")
o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
o:value("https://wifi.vivo.com.cn/generate_204", "VIVO (CN)")
o.default = o.keylist[3]
o:depends("enable_autoswitch", true)

o = s:option(DummyValue, "btn")
o.template = m:template_path("/socks_auto_switch/btn")
o:depends("backup_node_add_mode", "manual")

return api.return_map(m)
