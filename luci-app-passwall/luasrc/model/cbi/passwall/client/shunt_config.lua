local api = require "luci.passwall.api"
local appname = "passwall"
local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")

m = Map(appname, translate("Shunt Node Config"))
m.redirect = api.url("node_list")
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

s = m:section(NamedSection, arg[1], "nodes", "")
s.addremove = false
s.dynamic = false

local nodes_table = {}
local iface_table = {}
local balancers_table = {}
local urltest_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			type = e["type"],
			address = e["address"],
			chain_proxy = e["chain_proxy"],
			group = e["group"]
		}
	end
	if e.protocol == "_iface" then
		iface_table[#iface_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			group = e["group"]
		}
	end
	if e.protocol == "_balancing" then
		balancers_table[#balancers_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			group = e["group"]
		}
	end
	if e.protocol == "_urltest" then
		urltest_table[#urltest_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			group = e["group"]
		}
	end
end

local socks_list = {}
m.uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " " .. string.format("[%s %s]", s.port, translate("Port")),
			group = "Socks"
		}
	end
end)

o = s:option(Value, "remarks", translate("Node Remarks"))
o.default = translate("Remarks")
o.rmempty = false

o = s:option(Value, "group", translate("Group Name"))
o.default = ""
o:value("", translate("default"))
local groups = {}
m.uci:foreach(appname, "nodes", function(s)
	if s[".name"] ~= arg[1] then
		if s.group and s.group ~= "" then
			groups[s.group] = true
		end
	end
end)
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

local default_node = m.uci:get(appname, arg[1], "default_node") or "_direct"
-- [[ 分流模块 ]]
if #nodes_table > 0 then
	local type = s:option(ListValue, "type", translate("Type"))
	if has_xray then
		type:value("Xray", translate("Xray"))
	end
	if has_singbox then
		type:value("sing-box", translate("Sing-Box"))
	end

	o = s:option(Flag, "preproxy_enabled", translate("Preproxy"))

	o = s:option(ListValue, "main_node", string.format('<a style="color:#FF8C00">%s</a>', translate("Preproxy Node")), translate("Set the node to be used as a pre-proxy. Each rule (including <code>Default</code>) has a separate switch that controls whether this rule uses the pre-proxy or not."))
	o:depends({ ["preproxy_enabled"] = true })
	o.template = appname .. "/cbi/nodes_listvalue"
	o.group = {}
	for k, v in pairs(socks_list) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(urltest_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end

	o = s:option(Flag, "fakedns", "FakeDNS", translate("Use FakeDNS work in the shunt domain that proxy."))
end
m.uci:foreach(appname, "shunt_rules", function(e)
	if e[".name"] and e.remarks then
		o = s:option(ListValue, e[".name"], string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", e[".name"]), e.remarks))
		o:value("", translate("Close"))
		o:value("_default", translate("Default"))
		o:value("_direct", translate("Direct Connection"))
		o:value("_blackhole", translate("Blackhole"))
		o.template = appname .. "/cbi/nodes_listvalue"
		o.group = {"","","",""}

		if #nodes_table > 0 then
			local pt = s:option(ListValue, e[".name"] .. "_proxy_tag", string.format('* <a style="color:#FF8C00">%s</a>', e.remarks .. " " .. translate("Preproxy")))
			pt:value("", translate("Close"))
			pt:value("main", translate("Preproxy Node"))
			pt:depends("__hide__", "1")

			local fakedns_tag = s:option(Flag, e[".name"] .. "_fakedns", string.format('* <a style="color:#FF8C00">%s</a>', e.remarks .. " " .. "FakeDNS"))

			for k, v in pairs(socks_list) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
				fakedns_tag:depends({ ["fakedns"] = true, [e[".name"]] = v.id })
			end
			for k, v in pairs(balancers_table) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			end
			for k, v in pairs(urltest_table) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			end
			for k, v in pairs(iface_table) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			end
			for k, v in pairs(nodes_table) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
				if not api.is_local_ip(v.address) then  --本地节点禁止使用前置
					pt:depends({ ["preproxy_enabled"] = true, [e[".name"]] = v.id })
				end
				fakedns_tag:depends({ ["fakedns"] = true, [e[".name"]] = v.id })
			end
			if default_node ~= "_direct" or default_node ~= "_blackhole" then
				fakedns_tag:depends({ ["fakedns"] = true, [e[".name"]] = "_default" })
			end
		end
	end
end)

o = s:option(DummyValue, "shunt_tips", "　")
o.not_rewrite = true
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<a style="color: red" href="../rule">%s</a>', translate("No shunt rules? Click me to go to add."))
end

local o = s:option(ListValue, "default_node", string.format('* <a style="color:red">%s</a>', translate("Default")))
o:value("_direct", translate("Direct Connection"))
o:value("_blackhole", translate("Blackhole"))
o.template = appname .. "/cbi/nodes_listvalue"
o.group = {"",""}

if #nodes_table > 0 then
	for k, v in pairs(socks_list) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(urltest_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
	local dpt = s:option(ListValue, "default_proxy_tag", string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
	dpt:value("", translate("Close"))
	dpt:value("main", translate("Preproxy Node"))
	dpt:depends("__hide__", "1")
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remark)
		o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
		if not api.is_local_ip(v.address) then
			dpt:depends({ ["preproxy_enabled"] = true, ["default_node"] = v.id })
		end
	end
end

return m
