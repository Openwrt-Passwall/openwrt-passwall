local m, s, data = ...

if not data.node_id or not data.node then
	return
end

local current_node_id = data.node_id

local function get_cfgvalue()
	return function(self, section)
		return m:get(current_node_id, self.option)
	end
end
local function get_write()
	return function(self, section, value)
		if data.verify_option then
			if data.verify_option:formvalue(section) == current_node_id then
				m:set(current_node_id, self.option, value)
			end
		else
			m:set(current_node_id, self.option, value)
		end
	end
end
local function get_remove()
	return function(self, section)
		if data.verify_option then
			if data.verify_option:formvalue(section) == current_node_id then
				m:del(current_node_id, self.option)
			end
		else
			m:del(current_node_id, self.option)
		end
	end
end

if data.tab then
	s:tab(data.tab, data.tab_desc)
end

local function add_option(class, option_name, option_title, option_desc)
	local a
	if data.tab then
		a = s:taboption(data.tab, class, option_name, option_title)
	else
		a = s:option(class, option_name, option_title)
	end
	if a then
		if option_desc then
			a.description = option_desc
		end
		a.cfgvalue = get_cfgvalue()
		a.write = get_write()
		a.remove = get_remove()
	end
	if data.verify_option then
		a:depends(data.verify_option.option, current_node_id)
	end
	return a
end

local function add_depends(o, deps)
	if #o.deps > 0 then
		for index, value in ipairs(o.deps) do
			for k, v in pairs(deps) do
				o.deps[index][k] = v
			end
		end
	else
		o:depends(deps)
	end
end

if data.node.type == "Xray" then
	o = add_option(ListValue, "domainStrategy", translate("Domain Strategy"))
	o:value("AsIs")
	o:value("IPIfNonMatch")
	o:value("IPOnDemand")
	o.default = "IPOnDemand"
	o.description = "<br /><ul><li>" .. translate("'AsIs': Only use domain for routing. Default value.")
		.. "</li><li>" .. translate("'IPIfNonMatch': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again.")
		.. "</li><li>" .. translate("'IPOnDemand': As long as there is a IP-based rule, resolves the domain into IP immediately.")
		.. "</li></ul>"

	o = add_option(ListValue, "domainMatcher", translate("Domain matcher"))
	o:value("hybrid")
	o:value("linear")
end

o = add_option(Flag, "fakedns", '<a style="color:#FF8C00">FakeDNS</a>' .. " " .. translate("Main switch"), translate("Use FakeDNS work in the domain that proxy.") .. "<br>" ..
	translate("Suitable scenarios for let the node servers get the target domain names.") .. "<br>" ..
	translate("Such as: DNS unlocking of streaming media, reducing DNS query latency, etc."))

local shunt_rules = {}
m.uci:foreach(appname, "shunt_rules", function(e)
	e.id = e[".name"]
	e["_node_option"] = e[".name"]
	e["_node_default"] = ""
	e["_fakedns_option"] = e[".name"] .. "_fakedns"
	e["_proxy_tag_option"] = e[".name"] .. "_proxy_tag"
	table.insert(shunt_rules, e)
end)
table.insert(shunt_rules, {
	id = ".default",
	remarks = translate("Default"),
	_node_option = "default_node",
	_node_default = "_direct",
	_fakedns_option = "default_fakedns",
	_proxy_tag_option = "default_proxy_tag",
})

s2 = m:section(Table, shunt_rules, " ")
s2.config = appname
s2.sectiontype = "shunt_option_list"

o = s2:option(DummyValue, "remarks", translate("Rule"))
o.rawhtml = true
o.cfgvalue = function(self, section)
	if shunt_rules[section].id == ".default" then
		return string.format('<font style="color: red">%s</font>', shunt_rules[section].remarks)
	else
		return string.format('<a href="%s" target="_blank">%s</a>', api.url("shunt_rules", shunt_rules[section].id), shunt_rules[section].remarks)
	end
end

_node = s2:option(Value, "_node", translate("Node"))
_node.template = appname .. "/cbi/nodes_listvalue"
_node.group = {"","","",""}
_node:value("", translate("Close (Not use)"))
_node:value("_default", translate("Use default node"))
_node:value("_direct", translate("Direct Connection"))
_node:value("_blackhole", translate("Blackhole (Block)"))
_node.cfgvalue = function(self, section)
	return m:get(current_node_id, shunt_rules[section]["_node_option"]) or shunt_rules[section]["_node_default"]
end
_node.write = function(self, section, value)
	return m:set(current_node_id, shunt_rules[section]["_node_option"], value)
end
_node.remove = function(self, section)
	return m:del(current_node_id, shunt_rules[section]["_node_option"])
end

o = s2:option(Flag, "_fakedns", string.format('<a style="color:#FF8C00" title="%s">FakeDNS</a>', translate("Use FakeDNS work in the domain that proxy.") .. "\n" ..
	translate("Suitable scenarios for let the node servers get the target domain names.") .. "\n" ..
	translate("Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.")))
o.cfgvalue = function(self, section)
	return m:get(current_node_id, shunt_rules[section]["_fakedns_option"])
end
o.write = function(self, section, value)
	return m:set(current_node_id, shunt_rules[section]["_fakedns_option"], value)
end
o.remove = function(self, section)
	return m:del(current_node_id, shunt_rules[section]["_fakedns_option"])
end

proxy_tag_node = s2:option(ListValue, "_proxy_tag", string.format('<a style="color:red" title="%s">%s</a>',
	translate("Set the node to be used as a pre-proxy.") .. "\n" .. translate("Each rule has a separate switch that controls whether this rule uses the pre-proxy or not."),
	translate("Preproxy")))
proxy_tag_node.template = appname .. "/cbi/nodes_listvalue"
proxy_tag_node.group = {""}
proxy_tag_node:value("", translate("Close (Not use)"))
proxy_tag_node.cfgvalue = function(self, section)
	return m:get(current_node_id, shunt_rules[section]["_proxy_tag_option"])
end
proxy_tag_node.write = function(self, section, value)
	return m:set(current_node_id, shunt_rules[section]["_proxy_tag_option"], value)
end
proxy_tag_node.remove = function(self, section)
	return m:del(current_node_id, shunt_rules[section]["_proxy_tag_option"])
end

if data.socks_list then
	for k, v in pairs(data.socks_list) do
		_node:value(v.id, v.remark)
		_node.group[#_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

		proxy_tag_node:value(v.id, v.remark)
		proxy_tag_node.group[#proxy_tag_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end
if data.urltest_list then
	for k, v in pairs(data.urltest_list) do
		_node:value(v.id, v.remark)
		_node.group[#_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

		proxy_tag_node:value(v.id, v.remark)
		proxy_tag_node.group[#proxy_tag_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end
if data.balancing_list then
	for k, v in pairs(data.balancing_list) do
		_node:value(v.id, v.remark)
		_node.group[#_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

		proxy_tag_node:value(v.id, v.remark)
		proxy_tag_node.group[#proxy_tag_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end
if data.iface_list then
	for k, v in pairs(data.iface_list) do
		_node:value(v.id, v.remark)
		_node.group[#_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

		proxy_tag_node:value(v.id, v.remark)
		proxy_tag_node.group[#proxy_tag_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end
if data.normal_list then
	for k, v in pairs(data.normal_list) do
		_node:value(v.id, v.remark)
		_node.group[#_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

		proxy_tag_node:value(v.id, v.remark)
		proxy_tag_node.group[#proxy_tag_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end

local footer = Template(appname .. "/include/shunt_options")
footer.api = api
footer.id = current_node_id
footer.normal_list = api.jsonc.stringify(data.normal_list or {})
m:append(footer)
