api = require "luci.passwall.api"
api.set_default_cbi()

m = Map()
m.redirect = api.url("node_list")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

formvalue_key = "cbid." .. m.config .. "." .. arg[1] .. "."

m:appendTemplate("/node_config/header", {section = arg[1]})
m:appendTemplate("/cbi/nodes_multivalue_com")
m:appendTemplate("/cbi/nodes_listvalue_com")

groups = {}
m:foreach("nodes", function(s)
	if s[".name"] ~= arg[1] then
		if s.group and s.group ~= "" then
			groups[s.group] = true
		end
	end
end)

local s = m:section(NamedSection, arg[1], "nodes", translate("Node Config"))
s.addremove = false
s.dynamic = false

o = s:option(DummyValue, "passwall", "　")
o.rawhtml  = true
o.template = m:template_path("/node_config/link_share_man")
o.value = arg[1]

o = s:option(Value, "remarks", translate("Node Remarks"))
o.default = translate("Remarks")
o.rmempty = false

o = s:option(Value, "group", translate("Group Name"))
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

local types_dir = "/usr/lib/lua/luci/model/cbi/" .. api.appname .. "/client/type/"
s.val = {}
s.val["type"] = m:get(arg[1], "type")

if luci.http.formvalue("cbi.submit") == "1" then
	local formvalue_type = luci.http.formvalue(formvalue_key .. "type")
	if formvalue_type then
		s.val["type"] = formvalue_type
	end
end

o = s:option(ListValue, "type", translate("Type"))

local type_table = {}
for filename in api.fs.dir(types_dir) do
	if filename:match("^%d+_") then
		table.insert(type_table, filename)
	end
end
table.sort(type_table, function(a, b)
	return tonumber(a:match("^%d+")) < tonumber(b:match("^%d+"))
end)

for index, value in ipairs(type_table) do
	local p_func = loadfile(types_dir .. value)
	setfenv(p_func, getfenv(1))(m, s)
end

m:appendTemplate("/node_config/footer", {section = arg[1]})

return api.return_map(m)
