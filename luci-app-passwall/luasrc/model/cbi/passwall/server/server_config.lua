api = require "luci.passwall.api"
api.set_default_cbi()

m = Map(api.s_config)
m.redirect = api.url("server")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:appendTemplate("/server/config_header", {section = arg[1]})

m:appendTemplate("/cbi/nodes_listvalue_com")

user_list = {}
m:foreach("user", function(s)
	user_list[#user_list + 1] = s
end)

local s = m:section(NamedSection, arg[1], "server", translate("Server Config"))
s.addremove = false
s.dynamic = false

local types_dir = "/usr/lib/lua/luci/model/cbi/" .. api.appname .. "/server/type/"
s.val = m:get(arg[1]) or {}

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "remarks", translate("Remarks"))
o.default = translate("Remarks")
o.rmempty = false

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

m:appendTemplate("/server/config_footer", {section = arg[1]})

return api.return_map(m)
