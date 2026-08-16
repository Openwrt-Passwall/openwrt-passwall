api = require "luci.passwall.api"
api.set_default_cbi()

m = Map(api.s_config)
m.redirect = api.url("server")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

s = m:section(NamedSection, arg[1], "user", translate("User Config"))
s.addremove = false
s.dynamic = false

o = s:option(Value, "username", translate("Username"))
o.datatype = "and(uciname,maxlength(24))"
o.rmempty = false
function o.validate(self, value, section)
	local exists = false
	m.uci:foreach("passwall_server", "user", function(s)
		if s[".name"] ~= section and s.username == value then
			exists = true
			return false
		end
	end)
	if exists then
		return nil, translate("This username already exists.")
	end
	return value
end

o = s:option(Value, "password",  translate("Password"))
o.rmempty = false

o = s:option(Value, "uuid",  "UUID")
o.datatype = "uuid"
o.default = api.gen_uuid()
o.rmempty = false

return api.return_map(m)
