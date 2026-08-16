local api = require "luci.passwall.api"

api.set_default_cbi()

local com = require "luci.passwall.com"

m = Map()

-- [[ App Settings ]]--
s = m:section(NamedSection, "@global_app[0]", "global_app", translate("App Update"))

s:appendTemplate("/app_update/app_version", {com = com})

o = s:option(Flag, "github_proxy", translate("GitHub Proxy"), translate("Use gh-proxy instead of proxy nodes for component updates."))
o.default = 0

local k, v
for _, k in ipairs(com.order) do
	v = com[k]
	if k ~= "chinadns-ng" then
		o = s:option(Value, k:gsub("%-","_") .. "_file", translatef("%s App Path", v.name))
		o.default = v.default_path or ("/usr/bin/" .. k)
		o.rmempty = false
	end
end

o = s:option(DummyValue, "tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>', translate("if you want to run from memory, change the path, /tmp beginning then save the application and update it manually."))
end

return api.return_map(m)
