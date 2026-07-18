local api = require "luci.passwall.api"
local appname = api.appname

api.set_default_cbi()

m = Map("passwall_server", translate("Server-Side"))
api.set_apply_on_parse(m)

t = m:section(NamedSection, "global", "global")
t.anonymous = true
t.addremove = false

e = t:option(Flag, "enable", translate("Enable"))
e.rmempty = false

e = t:option(Value, "start_delay", translate("Delay Start"), translate("Units:seconds"))
e.default = "90"
e.datatype = "range(0,600)"
e.rmempty = false

local cfgname = "user"
t = m:section(TypedSection, cfgname, translate("Users Manager"))
t.anonymous = true
t.addremove = true
t.sortable = true
t.template = "cbi/tblsection"
t.extedit = api.url("server_user", "%s")
function t.create(e, t)
	local uuid = api.gen_uuid()
	t = uuid
	TypedSection.create(e, t)
	luci.http.redirect(e.extedit:format(t))
end
function t.remove(e, t)
	e.map.proceed = true
	e.map:del(t)
	luci.http.redirect(api.url("server"))
end

e = t:option(Flag, "enable", translate("Enable"))
e.width = "5%"
e.rmempty = false

e = t:option(DummyValue, "status", translate("Status"))
e.rawhtml = true
e.cfgvalue = function(t, n)
	return string.format('<font class="_users_status">%s</font>', translate("Collecting data..."))
end

e = t:option(DummyValue, "remarks", translate("Remarks"))
e.width = "15%"

e = t:option(DummyValue, "type", translate("Type"))
e.width = "20%"
e.rawhtml = true
e.cfgvalue = function(t, n)
	local str = ""
	local type = m:get(n, "type") or ""
	if type == "sing-box" or type == "Xray" then
		local protocol = m:get(n, "protocol") or ""
		if protocol == "vmess" then
			protocol = "VMess"
		elseif protocol == "vless" then
			protocol = "VLESS"
		elseif protocol == "shadowsocks" then
			protocol = "SS"
		elseif protocol == "shadowsocksr" then
			protocol = "SSR"
		elseif protocol == "wireguard" then
			protocol = "WG"
		elseif protocol == "hysteria" then
			protocol = "HY"
		elseif protocol == "hysteria2" then
			protocol = "HY2"
		elseif protocol == "anytls" then
			protocol = "AnyTLS"
		else
			protocol = protocol:gsub("^%l",string.upper)
			local custom = m:get(n, "custom") or "0"
			if custom == "1" then
				protocol = translate("Custom Config")
			end
		end
		if type == "sing-box" then type = "Sing-Box" end
		type = type .. " " .. protocol
	end
	str = str .. translate(type)
	return str
end

e = t:option(DummyValue, "port", translate("Port"))

e = t:option(Flag, "log", translate("Log"))
e.default = "1"
e.rmempty = false

local sortable = Template(appname .. "/cbi/sortable")
sortable.api = api
sortable.appname = m.config
sortable.target_cfgname = cfgname
m:append(sortable)

m:append(Template(appname .. "/server/log"))

m:append(Template(appname .. "/server/users_list_status"))

return api.return_map(m)
