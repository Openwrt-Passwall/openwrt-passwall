local api = require "luci.passwall.api"
api.set_default_cbi()

m = Map(api.s_config)

t = m:section(NamedSection, "global", "global", translate("Server-Side"))
t.anonymous = true
t.addremove = false

e = t:option(Flag, "enable", translate("Enable"))
e.rmempty = false

e = t:option(Value, "start_delay", translate("Delay Start"), translate("Units:seconds"))
e.default = "90"
e.datatype = "range(0,600)"
e.rmempty = false


s_server = m:section(TypedSection, "server", translate("Servers Manager"))
s_server.anonymous = true
s_server.addremove = true
s_server.sortable = true
s_server.template = "cbi/tblsection"
s_server.extedit = api.url("server_config", "%s")
function s_server.create(self, section)
	local uid = api.gen_random_char()
	TypedSection.create(self, uid)
	luci.http.redirect(self.extedit:format(uid))
end
function s_server.remove(self, section)
	local o = m:get(section) or {}
	if o[".type"] == self.sectiontype then
		m:del(section)
	end
end

e = s_server:option(Flag, "enable", translate("Enable"))
e.width = "5%"
e.rmempty = false

e = s_server:option(DummyValue, "status", translate("Status"))
e.rawhtml = true
e.cfgvalue = function(t, n)
	return string.format('<font class="_servers_status">%s</font>', translate("Collecting data..."))
end

e = s_server:option(DummyValue, "remarks", translate("Remarks"))
e.width = "15%"

e = s_server:option(DummyValue, "type", translate("Type"))
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

e = s_server:option(DummyValue, "port", translate("Port"))

e = s_server:option(Flag, "log", translate("Log"))
e.default = "1"
e.rmempty = false

m:appendTemplate("/cbi/sortable", {sectiontype = s_server.sectiontype})

m:appendTemplate("/server/server_list_status", {sectiontype = s_server.sectiontype})

s_user = m:section(TypedSection, "user", translate("Users Manager"))
s_user.anonymous = true
s_user.addremove = true
s_user.sortable = true
s_user.template = "cbi/tblsection"
s_user.extedit = api.url("server_user_config", "%s")
s_user.create = function(e, section)
	local uid = api.gen_random_char()
	TypedSection.create(e, uid)
	luci.http.redirect(e.extedit:format(uid))
end
s_user.remove = function(self, section)
	local o = m:get(section) or {}
	if o[".type"] == self.sectiontype then
		m:foreach("server", function(o)
			if o.user and section == o.user then
				m:set(o[".name"], "user", "")
			end
			local changed = false
			local users = o.users or {}
			for i = #users, 1, -1 do
				if section == users[i] then
					table.remove(users, i)
					changed = true
				end
			end
			if changed then
				m:set(o[".name"], "users", users)
			end
		end)
		m:del(section)
		luci.http.redirect(api.url("server"))
	end
end

e = s_user:option(DummyValue, "username", translate("Username"))
e.width = "25%"

e = s_user:option(DummyValue, "password", translate("Password"))
e.width = "25%"

e = s_user:option(DummyValue, "uuid", "UUID")
e.width = "25%"

m:appendTemplate("/cbi/sortable", {sectiontype = s_user.sectiontype})

m:appendTemplate("/server/log")

return api.return_map(m)
