local api = require "luci.passwall.api"

api.set_default_cbi()

m = Map()

s = m:section(NamedSection, "@global[0]", "global", translate("ACLs"), "<font color='red'>" .. translate("ACLs is a tools which used to designate specific IP proxy mode.") .. "</font>")

o = s:option(Flag, "acl_enable", translate("Main switch"))
o.rmempty = false
o.default = false

-- [[ ACLs Settings ]]--
s = m:section(TypedSection, "acl_rule")
s.template = "cbi/tblsection"
s.sortable = true
s.anonymous = true
s.addremove = true
s.extedit = api.url("acl_config", "%s")
function s.create(e, t)
	local uid = "acl_" .. api.gen_random_char(5)
	TypedSection.create(e, uid)
	luci.http.redirect(e.extedit:format(uid))
end
function s.remove(e, t)
	api.sys.call("rm -rf /tmp/etc/passwall_tmp/dns_" .. t .. "*")
	TypedSection.remove(e, t)
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.rmempty = true

local mac_t = {}
api.sys.net.mac_hints(function(e, t)
	mac_t[e] = {
		ip = t,
		mac = e
	}
end)

i = s:option(DummyValue, "interface", translate("Source Interface"))
i.cfgvalue = function(t, n)
	local v = Value.cfgvalue(t, n) or ''
	if v == "" then
		return translate("All")
	end
	return v
end

o = s:option(DummyValue, "sources", translate("Source"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local e = ''
	local v = Value.cfgvalue(t, n) or '-'
	string.gsub(v, '[^' .. " " .. ']+', function(w)
		local a = w
		if mac_t[w] then
			a = a .. ' (' .. mac_t[w].ip .. ')'
		end
		if #e > 0 then
			e = e .. "<br />"
		end
		e = e .. a
	end)
	return e
end

i = s:option(DummyValue, "mode", translate("Mode"))
i.cfgvalue = function(t, n)
	local v = Value.cfgvalue(t, n) or '0'
	if v == "1" then
		return translate("Proxy")
	end
	return translate("No Proxy")
end

m:appendTemplate("/cbi/sortable", {sectiontype = s.sectiontype})

return api.return_map(m)
