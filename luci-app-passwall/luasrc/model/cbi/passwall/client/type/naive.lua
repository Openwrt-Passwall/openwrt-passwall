local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("naive") then
	return
end

local type_name = "Naiveproxy"

-- [[ Naive ]]

s.fields["type"]:value(type_name, "NaiveProxy")

if s.val["type"] ~= type_name then
	return
end

local option_prefix = "naive_"

local function _n(name)
	return option_prefix .. name
end

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
o:value("https", translate("HTTPS"))
o:value("quic", translate("QUIC"))

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"

o = s:option(Value, _n("username"), translate("Username"))

o = s:option(Value, _n("password"), translate("Password"))
o.password = true

api.luci_types(arg[1], m, s, type_name, option_prefix)
