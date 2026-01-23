local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("tuic-client") then
	return
end

local type_name = "TUIC"

-- [[ TUIC ]]

s.fields["type"]:value(type_name, "TUIC")

if s.val["type"] ~= type_name then
	return
end

local option_prefix = "tuic_"

local function _n(name)
	return option_prefix .. name
end

o = s:option(ListValue, _n("del_protocol")) --始终隐藏，用于删除 protocol
o:depends({ [_n("__hide")] = "1" })
o.rewrite_option = "protocol"

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"

o = s:option(Value, _n("uuid"), translate("ID"))
o.password = true

-- Tuic Password for remote server connect
o = s:option(Value, _n("password"), translate("TUIC User Password For Connect Remote Server"))
o.password = true
o.rmempty = true
o.default = ""
o.rewrite_option = o.option

--[[
-- Tuic username for local socks connect
o = s:option(Value, _n("socks_username"), translate("TUIC UserName For Local Socks"))
o.rmempty = true
o.default = ""
o.rewrite_option = o.option

-- Tuic Password for local socks connect
o = s:option(Value, _n("socks_password"), translate("TUIC Password For Local Socks"))
o.password = true
o.rmempty = true
o.default = ""
o.rewrite_option = o.option
--]]

o = s:option(Value, _n("ip"), translate("Set the TUIC proxy server ip address"))
o.datatype = "ipaddr"
o.rmempty = true
o.rewrite_option = o.option

o = s:option(ListValue, _n("udp_relay_mode"), translate("UDP relay mode"))
o:value("native", translate("native"))
o:value("quic", translate("QUIC"))
o.default = "native"
o.rmempty = true
o.rewrite_option = o.option

o = s:option(ListValue, _n("congestion_control"), translate("Congestion control algorithm"))
o:value("bbr", translate("BBR"))
o:value("cubic", translate("CUBIC"))
o:value("new_reno", translate("New Reno"))
o.default = "cubic"
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Value, _n("heartbeat"), translate("Heartbeat interval(second)"))
o.datatype = "uinteger"
o.default = "3"
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Value, _n("timeout"), translate("Timeout for establishing a connection to server(second)"))
o.datatype = "uinteger"
o.default = "8"
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Value, _n("gc_interval"), translate("Garbage collection interval(second)"))
o.datatype = "uinteger"
o.default = "3"
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Value, _n("gc_lifetime"), translate("Garbage collection lifetime(second)"))
o.datatype = "uinteger"
o.default = "15"
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Value, _n("send_window"), translate("TUIC send window"))
o.datatype = "uinteger"
o.default = 20971520
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Value, _n("receive_window"), translate("TUIC receive window"))
o.datatype = "uinteger"
o.default = 10485760
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Value, _n("max_package_size"), translate("TUIC Maximum packet size the socks5 server can receive from external, in bytes"))
o.datatype = "uinteger"
o.default = 1500
o.rmempty = true
o.rewrite_option = o.option

--Tuic settings for the local inbound socks5 server
o = s:option(Flag, _n("dual_stack"), translate("Set if the listening socket should be dual-stack"))
o.default = 0
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Flag, _n("disable_sni"), translate("Disable SNI"))
o.default = 0
o.rmempty = true
o.rewrite_option = o.option

o = s:option(Flag, _n("zero_rtt_handshake"), translate("Enable 0-RTT QUIC handshake"))
o.default = 0
o.rmempty = true
o.rewrite_option = o.option

o = s:option(DynamicList, _n("tls_alpn"), translate("TLS ALPN"))
o.rmempty = true
o.rewrite_option = o.option

api.luci_types(arg[1], m, s, type_name, option_prefix)
