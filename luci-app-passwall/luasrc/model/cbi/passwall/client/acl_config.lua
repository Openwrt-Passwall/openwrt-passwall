local api = require "luci.passwall.api"
local appname = "passwall"

m = Map(appname)
m.redirect = api.url("acl")
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

local fs = api.fs
local sys = api.sys
local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")
local has_gfwlist = fs.access("/usr/share/passwall/rules/gfwlist")
local has_chnlist = fs.access("/usr/share/passwall/rules/chnlist")
local has_chnroute = fs.access("/usr/share/passwall/rules/chnroute")

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

local nodes_table = {}
for _, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local normal_list = {}
for _, v in pairs(nodes_table) do
	if v.node_type == "normal" then
		normal_list[#normal_list + 1] = v
	end
end

local socks_list = {}
m.uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " " .. string.format("[%s %s]", s.port, translate("Port")),
			group = "Socks"
		}
	end
end)

local dynamicList_write = function(self, section, value)
	local t = {}
	local t2 = {}
	if type(value) == "table" then
		local x
		for _, x in ipairs(value) do
			if x and #x > 0 then
				if not t2[x] then
					t2[x] = x
					t[#t+1] = x
				end
			end
		end
	else
		t = { value }
	end
	t = table.concat(t, " ")
	return DynamicList.write(self, section, t)
end

-- [[ ACLs Settings ]]--
s = m:section(NamedSection, arg[1], translate("ACLs"), translate("ACLs"))
s.addremove = false
s.dynamic = false

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.default = arg[1]
o.rmempty = false

o = s:option(Value, "interface", translate("Source Interface"))
o:value("", translate("All"))
-- Populate with actual kernel network devices instead of UCI interface names,
-- because the backend (nftables iifname / iptables -i) matches kernel device names.
do
	local nfs = require "nixio.fs"
	local _cursor = require("luci.model.uci").cursor()
	local _sysnet = "/sys/class/net/"

	-- Map UCI interface names to their device names and vice versa
	local _iface_to_dev = {}
	local _dev_to_ifaces = {}
	local _iface_proto = {}
	_cursor:foreach("network", "interface", function(sec)
		local name = sec[".name"]
		if name ~= "loopback" then
			_iface_proto[name] = sec.proto
			if sec.device then
				_iface_to_dev[name] = sec.device
				_dev_to_ifaces[sec.device] = _dev_to_ifaces[sec.device] or {}
				table.insert(_dev_to_ifaces[sec.device], name)
			end
		end
	end)

	-- Classify device type using sysfs attributes
	local function classify_sysfs(dev)
		if nfs.stat(_sysnet .. dev .. "/bridge", "type") == "dir" then
			return translate("Bridge")
		elseif nfs.stat(_sysnet .. dev .. "/wireless", "type") == "dir" then
			return translate("Wireless Adapter")
		elseif dev:match("^tun") or dev:match("^tap") or dev:match("^wg") or dev:match("^ppp") then
			return translate("Tunnel Interface")
		else
			return translate("Ethernet Adapter")
		end
	end

	-- Classify offline UCI interfaces by config hints
	local function classify_uci(dev_name, proto)
		if dev_name and dev_name:match("^br%-") then
			return translate("Bridge")
		elseif proto == "wireguard" or proto == "pppoe" or proto == "pptp" or proto == "l2tp" then
			return translate("Tunnel Interface")
		else
			return translate("Interface")
		end
	end

	local _seen = {}
	local _devices = {}

	-- Active kernel devices from /sys/class/net/.
	-- Skip bridge member ports (/master) and DSA master devices (/dsa) because
	-- nftables iifname matches the parent bridge for routed traffic, not
	-- individual member ports. Also skip internal virtual devices.
	local _iter = nfs.dir(_sysnet)
	if _iter then
		for dev in _iter do
			if dev ~= "lo"
				and not dev:match("^veth")
				and not dev:match("^ifb")
				and not dev:match("^gre")
				and not dev:match("^sit")
				and not dev:match("^ip6tnl")
				and not dev:match("^erspan")
				and not nfs.stat(_sysnet .. dev .. "/master", "type")
				and not nfs.stat(_sysnet .. dev .. "/dsa", "type")
			then
				local dtype = classify_sysfs(dev)
				local label = dtype .. ': "' .. dev .. '"'
				if _dev_to_ifaces[dev] then
					label = label .. " (" .. table.concat(_dev_to_ifaces[dev], ", ") .. ")"
				end
				_devices[#_devices + 1] = { name = dev, label = label, sort = dtype .. ":" .. dev }
				_seen[dev] = true
			end
		end
	end

	-- UCI interfaces whose device does not currently exist (down tunnels, VPNs, etc.).
	-- Stored by UCI name since the kernel device is not available yet.
	-- Dedup by device: if two interfaces share a device, only one is shown.
	for iface, dev in pairs(_iface_to_dev) do
		if not _seen[dev] then
			local dtype = classify_uci(dev, _iface_proto[iface])
			local label = dtype .. ': "' .. iface .. '"'
			-- Sort offline entries after active devices
			_devices[#_devices + 1] = { name = iface, label = label, sort = "zzz:" .. iface }
			_seen[dev] = true
		end
	end

	table.sort(_devices, function(a, b) return a.sort < b.sort end)
	for _, d in ipairs(_devices) do
		o:value(d.name, d.label)
	end
end

o.validate = function(self, value, section)
	if value == "" or value:match("^[a-zA-Z0-9][a-zA-Z0-9%.%_%-]*$") then
		return value
	end
	return nil, translate("Invalid interface name")
end

local mac_t = {}
sys.net.mac_hints(function(e, t)
	mac_t[#mac_t + 1] = {
		ip = t,
		mac = e
	}
end)
table.sort(mac_t, function(a,b)
	if #a.ip < #b.ip then
		return true
	elseif #a.ip == #b.ip then
		if a.ip < b.ip then
			return true
		else
			return #a.ip < #b.ip
		end
	end
	return false
end)

---- Source
sources = s:option(DynamicList, "sources", translate("Source"))
sources.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("MAC") .. ": 00:00:00:FF:FF:FF"
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li><li>" .. translate("IP range") .. ": 192.168.1.100-192.168.1.200"
.. "</li><li>" .. translate("IPSet") .. ": ipset:lanlist"
.. "</li></ul>"
sources.cast = "string"
for _, key in pairs(mac_t) do
	sources:value(key.mac, "%s (%s)" % {key.mac, key.ip})
end
sources.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local value2 = {}
			string.gsub(value, '[^' .. " " .. ']+', function(w) table.insert(value2, w) end)
			value = value2
		end
	end
	return value
end
sources.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if v:find("ipset:") and v:find("ipset:") == 1 then
			local ipset = v:gsub("ipset:", "")
			if ipset and ipset ~= "" then
				flag = true
			end
		end

		if flag == false and datatypes.macaddr(v) then
			flag = true
		end

		if flag == false and datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false and api.iprange(v) then
			flag = true
		end

		if flag == false then
			err[#err + 1] = v
		end
	end

	if #err > 0 then
		self:add_error(t, "invalid", translate("Not true format, please re-enter!"))
		for _, v in ipairs(err) do
			self:add_error(t, "invalid", v)
		end
	end

	return value
end
sources.write = dynamicList_write

---- TCP No Redir Ports
local TCP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_no_redir_ports")
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate

---- UDP No Redir Ports
local UDP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_no_redir_ports")
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"),
	"<font color='red'>" .. 
		translate("Fill in the ports you don't want to be forwarded by the agent, with the highest priority.") ..
	"</font>")
o:value("", translate("Use global config") .. "(" .. UDP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate

o = s:option(DummyValue, "_hide_node_option", "")
o.template = "passwall/cbi/hidevalue"
o.value = "1"
o:depends({ tcp_no_redir_ports = "1:65535", udp_no_redir_ports = "1:65535" })
if TCP_NO_REDIR_PORTS == "1:65535" and UDP_NO_REDIR_PORTS == "1:65535" then
	o:depends({ tcp_no_redir_ports = "", udp_no_redir_ports = "" })
end

o = s:option(Flag, "use_global_config", translatef("Use global config"))
o.default = "0"
o.rmempty = false
o:depends({ _hide_node_option = "1",  ['!reverse'] = true })

o = s:option(ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
o.default = ""
o:depends({ _hide_node_option = false, use_global_config = false })
o.template = appname .. "/cbi/nodes_listvalue"
o.group = {}
o.remove = function(self, section)
	m:del(section, self.option)
	m:del(section, "udp_node")
end

o = s:option(DummyValue, "_tcp_node_bool", "")
o.template = "passwall/cbi/hidevalue"
o.value = "1"
o:depends({ tcp_node = "",  ['!reverse'] = true })

o = s:option(ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
o.default = ""
o:value("", translate("Close"))
o:value("tcp", translate("Same as the tcp node"))
o:depends({ _tcp_node_bool = "1", _node_sel_other = "1" })
o.template = appname .. "/cbi/nodes_listvalue"
o.group = {"",""}
o.remove = function(self, section)
	local v = s.fields["shunt_udp_node"]:formvalue(section)
	if not v then
		return m:del(section, self.option)
	end
end

o = s:option(ListValue, "shunt_udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
o:value("close", translate("Close"))
o:value("tcp", translate("Same as the tcp node"))
o:depends({ _tcp_node_bool = "1", _node_sel_shunt = "1" })
o.cfgvalue = function(self, section)
	local v = m:get(section, "udp_node") or ""
	if v == "" then v = "close" end
	if v ~= "close" and v ~= "tcp" then v = "tcp" end
	return v
end
o.write = function(self, section, value)
	if value == "close" then value = "" end
	return m:set(section, "udp_node", value)
end

o = s:option(DummyValue, "_udp_node_bool", "")
o.template = "passwall/cbi/hidevalue"
o.value = "1"
o:depends({ udp_node = "",  ['!reverse'] = true })
o:depends({ shunt_udp_node = "tcp" })

---- TCP Proxy Drop Ports
local TCP_PROXY_DROP_PORTS = m:get("@global_forwarding[0]", "tcp_proxy_drop_ports")
o = s:option(Value, "tcp_proxy_drop_ports", translate("TCP Proxy Drop Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_PROXY_DROP_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _tcp_node_bool = "1" })

---- UDP Proxy Drop Ports
local UDP_PROXY_DROP_PORTS = m:get("@global_forwarding[0]", "udp_proxy_drop_ports")
o = s:option(Value, "udp_proxy_drop_ports", translate("UDP Proxy Drop Ports"))
o:value("", translate("Use global config") .. "(" .. UDP_PROXY_DROP_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("443", translate("QUIC"))
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _tcp_node_bool = "1" })

---- TCP Redir Ports
local TCP_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_redir_ports")
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"), translatef("Only work with using the %s node.", "TCP"))
o:value("", translate("Use global config") .. "(" .. TCP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("80,443", "80,443")
o:value("80:65535", "80 " .. translate("or more"))
o:value("1:443", "443 " .. translate("or less"))
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _tcp_node_bool = "1" })

---- UDP Redir Ports
local UDP_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_redir_ports")
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"), translatef("Only work with using the %s node.", "UDP"))
o:value("", translate("Use global config") .. "(" .. UDP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("53", "53")
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _udp_node_bool = "1" })

o = s:option(DummyValue, "tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>',
	translate("The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000."))
end
o:depends({ use_global_config = true })
o:depends({ _tcp_node_bool = "1" })

o = s:option(Flag, "use_direct_list", translatef("Use %s", translate("Direct List")))
o.default = "1"
o:depends({ _tcp_node_bool = "1" })

o = s:option(Flag, "use_proxy_list", translatef("Use %s", translate("Proxy List")))
o.default = "1"
o:depends({ _tcp_node_bool = "1" })

o = s:option(Flag, "use_block_list", translatef("Use %s", translate("Block List")))
o.default = "1"
o:depends({ _tcp_node_bool = "1" })

if has_gfwlist then
	o = s:option(Flag, "use_gfw_list", translatef("Use %s", translate("GFW List")))
	o.default = "1"
	o:depends({ _tcp_node_bool = "1" })
end

if has_chnlist or has_chnroute then
	o = s:option(ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
	o:depends({ _tcp_node_bool = "1" })
end

o = s:option(ListValue, "tcp_proxy_mode", "TCP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ _tcp_node_bool = "1" })

o = s:option(ListValue, "udp_proxy_mode", "UDP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ _udp_node_bool = "1" })

o = s:option(DummyValue, "switch_mode", " ")
o.template = appname .. "/global/proxy"
o:depends({ _tcp_node_bool = "1" })

-- Node → DNS Depends Settings
o = s:option(DummyValue, "_node_sel_shunt", "")
o.template = appname .. "/cbi/hidevalue"
o.value = "1"
o:depends({ tcp_node = "__always__" })

o = s:option(DummyValue, "_node_sel_other", "")
o.template = appname .. "/cbi/hidevalue"
o.value = "1"
o:depends({ _node_sel_shunt = "1",  ['!reverse'] = true })

---- DNS
o = s:option(ListValue, "dns_shunt", "DNS " .. translate("Shunt"))
o.default = "chinadns-ng"
o:value("dnsmasq", "Dnsmasq")
o:value("chinadns-ng", translate("ChinaDNS-NG (recommended)"))
o:depends({ _tcp_node_bool = "1" })

o = s:option(DummyValue, "view_chinadns_log", " ")
o.template = appname .. "/acl/view_chinadns_log"

o = s:option(Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"
o:depends({ _tcp_node_bool = "1" })

---- DNS Forward Mode
o = s:option(ListValue, "dns_mode", translate("Filter Mode"))
if api.is_finded("dns2socks") then
	o:value("dns2socks", "dns2socks")
end
if has_singbox then
	o:value("sing-box", "Sing-Box")
end
if has_xray then
	o:value("xray", "Xray")
end
o:depends({ _tcp_node_bool = "1", _node_sel_other = "1" })
o.remove = function(self, section)
	local f = s.fields["tcp_node"]
	local id_val = f and f:formvalue(section) or ""
	if id_val == "" then
		return m:del(section, self.option)
	end
	for _, v in pairs(nodes_table) do
		if v.id == id_val then
			local new_val = (v.type == "Xray") and "xray" or "sing-box"
			m:set(section, self.option, new_val)

			local dns_field = s.fields[v.type == "Xray" and "xray_dns_mode" or "singbox_dns_mode"]
			local v2ray_dns_mode = dns_field and dns_field:formvalue(section)
			if v2ray_dns_mode then
				m:set(section, "v2ray_dns_mode", v2ray_dns_mode)
			end

			break
		end
	end
end

o = s:option(ListValue, "xray_dns_mode", translate("Request protocol"))
o.default = "tcp"
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("doh", "DoH")
o:depends("dns_mode", "xray")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if s.fields["dns_mode"]:formvalue(section) == "xray" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

o = s:option(ListValue, "singbox_dns_mode", translate("Request protocol"))
o.default = "tcp"
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("doh", "DoH")
o:value("http3", "HTTP3(DoH3)")
o:depends("dns_mode", "sing-box")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if s.fields["dns_mode"]:formvalue(section) == "sing-box" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

---- DNS Forward
o = s:option(Value, "remote_dns", translate("Remote DNS"))
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("149.112.112.112", "149.112.112.112 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({dns_mode = "dns2socks"})
o:depends({xray_dns_mode = "udp"})
o:depends({xray_dns_mode = "tcp"})
o:depends({singbox_dns_mode = "udp"})
o:depends({singbox_dns_mode = "tcp"})

o = s:option(Value, "remote_dns_doh", translate("Remote DNS DoH"))
o.description = translate("Format: URL[,IP] (optional IP to map the domain in the URL)")
o:value("https://1.1.1.1/dns-query", "1.1.1.1 (CloudFlare)")
o:value("https://1.1.1.2/dns-query", "1.1.1.2 (CloudFlare-Security)")
o:value("https://8.8.4.4/dns-query", "8.8.4.4 (Google)")
o:value("https://8.8.8.8/dns-query", "8.8.8.8 (Google)")
o:value("https://9.9.9.9/dns-query", "9.9.9.9 (Quad9)")
o:value("https://149.112.112.112/dns-query", "149.112.112.112 (Quad9)")
o:value("https://208.67.222.222/dns-query", "208.67.222.222 (OpenDNS)")
o:value("https://dns.adguard.com/dns-query,94.140.14.14", "94.140.14.14 (AdGuard)")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "116.202.176.26 (LibreDNS)")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "116.202.176.26 (LibreDNS-NoAds)")
o.default = o.keylist[1]
o.validate = function(self, value, t)
	if value ~= "" then
		value = api.trim(value)
		local flag = 0
		local util = require "luci.util"
		local val = util.split(value, ",")
		local url = val[1]
		val[1] = nil
		for i = 1, #val do
			local v = val[i]
			if v then
				if not api.datatypes.ipmask4(v) then
					flag = 1
				end
			end
		end
		if flag == 0 then
			return value
		end
	end
	return nil, translate("DoH request address") .. " " .. translate("Format must be:") .. " URL,IP"
end
o:depends({xray_dns_mode = "doh"})
o:depends({singbox_dns_mode = "doh"})
o:depends({singbox_dns_mode = "http3"})

o = s:option(Value, "remote_dns_client_ip", translate("EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
		translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends({dns_mode = "sing-box"})
o:depends({dns_mode = "xray"})
o:depends({_node_sel_shunt = "1"})

o = s:option(Flag, "remote_fakedns", "FakeDNS", translate("Use FakeDNS work in the domain that proxy."))
o.default = "0"
o.rmempty = false
o:depends({dns_mode = "sing-box"})
o:depends({dns_mode = "xray"})
o.validate = function(self, value, t)
	if value and value == "1" then
		local _dns_mode = s.fields["dns_mode"]:formvalue(t)
		local _tcp_node = s.fields["tcp_node"]:formvalue(t)
		if _dns_mode and _tcp_node then
			if (m:get(_tcp_node, "type") or ""):lower() ~= _dns_mode and not _tcp_node:find("Socks_") then
				return nil, translatef("TCP node must be '%s' type to use FakeDNS.", _dns_mode)
			end
		end
	end
	return value
end

o = s:option(ListValue, "chinadns_ng_default_tag", translate("Default DNS"))
o.default = "none"
o:value("gfw", translate("Remote DNS"))
o:value("chn", translate("Direct DNS"))
o:value("none", translate("Smart, Do not accept no-ip reply from Direct DNS"))
o:value("none_noip", translate("Smart, Accept no-ip reply from Direct DNS"))
local desc = "<ul>"
		.. "<li>" .. translate("When not matching any domain name list:") .. "</li>"
		.. "<li>" .. translate("Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!") .. "</li>"
		.. "<li>" .. translate("Direct DNS: Internet experience may be better, but DNS will be leaked!") .. "</li>"
o.description = desc
		.. "<li>" .. translate("Smart: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China IP, then use the direct result, otherwise use the remote result.") .. "</li>"
		.. "<li>" .. translate("In smart mode, no-ip reply from Direct DNS:") .. "</li>"
		.. "<li>" .. translate("Do not accept: Wait and use Remote DNS Reply.") .. "</li>"
		.. "<li>" .. translate("Accept: Trust the Reply, using this option can improve DNS resolution speeds for some mainland IPv4-only sites.") .. "</li>"
		.. "</ul>"
o:depends({dns_shunt = "chinadns-ng", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:option(Flag, "force_https_soa", translate("Force HTTPS SOA"), translate("Force queries with qtype 65 to respond with an SOA record."))
o.default = "0"
o.rmempty = false
o:depends({dns_shunt = "chinadns-ng"})

o = s:option(ListValue, "use_default_dns", translate("Default DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o.description = desc .. "</ul>"
o:depends({dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})

local tcp = s.fields["tcp_node"]
local udp = s.fields["udp_node"]
for k, v in pairs(socks_list) do
	tcp:value(v.id, v["remark"])
	tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	udp:value(v.id, v["remark"])
	udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end
for k, v in pairs(nodes_table) do
	if #normal_list == 0 then
		s.fields["dns_mode"]:depends({ _tcp_node_bool = "1" })
		break
	end
	if v.protocol == "_shunt" then
		if v.type == "Xray" and has_xray then
			tcp:value(v.id, v["remark"])
			tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			udp:value(v.id, v["remark"])
			udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

			s.fields["xray_dns_mode"]:depends({ _tcp_node_bool = "1", tcp_node = v.id })
			s.fields["_node_sel_shunt"]:depends({ tcp_node = v.id })
		end
		if v.type == "sing-box" and has_singbox then
			tcp:value(v.id, v["remark"])
			tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			udp:value(v.id, v["remark"])
			udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")

			s.fields["singbox_dns_mode"]:depends({ _tcp_node_bool = "1", tcp_node = v.id })
			s.fields["_node_sel_shunt"]:depends({ tcp_node = v.id })
		end
	else
		tcp:value(v.id, v["remark"])
		tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
		udp:value(v.id, v["remark"])
		udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end

return m
