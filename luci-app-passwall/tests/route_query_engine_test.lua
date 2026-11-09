local here = (arg[0]:match("^(.*)[/\\]") or ".") .. "/../luasrc/passwall/"
package.path = here .. "?.lua;" .. package.path
local M = require "route_query_engine"

local pass, fail = 0, 0
local function chk(name, got, want)
	if got == want then pass = pass + 1
	else fail = fail + 1; print("FAIL "..name..": expected="..tostring(want).." got="..tostring(got)) end
end

local g = { tcp_proxy_mode = "gfw", remote_fakedns = "1" }
local gf = { prefer_nft = "1" }
local n = { type = "sing-box", protocol = "_shunt" }
local cfg = M.build_cfg(g, gf, n)
chk("build.defaults", cfg.udp_proxy_mode, "disable")
chk("build.mode", cfg.tcp_proxy_mode, "gfw")
chk("build.fakedns", cfg.use_fakedns, "1")
chk("build.shunt", cfg.use_shunt_node, "1")
chk("build.redir", cfg.tcp_redir_ports, "1:65535")

local acl = { tcp_proxy_mode = "global", use_direct_list = "0" }
local out = M.acl_cfg(cfg, acl)
chk("acl.override.mode", out.tcp_proxy_mode, "global")
chk("acl.passthru.shunt", out.use_shunt_node, "1")
chk("acl.default.drop", out.tcp_proxy_drop_ports, "disable")
local out2 = M.acl_cfg(cfg, nil)
chk("acl.nil", out2.tcp_proxy_mode, "gfw")

chk("src.single.hit", M.ip_source_entry_match("192.168.1.5", "192.168.1.5", nil, nil), true)
chk("src.single.miss", M.ip_source_entry_match("192.168.1.5", "192.168.1.6", nil, nil), false)
local function cidr_match(ip, cidr)
	local net, bits = cidr:match("^(.-)/(%d+)$")
	if net then
		local a = ip:match("^(%d+)%.(%d+)%.(%d+).")
		local b = net:match("^(%d+)%.(%d+)%.(%d+).")
		return a == b
	end
	return ip == cidr
end
chk("src.cidr.hit", M.ip_source_entry_match("192.168.1.0/24", "192.168.1.42", nil, cidr_match), true)
chk("src.cidr.miss", M.ip_source_entry_match("10.0.0.0/8", "192.168.1.42", nil, cidr_match), false)
chk("src.range.in", M.ip_source_entry_match("192.168.1.100-192.168.1.200", "192.168.1.150", nil, nil), true)
chk("src.range.out", M.ip_source_entry_match("192.168.1.100-192.168.1.200", "192.168.1.250", nil, nil), false)
chk("src.mac.match", M.ip_source_entry_match("AA:BB:CC:DD:EE:FF", nil, "AA:BB:CC:DD:EE:FF", nil), true)
chk("src.mac.noinfo", M.ip_source_entry_match("AA:BB:CC:DD:EE:FF", "192.168.1.5", nil, nil), nil)
chk("src.ipset", M.ip_source_entry_match("ipset:lanlist", "192.168.1.5", nil, nil), nil)

print(string.format("engine-test: %d passed, %d failed", pass, fail))
return { pass = pass, fail = fail }
