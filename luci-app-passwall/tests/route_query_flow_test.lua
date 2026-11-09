local here = (arg[0]:match("^(.*)[/\\]") or ".") .. "/../luasrc/passwall/"
package.path = here .. "?.lua;" .. here .. "/../?.lua;" .. package.path
local M = require "route_query_engine"
local rm = require "route_match"

local fs_mem = {}
local basic_uci = {}
basic_uci["@global[0]"] = { node = "node1", tcp_proxy_mode = "gfw", remote_fakedns = "0" }
basic_uci["@global_forwarding[0]"] = { prefer_nft = "1" }
basic_uci["node1"] = { ["type"] = "sing-box", protocol = "vmess", remarks = "SG1" }
basic_uci["acl1"] = { enabled = "1", remarks = "LAN", sources = { "192.168.1.100-192.168.1.200" }, tcp_proxy_mode = "global" }

local api = {
	appname = "passwall",
	CACHE_PATH = "/tmp/engtest_cache",
	fs = {
		access = function(p) return fs_mem[p] ~= nil end,
		readfile = function(p) return fs_mem[p] end,
		writefile = function(p, c) fs_mem[p] = c return true end,
		stat = function(p)
			if fs_mem[p] then return { dev = 1, ino = 2, size = #fs_mem[p], mtime = 3, ctime = 4 } end
		end,
	},
	sys = {
		exec = function() return "" end,
		call = function() return 0 end,
	},
	uci_get_c = function(sec)
		return basic_uci[sec]
	end,
	uci_foreach_c = function(stype, fn)
		for k, s in pairs(basic_uci) do
			if k:match("^acl") then s[".name"] = k; fn(s) end
		end
	end,
	is_json = function(s) return s and s:sub(1,1) == "{" end,
	jsonc = { parse = function(s) return { route = { final = "proxy", rules = {} } } end },
	trim = function(s) return (s and s:gsub("^%s+",""):gsub("%s+$","")) or "" end,
	datatypes = { port = function(v) local n = tonumber(v) return v ~= "" and n ~= nil and n >= 1 and n <= 65535 end },
	resolve_domain = function() return { "142.250.72.14" }, nil end,
	get_node_remarks = function(n) return (n.type or "") .. ":" .. (n.remarks or "") end,
	finded_com = function() return "/usr/bin/sing-box" end,
}

fs_mem["/tmp/etc/passwall/acl/default/global.json"] = '{"route":{"final":"proxy","rules":[]}}'
for _, p in ipairs({"/etc/passwall/rules/block_host","/etc/passwall/rules/direct_host","/etc/passwall/rules/proxy_host","/usr/share/passwall/rules/gfwlist","/usr/share/passwall/rules/chnlist"}) do
	fs_mem[p] = "# empty\n"
end

local env = { api = api, rm = rm, util = { shellquote = rm.shell_quote }, i18n = { translate = function(s) return s end } }

local pass, fail = 0, 0
local function chk(name, got, want)
	if got == want then pass = pass + 1
	else fail = fail + 1; print("FAIL "..name..": expected="..tostring(want).." got="..tostring(got)) end
end

local r = M.query({ target = "", port = "", proto = "tcp", src = "" }, env)
chk("q.empty", r.code, 0)

r = M.query({ target = "abc", port = "999999", proto = "tcp" }, env)
chk("q.invalidport", r.code, 0)

r = M.query({ target = "www.google.com", port = "443", proto = "tcp" }, env)
chk("q.ok", r.code, 1)
chk("q.type", r.type, "domain")
chk("q.system", type(r.system), "table")
chk("q.resolved", type(r.system.resolved), "table")
chk("q.agg.decision", r.system.decision, "direct")
chk("q.agg.matched", r.system.matched, nil)
chk("q.agg.note", r.system.note, "按解析 IP 判定")
chk("q.client.core", r.client.core, "sing-box")
chk("q.node_remarks", r.node_remarks, "sing-box:SG1")
chk("q.elapsed", type(r.elapsed), "number")

r = M.query({ target = "www.google.com", port = "443", proto = "tcp", src = "192.168.1.150" }, env)
chk("acl.match", r.acl and r.acl.matched, true)
chk("acl.name", r.acl and r.acl.name, "LAN")
chk("acl.system", type(r.acl and r.acl.system), "table")
chk("acl.client", type(r.acl and r.acl.client), "table")

r = M.query({ target = "www.google.com", port = "443", proto = "tcp", src = "10.0.0.9" }, env)
chk("acl.nomatch", r.acl and r.acl.matched, false)

r = M.query({ target = "www.google.com", port = "443", proto = "tcp", src = "not-an-ip" }, env)
chk("acl.invalidsrc", r.code, 0)

local rqrule_files = 0
for k in pairs(fs_mem) do
	if k:find("rqrule_", 1, true) then rqrule_files = rqrule_files + 1 end
end
chk("no.rqrule.leak", rqrule_files, 0)

print(string.format("query-test: %d passed, %d failed", pass, fail))
return { pass = pass, fail = fail }
