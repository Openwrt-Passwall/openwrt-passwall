local here = (arg[0]:match("^(.*)[/\\]") or ".") .. "/../luasrc/passwall/"
package.path = here .. "?.lua;" .. package.path
local M = require "route_query_engine"

local fs_mem = {}
local exec_calls = 0
local api = {
	appname = "passwall",
	CACHE_PATH = "/tmp/engtest_cache",
	fs = {
		access = function(p) return fs_mem[p] ~= nil end,
		readfile = function(p) return fs_mem[p] end,
		writefile = function(p, c) fs_mem[p] = c return true end,
	},
	sys = { exec = function() exec_calls = exec_calls + 1; return "" end, call = function() return 0 end },
}
local env = { api = api, exec = function(c) exec_calls = exec_calls + 1 return "" end }
local gf = { prefer_nft = "1" }

local pass, fail = 0, 0
local function chk(n, g, w) if g == w then pass = pass + 1 else fail = fail + 1; print("FAIL "..n..": "..tostring(g).." != "..tostring(w)) end end

local b1 = M.detect_backend(env, gf)
chk("b1.val", b1, "ipset")   -- all execs empty => has_fw4 false => ipset
local calls1 = exec_calls
chk("b1.calls", calls1, 5)   -- first probe: 5 execs

local b2 = M.detect_backend(env, gf)
chk("b2.val", b2, "ipset")
chk("b2.calls.noexec", exec_calls, calls1)  -- cached: no new exec

-- TTL expiry: rewrite cache with old timestamp -> reprobe
fs_mem[M.backend_cache_key(env)] = (os.time() - 320) .. " ipset\n"
local b3 = M.detect_backend(env, gf)
chk("b3.calls.reprobe", exec_calls, calls1 + 5)

print(string.format("backend-test: %d passed, %d failed", pass, fail))
return { pass = pass, fail = fail }
