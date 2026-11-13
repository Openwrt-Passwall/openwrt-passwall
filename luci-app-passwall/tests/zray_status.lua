-- Replay the router's two independent process argv values, without top truncation.
local files, config, port, custom
local api = {TMP_PATH = "/tmp/etc/passwall", fs = {}, jsonc = {}}
api.fs.readfile = function(path) return files[path] end
api.fs.dir = function()
	local i = 0
	return function() i = i + 1; if i <= 4 then return tostring(19537 + i) end end
end
api.jsonc.parse = function() return config end
api.get_cache_var = function() return port end
api.get_app_path = function() return custom or "/usr/bin/zray" end
package.loaded["luci.passwall.api"] = api
dofile("luasrc/passwall/util_zray.lua")
local zray = require "luci.passwall.util_zray"
local function argv(...) return table.concat({...}, "\0") .. "\0" end
local core = argv("/tmp/etc/passwall/bin/zray", "/tmp/etc/passwall/global_PAkmdvo1_socks.json")
local bridge = argv("/tmp/etc/passwall/bin/ipt2socks_default_TCP_UDP", "-l", "1041", "-b", "0.0.0.0", "-B", "::", "-s", "127.0.0.1", "-p", "23456", "-o", "60", "-n", "65535", "-v", "-R")
local function reset()
	files = {["/tmp/etc/passwall/global_PAkmdvo1_socks.json"] = "json", ["/proc/19538/cmdline"] = core, ["/proc/19539/cmdline"] = bridge}
	config, port, custom = {listen = "0.0.0.0:23456"}, "1041", nil
end
reset(); assert(zray.global_tcp_status("PAkmdvo1"))
files["/proc/19538/cmdline"] = nil; assert(not zray.global_tcp_status("PAkmdvo1"))
reset(); files["/proc/19539/cmdline"] = nil; assert(not zray.global_tcp_status("PAkmdvo1"))
reset(); port = "1042"; assert(not zray.global_tcp_status("PAkmdvo1"))
reset(); config.listen = "127.0.0.1:23457"; assert(not zray.global_tcp_status("PAkmdvo1"))
reset(); files["/proc/19538/cmdline"] = core:gsub("PAkmdvo1", "other_acl"); assert(not zray.global_tcp_status("PAkmdvo1"))
reset(); files["/proc/19539/cmdline"] = argv("/bin/ipt2socks", "-v"); assert(not zray.global_tcp_status("PAkmdvo1"))
reset(); custom = "/tmp/custom/zray"; files["/proc/19538/cmdline"] = argv(custom, "/tmp/etc/passwall/global_PAkmdvo1_socks.json"); assert(zray.global_tcp_status("PAkmdvo1"))
reset(); config = false; assert(not zray.global_tcp_status("PAkmdvo1"))
reset(); port = "invalid"; assert(not zray.global_tcp_status("PAkmdvo1"))
assert(not zray.global_tcp_status("../invalid"))
print("Zray TCP status: router argv, missing processes, wrong ports and ACL isolation passed")
