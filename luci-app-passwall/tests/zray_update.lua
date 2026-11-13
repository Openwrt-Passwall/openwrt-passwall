-- Execute the actual shared updater with a mocked filesystem/network/service.
local function read(path)
	local f = assert(io.open(path)); local s = f:read("*a"); f:close(); return s
end
local source = read("luasrc/passwall/api.lua")
local com = dofile("luasrc/passwall/com.lua")
local release, files, requests, commands, probe_version
local env = setmetatable({com = com, CACHE_PATH = "/cache", command_timeout = 300}, {__index = _G})
local function reset()
	files, requests, commands, probe_version = {["/usr/bin/zray"] = "old"}, {}, {}, "0.4.0"
	release = {tag_name = "v0.5.0", html_url = "https://github.com/yunnysunny/zray/releases/tag/v0.5.0", assets = {
		{name = "zray-aarch64.sha256", browser_download_url = "checksum", digest = "sha256:wrong"},
		{name = "zray-aarch64", browser_download_url = "official-binary", digest = "sha256:verified"},
		{name = "zray-x86_64", browser_download_url = "other-arch", digest = "sha256:other"}
	}}
end
env.fs = {
	access = function(path) return files[path] ~= nil end,
	stat = function(path, key) if key == "type" then return files[path] and "reg" end end,
	mkdirr = function() end,
	readfile = function(path) return files[path] end,
	writefile = function(path, content) files[path] = content end
}
env.jsonc = {parse = function(value) if value == "release" then return release elseif value == "{}" then return {} else return value end end, stringify = function(value) return value end}
env.i18n = {translate = function(s) return s end, translatef = string.format}
env.util = {shellquote = function(s) return "'" .. s .. "'" end, exec = function() return "/tmp/zray_download.test" end}
env.trim = function(s) return s:match("^%s*(.-)%s*$") end
env.clone = function(t) local n = {}; for k, v in pairs(t) do n[k] = v end; return n end
env.curl_args = {"-skfL", "--retry 3"}
env.uci_get_c = function() return "" end
env.get_app_path = function() return "/usr/bin/zray" end
env.get_app_version = function(_, file) if file then return files[file] == "new" and probe_version or "" end; return "0.4.0" end
env.auto_get_arch = function() return "aarch64" end
env.compare_versions = function(a, _, b) return a < b end
env.curl_auto = function(url, file, args)
	requests[#requests + 1] = {url = url, args = args}
	if file then files[file] = "new"; return 0, "" end
	return 0, "release"
end
env.curl_direct = env.curl_auto
env.verify_sha256 = function(file, digest) return files[file] == "new" and digest == "sha256:verified" end
env.remove = function(path) if not path:find("*", 1, true) then files[path] = nil end end
env.get_free_space = function() return 10000 end
env.get_file_space = function() return 100 end
env.get_final_dir = function() return "/usr/bin" end
env.sys = {call = function(cmd) commands[#commands + 1] = cmd; return cmd:find("pgrep", 1, true) and 0 or 0 end}
env.exec = function(cmd, args)
	if cmd == "/bin/mv" then files[args[3]], files[args[2]] = files[args[2]], nil end
	if cmd == "/bin/rm" then files[args[2]] = nil end
	return 0
end
local function actual(first, last)
	local start = assert(source:find(first, 1, true))
	local stop = assert(source:find(last, start, true))
	return source:sub(start, stop - 1)
end
local chunk = assert(loadstring(actual("local default_file_tree =", "function to_download_progress") .. actual("function to_move(app_name,file)", "function get_version()")))
setfenv(chunk, env); chunk()
assert(com.zray:get_url() == "https://api.github.com/repos/yunnysunny/zray/releases/latest")
local count = 0; for _, name in ipairs(com.order) do if name == "zray" then count = count + 1 end end
assert(count == 1 and com.zray.zipped == false)
for arch, name in pairs({aarch64 = "aarch64", rockchip = "aarch64", armv8 = "aarch64", x86_64 = "x86_64", armv7 = "arm-v7", mips = "mips-softfloat", mipsel = "mipsel-softfloat"}) do
	local pattern = string.format(com.zray.match_fmt_str, assert(com.zray.file_tree[arch]))
	assert(("zray-" .. name):match(pattern)); assert(not ("zray-" .. name .. ".sha256"):match(pattern))
end
reset()
local result = env.to_check("", "zray")
assert(result.code == 0 and result.has_update and result.data.browser_download_url == "official-binary")
assert(requests[1].url == com.zray:get_url() and not requests[1].args[1]:find("k", 1, true))
assert(env.to_check("mips64", "zray").code == 1)
assert(env.to_download("zray", "unverified-url", 100, "test").code == 1)
result = env.to_download("zray", "official-binary", 100, "test")
assert(result.code == 0 and result.zip == false and result.file == "/tmp/zray_download.test")
assert(not requests[#requests].args[1]:find("k", 1, true))
result = env.to_move("zray", result.file)
assert(result.code == 0 and files["/usr/bin/zray"] == "new")
assert(commands[2] == "/etc/init.d/passwall stop" and commands[3]:find("restart", 1, true))
reset(); env.to_check("aarch64", "zray")
local original_verify = env.verify_sha256; env.verify_sha256 = function() return false end
assert(env.to_download("zray", "official-binary", 100, "test").code == 1)
assert(files["/usr/bin/zray"] == "old" and not files["/tmp/zray_download.test"])
env.verify_sha256 = original_verify
files["/tmp/zray_download.invalid"] = "new"; probe_version = ""
assert(env.to_move("zray", "/tmp/zray_download.invalid").code == 1)
assert(files["/usr/bin/zray"] == "old" and #commands == 0)
release = {}; assert(env.to_check("aarch64", "zray").code == 1)
print("Zray updater: official source, exact architectures, checksum rejection, shared download/install/restart passed")

-- Regression: exec_call merges a shell's stderr into the version output.
local exit_code, output = 0, "0.4.0\n"
package.loaded["luci.passwall.api"] = {
	util = env.util,
	exec_call = function() return exit_code, output end
}
dofile("luasrc/passwall/util_zray_update.lua")
local updater = require "luci.passwall.util_zray_update"
assert(updater.version("/usr/bin/zray") == "0.4.0")
output = "sleep: invalid number '0.1'\n0.4.0\n"
assert(updater.version("/usr/bin/zray") == "0.4.0")
output = "shell warning\r\n0.4.1-dev\r\ncleanup warning\n"
assert(updater.version("/usr/bin/zray") == "0.4.1-dev")
output = "sleep: invalid number '0.1'\n"
assert(updater.version("/usr/bin/zray") == "")
exit_code, output = 1, "0.4.0\n"
assert(updater.version("/usr/bin/zray") == "")
print("Zray version parser: mixed stderr, CRLF and failed probes passed")
