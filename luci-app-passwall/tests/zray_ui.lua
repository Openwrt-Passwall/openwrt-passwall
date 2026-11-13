-- Exercise the node model with the real Passwall field-prefix and UCI helpers.
-- Run from luci-app-passwall: lua tests/zray_ui.lua
local function read(path)
	local file = assert(io.open(path))
	local contents = file:read("*a")
	file:close()
	return contents
end

local stored, posted = {}, {}
local m = {config = "passwall"}
function m:get(_, key) return stored[key] end
function m:set(_, key, value) stored[key] = value end
function m:del(_, key) stored[key] = nil end

local function section()
	local s = {map = m, fields = {}, children = {}, sectiontype = "nodes", section = "test"}
	function s:append(option) self.children[#self.children + 1] = option end
	function s:tab(name, title, description)
		self.tabs = self.tabs or {}
		self.tabs[name] = {childs = {}, title = title, description = description}
	end
	return s
end

local function field(map, _, name, title, description)
	local f = {map = map, option = name, title = title, description = description, deps = {}, choices = {}}
	function f:value(value) self.choices[#self.choices + 1] = value end
	function f:depends(value) self.deps[#self.deps + 1] = value end
	function f:formvalue() return posted[self.option] end
	return f
end
local Value = setmetatable({}, {__call = function(_, ...) return field(...) end})
function Value.validate(self, value)
	local min, max = self.datatype:match("range%((%d+),(%d+)%)")
	local n = tonumber(value)
	if n and n % 1 == 0 and n >= tonumber(min) and n <= tonumber(max) then return value end
end

local api = {
	finded_com = function() return true end,
	uci_get_c = function() return stored end,
	jsonc = {stringify = function(value) return value end},
	datatypes = {
		ipaddr = function(value) return value == "223.5.5.5" end,
		ip4addr = function(value) return value == "223.5.5.5" end,
		ip6addr = function(value) return value == "::1" end
	}
}
package.loaded["luci.passwall.api"] = api
package.loaded["luci.cbi"] = {}
local source = read("luasrc/passwall/api.lua")
local helpers = assert(source:match("(function set_type_cbi%(s%).-)\nfunction return_map"))
local env = setmetatable({util = {instanceof = function() return false end}}, {__index = _G})
local load_helpers = assert(loadstring(helpers))
setfenv(load_helpers, env)()
api.set_type_cbi, api.type_cbi_section = env.set_type_cbi, env.type_cbi_section

dofile("luasrc/passwall/util_zray.lua")
local zray = require "luci.passwall.util_zray"
local s1 = section()
s1.val = {type = "Zray"}
local kind = field(nil, nil, "type")
function kind:formvalue() return "Zray" end
s1.fields.type = kind
s1:append(kind)
local model_env = setmetatable({
	api = api, arg = {"test"}, Value = Value, ListValue = field, Flag = field,
	NamedSection = section, translate = function(value) return value end
}, {__index = _G})
local model = assert(loadfile("luasrc/model/cbi/passwall/client/type/7_zray.lua"))
setfenv(model, model_env)(m, s1)

local advanced = s1.tabs.advanced.childs
assert(#advanced == 12, "missing advanced controls")
assert(s1.tabs.basic.childs[1] == kind, "node type must stay accessible")
local seen = {}
for tab, data in pairs(s1.tabs) do
	for _, option in ipairs(data.childs) do
		assert(not seen[option], "field is in multiple tabs")
		seen[option] = true
		assert((tab == "advanced") == (option.zray_advanced == true))
	end
end
for _, option in ipairs(s1.children) do assert(seen[option], "field lost from both tabs") end

local values = {
	workers = "4", max_connections = "64", handshake_timeout_s = "20", connect_timeout_s = "8",
	idle_timeout_s = "900", sock_buf = "65536", stats_interval_s = "0",
	bootstrap_dns = "223.5.5.5:53", crypto_backend = "afalg", crypto_async = "0",
	crypto_min_bytes = "8192", crypto_max_bytes = "16384"
}
for _, option in ipairs(advanced) do
	local name = option.config_option
	assert(option.rewrite_option == "zray_" .. name)
	option:write("test", values[name])
	assert(option:cfgvalue("test") == values[name], "saved value not restored: " .. name)
	posted[option.option] = values[name]
end
local runtime = assert(zray.runtime_config(stored))
assert(runtime.workers == 4 and runtime.crypto_async == false and runtime.crypto_backend == "afalg")
assert(runtime.crypto_min_bytes == 8192 and runtime.crypto_max_bytes == 16384)

local min, max = s1.fields.zray_crypto_min_bytes, s1.fields.zray_crypto_max_bytes
assert(min:validate("8192", "test") and max:validate("16384", "test"))
posted[min.option], posted[max.option] = "16384", "8192"
assert(not min:validate("16384", "test") and not max:validate("8192", "test"))
posted[min.option], posted[max.option] = "1.5", "32768"
assert(not min:validate("1.5", "test"))
local dns = s1.fields.zray_bootstrap_dns
assert(dns:validate("223.5.5.5:53") and dns:validate(""))
assert(not dns:validate("dns.example.com"))
print("Zray node UI tabs, UCI save/restore, runtime conversion and validation checks passed")
