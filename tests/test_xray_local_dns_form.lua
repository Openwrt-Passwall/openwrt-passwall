-- Run from the repository root with Lua 5.1:
--   lua tests/test_xray_local_dns_form.lua
-- Loads the complete global CBI model and its real shunt-options include.
-- Exercises the real passthrough validate callback, not browser or CBI parsing.
-- Stored UCI values remain separate from the submitted HTTP form throughout.

local root = "luci-app-passwall/luasrc/model/cbi/passwall/client/"
local global_section = "@global[0]"
local function cbid(section, option)
	return "cbid.passwall." .. section .. "." .. option
end

local function fixture(old_default, new_default, old_fake, new_fake, controls)
	local function forbidden() error("unexpected external operation or UCI write", 2) end
	local stored = {
		[global_section] = {node = "shunt"},
		shunt = {
			[".name"] = "shunt", type = "Xray", protocol = "_shunt",
			default_node = old_default, fakedns = old_fake
		}
	}
	local post = {node_save_before = "shunt"}
	for option, value in pairs({
		node = "shunt", dns_shunt = "dnsmasq", direct_dns_mode = "tcp", xray_dns_mode = "tcp",
		fakedns = new_fake, direct_dns = "127.0.0.1:5533", remote_dns = "127.0.0.1:5533"
	}) do post[cbid(global_section, option)] = value end
	for key, value in pairs(controls or {}) do post[key] = value end
	local node_list = {
		normal_list = {{id = "exit", remark = "Synthetic exit"}},
		shunt_list = {{id = "shunt", remark = "Synthetic shunt"}}
	}
	local api = {
		c_config = "passwall", datatypes = {},
		fs = {access = function() return false end},
		i18n = {translate = function(value) return value end},
		jsonc = {stringify = function() return "[]" end},
		set_default_cbi = function() end,
		finded_com = function(name) return name == "xray" end,
		is_finded = function() return false end,
		get_valid_nodes = function() return {
			{id = "shunt", remark = "Synthetic shunt", type = "Xray", protocol = "_shunt"},
			{id = "exit", remark = "Synthetic exit", node_type = "normal", type = "Xray", protocol = "socks"}
		} end,
		get_node_list = function() return node_list end,
		get_app_version = function() return "26.9.9" end,
		compare_versions = function(left, operator, right)
			assert(left == "26.9.9" and operator == "<" and right == "26.4.25")
			return false
		end,
		url = function() return "/unused" end,
		return_map = function(map) return map end
	}
	local map = {config = "passwall", children = {}, api = api, set = forbidden, del = forbidden}
	function map:get(section, option)
		local values = stored[section]
		return option and values and values[option] or (not option and values or nil)
	end
	function map:formvalue(key) return post[key] end
	function map:foreach(kind, callback)
		if kind == "shunt_rules" then
			callback({[".name"] = "allow", remarks = "Synthetic allow"})
		else
			assert(kind == "socks", "unexpected UCI enumeration: " .. tostring(kind))
		end
	end
	function map:template_path(path) return "passwall" .. path end
	function map:appendTemplate() end
	local classes = {}
	for _, name in ipairs({"NamedSection", "TypedSection", "Table", "Flag", "ListValue", "Value", "DummyValue", "HideValue", "DynamicList"}) do
		classes[name] = {}
	end
	function map:section(class, section, sectiontype)
		local result = {map = self, config = self.config, fields = {}, children = {}, tabs = {}, tab_names = {}}
		result.section = class ~= classes.Table and section or nil
		result.data = class == classes.Table and section or nil
		result.sectiontype = sectiontype
		function result:tab(name, title)
			self.tab_names[#self.tab_names + 1] = name
			self.tabs[name] = {title = title, childs = {}}
		end
		function result:option(field_class, option)
			local field = {section = self, map = map, config = self.config, option = option, deps = {}, keylist = {}, vallist = {}}
			if field_class == classes.Flag then field.enabled, field.disabled = "1", "0" end
			function field:value(key, label)
				self.keylist[#self.keylist + 1] = key
				self.vallist[#self.vallist + 1] = label or key
			end
			function field:depends(dependency, value)
				self.deps[#self.deps + 1] = type(dependency) == "table" and dependency or {[dependency] = value}
			end
			function field:formvalue(row) return post[cbid(row, self.option)] end
			self.fields[option] = field
			self.children[#self.children + 1] = field
			return field
		end
		function result:taboption(tab, ...) return self:option(...) end
		self.children[#self.children + 1] = result
		return result
	end
	local environment = setmetatable({
		Map = function() return map end,
		translate = function(value) return value end,
		translatef = string.format,
		luci = {http = {formvalue = function(key) return post[key] end}},
		io = {popen = function(command) assert(command == "lsmod"); return nil end},
		os = setmetatable({}, {__index = function() return forbidden end}),
		require = function(name) assert(name == "luci.passwall.api"); return api end,
		loadfile = function(path)
			assert(path == "/usr/lib/lua/luci/model/cbi/passwall/client/include/shunt_options.lua")
			return loadfile(root .. "include/shunt_options.lua")
		end
	}, {__index = _G})
	for name, class in pairs(classes) do environment[name] = class end
	setfenv(assert(loadfile(root .. "global.lua")), environment)()
	local global, default_field, default_row
	for _, section in ipairs(map.children) do
		if section.section == global_section then global = section end
		for row, values in pairs(section.data or {}) do
			if values._node_option == "default_node" then default_field, default_row = section.fields._node, row end
		end
	end
	assert(global and default_field and default_row, "model did not create the expected global and shunt fields")
	post[cbid(default_row, default_field.option)] = new_default
	local option = assert(global.fields.local_dns_passthrough)
	return {
		validate = function(value)
			local result, message = option:validate(value, global_section)
			assert(map:get("shunt", "default_node") == old_default, "validation overwrote stored default_node")
			assert(map:get("shunt", "fakedns") == old_fake, "validation overwrote stored fakedns")
			return result, message
		end,
		forbid_reads = function()
			map.get, map.formvalue, api.get_app_version = forbidden, forbidden, forbidden
			for _, section in ipairs(map.children) do
				for _, field in pairs(section.fields) do field.formvalue = forbidden end
			end
		end,
		option = option
	}
end

local passed, failed = 0, 0
local function test(name, run)
	local ok, failure = pcall(run)
	if ok then
		passed = passed + 1
		io.stdout:write("PASS " .. name .. "\n")
	else
		failed = failed + 1
		io.stderr:write("FAIL " .. name .. ": " .. tostring(failure) .. "\n")
	end
end
local function rejected(form)
	local value, message = form.validate("1")
	assert(value == nil, "incompatible submitted shunt settings were accepted")
	assert(message and message:find("passthrough", 1, true), "missing passthrough validation error")
end
local function allowed(form)
	local value, message = form.validate("1")
	assert(value == "1", "valid submitted shunt settings were rejected: " .. tostring(message))
end

test("same-submit default Direct to Blackhole is rejected", function()
	rejected(fixture("_direct", "_blackhole", "0", nil))
end)
test("same-submit default Blackhole to Direct is allowed", function()
	allowed(fixture("_blackhole", "_direct", "0", nil))
end)
test("same-submit disabling shunt FakeDNS is allowed", function()
	allowed(fixture("_direct", "_direct", "1", nil))
end)
test("same-submit enabling shunt FakeDNS is rejected", function()
	rejected(fixture("_direct", "_direct", "0", "1"))
end)
for _, skipped in ipairs({
	{name = "loading shunt options", controls = {load_shunt = "1"}},
	{name = "switching the selected node", controls = {node_save_before = "previous"}}
}) do
	test(skipped.name .. " ignores unwritten incompatible form settings", function()
		allowed(fixture("_direct", "_blackhole", "0", "1", skipped.controls))
	end)
	test(skipped.name .. " retains incompatible stored settings", function()
		rejected(fixture("_blackhole", "_direct", "1", nil, skipped.controls))
	end)
end
test("disabling passthrough skips incompatible-field validation", function()
	local form = fixture("_blackhole", "_blackhole", "1", "1")
	form.forbid_reads()
	assert(form.option:validate("0", global_section) == "0")
end)

io.stdout:write(string.format("%d passed, %d failed\n", passed, failed))
if failed > 0 then os.exit(1) end
