-- Run from the repository root with Lua 5.1:
--   lua tests/test_xray_local_dns.lua
-- Exercises the public gen_config(var) boundary with synthetic UCI records.
-- No router, DNS server, LuCI installation, credentials or subprocesses needed.

local source = "luci-app-passwall/luasrc/passwall/util_xray.lua"
local function copy(value)
	if type(value) ~= "table" then return value end
	local result = {}
	for key, item in pairs(value) do result[key] = copy(item) end
	return result
end

local function equal(actual, expected, path)
	path = path or "config"
	assert(type(actual) == type(expected), path .. ": type differs")
	if type(expected) ~= "table" then
		assert(actual == expected, path .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual))
		return
	end
	for key, value in pairs(expected) do equal(actual[key], value, path .. "." .. tostring(key)) end
	for key in pairs(actual) do assert(expected[key] ~= nil, path .. ": unexpected key " .. tostring(key)) end
end

local function fixture()
	return {
		version = "26.9.9",
		sections = {
			["@global[0]"] = {node = "shunt", chn_list = "direct"},
			["@global_xray[0]"] = {},
			["@global_rules[0]"] = {},
			shunt = {
				[".name"] = "shunt", [".type"] = "nodes", type = "Xray", protocol = "_shunt",
				shunt_group = "test", default_node = "_direct", allow = "_direct", block = "_blackhole"
			}
		},
		rules = {
			{[".name"] = "allow", remarks = "Allow narrow match", group = "test", domain_list = "full:allowed.example.test"},
			{[".name"] = "block", remarks = "Block broader match", group = "test", domain_list = "domain:example.test"}
		},
		var = {
			flag = "global", node = "shunt", no_run = true, dns_listen_port = "15353",
			direct_dns_tcp_server = "127.0.0.1", direct_dns_port = "5533", direct_dns_query_strategy = "UseIP",
			remote_dns_tcp_server = "127.0.0.1", remote_dns_tcp_port = "5533", remote_dns_query_strategy = "UseIP"
		}
	}
end

local function generate(input)
	local data = copy(input)
	local function forbidden() error("unexpected external operation", 2) end
	local api = {
		c_config = "passwall", TMP_PATH = "/unused", TMP_IFACE_PATH = "/unused",
		clone = copy,
		trim = function(value) return (value or ""):match("^%s*(.-)%s*$") end,
		get_app_version = function(name) assert(name == "xray"); return data.version end,
		uci_get_c = function(section, option)
			local value = data.sections[section]
			return copy(option and value and value[option] or (not option and value or nil))
		end,
		uci_foreach_c = function(kind, callback)
			assert(kind == "shunt_rules", "unexpected UCI enumeration: " .. tostring(kind))
			for _, rule in ipairs(data.rules) do callback(copy(rule)) end
		end,
		is_ipv6 = function(value) return value and value:find(":", 1, true) ~= nil end,
		get_ipv6_full = function(value) return value:match("^%[") and value or "[" .. value .. "]" end,
		get_ipv6_only = function(value) return value:match("^%[(.-)%]$") or value end,
		is_local_ip = function(value) return value:find("127.0.0.1", 1, true) or value:find("::1", 1, true) end,
		vps_domain_exclude = function() return false end,
		split = function(value, separator)
			local items = {}
			for item in value:gmatch("[^" .. separator .. "]+") do items[#items + 1] = item end
			return items
		end,
		gen_random_char = function() return "fixture" end,
		datatypes = {hostname = function(value) return value and value:find("%a") ~= nil end},
		fs = setmetatable({}, {__index = function() return forbidden end}),
		sys = {
			call = forbidden,
			exec = function(command)
				assert(command:match("^uci show passwall | sed %-n "), "unexpected shell read")
				return data.node_domains or ""
			end
		},
		-- This boundary substitutes serialization only; generation remains real.
		jsonc = {stringify = function(config) return copy(config) end}
	}
	api.cleanEmptyTables = function(value)
		if type(value) ~= "table" then return nil end
		for key, item in pairs(value) do
			if type(item) == "table" then value[key] = api.cleanEmptyTables(item) end
		end
		return next(value) and value or nil
	end
	api.compare_versions = function(left, operator, right)
		local a, b = {}, {}
		for n in left:gmatch("%d+") do a[#a + 1] = tonumber(n) end
		for n in right:gmatch("%d+") do b[#b + 1] = tonumber(n) end
		local order = 0
		for index = 1, math.max(#a, #b) do
			if (a[index] or 0) ~= (b[index] or 0) then order = (a[index] or 0) < (b[index] or 0) and -1 or 1; break end
		end
		if operator == "<" then return order < 0 end
		if operator == ">" then return order > 0 end
		if operator == ">=" then return order >= 0 end
		if operator == "<=" then return order <= 0 end
		if operator == "==" or operator == "=" then return order == 0 end
		error("unsupported comparison operator")
	end
	local environment = setmetatable({arg = {}, module = function() end}, {__index = _G})
	environment._G = environment
	environment.require = function(name)
		assert(name == "luci.passwall.api", "unexpected module: " .. name)
		return api
	end
	environment.io = setmetatable({}, {__index = function() return forbidden end})
	environment.os = setmetatable({}, {__index = function() return forbidden end})
	-- A fresh module environment also isolates the generator's DNS bookkeeping.
	setfenv(assert(loadfile(source)), environment)()
	return environment.gen_config(data.var)
end

local function outbound(config, tag)
	local found
	for _, value in ipairs(config.outbounds or {}) do
		if value.tag == tag then assert(not found, "duplicate outbound " .. tag); found = value end
	end
	return assert(found, "missing outbound " .. tag)
end

local passed = 0
local function test(name, run)
	local ok, failure = pcall(run)
	if not ok then io.stderr:write("FAIL " .. name .. ": " .. tostring(failure) .. "\n"); os.exit(1) end
	passed = passed + 1
	io.stdout:write("PASS " .. name .. "\n")
end

test("explicit zero preserves the entire default configuration", function()
	local data = fixture()
	local expected = generate(data)
	data.var.local_dns_passthrough = "0"
	equal(generate(data), expected)
	equal(outbound(expected, "dns-out").settings.rules, {
		{action = "hijack", qType = "1,28", domain = {"full:allowed.example.test"}},
		{action = "return", rCode = 0, domain = {"domain:example.test"}},
		{action = "hijack", qType = "1,28"},
		{action = "direct"}
	})
end)

test("explicit passthrough keeps the configured local DNS endpoint", function()
	local data = fixture()
	data.var.local_dns_passthrough = "1"
	local dns = outbound(generate(data), "dns-out")
	equal(dns.settings.address, "127.0.0.1", "dns-out address")
	equal(dns.settings.port, 5533, "dns-out port")
	equal(dns.settings.network, "tcp", "dns-out network")
	equal(dns.streamSettings.sockopt.dialerProxy, "direct", "dns-out transport")
end)

test("passthrough changes only the approved client DNS fields", function()
	local data = fixture()
	local expected = generate(data)
	local dns = outbound(expected, "dns-out")
	dns.settings.address, dns.settings.port, dns.settings.network = "127.0.0.1", 5533, "tcp"
	dns.streamSettings.sockopt.dialerProxy = "direct"
	dns.settings.rules = {
		{action = "direct", qType = "1,28", domain = {"full:allowed.example.test"}},
		{action = "return", rCode = 0, domain = {"domain:example.test"}},
		{action = "direct", qType = "1,28"},
		{action = "direct"}
	}
	data.var.local_dns_passthrough = "1"
	equal(generate(data), expected)
end)

-- Interpret the public rule format for these literal fixture domains. This is
-- independent of the generator and makes overlapping allow/block behavior clear.
local function action_for(rules, domain, qtype)
	for _, rule in ipairs(rules) do
		local type_matches = not rule.qType
		for value in (rule.qType or ""):gmatch("[^,]+") do
			if tonumber(value) == qtype then type_matches = true end
		end
		local domain_matches = not rule.domain
		for _, matcher in ipairs(rule.domain or {}) do
			local kind, value = matcher:match("^(%a+):(.*)$")
			if kind == "full" and domain == value then domain_matches = true end
			if kind == "domain" and (domain == value or domain:sub(-#value - 1) == "." .. value) then domain_matches = true end
		end
		if type_matches and domain_matches then return rule.action end
	end
	error("no matching DNS rule")
end

test("overlapping blackhole rules retain their record-type precedence", function()
	local data = fixture()
	data.var.local_dns_passthrough = "1"
	local rules = outbound(generate(data), "dns-out").settings.rules
	for _, qtype in ipairs({1, 28}) do
		equal(action_for(rules, "allowed.example.test", qtype), "direct")
		equal(action_for(rules, "blocked.example.test", qtype), "return")
	end
	for _, qtype in ipairs({5, 15, 16, 65}) do
		-- Do not remove qType from the preceding allow rule: it would unblock these.
		equal(action_for(rules, "allowed.example.test", qtype), "return")
		equal(action_for(rules, "elsewhere.invalid", qtype), "direct")
	end
end)

for _, port in ipairs({1053, 5335, 65535}) do
	test("loopback port " .. port .. " is not hardcoded", function()
		local data = fixture()
		data.var.local_dns_passthrough = "1"
		data.var.direct_dns_port, data.var.remote_dns_tcp_port = tostring(port), tostring(port)
		equal(outbound(generate(data), "dns-out").settings.port, port)
	end)
end

for _, addresses in ipairs({{"::1", "::1"}, {"[::1]", "::1"}, {"0:0:0:0:0:0:0:1", "::1"}}) do
	test("IPv6 loopback normalization " .. addresses[1] .. " / " .. addresses[2], function()
		local data = fixture()
		data.var.local_dns_passthrough = "1"
		data.var.direct_dns_tcp_server, data.var.remote_dns_tcp_server = addresses[1], addresses[2]
		local settings = outbound(generate(data), "dns-out").settings
		equal(settings.address, "::1")
		equal(settings.port, 5533)
	end)
end

test("the direct query strategy may use its existing UseIP default", function()
	local data = fixture()
	data.var.local_dns_passthrough, data.var.direct_dns_query_strategy = "1", nil
	equal(outbound(generate(data), "dns-out").settings.address, "127.0.0.1")
end)

test("the oldest supported core accepts explicit passthrough", function()
	local data = fixture()
	data.version, data.var.local_dns_passthrough = "26.4.25", "1"
	equal(outbound(generate(data), "dns-out").settings.address, "127.0.0.1")
end)

local function reject(name, change)
	test("rejects " .. name, function()
		local data = fixture()
		data.var.local_dns_passthrough = "1"
		change(data)
		local ok, failure = pcall(generate, data)
		assert(not ok, "unsupported passthrough configuration was silently accepted")
		assert(tostring(failure):lower():find("passthrough", 1, true), "unrelated failure: " .. tostring(failure))
	end)
end

reject("an ACL instance", function(data) data.var.flag = "acl_test" end)
reject("a SOCKS instance", function(data) data.var.flag = "url_test_synthetic" end)
reject("a missing global instance flag", function(data) data.var.flag = nil end)
reject("a non-Xray shunt", function(data) data.sections.shunt.type = "sing-box" end)
reject("a non-shunt node", function(data) data.sections.shunt.protocol = "socks" end)
reject("a missing selected node", function(data) data.var.node = nil end)
reject("a missing DNS listener", function(data) data.var.dns_listen_port = nil end)
reject("a default blackhole", function(data) data.sections.shunt.default_node = "_blackhole" end)
reject("different loopback addresses", function(data) data.var.remote_dns_tcp_server = "::1" end)
reject("different endpoint ports", function(data) data.var.remote_dns_tcp_port = "5534" end)
reject("direct UDP DNS", function(data) data.var.direct_dns_udp_server = "127.0.0.1" end)
reject("remote UDP DNS", function(data) data.var.remote_dns_udp_server, data.var.remote_dns_udp_port = "127.0.0.1", "5533" end)
reject("remote DoH DNS", function(data) data.var.remote_dns_doh = "https://resolver.invalid/dns-query" end)
reject("a missing direct TCP endpoint", function(data) data.var.direct_dns_tcp_server = nil end)
reject("a missing remote TCP endpoint", function(data) data.var.remote_dns_tcp_server = nil end)
reject("the default remote UseIPv4 strategy", function(data) data.var.remote_dns_query_strategy = nil end)
reject("an IPv4-only direct strategy", function(data) data.var.direct_dns_query_strategy = "UseIPv4" end)
reject("an IPv6-only remote strategy", function(data) data.var.remote_dns_query_strategy = "UseIPv6" end)
reject("configured ECS", function(data) data.var.remote_dns_client_ip = "192.0.2.123" end)
reject("a DNS SOCKS proxy", function(data) data.var.dns_socks_address, data.var.dns_socks_port = "127.0.0.1", "1080" end)
reject("an incomplete DNS SOCKS address", function(data) data.var.dns_socks_address = "127.0.0.1" end)
reject("an incomplete DNS SOCKS port", function(data) data.var.dns_socks_port = "1080" end)
reject("global FakeDNS", function(data) data.var.remote_dns_fake = "1" end)
reject("per-rule FakeDNS", function(data) data.sections.shunt.fakedns, data.sections.shunt.allow_fakedns = "1", "1" end)
reject("default-rule FakeDNS", function(data) data.sections.shunt.fakedns, data.sections.shunt.default_fakedns = "1", "1" end)
reject("enabled shunt FakeDNS even without a selected fake rule", function(data) data.sections.shunt.fakedns = "1" end)

for _, address in ipairs({"localhost", "192.168.1.1", "10.0.0.1", "8.8.8.8", "0.0.0.0", "::", "fd00::1"}) do
	reject("non-loopback endpoint " .. address, function(data)
		data.var.direct_dns_tcp_server, data.var.remote_dns_tcp_server = address, address
	end)
end
for _, port in ipairs({"0", "-1", "65536", "5533.5", "invalid", "53", "15353"}) do
	reject("unsafe endpoint port " .. port, function(data)
		data.var.direct_dns_port, data.var.remote_dns_tcp_port = port, port
	end)
end
for _, version in ipairs({"26.3.27", "26.4.17", "26.4.24"}) do
	reject("unsupported Xray " .. version, function(data) data.version = version end)
end

test("disabled passthrough preserves older-core behavior", function()
	local data = fixture()
	data.version = "26.3.27"
	local expected = generate(data)
	equal(outbound(expected, "dns-out").settings.nonIPQuery, "reject")
	equal(outbound(expected, "dns-out").settings.rules, nil)
	data.var.local_dns_passthrough = "0"
	equal(generate(data), expected)
end)

test("global UCI opt-in is not inherited without an instance argument", function()
	local data = fixture()
	data.var.flag = "acl_test"
	local expected = generate(data)
	data.sections["@global[0]"].local_dns_passthrough = "1"
	equal(generate(data), expected)
end)

test("disabled passthrough preserves active FakeDNS", function()
	local data = fixture()
	data.var.remote_dns_fake = "1"
	data.sections.shunt.fakedns, data.sections.shunt.default_fakedns = "1", "1"
	local expected = generate(data)
	assert(expected.fakedns and #expected.fakedns > 0)
	data.var.local_dns_passthrough = "0"
	equal(generate(data), expected)
end)

test("node DNS and internal resolver settings remain unchanged", function()
	local data = fixture()
	data.sections.shunt.default_node = "exit"
	data.sections.exit = {
		[".name"] = "exit", [".type"] = "nodes", type = "Xray", protocol = "socks",
		address = "node.synthetic.test", port = "1080", transport = "tcp", stream_security = "none",
		domain_resolver = "tcp", domain_resolver_dns = "192.0.2.53:5353"
	}
	local expected = generate(data)
	equal(expected.dns.useSystemHosts, true)
	local found = false
	for _, server in ipairs(expected.dns.servers) do
		if server.address == "tcp://192.0.2.53:5353" then
			equal(server.domains, {"full:node.synthetic.test"}); found = true
		end
	end
	assert(found, "fixture did not exercise custom node DNS")
	data.var.local_dns_passthrough = "1"
	local actual = generate(data)
	equal(actual.dns, expected.dns)
	equal(actual.routing, expected.routing)
	equal(actual.inbounds, expected.inbounds)
	for _, value in ipairs(expected.outbounds) do
		if value.tag ~= "dns-out" then equal(outbound(actual, value.tag), value) end
	end
	equal(outbound(actual, "dns-out").streamSettings.sockopt.dialerProxy, "direct")
end)

io.stdout:write(string.format("%d tests passed\n", passed))
