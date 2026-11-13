-- Run from the luci-app-passwall directory: lua tests/zray.lua
-- Optional argument: write generated configurations for a real-core smoke test.
local output_dir = arg[1]
local current_node
-- IP parsing itself is provided by LuCI on the router; keep the fixture to
-- known literal addresses so the actual DNS endpoint parsing is exercised.
local ipv4 = { ["223.5.5.5"] = true, ["127.0.0.1"] = true }
local ipv6 = { ["2001:db8::53"] = true, ["::1"] = true }
local api = {
	uci_get_c = function() return current_node end,
	jsonc = { stringify = function(value) return value end },
	datatypes = {
		ip4addr = function(value) return ipv4[value] end,
		ip6addr = function(value) return ipv6[value] end,
		ipaddr = function(value) return ipv4[value] or ipv6[value] end
	}
}
package.loaded["luci.passwall.api"] = api
dofile("luasrc/passwall/util_zray.lua")
local zray = require "luci.passwall.util_zray"
local count = 0
local function check(value, message)
	assert(value, message)
	count = count + 1
end
local function node(overrides)
	local n = {
		type = "Zray", protocol = "vless", address = "127.0.0.1", port = "443",
		uuid = "00000000-0000-0000-0000-000000000000", tls = "1", reality = "1",
		reality_publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		reality_shortId = "0123abcd", tls_serverName = "example.com",
		transport = "tcp", flow = "xtls-rprx-vision"
	}
	for k, v in pairs(overrides or {}) do n[k] = v end
	return n
end
local function rejected(overrides)
	local capability, err = zray.validate_node(node(overrides))
	check(not capability and err, "accepted unsupported node")
end
check(zray.validate_node(node()).udp, "Vision UDP unavailable")
check(zray.validate_node(node({transport = "raw"})).network == "tcp")
check(not zray.validate_node(node({transport = "ws", flow = "none"})).udp)
for _, transport in ipairs({"grpc", "xhttp", "httpupgrade", "mkcp"}) do rejected({transport = transport}) end
rejected({protocol = "vmess"})
rejected({uuid = "not-a-uuid"})
rejected({transport = "ws"})
rejected({flow = "xtls-rprx-vision-udp443"})
rejected({tls = "0"})
rejected({reality = "0", tls_allowInsecure = "0"})
rejected({reality_publicKey = "invalid"})
rejected({reality_shortId = "123"})
rejected({fingerprint = "firefox"})
rejected({use_mldsa65Verify = "1"})
rejected({ech = "1"})
rejected({tls_pinSHA256 = "a-pin"})
rejected({encryption = "mlkem768x25519plus.native"})
rejected({chain_proxy = "1"})

-- Runtime controls must survive UCI string conversion, defaults and preflight.
for _, spec in ipairs(zray.runtime_numbers) do
	local name, default, min, max = unpack(spec)
	local key = "zray_" .. name
	local runtime = assert(zray.runtime_config(node()))
	check(runtime[name] == default, "wrong default for " .. name)
	local overrides = {[key] = tostring(min)}
	if name == "crypto_max_bytes" then overrides.zray_crypto_min_bytes = "1" end
	runtime = assert(zray.runtime_config(node(overrides)))
	check(runtime[name] == min, "minimum rejected for " .. name)
	overrides[key] = tostring(max)
	runtime = assert(zray.runtime_config(node(overrides)))
	check(runtime[name] == max, "maximum rejected for " .. name)
	for _, invalid in ipairs({tostring(min - 1), tostring(max + 1), "1.5", "invalid", true, "nan", "inf"}) do
		rejected({[key] = invalid})
	end
end
rejected({zray_crypto_min_bytes = "8192", zray_crypto_max_bytes = "4096"})
rejected({zray_crypto_backend = "unknown"})
rejected({zray_crypto_async = "yes"})
for _, value in ipairs({"223.5.5.5", "223.5.5.5:53", "127.0.0.1:65535", "2001:db8::53", "[2001:db8::53]", "[::1]:5353"}) do
	check(zray.validate_node(node({zray_bootstrap_dns = value})), "valid bootstrap DNS rejected: " .. value)
end
for _, value in ipairs({"dns.example.com", "223.5.5.5:0", "223.5.5.5:65536", "223.5.5.5:", "[::1]:", "[::1]junk", "[223.5.5.5]:53", "223.5.5.5/24", "223.5.5.5:53 ", "https://223.5.5.5/dns-query"}) do
	rejected({zray_bootstrap_dns = value})
end
current_node = node({
	zray_workers = "4", zray_max_connections = "64", zray_handshake_timeout_s = "20",
	zray_connect_timeout_s = "8", zray_idle_timeout_s = "900", zray_sock_buf = "65536",
	zray_stats_interval_s = "0", zray_bootstrap_dns = "[::1]:5353",
	zray_crypto_backend = "auto", zray_crypto_async = "0",
	zray_crypto_min_bytes = "8192", zray_crypto_max_bytes = "16384"
})
local custom = zray.gen_config({node = "test", local_socks_port = "18900"})
check(custom.workers == 4 and custom.max_connections == 64)
check(custom.handshake_timeout_s == 20 and custom.connect_timeout_s == 8 and custom.idle_timeout_s == 900)
check(custom.sock_buf == 65536 and custom.stats_interval_s == 0)
check(custom.bootstrap_dns == "[::1]:5353")
check(custom.crypto_backend == "auto" and custom.crypto_async == false)
check(custom.crypto_min_bytes == 8192 and custom.crypto_max_bytes == 16384)
check(custom.sniff == false and not custom.redirect, "runtime controls must preserve Passwall routing")
for _, backend in ipairs({"off", "auto", "afalg", "devcrypto"}) do
	check(zray.validate_node(node({zray_crypto_backend = backend})), "supported backend rejected")
end

local function json(t)
	local fields = {}
	for k, v in pairs(t) do
		fields[#fields + 1] = string.format("%q:", k) ..
			(type(v) == "string" and string.format("%q", v) or tostring(v))
	end
	return "{" .. table.concat(fields, ",") .. "}"
end
if output_dir then
	local f = assert(io.open(output_dir .. "/advanced.json", "w"))
	f:write(json(custom)); f:close()
end
for name, overrides in pairs({
	reality = {},
	tls = {reality = "0", tls_allowInsecure = "1"},
	websocket = {reality = "0", tls_allowInsecure = "1", transport = "ws", flow = "none", ws_path = "/proxy"}
}) do
	current_node = node(overrides)
	local config = zray.gen_config({node = "test", local_socks_port = "18900"})
	check(config.listen == "127.0.0.1:18900")
	check(config.sniff == false, "must preserve Passwall DNS/IP routing decisions")
	check(type(config.port) == "number")
	if name ~= "reality" then
		check(config.tls_verify == "none" and not config.public_key and not config.short_id)
	end
	if output_dir then
		local f = assert(io.open(output_dir .. "/" .. name .. ".json", "w"))
		f:write(json(config)); f:close()
	end
end
current_node = node()
local relay = zray.gen_config({node = "test", local_socks_address = "::1", local_socks_port = "18901", server_host = "127.0.0.1", server_port = "8443"})
check(relay.listen == "[::1]:18901" and relay.port == 8443)
check(relay.sni == "example.com", "relay override must preserve original SNI")

-- Execute the actual VLESS subscription parser without update/lock side effects.
-- Keep its surrounding dependencies minimal so the Zray-only case is exercised.
local file = assert(io.open("root/usr/share/passwall/subscribe.lua"))
local source = file:read("*a"); file:close()
local helper = assert(source:match("local function parse_host_port(.-)\nend"))
source = assert(source:match("local function processData(.-)\nlocal function curl"))
local env = setmetatable({
	DEFAULT_VLESS_TYPE = "zray", DEFAULT_ALLOWINSECURE = true,
	has_zray = true, core_has = {zray = true}, log = function() end,
	UrlDecode = function(s) return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)) end,
	split = function(s, delimiter)
		local values, pos = {}, 1
		s = s or ""
		while true do
			local first, last = s:find(delimiter, pos)
			if not first then values[#values + 1] = s:sub(pos); break end
			values[#values + 1] = s:sub(pos, first - 1)
			pos = last + 1
		end
		return values
	end,
	api = {is_ipv6addrport = function() return false end}
}, {__index = _G})
local loader = assert(loadstring("local function parse_host_port" .. helper .. "\nend\nreturn function" .. source))
setfenv(loader, env)
local parse = loader()
local prefix = "00000000-0000-0000-0000-000000000000@127.0.0.1:443?"
local reality = "security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=example.com&flow=xtls-rprx-vision"
check(parse("vless", prefix .. reality, "1").type == "Zray", "Zray-only VLESS import failed")
check(parse("vless", prefix .. reality .. "&type=raw", "1").transport == "tcp")
check(not parse("vless", prefix .. reality .. "&type=xhttp", "1"))
check(not parse("vless", prefix .. reality .. "&type=ws", "1"))
check(not parse("vless", prefix .. "security=tls", "1"), "must not silently inherit insecure TLS")
check(parse("vless", prefix .. "security=tls&allowInsecure=1&type=ws", "1").type == "Zray")
check(not parse("vless", prefix .. "security=none", "1"))
env.has_xray = true
check(not parse("vless", prefix .. reality .. "&type=xhttp", "1"), "explicit Zray choice must not fall back to Xray")
print("Zray generator/subscription: " .. count .. " checks passed")
