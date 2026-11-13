-- Zray uses Passwall's ipt2socks path; routing and DNS stay in Passwall.
module("luci.passwall.util_zray", package.seeall)
local api = require "luci.passwall.api"

local function present(v)
	return v ~= nil and v ~= "" and v ~= "0"
end

-- The global Zray JSON lives outside acl/default, and the ipt2socks command
-- has no "global" marker. Inspect complete argv instead of the top/grep path
-- convention used by native transparent-proxy backends.
function global_tcp_status(node)
	if type(node) ~= "string" or not node:match("^[%w_%-]+$") then return false end
	local config_file = api.TMP_PATH .. "/global_" .. node .. "_socks.json"
	local contents = api.fs.readfile(config_file)
	if not contents then return false end
	local ok, config = pcall(api.jsonc.parse, contents)
	if not ok or type(config) ~= "table" or type(config.listen) ~= "string" then return false end
	local socks_port = tonumber(config.listen:match(":(%d+)$"))
	local redir_port = tonumber(api.get_cache_var("ACL_GLOBAL_redir_port"))
	if not socks_port or socks_port < 1 or socks_port > 65535 or
		not redir_port or redir_port < 1 or redir_port > 65535 then return false end
	local entries = api.fs.dir("/proc")
	if not entries then return false end
	local core, bridge = false, false
	local core_path = api.get_app_path("zray")
	local function option(args, key)
		for i = 2, #args - 1 do
			if args[i] == key then return args[i + 1] end
		end
		return nil
	end
	for pid in entries do
		if pid:match("^%d+$") then
			local cmdline = api.fs.readfile("/proc/" .. pid .. "/cmdline") or ""
			local args = {}
			for arg in cmdline:gmatch("[^%z]+") do args[#args + 1] = arg end
			if args[1] == api.TMP_PATH .. "/bin/zray" or args[1] == core_path then
				if args[2] == config_file then core = true end
			elseif args[1] == api.TMP_PATH .. "/bin/ipt2socks_default_TCP_UDP" or
				args[1] == "/usr/bin/ipt2socks" or args[1] == "/bin/ipt2socks" then
				if tonumber(option(args, "-l")) == redir_port and
					tonumber(option(args, "-p")) == socks_port and option(args, "-s") == "127.0.0.1" then
					bridge = true
				end
			end
			if core and bridge then return true end
		end
	end
	return false
end

-- Keep runtime controls separate from shared node/transport fields in UCI.
-- Defaults match feed/zray/src/main.zig; JSON needs numbers and booleans,
-- while UCI stores strings. Bound seconds to u32 to avoid unsafe u64 arithmetic.
runtime_numbers = {
	{"workers", 1, 0, 16},
	{"max_connections", 128, 1, 4294967295},
	{"handshake_timeout_s", 15, 0, 4294967295},
	{"connect_timeout_s", 5, 1, 4294967295},
	{"idle_timeout_s", 600, 0, 4294967295},
	{"sock_buf", 0, 0, 2147483647},
	{"stats_interval_s", 60, 0, 4294967295},
	{"crypto_min_bytes", 4096, 1, 32768},
	{"crypto_max_bytes", 32768, 1, 32768}
}

function validate_bootstrap_dns(value)
	if value == nil or value == "" then return "" end
	if type(value) ~= "string" then return nil end
	if value:find("[/%s]") then return nil end
	local host, port
	if value:sub(1, 1) == "[" then
		host, port = value:match("^%[([^%]]+)%]:(%d+)$")
		if not host then host = value:match("^%[([^%]]+)%]$") end
		if not host or not api.datatypes.ip6addr(host) then return nil end
	elseif select(2, value:gsub(":", "")) == 1 then
		host, port = value:match("^([^:]+):(%d+)$")
		if not host or not api.datatypes.ip4addr(host) then return nil end
	else
		host = value
		if not api.datatypes.ipaddr(host) then return nil end
	end
	if port and (tonumber(port) < 1 or tonumber(port) > 65535) then return nil end
	return value
end

function runtime_config(node)
	local config = {}
	for _, spec in ipairs(runtime_numbers) do
		local key, default, min, max = unpack(spec)
		local value = node["zray_" .. key]
		if value == nil or value == "" then value = default end
		local n = (type(value) == "string" or type(value) == "number") and tonumber(value)
		if not n or n ~= n or n % 1 ~= 0 or n < min or n > max then
			return nil, "Invalid Zray " .. key .. ": expected an integer in " .. min .. ".." .. max
		end
		config[key] = n
	end
	if config.crypto_min_bytes > config.crypto_max_bytes then
		return nil, "Zray crypto_min_bytes must not exceed crypto_max_bytes"
	end
	local backend = node.zray_crypto_backend
	if backend == nil or backend == "" then backend = "off" end
	if backend ~= "off" and backend ~= "auto" and backend ~= "afalg" and backend ~= "devcrypto" then
		return nil, "Invalid Zray crypto_backend"
	end
	config.crypto_backend = backend
	local async = node.zray_crypto_async
	if async == nil or async == "" then async = "1" end
	if async ~= "0" and async ~= "1" and async ~= false and async ~= true then
		return nil, "Invalid Zray crypto_async"
	end
	config.crypto_async = async == "1" or async == true
	config.bootstrap_dns = validate_bootstrap_dns(node.zray_bootstrap_dns)
	if not config.bootstrap_dns then
		return nil, "Invalid Zray bootstrap_dns: use an IP address, IPv4:port or [IPv6]:port"
	end
	return config
end

function validate_node(node)
	if not node or node.protocol ~= "vless" then
		return nil, "Zray supports VLESS nodes only"
	end
	local network = node.transport or "tcp"
	if network == "raw" then network = "tcp" end
	if network ~= "tcp" and network ~= "ws" then
		return nil, "Zray supports TCP and WebSocket transports only"
	end
	local flow = node.flow or ""
	if flow == "" then flow = "none" end
	if flow ~= "none" and flow ~= "xtls-rprx-vision" then
		return nil, "Unsupported Zray flow: " .. flow
	end
	if network == "ws" and flow ~= "none" then
		return nil, "Zray WebSocket requires flow=none"
	end
	if node.tls ~= "1" then return nil, "Zray requires TLS or REALITY" end
	if present(node.encryption) and node.encryption ~= "none" then
		return nil, "Zray does not support VLESS encryption"
	end
	for _, key in ipairs({"ech", "use_mldsa65Verify", "use_finalmask", "mux", "chain_proxy"}) do
		if present(node[key]) then return nil, "Zray does not support " .. key end
	end
	if present(node.tcp_guise) and node.tcp_guise ~= "none" then
		return nil, "Zray does not support TCP header camouflage"
	end
	if present(node.tls_pinSHA256) or present(node.tls_CertByName) then
		return nil, "Zray does not support TLS certificate pinning"
	end
	if present(node.fingerprint) and node.fingerprint ~= "chrome" then
		return nil, "Zray uses the Chrome TLS fingerprint"
	end
	local uuid = node.uuid or ""
	if not uuid:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") then
		return nil, "Invalid VLESS UUID"
	end
	local port = tonumber(node.port)
	if not node.address or node.address == "" or not port or port < 1 or port > 65535 or port % 1 ~= 0 then
		return nil, "Invalid Zray server address or port"
	end
	if node.reality == "1" then
		local pk = node.reality_publicKey or ""
		if not pk:match("^[%w_%-]+=?$") or #pk:gsub("=$", "") ~= 43 then
			return nil, "Invalid REALITY public key"
		end
		local sid = node.reality_shortId or ""
		if #sid > 16 or #sid % 2 ~= 0 or sid:find("[^%x]") then
			return nil, "Invalid REALITY short ID"
		end
	elseif node.tls_allowInsecure ~= "1" then
		return nil, "Zray TLS currently requires explicit Allow insecure (no CA/pin verification)"
	end
	local runtime, err = runtime_config(node)
	if not runtime then return nil, err end
	return {network = network, flow = flow, udp = network == "tcp" and flow == "xtls-rprx-vision", runtime = runtime}
end

function gen_config(var)
	local node = api.uci_get_c(var.node)
	local capability, err = validate_node(node)
	if not capability then error(err, 0) end
	local address = var.local_socks_address or "127.0.0.1"
	if address:find(":", 1, true) and address:sub(1, 1) ~= "[" then address = "[" .. address .. "]" end
	local config = {
		listen = address .. ":" .. assert(tonumber(var.local_socks_port), "Missing SOCKS port"),
		server = var.server_host or node.address,
		port = tonumber(var.server_port or node.port),
		uuid = node.uuid,
		sni = node.tls_serverName or node.address,
		security = node.reality == "1" and "reality" or "tls",
		network = capability.network,
		flow = capability.flow,
		-- Preserve IP destinations chosen by Passwall's DNS/routing policy.
		sniff = false
	}
	if config.sni == "" then config.sni = node.address end
	if config.security == "reality" then
		config.public_key = node.reality_publicKey
		config.short_id = node.reality_shortId or ""
	else
		config.tls_verify = "none"
	end
	if capability.network == "ws" then
		config.ws_host = node.ws_host or config.sni
		config.ws_path = node.ws_path or "/"
	end
	for key, value in pairs(capability.runtime) do config[key] = value end
	return api.jsonc.stringify(config, 1)
end

if arg and arg[0] and arg[0]:match("util_zray%.lua$") then
	local ok, result = pcall(function()
		local var = assert(api.jsonc.parse(arg[2]), "Invalid generator arguments")
		if arg[1] == "check_node" then
			local capability, err = validate_node(api.uci_get_c(var.node))
			assert(capability, err)
			assert(var.proxy_udp ~= "proxy" or capability.udp,
				"Zray UDP requires TCP + Vision; disable UDP proxy for this node")
			return "OK"
		end
		assert(arg[1] == "gen_config", "Unknown Zray utility command")
		return gen_config(var)
	end)
	if not ok then io.stderr:write(tostring(result), "\n"); os.exit(1) end
	print(result)
end
