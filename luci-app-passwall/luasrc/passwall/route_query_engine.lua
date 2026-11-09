-- route_query_engine.lua - "走向查询" (route query) core logic.
--
-- Pure-Lua decision core, separated from the luci.controller glue so it can be
-- exercised in a plain Lua 5.1 environment without a LuCI runtime.
-- All LuCI / api reach-outs are injected via `env`:
--   env.api        luci.passwall.api      (uci_get_c, resolve_domain, get_node_remarks,
--                                          finded_com, is_json, jsonc + parse, CACHE_PATH,
--                                          fs, sys, datatypes, appname)
--   env.rm         luci.passwall.route_match  (system_*_decision, core_decision, set_env)
--   env.i18n       luci.i18n              (translate)
--
-- env.api must expose: fs, sys, datatypes, CACHE_PATH, appname, get_node_remarks,
-- finded_com, uci_get_c, resolve_domain, is_json, jsonc.parse. Tests stub these.

local M = {}

local function shell_quote(s)
	return "'" .. (s and s:gsub("'", "'\\''") or "") .. "'"
end

--------------------------------------------------------------------
-- Config assembly
--------------------------------------------------------------------

local GLOBAL_DEFAULTS = {
	tcp_proxy_mode = "disable",
	udp_proxy_mode = "disable",
	use_direct_list = "1",
	use_proxy_list = "1",
	use_block_list = "1",
	use_gfw_list = "1",
	chn_list = "direct",
	use_fakedns = "0",
}

local FORWARD_DEFAULTS = {
	tcp_no_redir_ports = "disable",
	udp_no_redir_ports = "disable",
	tcp_proxy_drop_ports = "disable",
	udp_proxy_drop_ports = "disable",
	tcp_redir_ports = "1:65535",
	udp_redir_ports = "1:65535",
}

-- Build the decision-level config consumed by route_match system_*_decision.
-- g / gf are raw uci tables (@global[0] / @global_forwarding[0]); node is the
-- node section table (may be {}). Returns cfg, node meta.
function M.build_cfg(g, gf, node)
	g = g or {}
	gf = gf or {}
	node = node or {}
	local cfg = {}
	for k, v in pairs(GLOBAL_DEFAULTS) do cfg[k] = g[k] or v end
	for k, v in pairs(FORWARD_DEFAULTS) do cfg[k] = gf[k] or v end
	cfg.use_fakedns = (g.remote_fakedns or "0") == "1" and "1" or "0"
	local node_protocol = node.protocol or ""
	local node_type = node.type or ""
	local use_shunt_node = (node_protocol == "_shunt") and "1" or "0"
	cfg.use_shunt_node = use_shunt_node
	return cfg, node_type, node_protocol, use_shunt_node
end

-- Merge ACL override fields onto a global cfg. `acl` is a raw acl_rule section.
-- Empty / missing ACL fields mean "use global", matching passwall behaviour.
function M.acl_cfg(cfg, acl)
	if not acl then return cfg end
	local out = {}
	for k, v in pairs(cfg) do out[k] = v end
	local override = {
		tcp_proxy_mode = acl.tcp_proxy_mode,
		udp_proxy_mode = acl.udp_proxy_mode,
		use_direct_list = acl.use_direct_list,
		use_proxy_list = acl.use_proxy_list,
		use_block_list = acl.use_block_list,
		use_gfw_list = acl.use_gfw_list,
		chn_list = acl.chn_list,
		tcp_no_redir_ports = acl.tcp_no_redir_ports,
		udp_no_redir_ports = acl.udp_no_redir_ports,
		tcp_proxy_drop_ports = acl.tcp_proxy_drop_ports,
		udp_proxy_drop_ports = acl.udp_proxy_drop_ports,
		tcp_redir_ports = acl.tcp_redir_ports,
		udp_redir_ports = acl.udp_redir_ports,
	}
	for k, v in pairs(override) do
		if v and v ~= "" then out[k] = v end
	end
	return out
end

--------------------------------------------------------------------
-- Transparent-proxy backend detection (disk-cached, 300s TTL)
--------------------------------------------------------------------

local BACKEND_TTL = 300

function M.backend_cache_key(env, prefer_nft)
	return env.api.CACHE_PATH .. "/route_query_backend_" .. (prefer_nft or "1")
end

-- Returns "nft" | "ipset". Mirrors app.sh check_run_environment order.
-- env.exec: function(cmd)->stdout (defaults to env.api.sys.exec).
function M.detect_backend(env, gf)
	gf = gf or {}
	local prefer_nft = gf.prefer_nft or "1"
	local api = env.api
	local exec = env.exec or api.sys.exec
	local cache_file = M.backend_cache_key(env, prefer_nft)
	if api.fs.access(cache_file) then
		local cached = api.fs.readfile(cache_file)
		if cached then
			local ts, val = cached:match("^(%d+)%s+(%S+)%s*$")
			if ts and val and (os.time() - tonumber(ts)) < BACKEND_TTL then
				if val == "nft" or val == "ipset" then return val end
			end
		end
	end
	local has_fw4 = exec("command -v fw4 2>/dev/null"):gsub("%s", "") ~= ""
	local dns_nft = exec("dnsmasq -v 2>/dev/null | grep -qw nftset && echo 1 || echo 0"):gsub("%s", "") == "1"
	local dns_ipset = exec("dnsmasq -v 2>/dev/null | grep -qw ipset && echo 1 || echo 0"):gsub("%s", "") == "1"
	local has_ipset = exec("command -v ipset 2>/dev/null"):gsub("%s", "") ~= ""
	local has_ipt = exec("command -v iptables 2>/dev/null"):gsub("%s", "") ~= ""
	local use_nft
	if prefer_nft == "1" then
		if has_fw4 and dns_nft then
			use_nft = true
		elseif has_ipset and has_ipt and dns_ipset then
			use_nft = false
		end
	else
		if has_ipset and has_ipt and dns_ipset then
			use_nft = false
		elseif has_fw4 and dns_nft then
			use_nft = true
		end
	end
	if use_nft == nil then use_nft = has_fw4 end
	local val = use_nft and "nft" or "ipset"
	api.fs.writefile(cache_file, os.time() .. " " .. val .. "\n")
	return val
end

local RULE_FILES = {
	block = "/etc/passwall/rules/block_host",
	direct = "/etc/passwall/rules/direct_host",
	proxy = "/etc/passwall/rules/proxy_host",
	gfw = "/usr/share/passwall/rules/gfwlist",
	chn = "/usr/share/passwall/rules/chnlist",
}

--------------------------------------------------------------------
-- System-level decision
--------------------------------------------------------------------

local function nft_hit(env, backend, set_name, ip)
	if not set_name then return false end
	if backend == "nft" then
		local cmd = string.format("nft get element inet passwall %s { %s } 2>/dev/null",
			shell_quote(set_name), shell_quote(ip))
		return env.api.sys.call(cmd) == 0
	end
	return env.api.sys.call(string.format("ipset -q test %s %s 2>/dev/null",
		shell_quote(set_name), shell_quote(ip))) == 0
end

-- Run the system-level decision for one target under one cfg/backend.
-- Returns a response-ready table.
function M.system_decide(env, target, port, proto, cfg, backend, files, use_dns)
	local trans = env.i18n and env.i18n.translate or function(s) return s end
	local rm = env.rm
	local hit = function(name, ip) return nft_hit(env, backend, name, ip) end
	local api = env.api

	local is_ip = rm.is_ip(target)
	if is_ip then
		local decision, matched, note = rm.system_ip_decision(cfg, target, port, proto, hit)
		return {
			decision = decision,
			matched = matched,
			note = note,
			backend = backend == "nft" and "nftables" or "ipset/iptables",
		}
	end

	files = files or RULE_FILES
	local readfile = function(path) return api.fs.readfile(path) end
	local decision, matched, entry, note = rm.system_domain_decision(cfg, target, port, proto, files, readfile)
	local resolved = {}
	local dns_note
	if not decision and use_dns then
		local ips, rerr = api.resolve_domain(target)
		if ips and #ips > 0 then
			for _, ip in ipairs(ips) do
				local dd, dm, dn = rm.system_ip_decision(cfg, ip, port, proto, hit)
				resolved[#resolved + 1] = { ip = ip, decision = dd, matched = dm, note = dn }
			end
			dns_note = "解析 " .. #ips .. " 个 IP"
		elseif rerr then
			dns_note = "域名解析失败"
		end
	end
	local final_decision, final_matched, final_note = decision, matched, note
	if not final_decision and #resolved > 0 then
		local all = resolved[1].decision
		local same = all ~= nil
		for i = 2, #resolved do
			if resolved[i].decision ~= all then same = false break end
		end
		if same then
			final_decision = all
			final_matched = nil
			final_note = (final_note and final_note .. "；" or "") .. trans("按解析 IP 判定")
		end
	end
	return {
		decision = final_decision,
		matched = final_matched,
		entry = entry,
		note = final_note,
		resolved = #resolved > 0 and resolved or nil,
		dns_note = dns_note,
		backend = backend == "nft" and "nftables" or "ipset/iptables",
	}
end

--------------------------------------------------------------------
-- Client-level (core route / global.json) decision
--------------------------------------------------------------------

-- Inject external tools into route_match (geosite/geoip/rule-set).
-- Returns { geoview_bin, singbox_bin }.
function M.setup_route_env(env)
	local api = env.api
	local sh_exec = function(cmd) return api.sys.exec(cmd or "") end
	local sh_hit = function(cmd) return api.sys.call(cmd or "") == 0 end
	local geoview_bin = api.finded_com("geoview") or ""
	local singbox_bin = api.finded_com("sing-box") or ""
	local geo_asset = api.uci_get_c("@global_rules[0]", "v2ray_location_asset")
	if geo_asset == nil or geo_asset == "" then geo_asset = "/usr/share/v2ray/" end
	local geo_dir = geo_asset:match("^(.*)/") or "/usr/share/v2ray/"
	local srs_dir = api.CACHE_PATH .. "/singbox_srss/"

	local function geosite_match(tag, domain)
		if geoview_bin == "" then return nil end
		local out = sh_exec(string.format("%s -type geosite -action lookup -input %s -value %s -lowmem=true",
			shell_quote(geoview_bin), shell_quote(geo_dir .. "geosite.dat"), shell_quote(domain))):lower()
		return out:find(tag:lower(), 1, true) ~= nil
	end
	local function geoip_match(tag, ip)
		if geoview_bin == "" then return nil end
		local out = sh_exec(string.format("%s -type geoip -action lookup -input %s -value %s -lowmem=true",
			shell_quote(geoview_bin), shell_quote(geo_dir .. "geoip.dat"), shell_quote(ip))):lower()
		return out:find(tag:lower(), 1, true) ~= nil
	end
	local function rule_set_match(name, target)
		if singbox_bin == "" then return nil end
		name = (name or ""):gsub("^local:", "")
		local srs_path = srs_dir .. name
		if srs_path:sub(-4) ~= ".srs" then srs_path = srs_path .. ".srs" end
		if not api.fs.access(srs_path) then return nil end
		return sh_hit(string.format("%s rule-set match %s %s",
			shell_quote(singbox_bin), shell_quote(srs_path), shell_quote(target)))
	end
	env.rm.set_env({
		exec = sh_exec,
		geosite_match = geosite_match,
		geoip_match = geoip_match,
		rule_set_match = rule_set_match,
		shell_quote = shell_quote,
	})
	return { geoview_bin = geoview_bin, singbox_bin = singbox_bin }
end

-- Read the running core config (global.json) for an acl dir. sid = "default" or
-- acl section id. Returns parsed table or nil.
function M.read_global_json(env, sid)
	local api = env.api
	local path = string.format("/tmp/etc/%s/acl/%s/global.json", api.appname, sid)
	if not api.fs.access(path) then return nil end
	local raw = api.fs.readfile(path)
	if not raw or not api.is_json(raw) then return nil end
	return api.jsonc.parse(raw)
end

local function core_kind_of(node_type)
	if node_type == "sing-box" then return "singbox" end
	if node_type == "Xray" then return "xray" end
	return nil
end

-- Decide one client path. Params mirror controller's original logic.
function M.client_decide(env, gc, node_id, node_type, target, port, proto, protocol)
	local trans = env.i18n.translate
	local client = { available = false }
	local core_kind = core_kind_of(node_type)
	if not node_id then
		client.note = trans("未配置全局节点")
	elseif not core_kind then
		client.note = trans("当前全局节点类型不参与代理客户端路由分流，走向由系统级转发决定")
	elseif not gc then
		client.note = trans("未能读取代理客户端运行配置(global.json)，代理客户端分流无法判定")
	else
		local rm = env.rm
		local res
		if gc.route and core_kind == "singbox" then
			res = rm.core_decision("singbox", gc.route.rules or {}, target, gc.route.final, {
				port = port, proto = proto,
				protocol = protocol ~= "" and protocol or nil,
			})
			client.core = "sing-box"
		elseif gc.routing and core_kind == "xray" then
			res = rm.core_decision("xray", gc.routing.rules or {}, target, "", {
				port = port, proto = proto,
				protocol = protocol ~= "" and protocol or nil,
			})
			client.core = "xray"
		end
		if res then
			client.available = true
			client.outbound = res.outbound
			client.rule = res.rule
			client.matched = res.matched
			client.note = res.note
			client.final = res.check == "default"
		else
			client.note = trans("客户端配置不含可识别的路由规则")
		end
	end
	return client
end

--------------------------------------------------------------------
-- ACL (source-IP scenario) helpers
--------------------------------------------------------------------

-- Convert an IPv4 address to its 32-bit number (local, dependency-free).
local function ipv4_num(ip)
	local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if not a then return nil end
	a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
	if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
	return (a * 16777216) + (b * 65536) + (c * 256) + d
end

-- Match a single ACL source entry against ip/mac.
--   entry: MAC | single IP | CIDR | "a-b" IPv4 range | "ipset:<name>"
--   ip:    source ip (string) or nil
--   mac:   source mac (uppercase, colon-separated) or nil
--   cidr_match: function(ip, cidr) -> boolean (reuse route_match.cidr_match)
-- Returns true / false / nil(unverifiable, e.g. ipset or mac-only with ip given)
function M.ip_source_entry_match(entry, ip, mac, cidr_match)
	entry = entry or ""
	entry = entry:gsub("%s+", ""):upper()
	ip = ip and ip:upper() or nil
	mac = mac and mac:upper() or nil

	if entry:find("IPSET:", 1, true) == 1 then
		return nil -- needs ipset/nft lookup
	end

	if entry:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
		return mac and (entry == mac) or nil
	end

	if not ip then return nil end
	-- CIDR / single IP via the existing engine implementation
	if cidr_match and (entry:find("/", 1, true) or ipv4_num(entry) ~= nil) then
		return cidr_match(ip, entry)
	end
	-- single IP without cidr_match: numeric equality
	if ipv4_num(entry) ~= nil and ipv4_num(ip) ~= nil then
		return ipv4_num(entry) == ipv4_num(ip)
	end
	-- IPv4 range a-b (only meaningful when end is a plain IPv4)
	local s, e = entry:match("^(.-)%-(%d+%.%d+%.%d+%.%d+)$")
	if s then
		local sn, en = ipv4_num(s), ipv4_num(e)
		local inum = ipv4_num(ip)
		if sn and en and inum then return inum >= sn and inum <= en end
		return false
	end
	return false
end

-- List acl_rule sections that enable the given source ip/mac.
-- sources may contain ip / cidr / range / mac / ipset entries.
-- Returns an array of matched acl section tables.
function M.match_acl(env, ip, mac)
	local rm = env.rm
	local matched = {}
	local seen = {}
	env.api.uci_foreach_c("acl_rule", function(s)
		if s.enabled ~= "1" then return end
		local src_list = s.sources
		if type(src_list) == "string" then
			local t = {}
			for w in src_list:gmatch("%S+") do t[#t + 1] = w end
			src_list = t
		end
		if not src_list or #src_list == 0 then return end
		local found = false
		for _, e in ipairs(src_list) do
			local r = M.ip_source_entry_match(e, ip, mac, rm.cidr_match)
			if r == true then found = true break end
		end
		if found and not seen[s[".name"]] then
			seen[s[".name"]] = true
			matched[#matched + 1] = s
		end
	end)
	return matched
end

--------------------------------------------------------------------
-- Top-level query
--------------------------------------------------------------------

-- opts: { target, port, proto, protocol, src }
-- env:  { api, rm, util, i18n }
-- Returns the response-ready data table (code 0 on validation failure,
-- code 1 with system/client/acl details otherwise).
function M.query(opts, env)
	local t_start = os.time()
	local ok, err_or_data = pcall(function()
		local api = env.api
		local rm = env.rm
		local trans = env.i18n.translate
		local target = api.trim(opts.target or "")
		local port = opts.port or ""
		local proto = opts.proto or "tcp"
		local protocol = opts.protocol or ""
		local src = api.trim(opts.src or "")

		if target == "" then
			return { code = 0, message = trans("请输入域名或 IP 地址！"), elapsed = os.time() - t_start }
		end
		if proto ~= "tcp" and proto ~= "udp" then proto = "tcp" end
		port = tonumber(port) and tostring(math.floor(tonumber(port))) or ""
		if port ~= "" and not api.datatypes.port(port) then
			return { code = 0, message = trans("端口无效！"), elapsed = os.time() - t_start }
		end

		local is_ip = rm.is_ip(target)
		local is6 = rm.is_ipv6(target)
		local port_n = tonumber(port) or nil

		local g = api.uci_get_c("@global[0]") or {}
		local gf = api.uci_get_c("@global_forwarding[0]") or {}

		local node_id = g.node
		local n = {}
		local node_type, node_remarks = "", ""
		if node_id then
			n = api.uci_get_c(node_id) or {}
			node_type = n.type or ""
			node_remarks = api.get_node_remarks(n) or ""
		end

		local cfg, _, _ = M.build_cfg(g, gf, n)
		local backend = M.detect_backend(env, gf)

		local tools = M.setup_route_env(env)
		local gc = M.read_global_json(env, "default")

		local system = M.system_decide(env, target, port_n, proto, cfg, backend, nil, true)
		local client = M.client_decide(env, gc, node_id, node_type, target, port_n, proto, protocol)

		local acl = nil
		if src ~= "" then
			local src_ip, src_mac = src, nil
			if src:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
				src_mac = src:upper()
				src_ip = nil
			elseif not (rm.is_ipv4(src) or rm.is_ipv6(src)) then
				return { code = 0, message = trans("来源设备 IP 无效！"), elapsed = os.time() - t_start }
			end
			local tmp = M.match_acl(env, src_ip, src_mac)
			if #tmp > 0 then
				local acl_sec = tmp[1]
				local acl_name = acl_sec.remarks or acl_sec[".name"]
				local use_global = acl_sec.use_global_config == "1"
				local acl_node_id = acl_sec.node
				local acl_node = acl_node_id and api.uci_get_c(acl_node_id) or nil
				local acl_node_type = acl_node and (acl_node.type or "") or node_type
				local acl_node_protocol = acl_node and (acl_node.protocol or "") or ""
				local acl_cfg = M.acl_cfg(cfg, acl_sec)
				if acl_node_protocol == "_shunt" then
					acl_cfg.use_shunt_node = "1"
				elseif acl_node_protocol ~= "" then
					acl_cfg.use_shunt_node = "0"
				end
				local acl_system = M.system_decide(env, target, port_n, proto, acl_cfg, backend, nil, true)
				-- client: use_global ACL reuses default json & global node; a
				-- dedicated ACL tries its own acl dir json (falling back to the
				-- default global.json, since dedicated core configs are named by
				-- node_id + runtime port and not discoverable from the query end).
				local acl_client
				if use_global then
					acl_client = M.client_decide(env, gc, node_id, node_type, target, port_n, proto, protocol)
				else
					local acl_gc = M.read_global_json(env, acl_sec[".name"])
					local approx = false
					if not acl_gc then
						acl_gc = gc
						approx = true
					end
					acl_client = M.client_decide(env, acl_gc, acl_node_id, acl_node_type, target, port_n, proto, protocol)
					if approx and acl_client.available then
						acl_client.note = (acl_client.note and acl_client.note .. "；" or "") .. trans("代理客户端分流按全局配置近似判定")
					end
				end
				acl = {
					matched = true,
					name = acl_name,
					use_global_config = use_global,
					node_id = acl_node_id,
					node_type = acl_node_type,
					system = acl_system,
					client = acl_client,
				}
			else
				acl = { matched = false, note = trans("未匹配到可用的 ACL，沿用全局判定") }
			end
		end

		return {
			code = 1,
			target = target,
			type = is_ip and "ip" or "domain",
			family = (is_ip and (is6 and "ipv6" or "ipv4")) or "",
			port = port,
			proto = proto,
			node_id = node_id,
			node_type = node_type,
			node_remarks = node_remarks,
			system = system,
			client = client,
			acl = acl,
			elapsed = os.time() - t_start,
			geoview_bin = tools.geoview_bin,
			singbox_bin = tools.singbox_bin,
		}
	end)
	if ok then return err_or_data end
	return { code = 0, message = "route_query_engine: " .. tostring(err_or_data), elapsed = os.time() - t_start }
end

return M