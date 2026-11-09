-- route_match.lua - Route direction (direct / proxy / block) query engine.
--
-- Pure-Lua core, testable in a plain Lua 5.1 environment (no LuCI deps):
--   lua route_match.lua --selftest
-- Inside LuCI it is loaded via require "luci.passwall.route_match".
--
-- The module contains only pure matching logic. Shell tool access (geoview /
-- sing-box / grep) is injected by the caller via M.set_env() so the core stays
-- dependency-free and unit-testable.

local M = {}

-- POSIX shell single-quote helper.
function M.shell_quote(s)
	return "'" .. (s and s:gsub("'", "'\\''") or "") .. "'"
end
local function shell_quote(s) return M.shell_quote(s) end

--------------------------------------------------------------------
-- String helpers
--------------------------------------------------------------------

function M.trim(s)
	return (s and s:gsub("^%s+", ""):gsub("%s+$", "")) or ""
end

function M.lower(s)
	return s and s:lower() or s
end

-- Split string by any single separator char ("," or " ")
function M.split(s, sep)
	local out = {}
	if not s then return out end
	for w in s:gmatch("[^" .. sep .. "]+") do
		out[#out + 1] = w
	end
	return out
end

-- Normalise a domain for comparisons: lower-case, strip leading/trailing dots.
function M.norm_domain(domain)
	domain = M.lower(M.trim(domain))
	domain = domain:gsub("^%.", ""):gsub("%.$", "")
	return domain
end

function M.is_subdomain(domain, base)
	domain = M.norm_domain(domain)
	base = M.norm_domain(base)
	if base == "" then return false end
	if domain == base then return true end
	return #domain > #base and domain:sub(-#base - 1) == "." .. base
end

--------------------------------------------------------------------
-- Rule list entry parsing
-- (mirrors util_sing-box.lua / util_xray.lua parsing of shunt domain/ip lists)
--------------------------------------------------------------------

-- Entry classification for domain lists.
-- Returns: nil for empty/comment, else one of
--   "plain", "domain", "full", "regexp", "keyword", "geosite", "geoip", "rule_set"
function M.get_entry_kind(entry)
	local e = M.trim(entry)
	if e == "" or e:sub(1, 1) == "#" then return nil end
	for _, k in ipairs({ "geosite:", "geoip:", "regexp:", "keyword:", "full:", "domain:", "rule-set:", "rs:" }) do
		if e:find(k, 1, true) == 1 then
			if k == "rule-set:" or k == "rs:" then return "rule_set" end
			return k:sub(1, -2)
		end
	end
	return "plain"
end

function M.entry_payload(entry, prefix)
	local e = M.trim(entry)
	if prefix:sub(-1) ~= ":" then prefix = prefix .. ":" end
	return e:sub(#prefix + 1)
end

-- Extract the rule-set identifier from a rule set entry (rule-set: / rs:).
function M.rule_set_name(entry)
	local e = M.trim(entry)
	if e:find("rule-set:", 1, true) == 1 then return e:sub(#"rule-set:" + 1) end
	if e:find("rs:", 1, true) == 1 then return e:sub(#"rs:" + 1) end
	return e
end

-- Parse a multi-line domain list into entries.
function M.parse_entries(raw)
	local out = {}
	if not raw then return out end
	for line in (raw .. "\n"):gmatch("([^\n]+)") do
		local e = M.trim(line)
		if e ~= "" and e:sub(1, 1) ~= "#" then
			out[#out + 1] = e
		end
	end
	return out
end

--------------------------------------------------------------------
-- IP helpers (IPv4 / IPv6, no bit libraries required for Lua 5.1)
--------------------------------------------------------------------

function M.is_ipv4(ip)
	if not ip then return false end
	if not ip:match("^%d+%.%d+%.%d+%.%d+$") then return false end
	for o in (ip .. "."):gmatch("(%d+)%.") do
		if tonumber(o) > 255 then return false end
	end
	return true
end

function M.is_ipv6(ip)
	if not ip then return false end
	if ip:find(":") == nil then return false end
	ip = ip:gsub("^%[", ""):gsub("%]$", "")
	if not ip:match("^[%x:]+$") then return false end
	local count = 0
	for _ in ip:gmatch(":") do count = count + 1 end
	-- valid when containing '::' (up to 8 groups) or having exactly 7 colons
	return (ip:find("::", 1, true) ~= nil and count <= 7)
		or (count == 7)
end

function M.is_ip(ip)
	return M.is_ipv4(ip) or M.is_ipv6(ip)
end

function M.ipv4_to_num(ip)
	if not M.is_ipv4(ip) then return nil end
	local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
end

-- Expand IPv6 to 8 groups of hex, return as list of strings (lower-case, no
-- compression). Returns nil on parse failure.
function M.ipv6_expand(ip)
	if not M.is_ipv6(ip) then return nil end
	ip = ip:gsub("^%[", ""):gsub("%]$", "")
	local left, right
	local dbl = ip:find("::", 1, true)
	if dbl then
		left = ip:sub(1, dbl - 1)
		right = ip:sub(dbl + 2)
	else
		left = ip
		right = ""
	end
	local function parts(str)
		local out = {}
		if str == "" then return out end
		for h in str:gmatch("[^:]+") do out[#out + 1] = h end
		return out
	end
	local lp = parts(left)
	local rp = parts(right)
	if not dbl and #lp + #rp ~= 8 then return nil end
	if dbl and #lp + #rp > 7 then return nil end
	local missing = 8 - (#lp + #rp)
	if missing < 0 then return nil end
	local out = {}
	for i = 1, #lp do out[#out + 1] = string.format("%x", tonumber(lp[i], 16) or 0) end
	for i = 1, missing do out[#out + 1] = "0" end
	for i = 1, #rp do out[#out + 1] = string.format("%x", tonumber(rp[i], 16) or 0) end
	return out
end

-- Compare two IPv6 addrs, returns -1/0/1.
function M.ipv6_compare(a, b)
	local pa = M.ipv6_expand(a)
	local pb = M.ipv6_expand(b)
	if not pa or not pb then return nil end
	for i = 1, 8 do
		local na = tonumber(pa[i], 16)
		local nb = tonumber(pb[i], 16)
		if na < nb then return -1 end
		if na > nb then return 1 end
	end
	return 0
end

local function ipv4_in_cidr(ip, cidr)
	local ipn = M.ipv4_to_num(ip)
	if not ipn then return false end
	local addr, p = cidr:match("^(.-)/(%d+)$")
	if not addr then
		-- bare IP equality
		return M.is_ipv4(cidr) and M.ipv4_to_num(cidr) == ipn
	end
	local an = M.ipv4_to_num(addr)
	if not an then return false end
	p = tonumber(p)
	if not p or p < 0 or p > 32 then return false end
	if p == 0 then return true end
	return math.floor(ipn / (2 ^ (32 - p))) == math.floor(an / (2 ^ (32 - p)))
end

-- bit-wise AND on two integers < 2^16, portable across Lua 5.1/5.3.
local function band16(a, b)
	local r = 0
	local p = 1
	while a > 0 or b > 0 do
		local ra = a % 2
		local rb = b % 2
		if ra == 1 and rb == 1 then r = r + p end
		a = math.floor(a / 2)
		b = math.floor(b / 2)
		p = p * 2
	end
	return r
end

local function ipv6_in_cidr(ip, addr, prefix)
	if prefix < 0 or prefix > 128 then return false end
	if prefix == 0 then return true end
	local p1 = M.ipv6_expand(ip)
	local p2 = M.ipv6_expand(addr)
	if not p1 or not p2 then return false end
	local full = math.floor(prefix / 16)
	local rem = prefix % 16
	for i = 1, full do
		if tonumber(p1[i], 16) ~= tonumber(p2[i], 16) then return false end
	end
	if rem > 0 then
		local mask = 2 ^ rem - 1
		local shift = 16 - rem
		local g1 = math.floor(tonumber(p1[full + 1], 16) / 2 ^ shift)
		local g2 = math.floor(tonumber(p2[full + 1], 16) / 2 ^ shift)
		if band16(g1, mask) ~= band16(g2, mask) then return false end
	end
	return true
end

function M.cidr_match(ip, cidr)
	cidr = M.trim(cidr)
	if cidr == "" then return false end
	if M.is_ipv4(ip) and M.is_ipv4(cidr) then
		return ipv4_in_cidr(ip, cidr)
	elseif M.is_ipv6(ip) and M.is_ipv6(cidr) and not cidr:find("/") then
		return M.ipv6_compare(ip, cidr) == 0
	end
	local addr, prefix = cidr:match("^(.-)/(%d+)$")
	if not addr or not prefix then return false end
	if M.is_ipv4(ip) and M.is_ipv4(addr) then
		return ipv4_in_cidr(ip, addr .. "/" .. prefix)
	end
	if M.is_ipv6(ip) and M.is_ipv6(addr) then
		return ipv6_in_cidr(ip, addr, tonumber(prefix))
	end
	return false
end

function M.cidr_match_bits(ip, cidr)
	return M.cidr_match(ip, cidr)
end

--------------------------------------------------------------------
-- Port matching
--------------------------------------------------------------------

-- port_str: "disable" | "80,443" | "8000-8100" | "1:65535" | ""
--   "disable" => empty list (matches nothing); "" / "1:65535" => all ports.
function M.port_match(port, port_str)
	if port_str == nil then return true end
	if not port then return true end
	port = tonumber(port)
	if not port then return true end
	port_str = M.trim(tostring(port_str))
	if port_str == "disable" then return false end
	if port_str == "" or port_str == "1:65535" then return true end
	for _, token in ipairs(M.split(port_str:gsub(":", "-"), ",")) do
		local lo, hi = token:match("^(%d+)%-(%d+)$")
		if lo and hi then
			if port >= tonumber(lo) and port <= tonumber(hi) then return true end
		else
			local n = token:match("^(%d+)$")
			if n and port == tonumber(n) then return true end
		end
	end
	return false
end

--------------------------------------------------------------------
-- Rule entry matching
--------------------------------------------------------------------

-- Regex via external grep (injected exec). Falls back to Lua pattern heuristics.
M.regex_match = function(regex, addr)
	if M.exec then
		local ok, out = pcall(M.exec, "printf '%s' " .. shell_quote(addr) .. " | grep -Eq " .. shell_quote(regex) .. " && echo 1 || echo 0")
		if ok and out and out:gsub("%s", "") ~= "" then
			return out:gsub("%s", "") == "1"
		end
	end
	-- Lua fallback: try as Lua pattern (silently ignore invalid patterns).
	local p = regex
	p = p:gsub("%%", "%%%") -- no-op safety
	p = p:gsub("\\%.", "%%"):gsub("%%.", "%%")
	local okc, r = pcall(function()
		return M.lower(addr):find(p) ~= nil
	end)
	if okc then return r end
	return false
end

-- Match a single domain-list entry against a target domain.
-- opts.plain_suffix: plain text treated as suffix (is_subdomain) instead of
--   substring. Used for xray rules and rule files where bare text means
--   "domain plus its subdomains". sing-box plain text means substring.
-- Returns nil when the entry kind cannot be evaluated (e.g. geosite without tool).
function M.domain_entry_match(entry, target, opts)
	opts = opts or {}
	local kind = M.get_entry_kind(entry)
	if not kind then return nil end
	local t = M.norm_domain(target)
	local p
	if kind == "plain" then
		p = M.norm_domain(entry)
		if opts.plain_suffix then
			return M.is_subdomain(t, p)
		end
		return t:find(p, 1, true) ~= nil  -- substring (domain_keyword)
	elseif kind == "keyword" then
		return t:find(M.trim(M.entry_payload(entry, "keyword")), 1, true) ~= nil
	elseif kind == "domain" then
		return M.is_subdomain(t, M.entry_payload(entry, "domain"))
	elseif kind == "full" then
		return t == M.norm_domain(M.entry_payload(entry, "full"))
	elseif kind == "regexp" then
		return M.regex_match(M.entry_payload(entry, "regexp"), t)
	elseif kind == "geosite" then
		p = M.entry_payload(entry, "geosite")
		if M.geosite_match then return M.geosite_match(p, target) end
		return nil
	elseif kind == "rule_set" then
		p = M.rule_set_name(entry)
		if M.rule_set_match then return M.rule_set_match(p, target) end
		return nil
	end
	return nil
end

-- Match a single ip-list entry against an IP.
function M.ip_entry_match(entry, ip)
	local kind = M.get_entry_kind(entry)
	if not kind then return false end
	if kind == "plain" then
		return M.cidr_match(ip, entry)
	elseif kind == "geoip" then
		local tag = M.entry_payload(entry, "geoip")
		if tag == "private" then
			return M.is_private_ip(ip)
		end
		if M.geoip_match then return M.geoip_match(tag, ip) end
		return nil
	elseif kind == "rule_set" then
		if M.rule_set_match then return M.rule_set_match(M.rule_set_name(entry), ip) end
		return nil
	end
	return false
end

--------------------------------------------------------------------
-- Private network detection
--------------------------------------------------------------------

function M.is_private_ip(ip)
	if M.is_ipv4(ip) then
		local n = M.ipv4_to_num(ip)
		if not n then return false end
		return
			(n >= M.ipv4_to_num("10.0.0.0") and n <= M.ipv4_to_num("10.255.255.255")) or
			(n >= M.ipv4_to_num("172.16.0.0") and n <= M.ipv4_to_num("172.31.255.255")) or
			(n >= M.ipv4_to_num("192.168.0.0") and n <= M.ipv4_to_num("192.168.255.255")) or
			(n >= M.ipv4_to_num("127.0.0.0") and n <= M.ipv4_to_num("127.255.255.255"))
	end
	if M.is_ipv6(ip) then
		local p = M.ipv6_expand(ip)
		if not p then return false end
		if p[1] and M.ipv6_expand("::1")
			and M.ipv6_compare(ip, "::1") == 0 then return true end
		local first = tonumber(p[1], 16)
		if first >= 0xfc00 and first <= 0xfdff then return true end  -- fc00::/7
		if first == 0xfe80 and tonumber(p[2], 16) >= 0x8000 then return true end -- fe80::/10
	end
	return false
end

--------------------------------------------------------------------
-- Match aggregated domain/ip lists
--------------------------------------------------------------------

-- domain entries: iterate; returns true on first match, nil if hit an
-- unevaluable kind (geosite/rule_set with no tool), false if none matched.
function M.match_domain_entries(entries, target)
	if not entries then return false end
	local unknown = false
	for _, e in ipairs(entries) do
		local r = M.domain_entry_match(e, target)
		if r == true then return true end
		if r == nil then unknown = true end
	end
	if unknown then return nil end
	return false
end

function M.match_ip_entries(entries, ip)
	if not entries then return false end
	local unknown = false
	for _, e in ipairs(entries) do
		local r = M.ip_entry_match(e, ip)
		if r == true then return true end
		if r == nil then unknown = true end
	end
	if unknown then return nil end
	return false
end

--------------------------------------------------------------------
-- Environment injection (set by controller / CLI harness)
--------------------------------------------------------------------

function M.set_env(env)
	if not env then return end
	M.exec = env.exec or M.exec
	M.geosite_match = env.geosite_match or M.geosite_match
	M.geoip_match = env.geoip_match or M.geoip_match
	M.rule_set_match = env.rule_set_match or M.rule_set_match
	M.shell_quote = env.shell_quote or M.shell_quote
end

--------------------------------------------------------------------
-- Decision logic
--------------------------------------------------------------------

local function rule_tag_of(rule)
	if type(rule) ~= "table" then return nil end
	return rule.ruleTag or rule.name or rule.remarks or rule.outbound or rule.outboundTag or rule.tag
end
M.rule_tag_of = rule_tag_of

-- Decide direction for an IP against system-level (nft/ipset) ACL semantics.
-- cfg: see controller for shape. nft_hit: function(set_name, ip) -> boolean
-- returns (decision, matched_set, note)
function M.system_ip_decision(cfg, ip, port, proto, nft_hit)
	local function hit(name)
		if not name then return false end
		if nft_hit then return nft_hit(name, ip) or false end
		return false
	end
	local is6 = M.is_ipv6(ip)

	local function decide_proxy_chain(found)
		-- drop-ports gate: if the port falls inside the drop list, the flow is
		-- rejected (block). Otherwise, only ports within the redir list get
		-- proxied; anything else falls through to a direct default.
		local drop = proto == "udp" and cfg.udp_proxy_drop_ports or cfg.tcp_proxy_drop_ports
		local redir = proto == "udp" and cfg.udp_redir_ports or cfg.tcp_redir_ports
		if port and drop ~= "disable" and M.port_match(port, drop) then
			return "block", found
		end
		if port and redir ~= "disable" and not M.port_match(port, redir) then
			return "direct", found
		end
		local mode = proto == "udp" and cfg.udp_proxy_mode or cfg.tcp_proxy_mode
		if mode == "disable" then return "direct", found end
		return "proxy", found
	end

	local suffix = is6 and "6" or ""
	-- static sets are named <base><suf>_static (e.g. psw_chn6_static)
	local function st(base) return base .. suffix .. "_static" end
	local function dy(base) return base .. suffix end
	-- 1. local/lan/vps/wan direct (target side)
	if hit(dy("psw_local")) or hit(dy("psw_lan")) or hit(dy("psw_vps")) or hit(dy("psw_wan")) then
		return "direct", "local/lan/vps/wan", nil
	end
	-- no-redir ports gate (return direct) happens before block/white in nft.
	local no_redir = proto == "udp" and cfg.udp_no_redir_ports or cfg.tcp_no_redir_ports
	if no_redir == "1:65535" then
		return "direct", "no_redir_ports (1:65535)", "不代理所有端口"
	end
	if port and M.port_match(port, no_redir) then
		return "direct", "no_redir_ports", nil
	end
	-- 2. block list
	if cfg.use_block_list == "1" then
		if hit(st("psw_block")) or hit(dy("psw_block")) then
			return "block", "psw_block", nil
		end
	end
	-- 3. direct list
	if cfg.use_direct_list == "1" then
		if hit(st("psw_white")) or hit(dy("psw_white")) then
			return "direct", "psw_white", nil
		end
	end
	-- special: fake ip (fakedns) is always proxied when enabled
	if cfg.use_fakedns == "1" then
		if ip:match("^198%.18%.") or (is6 and ip:match("^2001%:2%:")) then
			return "proxy", "fakedns", "FakeIP 命中，实际走向由代理客户端分流决定"
		end
	end
	-- 4. proxy chain
	if cfg.use_proxy_list == "1" then
		if hit(st("psw_black")) or hit(dy("psw_black")) then
			return decide_proxy_chain("psw_black")
		end
	end
	if cfg.use_gfw_list == "1" then
		if hit(dy("psw_gfw")) then
			return decide_proxy_chain("psw_gfw")
		end
	end
	if cfg.chn_list ~= "0" then
		if hit(st("psw_chn")) or hit(dy("psw_chn")) then
			if cfg.chn_list == "direct" then return "direct", "psw_chn" end
			return decide_proxy_chain("psw_chn")
		end
	end
	if cfg.use_shunt_node == "1" then
		if hit(st("psw_shunt")) or hit(dy("psw_shunt")) then
			return decide_proxy_chain("psw_shunt")
		end
	end
	-- 5. default (only redir ports are candidates for proxying by default)
	-- drop-ports gate applies unconditionally to the final default (nft has a
	-- catch-all reject for drop ports after the collection-based reject rules).
	local drop = proto == "udp" and cfg.udp_proxy_drop_ports or cfg.tcp_proxy_drop_ports
	if port and drop ~= "disable" and M.port_match(port, drop) then
		return "block", "default(drop_ports)", "端口命中屏蔽端口列表"
	end
	if not port then
		local mode = proto == "udp" and cfg.udp_proxy_mode or cfg.tcp_proxy_mode
		if mode == "disable" then return "direct", "default", nil end
		return "proxy", "default", "未指定端口，按默认代理模式判定"
	end
	local redir = proto == "udp" and cfg.udp_redir_ports or cfg.tcp_redir_ports
	if M.port_match(port, redir) then
		local mode = proto == "udp" and cfg.udp_proxy_mode or cfg.tcp_proxy_mode
		if mode == "disable" then return "direct", "default", nil end
		return "proxy", "default", nil
	end
	return "direct", "default", "端口不在代理端口列表内"
end

-- Decide direction for a domain against system-level rule files.
-- files: {block=path, direct=path, proxy=path, gfw=path, chn=path}
--  readfile: function(path) -> content string
-- returns (decision, matched_file, domain_rule_entry, note)
function M.system_domain_decision(cfg, domain, port, proto, files, readfile)
	local function from_file(kind, file)
		if not file then return nil end
		local content = readfile and readfile(file)
		if not content then return nil end
		for _, e in ipairs(M.parse_entries(content)) do
			-- rule file plain text means "domain + subdomains"
			local r = M.domain_entry_match(e, domain, { plain_suffix = true })
			if r == true then return true, e end
		end
		return false, nil
	end

	-- Apply the same port gating nft applies to proxy-list (domain) sets.
	local function proxy_gate(found, note)
		local drop = (proto or "tcp") == "udp" and cfg.udp_proxy_drop_ports or cfg.tcp_proxy_drop_ports
		if port and drop ~= "disable" and M.port_match(port, drop) then
			return "block", found, ("端口命中屏蔽端口列表，实际被屏蔽")
		end
		local redir = (proto or "tcp") == "udp" and cfg.udp_redir_ports or cfg.tcp_redir_ports
		if port and redir ~= "disable" and not M.port_match(port, redir) then
			return "direct", found, "端口不在代理端口列表内"
		end
		local mode = (proto or "tcp") == "udp" and cfg.udp_proxy_mode or cfg.tcp_proxy_mode
		if mode == "disable" then return "direct", found, nil end
		return "proxy", found, note
	end

	if cfg.use_block_list == "1" then
		local ok, e = from_file("block", files and files.block)
		if ok then return "block", "block_host", e, nil end
	end
	if cfg.use_direct_list == "1" then
		local ok, e = from_file("direct", files and files.direct)
		if ok then return "direct", "direct_host", e, nil end
	end
	if cfg.use_proxy_list == "1" then
		local ok, e = from_file("proxy", files and files.proxy)
		if ok then return proxy_gate("proxy_host", nil) end
	end
	if cfg.use_gfw_list == "1" then
		local ok, e = from_file("gfw", files and files.gfw)
		if ok then return proxy_gate("gfwlist", "命中 GFW 列表") end
	end
	if cfg.chn_list ~= "0" then
		local ok, e = from_file("chn", files and files.chn)
		if ok then
			if cfg.chn_list == "proxy" then return proxy_gate("chnlist", nil) end
			return "direct", "chnlist", e, nil
		end
	end
	return nil, nil, nil, nil
end

--------------------------------------------------------------------
-- Client (sing-box / xray) routing decision
--------------------------------------------------------------------

-- target: domain or IP. rules: sing-box route.rules or xray routing.rules,
-- final_out: final outbound tag (sing-box route.final / xray default).
-- kind: "singbox"|"xray"
-- returns: {matched=bool, outbound=tag, rule=remark, check="domain/ip/protocol/default", note}
function M.core_decision(kind, rules, target, final_out, opts)
	opts = opts or {}
	local is_domain = M.is_ip(target) == false
	local port = opts.port
	local proto = opts.proto or "tcp"
	local protocol = opts.protocol  -- optional sniffed protocol
	local tgt_domain = is_domain and M.norm_domain(target) or nil
	local tgt_ip = is_domain and nil or target
	local is6 = tgt_ip and M.is_ipv6(tgt_ip)

	local function rule_step(rule, i)
		-- returns outbound/nil, note
		local note = nil

		if kind == "singbox" then
			if rule.action and rule.action ~= "route" and rule.action ~= "reject" then
				return nil, nil, true -- skip unrelated (sniff/dns)
			end
			local out = rule.outbound
			if rule.action == "reject" then out = "block" end
			local invert = rule.invert == true
			local hit = false
			local evaluated = false

			local has_domain_cond = tgt_domain ~= nil
				and ((rule.domain and #rule.domain > 0)
					or (rule.domain_suffix and #rule.domain_suffix > 0)
					or (rule.domain_keyword and #rule.domain_keyword > 0)
					or (rule.domain_regex and #rule.domain_regex > 0))
			local has_ip_cond = tgt_ip ~= nil
				and ((rule.ip_cidr and #rule.ip_cidr > 0) or (rule.ip_is_private))

			-- domain match
			if has_domain_cond then
				evaluated = true
				local hit_domain = false
				if rule.domain and #rule.domain > 0 then
					for _, e in ipairs(rule.domain) do
						if M.norm_domain(e) == tgt_domain then hit_domain = true break end
					end
				end
				if rule.domain_suffix and #rule.domain_suffix > 0 then
					for _, e in ipairs(rule.domain_suffix) do
						if M.is_subdomain(tgt_domain, e) then hit_domain = true break end
					end
				end
				if rule.domain_keyword and #rule.domain_keyword > 0 then
					for _, e in ipairs(rule.domain_keyword) do
						if tgt_domain:find(e, 1, true) then hit_domain = true break end
					end
				end
				if rule.domain_regex and #rule.domain_regex > 0 then
					for _, e in ipairs(rule.domain_regex) do
						if M.regex_match(e, tgt_domain) then hit_domain = true break end
					end
				end
				if hit_domain then hit = true end
			end

			-- ip match
			if has_ip_cond then
				evaluated = true
				local ip_hit = false
				if rule.ip_cidr and #rule.ip_cidr > 0 then
					for _, e in ipairs(rule.ip_cidr) do
						if M.cidr_match(tgt_ip, e) then ip_hit = true break end
					end
				end
				if rule.ip_is_private and M.is_private_ip(tgt_ip) then ip_hit = true end
				if ip_hit then hit = true end
			end

			-- rule_set / geosite (external tools, injected via M.set_env or opts)
			if not hit then
				if (rule.rule_set and #rule.rule_set > 0) and (tgt_domain or tgt_ip) then
					for _, rs in ipairs(rule.rule_set) do
						local r
						if M.rule_set_match then
							r = M.rule_set_match(rs, tgt_domain or tgt_ip)
						elseif opts.rule_set_match then
							r = opts.rule_set_match(rs, tgt_domain or tgt_ip)
						end
						if r == true then hit = true evaluated = true
						elseif r == nil then note = "规则集[" .. rs .. "]无法判定（缺少工具），已跳过" end
					end
				end
			end

			-- port
			if hit and port then
				local okp = false
				if rule.port and #rule.port > 0 then
					for _, p in ipairs(rule.port) do if tonumber(p) == tonumber(port) then okp = true break end end
				end
				if not okp and rule.port_range and #rule.port_range > 0 then
					for _, r in ipairs(rule.port_range) do
						if M.port_match(port, r) then okp = true break end
					end
				end
				-- empty port condition => always match
				okp = (not rule.port or #rule.port == 0) and (not rule.port_range or #rule.port_range == 0) and true or okp
				if not okp then return nil, "端口不匹配", true end
			end

			-- protocol
			if hit and protocol and rule.protocol and #rule.protocol > 0 then
				local okpr = false
				for _, p in ipairs(rule.protocol) do
					if p == protocol then okpr = true break end
				end
				if not okpr then return nil, "协议不匹配", true end
			end

			-- network
			if hit and rule.network and #rule.network > 0 then
				local okn = false
				for _, n in ipairs(rule.network) do
					if n == proto then okn = true break end
				end
				if not okn then return nil, "网络类型不匹配", true end
			end

			-- invert: invert a rule that was evaluated against at least one
			-- condition but did NOT match -> it now matches.
			if invert then
				if evaluated and not hit then
					hit = true
					note = (note or "") .. " 反向规则取反命中"
				elseif hit then
					hit = false
				end
			end

			if hit then return out, note, false end
			if not evaluated then return nil, nil, false end
			return nil, nil, true
		elseif kind == "xray" then
			-- skip dns inbound rules
			if rule.inboundTag then
				local is_dns = false
				for _, it in ipairs(rule.inboundTag) do
					if it:find("dns") then is_dns = true break end
				end
				if is_dns then return nil, nil, true end
			end
			local out = rule.outboundTag
			if not out then return nil, nil, true end -- balancer etc, skip
			local has_domains = rule.domains and #rule.domains > 0
			local has_ip = rule.ip and #rule.ip > 0

			-- Rule applicability: a domain-condition rule is not applicable to
			-- an IP target (and vice versa). Pure conditions (only
			-- port/protocol/network, like the trailing default rule) match any
			-- target type.
			if has_domains and not tgt_domain then
				return nil, nil, true -- not applicable, keep scanning
			end
			if has_ip and not tgt_ip then
				return nil, nil, true
			end

			local hit = false
			local evaluated = false

			if has_domains then
				for _, e in ipairs(rule.domains) do
					local r = M.domain_entry_match(e, tgt_domain, { plain_suffix = true })
					if r == true then hit = true break end
					if r == nil then note = "geosite 无法判定（缺少工具）" end
				end
				evaluated = true
			end
			if not hit and has_ip then
				for _, e in ipairs(rule.ip) do
					if M.cidr_match(tgt_ip, e) then hit = true break end
				end
				-- geoip:/rule-set: entries are handled via ip_entry_match
				if not hit then
					for _, e in ipairs(rule.ip) do
						if e:find("geoip:", 1, true) == 1 or e:find("rule-set:", 1, true) == 1 or e:find("rs:", 1, true) == 1 then
							local r = M.ip_entry_match(e, tgt_ip)
							if r == true then hit = true break end
							if r == nil then note = "geoip/rule-set 无法判定（缺少工具）" end
						end
					end
				end
				evaluated = true
			end
			-- source rule: only applies to specific devices; cannot evaluate
			if not hit and rule.source and #rule.source > 0 then
				return nil, "来源IP限定规则，需指定设备", true
			end
			-- once a domain/ip condition has matched, verify the secondary
			-- conditions (port / protocol / network) like sing-box does.
			if hit then
				if rule.port and port and not M.port_match(port, rule.port) then
					return nil, "端口不匹配", true
				end
				if rule.protocol and #rule.protocol > 0 and protocol then
					local okp = false
					for _, p in ipairs(rule.protocol) do if p == protocol then okp = true break end end
					if not okp then return nil, "协议不匹配", true end
				end
				if rule.network and proto then
					local okn = rule.network:find(proto) ~= nil
					if not okn then return nil, "网络类型不匹配", true end
				end
				return out, note, false
			end
			if not hit and has_domains then
				return nil, nil, true -- domain rule evaluated & not matched
			end
			if not hit and has_ip then
				return nil, nil, true -- ip rule evaluated & not matched
			end
			if not hit then
				-- rule without domain/ip (pure condition rule, e.g. default).
				-- only meaningful if it has port/protocol/network; otherwise it
				-- is a generic fallback rule -> treat as candidate.
				if (rule.port) or (rule.protocol and #rule.protocol > 0) or (rule.network) then
					if rule.port and port and not M.port_match(port, rule.port) then
						return nil, "端口不匹配", true
					end
					if rule.protocol and #rule.protocol > 0 and protocol then
						local okp = false
						for _, p in ipairs(rule.protocol) do if p == protocol then okp = true break end end
						if not okp then return nil, "协议不匹配", true end
					end
					if rule.network and proto then
						local okn = rule.network:find(proto) ~= nil
						if not okn then return nil, "网络类型不匹配", true end
					end
					hit = true
					evaluated = true
				end
			end

			if not hit and not evaluated then
				return nil, nil, false
			end
			if evaluated and not hit then
				return nil, nil, true
			end
			return out, note, false
		end
		return nil, nil, false
	end

	local rule_no = 0
	for _, rule in ipairs(rules or {}) do
		rule_no = rule_no + 1
		local out, note, skipped = rule_step(rule, rule_no)
		if out then
			return { matched = true, outbound = out, rule = rule.ruleTag or rule_tag_of(rule), rule_no = rule_no, check = "matches", note = note }
		end
	end
	return { matched = false, outbound = final_out, rule = nil, check = "default", note = (final_out and "未命中任何规则，落入兜底" or nil) }
end

--------------------------------------------------------------------
-- Self-test
--------------------------------------------------------------------

function M.selftest()
	local pass, fail = 0, 0
	local function check(name, got, want)
		if got == want then
			pass = pass + 1
		else
			fail = fail + 1
			print("FAIL " .. name .. ": expected=" .. tostring(want) .. " got=" .. tostring(got))
		end
	end

	check("is_ipv4", M.is_ipv4("1.2.3.4"), true)
	check("is_ipv4.bad", M.is_ipv4("999.2.3.4"), false)
	check("is_ipv6", M.is_ipv6("2001:db8::1"), true)
	check("is_ipv6.short", M.is_ipv6("::1"), true)
	check("is_ipv6.not", M.is_ipv6("1.2.3.4"), false)
	check("norm_domain", M.norm_domain(".GooGle.com."), "google.com")
	check("is_subdomain", M.is_subdomain("www.google.com", "google.com"), true)
	check("is_subdomain.same", M.is_subdomain("google.com", "google.com"), true)
	check("is_subdomain.nope", M.is_subdomain("notgoogle.com", "google.com"), false) -- 'notgoogle.com' ends? check
	-- careful: is_subdomain("notgoogle.com","google.com") => suffix ".google.com"? "notgoogle.com" has no leading dot before google
	check("is_subdomain.dotfail", M.is_subdomain("abcgoogle.com", "google.com"), false)

	check("cidr.v4.in", M.cidr_match("192.168.1.5", "192.168.0.0/16"), true)
	check("cidr.v4.out", M.cidr_match("192.169.1.5", "192.168.0.0/16"), false)
	check("cidr.v4.bare", M.cidr_match("8.8.8.8", "8.8.8.8"), true)
	check("cidr.v6.in", M.cidr_match("2001:db8::1", "2001:db8::/32"), true)
	check("cidr.v6.out", M.cidr_match("2001:db9::1", "2001:db8::/32"), false)
	check("cidr.mask0", M.cidr_match("1.2.3.4", "0.0.0.0/0"), true)

	check("port.single", M.port_match(80, "80,443"), true)
	check("port.range", M.port_match(8080, "8000-8100"), true)
	check("port.colon", M.port_match(65535, "1:65535"), true)
	check("port.miss", M.port_match(81, "80,443"), false)
	check("port.any.nil", M.port_match(nil, "80,443"), true)

	check("kind.plain", M.get_entry_kind("google.com"), "plain")
	check("kind.domain", M.get_entry_kind("domain:google.com"), "domain")
	check("kind.full", M.get_entry_kind("full:google.com"), "full")
	check("kind.regexp", M.get_entry_kind("regexp:\\.goo"), "regexp")
	check("kind.geosite", M.get_entry_kind("geosite:cn"), "geosite")
	check("kind.geoip", M.get_entry_kind("geoip:cn"), "geoip")
	check("kind.geoip.private", M.get_entry_kind("geoip:private"), "geoip")
	check("kind.rule_set", M.get_entry_kind("rule-set:local:/tmp/x.srs"), "rule_set")
	check("kind.rs", M.get_entry_kind("rs:abc"), "rule_set")
	check("kind.keyword", M.get_entry_kind("keyword:abc"), "keyword")
	check("rs.name.full", M.rule_set_name("rule-set:local:/tmp/x.srs"), "local:/tmp/x.srs")
	check("rs.name.short", M.rule_set_name("rs:abc"), "abc")
	check("kind.comment", M.get_entry_kind("# c"), nil)

	check("entry.domain", M.domain_entry_match("domain:google.com", "www.google.com"), true)
	check("entry.full", M.domain_entry_match("full:google.com", "www.google.com"), false)
	check("entry.plain.sub", M.domain_entry_match("google", "www.google.com"), true)
	check("entry.plain.miss", M.domain_entry_match("example", "www.google.com"), false)

	-- regex via shell (no exec injected -> falls back to lua, returns bool)
	check("regex", M.regex_match("\\.goo.*\\.com$", "www.google.com"), true)

	check("private.ipv4", M.is_private_ip("192.168.0.1"), true)
	check("private.pub", M.is_private_ip("8.8.8.8"), false)
	check("private.v6", M.is_private_ip("fd00::1"), true)
	check("private.v6pub", M.is_private_ip("2001:4860::8888"), false)

	-- system_ip_decision
	local cfg = {
		use_block_list = "1", use_direct_list = "1", use_proxy_list = "1",
		use_gfw_list = "1", chn_list = "direct", use_shunt_node = "0",
		tcp_proxy_mode = "proxy", udp_proxy_mode = "proxy",
		tcp_no_redir_ports = "disable", udp_no_redir_ports = "disable",
		tcp_proxy_drop_ports = "disable", udp_proxy_drop_ports = "443",
		tcp_redir_ports = "1:65535", udp_redir_ports = "1:65535",
	}
	local sets = {}
	local nft_hit = function(name, ip) return sets[name] == true end
	sets["psw_black"] = true
	check("sys.proxy.black", (M.system_ip_decision(cfg, "1.1.1.1", 443, "tcp", nft_hit)), "proxy")
	sets["psw_black"] = nil
	sets["psw_white"] = true
	check("sys.direct.white", (M.system_ip_decision(cfg, "127.0.0.1", 443, "tcp", nft_hit)), "direct")
	sets["psw_white"] = nil
	sets["psw_block"] = true
	check("sys.block", (M.system_ip_decision(cfg, "9.9.9.9", 443, "tcp", nft_hit)), "block")
	sets["psw_block"] = nil
	check("sys.default.proxy", (M.system_ip_decision(cfg, "8.8.8.8", 443, "tcp", nft_hit)), "proxy")
	check("sys.default.direct-mode", (M.system_ip_decision({
		use_block_list = "1", use_direct_list = "1", use_proxy_list = "1",
		use_gfw_list = "1", chn_list = "direct", use_shunt_node = "0",
		tcp_proxy_mode = "disable", udp_proxy_mode = "disable",
		tcp_no_redir_ports = "disable", udp_no_redir_ports = "disable",
		tcp_proxy_drop_ports = "disable", udp_proxy_drop_ports = "443",
		tcp_redir_ports = "1:65535", udp_redir_ports = "1:65535",
	}, "8.8.8.8", 443, "tcp", nft_hit)), "direct")

	-- system_domain_decision
	local files = { block = "/b", direct = "/d", proxy = "/p", gfw = "/g", chn = "/c" }
	local readfile = function(path)
		if path == "/b" then return "blocked.com\n" end
		if path == "/d" then return "direct.example.com\n" end
		if path == "/p" then return "proxy.example.com\n" end
		if path == "/g" then return "google.com\n" end
		if path == "/c" then return "baidu.com\n" end
		return ""
	end
	local dec, f = M.system_domain_decision(cfg, "www.blocked.com", nil, "tcp", files, readfile)
	check("sysd.block", dec, "block")
	dec, f = M.system_domain_decision(cfg, "direct.example.com", nil, "tcp", files, readfile)
	check("sysd.direct", dec, "direct")
	dec, f = M.system_domain_decision(cfg, "sub.proxy.example.com", nil, "tcp", files, readfile)
	check("sysd.proxy", dec, "proxy")
	dec, f = M.system_domain_decision(cfg, "www.google.com", nil, "tcp", files, readfile)
	check("sysd.gfw", dec, "proxy")
	dec, f = M.system_domain_decision(cfg, "www.baidu.com", nil, "tcp", files, readfile)
	check("sysd.chn", dec, "direct")

	-- core_decision (sing-box style rules)
	local rules = {
		{ action = "route", domain_suffix = { "google.com" }, outbound = "myproxy" },
		{ action = "route", ip_cidr = { "10.0.0.0/8" }, outbound = "direct" },
	}
	local res = M.core_decision("singbox", rules, "www.google.com", "myproxy", {})
	check("core.domain.out", res.outbound, "myproxy")
	res = M.core_decision("singbox", rules, "10.1.2.3", "myproxy", {})
	check("core.ip.out", res.outbound, "direct")
	res = M.core_decision("singbox", rules, "example.net", "myproxy", {})
	check("core.final", res.outbound, "myproxy")
	check("core.final.matched", res.matched, false)

	print(string.format("selftest: %d passed, %d failed", pass, fail))
	return fail == 0
end

-- run self-test when executed as a script
if _G.arg and (arg[1] == "--selftest") then
	os.exit(M.selftest() and 0 or 1)
end

return M