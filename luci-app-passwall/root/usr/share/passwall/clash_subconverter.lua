#!/usr/bin/lua

-- Copyright(c): lwb1978 2025–2027

local api = require("luci.passwall.api")
local base64 = api.base64Encode
local json = api.jsonc

local domain_redir = {}

local function urlencode(value)
	return api.UrlEncode(value == nil and "" or tostring(value))
end

local function add_param(params, key, value)
	if value ~= nil and value ~= "" then
		if type(value) == "boolean" then value = value and "1" or "0" end
		params[#params + 1] = key .. "=" .. urlencode(value)
	end
end

local function build_ech(node)
	local opts = node["ech-opts"]
	if type(opts) ~= "table" or opts.enable ~= true then return nil end
	if opts.config and opts.config ~= "" then return opts.config end
	local name = opts["query-server-name"]
	if not name or name == "" then name = node.servername or node.sni or node.server end
	if name == "" then name = node.server end
	return name .. "+https://223.5.5.5/dns-query"
end

local function bandwidth_mbps(value)
	if value == nil then return nil end
	local number = tonumber(value)
	if number then return number end
	local amount, prefix, unit = tostring(value):match("^%s*(%d+)%s*([KMGT]?)([Bb])ps%s*$")
	local scales = { [""] = 1, K = 1000, M = 1000000, G = 1000000000, T = 1000000000000 }
	if not amount then return nil end
	return tonumber(amount) * scales[prefix] * (unit == "B" and 8 or 1) / 1000000
end

local function inherit(base, overrides)
	local result = {}
	for key, value in pairs(base or {}) do result[key] = value end
	for key, value in pairs(overrides or {}) do result[key] = value end
	return result
end

local function build_xhttp_extra(opts)
	local extra = {}
	local fields = {
		headers = "headers", ["x-padding-bytes"] = "xPaddingBytes",
		["no-grpc-header"] = "noGRPCHeader", ["x-padding-obfs-mode"] = "xPaddingObfsMode",
		["x-padding-key"] = "xPaddingKey", ["x-padding-header"] = "xPaddingHeader",
		["x-padding-placement"] = "xPaddingPlacement", ["x-padding-method"] = "xPaddingMethod",
		["uplink-http-method"] = "uplinkHTTPMethod", ["session-placement"] = "sessionIDPlacement",
		["session-key"] = "sessionIDKey", ["session-table"] = "sessionIDTable",
		["session-length"] = "sessionIDLength", ["seq-placement"] = "seqPlacement", ["seq-key"] = "seqKey",
		["uplink-data-placement"] = "uplinkDataPlacement", ["uplink-data-key"] = "uplinkDataKey",
		["uplink-chunk-size"] = "uplinkChunkSize", ["sc-max-each-post-bytes"] = "scMaxEachPostBytes",
		["sc-min-posts-interval-ms"] = "scMinPostsIntervalMs"
	}
	for source, target in pairs(fields) do extra[target] = opts[source] end
	-- jsonc treats empty tables as arrays and repeated table references as null.
	if type(extra.headers) == "table" then
		extra.headers = next(extra.headers) and inherit(extra.headers) or nil
	end
	local reuse = opts["reuse-settings"]
	if reuse then
		local xmux = {}
		local ranges = {
			["max-concurrency"] = "maxConcurrency", ["max-connections"] = "maxConnections",
			["c-max-reuse-times"] = "cMaxReuseTimes", ["h-max-request-times"] = "hMaxRequestTimes",
			["h-max-reusable-secs"] = "hMaxReusableSecs"
		}
		for source, target in pairs(ranges) do
			local value = reuse[source]
			if value ~= nil then xmux[target] = tonumber(value) or value end
		end
		xmux.hKeepAlivePeriod = tonumber(reuse["h-keep-alive-period"])
		if next(xmux) then extra.xmux = xmux end
	end
	return extra
end

local function host_format(host)
	if not host then return "" end
	local str = host:match("%[(.-)%]") or host
	if api.datatypes.ip6addr(str) then
		return "[" .. str .. "]"
	end
	return host
end

local function build_alpn(alpn)   -- 排序+去重
	if not alpn then return nil end

	local seen = {}
	local order = { "h3", "h2", "http/1.1" }

	if type(alpn) == "table" then
		for _, v in ipairs(alpn) do
			if v then seen[v] = true end
		end
	else
		seen[tostring(alpn)] = true
	end

	local t = {}
	for _, v in ipairs(order) do
		if seen[v] then table.insert(t, v) end
	end

	if #t == 0 then return nil end
	return table.concat(t, ",")
end

local function build_common(node)
	local o = {}

	o.server = host_format(node.server)
	o.port = node.port
	o.name = node.name

	-- ===== TLS =====
	o.tls = {}

	if node["reality-opts"] then
		o.tls.security = "reality"
		o.tls.pbk = node["reality-opts"]["public-key"]
		o.tls.sid = node["reality-opts"]["short-id"]
	elseif node.tls then
		o.tls.security = "tls"
	end

	o.tls.sni = node.servername or node.sni
	o.tls.fp = node["client-fingerprint"]
	o.tls.pcs = node.fingerprint
	o.tls.vcn = node["name-cert-verify"]
	o.tls.insecure = node["skip-cert-verify"] == true

	o.tls.alpn = build_alpn(node.alpn)

	o.tls.ech = build_ech(node)

	-- ===== transport =====
	o.transport = {}
	local net = node.network or "tcp"
	o.transport.type = net

	local function get_first(v)
		if type(v) == "table" then return v[1] end
		return v
	end

	if net == "ws" then
		local opts = node["ws-opts"]
		if opts then
			local path = opts.path or "/"
			if opts["v2ray-http-upgrade"] ~= true and opts["max-early-data"] then
				path = path .. (path:find("?", 1, true) and "&ed=" or "?ed=") .. opts["max-early-data"]
			end
			if opts["v2ray-http-upgrade"] ~= true and opts["early-data-header-name"] then
				path = path .. (path:find("?", 1, true) and "&eh=" or "?eh=") .. opts["early-data-header-name"]
			end
			o.transport.path = path
			o.transport.host = opts.headers and opts.headers.Host
			if opts["v2ray-http-upgrade"] == true then o.transport.type = "httpupgrade" end
		end

	elseif net == "grpc" then
		local opts = node["grpc-opts"]
		if opts then
			o.transport.serviceName = opts["grpc-service-name"]
		end

	elseif net == "http" then
		-- Use TCP + HTTP camouflage so each core selects its matching transport.
		o.transport.type = "tcp"
		o.transport.headerType = "http"
		o.transport.host = node.server
		o.transport.path = "/"
		local opts = node["http-opts"]
		if opts then
			-- Clash http-opts carries the camouflage Host under headers.Host
			-- (a list), like ws-opts; opts.host is not standard for http.
			o.transport.host = get_first(opts.host) or (opts.headers and get_first(opts.headers.Host)) or o.transport.host
			o.transport.path = get_first(opts.path) or o.transport.path
		end

	elseif net == "h2" then
		local opts = node["h2-opts"]
		if opts then
			o.transport.host = get_first(opts.host)
			o.transport.path = opts.path
		end

	elseif net == "xhttp" then
		local opts = node["xhttp-opts"]
		if opts then
			o.transport.host = opts.host
			o.transport.path = opts.path
			o.transport.mode = opts.mode

			local extra = build_xhttp_extra(opts)

			-- download-settings
			if opts["download-settings"] then
				local d = opts["download-settings"]
				local effective = inherit(node, d)
				local ds = {
					address = domain_redir[effective.server] or effective.server,
					port = effective.port,
					network = "xhttp",
					security = effective.tls and "tls" or "none"
				}
				local sni = effective.servername or effective.sni or effective.server
				local alpn = build_alpn(effective.alpn)
				if effective.tls or effective["reality-opts"] then
					ds.tlsSettings = {
						serverName = sni,
						allowInsecure = effective["skip-cert-verify"] == true,
						fingerprint = effective["client-fingerprint"],
						pinnedPeerCertSha256 = effective.fingerprint and api.sha256_sb_xray(effective.fingerprint) or nil,
						verifyPeerCertByName = effective["name-cert-verify"],
						alpn = alpn and api.split(alpn, ",") or nil,
						echConfigList = build_ech(effective)
					}
					local reality = effective["reality-opts"]
					if reality then
						ds.security = "reality"
						ds.realitySettings = {
							serverName = sni, fingerprint = effective["client-fingerprint"] or "chrome",
							publicKey = reality["public-key"], shortId = reality["short-id"] or ""
						}
						ds.tlsSettings = nil
					end
				end
				local xs = build_xhttp_extra(inherit(opts, d))
				xs.path = d.path or opts.path or "/"
				xs.host = d.host or opts.host or sni
				xs.mode = opts.mode or "auto"
				ds.xhttpSettings = xs

				extra.downloadSettings = ds
			end

			if next(extra) then
				o.transport.extra = json.stringify(extra)
			end
		end
	end

	return o
end

-- VLESS
local function encode_vless(node)
	local o = build_common(node)

	local link = "vless://" .. node.uuid .. "@" .. o.server .. ":" .. o.port
	local p = {}

	if type(node.flow) == "string" and node.flow:sub(1, 5) == "xtls-" then add_param(p, "flow", node.flow) end
	add_param(p, "encryption", node.encryption)

	-- TLS
	add_param(p, "security", o.tls.security)
	add_param(p, "pbk", o.tls.pbk)
	add_param(p, "sid", o.tls.sid)
	add_param(p, "sni", o.tls.sni)
	add_param(p, "fp", o.tls.fp)
	add_param(p, "alpn", o.tls.alpn)
	add_param(p, "ech", o.tls.ech)
	add_param(p, "pcs", o.tls.pcs)
	add_param(p, "vcn", o.tls.vcn)
	add_param(p, "allowInsecure", o.tls.insecure)

	-- transport
	add_param(p, "type", o.transport.type)
	add_param(p, "headerType", o.transport.headerType)
	add_param(p, "host", o.transport.host)
	add_param(p, "path", o.transport.path)
	add_param(p, "serviceName", o.transport.serviceName)
	add_param(p, "mode", o.transport.mode)
	add_param(p, "extra", o.transport.extra)

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(o.name or "")
end

-- Trojan
local function encode_trojan(node)
	local o = build_common(node)

	local link = "trojan://" .. urlencode(node.password) .. "@" .. o.server .. ":" .. o.port
	local p = {}

	add_param(p, "security", o.tls.security)
	add_param(p, "pbk", o.tls.pbk)
	add_param(p, "sid", o.tls.sid)
	add_param(p, "sni", o.tls.sni)
	add_param(p, "fp", o.tls.fp)
	add_param(p, "alpn", o.tls.alpn)
	add_param(p, "ech", o.tls.ech)
	add_param(p, "pcs", o.tls.pcs)
	add_param(p, "vcn", o.tls.vcn)
	add_param(p, "allowInsecure", o.tls.insecure)
	add_param(p, "type", o.transport.type)
	add_param(p, "headerType", o.transport.headerType)
	add_param(p, "host", o.transport.host)
	add_param(p, "path", o.transport.path)
	add_param(p, "serviceName", o.transport.serviceName)

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(o.name or "")
end

-- VMess
local function encode_vmess(node)
	local o = build_common(node)

	local obj = {
		v = "2",
		ps = o.name,
		add = node.server,
		port = tostring(node.port),
		id = node.uuid,
		aid = tostring(node.alterId or 0),
		net = o.transport.type,
		security = node.cipher,
		scy = node.cipher,
		type = o.transport.headerType or "none",
		host = o.transport.host or "",
		path = urlencode(o.transport.path or ""),
		tls = o.tls.security == "tls" and "tls" or "",
		sni = o.tls.sni,
		alpn = o.tls.alpn,
		fp = o.tls.fp,
		ech = o.tls.ech,
		pcs = o.tls.pcs,
		vcn = o.tls.vcn,
		insecure = o.tls.insecure and "1" or "0",
		tfo = node.tfo and "1" or "0"
	}

	if o.transport.type == "grpc" then
		obj.path = urlencode(o.transport.serviceName or "")
	end

	return 0, "vmess://" .. base64(json.stringify(obj))
end

-- SS
local function encode_ss(node)
	local ss_method = {
		["none"]=1, ["aes-128-gcm"]=1, ["aes-192-gcm"]=1, ["aes-256-gcm"]=1, ["chacha20-ietf-poly1305"]=1, ["xchacha20-ietf-poly1305"]=1, ["2022-blake3-aes-128-gcm"]=1, ["2022-blake3-aes-256-gcm"]=1, ["2022-blake3-chacha20-poly1305"]=1,
		["aes-128-ctr"]=1, ["aes-192-ctr"]=1, ["aes-256-ctr"]=1, ["aes-128-cfb"]=1, ["aes-192-cfb"]=1, ["aes-256-cfb"]=1, ["rc4-md5"]=1, ["chacha20-ietf"]=1, ["xchacha20"]=1,
	}
	if not ss_method[node.cipher or ""] then
		return 1, "订阅转换 → 丢弃 SS 节点：" .. (node.name or "") .. "，因 Core 不支持 " .. (node.cipher or "") .. " 加密方式"
	end

	local userinfo = node.cipher .. ":" .. node.password
	local base = userinfo .. "@" .. host_format(node.server) .. ":" .. node.port
	local link = "ss://" .. base64(base)

	local p = {}

	if node.udp then add_param(p, "udp", true) end
	if node["udp-over-tcp"] then add_param(p, "uot", true) end

	if node.plugin then
		local plugin = (node.plugin == "obfs") and "obfs-local" or node.plugin
		if plugin == "shadow-tls" then
			local shadow_tls = base64(json.stringify(node["plugin-opts"] or {}))
			add_param(p, "shadow-tls", shadow_tls)
		elseif plugin == "obfs-local" or plugin == "v2ray-plugin" then
			local opts = {}
			for k, v in pairs(node["plugin-opts"] or {}) do
				if plugin == "obfs-local" then
					if k == "mode" then k = "obfs" end
					if k == "host" then k = "obfs-host" end
				elseif plugin == "v2ray-plugin" then
					if k == "mode" and v == "websocket" then
						v = nil
					elseif type(v) == "boolean" then
						if v == true then
							table.insert(opts, k)
						end
						v = nil
					end
				end
				if v ~= nil then
					if type(v) == "boolean" then
						v = v and "1" or "0"
					end
					table.insert(opts, k .. "=" .. v)
				end
			end
			if #opts > 0 then plugin = plugin .. ";" .. table.concat(opts, ";") end
			add_param(p, "plugin", plugin)
		else
			return 1, "订阅转换 → 丢弃 SS 节点：" .. (node.name or "") .. "，因 Core 不支持 " .. plugin .. " 插件"
		end
	end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(node.name or "")
end

-- Hysteria
local function encode_hysteria(node)
	if node.protocol and node.protocol ~= "udp" then
		return 1, "订阅转换 → 丢弃 Hysteria 节点：" .. node.name .. "，当前 Core 不支持 " .. node.protocol .. " 传输"
	end
	local link = "hysteria://" .. host_format(node.server) .. ":" .. (node.port or "")
	local p = {}

	add_param(p, "auth", node["auth-str"])
	add_param(p, "mport", node.ports)
	add_param(p, "obfsParam", node.obfs)
	add_param(p, "sni", node.sni)
	add_param(p, "upmbps", bandwidth_mbps(node.up))
	add_param(p, "downmbps", bandwidth_mbps(node.down))
	add_param(p, "insecure", node["skip-cert-verify"] == true)
	add_param(p, "vcn", node["name-cert-verify"])
	add_param(p, "pinSHA256", node.fingerprint)

	add_param(p, "alpn", build_alpn(node.alpn))

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(node.name or "")
end

-- Hysteria2
local function encode_hysteria2(node)
	-- Hopping subscriptions may omit port; keep a valid fallback for all cores.
	local port = node.port or tostring(node.ports or ""):match("^%s*(%d+)")
	local link = "hysteria2://" .. urlencode(node.password or "") .. "@" .. host_format(node.server) .. ":" .. port
	local p = {}

	add_param(p, "mport", node.ports)
	add_param(p, "hopInterval", node["hop-interval"])
	add_param(p, "obfs", node.obfs)
	add_param(p, "obfs-password", node["obfs-password"])
	add_param(p, "minPacketSize", node["obfs-min-packet-size"])
	add_param(p, "maxPacketSize", node["obfs-max-packet-size"])
	add_param(p, "upmbps", bandwidth_mbps(node.up))
	add_param(p, "downmbps", bandwidth_mbps(node.down))
	add_param(p, "ech", build_ech(node))
	add_param(p, "vcn", node["name-cert-verify"])
	add_param(p, "sni", node.sni)
	add_param(p, "insecure", node["skip-cert-verify"] == true)
	add_param(p, "pinSHA256", node.fingerprint)

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(node.name or "")
end

-- TUIC
local function encode_tuic(node)
	if node.token then
		return 1, "订阅转换 → 丢弃 TUIC 节点：" .. node.name .. "，当前 Core 不支持 TUIC v4"
	end
	if not node.uuid or node.password == nil then
		return 1, "订阅转换 → 丢弃 TUIC 节点：" .. node.name .. "，认证信息不完整。"
	end
	local link = "tuic://" .. urlencode(node.uuid) .. ":" .. urlencode(node.password) .. "@" .. host_format(node.server) .. ":" .. node.port
	local p = {}

	add_param(p, "congestion_control", node["congestion-controller"])
	add_param(p, "alpn", build_alpn(node.alpn))
	add_param(p, "sni", node.sni)
	if node["disable-sni"] then add_param(p, "disable_sni", true) end
	add_param(p, "allowInsecure", node["skip-cert-verify"] == true)
	add_param(p, "udp_relay_mode", node["udp-relay-mode"])
	add_param(p, "pcs", node.fingerprint)
	add_param(p, "vcn", node["name-cert-verify"])

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(node.name or "")
end

-- AnyTLS
local function encode_anytls(node)
	local err_msg
	if node["shadow-tls-opts"] then
		err_msg = "ShadowTLS"
	elseif node["restls-opts"] then
		err_msg = "ResTLS"
	elseif node["jls-opts"] then
		err_msg = "JLS"
	end
	if err_msg then
		err_msg = "订阅转换 → 丢弃 AnyTLS 节点：" .. (node.name or "") .. "，因 Sing-Box 不支持 AnyTLS + " .. err_msg
		return 1, err_msg
	end

	local o = build_common(node)

	local link = "anytls://" .. urlencode(node.password or "") .. "@" .. host_format(node.server) .. ":" .. node.port
	local p = {}

	add_param(p, "security", o.tls.security)
	add_param(p, "pbk", o.tls.pbk)
	add_param(p, "sid", o.tls.sid)
	add_param(p, "sni", o.tls.sni)
	add_param(p, "alpn", o.tls.alpn)
	add_param(p, "fp", o.tls.fp)
	add_param(p, "ech", o.tls.ech)
	add_param(p, "pcs", o.tls.pcs)
	add_param(p, "insecure", o.tls.insecure)

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(node.name or "")
end

-- SSR
local function encode_ssr(node)
	local link = host_format(node.server) .. ":" .. node.port .. ":" .. (node.protocol or "") .. ":" ..
			(node.cipher or "") .. ":" .. (node.obfs or "") .. ":" .. base64(node.password)
	local p = {}

	if node["obfs-param"] then table.insert(p, "obfsparam=" .. base64(node["obfs-param"])) end
	if node["protocol-param"] then table.insert(p, "protoparam=" .. base64(node["protocol-param"])) end
	table.insert(p, "remarks=" .. base64(node.name))

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, "ssr://" .. base64(link)
end

-- snell
local function encode_snell(node)
	local err_msg
	local obfs = node["obfs-opts"] or {}
	if obfs.mode and obfs.mode ~= "http" and obfs.mode ~= "none" then
		err_msg = obfs.mode
	end
	if err_msg then
		err_msg = "订阅转换 → 丢弃 Snell 节点：" .. (node.name or "") .. "，因 Sing-Box 不支持 Snell + " .. err_msg
		return 1, err_msg
	end
	local version = node.version and tonumber(node.version) or 4
	version = (version == 5) and 4 or version
	if version < 4 then
		err_msg = "订阅转换 → 丢弃 Snell 节点：" .. (node.name or "") .. "，因 Sing-Box 不支持 Snell 版本小于 4"
		return 1, err_msg
	end

	local link = "snell://" .. host_format(node.server) .. ":" .. node.port
	local p = {}

	add_param(p, "psk", node.psk)
	add_param(p, "version", version)
	if obfs.mode == "http" then
		add_param(p, "obfs", "http")
		add_param(p, "obfs-host", obfs.host)
	end
	add_param(p, "reuse", node.reuse and "1" or "0")

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return 0, link .. "#" .. urlencode(node.name or "")
end

local function encode_node(node)
	if type(node) ~= "table" or not node.type or not node.name then
		return 1, "订阅转换 → 跳过格式不完整的节点。"
	end
	if not node.server or node.server == "" or not (node.port or (node.type == "hysteria2" and node.ports)) then
		return 1, "订阅转换 → 丢弃节点：" .. tostring(node.name) .. "，节点信息不完整。"
	end
	node = inherit(node)

	local t = node.type
	if t == "hysteria" or t == "hysteria2" then
		local up, down = bandwidth_mbps(node.up), bandwidth_mbps(node.down)
		if (node.up ~= nil and up == nil) or (node.down ~= nil and down == nil) then
			return 1, "订阅转换 → 丢弃节点：" .. tostring(node.name) .. "，带宽格式不正确。"
		end
		node.up, node.down = up, down
	end

	node.server = domain_redir[node.server] or node.server

	if t == "vless" then return encode_vless(node)
	elseif t == "trojan" then return encode_trojan(node)
	elseif t == "vmess" then return encode_vmess(node)
	elseif t == "ss" then return encode_ss(node)
	elseif t == "hysteria" then return encode_hysteria(node)
	elseif t == "hysteria2" then return encode_hysteria2(node)
	elseif t == "tuic" then return encode_tuic(node)
	elseif t == "anytls" then return encode_anytls(node)
	elseif t == "ssr" then return encode_ssr(node)
	elseif t == "snell" then return encode_snell(node)
	else api.log("订阅转换 → 丢弃不支持的节点：" .. node.name .. "，节点类型：" .. t)
	end
end

local function parse_dns_endpoint(value)
	if type(value) ~= "string" then return nil end
	value = api.trim(value)
	-- Clash fragments and URL queries cannot be preserved by both node DNS backends.
	if value == "" or value:find("[%s#?@,]") then return nil end
	local url = value:find("://", 1, true) and value or "udp://" .. value
	local ok, endpoint = pcall(api.parseURL, url)
	if not ok or not endpoint then return nil end
	local protocol = endpoint.protocol
	if protocol ~= "udp" and protocol ~= "tcp" and protocol ~= "https" then return nil end
	local host = endpoint.hostname
	if not host or not (api.is_ip(host) or api.datatypes.hostname(host)) then return nil end
	local bracketed = endpoint.host:sub(1, 1) == "["
	local ipv6 = api.datatypes.ip6addr(host)
	if bracketed and not ipv6 then return nil end
	if protocol == "https" and ipv6 and not bracketed then return nil end
	local port = endpoint.port or (protocol == "https" and 443 or 53)
	if port < 1 or port > 65535 then return nil end
	if protocol ~= "https" and endpoint.pathname then return nil end
	return { protocol = protocol, host = host:lower():gsub("%.$", ""), port = port, url = url }
end

local function is_loopback_dns(host)
	return host == "localhost" or (api.datatypes.ip4addr(host) and host:match("^127%.")) or host:match("^[0:]+:0*1$")
end

local function is_unspecified_dns(host)
	return host == "0.0.0.0" or host:match("^[0:]+$")
end

local function extract_clash_dns(data)
	local dns = data.dns
	if type(dns) ~= "table" or not dns["proxy-server-nameserver"] then return nil end
	-- A subscription-wide resolver cannot represent per-domain node DNS policies.
	local node_policy = dns["proxy-server-nameserver-policy"]
	if type(node_policy) == "table" and next(node_policy) then return nil end
	local listener = parse_dns_endpoint(dns.listen)
	local resolving = {}
	local policy = dns["nameserver-policy"]
	local has_policy = type(policy) == "table" and next(policy)
	local function pick(candidates, depth)
		if depth > 4 then return nil end
		if type(candidates) == "string" then candidates = { candidates } end
		if type(candidates) ~= "table" then return nil end
		for _, value in ipairs(candidates) do
			local endpoint = parse_dns_endpoint(value)
			if endpoint and not is_unspecified_dns(endpoint.host) then
				if is_loopback_dns(endpoint.host) then
					local key = endpoint.protocol .. "://" .. endpoint.host .. ":" .. endpoint.port
					local listen_matches = listener and listener.protocol ~= "https" and listener.port == endpoint.port and (
						listener.host == endpoint.host or
						(listener.host == "0.0.0.0" and not endpoint.host:find(":", 1, true)) or
						(is_unspecified_dns(listener.host) and listener.host ~= "0.0.0.0" and endpoint.host:find(":", 1, true)) or
						(endpoint.host == "localhost" and is_loopback_dns(listener.host)))
					if endpoint.protocol ~= "https" and dns.enable == true and listen_matches and not resolving[key] and not has_policy then
						resolving[key] = true
						local resolver = pick(dns.nameserver, depth + 1)
						resolving[key] = nil
						if resolver then return resolver end
					end
				elseif endpoint.protocol == "https" then
					return { domain_resolver = "https", domain_resolver_dns_https = endpoint.url }
				elseif api.datatypes.ip4addr(endpoint.host) then
					return { domain_resolver = endpoint.protocol, domain_resolver_dns = endpoint.host .. ":" .. endpoint.port }
				end
			end
		end
	end
	local resolver = pick(dns["proxy-server-nameserver"], 0)
	if resolver then
		local address = resolver.domain_resolver_dns_https or resolver.domain_resolver .. "://" .. resolver.domain_resolver_dns
		api.log("订阅转换 → 已提取节点域名 DNS：" .. address)
	end
	return resolver
end

function parseClashNode(raw, remark, auto_dns)
	if not raw then return "" end
	domain_redir = {}
	local ok, lyaml = pcall(require, "lyaml")
	if not ok then return raw end

	local parsed, data = pcall(lyaml.load, raw)
	if not parsed then
		api.log('订阅转换 → YAML 解析失败：' .. tostring(remark or ""))
		return ""
	end
	if not data or type(data) ~= "table" then return raw end
	if type(data.proxies) ~= "table" then return "" end

	api.log('检测到 Clash 订阅，正在进行转换 ...')

	-- Some airports use hosts domain redirect to disguise the real node domain name.
	for k, v in pairs(type(data.hosts) == "table" and data.hosts or {}) do
		if type(k) == "string" and type(v) == "string" then
			if api.datatypes.hostname(k) and api.datatypes.hostname(v) then
				domain_redir[k] = v
			end
		end
	end

	local links = {}
	for _, node in ipairs(data.proxies) do
		local converted, err, link = pcall(encode_node, node)
		if not converted then
			local name = type(node) == "table" and node.name or ""
			api.log('订阅转换 → 丢弃节点：' .. tostring(name or "") .. '，转换失败，已跳过。')
		elseif err == 1 and link then
			api.log(link)
		elseif link then
			table.insert(links, link)
		end
	end

	local resolver = #links > 0 and auto_dns and extract_clash_dns(data) or nil
	return #links > 0 and table.concat(links, "\n") or "", resolver
end

function parse_clash_sub_info(headers)
	local userinfo = headers:match("[Ss]ubscription%-userinfo:%s*([^\r\n]+)")
	if not userinfo then return nil end

	local upload = tonumber(userinfo:match("upload=(%d+)")) or 0
	local download = tonumber(userinfo:match("download=(%d+)")) or 0
	local total = tonumber(userinfo:match("total=(%d+)")) or 0
	local expire = tonumber(userinfo:match("expire=(%d+)"))
	local remain = total - (upload + download)
	if remain < 0 then remain = 0 end

	local function format_size(bytes)
		local units = { "B", "KB", "MB", "GB", "TB", "PB" }
		local i = 1
		while bytes >= 1024 and i < #units do
			bytes = bytes / 1024
			i = i + 1
		end
		if bytes >= 100 then
			return string.format("%.0f%s", bytes, units[i])
		elseif bytes >= 10 then
			return string.format("%.1f%s", bytes, units[i])
		else
			return string.format("%.2f%s", bytes, units[i])
		end
	end

	local rem_traffic = format_size(remain)

	local expired_date
	if expire and expire > 0 then
		local t = os.date("*t", expire)
		expired_date = string.format("%d-%d-%d", t.year, t.month, t.day)
	else
		expired_date = "长期有效"
	end

	return {
		rem_traffic = rem_traffic,
		expired_date = expired_date
	}
end
