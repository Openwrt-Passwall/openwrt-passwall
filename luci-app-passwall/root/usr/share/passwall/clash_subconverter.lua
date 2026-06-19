#!/usr/bin/lua

-- Copyright(c): lwb1978 2025–2027

local api = require("luci.passwall.api")
local urlencode = api.UrlEncode
local base64 = api.base64Encode
local json = api.jsonc

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
	o.tls.insecure = node["skip-cert-verify"] == true

	o.tls.alpn = build_alpn(node.alpn)

	local ech_opts = node["ech-opts"]
	if ech_opts and ech_opts.enable == true then
		if ech_opts["query-server-name"] then
			o.tls.ech = ech_opts["query-server-name"] .. "+https://223.5.5.5/dns-query"
		elseif ech_opts.config then
			o.tls.ech = ech_opts.config
		end
	end

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
			o.transport.path = opts.path
			o.transport.host = opts.headers and opts.headers.Host
		end

	elseif net == "grpc" then
		local opts = node["grpc-opts"]
		if opts then
			o.transport.serviceName = opts["grpc-service-name"]
		end

	elseif net == "http" then
		local opts = node["http-opts"]
		if opts then
			-- Clash http-opts carries the camouflage Host under headers.Host
			-- (a list), like ws-opts; opts.host is not standard for http.
			o.transport.host = get_first(opts.host) or (opts.headers and get_first(opts.headers.Host))
			o.transport.path = get_first(opts.path)
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

			local extra = {}

			-- headers
			if opts.headers then
				extra.headers = opts.headers
			end

			if opts["x-padding-bytes"] then
				extra.xPaddingBytes = opts["x-padding-bytes"]
			end

			if opts["no-grpc-header"] ~= nil then
				extra.noGRPCHeader = opts["no-grpc-header"]
			end

			if opts["sc-max-each-post-bytes"] then
				extra.scMaxEachPostBytes = opts["sc-max-each-post-bytes"]
			end

			if opts["sc-min-posts-interval-ms"] then
				extra.scMinPostsIntervalMs = opts["sc-min-posts-interval-ms"]
			end

			-- xmux
			if opts["reuse-settings"] then
				local r = opts["reuse-settings"]
				local xmux = {}

				if r["max-concurrency"] then xmux.maxConcurrency = r["max-concurrency"] end
				if r["max-connections"] then xmux.maxConnections = tonumber(r["max-connections"]) end
				if r["c-max-reuse-times"] then xmux.cMaxReuseTimes = tonumber(r["c-max-reuse-times"]) end
				if r["h-max-request-times"] then xmux.hMaxRequestTimes = r["h-max-request-times"] end
				if r["h-max-reusable-secs"] then xmux.hMaxReusableSecs = r["h-max-reusable-secs"] end
				if r["h-keep-alive-period"] then xmux.hKeepAlivePeriod = tonumber(r["h-keep-alive-period"]) end

				if next(xmux) then extra.xmux = xmux end
			end

			-- download-settings
			if opts["download-settings"] then
				local d = opts["download-settings"]
				local ds = {}

				if d.server then ds.address = d.server end
				if d.port then ds.port = d.port end

				ds.network = "xhttp"

				-- TLS
				if d.tls then
					ds.security = "tls"
					ds.tlsSettings = {}

					if d.servername then
						ds.tlsSettings.serverName = d.servername
					end
					if d["skip-cert-verify"] == true then
						ds.tlsSettings.allowInsecure = true
					end
					if d["client-fingerprint"] then
						ds.tlsSettings.fingerprint = d["client-fingerprint"]
					end
					if d.fingerprint then
						ds.tlsSettings.pinnedPeerCertSha256 = d.fingerprint
					end
					if d.alpn then
						ds.tlsSettings.alpn = d.alpn
					end
				end

				-- xhttpSettings
				local xs = {}

				if d.path then xs.path = d.path end
				if d.host then xs.host = d.host end

				if next(xs) then
					ds.xhttpSettings = xs
				end

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

	if node.flow then table.insert(p, "flow=" .. urlencode(node.flow)) end
	if node.encryption then table.insert(p, "encryption=" .. urlencode(node.encryption)) end

	-- TLS
	if o.tls.security then table.insert(p, "security=" .. o.tls.security) end
	if o.tls.pbk then table.insert(p, "pbk=" .. urlencode(o.tls.pbk)) end
	if o.tls.sid then table.insert(p, "sid=" .. urlencode(o.tls.sid)) end
	if o.tls.sni then table.insert(p, "sni=" .. urlencode(o.tls.sni)) end
	if o.tls.fp then table.insert(p, "fp=" .. urlencode(o.tls.fp)) end
	if o.tls.alpn then table.insert(p, "alpn=" .. urlencode(o.tls.alpn)) end
	if o.tls.ech then table.insert(p, "ech=" .. urlencode(o.tls.ech)) end
	if o.tls.pcs then table.insert(p, "pcs=" .. urlencode(o.tls.pcs)) end
	table.insert(p, "allowInsecure=" .. (o.tls.insecure and "1" or "0"))

	-- transport
	table.insert(p, "type=" .. o.transport.type)
	if o.transport.host then table.insert(p, "host=" .. urlencode(o.transport.host)) end
	if o.transport.path then table.insert(p, "path=" .. urlencode(o.transport.path)) end
	if o.transport.serviceName then table.insert(p, "serviceName=" .. urlencode(o.transport.serviceName)) end
	if o.transport.mode then table.insert(p, "mode=" .. urlencode(o.transport.mode)) end
	if o.transport.extra then table.insert(p, "extra=" .. urlencode(o.transport.extra)) end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return link .. "#" .. urlencode(o.name or "")
end

-- Trojan
local function encode_trojan(node)
	local o = build_common(node)

	local link = "trojan://" .. node.password .. "@" .. o.server .. ":" .. o.port
	local p = {}

	if o.tls.security then table.insert(p, "security=" .. o.tls.security) end
	if o.tls.pbk then table.insert(p, "pbk=" .. urlencode(o.tls.pbk)) end
	if o.tls.sid then table.insert(p, "sid=" .. urlencode(o.tls.sid)) end
	if o.tls.sni then table.insert(p, "sni=" .. urlencode(o.tls.sni)) end
	if o.tls.fp then table.insert(p, "fp=" .. urlencode(o.tls.fp)) end
	if o.tls.alpn then table.insert(p, "alpn=" .. urlencode(o.tls.alpn)) end
	if o.tls.ech then table.insert(p, "ech=" .. urlencode(o.tls.ech)) end
	if o.tls.pcs then table.insert(p, "pcs=" .. urlencode(o.tls.pcs)) end
	table.insert(p, "allowInsecure=" .. (o.tls.insecure and "1" or "0"))

	table.insert(p, "type=" .. o.transport.type)
	if o.transport.host then table.insert(p, "host=" .. urlencode(o.transport.host)) end
	if o.transport.path then table.insert(p, "path=" .. urlencode(o.transport.path)) end
	if o.transport.serviceName then table.insert(p, "serviceName=" .. urlencode(o.transport.serviceName)) end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return link .. "#" .. urlencode(o.name or "")
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
		type = "none",
		host = o.transport.host or "",
		path = o.transport.path or "",
		tls = o.tls.security == "tls" and "tls" or "",
		sni = o.tls.sni,
		alpn = o.tls.alpn,
		fp = o.tls.fp,
		ech = o.tls.ech,
		pcs = o.tls.pcs,
		insecure = o.tls.insecure and "1" or "0",
		tfo = node.tfo and "1" or "0"
	}

	if o.transport.type == "grpc" then
		obj.path = o.transport.serviceName or ""
	end

	return "vmess://" .. base64(json.stringify(obj))
end

-- SS
local function encode_ss(node)
	local userinfo = node.cipher .. ":" .. node.password
	local base = userinfo .. "@" .. host_format(node.server) .. ":" .. node.port
	local link = "ss://" .. base64(base)

	local p = {}

	if node.udp then table.insert(p, "udp=1") end
	if node["udp-over-tcp"] then table.insert(p, "uot=1") end

	if node.plugin then
		local plugin = (node.plugin == "obfs") and "obfs-local" or node.plugin
		if plugin == "shadow-tls" then
			local shadow_tls = base64(json.stringify(node["plugin-opts"] or {}))
			table.insert(p, "shadow-tls=" .. urlencode(shadow_tls))
		else
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
				elseif plugin == "gost-plugin" then
					if k == "mode" and v == "websocket" then v = "ws" end
					if k == "host" then k = "serverName" end
					if k == "headers" then v = nil end
				end
				if v ~= nil then
					if type(v) == "boolean" then
						v = v and "1" or "0"
					end
					table.insert(opts, k .. "=" .. v)
				end
			end
			if #opts > 0 then plugin = plugin .. ";" .. table.concat(opts, ";") end
			table.insert(p, "plugin=" .. urlencode(plugin))
		end
	end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return link .. "#" .. urlencode(node.name or "")
end

-- Hysteria
local function encode_hysteria2(node)
	local link = "hysteria://" .. host_format(node.server) .. ":" .. (node.port or "")
	local p = {}

	if node["auth-str"] then table.insert(p, "auth=" .. node["auth-str"]) end
	if node["ports"] then table.insert(p, "mport=" .. node["ports"]) end
	if node.obfs then table.insert(p, "obfsParam=" .. node.obfs) end
	if node.sni then table.insert(p, "sni=" .. node.sni) end
	if node.up then table.insert(p, "upmbps=" .. node.up) end
	if node.down then table.insert(p, "downmbps=" .. node.down) end
	if node["skip-cert-verify"] then table.insert(p, "insecure=1") end
	if node["fingerprint"] then table.insert(p, "pinSHA256=" .. urlencode(node["fingerprint"])) end

	if node.alpn then
		table.insert(p, "alpn=" .. urlencode(build_alpn(node.alpn)))
	end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return link .. "#" .. urlencode(node.name or "")
end

-- Hysteria2
local function encode_hysteria2(node)
	local link = "hysteria2://" .. (node.password or "") .. "@" .. host_format(node.server) .. ":" .. (node.port or "")
	local p = {}

	if node["ports"] then table.insert(p, "mport=" .. urlencode(node["ports"])) end
	if node.obfs then table.insert(p, "obfs=" .. node.obfs) end
	if node["obfs-password"] then table.insert(p, "obfs-password=" .. node["obfs-password"]) end
	if node.up then table.insert(p, "upmbps=" .. node.up) end
	if node.down then table.insert(p, "downmbps=" .. node.down) end

	if node.sni then table.insert(p, "sni=" .. urlencode(node.sni)) end
	if node["skip-cert-verify"] then table.insert(p, "insecure=1") end
	if node["fingerprint"] then table.insert(p, "pinSHA256=" .. urlencode(node["fingerprint"])) end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return link .. "#" .. urlencode(node.name or "")
end

-- TUIC
local function encode_tuic(node)
	local link = "tuic://" .. node.uuid .. ":" .. node.password .. "@" .. host_format(node.server) .. ":" .. node.port
	local p = {}

	if node["congestion-controller"] then
		table.insert(p, "congestion_control=" .. node["congestion-controller"])
	end

	if node.alpn then
		table.insert(p, "alpn=" .. urlencode(build_alpn(node.alpn)))
	end

	if node.sni then table.insert(p, "sni=" .. urlencode(node.sni)) end
	if node["disable-sni"] then table.insert(p, "disable_sni=1") end
	if node["skip-cert-verify"] then table.insert(p, "allowInsecure=1") end
	if node["udp-relay-mode"] then table.insert(p, "udp_relay_mode=" .. node["udp-relay-mode"]) end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return link .. "#" .. urlencode(node.name or "")
end

-- AnyTLS
local function encode_anytls(node)
	local o = build_common(node)

	local link = "anytls://" .. (node.password or "") .. "@" .. host_format(node.server) .. ":" .. node.port
	local p = {}

	if o.tls.sni then table.insert(p, "sni=" .. urlencode(o.tls.sni)) end
	if o.tls.alpn then table.insert(p, "alpn=" .. urlencode(o.tls.alpn)) end
	if o.tls.fp then table.insert(p, "fp=" .. urlencode(o.tls.fp)) end
	if o.tls.ech then table.insert(p, "ech=" .. urlencode(o.tls.ech)) end
	if o.tls.pcs then
		table.insert(p, "allowInsecure=1")
	else
		table.insert(p, "allowInsecure=" .. (o.tls.insecure and "1" or "0"))
	end

	if #p > 0 then
		link = link .. "?" .. table.concat(p, "&")
	end

	return link .. "#" .. urlencode(node.name or "")
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

	return "ssr://" .. base64(link)
end

local function encode_node(node)
	if (not node.type) or (not node.name) then return nil end

	local t = node.type

	if t == "vless" then return encode_vless(node)
	elseif t == "trojan" then return encode_trojan(node)
	elseif t == "vmess" then return encode_vmess(node)
	elseif t == "ss" then return encode_ss(node)
	elseif t == "hysteria" then return encode_hysteria(node)
	elseif t == "hysteria2" then return encode_hysteria2(node)
	elseif t == "tuic" then return encode_tuic(node)
	elseif t == "anytls" then return encode_anytls(node)
	elseif t == "ssr" then return encode_ssr(node)
	else api.log("订阅转换 → 丢弃不支持的节点：" .. node.name .. "，节点类型：" .. t)
	end
end

function parseClashNode(raw, remark)
	if not raw then return "" end 
	local ok, lyaml = pcall(require, "lyaml")
	if not ok then return raw end

	local data = lyaml.load(raw)
	if not data or type(data) ~= "table" then return raw end
	if not data.proxies then return "" end

	api.log('检测到 Clash 订阅，正在进行转换 ...')

	local links = {}
	for _, node in ipairs(data.proxies) do
		local link = encode_node(node)
		if link then
			table.insert(links, link)
		end
	end

	return #links > 0 and table.concat(links, "\n") or ""
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
