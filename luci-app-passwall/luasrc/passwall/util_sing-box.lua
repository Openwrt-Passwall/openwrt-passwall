module("luci.passwall.util_sing-box", package.seeall)
local api = require "luci.passwall.api"
local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local appname = "passwall"
local fs = api.fs
local split = api.split
local ech_domain = {}

local local_version = api.get_app_version("sing-box"):match("[^v]+")
local version_ge_1_14_0 = api.compare_versions(local_version, ">=", "1.14.0")

local GLOBAL = {
	DNS_SERVER = {},
	DNS_HOSTNAME = {},
	VPS_EXCLUDE = {}
}

local GEO_VAR = {
	OK = nil,
	DIR = nil,
	SITE_PATH = nil,
	IP_PATH = nil,
	SITE_TAGS = {},
	IP_TAGS = {},
	TO_SRS_PATH = "/tmp/etc/" .. appname .."_tmp/singbox_srss/"
}

function check_geoview()
	if not GEO_VAR.OK then
		-- Only get once
		GEO_VAR.OK = (api.finded_com("geoview") and api.compare_versions(api.get_app_version("geoview"), ">=", "0.1.10")) and 1 or 0
	end
	if GEO_VAR.OK == 0 then
		api.log("！！！注意：缺少 Geoview 组件或版本过低，Sing-Box 分流无法启用！")
	else
		GEO_VAR.DIR = GEO_VAR.DIR or (uci:get(appname, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"):match("^(.*)/")
		GEO_VAR.SITE_PATH = GEO_VAR.SITE_PATH or (GEO_VAR.DIR .. "/geosite.dat")
		GEO_VAR.IP_PATH = GEO_VAR.IP_PATH or (GEO_VAR.DIR .. "/geoip.dat")
		if not fs.access(GEO_VAR.TO_SRS_PATH) then
			fs.mkdir(GEO_VAR.TO_SRS_PATH)
		end
	end
	return GEO_VAR.OK
end

function geo_convert_srs(var)
	if check_geoview() ~= 1 then
		return
	end
	local geo_path = var["geo_path"]
	local prefix = var["prefix"]
	local rule_name = var["rule_name"]
	local output_srs_file = GEO_VAR.TO_SRS_PATH .. prefix .. "-" .. rule_name .. ".srs"
	local bin = api.finded_com("geoview")
	if not fs.access(output_srs_file) and bin then
		local cmd = string.format("%q -type %q -action convert -input %q -list %q -output %q -lowmem=true",
			bin, prefix, geo_path, rule_name, output_srs_file)
		sys.call(cmd)
		local status = fs.access(output_srs_file) and "success." or "failed!"
		if status == "failed!" then
			api.log(string.format("  - %s:%s 转换为srs格式：%s", prefix, rule_name, status))
		end
	end
end

local function convert_geofile()
	if check_geoview() ~= 1 then
		return
	end
	local function convert(file_path, prefix, tags)
		if next(tags) and fs.access(file_path) then
			local md5_file = GEO_VAR.TO_SRS_PATH .. prefix .. ".dat.md5"
			local new_md5 = sys.exec("md5sum " .. file_path .. " 2>/dev/null | awk '{print $1}'"):gsub("\n", "")
			local old_md5 = sys.exec("[ -f " .. md5_file .. " ] && head -n 1 " .. md5_file .. " | tr -d ' \t\n' || echo ''")
			if new_md5 ~= "" and new_md5 ~= old_md5 then
				sys.call("printf '%s' " .. new_md5 .. " > " .. md5_file)
				sys.call("rm -rf " .. GEO_VAR.TO_SRS_PATH .. prefix .. "-*.srs" )
			end
			for k in pairs(tags) do
				geo_convert_srs({["geo_path"] = file_path, ["prefix"] = prefix, ["rule_name"] = k})
			end
		end
	end
	--api.log("Sing-Box 规则集转换：")
	convert(GEO_VAR.SITE_PATH, "geosite", GEO_VAR.SITE_TAGS)
	convert(GEO_VAR.IP_PATH, "geoip", GEO_VAR.IP_TAGS)
end

function gen_outbound(flag, node, tag, proxy_table)
	local result = nil
	if node then
		local node_id = node[".name"]
		if tag == nil then
			tag = node_id
		end
		local remarks = node.remarks

		local proxy_tag = nil
		local fragment = nil
		local record_fragment = nil
		local run_socks_instance = true
		if proxy_table ~= nil and type(proxy_table) == "table" then
			proxy_tag = proxy_table.tag or nil
			fragment = proxy_table.fragment or nil
			record_fragment = proxy_table.record_fragment or nil
			run_socks_instance = proxy_table.run_socks_instance
		end

		if node.type ~= "sing-box" then
			local relay_port = node.port
			local new_port = api.get_new_port()
			local config_file = string.format("%s_%s_%s.json", flag, tag, new_port)
			if tag and node_id and not tag:find(node_id) then
				config_file = string.format("%s_%s_%s_%s.json", flag, tag, node_id, new_port)
			end
			if run_socks_instance then
				sys.call(string.format('/usr/share/%s/app.sh run_socks "%s"> /dev/null',
					appname,
					string.format("flag=%s node=%s bind=%s socks_port=%s config_file=%s relay_port=%s",
						new_port, --flag
						node_id, --node
						"127.0.0.1", --bind
						new_port, --socks port
						config_file, --config file
						(proxy_tag and relay_port) and tostring(relay_port) or "" --relay port
						)
					)
				)
			end
			node = {
				protocol = "socks",
				address = "127.0.0.1",
				port = new_port
			}
			proxy_tag = "socks <- " .. node_id
		else
			if proxy_tag then
				node.detour = proxy_tag
			end
		end

		if remarks then
			tag = tag .. ":" .. remarks
		end

		node.address = (node.address or ""):lower()

		result = {
			_id = node_id,
			_flag = flag,
			_flag_proxy_tag = proxy_tag,
			tag = tag,
			type = node.protocol,
			server = node.address,
			server_port = tonumber(node.port),
			domain_resolver = {
				server = "direct",
				strategy = node.domain_strategy
			},
			detour = node.detour,
		}

		if api.datatypes.hostname(node.address) and node.domain_resolver and (node.domain_resolver_dns or node.domain_resolver_dns_https) then
			local dns_proto = node.domain_resolver
			local server_address
			local server_port
			local server_path
			if dns_proto == "https" then
				local _a = api.parseDoH(node.domain_resolver_dns_https)
				if _a then
					server_address = _a.hostname
					server_port = _a.port or 443
					server_path = _a.pathname or ""
					if _a.hostname and api.datatypes.hostname(_a.hostname) then
						GLOBAL.DNS_HOSTNAME[_a.hostname] = true
					end
				end
			else
				server_address = node.domain_resolver_dns
				server_port = 53
				local split = api.split(server_address, ":")
				if #split > 1 then
					server_address = split[1]
					server_port = tonumber(split[#split])
				end
			end
			local dns_key = dns_proto .. "|" .. tostring(server_address) .. "|" .. tostring(server_port) .. "|" .. tostring(server_path or "")
			if not GLOBAL.DNS_SERVER[dns_key] then
				GLOBAL.DNS_SERVER[dns_key] = {
					server = {
						tag = "dns-node-" .. api.gen_short_uuid(),
						type = dns_proto,
						server = server_address,
						server_port = server_port,
						path = server_path,
						domain_resolver = "direct",
						detour = "direct"
					},
					domain = {}
				}
			end
			local exists
			for _, d in ipairs(GLOBAL.DNS_SERVER[dns_key].domain) do
				if d == node.address then exists = true; break end
			end
			if not exists then table.insert(GLOBAL.DNS_SERVER[dns_key].domain, node.address) end
			result.domain_resolver.server = GLOBAL.DNS_SERVER[dns_key].server.tag
			GLOBAL.VPS_EXCLUDE[node.address] = true
		end

		local tls = nil
		if node.protocol == "hysteria" or node.protocol == "hysteria2" or node.protocol == "tuic" or node.protocol == "naive" then
			node.tls = "1"
		end
		if node.tls == "1" then
			local alpn = nil
			if node.alpn and node.alpn ~= "default" then
				alpn = {}
				string.gsub(node.alpn, '[^' .. "," .. ']+', function(w)
					table.insert(alpn, w)
				end)
			end
			tls = {
				enabled = true,
				disable_sni = (node.tls_disable_sni == "1") and true or false, --不要在 ClientHello 中发送服务器名称.
				server_name = node.tls_serverName, --用于验证返回证书上的主机名，除非设置不安全。它还包含在 ClientHello 中以支持虚拟主机，除非它是 IP 地址。
				insecure = (node.tls_allowInsecure == "1") and true or false, --接受任何服务器证书。
				alpn = alpn, --支持的应用层协议协商列表，按优先顺序排列。如果两个对等点都支持 ALPN，则选择的协议将是此列表中的一个，如果没有相互支持的协议则连接将失败。
				--min_version = "1.2",
				--max_version = "1.3",
				fragment = fragment,
				record_fragment = record_fragment,
				ech = (node.ech == "1") and (function()
					local function get_ech_domain(s) --兼容xray "域名+DNS" 格式ech
						local domain, dns = s:match("^([^+]+)%+(.+)$")
						if not domain or not dns then return nil end
						if not (dns:match("^https?://") or dns:match("^tcp://") or dns:match("^udp://") or dns:match("^h2c://")) then
							return nil
						end
						if not domain:match("^[%w%-%.]+%.[%a]+$") then return nil end
						return domain
					end
					local ech = { enabled = true }
					local config = node.ech_config
					local qname = node.ech_query_server_name
					if config and not qname then
						qname = get_ech_domain(config)
						if not qname and not (config:match("%-+%s*BEGIN") and config:match("%-+%s*END")) then
							config = "-----BEGIN ECH CONFIGS-----\n" .. config:gsub("%s+", "") .. "\n-----END ECH CONFIGS-----"
						end
					end
					if qname then
						ech.query_server_name = qname
						ech_domain[qname] = true
					elseif config then
						ech.config = { config }
					elseif node.tls_serverName and node.tls_serverName ~= "" then
						ech_domain[node.tls_serverName] = true
					end
					return ech
				end)() or nil,
				utls = (node.utls == "1" or node.reality == "1") and {
					enabled = true,
					fingerprint = node.fingerprint or "chrome"
				} or nil,
				reality = (node.reality == "1") and {
					enabled = true,
					public_key = node.reality_publicKey,
					short_id = node.reality_shortId
				} or nil
			}
		end

		local mux = nil
		if node.mux == "1" then
			mux = {
				enabled = true,
				protocol = node.mux_type or "h2mux",
				max_connections = ( (node.tcpbrutal == "1") and 1 ) or tonumber(node.mux_concurrency) or 4,
				padding = (node.mux_padding == "1") and true or false,
				--min_streams = 4,
				--max_streams = 0,
				brutal = {
					enabled = (node.tcpbrutal == "1") and true or false,
					up_mbps = tonumber(node.tcpbrutal_up_mbps) or 10,
					down_mbps = tonumber(node.tcpbrutal_down_mbps) or 50,
				},
			}
		end

		local v2ray_transport = nil

		if node.transport == "tcp" and node.tcp_guise == "http" and (node.tcp_guise_http_host or "") ~= "" then  --模拟xray raw(tcp)传输
			v2ray_transport = {
				type = "http",
				host = node.tcp_guise_http_host,
				path = node.tcp_guise_http_path and (function()
						local first = node.tcp_guise_http_path[1]
						return (first == "" or not first) and "/" or first
					end)() or "/",
				headers = node.user_agent and {
					["User-Agent"] = node.user_agent
				} or nil,
				idle_timeout = (node.http_h2_health_check == "1") and node.http_h2_read_idle_timeout or nil,
				ping_timeout = (node.http_h2_health_check == "1") and node.http_h2_health_check_timeout or nil,
			}
			--不强制执行 TLS。如果未配置 TLS，将使用纯 HTTP 1.1。
		end

		if node.transport == "http" then
			v2ray_transport = {
				type = "http",
				host = node.http_host or {},
				path = node.http_path or "/",
				headers = node.user_agent and {
					["User-Agent"] = node.user_agent
				} or nil,
				idle_timeout = (node.http_h2_health_check == "1") and node.http_h2_read_idle_timeout or nil,
				ping_timeout = (node.http_h2_health_check == "1") and node.http_h2_health_check_timeout or nil,
			}
			--不强制执行 TLS。如果未配置 TLS，将使用纯 HTTP 1.1。
		end

		if node.transport == "ws" then
			v2ray_transport = {
				type = "ws",
				path = node.ws_path or "/",
				headers = (node.ws_host or node.user_agent) and {
					Host = node.ws_host,
					["User-Agent"] = node.user_agent
				} or nil,
				max_early_data = tonumber(node.ws_maxEarlyData) or nil,
				early_data_header_name = (node.ws_earlyDataHeaderName) and node.ws_earlyDataHeaderName or nil --要与 Xray-core 兼容，请将其设置为 Sec-WebSocket-Protocol。它需要与服务器保持一致。
			}
		end

		if node.transport == "httpupgrade" then
			v2ray_transport = {
				type = "httpupgrade",
				host = node.httpupgrade_host,
				path = node.httpupgrade_path or "/",
				headers = node.user_agent and {
					["User-Agent"] = node.user_agent
				} or nil
			}
		end

		if node.transport == "quic" then
			v2ray_transport = {
				type = "quic"
			}
			--没有额外的加密支持： 它基本上是重复加密。 并且 Xray-core 在这里与 v2ray-core 不兼容。
		end

		if node.transport == "grpc" then
			v2ray_transport = {
				type = "grpc",
				service_name = node.grpc_serviceName,
				idle_timeout = tonumber(node.grpc_idle_timeout) or nil,
				ping_timeout = tonumber(node.grpc_health_check_timeout) or nil,
				permit_without_stream = (node.grpc_permit_without_stream == "1") and true or nil,
			}
		end

		local protocol_table = nil

		if node.protocol == "socks" then
			protocol_table = {
				version = "5",
				username = (node.username and node.password) and node.username or nil,
				password = (node.username and node.password) and node.password or nil,
				udp_over_tcp = node.uot == "1" and {
					enabled = true,
					version = 2
				} or nil,
			}
		end

		if node.protocol == "http" then
			protocol_table = {
				username = (node.username and node.password) and node.username or nil,
				password = (node.username and node.password) and node.password or nil,
				path = nil,
				headers = nil,
				tls = tls
			}
		end

		if node.protocol == "shadowsocks" then
			protocol_table = {
				method = node.method or nil,
				password = node.password or "",
				plugin = (node.plugin_enabled and node.plugin) or nil,
				plugin_opts = (node.plugin_enabled and node.plugin_opts) or nil,
				udp_over_tcp = node.uot == "1" and {
					enabled = true,
					version = 2
				} or nil,
				multiplex = mux,
			}
		end

		if node.protocol == "trojan" then
			protocol_table = {
				password = node.password,
				tls = tls,
				multiplex = mux,
				transport = v2ray_transport
			}
		end

		if node.protocol == "vmess" then
			protocol_table = {
				uuid = node.uuid,
				security = node.security,
				alter_id = (node.alter_id) and tonumber(node.alter_id) or 0,
				global_padding = (node.global_padding == "1") and true or false,
				authenticated_length = (node.authenticated_length == "1") and true or false,
				tls = tls,
				packet_encoding = "", --UDP 包编码。(空)：禁用	packetaddr：由 v2ray 5+ 支持	xudp：由 xray 支持
				multiplex = mux,
				transport = v2ray_transport,
			}
		end

		if node.protocol == "vless" then
			protocol_table = {
				uuid = node.uuid,
				flow = (node.tls == '1' and node.flow) and node.flow or nil,
				tls = tls,
				packet_encoding = "xudp", --UDP 包编码。(空)：禁用	packetaddr：由 v2ray 5+ 支持	xudp：由 xray 支持
				multiplex = mux,
				transport = v2ray_transport,
			}
		end

		if node.protocol == "wireguard" then
			if node.wireguard_reserved then
				local bytes = {}
				if not node.wireguard_reserved:match("[^%d,]+") then
					node.wireguard_reserved:gsub("%d+", function(b)
						bytes[#bytes + 1] = tonumber(b)
					end)
				else
					local result = api.base64Decode(node.wireguard_reserved)
					for i = 1, #result do
						bytes[i] = result:byte(i)
					end
				end
				node.wireguard_reserved = #bytes > 0 and bytes or nil
			end
			protocol_table = {
				system_interface = nil,
				interface_name = nil,
				local_address = node.wireguard_local_address,
				private_key = node.wireguard_secret_key,
				peer_public_key = node.wireguard_public_key,
				pre_shared_key = node.wireguard_preSharedKey,
				reserved = node.wireguard_reserved,
				mtu = tonumber(node.wireguard_mtu),
			}
		end

		if node.protocol == "hysteria" then
			local server_ports = {}
			if node.hysteria_hop then
				node.hysteria_hop = string.gsub(node.hysteria_hop, "-", ":")
				for range in node.hysteria_hop:gmatch("([^,]+)") do
					if range:match("^%d+:%d+$") then
						table.insert(server_ports, range)
					end
				end
			end
			protocol_table = {
				server_ports = next(server_ports) and server_ports or nil,
				hop_interval = (function()
							if not next(server_ports) then return nil end
							local v = tonumber((node.hysteria_hop_interval or "30"):match("^%d+"))
							return (v and v >= 5) and (v .. "s") or "30s"
						end)(),
				up_mbps = tonumber(node.hysteria_up_mbps),
				down_mbps = tonumber(node.hysteria_down_mbps),
				obfs = node.hysteria_obfs,
				auth = (node.hysteria_auth_type == "base64") and node.hysteria_auth_password or nil,
				auth_str = (node.hysteria_auth_type == "string") and node.hysteria_auth_password or nil,
				recv_window_conn = tonumber(node.hysteria_recv_window_conn),
				recv_window = tonumber(node.hysteria_recv_window),
				disable_mtu_discovery = (node.hysteria_disable_mtu_discovery == "1") and true or false,
				tls = tls
			}
		end

		if node.protocol == "shadowtls" then
			protocol_table = {
				version = tonumber(node.shadowtls_version),
				password = (node.shadowtls_version == "2" or node.shadowtls_version == "3") and node.password or nil,
				tls = tls,
			}
		end

		if node.protocol == "tuic" then
			protocol_table = {
				uuid = node.uuid,
				password = node.password,
				congestion_control = node.tuic_congestion_control or "cubic",
				udp_relay_mode = node.tuic_udp_relay_mode or "native",
				udp_over_stream = false,
				zero_rtt_handshake = (node.tuic_zero_rtt_handshake == "1") and true or false,
				heartbeat = (tonumber(node.tuic_heartbeat) or 3) .. "s",
				tls = tls
			}
			if node.tuic_alpn and node.tuic_alpn ~= "default" then
				local alpn = {}
				string.gsub(node.tuic_alpn, '[^,]+', function(w)
					table.insert(alpn, w)
				end)
				if #alpn > 0 then protocol_table.tls.alpn = alpn end
			end
		end

		if node.protocol == "hysteria2" then
			local server_ports = {}
			if node.hysteria2_hop then
				node.hysteria2_hop = string.gsub(node.hysteria2_hop, "-", ":")
				for range in node.hysteria2_hop:gmatch("([^,]+)") do
					if range:match("^%d+:%d+$") then
						table.insert(server_ports, range)
					end
				end
			end
			local interval, interval_max
			if next(server_ports) then
				interval = "30s"
				local t = node.hysteria2_hop_interval or "30s"
				if t:find("-", 1, true) then
					local min, max = t:match("^(%d+)%-(%d+)$")
					min = tonumber(min)
					max = tonumber(max)
					if min and max then
						min = (min >= 5) and min or 5
						max = (max >= min) and max or min
						interval = min .. "s"
						interval_max = max .. "s"
					end
				else
					t = tonumber(t:match("^%d+"))
					t = (t and t >= 5) and t or 30
					interval = t .. "s"
				end
			end
			protocol_table = {
				server_ports = next(server_ports) and server_ports or nil,
				hop_interval = interval,
				hop_interval_max = interval_max,
				up_mbps = (node.hysteria2_up_mbps and tonumber(node.hysteria2_up_mbps)) and tonumber(node.hysteria2_up_mbps) or nil,
				down_mbps = (node.hysteria2_down_mbps and tonumber(node.hysteria2_down_mbps)) and tonumber(node.hysteria2_down_mbps) or nil,
				obfs = node.hysteria2_obfs_type and {
					type = node.hysteria2_obfs_type,
					password = node.hysteria2_obfs_password
				} or nil,
				password = node.hysteria2_auth_password or nil,
				tls = tls
			}
		end

		if node.protocol == "anytls" then
			protocol_table = {
				password = (node.password and node.password ~= "") and node.password or "",
				idle_session_check_interval = "30s",
				idle_session_timeout = "30s",
				min_idle_session = 5,
				tls = tls
			}
		end

		if node.protocol == "ssh" then
			protocol_table = {
				user = (node.username and node.username ~= "") and node.username or "root",
				password = (node.password and node.password ~= "") and node.password or "",
				private_key = node.ssh_priv_key,
				private_key_passphrase = node.ssh_priv_key_pp,
				host_key = node.ssh_host_key,
				host_key_algorithms = node.ssh_host_key_algo,
				client_version = node.ssh_client_version
			}
		end

		if node.protocol == "naive" then
			protocol_table = {
				username = (node.username and node.username ~= "") and node.username or "",
				password = (node.password and node.password ~= "") and node.password or "",
				insecure_concurrency = tonumber(node.naive_insecure_concurrency or 0) > 0 and tonumber(node.naive_insecure_concurrency) or 0,
				udp_over_tcp = node.uot == "1" and {
					enabled = true,
					version = 2
				} or false,
				extra_headers = node.user_agent and {
					["User-Agent"] = node.user_agent
				} or nil,
				quic = node.naive_quic == "1" and true or false,
				quic_congestion_control = (node.naive_quic == "1" and node.naive_congestion_control) and node.naive_congestion_control or nil,
				tls = tls
			}
		end

		if protocol_table then
			for key, value in pairs(protocol_table) do
				result[key] = value
			end
		end
	end
	return result
end

function gen_config_server(node)
	local outbounds = {
		{ type = "direct", tag = "direct" }
	}

	local tls = {
		enabled = true,
		certificate_path = node.tls_certificateFile,
		key_path = node.tls_keyFile,
		alpn = (node.alpn and node.alpn ~= "default") and (function()
			local alpn = {}
			string.gsub(node.alpn, '[^,]+', function(w)
				table.insert(alpn, w)
			end)
			if #alpn > 0 then return alpn end
			return nil
		end)() or nil
	}

	if node.tls == "1" and node.reality == "1" then
		tls.certificate_path = nil
		tls.key_path = nil
		tls.server_name = node.reality_handshake_server
		tls.reality = {
			enabled = true,
			private_key = node.reality_private_key,
			short_id = {
				node.reality_shortId
			},
			handshake = {
				server = node.reality_handshake_server,
				server_port = tonumber(node.reality_handshake_server_port)
			}
		}
	end

	if node.tls == "1" and node.ech == "1" then
		tls.ech = {
			enabled = true,
			key = node.ech_key and { node.ech_key } or nil
		}
	end

	local mux = nil
	if node.mux == "1" then
		mux = {
			enabled = true,
			padding = (node.mux_padding == "1") and true or false,
			brutal = {
				enabled = (node.tcpbrutal == "1") and true or false,
				up_mbps = tonumber(node.tcpbrutal_up_mbps) or 10,
				down_mbps = tonumber(node.tcpbrutal_down_mbps) or 50,
			},
		}
	end

	local v2ray_transport = nil

	if node.transport == "http" then
		v2ray_transport = {
			type = "http",
			host = node.http_host or {},
			path = node.http_path or "/",
		}
	end

	if node.transport == "ws" then
		v2ray_transport = {
			type = "ws",
			path = node.ws_path or "/",
			headers = (node.ws_host ~= nil) and { Host = node.ws_host } or nil,
			early_data_header_name = (node.ws_earlyDataHeaderName) and node.ws_earlyDataHeaderName or nil --要与 Xray-core 兼容，请将其设置为 Sec-WebSocket-Protocol。它需要与服务器保持一致。
		}
	end

	if node.transport == "httpupgrade" then
		v2ray_transport = {
			type = "httpupgrade",
			host = node.httpupgrade_host,
			path = node.httpupgrade_path or "/",
		}
	end

	if node.transport == "quic" then
		v2ray_transport = {
			type = "quic"
		}
		--没有额外的加密支持： 它基本上是重复加密。 并且 Xray-core 在这里与 v2ray-core 不兼容。
	end

	if node.transport == "grpc" then
		v2ray_transport = {
			type = "grpc",
			service_name = node.grpc_serviceName,
		}
	end

	local inbound = {
		type = node.protocol,
		tag = "inbound",
		listen = (node.bind_local == "1") and "127.0.0.1" or "::",
		listen_port = tonumber(node.port),
	}

	local protocol_table = nil

	if node.protocol == "mixed" then
		protocol_table = {
			users = (node.auth == "1") and {
				{
					username = node.username,
					password = node.password
				}
			} or nil,
			set_system_proxy = false
		}
	end

	if node.protocol == "socks" then
		protocol_table = {
			users = (node.auth == "1") and {
				{
					username = node.username,
					password = node.password
				}
			} or nil
		}
	end

	if node.protocol == "http" then
		protocol_table = {
			users = (node.auth == "1") and {
				{
					username = node.username,
					password = node.password
				}
			} or nil,
			tls = (node.tls == "1") and tls or nil,
		}
	end

	if node.protocol == "shadowsocks" then
		protocol_table = {
			method = node.method,
			password = node.password,
			multiplex = mux,
		}
	end

	if node.protocol == "vmess" then
		if node.uuid then
			local users = {}
			for i = 1, #node.uuid do
				users[i] = {
					name = node.uuid[i],
					uuid = node.uuid[i],
					alterId = 0,
				}
			end
			protocol_table = {
				users = users,
				tls = (node.tls == "1") and tls or nil,
				multiplex = mux,
				transport = v2ray_transport,
			}
		end
	end

	if node.protocol == "vless" then
		if node.uuid then
			local users = {}
			for i = 1, #node.uuid do
				users[i] = {
					name = node.uuid[i],
					uuid = node.uuid[i],
					flow = node.flow,
				}
			end
			protocol_table = {
				users = users,
				tls = (node.tls == "1") and tls or nil,
				multiplex = mux,
				transport = v2ray_transport,
			}
		end
	end

	if node.protocol == "trojan" then
		if node.uuid then
			local users = {}
			for i = 1, #node.uuid do
				users[i] = {
					name = node.uuid[i],
					password = node.uuid[i],
				}
			end
			protocol_table = {
				users = users,
				tls = (node.tls == "1") and tls or nil,
				fallback = nil,
				fallback_for_alpn = nil,
				multiplex = mux,
				transport = v2ray_transport,
			}
		end
	end

	if node.protocol == "naive" then
		protocol_table = {
			users = {
				{
					username = node.username,
					password = node.password
				}
			},
			tls = tls,
		}
	end

	if node.protocol == "hysteria" then
		protocol_table = {
			up = node.hysteria_up_mbps .. " Mbps",
			down = node.hysteria_down_mbps .. " Mbps",
			up_mbps = tonumber(node.hysteria_up_mbps),
			down_mbps = tonumber(node.hysteria_down_mbps),
			obfs = node.hysteria_obfs,
			users = {
				{
					name = "user1",
					auth = (node.hysteria_auth_type == "base64") and node.hysteria_auth_password or nil,
					auth_str = (node.hysteria_auth_type == "string") and node.hysteria_auth_password or nil,
				}
			},
			recv_window_conn = node.hysteria_recv_window_conn and tonumber(node.hysteria_recv_window_conn) or nil,
			recv_window_client = node.hysteria_recv_window_client and tonumber(node.hysteria_recv_window_client) or nil,
			max_conn_client = node.hysteria_max_conn_client and tonumber(node.hysteria_max_conn_client) or nil,
			disable_mtu_discovery = (node.hysteria_disable_mtu_discovery == "1") and true or false,
			tls = tls
		}
	end

	if node.protocol == "tuic" then
		if node.uuid then
			local users = {}
			for i = 1, #node.uuid do
				users[i] = {
					name = node.uuid[i],
					uuid = node.uuid[i],
					password = node.password
				}
			end
			tls.alpn = (node.tuic_alpn and node.tuic_alpn ~= "default") and (function()
				local alpn = {}
				string.gsub(node.tuic_alpn, '[^,]+', function(w)
					table.insert(alpn, w)
				end)
				if #alpn > 0 then return alpn end
				return nil
			end)() or nil
			protocol_table = {
				users = users,
				congestion_control = node.tuic_congestion_control or "cubic",
				zero_rtt_handshake = (node.tuic_zero_rtt_handshake == "1") and true or false,
				heartbeat = (tonumber(node.tuic_heartbeat) or 3) .. "s",
				tls = tls
			}
		end
	end

	if node.protocol == "hysteria2" then
		protocol_table = {
			up_mbps = (node.hysteria2_ignore_client_bandwidth ~= "1" and node.hysteria2_up_mbps and tonumber(node.hysteria2_up_mbps)) and tonumber(node.hysteria2_up_mbps) or nil,
			down_mbps = (node.hysteria2_ignore_client_bandwidth ~= "1" and node.hysteria2_down_mbps and tonumber(node.hysteria2_down_mbps)) and tonumber(node.hysteria2_down_mbps) or nil,
			obfs = node.hysteria2_obfs_type and {
				type = node.hysteria2_obfs_type,
				password = node.hysteria2_obfs_password
			} or nil,
			users = {
				{
					name = "user1",
					password = node.hysteria2_auth_password or nil,
				}
			},
			ignore_client_bandwidth = (node.hysteria2_ignore_client_bandwidth == "1") and true or false,
			tls = tls
		}
	end

	if node.protocol == "anytls" then
		protocol_table = {
			users = {
				{
					name = (node.username and node.username ~= "") and node.username or "sekai",
					password = node.password
				}
			},
			tls = tls,
		}
	end

	if node.protocol == "direct" then
		protocol_table = {
			network = (node.d_protocol ~= "TCP,UDP") and node.d_protocol or nil,
			override_address = node.d_address,
			override_port = tonumber(node.d_port)
		}
	end

	if protocol_table then
		for key, value in pairs(protocol_table) do
			inbound[key] = value
		end
	end

	local route = {
		rules = {
			{
				ip_is_private = true,
				action = node.accept_lan == "1" and "route" or "reject",
				outbound = node.accept_lan == "1" and "direct" or nil

			}
		}
	}

	if node.outbound_node then
		local outbound = nil
		if node.outbound_node == "_iface" and node.outbound_node_iface then
			outbound = {
				type = "direct",
				tag = "outbound",
				bind_interface = node.outbound_node_iface,
				routing_mark = 255,
			}
			sys.call(string.format("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.outbound_node_iface))
		else
			local outbound_node_t = uci:get_all("passwall", node.outbound_node)
			if node.outbound_node == "_socks" or node.outbound_node == "_http" then
				outbound_node_t = {
					type = node.type,
					protocol = node.outbound_node:gsub("_", ""),
					address = node.outbound_node_address,
					port = tonumber(node.outbound_node_port),
					username = (node.outbound_node_username and node.outbound_node_username ~= "") and node.outbound_node_username or nil,
					password = (node.outbound_node_password and node.outbound_node_password ~= "") and node.outbound_node_password or nil,
				}
			end
			outbound = require("luci.passwall.util_sing-box").gen_outbound(nil, outbound_node_t, "outbound")
		end
		if outbound then
			route.final = outbound.tag
			table.insert(outbounds, 1, outbound)
		end
	end

	local config = {
		log = {
			disabled = (not node or node.log == "0") and true or false,
			level = node.loglevel or "info",
			timestamp = true,
			--output = logfile,
		},
		dns = {
			servers = {{
				type = "local",
				tag = "direct"
			}}
		},
		inbounds = { inbound },
		outbounds = outbounds,
		route = route
	}

	for index, value in ipairs(config.outbounds) do
		for k, v in pairs(config.outbounds[index]) do
			if k:find("_") == 1 then
				config.outbounds[index][k] = nil
			end
		end
	end

	return config
end

function gen_config(var)
	local flag = var["flag"]
	local log = var["log"] or "0"
	local loglevel = var["loglevel"] or "warn"
	local logfile = var["logfile"] or "/dev/null"
	local node_id = var["node"]
	local server_host = var["server_host"]
	local server_port = var["server_port"]
	local tcp_proxy_way = var["tcp_proxy_way"]
	local tcp_redir_port = var["tcp_redir_port"]
	local udp_redir_port = var["udp_redir_port"]
	local local_socks_address = var["local_socks_address"] or "0.0.0.0"
	local local_socks_port = var["local_socks_port"]
	local local_socks_username = var["local_socks_username"]
	local local_socks_password = var["local_socks_password"]
	local local_http_address = var["local_http_address"] or "0.0.0.0"
	local local_http_port = var["local_http_port"]
	local local_http_username = var["local_http_username"]
	local local_http_password = var["local_http_password"]
	local dns_listen_port = var["dns_listen_port"]
	local direct_dns_port = var["direct_dns_port"]
	local direct_dns_udp_server = var["direct_dns_udp_server"]
	local direct_dns_tcp_server = var["direct_dns_tcp_server"]
	local direct_dns_query_strategy = var["direct_dns_query_strategy"]
	local remote_dns_udp_server = var["remote_dns_udp_server"]
	local remote_dns_udp_port = var["remote_dns_udp_port"]
	local remote_dns_tcp_server = var["remote_dns_tcp_server"]
	local remote_dns_tcp_port = var["remote_dns_tcp_port"]
	local remote_dns_doh = var["remote_dns_doh"]
	local remote_dns_http3 = var["remote_dns_http3"]
	local remote_dns_client_ip = var["remote_dns_client_ip"]
	local remote_dns_query_strategy = var["remote_dns_query_strategy"]
	local remote_dns_fake = var["remote_dns_fake"]
	local dns_cache = var["dns_cache"]
	local dns_socks_address = var["dns_socks_address"]
	local dns_socks_port = var["dns_socks_port"]
	local no_run = var["no_run"]

	local dns_domain_rules = {}
	local dns = nil
	local inbounds = {}
	local outbounds = {}
	local rule_set_table = {}
	local COMMON = {}

	local singbox_settings = uci:get_all(appname, "@global_singbox[0]") or {}

	local route = {
		rules = {}
	}

	local experimental = nil

	function add_rule_set(tab)
		if tab and next(tab) and tab.tag and not rule_set_table[tab.tag]then
			rule_set_table[tab.tag] = tab
		end
	end

	function parse_rule_set(w, rs)
		-- Format: remote:https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-netflix.srs'
		-- Format: local:/usr/share/sing-box/geosite-netflix.srs'
		local result = nil
		if w and #w > 0 then
			if w:find("local:") == 1 or w:find("remote:") == 1 then
				local _type = w:sub(1, w:find(":") - 1) -- "local" or "remote"
				w = w:sub(w:find(":") + 1, #w)
				local format = nil
				local filename = w:sub(-w:reverse():find("/") + 1) -- geosite-netflix.srs
				local suffix = ""
				local find_doc = filename:reverse():find("%.")
				if find_doc then
					suffix = filename:sub(-find_doc + 1) -- "srs" or "json"
				end
				if suffix == "srs" then
					format = "binary"
				elseif suffix == "json" then
					format = "source"
				end
				if format then
					local rule_set_tag = filename:sub(1, filename:find("%.") - 1) --geosite-netflix
					if rule_set_tag and #rule_set_tag > 0 then
						if rs then
							rule_set_tag = "rs_" .. rule_set_tag
						end
						result = {
							type = _type,
							tag = rule_set_tag,
							format = format,
							path = _type == "local" and w or nil,
							url = _type == "remote" and w or nil,
							--download_detour = _type == "remote" and "",
							--update_interval = _type == "remote" and "",
						}
					end
				end
			end
		end
		return result
	end

	function geo_rule_set(prefix, rule_name)
		local output_srs_file = "local:" .. GEO_VAR.TO_SRS_PATH .. prefix .. "-" .. rule_name .. ".srs"
		return parse_rule_set(output_srs_file)
	end

	if node_id then
		local node = uci:get_all(appname, node_id)
		if node then
			if server_host and server_port then
				node.address = server_host
				node.port = server_port
			end
		end

		if local_socks_port then
			local inbound = {
				type = "socks",
				tag = "socks-in",
				listen = local_socks_address,
				listen_port = tonumber(local_socks_port),
			}
			if local_socks_username and local_socks_password and local_socks_username ~= "" and local_socks_password ~= "" then
				inbound.users = {
					{
						username = local_socks_username,
						password = local_socks_password
					}
				}
			end
			table.insert(inbounds, inbound)
			table.insert(route.rules, {
				action = "sniff",
				inbound = inbound.tag
			})
		end

		if local_http_port then
			local inbound = {
				type = "http",
				tag = "http-in",
				listen = local_http_address,
				listen_port = tonumber(local_http_port)
			}
			if local_http_username and local_http_password and local_http_username ~= "" and local_http_password ~= "" then
				inbound.users = {
					{
						username = local_http_username,
						password = local_http_password
					}
				}
			end
			table.insert(inbounds, inbound)
		end

		if tcp_redir_port then
			local inbound
			if tcp_proxy_way ~= "tproxy" then
				inbound = {
					type = "redirect",
					tag = "redirect_tcp",
					listen = "::",
					listen_port = tonumber(tcp_redir_port)
				}
			else
				inbound = {
					type = "tproxy",
					tag = "tproxy_tcp",
					network = "tcp",
					listen = "::",
					listen_port = tonumber(tcp_redir_port)
				}
			end
			table.insert(inbounds, inbound)
			table.insert(route.rules, {
				action = "sniff",
				inbound = inbound.tag
			})
		end

		if udp_redir_port then
			local inbound = {
				type = "tproxy",
				tag = "tproxy_udp",
				network = "udp",
				listen = "::",
				listen_port = tonumber(udp_redir_port)
			}
			table.insert(inbounds, inbound)
			table.insert(route.rules, {
				action = "sniff",
				inbound = inbound.tag
			})
		end

		function gen_socks_config_node(node_id, socks_id, remarks)
			if node_id then
				socks_id = node_id:sub(1 + #"Socks_")
			end
			local result
			local socks_node = uci:get_all(appname, socks_id) or nil
			if socks_node then
				if not remarks then
					remarks = socks_node.port
				end
				result = {
					[".name"] = "Socksid_" .. socks_id,
					remarks = remarks,
					type = "sing-box",
					protocol = "socks",
					address = "127.0.0.1",
					port = socks_node.port,
					uot = "1"
				}
			end
			return result
		end

		local nodes_list = {}
		function get_urltest_batch_nodes(_node)
			if #nodes_list == 0 then
				for k, e in ipairs(api.get_valid_nodes()) do
					if e.node_type == "normal" and (not e.chain_proxy or e.chain_proxy == "") then
						nodes_list[#nodes_list + 1] = {
							id = e[".name"],
							remarks = e["remarks"],
							group = e["group"]
						}
					end
				end
			end
			if not _node.node_group or _node.node_group == "" then return {} end
			local nodes = {}
			for g in _node.node_group:gmatch("%S+") do
				g = api.UrlDecode(g)
				for k, v in pairs(nodes_list) do
					local gn = (v.group and v.group ~= "") and v.group or "default"
					if gn:lower() == g:lower() and api.match_node_rule(v.remarks, _node.node_match_rule) then
						nodes[#nodes + 1] = v.id
					end
				end
			end
			return nodes
		end
	
		function get_node_by_id(node_id)
			if not node_id or node_id == "" or node_id == "nil" then return nil end
			if node_id:find("Socks_") then
				return gen_socks_config_node(node_id)
			else
				return uci:get_all(appname, node_id)
			end
		end

		function gen_urltest_outbound(_node)
			local urltest_id = _node[".name"]
			local urltest_tag = "urltest-" .. urltest_id
			-- existing urltest
			for _, v in ipairs(outbounds) do
				if v.tag == urltest_tag then
					return v, true
				end
			end
			-- new urltest
			local ut_nodes
			if _node.node_add_mode and _node.node_add_mode == "batch" then
				ut_nodes = get_urltest_batch_nodes(_node)
			else
				ut_nodes = _node.urltest_node
			end
			if #ut_nodes == 0 then return nil end
			local valid_nodes = {}
			for i = 1, #(ut_nodes or {}) do
				local ut_node_id = ut_nodes[i]
				local ut_node_tag = "ut-" .. ut_node_id
				local is_new_ut_node = true
				for _, outbound in ipairs(outbounds) do
					if string.sub(outbound.tag, 1, #ut_node_tag) == ut_node_tag then
						is_new_ut_node = false
						valid_nodes[#valid_nodes + 1] = outbound.tag
						break
					end
				end
				if is_new_ut_node then
					local outboundTag = gen_outbound_get_tag(flag, ut_node_id, ut_node_tag, { fragment = singbox_settings.fragment == "1" or nil, record_fragment = singbox_settings.record_fragment == "1" or nil, run_socks_instance = not no_run })
					if outboundTag then
						valid_nodes[#valid_nodes + 1] = outboundTag
					end
				end
			end
			if #valid_nodes == 0 then return nil end
			local outbound = {
				type = "urltest",
				tag = urltest_tag,
				outbounds = valid_nodes,
				url = _node.urltest_url or "https://www.gstatic.com/generate_204",
				interval = (api.format_go_time(_node.urltest_interval) ~= "0s") and api.format_go_time(_node.urltest_interval) or "3m",
				tolerance = (_node.urltest_tolerance and tonumber(_node.urltest_tolerance) > 0) and tonumber(_node.urltest_tolerance) or 50,
				idle_timeout = (api.format_go_time(_node.urltest_idle_timeout) ~= "0s") and api.format_go_time(_node.urltest_idle_timeout) or "30m",
				interrupt_exist_connections = (_node.urltest_interrupt_exist_connections == "true" or _node.urltest_interrupt_exist_connections == "1") and true or false
			}
			return outbound
		end

		function set_outbound_detour(node, outbound, outbounds_table)
			if not node or not outbound or not outbounds_table then return nil end
			local default_outTag = outbound.tag
			local last_insert_outbound

			if node.shadowtls == "1" then
				local _node = {
					type = "sing-box",
					protocol = "shadowtls",
					shadowtls_version = node.shadowtls_version,
					password = (node.shadowtls_version == "2" or node.shadowtls_version == "3") and node.shadowtls_password or nil,
					address = node.address,
					port = node.port,
					tls = "1",
					tls_serverName = node.shadowtls_serverName,
					utls = node.shadowtls_utls,
					fingerprint = node.shadowtls_fingerprint
				}
				local shadowtls_outbound = gen_outbound(nil, _node, outbound.tag .. "_shadowtls")
				if shadowtls_outbound then
					last_insert_outbound = shadowtls_outbound
					outbound.detour = outbound.tag .. "_shadowtls"
					outbound.server = nil
					outbound.server_port = nil
				end
			end

			if node.chain_proxy == "1" and node.preproxy_node then
				if outbound["_flag_proxy_tag"] then
					--Ignore
				else
					local preproxy_node = get_node_by_id(node.preproxy_node)
					if preproxy_node then
						local preproxy_outbound, exist
						if preproxy_node.protocol == "_urltest" then
							preproxy_outbound, exist = gen_urltest_outbound(preproxy_node)
						else
							preproxy_outbound = gen_outbound(node[".name"], preproxy_node)
						end
						if preproxy_outbound then
							outbound.tag = preproxy_outbound.tag .. " -> " .. outbound.tag
							outbound.detour = preproxy_outbound.tag
							if not exist then
								last_insert_outbound = preproxy_outbound
							end
							default_outTag = outbound.tag
						end
					end
				end
			end
			if node.chain_proxy == "2" and node.to_node then
				local to_node = get_node_by_id(node.to_node)
				if to_node then
					-- Landing Node not support use special node.
					if to_node.protocol:find("^_") then
						to_node = nil
					end
				end
				if to_node then
					local to_outbound
					if to_node.type ~= "sing-box" then
						local tag = to_node[".name"]
						local new_port = api.get_new_port()
						table.insert(inbounds, {
							type = "direct",
							tag = tag,
							listen = "127.0.0.1",
							listen_port = new_port,
							override_address = to_node.address,
							override_port = tonumber(to_node.port),
						})
						table.insert(rules, 1, {
							action = "route",
							inbound = {tag},
							outbound = outbound.tag,
						})
						if to_node.tls_serverName == nil then
							to_node.tls_serverName = to_node.address
						end
						to_node.address = "127.0.0.1"
						to_node.port = new_port
						to_outbound = gen_outbound(node[".name"], to_node, tag, {
							tag = tag,
							run_socks_instance = not no_run
						})
					else
						to_outbound = gen_outbound(node[".name"], to_node)
					end
					if to_outbound then
						to_outbound.tag = outbound.tag .. " -> " .. to_outbound.tag
						if to_node.type == "sing-box" then
							to_outbound.detour = outbound.tag
						end
						table.insert(outbounds_table, to_outbound)
						default_outTag = to_outbound.tag
					end
				end
			end
			return default_outTag, last_insert_outbound
		end

		function gen_outbound_get_tag(flag, node_id, tag, proxy_table)
			if not node_id or node_id == "nil" then return nil end
			local node
			if type(node_id) == "string" then
				node = get_node_by_id(node_id)
			elseif type(node_id) == "table" then
				node = node_id
			end
			if not tag then tag = node[".name"] end
			if node then
				if proxy_table.chain_proxy == "1" or proxy_table.chain_proxy == "2" then
					node.chain_proxy = proxy_table.chain_proxy
					node.preproxy_node = proxy_table.chain_proxy == "1" and proxy_table.preproxy_node
					node.to_node = proxy_table.chain_proxy == "2" and proxy_table.to_node
					proxy_table.chain_proxy = nil
					proxy_table.preproxy_node = nil
					proxy_table.to_node = nil
				end
				local outbound, exist
				if node.protocol == "_urltest" then
					outbound, exist = gen_urltest_outbound(node)
					if exist then
						return outbound.tag
					end
				elseif node.protocol == "_iface" then
					if node.iface then
						outbound = {
							tag = tag,
							type = "direct",
							bind_interface = node.iface,
							routing_mark = 255,
						}
						sys.call(string.format("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.iface))
					end
				else
					for _, _outbound in ipairs(outbounds) do
						-- Avoid generating duplicate nested processes
						if _outbound["_flag_proxy_tag"] and _outbound["_flag_proxy_tag"]:find("socks <- " .. node[".name"], 1, true) then
							outbound = api.clone(_outbound)
							outbound.tag = tag
							break
						end
					end
					if not outbound then
						outbound = gen_outbound(flag, node, tag, proxy_table)
					end
				end
				if outbound then
					local default_outbound_tag, last_insert_outbound = set_outbound_detour(node, outbound, outbounds)
					table.insert(outbounds, outbound)
					if last_insert_outbound then
						table.insert(outbounds, last_insert_outbound)
					end
					return default_outbound_tag
				end
			end
		end

		rules = {}

		if node and node.protocol == "_shunt" then
			inner_fakedns = node.fakedns or "0"

			local function gen_shunt_node(rule_name, _node_id)
				if not rule_name then return nil, nil end
				if not _node_id then _node_id = node[rule_name] end
				if _node_id == "_direct" then
					return "direct"
				elseif _node_id == "_blackhole" then
					return "block"
				elseif _node_id == "_default" and rule_name ~= "default" then
					return "default"
				elseif _node_id then
					local proxy_table = {
						fragment = singbox_settings.fragment == "1",
						record_fragment = singbox_settings.record_fragment == "1",
						run_socks_instance = not no_run,
					}
					local preproxy_node_id = node[rule_name .. "_proxy_tag"]
					if preproxy_node_id == _node_id then preproxy_node_id = nil end
					if preproxy_node_id then
						proxy_table.chain_proxy = "2"
						proxy_table.to_node = _node_id
						return gen_outbound_get_tag(flag, preproxy_node_id, rule_name, proxy_table)
					else
						return gen_outbound_get_tag(flag, _node_id, rule_name, proxy_table)
					end
				end
				return nil
			end

			--default_node
			local default_node_id = node.default_node or "_direct"
			COMMON.default_outbound_tag = gen_shunt_node("default", default_node_id)

			if inner_fakedns == "1" and node["default_fakedns"] == "1" then
				remote_dns_fake = true
			end

			--shunt rule
			uci:foreach(appname, "shunt_rules", function(e)
				local outboundTag = gen_shunt_node(e[".name"])
				if outboundTag and e.remarks then
					if outboundTag == "default" then
						outboundTag = COMMON.default_outbound_tag
					end
					local protocols = nil
					if e["protocol"] and e["protocol"] ~= "" then
						protocols = {}
						string.gsub(e["protocol"], '[^' .. " " .. ']+', function(w)
							table.insert(protocols, w)
						end)
					end

					local inboundTag = nil
					if e["inbound"] and e["inbound"] ~= "" then
						inboundTag = {}
						if e["inbound"]:find("tproxy") then
							if tcp_redir_port then
								if tcp_proxy_way == "tproxy" then
									table.insert(inboundTag, "tproxy_tcp")
								else
									table.insert(inboundTag, "redirect_tcp")
								end
							end
							if udp_redir_port then
								table.insert(inboundTag, "tproxy_udp")
							end
						end
						if e["inbound"]:find("socks") then
							if local_socks_port then
								table.insert(inboundTag, "socks-in")
							end
						end
					end
					
					local rule = {
						action = "route",
						inbound = inboundTag,
						outbound = outboundTag,
						protocol = protocols
					}

					if outboundTag == "block" then
						rule.action = "reject"
						rule.outbound = nil
					end

					if e.network then
						local network = {}
						string.gsub(e.network, '[^' .. "," .. ']+', function(w)
							table.insert(network, w)
						end)
						rule.network = network
					end

					if e.source then
						local source_ip_cidr = {}
						local is_private = false
						string.gsub(e.source, '[^' .. " " .. ']+', function(w)
							if w:find("geoip") == 1 then
								local _geoip = w:sub(1 + #"geoip:")     --适配srs
								if _geoip == "private" then
									is_private = true
								end
							else
								table.insert(source_ip_cidr, w)
							end
						end)
						rule.source_ip_is_private = is_private and true or nil
						rule.source_ip_cidr = #source_ip_cidr > 0 and source_ip_cidr or nil
						if is_private or #source_ip_cidr > 0 then rule.rule_set_ip_cidr_match_source = true end
					end

					--[[
					-- Too low usage rate, hidden
					if e.sourcePort then
						local source_port = {}
						local source_port_range = {}
						string.gsub(e.sourcePort, '[^' .. "," .. ']+', function(w)
							if tonumber(w) and tonumber(w) >= 1 and tonumber(w) <= 65535 then
								table.insert(source_port, tonumber(w))
							else
								table.insert(source_port_range, w)
							end
						end)
						rule.source_port = #source_port > 0 and source_port or nil
						rule.source_port_range = #source_port_range > 0 and source_port_range or nil
					end
					]]--

					if e.port then
						local port = {}
						local port_range = {}
						string.gsub(e.port, '[^' .. "," .. ']+', function(w)
							if tonumber(w) and tonumber(w) >= 1 and tonumber(w) <= 65535 then
								table.insert(port, tonumber(w))
							else
								table.insert(port_range, w)
							end
						end)
						rule.port = #port > 0 and port or nil
						rule.port_range = #port_range > 0 and port_range or nil
					end

					local rule_set = {}

					if e.domain_list then
						local domain_table = {
							shunt_tag = e[".name"],
							outboundTag = outboundTag,
							domain = {},
							domain_suffix = {},
							domain_keyword = {},
							domain_regex = {},
							rule_set = {},
							fakedns = nil,
							invert = e.invert == "1" and true or nil
						}
						string.gsub(e.domain_list, '[^' .. "\r\n" .. ']+', function(w)
							if w:find("#") == 1 then return end
							if w:find("geosite:") == 1 then
								local _geosite = w:sub(1 + #"geosite:")  --适配srs
								local t = geo_rule_set("geosite", _geosite)
								if t then
									GEO_VAR.SITE_TAGS[_geosite] = true
									add_rule_set(t)
									table.insert(rule_set, t.tag)
									table.insert(domain_table.rule_set, t.tag)
								end
							elseif w:find("regexp:") == 1 then
								table.insert(domain_table.domain_regex, w:sub(1 + #"regexp:"))
							elseif w:find("full:") == 1 then
								table.insert(domain_table.domain, w:sub(1 + #"full:"))
							elseif w:find("domain:") == 1 then
								table.insert(domain_table.domain_suffix, w:sub(1 + #"domain:"))
							elseif w:find("rule-set:", 1, true) == 1 or w:find("rs:") == 1 then
								w = w:sub(w:find(":") + 1, #w)
								local t = parse_rule_set(w, true)
								if t then
									add_rule_set(t)
									table.insert(rule_set, t.tag)
									table.insert(domain_table.rule_set, t.tag)
								end
							else
								table.insert(domain_table.domain_keyword, w)
							end
						end)
						rule.domain = #domain_table.domain > 0 and domain_table.domain or nil
						rule.domain_suffix = #domain_table.domain_suffix > 0 and domain_table.domain_suffix or nil
						rule.domain_keyword = #domain_table.domain_keyword > 0 and domain_table.domain_keyword or nil
						rule.domain_regex = #domain_table.domain_regex > 0 and domain_table.domain_regex or nil
						rule.rule_set = #domain_table.rule_set > 0 and domain_table.rule_set or nil
						if inner_fakedns == "1" and node[e[".name"] .. "_fakedns"] == "1" then
							domain_table.fakedns = true
						end

						if outboundTag then
							table.insert(dns_domain_rules, api.clone(domain_table))
						end
					end

					if e.ip_list then
						local ip_cidr = {}
						local is_private = false
						string.gsub(e.ip_list, '[^' .. "\r\n" .. ']+', function(w)
							if w:find("#") == 1 then return end
							if w:find("geoip:") == 1 then
								local _geoip = w:sub(1 + #"geoip:")     --适配srs
								if _geoip == "private" then
									is_private = true
								else
									local t = geo_rule_set("geoip", _geoip)
									if t then
										GEO_VAR.IP_TAGS[_geoip] = true
										add_rule_set(t)
										table.insert(rule_set, t.tag)
									end
								end
							elseif w:find("rule-set:", 1, true) == 1 or w:find("rs:") == 1 then
								w = w:sub(w:find(":") + 1, #w)
								local t = parse_rule_set(w, true)
								if t then
									add_rule_set(t)
									table.insert(rule_set, t.tag)
								end
							else
								table.insert(ip_cidr, w)
							end
						end)

						rule.ip_is_private = is_private and true or nil
						rule.ip_cidr = #ip_cidr > 0 and ip_cidr or nil
					end

					rule.rule_set = #rule_set > 0 and rule_set or nil --适配srs
					rule.invert = e.invert == "1" and true or nil

					table.insert(rules, rule)
				end
			end)
		else
			COMMON.default_outbound_tag = gen_outbound_get_tag(flag, node or node_id, nil, {
				fragment = singbox_settings.fragment == "1" or nil,
				record_fragment = singbox_settings.record_fragment == "1" or nil,
				run_socks_instance = not no_run
			})
		end

		for index, value in ipairs(rules) do
			table.insert(route.rules, rules[index])
		end
	end

	if COMMON.default_outbound_tag then
		route.final = COMMON.default_outbound_tag
	end

	if dns_listen_port then
		dns = {
			servers = {},
			rules = {},
			disable_cache = (dns_cache and dns_cache == "0") and true or false,
			disable_expire = false, --禁用 DNS 缓存过期。
			independent_cache = false, --使每个 DNS 服务器的缓存独立，以满足特殊目的。如果启用，将轻微降低性能。
			reverse_mapping = true, --在响应 DNS 查询后存储 IP 地址的反向映射以为路由目的提供域名。
		}

		local default_outTag = COMMON.default_outbound_tag

		if dns_socks_address and dns_socks_port then
			default_outTag = "dns_socks_out"
			table.insert(outbounds, 1, {
				type = "socks",
				tag = default_outTag,
				server = dns_socks_address,
				server_port = tonumber(dns_socks_port)
			})
		end

		remote_strategy = "prefer_ipv6"
		if remote_dns_query_strategy == "UseIPv4" then
			remote_strategy = "ipv4_only"
		elseif remote_dns_query_strategy == "UseIPv6" then
			remote_strategy = "ipv6_only"
		end

		local remote_server = {
			tag = "remote",
			domain_resolver = "direct",
			detour = default_outTag,
		}

		if remote_dns_udp_server then
			local server_port = tonumber(remote_dns_udp_port) or 53
			remote_server.type = "udp"
			remote_server.server = remote_dns_udp_server
			remote_server.server_port = server_port

		elseif remote_dns_tcp_server then
			local server_port = tonumber(remote_dns_tcp_port) or 53
			remote_server.type = "tcp"
			remote_server.server = remote_dns_tcp_server
			remote_server.server_port = server_port

		elseif remote_dns_doh then
			local _a = api.parseDoH(remote_dns_doh)
			if _a then
				remote_server.type = "https"
				if remote_dns_http3 then
					remote_server.type = "h3"
				end
				remote_server.server = _a.hostname
				remote_server.server_port = _a.port or 443
				remote_server.path = _a.pathname or ""

				if api.datatypes.hostname(_a.hostname) then
					if _a.hostip then
						if not hosts_predefined then hosts_predefined = {} end
						hosts_predefined[_a.hostname] = _a.hostip
						remote_server_domain_resolver = "hosts"
					else
						GLOBAL.DNS_HOSTNAME[_a.hostname] = true
						remote_server_domain_resolver = "direct"
					end
				end
			end
		end

		if api.is_local_ip(remote_server.server) then  --dns为本地ip，不走代理
			remote_server.detour = "direct"
		end

		if remote_server_domain_resolver then
			remote_server.domain_resolver = remote_server_domain_resolver
		end

		table.insert(dns.servers, remote_server)

		fakedns_tag = "remote_fakeip"
		if remote_dns_fake or inner_fakedns == "1" then		
			table.insert(dns.servers, {
				tag = fakedns_tag,
				type = "fakeip",
				inet4_range = "198.18.0.0/15",
				inet6_range = "fc00::/18",
			})

			if not experimental then
				experimental = {}
			end
			experimental.cache_file = {
				enabled = true,
				store_fakeip = true,
				path = api.CACHE_PATH .. "/singbox_" .. flag .. ".db"
			}
		end

		if direct_dns_udp_server or direct_dns_tcp_server then
			local domain = {}
			local nodes_domain_text = sys.exec([[uci show passwall | sed -n "s/.*\.address='\([^']*\)'/\1/p" | sort -u]])
			string.gsub(nodes_domain_text, '[^' .. "\r\n" .. ']+', function(w)
				w = (w or ""):lower()
				if not api.vps_domain_exclude(w) and api.datatypes.hostname(w) and not GLOBAL.VPS_EXCLUDE[w] then
					table.insert(domain, w)
				end
			end)
			if #domain > 0 then
				table.insert(dns_domain_rules, 1, {
					outboundTag = "direct",
					domain = domain
				})
			end

			direct_strategy = "prefer_ipv6"
			if direct_dns_query_strategy == "UseIPv4" then
				direct_strategy = "ipv4_only"
			elseif direct_dns_query_strategy == "UseIPv6" then
				direct_strategy = "ipv6_only"
			end

			local direct_dns_server, port, type
			if direct_dns_udp_server then
				port = tonumber(direct_dns_port) or 53
				direct_dns_server = direct_dns_udp_server
				type = "udp"
			elseif direct_dns_tcp_server then
				port = tonumber(direct_dns_port) or 53
				direct_dns_server = direct_dns_tcp_server
				type = "tcp"
			end

			table.insert(dns.servers, {
				tag = "direct",
				type = type,
				server = direct_dns_server,
				server_port = port,
				detour = "direct",
			})
		end

		local default_dns_flag = "remote"
		if dns_socks_address and dns_socks_port then
		else
			if node_id and (tcp_redir_port or udp_redir_port) then
				local node = get_node_by_id(node_id)
				if node.protocol == "_shunt" then
					if node.default_node == "_direct" then
						default_dns_flag = "direct"
					end
				end
			else default_dns_flag = "direct"
			end
		end
		if default_dns_flag == "remote" then
			if remote_dns_fake then
				table.insert(dns.rules, {
					query_type = { "A", "AAAA" },
					server = fakedns_tag,
					disable_cache = true,
					rewrite_ttl = 30,
					strategy = remote_strategy
				})
			end
		end
		dns.final = default_dns_flag

		--按分流顺序DNS
		if dns_domain_rules and #dns_domain_rules > 0 then
			for index, value in ipairs(dns_domain_rules) do
				if value.outboundTag and (value.domain or value.domain_suffix or value.domain_keyword or value.domain_regex or value.rule_set) then
					local dns_rule = {
						action = "route",
						server = value.outboundTag,
						domain = (value.domain and #value.domain > 0) and value.domain or nil,
						domain_suffix = (value.domain_suffix and #value.domain_suffix > 0) and value.domain_suffix or nil,
						domain_keyword = (value.domain_keyword and #value.domain_keyword > 0) and value.domain_keyword or nil,
						domain_regex = (value.domain_regex and #value.domain_regex > 0) and value.domain_regex or nil,
						rule_set = (value.rule_set and #value.rule_set > 0) and value.rule_set or nil,  --适配srs
						disable_cache = false,
						invert = value.invert,
					}
					if value.outboundTag == "block" then
						dns_rule.action = "predefined"
						dns_rule.rcode = "NOERROR"
						dns_rule.server = nil
						dns_rule.disable_cache = nil
					end
					if value.outboundTag == "direct" then
						dns_rule.strategy = direct_strategy
					end
					if value.outboundTag ~= "block" and value.outboundTag ~= "direct" then
						dns_rule.server = "remote"
						dns_rule.rewrite_ttl = 30
						dns_rule.strategy = remote_strategy
						dns_rule.client_subnet = remote_dns_client_ip
						if value.outboundTag ~= COMMON.default_outbound_tag and (remote_server.address or remote_server.server) then
							local remote_dns_server = api.clone(remote_server)
							remote_dns_server.tag = value.shunt_tag
							local is_local = (remote_server.address and api.is_local_ip(remote_server.address)) or
									 (remote_server.server and api.is_local_ip(remote_server.server))  --dns为本地ip，不走代理
							remote_dns_server.detour = is_local and "direct" or value.outboundTag
							table.insert(dns.servers, remote_dns_server)
							dns_rule.server = remote_dns_server.tag
						end
						if value.fakedns then
							local fakedns_dns_rule = api.clone(dns_rule)
							fakedns_dns_rule.query_type = {
								"A", "AAAA"
							}
							fakedns_dns_rule.server = fakedns_tag
							fakedns_dns_rule.disable_cache = true
							table.insert(dns.rules, fakedns_dns_rule)
						end
					end
					table.insert(dns.rules, dns_rule)
				end
			end
		end
		local dns_in_inbound = {
			type = "direct",
			tag = "dns-in",
			listen = "127.0.0.1",
			listen_port = tonumber(dns_listen_port),
		}
		table.insert(inbounds, dns_in_inbound)
		table.insert(route.rules, {
			action = "sniff",
			inbound = dns_in_inbound.tag
		})
		table.insert(route.rules, 1, {
			action = "hijack-dns",
			inbound = dns_in_inbound.tag
		})
	end

	if not dns then
		dns = {
			servers = {{
				type = "local",
				tag = "direct"
			}}
		}
	end

	if not dns.rules then dns.rules = {} end

	for i, v in pairs(GLOBAL.DNS_SERVER) do
		table.insert(dns.servers, v.server)
		table.insert(dns.rules, 1, {
			action = "route",
			server = v.server.tag,
			disable_cache = false,
			domain = v.domain,
		})
	end
	if next(GLOBAL.DNS_HOSTNAME) then
		local hostname = {}
		for line, _ in pairs(GLOBAL.DNS_HOSTNAME) do
			table.insert(hostname, line)
		end
		table.insert(dns.rules, 1, {
			query_type = { "A", "AAAA" },
			domain = hostname,
			server = "direct"
		})
	end

	if next(ech_domain) ~= nil then
		table.insert(dns.servers, {
			tag = "ech-dns",
			type = "https",
			server = "223.5.5.5"
		})
		local domain = {}
		for line, _ in pairs(ech_domain) do domain[#domain+1] = line end
		table.insert(dns.rules, 1, {
			domain = domain,
			server = "ech-dns"
		})
	end

	table.insert(dns.servers, {
		tag = "hosts",
		type = "hosts",
		predefined = (hosts_predefined and next(hosts_predefined) ~= nil) and hosts_predefined or nil
	})
	if not version_ge_1_14_0 then
		table.insert(dns.rules, 1, {
			ip_accept_any = true,
			server = "hosts"
		})
	else
		table.insert(dns.rules, 1, {
			action = "evaluate",
			server = "hosts"
		})
		table.insert(dns.rules, 2, {
			match_response = true,
			ip_accept_any = true,
			action = "respond"
		})
	end

	if COMMON.default_outbound_tag == "block" then
		route.final = nil
		table.insert(route.rules, {
			action = "reject"
		})
	end

	if next(rule_set_table) then
		route.rule_set = {}
		for k, v in pairs(rule_set_table) do
			table.insert(route.rule_set, v)
		end
	end
	
	if inbounds or outbounds then
		local config = {
			log = {
				disabled = log == "0" and true or false,
				level = loglevel,
				timestamp = true,
				output = logfile,
			},
			-- DNS
			dns = dns,
			-- 传入连接
			inbounds = inbounds,
			-- 传出连接
			outbounds = outbounds,
			-- 路由
			route = route,
			--实验性
			experimental = experimental,
		}
		table.insert(outbounds, {
			type = "direct",
			tag = "direct",
			routing_mark = 255,
			domain_resolver = {
				server = "direct",
				strategy = "prefer_ipv6"
			}
		})
		for index, value in ipairs(config.outbounds) do
			if not value["_flag_proxy_tag"] and not value.detour and value["_id"] and value.server and (value.server_port or value.server_ports) and not no_run then
				sys.call(string.format("echo '%s' >> %s", value["_id"], api.TMP_PATH .. "/direct_node_list"))
			end
			if not value.detour and value.server then
				value.detour = "direct"
			end
			if value.server and not api.datatypes.hostname(value.server) then
				value.domain_resolver = nil
			end
			for k, v in pairs(config.outbounds[index]) do
				if k:find("_") == 1 then
					config.outbounds[index][k] = nil
				end
			end
		end
		if true then
			local endpoints = {}
			for i = #config.outbounds, 1, -1 do
				local value = config.outbounds[i]
				if value.type == "wireguard" then
					-- https://sing-box.sagernet.org/migration/#migrate-wireguard-outbound-to-endpoint
					local endpoint = {
						type = "wireguard",
						tag = value.tag,
						system = value.system_interface,
						name = value.interface_name,
						mtu = value.mtu,
						address = value.local_address,
						private_key = value.private_key,
						peers = {
							{
								address = value.server,
								port = value.server_port,
								public_key = value.peer_public_key,
								pre_shared_key = value.pre_shared_key,
								allowed_ips = {"0.0.0.0/0"},
								reserved = value.reserved
							}
						},
						domain_resolver = {
							server = "direct",
							strategy = value.domain_strategy
						},
						detour = value.detour
					}
					endpoints[#endpoints + 1] = endpoint
					table.remove(config.outbounds, i)
				end
			end
			if #endpoints > 0 then
				config.endpoints = endpoints
			end
		end
		return jsonc.stringify(config, 1)
	end
end

function gen_proto_config(var)
	local local_socks_address = var["local_socks_address"] or "0.0.0.0"
	local local_socks_port = var["local_socks_port"]
	local local_socks_username = var["local_socks_username"]
	local local_socks_password = var["local_socks_password"]
	local local_http_address = var["local_http_address"] or "0.0.0.0"
	local local_http_port = var["local_http_port"]
	local local_http_username = var["local_http_username"]
	local local_http_password = var["local_http_password"]
	local server_proto = var["server_proto"]
	local server_address = var["server_address"]
	local server_port = var["server_port"]
	local server_username = var["server_username"]
	local server_password = var["server_password"]

	local inbounds = {}
	local outbounds = {}

	if local_socks_address and local_socks_port then
		local inbound = {
			type = "socks",
			tag = "socks-in",
			listen = local_socks_address,
			listen_port = tonumber(local_socks_port),
		}
		if local_socks_username and local_socks_password and local_socks_username ~= "" and local_socks_password ~= "" then
			inbound.users = {
				username = local_socks_username,
				password = local_socks_password
			}
		end
		table.insert(inbounds, inbound)
	end

	if local_http_address and local_http_port then
		local inbound = {
			type = "http",
			tag = "http-in",
			tls = nil,
			listen = local_http_address,
			listen_port = tonumber(local_http_port),
		}
		if local_http_username and local_http_password and local_http_username ~= "" and local_http_password ~= "" then
			inbound.users = {
				{
					username = local_http_username,
					password = local_http_password
				}
			}
		end
		table.insert(inbounds, inbound)
	end

	if server_proto ~= "nil" and server_address ~= "nil" and server_port ~= "nil" then
		local outbound = {
			type = server_proto,
			tag = "out",
			server = server_address,
			server_port = tonumber(server_port),
			username = (server_username and server_password) and server_username or nil,
			password = (server_username and server_password) and server_password or nil,
		}
		if outbound then table.insert(outbounds, outbound) end
	end
	
	local config = {
		log = {
			disabled = true,
			level = "warn",
			timestamp = true,
		},
		-- 传入连接
		inbounds = inbounds,
		-- 传出连接
		outbounds = outbounds,
	}
	return jsonc.stringify(config, 1)
end

_G.gen_config = gen_config
_G.gen_proto_config = gen_proto_config
_G.geo_convert_srs = geo_convert_srs

if arg[1] then
	local func =_G[arg[1]]
	if func then
		local var = nil
		if arg[2] then
			var = jsonc.parse(arg[2])
		end
		print(func(var))
		if (next(GEO_VAR.SITE_TAGS) or next(GEO_VAR.IP_TAGS)) and not no_run then
			convert_geofile()
		end
	end
end
