module("luci.passwall.util_sing-box", package.seeall)
local api = require "luci.passwall.api"
local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local appname = "passwall"
local fs = api.fs
local split = api.split

local local_version = api.get_app_version("sing-box"):match("[^v]+")
local version_ge_1_11_0 = api.compare_versions(local_version, ">=", "1.11.0")
local version_ge_1_12_0 = api.compare_versions(local_version, ">=", "1.12.0")

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
	if not fs.access(output_srs_file) then
		local bin = api.get_app_path("geoview")
		local cmd = string.format(bin .. " -type %s -action convert -input '%s' -list '%s' -output '%s' -lowmem=true",
			prefix, geo_path, rule_name, output_srs_file)
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
		else
			if proxy_tag then
				node.detour = proxy_tag
			end
		end

		result = {
			_id = node_id,
			_flag = flag,
			_flag_proxy_tag = proxy_tag,
			tag = tag,
			type = node.protocol,
			server = node.address,
			server_port = tonumber(node.port),
			domain_strategy = node.domain_strategy,
			detour = node.detour,
		}

		if version_ge_1_12_0 then
			--https://sing-box.sagernet.org/migration/#migrate-outbound-domain-strategy-option-to-domain-resolver
			result.domain_strategy = nil
			result.domain_resolver = {
				server = "direct",
				strategy = (node.domain_strategy and node.domain_strategy ~="") and node.domain_strategy or nil
			}
		end

		local tls = nil
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
				ech = {
					enabled = (node.ech == "1") and true or false,
					config = node.ech_config and split(node.ech_config:gsub("\\n", "\n"), "\n") or {}
				},
				utls = {
					enabled = (node.utls == "1" or node.reality == "1") and true or false,
					fingerprint = node.fingerprint or "chrome"
				},
				reality = {
					enabled = (node.reality == "1") and true or false,
					public_key = node.reality_publicKey,
					short_id = node.reality_shortId
				}
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
					local result = api.bin.b64decode(node.wireguard_reserved)
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
							local v = tonumber((node.hysteria_hop_interval or "30s"):match("^%d+"))
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
				tls = {
					enabled = true,
					server_name = node.tls_serverName,
					insecure = (node.tls_allowInsecure == "1") and true or false,
					fragment = fragment,
					record_fragment = record_fragment,
					alpn = (node.hysteria_alpn and node.hysteria_alpn ~= "") and {
						node.hysteria_alpn
					} or nil,
					ech = {
						enabled = (node.ech == "1") and true or false,
						config = node.ech_config and split(node.ech_config:gsub("\\n", "\n"), "\n") or {}
					}
				}
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
				heartbeat = node.tuic_heartbeat .. "s",
				tls = {
					enabled = true,
					server_name = node.tls_serverName,
					insecure = (node.tls_allowInsecure == "1") and true or false,
					fragment = fragment,
					record_fragment = record_fragment,
					alpn = (node.tuic_alpn and node.tuic_alpn ~= "") and {
						node.tuic_alpn
					} or nil,
					ech = {
						enabled = (node.ech == "1") and true or false,
						config = node.ech_config and split(node.ech_config:gsub("\\n", "\n"), "\n") or {}
					}
				}
			}
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
			protocol_table = {
				server_ports = next(server_ports) and server_ports or nil,
				hop_interval = (function()
							if not next(server_ports) then return nil end
							local v = tonumber((node.hysteria2_hop_interval or "30s"):match("^%d+"))
							return (v and v >= 5) and (v .. "s") or "30s"
						end)(),
				up_mbps = (node.hysteria2_up_mbps and tonumber(node.hysteria2_up_mbps)) and tonumber(node.hysteria2_up_mbps) or nil,
				down_mbps = (node.hysteria2_down_mbps and tonumber(node.hysteria2_down_mbps)) and tonumber(node.hysteria2_down_mbps) or nil,
				obfs = {
					type = node.hysteria2_obfs_type,
					password = node.hysteria2_obfs_password
				},
				password = node.hysteria2_auth_password or nil,
				tls = {
					enabled = true,
					server_name = node.tls_serverName,
					insecure = (node.tls_allowInsecure == "1") and true or false,
					fragment = fragment,
					record_fragment = record_fragment,
					ech = {
						enabled = (node.ech == "1") and true or false,
						config = node.ech_config and split(node.ech_config:gsub("\\n", "\n"), "\n") or {}
					}
				}
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
			key = node.ech_key and split(node.ech_key:gsub("\\n", "\n"), "\n") or {}
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
		tls.alpn = (node.hysteria_alpn and node.hysteria_alpn ~= "") and {
			node.hysteria_alpn
		} or nil
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
			tls.alpn = (node.tuic_alpn and node.tuic_alpn ~= "") and {
				node.tuic_alpn
			} or nil
			protocol_table = {
				users = users,
				congestion_control = node.tuic_congestion_control or "cubic",
				zero_rtt_handshake = (node.tuic_zero_rtt_handshake == "1") and true or false,
				heartbeat = node.tuic_heartbeat .. "s",
				tls = tls
			}
		end
	end

	if node.protocol == "hysteria2" then
		protocol_table = {
			up_mbps = (node.hysteria2_ignore_client_bandwidth ~= "1" and node.hysteria2_up_mbps and tonumber(node.hysteria2_up_mbps)) and tonumber(node.hysteria2_up_mbps) or nil,
			down_mbps = (node.hysteria2_ignore_client_bandwidth ~= "1" and node.hysteria2_down_mbps and tonumber(node.hysteria2_down_mbps)) and tonumber(node.hysteria2_down_mbps) or nil,
			obfs = {
				type = node.hysteria2_obfs_type,
				password = node.hysteria2_obfs_password
			},
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
			route.final = "outbound"
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
	local remote_dns_server = var["remote_dns_server"]
	local remote_dns_port = var["remote_dns_port"]
	local remote_dns_udp_server = var["remote_dns_udp_server"]
	local remote_dns_tcp_server = var["remote_dns_tcp_server"]
	local remote_dns_doh_url = var["remote_dns_doh_url"]
	local remote_dns_doh_host = var["remote_dns_doh_host"]
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
				sniff = true
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
			if tcp_proxy_way ~= "tproxy" then
				local inbound = {
					type = "redirect",
					tag = "redirect_tcp",
					listen = "::",
					listen_port = tonumber(tcp_redir_port),
					sniff = true
				}
				table.insert(inbounds, inbound)
			else
				local inbound = {
					type = "tproxy",
					tag = "tproxy_tcp",
					network = "tcp",
					listen = "::",
					listen_port = tonumber(tcp_redir_port),
					sniff = true
				}
				table.insert(inbounds, inbound)
			end
		end

		if udp_redir_port then
			local inbound = {
				type = "tproxy",
				tag = "tproxy_udp",
				network = "udp",
				listen = "::",
				listen_port = tonumber(udp_redir_port),
				sniff = true
			}
			table.insert(inbounds, inbound)
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
					if gn == g and api.match_node_rule(v.remarks, _node.node_match_rule) then
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
					return urltest_tag
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
			for i = 1, #ut_nodes do
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

		function set_outbound_detour(node, outbound, outbounds_table, shunt_rule_name)
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
						local preproxy_outbound
						if preproxy_node.protocol == "_urltest" then
							if preproxy_node.urltest_node then
								preproxy_outbound = gen_urltest(preproxy_node)
							end
						else
							preproxy_outbound = gen_outbound(node[".name"], preproxy_node)
						end
						if preproxy_outbound then
							preproxy_outbound.tag = preproxy_node[".name"]
							if preproxy_node.remarks then
								preproxy_outbound.tag = preproxy_outbound.tag .. ":" .. preproxy_node.remarks
							end
							outbound.tag = preproxy_outbound.tag .. " -> " .. outbound.tag
							outbound.detour = preproxy_outbound.tag
							last_insert_outbound = preproxy_outbound
							default_outTag = outbound.tag
						end
					end
				end
			end
			if node.chain_proxy == "2" and node.to_node then
				local to_node = get_node_by_id(node.to_node)
				if to_node then
					-- Landing Node not support use special node.
					if to_node.protocol:find("_") then
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
						if shunt_rule_name then
							to_outbound.tag = outbound.tag
							outbound.tag = node[".name"]
						else
							if to_node.remarks then
								to_outbound.tag = to_outbound.tag .. ":" .. to_node.remarks
							end
							to_outbound.tag = outbound.tag .. " -> " .. to_outbound.tag
						end
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
			if node then
				if node.protocol == "_iface" then
					if node.iface then
						local outbound = {
							tag = tag,
							type = "direct",
							bind_interface = node.iface,
							routing_mark = 255,
						}
						table.insert(outbounds, outbound)
						sys.call(string.format("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.iface))
						return outbound.tag
					end
					return nil
				end
				if proxy_table.chain_proxy == "1" or proxy_table.chain_proxy == "2" then
					node.chain_proxy = proxy_table.chain_proxy
					node.preproxy_node = proxy_table.chain_proxy == "1" and proxy_table.preproxy_node
					node.to_node = proxy_table.chain_proxy == "2" and proxy_table.to_node
					proxy_table.chain_proxy = nil
					proxy_table.preproxy_node = nil
					proxy_table.to_node = nil
				end
				local outbound
				if node.protocol == "_urltest" then
					if node.urltest_node then
						outbound = gen_urltest_outbound(node)
					end
				else
					outbound = gen_outbound(flag, node, tag, proxy_table)
				end
				if outbound then
					if node.remarks then
						outbound.tag = outbound.tag .. ":" .. node.remarks
					end
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

		if node.protocol == "_shunt" then
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
						inbound = inboundTag,
						outbound = outboundTag,
						protocol = protocols
					}

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
			COMMON.default_outbound_tag = gen_outbound_get_tag(flag, node, nil, {
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
			fakeip = nil,
		}

		if not version_ge_1_12_0 then --Migrate to new DNS server formats
			table.insert(dns.servers, {
				tag = "block",
				address = "rcode://success",
			})
		end

		if dns_socks_address and dns_socks_port then
			default_outTag = "dns_socks_out"
			table.insert(outbounds, 1, {
				type = "socks",
				tag = default_outTag,
				server = dns_socks_address,
				server_port = tonumber(dns_socks_port)
			})
		else 
			default_outTag = COMMON.default_outbound_tag
		end

		local remote_strategy = "prefer_ipv6"
		if remote_dns_query_strategy == "UseIPv4" then
			remote_strategy = "ipv4_only"
		elseif remote_dns_query_strategy == "UseIPv6" then
			remote_strategy = "ipv6_only"
		end

		local remote_server = {}
		local fakedns_tag = "remote_fakeip"

		if not version_ge_1_12_0 then --Migrate to new DNS server formats
			remote_server = {
				tag = "remote",
				address_strategy = "prefer_ipv4",
				strategy = remote_strategy,
				address_resolver = "direct",
				detour = default_outTag,
				client_subnet = (remote_dns_client_ip and remote_dns_client_ip ~= "") and remote_dns_client_ip or nil,
			}

			if remote_dns_udp_server then
				remote_server.address = remote_dns_udp_server
			end

			if remote_dns_tcp_server then
				remote_server.address = remote_dns_tcp_server
			end

			if remote_dns_doh_url and remote_dns_doh_host then
				remote_server.address = remote_dns_doh_url
			end

			if remote_server.address then
				if api.is_local_ip(remote_server.address) then  --dns为本地ip，不走代理
					remote_server.detour = "direct"
				end
				table.insert(dns.servers, remote_server)
			end

			if remote_dns_fake or inner_fakedns == "1" then
				dns.fakeip = {
					enabled = true,
					inet4_range = "198.18.0.0/15",
					inet6_range = "fc00::/18",
				}
				
				table.insert(dns.servers, {
					tag = fakedns_tag,
					address = "fakeip",
					strategy = remote_strategy,
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
		else               -- Migrate to 1.12 DNS
			remote_server = {
				tag = "remote",
				domain_strategy = remote_strategy,
				detour = default_outTag,
			}

			local tmp_address

			if remote_dns_udp_server then
				local server_port = tonumber(remote_dns_port) or 53
				remote_server.type = "udp"
				remote_server.server = remote_dns_server
				remote_server.server_port = server_port
				tmp_address = remote_dns_server
			end

			if remote_dns_tcp_server then
				local server_port = tonumber(remote_dns_port) or 53
				remote_server.type = "tcp"
				remote_server.server = remote_dns_server
				remote_server.server_port = server_port
				tmp_address = remote_dns_server
			end

			if remote_dns_doh_url and remote_dns_doh_host then
				local server_port = tonumber(remote_dns_port) or 443
				remote_server.type = "https"
				remote_server.server = remote_dns_doh_host
				remote_server.server_port = server_port
				tmp_address = remote_dns_doh_host
			end

			if tmp_address and not tmp_address:match("^%d+%.%d+%.%d+%.%d+$") and not tmp_address:match("^[%[%]%x:]+$") then  --dns为域名时
				remote_server.domain_resolver = "direct"
			end

			if remote_server.server then
				if api.is_local_ip(remote_server.server) then  --dns为本地ip，不走代理
					remote_server.detour = "direct"
				end
				table.insert(dns.servers, remote_server)
			end

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
		end

		local direct_strategy = "prefer_ipv6"
		if direct_dns_udp_server or direct_dns_tcp_server then
			if direct_dns_query_strategy == "UseIPv4" then
				direct_strategy = "ipv4_only"
			elseif direct_dns_query_strategy == "UseIPv6" then
				direct_strategy = "ipv6_only"
			end

			local domain = {}
			local nodes_domain_text = sys.exec('uci show passwall | grep ".address=" | cut -d "\'" -f 2 | grep "[a-zA-Z]$" | sort -u')
			string.gsub(nodes_domain_text, '[^' .. "\r\n" .. ']+', function(w)
				table.insert(domain, w)
			end)
			if #domain > 0 then
				table.insert(dns_domain_rules, 1, {
					outboundTag = "direct",
					domain = domain,
					strategy = version_ge_1_12_0 and direct_strategy or nil
				})
			end

			if not version_ge_1_12_0 then --Migrate to new DNS server formats
				local direct_dns_server, port
				if direct_dns_udp_server then
					port = tonumber(direct_dns_port) or 53
					direct_dns_server = "udp://" .. direct_dns_udp_server .. ":" .. port
				elseif direct_dns_tcp_server then
					port = tonumber(direct_dns_port) or 53
					direct_dns_server = "tcp://" .. direct_dns_tcp_server .. ":" .. port
				end
		
				table.insert(dns.servers, {
					tag = "direct",
					address = direct_dns_server,
					address_strategy = "prefer_ipv6",
					strategy = direct_strategy,
					detour = "direct",
				})
			else               -- Migrate to 1.12 DNS
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
					domain_strategy = direct_strategy,
					detour = "direct",
				})
			end

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
					disable_cache = true
				})
			end
		end
		dns.final = default_dns_flag
		if version_ge_1_12_0 then  -- Migrate to 1.12 DNS
			dns.strategy = (default_dns_flag == "direct") and direct_strategy or remote_strategy
		end

		--按分流顺序DNS
		if dns_domain_rules and #dns_domain_rules > 0 then
			for index, value in ipairs(dns_domain_rules) do
				if value.outboundTag and (value.domain or value.domain_suffix or value.domain_keyword or value.domain_regex or value.rule_set) then
					local dns_rule = {
						server = value.outboundTag,
						domain = (value.domain and #value.domain > 0) and value.domain or nil,
						domain_suffix = (value.domain_suffix and #value.domain_suffix > 0) and value.domain_suffix or nil,
						domain_keyword = (value.domain_keyword and #value.domain_keyword > 0) and value.domain_keyword or nil,
						domain_regex = (value.domain_regex and #value.domain_regex > 0) and value.domain_regex or nil,
						rule_set = (value.rule_set and #value.rule_set > 0) and value.rule_set or nil,  --适配srs
						disable_cache = false,
						invert = value.invert,
						strategy = (version_ge_1_12_0 and value.outboundTag == "direct") and direct_strategy or nil --Migrate to 1.12 DNS
					}
					if version_ge_1_12_0 and value.outboundTag == "block" then --Migrate to 1.12 DNS
						dns_rule.action = "predefined"
						dns_rule.rcode = "NOERROR"
						dns_rule.server = nil
						dns_rule.disable_cache = nil
					end
					if value.outboundTag ~= "block" and value.outboundTag ~= "direct" then
						dns_rule.server = "remote"
						dns_rule.strategy = version_ge_1_12_0 and remote_strategy or nil --Migrate to 1.12 DNS
						dns_rule.client_subnet = (version_ge_1_12_0 and remote_dns_client_ip and remote_dns_client_ip ~= "") and remote_dns_client_ip or nil --Migrate to 1.12 DNS
						if value.outboundTag ~= COMMON.default_outbound_tag and (remote_server.address or remote_server.server) then
							local remote_shunt_server = api.clone(remote_server)
							remote_shunt_server.tag = value.outboundTag
							local is_local = (remote_server.address and api.is_local_ip(remote_server.address)) or
									 (remote_server.server and api.is_local_ip(remote_server.server))  --dns为本地ip，不走代理
							remote_shunt_server.detour = is_local and "direct" or value.outboundTag
							table.insert(dns.servers, remote_shunt_server)
							dns_rule.server = remote_shunt_server.tag
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
	
		table.insert(inbounds, {
			type = "direct",
			tag = "dns-in",
			listen = "127.0.0.1",
			listen_port = tonumber(dns_listen_port),
			sniff = true,
		})
		table.insert(outbounds, {
			type = "dns",
			tag = "dns-out",
		})
		table.insert(route.rules, 1, {
			protocol = "dns",
			inbound = {
				"dns-in"
			},
			outbound = "dns-out"
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

		local direct_outbound = {
			type = "direct",
			tag = "direct",
			routing_mark = 255,
		}
		if not version_ge_1_12_0 then  --Migrate to 1.12 DNS
			direct_outbound.domain_strategy = "prefer_ipv6"
		else
			local domain_resolver = {
				server = "direct",
				strategy = "prefer_ipv6"
			}
			direct_outbound.domain_resolver = domain_resolver

			-- 当没有 direct dns 服务器时添加 local
			local hasDirect = false
			if config.dns and config.dns.servers then
				for _, server in ipairs(config.dns.servers) do
					if server.tag == "direct" then
						hasDirect = true
						break
					end
				end
			end
			if not hasDirect then
				config.dns = {
					servers = {
						{
							type = "local",
							tag = "direct",
							detour = "direct"
						}
					},
				}
			end
		end
		table.insert(outbounds,direct_outbound)

		table.insert(outbounds, {
			type = "block",
			tag = "block"
		})
		for index, value in ipairs(config.outbounds) do
			if not value["_flag_proxy_tag"] and not value.detour and value["_id"] and value.server and value.server_port and not no_run then
				sys.call(string.format("echo '%s' >> %s", value["_id"], api.TMP_PATH .. "/direct_node_list"))
			end
			for k, v in pairs(config.outbounds[index]) do
				if k:find("_") == 1 then
					config.outbounds[index][k] = nil
				end
			end
		end
		if version_ge_1_11_0 then
			-- Migrate logics
			-- https://sing-box.sagernet.org/migration/
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
						domain_strategy = value.domain_strategy,
						detour = value.detour
					}
					endpoints[#endpoints + 1] = endpoint
					table.remove(config.outbounds, i)
				end
				if value.type == "block" or value.type == "dns" then
					-- https://sing-box.sagernet.org/migration/#migrate-legacy-special-outbounds-to-rule-actions
					table.remove(config.outbounds, i)
				end
			end
			if #endpoints > 0 then
				config.endpoints = endpoints
			end

			-- https://sing-box.sagernet.org/migration/#migrate-legacy-special-outbounds-to-rule-actions
			for i = #config.route.rules, 1, -1 do
				local value = config.route.rules[i]
				if value.outbound == "block" then
					value.action = "reject"
					value.outbound = nil
				elseif value.outbound == "dns-out" then
					value.action = "hijack-dns"
					value.outbound = nil
				else
					value.action = "route"
				end
			end

			-- https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions
			for i = #config.inbounds, 1, -1 do
				local value = config.inbounds[i]
				if value.sniff == true then
					table.insert(config.route.rules, 1, {
						inbound = value.tag,
						action = "sniff"
					})
					value.sniff = nil
				end
				if value.domain_strategy then
					table.insert(config.route.rules, 1, {
						inbound = value.tag,
						action = "resolve",
						strategy = value.domain_strategy,
						--server = ""
					})
					value.domain_strategy = nil
				end
			end

			if config.route.final == "block" then
				config.route.final = nil
				table.insert(config.route.rules, {
					action = "reject"
				})
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
