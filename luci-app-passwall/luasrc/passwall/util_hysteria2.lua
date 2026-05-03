module("luci.passwall.util_hysteria2", package.seeall)
local api = require "luci.passwall.api"
local uci = api.uci
local jsonc = api.jsonc

function gen_config_server(node)
	local config = {
		listen = ":" .. node.port,
		tls = {
			cert = node.tls_certificateFile,
			key = node.tls_keyFile,
		},
		obfs = (node.hysteria2_obfs) and {
			type = "salamander",
			salamander = {
				password = node.hysteria2_obfs
			}
		} or nil,
		auth = {
			type = "password",
			password = node.hysteria2_auth_password
		},
		bandwidth = (node.hysteria2_up_mbps or node.hysteria2_down_mbps) and {
			up = node.hysteria2_up_mbps and node.hysteria2_up_mbps .. " mbps" or nil,
			down = node.hysteria2_down_mbps and node.hysteria2_down_mbps .. " mbps" or nil
		} or nil,
		ignoreClientBandwidth = (node.hysteria2_ignoreClientBandwidth == "1") and true or false,
		disableUDP = (node.hysteria2_udp == "0") and true or false,
	}
	return config
end

function gen_config(var)
	local node_id = var["node"]
	if not node_id then
		print("node 不能为空")
		return
	end
	local node = uci:get_all("passwall", node_id)
	local local_tcp_redir_port = var["local_tcp_redir_port"]
	local local_udp_redir_port = var["local_udp_redir_port"]
	local local_socks_address = var["local_socks_address"] or "0.0.0.0"
	local local_socks_port = var["local_socks_port"]
	local local_socks_username = var["local_socks_username"]
	local local_socks_password = var["local_socks_password"]
	local local_http_address = var["local_http_address"] or "0.0.0.0"
	local local_http_port = var["local_http_port"]
	local local_http_username = var["local_http_username"]
	local local_http_password = var["local_http_password"]
	local tcp_proxy_way = var["tcp_proxy_way"]
	local server_host = var["server_host"] or (node.address or ""):lower()
	local server_port = var["server_port"] or node.port

	if api.is_ipv6(server_host) then
		server_host = api.get_ipv6_full(server_host)
	end
	local server = server_host .. ":" .. server_port

	if (node.hysteria2_hop) then
		server = server .. "," .. string.gsub(node.hysteria2_hop, ":", "-")
	end

	local config = {
		server = server,
		transport = {
			type = "udp",
			udp = node.hysteria2_hop and (function()
				local udp = {}
				local t = node.hysteria2_hop_interval
				if not t then return nil end
				if t:find("-", 1, true) then
					local min, max = t:match("^(%d+)%-(%d+)$")
					min = tonumber(min)
					max = tonumber(max)
					if min and max then
						min = (min >= 5) and min or 5
						max = (max >= min) and max or min
						udp.minHopInterval = min .. "s"
						udp.maxHopInterval = max .. "s"
						return udp
					end
				end
				t = tonumber((t or "30"):match("^%d+"))
				t = (t and t >= 5) and t or 30
				udp.hopInterval = t .. "s"
				return udp
			end)() or nil
		},
		obfs = (node.hysteria2_obfs) and {
			type = "salamander",
			salamander = {
				password = node.hysteria2_obfs
			}
		} or nil,
		auth = node.hysteria2_auth_password,
		tls = {
			sni = node.tls_serverName,
			insecure = (node.tls_allowInsecure == "1") and true or false,
			pinSHA256 = (node.tls_pinSHA256) and node.tls_pinSHA256 or nil,
		},
		quic = {
			initStreamReceiveWindow = (node.hysteria2_recv_window) and tonumber(node.hysteria2_recv_window) or nil,
			initConnReceiveWindow = (node.hysteria2_recv_window_conn) and tonumber(node.hysteria2_recv_window_conn) or nil,
			maxIdleTimeout = (function(t)
				t = tonumber(tostring(t or "30"):match("^%d+"))
				return (t and t >= 4 and t <= 120) and t .. "s" or "30s"
			end)(node.hysteria2_idle_timeout),
			keepAlivePeriod = (function(t)
				t = tonumber(tostring(t or "0"):match("^%d+"))
				return (t and t >= 2 and t <= 60) and t .. "s" or nil
			end)(node.hysteria2_keep_alive_period),
			disablePathMTUDiscovery = (node.hysteria2_disable_mtu_discovery) and true or false,
		},
		bandwidth = (node.hysteria2_up_mbps or node.hysteria2_down_mbps) and {
			up = node.hysteria2_up_mbps and node.hysteria2_up_mbps .. " mbps" or nil,
			down = node.hysteria2_down_mbps and node.hysteria2_down_mbps .. " mbps" or nil
		} or nil,
		fast_open = (node.fast_open == "1") and true or false,
		lazy = (node.hysteria2_lazy_start == "1") and true or false,
		socks5 = (local_socks_address and local_socks_port) and {
			listen = local_socks_address .. ":" .. local_socks_port,
			username = (local_socks_username and local_socks_password) and local_socks_username or nil,
			password = (local_socks_username and local_socks_password) and local_socks_password or nil,
			disableUDP = false,
		} or nil,
		http = (local_http_address and local_http_port) and {
			listen = local_http_address .. ":" .. local_http_port,
			username = (local_http_username and local_http_password) and local_http_username or nil,
			password = (local_http_username and local_http_password) and local_http_password or nil,
		} or nil,
		tcpRedirect = ("redirect" == tcp_proxy_way and local_tcp_redir_port) and {
			listen = "0.0.0.0:" .. local_tcp_redir_port
		} or nil,
		tcpTProxy = ("tproxy" == tcp_proxy_way and local_tcp_redir_port) and {
			listen = "0.0.0.0:" .. local_tcp_redir_port
		} or nil,
		udpTProxy = (local_udp_redir_port) and {
			listen = "0.0.0.0:" .. local_udp_redir_port
		} or nil
	}

	return jsonc.stringify(config, 1)
end

_G.gen_config = gen_config

if arg[1] then
	local func =_G[arg[1]]
	if func then
		local var = nil
		if arg[2] then
			var = jsonc.parse(arg[2])
		end
		print(func(var))
	end
end
