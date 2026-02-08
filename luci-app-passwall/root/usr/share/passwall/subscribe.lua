#!/usr/bin/lua

------------------------------------------------
-- @author William Chan <root@williamchan.me>
------------------------------------------------
require 'luci.util'
require 'luci.jsonc'
require 'luci.sys'
local appname = 'passwall'
local api = require ("luci.passwall.api")
local datatypes = require "luci.cbi.datatypes"

-- these global functions are accessed all the time by the event handler
-- so caching them is worth the effort
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub
local split = api.split
local jsonParse, jsonStringify = luci.jsonc.parse, luci.jsonc.stringify
local base64Decode = api.base64Decode
local UrlEncode = api.UrlEncode
local UrlDecode = api.UrlDecode
local uci = api.uci
local fs = api.fs
uci:revert(appname)

local has_ss = api.is_finded("ss-redir")
local has_ss_rust = api.is_finded("sslocal")
local has_ssr = api.is_finded("ssr-local") and api.is_finded("ssr-redir")
local has_trojan_plus = api.is_finded("trojan-plus")
local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")
local has_hysteria2 = api.finded_com("hysteria")
local allowInsecure_default = nil
-- 取节点使用core类型（节点订阅页面未设置时，自动取默认）
local function get_core(field, candidates)
	local v = uci:get(appname, "@global_subscribe[0]", field)
	if not v or v == "" then
		for _, c in ipairs(candidates) do
			if c[1] then return c[2] end
		end
	end
	return v
end
local ss_type_default = get_core("ss_type", {{has_ss,"shadowsocks-libev"},{has_ss_rust,"shadowsocks-rust"},{has_singbox,"sing-box"},{has_xray,"xray"}})
local trojan_type_default = get_core("trojan_type", {{has_trojan_plus,"trojan-plus"},{has_singbox,"sing-box"},{has_xray,"xray"}})
local vmess_type_default = get_core("vmess_type", {{has_xray,"xray"},{has_singbox,"sing-box"}})
local vless_type_default = get_core("vless_type", {{has_xray,"xray"},{has_singbox,"sing-box"}})
local hysteria2_type_default = get_core("hysteria2_type", {{has_hysteria2,"hysteria2"},{has_singbox,"sing-box"},{has_xray,"xray"}})
----
local domain_strategy_default = uci:get(appname, "@global_subscribe[0]", "domain_strategy") or ""
local domain_strategy_node = ""
local preproxy_node_group, to_node_group, chain_node_type = "", "", ""
-- 判断是否过滤节点关键字
local filter_keyword_mode_default = uci:get(appname, "@global_subscribe[0]", "filter_keyword_mode") or "0"
local filter_keyword_discard_list_default = uci:get(appname, "@global_subscribe[0]", "filter_discard_list") or {}
local filter_keyword_keep_list_default = uci:get(appname, "@global_subscribe[0]", "filter_keep_list") or {}
local function is_filter_keyword(value)
	if filter_keyword_mode_default == "1" then
		for k,v in ipairs(filter_keyword_discard_list_default) do
			if value:find(v, 1, true) then
				return true
			end
		end
	elseif filter_keyword_mode_default == "2" then
		local result = true
		for k,v in ipairs(filter_keyword_keep_list_default) do
			if value:find(v, 1, true) then
				result = false
			end
		end
		return result
	elseif filter_keyword_mode_default == "3" then
		local result = false
		for k,v in ipairs(filter_keyword_discard_list_default) do
			if value:find(v, 1, true) then
				result = true
			end
		end
		for k,v in ipairs(filter_keyword_keep_list_default) do
			if value:find(v, 1, true) then
				result = false
			end
		end
		return result
	elseif filter_keyword_mode_default == "4" then
		local result = true
		for k,v in ipairs(filter_keyword_keep_list_default) do
			if value:find(v, 1, true) then
				result = false
			end
		end
		for k,v in ipairs(filter_keyword_discard_list_default) do
			if value:find(v, 1, true) then
				result = true
			end
		end
		return result
	end
	return false
end

local nodeResult = {} -- update result
local isDebug = false

local log = function(...)
	if isDebug == true then
		local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
		print(result)
	else
		api.log(...)
	end
end

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = e
	end
end

-- 获取各项动态配置的当前服务器，可以用 get 和 set， get必须要获取到节点表
local CONFIG = {}
do
	local function import_config(protocol)
		local name = string.upper(protocol)
		local szType = "@global[0]"
		local option = protocol .. "_node"
		
		local node_id = uci:get(appname, szType, option)
		CONFIG[#CONFIG + 1] = {
			log = true,
			remarks = name .. "节点",
			currentNode = node_id and uci:get_all(appname, node_id) or nil,
			set = function(o, server)
				uci:set(appname, szType, option, server)
				o.newNodeId = server
			end
		}
	end
	import_config("tcp")
	import_config("udp")

	if true then
		local i = 0
		local option = "node"
		uci:foreach(appname, "socks", function(t)
			i = i + 1
			local id = t[".name"]
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = id,
				remarks = "Socks节点列表[" .. i .. "]",
				currentNode = node_id and uci:get_all(appname, node_id) or nil,
				set = function(o, server)
					if not server or server == "" then
						if #nodes_table > 0 then
							server = nodes_table[1][".name"]
						end
					end
					uci:set(appname, t[".name"], option, server)
					o.newNodeId = server
				end
			}
			if t.autoswitch_backup_node and #t.autoswitch_backup_node > 0 then
				local flag = "Socks节点列表[" .. i .. "]备用节点的列表"
				local currentNodes = {}
				local newNodes = {}
				for k, node_id in ipairs(t.autoswitch_backup_node) do
					if node_id then
						local currentNode = uci:get_all(appname, node_id) or nil
						if currentNode then
							currentNodes[#currentNodes + 1] = {
								log = true,
								remarks = flag .. "[" .. k .. "]",
								currentNode = currentNode,
								set = function(o, server)
									if server and server ~= "nil" then
										table.insert(o.newNodes, server)
									end
								end
							}
						end
					end
				end
				CONFIG[#CONFIG + 1] = {
					remarks = flag,
					currentNodes = currentNodes,
					newNodes = newNodes,
					set = function(o, newNodes)
						if o then
							if not newNodes then newNodes = o.newNodes end
							uci:set_list(appname, id, "autoswitch_backup_node", newNodes or {})
						end
					end
				}
			end
		end)
	end

	if true then
		local i = 0
		local option = "lbss"
		local function is_ip_port(str)
			if type(str) ~= "string" then return false end
			local ip, port = str:match("^([%d%.]+):(%d+)$")
			return ip and datatypes.ipaddr(ip) and tonumber(port) and tonumber(port) <= 65535
		end
		uci:foreach(appname, "haproxy_config", function(t)
			i = i + 1
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = t[".name"],
				remarks = "HAProxy负载均衡节点列表[" .. i .. "]",
				currentNode = node_id and uci:get_all(appname, node_id) or nil,
				set = function(o, server)
					-- 如果当前 lbss 值不是 ip:port 格式，才进行修改
					if not is_ip_port(t[option]) then
						uci:set(appname, t[".name"], option, server)
						o.newNodeId = server
					end
				end,
				delete = function(o)
					-- 如果当前 lbss 值不是 ip:port 格式，才进行删除
					if not is_ip_port(t[option]) then
						uci:delete(appname, t[".name"])
					end
				end
			}
		end)
	end

	if true then
		local i = 0
		local options = {"tcp", "udp"}
		uci:foreach(appname, "acl_rule", function(t)
			i = i + 1
			for index, value in ipairs(options) do
				local option = value .. "_node"
				local node_id = t[option]
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = t[".name"],
					remarks = "访问控制列表[" .. i .. "]",
					currentNode = node_id and uci:get_all(appname, node_id) or nil,
					set = function(o, server)
						uci:set(appname, t[".name"], option, server)
						o.newNodeId = server
					end
				}
			end
		end)
	end

	uci:foreach(appname, "nodes", function(node)
		local node_id = node[".name"]
		if node.protocol and node.protocol == '_shunt' then
			local rules = {}
			uci:foreach(appname, "shunt_rules", function(e)
				if e[".name"] and e.remarks then
					table.insert(rules, e)
				end
			end)
			table.insert(rules, {
				[".name"] = "default_node",
				remarks = "默认"
			})

			for k, e in pairs(rules) do
				local _node_id = node[e[".name"]] or nil
				if _node_id and api.parseURL(_node_id) then
				else
					CONFIG[#CONFIG + 1] = {
						log = false,
						currentNode = _node_id and uci:get_all(appname, _node_id) or nil,
						remarks = "分流" .. e.remarks .. "节点",
						set = function(o, server)
							if not server then server = "" end
							uci:set(appname, node_id, e[".name"], server)
							o.newNodeId = server
						end
					}
				end
			end
		elseif node.protocol and node.protocol == '_balancing' then
			local flag = "Xray负载均衡节点[" .. node_id .. "]列表"
			local currentNodes = {}
			local newNodes = {}
			if node.balancing_node then
				for k, node in pairs(node.balancing_node) do
					currentNodes[#currentNodes + 1] = {
						log = true,
						node = node,
						currentNode = node and uci:get_all(appname, node) or nil,
						remarks = node,
						set = function(o, server)
							if o and server and server ~= "nil" then
								table.insert(o.newNodes, server)
							end
						end
					}
				end
			end
			CONFIG[#CONFIG + 1] = {
				remarks = flag,
				currentNodes = currentNodes,
				newNodes = newNodes,
				set = function(o, newNodes)
					if o then
						if not newNodes then newNodes = o.newNodes end
						uci:set_list(appname, node_id, "balancing_node", newNodes or {})
					end
				end
			}

			--后备节点
			local currentNode = uci:get_all(appname, node_id) or nil
			if currentNode and currentNode.fallback_node then
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = node_id,
					remarks = "Xray负载均衡节点[" .. node_id .. "]后备节点",
					currentNode = uci:get_all(appname, currentNode.fallback_node) or nil,
					set = function(o, server)
						uci:set(appname, node_id, "fallback_node", server)
						o.newNodeId = server
					end,
					delete = function(o)
						uci:delete(appname, node_id, "fallback_node")
					end
				}
			end
		elseif node.protocol and node.protocol == '_urltest' then
			local flag = "Sing-Box URLTest节点[" .. node_id .. "]列表"
			local currentNodes = {}
			local newNodes = {}
			if node.urltest_node then
				for k, node in pairs(node.urltest_node) do
					currentNodes[#currentNodes + 1] = {
						log = true,
						node = node,
						currentNode = node and uci:get_all(appname, node) or nil,
						remarks = node,
						set = function(o, server)
							if o and server and server ~= "nil" then
								table.insert(o.newNodes, server)
							end
						end
					}
				end
			end
			CONFIG[#CONFIG + 1] = {
				remarks = flag,
				currentNodes = currentNodes,
				newNodes = newNodes,
				set = function(o, newNodes)
					if o then
						if not newNodes then newNodes = o.newNodes end
						uci:set_list(appname, node_id, "urltest_node", newNodes or {})
					end
				end
			}
		else
			--前置代理节点
			local currentNode = uci:get_all(appname, node_id) or nil
			if currentNode and currentNode.preproxy_node then
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = node_id,
					remarks = "节点[" .. node_id .. "]前置代理节点",
					currentNode = uci:get_all(appname, currentNode.preproxy_node) or nil,
					set = function(o, server)
						uci:set(appname, node_id, "preproxy_node", server)
						o.newNodeId = server
					end,
					delete = function(o)
						uci:delete(appname, node_id, "preproxy_node")
					end
				}
			end
			--落地节点
			local currentNode = uci:get_all(appname, node_id) or nil
			if currentNode and currentNode.to_node then
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = node_id,
					remarks = "节点[" .. node_id .. "]落地节点",
					currentNode = uci:get_all(appname, currentNode.to_node) or nil,
					set = function(o, server)
						uci:set(appname, node_id, "to_node", server)
						o.newNodeId = server
					end,
					delete = function(o)
						uci:delete(appname, node_id, "to_node")
					end
				}
			end
		end
	end)

	for k, v in pairs(CONFIG) do
		if v.currentNodes and type(v.currentNodes) == "table" then
			for kk, vv in pairs(v.currentNodes) do
				if vv.currentNode == nil then
					CONFIG[k].currentNodes[kk] = nil
				end
			end
		else
			if v.currentNode == nil then
				if v.delete then
					v.delete()
				end
				CONFIG[k] = nil
			end
		end
	end
end

-- 取机场信息（剩余流量、到期时间）
local subscribe_info = {}
local function get_subscribe_info(cfgid, value)
	if type(cfgid) ~= "string" or cfgid == "" or type(value) ~= "string" then
		return
	end
	value = value:gsub("%s+", "")
	local date_patterns = {"套餐到期：(.+)", "过期时间：(.+)", "有效期至：(.+)", "到期时间：(.+)", "截止日期：(.+)"}
	local expired_date
	for _, p in ipairs(date_patterns) do expired_date = value:match(p) or expired_date end
	local rem_patterns = {"剩余流量：(.+)", "流量剩余：(.+)", "可用流量：(.+)", "套餐剩余：(.+)"}
	local rem_traffic
	for _, p in ipairs(rem_patterns) do rem_traffic = value:match(p) or rem_traffic end
	subscribe_info[cfgid] = subscribe_info[cfgid] or {expired_date = "", rem_traffic = ""}
	if expired_date then
		local function formatDate(str)
			local y, m, d = str:match("(%d%d%d%d)[-/]?(%d%d?)[-/]?(%d%d?)")
			if y and m and d then
				return y .. "." .. m .. "." .. d
			end
			return str
		end
		subscribe_info[cfgid]["expired_date"] = formatDate(expired_date)
	end
	if rem_traffic then
		subscribe_info[cfgid]["rem_traffic"] = rem_traffic
	end
end

-- 设置 ss 协议实现类型
local function set_ss_implementation(result)
	if ss_type_default == "shadowsocks-libev" and has_ss then
		result.type = "SS"
	elseif ss_type_default == "shadowsocks-rust" and has_ss_rust then
		result.type = 'SS-Rust'
	elseif ss_type_default == "xray" and has_xray then
		result.type = 'Xray'
		result.protocol = 'shadowsocks'
		result.transport = 'raw'
	elseif ss_type_default == "sing-box" and has_singbox then
		result.type = 'sing-box'
		result.protocol = 'shadowsocks'
	else
		log("跳过 SS 节点，因未适配到 SS 核心程序，或未正确设置节点使用类型。")
		return nil
	end
	return result
end

-- 处理数据
local function processData(szType, content, add_mode, group)
	--log(content, add_mode, group)
	local result = {
		timeout = 60,
		add_mode = add_mode, --0为手动配置,1为导入,2为订阅
		group = group
	}
	--ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks&group=base64group&udpport=0&uot=0)
	if szType == 'ssr' then
		if not has_ssr then
			log("跳过 SSR 节点，因未安装 SSR 核心程序 shadowsocksr-libev。")
			return nil
		end
		result.type = "SSR"

		local dat = split(content, "/%?")
		local hostInfo = split(dat[1], ':')
		if dat[1]:match('%[(.*)%]') then
			result.address = dat[1]:match('%[(.*)%]')
		else
			result.address = hostInfo[#hostInfo-5]
		end
		result.port = hostInfo[#hostInfo-4]
		result.protocol = hostInfo[#hostInfo-3]
		result.method = hostInfo[#hostInfo-2]
		result.obfs = hostInfo[#hostInfo-1]
		result.password = base64Decode(hostInfo[#hostInfo])	
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			params[t[1]] = t[2]
		end
		result.obfs_param = base64Decode(params.obfsparam)
		result.protocol_param = base64Decode(params.protoparam)
		-- local ssr_group = base64Decode(params.group)
		-- if ssr_group then result.ssr_group = ssr_group end
		result.remarks = base64Decode(params.remarks)
	elseif szType == 'vmess' then
		local info = jsonParse(content)
		if vmess_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif vmess_type_default == "xray" and has_xray then
			result.type = "Xray"
		else
			log("跳过 VMess 节点，因未适配到 VMess 核心程序，或未正确设置节点使用类型。")
			return nil
		end
		result.alter_id = info.aid
		result.address = info.add
		result.port = info.port
		result.protocol = 'vmess'
		result.uuid = info.id
		result.remarks = info.ps
		-- result.mux = 1
		-- result.mux_concurrency = 8

		if not info.net then info.net = "tcp" end
		info.net = string.lower(info.net)
		if result.type == "sing-box" and info.net == "raw" then 
			info.net = "tcp"
		elseif result.type == "Xray" and info.net == "tcp" then
			info.net = "raw"
		end
		if info.net == 'h2' or info.net == 'http' then
			info.net = "http"
			result.transport = (result.type == "Xray") and "xhttp" or "http"
		else
			result.transport = info.net
		end
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
			if result.type == "sing-box" and info.path then
				local ws_path_dat = split(info.path, "?")
				local ws_path = ws_path_dat[1]
				local ws_path_params = {}
				for _, v in pairs(split(ws_path_dat[2], '&')) do
					local t = split(v, '=')
					ws_path_params[t[1]] = t[2]
				end
				if ws_path_params.ed and tonumber(ws_path_params.ed) then
					result.ws_path = ws_path
					result.ws_enableEarlyData = "1"
					result.ws_maxEarlyData = tonumber(ws_path_params.ed)
					result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
				end
			end
		end
		if info.net == "http" then
			if result.type == "Xray" then
				result.xhttp_mode = "stream-one"
				result.xhttp_host = info.host
				result.xhttp_path = info.path
			else
				result.http_host = (info.host and info.host ~= "") and { info.host } or nil
				result.http_path = info.path
			end
		end
		if info.net == 'raw' or info.net == 'tcp' then
			if info.type and info.type ~= "http" then
				info.type = "none"
			end
			result.tcp_guise = info.type
			result.tcp_guise_http_host = (info.host and info.host ~= "") and { info.host } or nil
			result.tcp_guise_http_path = (info.path and info.path ~= "") and { info.path } or nil
		end
		if info.net == 'kcp' or info.net == 'mkcp' then
			info.net = "mkcp"
			result.mkcp_guise = info.type
			result.mkcp_mtu = 1350
			result.mkcp_tti = 50
			result.mkcp_uplinkCapacity = 5
			result.mkcp_downlinkCapacity = 20
			result.mkcp_readBufferSize = 2
			result.mkcp_writeBufferSize = 2
			result.mkcp_seed = info.seed
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.securty
		end
		if info.net == 'grpc' then
			result.grpc_serviceName = info.path
		end
		if info.net == 'xhttp' then
			result.xhttp_host = info.host
			result.xhttp_path = info.path
		end
		if info.net == 'httpupgrade' then
			result.httpupgrade_host = info.host
			result.httpupgrade_path = info.path
		end
		if not info.security then result.security = "auto" end
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.tls_serverName = (info.sni and info.sni ~= "") and info.sni or info.host
			info.allowinsecure = info.allowinsecure or info.insecure
			if info.allowinsecure and (info.allowinsecure == "1" or info.allowinsecure == "0") then
				result.tls_allowInsecure = info.allowinsecure
			else
				result.tls_allowInsecure = allowInsecure_default and "1" or "0"
			end
			result.tls_CertSha = info.pcs
			result.tls_CertByName = info.vcn
		else
			result.tls = "0"
		end

		result.tcp_fast_open = info.tfo

		if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp") then
			log("跳过节点:" .. result.remarks .."，因Sing-Box不支持" .. szType .. "协议的" .. result.transport .. "传输方式，需更换Xray。")
			return nil
		end
	elseif szType == "ss" then
		result = set_ss_implementation(result)
		if not result then return nil end

		--SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
		--userinfo = websafe-base64-encode-utf8(method  ":" password)
		--ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1
		--ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888/?plugin=v2ray-plugin%3Bserver#Example3
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@xxxxxx.com:443?type=ws&path=%2Ftestpath&host=xxxxxx.com&security=tls&fp=&alpn=h3%2Ch2%2Chttp%2F1.1&sni=xxxxxx.com#test-1%40ss
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp4eHh4eHhAeHh4eC54eHh4eC5jb206NTYwMDE#Hong%20Kong-01

		local idx_sp = content:find("#") or 0
		local alias = ""
		if idx_sp > 0 then
			alias = content:sub(idx_sp + 1, -1)
		end
		result.remarks = UrlDecode(alias)
		local info = content:sub(1, idx_sp - 1):gsub("/%?", "?")
		local params = {}
		if info:find("%?") then
			local find_index = info:find("%?")
			local query = split(info, "%?")
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				if #t >= 2 then params[t[1]] = UrlDecode(t[2]) end
			end
			if params.plugin then
				local plugin_info = params.plugin
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts = plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
				end
			end
			if result.plugin and result.plugin == "simple-obfs" then
				result.plugin = "obfs-local"
			end
			info = info:sub(1, find_index - 1)
		end

		local hostInfo = split(base64Decode(UrlDecode(info)), "@")
		if hostInfo and #hostInfo > 0 then
			local host_port = hostInfo[#hostInfo]
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				result.port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local userinfo = nil
			if #hostInfo > 2 then
				userinfo = {}
				for i = 1, #hostInfo - 1 do
					tinsert(userinfo, hostInfo[i])
				end
				userinfo = table.concat(userinfo, '@')
			else
				userinfo = base64Decode(hostInfo[1])
			end
			local method, password
			if userinfo:find(":") then
				method = userinfo:sub(1, userinfo:find(":") - 1)
				password = userinfo:sub(userinfo:find(":") + 1, #userinfo)
			else
				password = hostInfo[1]  --一些链接用明文uuid做密码
			end

			-- 判断密码是否经过url编码
			local function isURLEncodedPassword(pwd)
				if not pwd:find("%%[0-9A-Fa-f][0-9A-Fa-f]") then
					return false
				end
				local ok, decoded = pcall(UrlDecode, pwd)
				return ok and UrlEncode(decoded) == pwd
			end

			local decoded = UrlDecode(password)
			if isURLEncodedPassword(password) and decoded then
				password = decoded
			end

			local _method = (method or "none"):lower()
			method = (_method == "chacha20-poly1305" and "chacha20-ietf-poly1305") or
				(_method == "xchacha20-poly1305" and "xchacha20-ietf-poly1305") or _method

			result.method = method
			result.password = password
			result.tcp_fast_open = params.tfo

			local need_upgrade = (result.type ~= "Xray" and result.type ~= "sing-box")
				and (params.type and params.type ~= "tcp")
				and (params.headerType and params.headerType ~= "none")
			if has_xray and (need_upgrade or params.type == "xhttp") then
				result.type = "Xray"
				result.protocol = "shadowsocks"
			elseif has_singbox and need_upgrade then
				result.type = "sing-box"
				result.protocol = "shadowsocks"
			end

			if result.plugin then
				if result.type == 'Xray' then
					-- obfs-local插件转换成xray支持的格式
					if result.plugin ~= "obfs-local" then
						result.error_msg = "Xray不支持 " .. result.plugin .. " 插件."
					else
						local obfs = result.plugin_opts:match("obfs=([^;]+)") or ""
						local obfs_host = result.plugin_opts:match("obfs%-host=([^;]+)") or ""
						if obfs == "" or obfs_host == "" then
							result.error_msg = "SS " .. result.plugin .. " 插件选项不完整."
						end
						if obfs == "http" then
							result.transport = "raw"
							result.tcp_guise = "http"
							result.tcp_guise_http_host = (obfs_host and obfs_host ~= "") and { obfs_host } or nil
							result.tcp_guise_http_path = { "/" }
						elseif obfs == "tls" then
							result.tls = "1"
							result.tls_serverName = obfs_host
							result.tls_allowInsecure = "1"
						end
						result.plugin = nil
						result.plugin_opts = nil
					end
				else
					result.plugin_enabled = "1"
				end
			end

			if result.type == "SS" then
				local aead2022_methods = { "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305" }
				local aead2022 = false
				for k, v in ipairs(aead2022_methods) do
					if method:lower() == v:lower() then
						aead2022 = true
					end
				end
				if aead2022 then
					-- shadowsocks-libev 不支持2022加密
					result.error_msg = "shadowsocks-libev 不支持2022加密."
				end
			end

			if params.type then
				params.type = string.lower(params.type)
				if result.type == "sing-box" and params.type == "raw" then 
					params.type = "tcp"
				elseif result.type == "Xray" and params.type == "tcp" then
					params.type = "raw"
				end
				if params.type == "h2" or params.type == "http" then
					params.type = "http"
					result.transport = (result.type == "Xray") and "xhttp" or "http"
				else
					result.transport = params.type
				end
				if result.type ~= "SS-Rust" and result.type ~= "SS" then
					if params.type == 'ws' then
						result.ws_host = params.host
						result.ws_path = params.path
						if result.type == "sing-box" and params.path then
							local ws_path_dat = split(params.path, "%?")
							local ws_path = ws_path_dat[1]
							local ws_path_params = {}
							for _, v in pairs(split(ws_path_dat[2], '&')) do
								local t = split(v, '=')
								ws_path_params[t[1]] = t[2]
							end
							if ws_path_params.ed and tonumber(ws_path_params.ed) then
								result.ws_path = ws_path
								result.ws_enableEarlyData = "1"
								result.ws_maxEarlyData = tonumber(ws_path_params.ed)
								result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
							end
						end
					end
					if params.type == "http" then
						if result.type == "sing-box" then
							result.transport = "http"
							result.http_host = (params.host and params.host ~= "") and { params.host } or nil
							result.http_path = params.path
						elseif result.type == "Xray" then
							result.transport = "xhttp"
							result.xhttp_mode = "stream-one"
							result.xhttp_host = params.host
							result.xhttp_path = params.path
						end
					end
					if params.type == 'raw' or params.type == 'tcp' then
						result.tcp_guise = params.headerType or "none"
						result.tcp_guise_http_host = (params.host and params.host ~= "") and { params.host } or nil
						result.tcp_guise_http_path = (params.path and params.path ~= "") and { params.path } or nil
					end
					if params.type == 'kcp' or params.type == 'mkcp' then
						result.transport = "mkcp"
						result.mkcp_guise = params.headerType or "none"
						result.mkcp_mtu = 1350
						result.mkcp_tti = 50
						result.mkcp_uplinkCapacity = 5
						result.mkcp_downlinkCapacity = 20
						result.mkcp_readBufferSize = 2
						result.mkcp_writeBufferSize = 2
						result.mkcp_seed = params.seed
					end
					if params.type == 'quic' then
						result.quic_guise = params.headerType or "none"
						result.quic_key = params.key
						result.quic_security = params.quicSecurity or "none"
					end
					if params.type == 'grpc' then
						if params.path then result.grpc_serviceName = params.path end
						if params.serviceName then result.grpc_serviceName = params.serviceName end
						result.grpc_mode = params.mode or "gun"
					end
					if params.type == 'xhttp' then
						if result.type ~= "Xray" then
							result.error_msg = "请更换 Xray 以支持 xhttp 传输方式."
						end
						result.xhttp_host = params.host
						result.xhttp_path = params.path
						result.xhttp_mode = params.mode or "auto"
						result.use_xhttp_extra = (params.extra and params.extra ~= "") and "1" or nil
						result.xhttp_extra = (params.extra and params.extra ~= "") and api.base64Encode(params.extra) or nil
						local success, Data = pcall(jsonParse, params.extra)
						if success and Data then
							local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
									or (Data.downloadSettings and Data.downloadSettings.address)
							result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "") or nil
						end
					end
					result.tls = "0"
					if params.security == "tls" or params.security == "reality" then
						result.tls = "1"
						result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
						result.alpn = params.alpn
						if params.fp and params.fp ~= "" then
							result.utls = "1"
							result.fingerprint = params.fp
						end
						if params.ech and params.ech ~= "" then
							result.ech = "1"
							result.ech_config = params.ech
						end
						result.tls_CertSha = params.pcs
						result.tls_CertByName = params.vcn
						if params.security == "reality" then
							result.reality = "1"
							result.reality_publicKey = params.pbk or nil
							result.reality_shortId = params.sid or nil
							result.reality_spiderX = params.spx or nil
							result.use_mldsa65Verify = (params.pqv and params.pqv ~= "") and "1" or nil
							result.reality_mldsa65Verify = params.pqv or nil
						end
					end
					params.allowinsecure = params.allowinsecure or params.insecure
					if params.allowinsecure and (params.allowinsecure == "1" or params.allowinsecure == "0") then
						result.tls_allowInsecure = params.allowinsecure
					else
						result.tls_allowInsecure = allowInsecure_default and "1" or "0"
					end
					result.uot = params.udp
				elseif (params.type ~= "tcp" and params.type ~= "raw") and (params.headerType and params.headerType ~= "none") then
					result.error_msg = "请更换Xray或Sing-Box来支持SS更多的传输方式."
				end
			end

			if params["shadow-tls"] then
				if result.type ~= "sing-box" and result.type ~= "SS-Rust" then
					result.error_msg =  ss_type_default .. " 不支持 shadow-tls 插件."
				else
					-- 解析SS Shadow-TLS 插件参数
					local function parseShadowTLSParams(b64str, out)
						local ok, data = pcall(jsonParse, base64Decode(b64str))
						if not ok or type(data) ~= "table" then return "" end
						if type(out) == "table" then
							for k, v in pairs(data) do out[k] = v end
						end
						local t = {}
						if data.version then t[#t+1] = "v" .. data.version .. "=1" end
						if data.password then t[#t+1] = "passwd=" .. data.password end
						for k, v in pairs(data) do
							if k ~= "version" and k ~= "password" then
								t[#t+1] = k .. "=" .. tostring(v)
							end
						end
						return table.concat(t, ";")
					end

					if result.type == "SS-Rust" then
						result.plugin_enabled = "1"
						result.plugin = "shadow-tls"
						result.plugin_opts = parseShadowTLSParams(params["shadow-tls"])
					elseif result.type == "sing-box" then
						local shadowtlsOpt = {}
						parseShadowTLSParams(params["shadow-tls"], shadowtlsOpt)
						if next(shadowtlsOpt) then
							result.shadowtls = "1"
							result.shadowtls_version = shadowtlsOpt.version or "1"
							result.shadowtls_password = shadowtlsOpt.password
							result.shadowtls_serverName = shadowtlsOpt.host
							if shadowtlsOpt.fingerprint then
								result.shadowtls_utls = "1"
								result.shadowtls_fingerprint = shadowtlsOpt.fingerprint or "chrome"
							end
						end
					end
				end
			end
		end
	elseif szType == "trojan" then
		if trojan_type_default == "trojan-plus" and has_trojan_plus then
			result.type = "Trojan-Plus"
		elseif trojan_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
			result.protocol = 'trojan'
		elseif trojan_type_default == "xray" and has_xray then
			result.type = 'Xray'
			result.protocol = 'trojan'
		else
			log("跳过 Trojan 节点，因未适配到 Trojan 核心程序，或未正确设置节点使用类型。")
			return nil
		end
		
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "%?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				if #t > 1 then
					params[string.lower(t[1])] = UrlDecode(t[2])
				end
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local peer, sni = nil, ""
			if params.peer then peer = params.peer end
			sni = params.sni and params.sni or ""
			result.port = port

			result.tls = '1'
			result.tls_serverName = peer and peer or sni
			result.tls_CertSha = params.pcs
			result.tls_CertByName = params.vcn

			params.allowinsecure = params.allowinsecure or params.insecure
			if params.allowinsecure then
				if params.allowinsecure == "1" or params.allowinsecure == "0" then
					result.tls_allowInsecure = params.allowinsecure
				else
					result.tls_allowInsecure = string.lower(params.allowinsecure) == "true" and "1" or "0"
				end
				--log(result.remarks .. ' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
			else
				result.tls_allowInsecure = allowInsecure_default and "1" or "0"
			end

			if not params.type then params.type = "tcp" end
			params.type = string.lower(params.type)
			if result.type == "sing-box" and params.type == "raw" then 
				params.type = "tcp"
			elseif result.type == "Xray" and params.type == "tcp" then
				params.type = "raw"
			end
			if params.type == "h2" or params.type == "http" then
				params.type = "http"
				result.transport = (result.type == "Xray") and "xhttp" or "http"
			else
				result.transport = params.type
			end
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "%?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == "http" then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = (params.host and params.host ~= "") and { params.host } or nil
					result.http_path = params.path
				elseif result.type == "Xray" then
					result.transport = "xhttp"
					result.xhttp_mode = "stream-one"
					result.xhttp_host = params.host
					result.xhttp_path = params.path
				end
			end
			if params.type == 'raw' or params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = (params.host and params.host ~= "") and { params.host } or nil
				result.tcp_guise_http_path = (params.path and params.path ~= "") and { params.path } or nil
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_mtu = 1350
				result.mkcp_tti = 50
				result.mkcp_uplinkCapacity = 5
				result.mkcp_downlinkCapacity = 20
				result.mkcp_readBufferSize = 2
				result.mkcp_writeBufferSize = 2
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				if params.path then result.grpc_serviceName = params.path end
				if params.serviceName then result.grpc_serviceName = params.serviceName end
				result.grpc_mode = params.mode or "gun"
			end
			if params.type == 'xhttp' then
				result.xhttp_host = params.host
				result.xhttp_path = params.path
			end
			if params.type == 'httpupgrade' then
				result.httpupgrade_host = params.host
				result.httpupgrade_path = params.path
			end

			result.alpn = params.alpn
			result.tcp_fast_open = params.tfo

			if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp") then
				log("跳过节点:" .. result.remarks .."，因Sing-Box不支持" .. szType .. "协议的" .. result.transport .. "传输方式，需更换Xray。")
				return nil
			end
		end

	elseif szType == "ssd" then
		result = set_ss_implementation(result)
		if not result then return nil end
		result.address = content.server
		result.port = content.port
		result.password = content.password
		result.method = content.encryption
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_options
		result.group = content.airport
		result.remarks = content.remarks
	elseif szType == "vless" then
		if vless_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif vless_type_default == "xray" and has_xray then
			result.type = "Xray"
		else
			log("跳过 VLESS 节点，因未适配到 VLESS 核心程序，或未正确设置节点使用类型。")
			return nil
		end
		result.protocol = "vless"
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.uuid = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "%?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = UrlDecode(t[2])
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			if not params.type then params.type = "tcp" end
			params.type = string.lower(params.type)
			if ({ xhttp=true, kcp=true, mkcp=true })[params.type] and result.type ~= "Xray" and has_xray then
				result.type = "Xray"
			end
			if result.type == "sing-box" and params.type == "raw" then 
				params.type = "tcp"
			elseif result.type == "Xray" and params.type == "tcp" then
				params.type = "raw"
			end
			if params.type == "h2" or params.type == "http" then
				params.type = "http"
				result.transport = (result.type == "Xray") and "xhttp" or "http"
			else
				result.transport = params.type
			end
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "%?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == "http" then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = (params.host and params.host ~= "") and { params.host } or nil
					result.http_path = params.path
				elseif result.type == "Xray" then
					result.transport = "xhttp"
					result.xhttp_mode = "stream-one"
					result.xhttp_host = params.host
					result.xhttp_path = params.path
				end
			end
			if params.type == 'raw' or params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = (params.host and params.host ~= "") and { params.host } or nil
				result.tcp_guise_http_path = (params.path and params.path ~= "") and { params.path } or nil
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_mtu = 1350
				result.mkcp_tti = 50
				result.mkcp_uplinkCapacity = 5
				result.mkcp_downlinkCapacity = 20
				result.mkcp_readBufferSize = 2
				result.mkcp_writeBufferSize = 2
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				if params.path then result.grpc_serviceName = params.path end
				if params.serviceName then result.grpc_serviceName = params.serviceName end
				result.grpc_mode = params.mode or "gun"
			end
			if params.type == 'xhttp' then
				result.xhttp_host = params.host
				result.xhttp_path = params.path
				result.xhttp_mode = params.mode or "auto"
				result.use_xhttp_extra = (params.extra and params.extra ~= "") and "1" or nil
				result.xhttp_extra = (params.extra and params.extra ~= "") and api.base64Encode(params.extra) or nil
				local success, Data = pcall(jsonParse, params.extra)
				if success and Data then
					local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
							or (Data.downloadSettings and Data.downloadSettings.address)
					result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "") or nil
				end
			end
			if params.type == 'httpupgrade' then
				result.httpupgrade_host = params.host
				result.httpupgrade_path = params.path
			end
			
			result.encryption = params.encryption or "none"

			result.flow = params.flow and params.flow:gsub("-udp443", "") or nil

			result.tls = "0"
			if params.security == "tls" or params.security == "reality" then
				result.tls = "1"
				result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
				result.alpn = params.alpn
				if params.fp and params.fp ~= "" then
					result.utls = "1"
					result.fingerprint = params.fp
				end
				if params.ech and params.ech ~= "" then
					result.ech = "1"
					result.ech_config = params.ech
				end
				result.tls_CertSha = params.pcs
				result.tls_CertByName = params.vcn
				if params.security == "reality" then
					result.reality = "1"
					result.reality_publicKey = params.pbk or nil
					result.reality_shortId = params.sid or nil
					result.reality_spiderX = params.spx or nil
					result.use_mldsa65Verify = (params.pqv and params.pqv ~= "") and "1" or nil
					result.reality_mldsa65Verify = params.pqv or nil
				end
			end

			result.port = port

			params.allowinsecure = params.allowinsecure or params.insecure
			if params.allowinsecure and (params.allowinsecure == "1" or params.allowinsecure == "0") then
				result.tls_allowInsecure = params.allowinsecure
			else
				result.tls_allowInsecure = allowInsecure_default and "1" or "0"
			end

			result.tcp_fast_open = params.tfo

			if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp") then
				log("跳过节点:" .. result.remarks .."，因Sing-Box不支持" .. szType .. "协议的" .. result.transport .. "传输方式，需更换Xray。")
				return nil
			end
		end
	elseif szType == 'hysteria' then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "hysteria"
		else
			log("跳过 Hysteria 节点，因未安装 Hysteria 核心程序 Sing-box。")
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		
		local dat = split(content:gsub("/%?", "?"), '%?')
		local host_port = dat[1]
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			if #t > 0 then
				params[t[1]] = t[2]
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.hysteria_obfs = params.obfsParam
		result.hysteria_auth_type = "string"
		result.hysteria_auth_password = params.auth
		result.tls_serverName = params.peer
		params.allowinsecure = params.allowinsecure or params.insecure
		if params.allowinsecure and (params.allowinsecure == "1" or params.allowinsecure == "0") then
			result.tls_allowInsecure = params.allowinsecure
			--log(result.remarks ..' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
		result.hysteria_alpn = params.alpn
		result.hysteria_up_mbps = params.upmbps
		result.hysteria_down_mbps = params.downmbps
		result.hysteria_hop = params.mport

	elseif szType == 'hysteria2' or szType == 'hy2' then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@") then
			local contents = split(content, "@")
			result.hysteria2_auth_password = UrlDecode(contents[1])
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "%?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local t = split(v, '=')
			if #t > 1 then
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		result.tls_CertSha = params.pcs
		result.tls_CertByName = params.vcn
		params.allowinsecure = params.allowinsecure or params.insecure
		if params.allowinsecure and (params.allowinsecure == "1" or params.allowinsecure == "0") then
			result.tls_allowInsecure = params.allowinsecure
			--log(result.remarks ..' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
		result.hysteria2_tls_pinSHA256 = params.pinSHA256
		result.hysteria2_hop = params.mport

		if (hysteria2_type_default == "sing-box" and has_singbox) or (hysteria2_type_default == "xray" and has_xray) then
			local is_singbox = hysteria2_type_default == "sing-box" and has_singbox
			result.type = is_singbox and 'sing-box' or 'Xray'
			result.protocol = "hysteria2"
			if params["obfs-password"] or params["obfs_password"] then
				result.hysteria2_obfs_type = "salamander"
				result.hysteria2_obfs_password = params["obfs-password"] or params["obfs_password"]
			end
		elseif has_hysteria2 then
			result.type = "Hysteria2"
			if params["obfs-password"] or params["obfs_password"] then
				result.hysteria2_obfs = params["obfs-password"] or params["obfs_password"]
			end
		else
			log("跳过 Hysteria2 节点，因未适配到 Hysteria2 核心程序，或未正确设置节点使用类型。")
			return nil
		end
	elseif szType == 'tuic' then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "tuic"
		else
			log("跳过 Tuic 节点，因未安装 Tuic 核心程序 Sing-box。")
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@") then
			local contents = split(content, "@")
			if contents[1]:find(":") then
				local userinfo = split(contents[1], ":")
				result.uuid = UrlDecode(userinfo[1])
				result.password = UrlDecode(userinfo[2])
			end
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "%?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local t = split(v, '=')
			if #t > 1 then
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
		end
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		result.tuic_alpn = params.alpn or "default"
		result.tuic_congestion_control = params.congestion_control or "cubic"
		result.tuic_udp_relay_mode = params.udp_relay_mode or "native"
		params.allowinsecure = params.allowinsecure or params.insecure
		if params.allowinsecure then
			if params.allowinsecure == "1" or params.allowinsecure == "0" then
				result.tls_allowInsecure = params.allowinsecure
			else
				result.tls_allowInsecure = string.lower(params.allowinsecure) == "true" and "1" or "0"
			end
			--log(result.remarks .. ' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
	elseif szType == "anytls" then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "anytls"
		else
			log("跳过 AnyTLS 节点，因未安装 AnyTLS 核心程序 Sing-box 1.12。")
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "%?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = UrlDecode(t[2])
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end
			result.tls = "0"
			if (not params.security or params.security == "") and params.sni and params.sni ~= "" then
				params.security = "tls"
			end
			if params.security == "tls" or params.security == "reality" then
				result.tls = "1"
				result.tls_serverName = params.sni
				result.alpn = params.alpn
				if params.fp and params.fp ~= "" then
					result.utls = "1"
					result.fingerprint = params.fp
				end
				if params.security == "reality" then
					result.reality = "1"
					result.reality_publicKey = params.pbk or nil
					result.reality_shortId = params.sid or nil
				end
			end
			result.port = port
			params.allowinsecure = params.allowinsecure or params.insecure
			if params.allowinsecure and (params.allowinsecure == "1" or params.allowinsecure == "0") then
				result.tls_allowInsecure = params.allowinsecure
			else
				result.tls_allowInsecure = allowInsecure_default and "1" or "0"
			end
			local singbox_version = api.get_app_version("sing-box")
			local version_ge_1_12 = api.compare_versions(singbox_version:match("[^v]+"), ">=", "1.12.0")
			if not has_singbox or not version_ge_1_12 then
				log("跳过节点:" .. result.remarks .."，因" .. szType .. "类型的节点需要 Sing-Box 1.12 以上版本支持。")
				return nil
			end
		end
	else
		log('暂时不支持' .. szType .. "类型的节点订阅，跳过此节点。")
		return nil
	end
	if not result.remarks or result.remarks == "" then
		if result.address and result.port then
			result.remarks = result.address .. ':' .. result.port
		else
			result.remarks = "NULL"
		end
	end
	return result
end

local function curl(url, file, ua, mode)
	if not url or url == "" then return 404 end
	local curl_args = {
		"-skL", "-w %{http_code}", "--retry 3", "--connect-timeout 3"
	}
	if ua and ua ~= "" and ua ~= "curl" then
		ua = (ua == "passwall") and ("passwall/" .. api.get_version()) or ua
		curl_args[#curl_args + 1] = '--user-agent "' .. ua .. '"'
	end
	curl_args[#curl_args + 1] = get_headers()
	local return_code, result
	if mode == "direct" then
		return_code, result = api.curl_base(url, file, curl_args)
	elseif mode == "proxy" then
		return_code, result = api.curl_proxy(url, file, curl_args)
	else
		return_code, result = api.curl_logic(url, file, curl_args)
	end
	return tonumber(result)
end

function get_headers()
	local cache_file = "/tmp/etc/" .. appname .. "_tmp/sub_curl_headers"
	if fs.access(cache_file) then
		return luci.sys.exec("cat " .. cache_file)
	end
	local headers = {}

	local function readfile(path)
		local f = io.open(path, "r")
		if not f then return nil end
		local c = f:read("*a")
		f:close()
		return api.trim(c)
	end

	headers[#headers + 1] = "x-device-os: OpenWrt"

	local rel = readfile("/etc/openwrt_release")
	local os_ver = rel and rel:match("DISTRIB_RELEASE='([^']+)'")
	if os_ver then
		headers[#headers + 1] = "x-ver-os: " .. os_ver
	end

	local model = readfile("/tmp/sysinfo/model")
	if model then
		headers[#headers + 1] = "x-device-model: " .. model
	end

	local mac = readfile("/sys/class/net/eth0/address")
	if mac and model then
		local raw = mac .. "-" .. model
		local p = io.popen("printf '%s' '" .. raw:gsub("'", "'\\''") .. "' | sha256sum")
		if p then
			local hash = p:read("*l")
			p:close()
			hash = hash and hash:match("^%w+")
			if hash then
				headers[#headers + 1] = "x-hwid: " .. hash
			end
		end
	end

	local out = {}
	for i = 1, #headers do
		out[i] = "-H '" .. headers[i]:gsub("'", "'\\''") .. "'"
	end
	local headers_str = table.concat(out, " ")
	local f = io.open(cache_file, "w"); if f then f:write(headers_str); f:close() end
	return headers_str
end

local function truncate_nodes(group)
	for _, config in pairs(CONFIG) do
		if config.currentNodes and #config.currentNodes > 0 then
			local newNodes = {}
			local removeNodesSet = {}
			for k, v in pairs(config.currentNodes) do
				if v.currentNode and v.currentNode.add_mode == "2" then
					if (not group) or (group:lower() == (v.currentNode.group or ""):lower()) then
						removeNodesSet[v.currentNode[".name"]] = true
					end
				end
			end
			for _, value in ipairs(config.currentNodes) do
				if not removeNodesSet[value.currentNode[".name"]] then
					newNodes[#newNodes + 1] = value.currentNode[".name"]
				end
			end
			if config.set then
				config.set(config, newNodes)
			end
		else
			if config.currentNode and config.currentNode.add_mode == "2" then
				if (not group) or (group:lower() == (config.currentNode.group or ""):lower()) then
					if config.delete then
						config.delete(config)
					elseif config.set then
						config.set(config, "")
					end
				end
			end
		end
	end
	uci:foreach(appname, "nodes", function(node)
		if node.add_mode == "2" then
			if (not group) or (group:lower() == (node.group or ""):lower()) then
				uci:delete(appname, node['.name'])
			end
		end
	end)
	uci:foreach(appname, "subscribe_list", function(o)
		if (not group) or (group:lower() == (o.remark or ""):lower()) then
			uci:delete(appname, o['.name'], "md5")
		end
	end)
	api.uci_save(uci, appname, true)
end

local function select_node(nodes, config, parentConfig)
	if config.currentNode then
		local server
		-- 特别优先级 cfgid
		if config.currentNode[".name"] then
			for index, node in pairs(nodes) do
				if node[".name"] == config.currentNode[".name"] then
					if config.log == nil or config.log == true then
						log('更新【' .. config.remarks .. '】匹配节点：' .. node.remarks)
					end
					server = node[".name"]
					break
				end
			end
		end
		-- 第一优先级 类型 + 备注 + IP + 端口
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.remarks and config.currentNode.address and config.currentNode.port then
					if node.type and node.remarks and node.address and node.port then
						if node.type == config.currentNode.type and node.remarks == config.currentNode.remarks and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第一匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第二优先级 类型 + IP + 端口
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.address and config.currentNode.port then
					if node.type and node.address and node.port then
						if node.type == config.currentNode.type and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第二匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第三优先级 IP + 端口
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address and config.currentNode.port then
					if node.address and node.port then
						if node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第三匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第四优先级 IP
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address then
					if node.address then
						if node.address == config.currentNode.address then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第四匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第五优先级备注
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.remarks then
					if node.remarks then
						if node.remarks == config.currentNode.remarks then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第五匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		if not parentConfig then
			-- 还不行 随便找一个
			if not server then
				if #nodes_table > 0 then
					if config.log == nil or config.log == true then
						log('【' .. config.remarks .. '】' .. '无法找到最匹配的节点，当前已更换为：' .. nodes_table[1].remarks)
					end
					server = nodes_table[1][".name"]
				end
			end
		end
		if server then
			if parentConfig then
				config.set(parentConfig, server)
			else
				config.set(config, server)
			end
		end
	else
		if not parentConfig then
			config.set(config, "")
		end
	end
end

local function update_node(manual)
	if next(nodeResult) == nil then
		log("没有可用的节点信息更新。")
		return
	end

	local group = {}
	for _, v in ipairs(nodeResult) do
		group[v["remark"]:lower()] = true
	end

	if manual == 0 and next(group) then
		uci:foreach(appname, "nodes", function(node)
			-- 如果未发现新节点或手动导入的节点就不要删除了...
			if node.add_mode == "2" and (node.group and group[node.group:lower()] == true) then
				uci:delete(appname, node['.name'])
			end
		end)
	end
	for _, v in ipairs(nodeResult) do
		local remark = v["remark"]
		local list = v["list"]
		for _, vv in ipairs(list) do
			local cfgid = uci:section(appname, "nodes", api.gen_short_uuid())
			for kkk, vvv in pairs(vv) do
				if type(vvv) == "table" and next(vvv) ~= nil then
					uci:set_list(appname, cfgid, kkk, vvv)
				else
					if kkk ~= "group" or vvv ~= "default" then
						uci:set(appname, cfgid, kkk, vvv)
					end
					-- sing-box 域名解析策略
					if kkk == "type" and vvv == "sing-box" then
						uci:set(appname, cfgid, "domain_strategy", domain_strategy_node)
					end
					-- 订阅组链式代理
					if chain_node_type ~= "" and kkk == "type" and (vvv == "Xray" or vvv == "sing-box") then
						if preproxy_node_group ~="" then
							uci:set(appname, cfgid, "chain_proxy", "1")
							uci:set(appname, cfgid, "preproxy_node", preproxy_node_group)
						elseif to_node_group ~= "" then
							uci:set(appname, cfgid, "chain_proxy", "2")
							uci:set(appname, cfgid, "to_node", to_node_group)
						end
					end		
				end
			end
		end
	end
	-- 更新机场信息
	for cfgid, info in pairs(subscribe_info) do
		for key, value in pairs(info) do
			if value ~= "" then
				uci:set(appname, cfgid, key, value)
			else
				uci:delete(appname, cfgid, key)
			end
		end
	end
	api.uci_save(uci, appname, true)

	if next(CONFIG) then
		local nodes = {}
		uci:foreach(appname, "nodes", function(node)
			nodes[#nodes + 1] = node
		end)

		for _, config in pairs(CONFIG) do
			if config.currentNodes and #config.currentNodes > 0 then
				if config.remarks and config.currentNodes[1].log ~= false then
					log('----【' .. config.remarks .. '】----')
				end
				for kk, vv in pairs(config.currentNodes) do
					select_node(nodes, vv, config)
				end
				config.set(config)
			else
				select_node(nodes, config)
			end
		end

		api.uci_save(uci, appname, true)
	end

	if arg[3] == "cron" then
		if not fs.access("/var/lock/" .. appname .. ".lock") then
			luci.sys.call("touch /tmp/lock/" .. appname .. "_cron.lock")
		end
	end

	if manual ~= 1 then
		luci.sys.call("/etc/init.d/" .. appname .. " restart > /dev/null 2>&1 &")
	end
end

local function parse_link(raw, add_mode, group, cfgid)
	if raw and #raw > 0 then
		local nodes, szType
		local node_list = {}
		-- SSD 似乎是这种格式 ssd:// 开头的
		if raw:find('ssd://') then
			szType = 'ssd'
			local nEnd = select(2, raw:find('ssd://'))
			nodes = base64Decode(raw:sub(nEnd + 1, #raw))
			nodes = jsonParse(nodes)
			local extra = {
				airport = nodes.airport,
				port = nodes.port,
				encryption = nodes.encryption,
				password = nodes.password
			}
			local servers = {}
			-- SS里面包着 干脆直接这样
			for _, server in ipairs(nodes.servers) do
				tinsert(servers, setmetatable(server, { __index = extra }))
			end
			nodes = servers
		else
			-- ssd 外的格式
			if add_mode == "1" then
				nodes = split(raw, "\n")
			else
				nodes = split(base64Decode(raw):gsub("\r\n", "\n"), "\n")
			end
		end

		for _, v in ipairs(nodes) do
			if v and (szType == 'ssd' or not string.match(v, "^%s*$")) then
				xpcall(function ()
					local result
					if szType == 'ssd' then
						result = processData(szType, v, add_mode, group)
					elseif not szType then
						local node = api.trim(v)
						local dat = split(node, "://")
						if dat and dat[1] and dat[2] then
							if dat[1] == 'vmess' or dat[1] == 'ssr' then
								local link = api.trim(dat[2]:gsub("#.*$", ""))
								result = processData(dat[1], base64Decode(link), add_mode, group)
							else
								local link = dat[2]:gsub("&amp;", "&"):gsub("%s*#%s*", "#")  -- 一些奇葩的链接用"&amp;"当做"&"，"#"前后带空格
								result = processData(dat[1], link, add_mode, group)
							end
						end
					else
						log('跳过未知类型: ' .. szType)
					end
					-- log(result)
					if result then
						if result.error_msg then
							log('丢弃节点: ' .. result.remarks .. ", 原因:" .. result.error_msg)
						elseif not result.type then
							log('丢弃节点: ' .. result.remarks .. ", 找不到可使用二进制.")
						elseif (add_mode == "2" and is_filter_keyword(result.remarks)) or not result.address or result.remarks == "NULL" or result.address == "127.0.0.1" or
								(not datatypes.hostname(result.address) and not (api.is_ip(result.address))) then
							log('丢弃过滤节点: ' .. result.type .. ' 节点, ' .. result.remarks)
						else
							tinsert(node_list, result)
						end
						if add_mode == "2" then
							get_subscribe_info(cfgid, result.remarks)
						end
					end
				end, function (err)
					--log(err)
					log(v, "解析错误，跳过此节点。")
				end
			)
			end
		end
		if #node_list > 0 then
			nodeResult[#nodeResult + 1] = {
				remark = group,
				list = node_list
			}
		end
		log('成功解析【' .. group .. '】节点数量: ' .. #node_list)
	else
		if add_mode == "2" then
			log('获取到的【' .. group .. '】订阅内容为空，可能是订阅地址无效，或是网络问题，请诊断！')
		end
	end
end

local execute = function()
	do
		local subscribe_list = {}
		local fail_list = {}
		if arg[2] ~= "all" then
			string.gsub(arg[2], '[^' .. "," .. ']+', function(w)
				subscribe_list[#subscribe_list + 1] = uci:get_all(appname, w) or {}
			end)
		else
			uci:foreach(appname, "subscribe_list", function(o)
				subscribe_list[#subscribe_list + 1] = o
			end)
		end

		local manual_sub = arg[3] == "manual"

		for index, value in ipairs(subscribe_list) do
			local cfgid = value[".name"]
			local remark = value.remark or ""
			local url = value.url or ""
			if value.allowInsecure and value.allowInsecure == "1" then
				allowInsecure_default = true
			end
			local filter_keyword_mode = value.filter_keyword_mode or "5"
			if filter_keyword_mode == "0" then
				filter_keyword_mode_default = "0"
			elseif filter_keyword_mode == "1" then
				filter_keyword_mode_default = "1"
				filter_keyword_discard_list_default = value.filter_discard_list or {}
			elseif filter_keyword_mode == "2" then
				filter_keyword_mode_default = "2"
				filter_keyword_keep_list_default = value.filter_keep_list or {}
			elseif filter_keyword_mode == "3" then
				filter_keyword_mode_default = "3"
				filter_keyword_keep_list_default = value.filter_keep_list or {}
				filter_keyword_discard_list_default = value.filter_discard_list or {}
			elseif filter_keyword_mode == "4" then
				filter_keyword_mode_default = "4"
				filter_keyword_keep_list_default = value.filter_keep_list or {}
				filter_keyword_discard_list_default = value.filter_discard_list or {}
			end
			local ss_type = value.ss_type or "global"
			if ss_type ~= "global" then
				ss_type_default = ss_type
			end
			local trojan_type = value.trojan_type or "global"
			if trojan_type ~= "global" then
				trojan_type_default = trojan_type
			end
			local vmess_type = value.vmess_type or "global"
			if vmess_type ~= "global" then
				vmess_type_default = vmess_type
			end
			local vless_type = value.vless_type or "global"
			if vless_type ~= "global" then
				vless_type_default = vless_type
			end
			local hysteria2_type = value.hysteria2_type or "global"
			if hysteria2_type ~= "global" then
				hysteria2_type_default = hysteria2_type
			end
			local domain_strategy = value.domain_strategy or "global"
			if domain_strategy ~= "global" then
				domain_strategy_node = domain_strategy
			else
				domain_strategy_node = domain_strategy_default
			end

			-- 订阅组链式代理
			local function valid_chain_node(node)
				if not node then return "" end
				local cp = uci:get(appname, node, "chain_proxy") or ""
				local am = uci:get(appname, node, "add_mode") or "0"
				chain_node_type = (cp == "" and am ~= "2") and (uci:get(appname, node, "type") or "") or ""
				if chain_node_type ~= "Xray" and chain_node_type ~= "sing-box" then
					chain_node_type = ""
					return ""
				end
				return node
			end
			preproxy_node_group = (value.chain_proxy == "1") and valid_chain_node(value.preproxy_node) or ""
			to_node_group = (value.chain_proxy == "2") and valid_chain_node(value.to_node) or ""

			local ua = value.user_agent
			local access_mode = value.access_mode
			local result = (not access_mode) and "自动" or (access_mode == "direct" and "直连访问" or (access_mode == "proxy" and "通过代理" or "自动"))
			log('正在订阅:【' .. remark .. '】' .. url .. ' [' .. result .. ']')
			local tmp_file = "/tmp/" .. cfgid
			value.http_code = curl(url, tmp_file, ua, access_mode)
			if value.http_code ~= 200 then
				fail_list[#fail_list + 1] = value
			else
				if luci.sys.call("[ -f " .. tmp_file .. " ] && sed -i -e '/^[ \t]*$/d' -e '/^[ \t]*\r$/d' " .. tmp_file) == 0 then
					local f = io.open(tmp_file, "r")
					local stdout = f:read("*all")
					f:close()
					local raw_data = api.trim(stdout)
					local old_md5 = value.md5 or ""
					local new_md5 = luci.sys.exec("md5sum " .. tmp_file .. " 2>/dev/null | awk '{print $1}'"):gsub("\n", "")
					if not manual_sub and old_md5 == new_md5 then
						log('订阅:【' .. remark .. '】没有变化，无需更新。')
					else
						parse_link(raw_data, "2", remark, cfgid)
						uci:set(appname, cfgid, "md5", new_md5)
					end
				else
					fail_list[#fail_list + 1] = value
				end
			end
			luci.sys.call("rm -f " .. tmp_file)
			allowInsecure_default = nil
			filter_keyword_mode_default = uci:get(appname, "@global_subscribe[0]", "filter_keyword_mode") or "0"
			filter_keyword_discard_list_default = uci:get(appname, "@global_subscribe[0]", "filter_discard_list") or {}
			filter_keyword_keep_list_default = uci:get(appname, "@global_subscribe[0]", "filter_keep_list") or {}
			ss_type_default = uci:get(appname, "@global_subscribe[0]", "ss_type") or "shadowsocks-libev"
			trojan_type_default = uci:get(appname, "@global_subscribe[0]", "trojan_type") or "trojan-plus"
			vmess_type_default = uci:get(appname, "@global_subscribe[0]", "vmess_type") or "xray"
			vless_type_default = uci:get(appname, "@global_subscribe[0]", "vless_type") or "xray"
			hysteria2_type_default = uci:get(appname, "@global_subscribe[0]", "hysteria2_type") or "hysteria2"
		end

		if #fail_list > 0 then
			for index, value in ipairs(fail_list) do
				log(string.format('【%s】订阅失败，可能是订阅地址无效，或是网络问题，请诊断！[%s]', value.remark, tostring(value.http_code)))
			end
		end
		update_node(0)
	end
end

if arg[1] then
	if arg[1] == "start" then
		log('开始订阅...')
		xpcall(execute, function(e)
			log(e)
			if type(debug) == "table" and type(debug.traceback) == "function" then
				log(debug.traceback())
			end
			log('发生错误, 正在恢复服务')
		end)
		log('订阅完毕...\n')
	elseif arg[1] == "add" then
		local f = assert(io.open("/tmp/links.conf", 'r'))
		local raw = f:read('*all')
		f:close()
		parse_link(raw, "1", arg[2])
		update_node(1)
		luci.sys.call("rm -f /tmp/links.conf")
	elseif arg[1] == "truncate" then
		truncate_nodes(arg[2])
	end
end
