local api = require "luci.passwall.api"
local appname = api.appname

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local SMARTDNS_CONF = var["-SMARTDNS_CONF"]
local LOCAL_GROUP = var["-LOCAL_GROUP"]
local REMOTE_GROUP = var["-REMOTE_GROUP"]
local REMOTE_PROXY_SERVER = var["-REMOTE_PROXY_SERVER"]
local USE_DEFAULT_DNS = var["-USE_DEFAULT_DNS"]
local REMOTE_DNS = var["-REMOTE_DNS"]
local TUN_DNS = var["-TUN_DNS"]
local DNS_MODE = var["-DNS_MODE"]
local REMOTE_FAKEDNS = var["-REMOTE_FAKEDNS"]
local TCP_NODE = var["-TCP_NODE"]
local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
local USE_PROXY_LIST = var["-USE_PROXY_LIST"]
local USE_BLOCK_LIST = var["-USE_BLOCK_LIST"]
local USE_GFW_LIST = var["-USE_GFW_LIST"]
local CHN_LIST = var["-CHN_LIST"]
local DEFAULT_PROXY_MODE = var["-DEFAULT_PROXY_MODE"]
local NO_PROXY_IPV6 = var["-NO_PROXY_IPV6"]
local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]
local NFTFLAG = var["-NFTFLAG"]
local SUBNET = var["-SUBNET"]
local LISTEN_PORT = var["-LISTEN_PORT"]
local LOCAL_PORT = var["-LOCAL_PORT"]

local uci = api.uci
local sys = api.sys
local fs = api.fs
local datatypes = api.datatypes

local TMP_PATH = "/tmp/etc/" .. appname
local TMP_ACL_PATH = TMP_PATH .. "/acl"
local RULES_PATH = "/usr/share/" .. appname .. "/rules"
local FLAG_PATH = TMP_ACL_PATH .. "/" .. FLAG
local TMP_CONF_FILE = FLAG_PATH .. "/smartdns.conf"
local config_lines = {}
local tmp_lines = {}
local USE_GEOVIEW = uci:get(appname, "@global_rules[0]", "enable_geoview")
local IS_SHUNT_NODE = uci:get(appname, TCP_NODE, "protocol") == "_shunt"

if IS_SHUNT_NODE then
	REMOTE_FAKEDNS = uci:get(appname, TCP_NODE, "fakedns") or "0"
end

local function log(...)
	if NO_LOGIC_LOG == "1" then
		return
	end
	api.log(...)
end

local function is_file_nonzero(path)
	if path and #path > 1 then
		if sys.exec('[ -s "%s" ] && echo -n 1' % path) == "1" then
			return true
		end
	end
	return nil
end

local function insert_unique(dest_table, value, lookup_table)
	if not lookup_table[value] then
		table.insert(dest_table, value)
		lookup_table[value] = true
	end
end

local function merge_array(array1, array2)
	for i, line in ipairs(array2) do
		table.insert(array1, #array1 + 1, line)
	end
end

local function insert_array_before(array1, array2, target) --将array2插入到array1的target前面，target不存在则追加
	for i, line in ipairs(array1) do
		if line == target then
			for j = #array2, 1, -1 do
				table.insert(array1, i, array2[j])
			end
			return
		end
	end
	merge_array(array1, array2)
end

local function insert_array_after(array1, array2, target) --将array2插入到array1的target后面，target不存在则追加
	for i, line in ipairs(array1) do
		if line == target then
			for j = 1, #array2 do
				table.insert(array1, i + j, array2[j])
			end
			return
		end
	end
	merge_array(array1, array2)
end

local function get_geosite(list_arg, out_path)
	local geosite_path = uci:get(appname, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
	geosite_path = geosite_path:match("^(.*)/") .. "/geosite.dat"
	if not is_file_nonzero(geosite_path) then return 1 end
	local bin = api.finded_com("geoview")
	if bin and list_arg and out_path then
		local cmd = string.format("%q -type geosite -append=true -input %q -list %q -output %q -lowmem=true",
			bin, geosite_path, list_arg, out_path)
		sys.call(cmd)
		return 0
	end
	return 1
end

if not fs.access(FLAG_PATH) then
	fs.mkdir(FLAG_PATH)
end

local LOCAL_EXTEND_ARG = ""
if LOCAL_GROUP == "null" or LOCAL_GROUP == "" then
	log("  * 注意：SmartDNS 国内分组名未设置，DNS 将无法正常工作！！！")
	os.exit(1)
else
	--从smartdns配置中读取参数
	local custom_conf_path = "/etc/smartdns/custom.conf"
	local options = {
		{key = "dualstack_ip_selection", config_key = "dualstack-ip-selection", yes_no = true, arg_yes = "-d yes", arg_no = "-d no", default = "yes"},
		{key = "speed_check_mode", config_key = "speed-check-mode", prefix = "-c ", default = "ping,tcp:80,tcp:443"},
		{key = "serve_expired", config_key = "serve-expired", yes_no = true, arg_yes = "", arg_no = "-no-serve-expired", default = "yes"},
		{key = "response_mode", config_key = "response-mode", prefix = "-r ", default = "first-ping"},
		{key = "rr_ttl", config_key = "rr-ttl", prefix = "-rr-ttl "},
		{key = "rr_ttl_min", config_key = "rr-ttl-min", prefix = "-rr-ttl-min "},
		{key = "rr_ttl_max", config_key = "rr-ttl-max", prefix = "-rr-ttl-max "},
		{key = "rr_ttl_reply_max", config_key = "rr-ttl-reply-max", prefix = "-rr-ttl-reply-max "},
		{
			key = "force_aaaa_soa",
			config_key = "force-qtype-SOA",
			prefix = "-address ",
			get_value = function(custom_config)
				local soa = custom_config["force-qtype-SOA"]
				return ((soa and soa:match("(^|%s)28(%s|$)"))
					or custom_config["force-AAAA-SOA"] == "yes"
					or uci:get("smartdns", "@smartdns[0]", "force_aaaa_soa") == "1")
					and "#6" or "-6"
			end
		}
	}
	-- 从 custom.conf 中读取值，以最后出现的值为准
	local custom_config = {}
	local f_in = io.open(custom_conf_path, "r")
	if f_in then
		for line in f_in:lines() do
			line = api.trim(line)
			if line ~= "" and not line:match("^#") then
				local param, value = line:match("^(%S+)%s+(.+)$")
				if param and value then custom_config[param] = value end
			end
		end
		f_in:close()
	end
	-- 从 smartdns 配置中读取值，优先级以 custom.conf 为准
	for _, opt in ipairs(options) do
		local val
		if opt.get_value then
			val = opt.get_value(custom_config)
		else
			val = custom_config[opt.config_key] or uci:get("smartdns", "@smartdns[0]", opt.key) or opt.default
		end
		if val == "yes" then val = "1" elseif val == "no" then val = "0" end
		if opt.yes_no then
			local arg = (val == "1" and opt.arg_yes or opt.arg_no)
			if arg and arg ~= "" then
				LOCAL_EXTEND_ARG = LOCAL_EXTEND_ARG .. (LOCAL_EXTEND_ARG ~= "" and " " or "") .. arg
			end
		else
			if val and (not opt.value or (opt.invert and val ~= opt.value) or (not opt.invert and val == opt.value)) then
				LOCAL_EXTEND_ARG = LOCAL_EXTEND_ARG .. (LOCAL_EXTEND_ARG ~= "" and " " or "") .. (opt.prefix or "") .. (opt.arg or val)
			end
		end
	end
end

if not REMOTE_GROUP or REMOTE_GROUP == "nil" then
	REMOTE_GROUP = "passwall_proxy"
	if REMOTE_DNS then
		REMOTE_DNS = REMOTE_DNS:gsub("#", ":")
	end
	sys.call('sed -i "/passwall/d" /etc/smartdns/custom.conf >/dev/null 2>&1')
end

local force_https_soa = uci:get(appname, "@global[0]", "force_https_soa") or 0
local proxy_server_name = "passwall-proxy-server"
config_lines = {
	tonumber(LISTEN_PORT) ~= 0 and "bind [::]:" .. LISTEN_PORT .. "@lo" or "",
	(tonumber(LOCAL_PORT) ~= 0 and LOCAL_GROUP) and "bind [::]:" .. LOCAL_PORT .. "@lo -group " ..  LOCAL_GROUP or "",
	tonumber(force_https_soa) == 1 and "force-qtype-SOA 65" or "force-qtype-SOA -,65",
	"server 114.114.114.114 -bootstrap-dns",
	is_file_nonzero("/etc/hosts") and "hosts-file /etc/hosts" or "",
	DNS_MODE == "socks" and string.format("proxy-server socks5://%s -name %s", REMOTE_PROXY_SERVER, proxy_server_name) or ""
}
if DNS_MODE == "socks" then
	for w in string.gmatch(REMOTE_DNS, '[^|]+') do
		local server_dns = api.trim(w)
		local server_param

		local dnsType = string.match(server_dns, "^(.-)://")
		dnsType = dnsType and string.lower(dnsType) or nil
		local dnsServer = string.match(server_dns, "://(.+)") or server_dns

		if dnsType and dnsType ~= "" and dnsType ~= "udp" then
			if dnsType == "tcp" then
				server_param = "server-tcp " .. dnsServer
			elseif dnsType == "tls" then
				server_param = "server-tls " .. dnsServer
			elseif dnsType == "quic" then
				server_param = "server-quic " .. dnsServer
			elseif dnsType == "https" or dnsType == "h3" then
				local http_host = nil
				local url = w
				local port = 443
				local s = api.split(w, ",")
				if s and #s > 1 then
					url = s[1]
					local dns_ip = s[2]
					local host_port = api.get_domain_from_url(s[1])
					if host_port and #host_port > 0 then
						http_host = host_port
						local s2 = api.split(host_port, ":")
						if s2 and #s2 > 1 then
							http_host = s2[1]
							port = s2[2]
						end 
						url = url:gsub(http_host, dns_ip)
					end
				end
				server_dns = url
				if http_host then
					server_dns = server_dns .. " -http-host " .. http_host
				end
				server_param = (dnsType == "https" and "server-https " or "server-h3 ") .. server_dns
			end
		else
			server_param = "server " .. dnsServer

		end

		if not api.is_local_ip(w) then
			server_param = server_param .. " -proxy " .. proxy_server_name
		end

		server_param = server_param .. " -group " .. REMOTE_GROUP .. " -exclude-default-group"
		if SUBNET and SUBNET ~= "" and SUBNET ~= "0" then
			server_param = server_param .. " -subnet " .. SUBNET
		end
		table.insert(config_lines, server_param)
	end
	if not IS_SHUNT_NODE then REMOTE_FAKEDNS = "0" end
else
	local server_param = string.format("server %s -group %s -exclude-default-group", TUN_DNS:gsub("#", ":"), REMOTE_GROUP)
	table.insert(config_lines, server_param)
	log("  - " .. DNS_MODE:gsub("^%l",string.upper) .. " " .. TUN_DNS .. " -> " .. REMOTE_GROUP)
end

--设置默认 DNS 分组(托底组)
local DEFAULT_DNS_GROUP = (USE_DEFAULT_DNS == "direct" and LOCAL_GROUP) or
                          (USE_DEFAULT_DNS == "remote" and REMOTE_GROUP)
local only_global = (DEFAULT_PROXY_MODE == "proxy" and CHN_LIST == "0" and USE_GFW_LIST == "0") and 1 --没有启用中国列表和GFW列表时(全局)
if only_global == 1 then
	DEFAULT_DNS_GROUP = REMOTE_GROUP
end
if DEFAULT_DNS_GROUP then
	local domain_rules_str = "domain-rules /./ -nameserver " .. DEFAULT_DNS_GROUP
	if DEFAULT_DNS_GROUP == REMOTE_GROUP then
		domain_rules_str = domain_rules_str .. " -speed-check-mode none -d no -no-serve-expired"
		domain_rules_str = domain_rules_str .. " -address " .. (NO_PROXY_IPV6 == "1" and "#6" or "-6")
	elseif DEFAULT_DNS_GROUP == LOCAL_GROUP then
		domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	end
	table.insert(config_lines, domain_rules_str)
end

local setflag = (NFTFLAG == "1") and "inet#passwall#" or ""
local set_type = (NFTFLAG == "1") and "-nftset" or "-ipset"

--预设排序标签(越往后优先级越高)
for i = 1, 8 do
	table.insert(config_lines, "#--" .. i)
end

--屏蔽列表
local file_block_host = TMP_ACL_PATH .. "/block_host"
if USE_BLOCK_LIST == "1" and not fs.access(file_block_host) then
	local block_domain, lookup_block_domain = {}, {}
	local geosite_arg = ""
	for line in io.lines(RULES_PATH .. "/block_host") do
		if not line:find("#") and line:find("geosite:") then
			line = string.match(line, ":([^:]+)$")
			geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
		else
			line = api.get_std_domain(line)
			if line ~= "" and not line:find("#") then
				insert_unique(block_domain, line, lookup_block_domain)
			end
		end
	end
	if #block_domain > 0 then
		local f_out = io.open(file_block_host, "w")
		for i = 1, #block_domain do
			f_out:write(block_domain[i] .. "\n")
		end
		f_out:close()
	end
	if USE_GEOVIEW == "1" and geosite_arg ~= "" and api.is_finded("geoview") then
		if get_geosite(geosite_arg, file_block_host) == 0 then
			log("  * 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)完成")
		else
			log("  * 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)失败！")
		end
	end
end
if USE_BLOCK_LIST == "1" and is_file_nonzero(file_block_host) then
	local domain_set_name = "passwall-block"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_block_host),
		string.format("domain-rules /domain-set:%s/ -a #", domain_set_name)
	}
	insert_array_after(config_lines, tmp_lines, "#--7")
end

--始终用国内DNS解析节点域名
local file_vpslist = TMP_ACL_PATH .. "/vpslist"
if not is_file_nonzero(file_vpslist) then
	local f_out = io.open(file_vpslist, "w")
	local written_domains = {}
	local function process_address(address)
		address = (address or ""):lower()
		if api.vps_domain_exclude(address) then return end
		if datatypes.hostname(address) and not written_domains[address] then
			f_out:write(address .. "\n")
			written_domains[address] = true
		end
	end
	uci:foreach(appname, "nodes", function(t)
		process_address(t.address)
		process_address(t.download_address)
	end)
	uci:foreach(appname, "subscribe_list", function(t)  --订阅链接
		local url, _ = api.get_domain_port_from_url(t.url or "")
		if url and url ~= "" then
			process_address(url)
		end
	end)
	f_out:close()
end
if is_file_nonzero(file_vpslist) then
	local domain_set_name = "passwall-vpslist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_vpslist)
	}
	local sets = {
		"#4:" .. setflag .. "passwall_vps",
		"#6:" .. setflag .. "passwall_vps6"
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
	domain_rules_str = domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")
	domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--8")
	log(string.format("  - 节点列表中的域名(vpslist)使用分组：%s", LOCAL_GROUP or "默认"))
end

--直连（白名单）列表
local file_direct_host = TMP_ACL_PATH .. "/direct_host"
if USE_DIRECT_LIST == "1" and not fs.access(file_direct_host) then
	local direct_domain, lookup_direct_domain = {}, {}
	local geosite_arg = ""
	for line in io.lines(RULES_PATH .. "/direct_host") do
		if not line:find("#") and line:find("geosite:") then
			line = string.match(line, ":([^:]+)$")
			geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
		else
			line = api.get_std_domain(line)
			if line ~= "" and not line:find("#") then
				insert_unique(direct_domain, line, lookup_direct_domain)
			end
		end
	end
	if #direct_domain > 0 then
		local f_out = io.open(file_direct_host, "w")
		for i = 1, #direct_domain do
			f_out:write(direct_domain[i] .. "\n")
		end
		f_out:close()
	end
	if USE_GEOVIEW == "1" and geosite_arg ~= "" and api.is_finded("geoview") then
		if get_geosite(geosite_arg, file_direct_host) == 0 then
			log("  * 解析[直连列表] Geosite 到域名白名单(whitelist)完成")
		else
			log("  * 解析[直连列表] Geosite 到域名白名单(whitelist)失败！")
		end
	end
end
if USE_DIRECT_LIST == "1" and is_file_nonzero(file_direct_host) then
	local domain_set_name = "passwall-directlist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_direct_host)
	}
	local sets = {
		"#4:" .. setflag .. "passwall_white",
		"#6:" .. setflag .. "passwall_white6"
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
	domain_rules_str = domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")
	domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--6")
	log(string.format("  - 域名白名单(whitelist)使用分组：%s", LOCAL_GROUP or "默认"))
end

--代理（黑名单）列表
local file_proxy_host = TMP_ACL_PATH .. "/proxy_host"
if USE_PROXY_LIST == "1" and not fs.access(file_proxy_host) then
	local proxy_domain, lookup_proxy_domain = {}, {}
	local geosite_arg = ""
	for line in io.lines(RULES_PATH .. "/proxy_host") do
		if not line:find("#") and line:find("geosite:") then
			line = string.match(line, ":([^:]+)$")
			geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
		else
			line = api.get_std_domain(line)
			if line ~= "" and not line:find("#") then
				insert_unique(proxy_domain, line, lookup_proxy_domain)
			end
		end
	end
	if #proxy_domain > 0 then
		local f_out = io.open(file_proxy_host, "w")
		for i = 1, #proxy_domain do
			f_out:write(proxy_domain[i] .. "\n")
		end
		f_out:close()
	end
	if USE_GEOVIEW == "1" and geosite_arg ~= "" and api.is_finded("geoview") then
		if get_geosite(geosite_arg, file_proxy_host) == 0 then
			log("  * 解析[代理列表] Geosite 到代理域名表(blacklist)完成")
		else
			log("  * 解析[代理列表] Geosite 到代理域名表(blacklist)失败！")
		end
	end
end
if USE_PROXY_LIST == "1" and is_file_nonzero(file_proxy_host) then
	local domain_set_name = "passwall-proxylist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_proxy_host)
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
	domain_rules_str = domain_rules_str .. " -speed-check-mode none"
	domain_rules_str = domain_rules_str .. " -no-serve-expired"
	local sets = {
		"#4:" .. setflag .. "passwall_black"
	}
	if NO_PROXY_IPV6 == "1" then
		domain_rules_str = domain_rules_str .. " -address #6"
		domain_rules_str = REMOTE_FAKEDNS ~= "1" and (domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")) or domain_rules_str
	else
		domain_rules_str = domain_rules_str .. " -address -6"
		table.insert(sets, "#6:" .. setflag .. "passwall_black6")
		domain_rules_str = REMOTE_FAKEDNS ~= "1" and (domain_rules_str .. " -d no " .. set_type .. " " .. table.concat(sets, ",")) or domain_rules_str
	end
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--5")
	log(string.format("  - 代理域名表(blacklist)使用分组：%s", REMOTE_GROUP or "默认"))
end

--GFW列表
if USE_GFW_LIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	local domain_set_name = "passwall-gfwlist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, RULES_PATH .. "/gfwlist")
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
	domain_rules_str = domain_rules_str .. " -speed-check-mode none"
	domain_rules_str = domain_rules_str .. " -no-serve-expired"
	local sets = {
		"#4:" .. setflag .. "passwall_gfw"
	}
	if NO_PROXY_IPV6 == "1" then
		domain_rules_str = domain_rules_str .. " -address #6"
		domain_rules_str = REMOTE_FAKEDNS ~= "1" and (domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")) or domain_rules_str
	else
		domain_rules_str = domain_rules_str .. " -address -6"
		table.insert(sets, "#6:" .. setflag .. "passwall_gfw6")
		domain_rules_str = REMOTE_FAKEDNS ~= "1" and (domain_rules_str .. " -d no " .. set_type .. " " .. table.concat(sets, ",")) or domain_rules_str
	end
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--1")
	log(string.format("  - 防火墙域名表(gfwlist)使用分组：%s", REMOTE_GROUP or "默认"))
end

--中国列表
if CHN_LIST ~= "0" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	local domain_set_name = "passwall-chnlist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, RULES_PATH .. "/chnlist")
	}

	if CHN_LIST == "direct" then
		local sets = {
			"#4:" .. setflag .. "passwall_chn",
			"#6:" .. setflag .. "passwall_chn6"
		}
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
		domain_rules_str = domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")
		domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--2")
		log(string.format("  - 中国域名表(chnroute)使用分组：%s", LOCAL_GROUP or "默认"))
	end

	--回中国模式
	if CHN_LIST == "proxy" then
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
		domain_rules_str = domain_rules_str .. " -speed-check-mode none"
		domain_rules_str = domain_rules_str .. " -no-serve-expired"
		local sets = {
			"#4:" .. setflag .. "passwall_chn"
		}
		if NO_PROXY_IPV6 == "1" then
			domain_rules_str = domain_rules_str .. " -address #6"
			domain_rules_str = REMOTE_FAKEDNS ~= "1" and (domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")) or domain_rules_str
		else
			domain_rules_str = domain_rules_str .. " -address -6"
			table.insert(sets, "#6:" .. setflag .. "passwall_chn6")
			domain_rules_str = REMOTE_FAKEDNS ~= "1" and (domain_rules_str .. " -d no " .. set_type .. " " .. table.concat(sets, ",")) or domain_rules_str
		end
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--2")
		log(string.format("  - 中国域名表(chnroute)使用分组：%s", REMOTE_GROUP or "默认"))
	end
end

--分流规则
if IS_SHUNT_NODE then
	local white_domain, lookup_white_domain = {}, {}
	local shunt_domain, lookup_shunt_domain = {}, {}
	local file_white_host = FLAG_PATH .. "/shunt_direct_host"
	local file_shunt_host = FLAG_PATH .. "/shunt_proxy_host"
	local geosite_white_arg, geosite_shunt_arg = "", ""

	local t = uci:get_all(appname, TCP_NODE)
	local default_node_id = t["default_node"] or "_direct"
	uci:foreach(appname, "shunt_rules", function(s)
		local _node_id = t[s[".name"]]
		if _node_id and _node_id ~= "_blackhole" then
			if _node_id == "_default" then
				_node_id = default_node_id
			end

			local domain_list = s.domain_list or ""
			for line in string.gmatch(domain_list, "[^\r\n]+") do
				if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("ext:") then
					if line:find("geosite:") then
						line = string.match(line, ":([^:]+)$")
						if _node_id == "_direct" then
							geosite_white_arg = geosite_white_arg .. (geosite_white_arg ~= "" and "," or "") .. line
						else
							geosite_shunt_arg = geosite_shunt_arg .. (geosite_shunt_arg ~= "" and "," or "") .. line
						end
					else
						if line:find("domain:") or line:find("full:") then
							line = string.match(line, ":([^:]+)$")
						end
						line = api.get_std_domain(line)
						if line ~= "" and not line:find("#") then
							if _node_id == "_direct" then
								insert_unique(white_domain, line, lookup_white_domain)
							else
								insert_unique(shunt_domain, line, lookup_shunt_domain)
							end
						end
					end
				end
			end

			if _node_id ~= "_direct" then
				log(string.format("  - Sing-Box/Xray分流规则(%s)使用分组：%s", s.remarks, REMOTE_GROUP or "默认"))
			end
		end
	end)

	if is_file_nonzero(file_white_host) == nil then
		if #white_domain > 0 then
			local f_out = io.open(file_white_host, "w")
			for i = 1, #white_domain do
				f_out:write(white_domain[i] .. "\n")
			end
			f_out:close()
		end
	end

	if is_file_nonzero(file_shunt_host) == nil then
		if #shunt_domain > 0 then
			local f_out = io.open(file_shunt_host, "w")
			for i = 1, #shunt_domain do
				f_out:write(shunt_domain[i] .. "\n")
			end
			f_out:close()
		end
	end

	if USE_GFW_LIST == "1" and CHN_LIST == "0" and USE_GEOVIEW == "1" and api.is_finded("geoview") then  --仅GFW模式解析geosite
		local return_white, return_shunt
		if geosite_white_arg ~= "" then
			return_white = get_geosite(geosite_white_arg, file_white_host)
		end
		if geosite_shunt_arg ~= "" then
			return_shunt = get_geosite(geosite_shunt_arg, file_shunt_host)
		end
		if (return_white == nil or return_white == 0) and (return_shunt == nil or return_shunt == 0) then
			log("  * 解析[分流节点] Geosite 完成")
		else
			log("  * 解析[分流节点] Geosite 失败！")
		end
	end

	if is_file_nonzero(file_white_host) then
		local domain_set_name = "passwall-whitehost"
		tmp_lines = {
			string.format("domain-set -name %s -file %s", domain_set_name, file_white_host)
		}
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
		if USE_DIRECT_LIST == "1" then
			local sets = {
				"#4:" .. setflag .. "passwall_white",
				"#6:" .. setflag .. "passwall_white6"
			}
			domain_rules_str = domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")
		else
			local sets = {
				"#4:" .. setflag .. "passwall_shunt",
				"#6:" .. setflag .. "passwall_shunt6"
			}
			domain_rules_str = domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ",")
		end
		domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--4")
	end

	if is_file_nonzero(file_shunt_host) then
		local domain_set_name = "passwall-shuntlist"
		tmp_lines = {
			string.format("domain-set -name %s -file %s", domain_set_name, file_shunt_host)
		}
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
		domain_rules_str = domain_rules_str .. " -speed-check-mode none"
		domain_rules_str = domain_rules_str .. " -no-serve-expired"
		local sets = {
			"#4:" .. setflag .. "passwall_shunt"
		}
		if NO_PROXY_IPV6 == "1" then
			domain_rules_str = domain_rules_str .. " -address #6"
			domain_rules_str = (not only_global and REMOTE_FAKEDNS == "1")
					and domain_rules_str
					or (domain_rules_str .. " " .. set_type .. " " .. table.concat(sets, ","))
		else
			domain_rules_str = domain_rules_str .. " -address -6"
			table.insert(sets, "#6:" .. setflag .. "passwall_shunt6")
			domain_rules_str = (not only_global and REMOTE_FAKEDNS == "1")
					and domain_rules_str
					or (domain_rules_str .. " -d no " .. set_type .. " " .. table.concat(sets, ","))
		end
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--3")
	end

end

if #config_lines > 0 then
	local f_out = io.open(TMP_CONF_FILE, "w")
	for i = 1, #config_lines do
		line = config_lines[i]
		if line ~= "" and not line:find("^#--") then
			f_out:write(line .. "\n")
		end
	end
	f_out:close()
end

if DEFAULT_DNS_GROUP then
	log(string.format("  - 默认 DNS 分组：%s", DEFAULT_DNS_GROUP))
end

fs.symlink(TMP_CONF_FILE, SMARTDNS_CONF)
sys.call(string.format('echo "conf-file %s" >> /etc/smartdns/custom.conf', string.gsub(SMARTDNS_CONF, appname, appname .. "*")))
log("  - SmartDNS已作为Dnsmasq上游，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理域名)分流失效！！！")
