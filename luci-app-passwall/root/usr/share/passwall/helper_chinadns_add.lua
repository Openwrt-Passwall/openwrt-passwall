local api = require "luci.passwall.api"
local appname = api.appname

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local LISTEN_PORT = var["-LISTEN_PORT"]
local DNS_LOCAL = var["-DNS_LOCAL"]
local DNS_TRUST = var["-DNS_TRUST"]
local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
local USE_PROXY_LIST = var["-USE_PROXY_LIST"]
local USE_BLOCK_LIST = var["-USE_BLOCK_LIST"]
local GFWLIST = var["-GFWLIST"]
local CHNLIST = var["-CHNLIST"]
local NO_IPV6_TRUST = var["-NO_IPV6_TRUST"]
local DEFAULT_MODE = var["-DEFAULT_MODE"]
local DEFAULT_TAG = var["-DEFAULT_TAG"]
local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]
local TCP_NODE = var["-TCP_NODE"]
local NFTFLAG = var["-NFTFLAG"]
local REMOTE_FAKEDNS = var["-REMOTE_FAKEDNS"]
local FILTER_HTTPS = var["-FILTER_HTTPS"]
local LOG_FILE = var["-LOG_FILE"]

local uci = api.uci
local sys = api.sys
local fs = api.fs
local datatypes = api.datatypes

local TMP_PATH = "/tmp/etc/" .. appname
local TMP_ACL_PATH = TMP_PATH .. "/acl"
local RULES_PATH = "/usr/share/" .. appname .. "/rules"
local FLAG_PATH = TMP_ACL_PATH .. "/" .. FLAG
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

local setflag = (NFTFLAG == "1") and "inet@passwall@" or ""

local only_global = (DEFAULT_MODE == "proxy" and CHNLIST == "0" and GFWLIST == "0") and 1

config_lines = {
	LOG_FILE ~= "/dev/null" and "verbose" or "",
	"bind-addr ::",
	"bind-port " .. LISTEN_PORT,
	"china-dns " .. DNS_LOCAL,
	"trust-dns " .. DNS_TRUST,
	tonumber(FILTER_HTTPS) == 1 and "filter-qtype 65" or ""
}

for i = 1, 6 do
	table.insert(config_lines, "#--" .. i)
end

--自定义规则组，后声明的组具有更高优先级
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
	tmp_lines = {
		"group null",
		"group-dnl " .. file_block_host
	}
	insert_array_after(config_lines, tmp_lines, "#--5")
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
	local sets = {
		setflag .. "passwall_vps",
		setflag .. "passwall_vps6"
	}
	tmp_lines = {
		"group vpslist",
		"group-dnl " .. file_vpslist,
		"group-upstream " .. DNS_LOCAL,
		"group-ipset " .. table.concat(sets, ",")
	}
	insert_array_after(config_lines, tmp_lines, "#--6")
	log(string.format("  - 节点列表中的域名(vpslist)：%s", DNS_LOCAL or "默认"))
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
	local sets = {
		setflag .. "passwall_white",
		setflag .. "passwall_white6"
	}
	tmp_lines = {
		"group directlist",
		"group-dnl " .. file_direct_host,
		"group-upstream " .. DNS_LOCAL,
		"group-ipset " .. table.concat(sets, ",")
	}
	insert_array_after(config_lines, tmp_lines, "#--4")
	log(string.format("  - 域名白名单(whitelist)：%s", DNS_LOCAL or "默认"))
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
	local sets = {
		setflag .. "passwall_black",
		setflag .. "passwall_black6"
	}
	if FLAG ~= "default" then
		sets = {
			setflag .. "passwall_" .. FLAG .. "_black",
			setflag .. "passwall_" .. FLAG .. "_black6"
		}
	end
	tmp_lines = {
		"group proxylist",
		"group-dnl " .. file_proxy_host,
		"group-upstream " .. DNS_TRUST,
		REMOTE_FAKEDNS ~= "1" and "group-ipset " .. table.concat(sets, ",") or ""
	}
	if NO_IPV6_TRUST == "1" then table.insert(tmp_lines, "no-ipv6 tag:proxylist") end
	insert_array_after(config_lines, tmp_lines, "#--3")
	log(string.format("  - 代理域名表(blacklist)：%s", DNS_TRUST or "默认"))
end

--内置组(chn/gfw)优先级在自定义组后
--GFW列表
if GFWLIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	local sets = {
		setflag .. "passwall_gfw",
		setflag .. "passwall_gfw6"
	}
	if FLAG ~= "default" then
		sets = {
			setflag .. "passwall_" .. FLAG .. "_gfw",
			setflag .. "passwall_" .. FLAG .. "_gfw6"
		}
	end
	tmp_lines = {
		"gfwlist-file " .. RULES_PATH .. "/gfwlist",
		REMOTE_FAKEDNS ~= "1" and "add-taggfw-ip " .. table.concat(sets, ",") or ""
	}
	if NO_IPV6_TRUST == "1" then table.insert(tmp_lines, "no-ipv6 tag:gfw") end
	merge_array(config_lines, tmp_lines)
	log(string.format("  - 防火墙域名表(gfwlist)：%s", DNS_TRUST or "默认"))
end

--中国列表
if CHNLIST ~= "0" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	if CHNLIST == "direct" then
		tmp_lines = {
			"chnlist-file " .. RULES_PATH .. "/chnlist",
			"ipset-name4 " .. setflag .. "passwall_chn",
			"ipset-name6 " .. setflag .. "passwall_chn6",
			"add-tagchn-ip",
			"chnlist-first"
		}
		merge_array(config_lines, tmp_lines)
		log(string.format("  - 中国域名表(chnroute)：%s", DNS_LOCAL or "默认"))
	end

	--回中国模式
	if CHNLIST == "proxy" then
		local sets = {
			setflag .. "passwall_chn",
			setflag .. "passwall_chn6"
		}
		tmp_lines = {
			"group chn_proxy",
			"group-dnl " .. RULES_PATH .. "/chnlist",
			"group-upstream " .. DNS_TRUST,
			REMOTE_FAKEDNS ~= "1" and "group-ipset " .. table.concat(sets, ",") or ""
		}
		if NO_IPV6_TRUST == "1" then table.insert(tmp_lines, "no-ipv6 tag:chn_proxy") end
		insert_array_after(config_lines, tmp_lines, "#--1")
		log(string.format("  - 中国域名表(chnroute)：%s", DNS_TRUST or "默认"))
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
				log(string.format("  - Sing-Box/Xray分流规则(%s)：%s", s.remarks, DNS_TRUST or "默认"))
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

	if GFWLIST == "1" and CHNLIST == "0" and USE_GEOVIEW == "1" and api.is_finded("geoview") then  --仅GFW模式解析geosite
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

	local sets = {
		setflag .. "passwall_shunt",
		setflag .. "passwall_shunt6"
	}
	if FLAG ~= "default" then
		sets = {
			setflag .. "passwall_" .. FLAG .. "_shunt",
			setflag .. "passwall_" .. FLAG .. "_shunt6"
		}
	end

	if is_file_nonzero(file_white_host) then
		if USE_DIRECT_LIST == "1" then
			--当白名单启用时，添加到白名单组一同处理
			for i, v in ipairs(config_lines) do
				if v == "group-dnl " .. file_direct_host then
					config_lines[i] = "group-dnl " .. file_direct_host .. "," .. file_white_host
					break
				end
			end
		else
			--当白名单不启用时，创建新组，ipset到shuntlist
			tmp_lines = {
				"group whitelist",
				"group-dnl " .. file_white_host,
				"group-upstream " .. DNS_LOCAL,
				"group-ipset " .. table.concat(sets, ",")
			}
			insert_array_after(config_lines, tmp_lines, "#--4")
		end
		
	end

	if is_file_nonzero(file_shunt_host) then
		tmp_lines = {
			"group shuntlist",
			"group-dnl " .. file_shunt_host,
			"group-upstream " .. DNS_TRUST,
			(not only_global and REMOTE_FAKEDNS == "1") and "" or ("group-ipset " .. table.concat(sets, ","))
		}
		if NO_IPV6_TRUST == "1" then table.insert(tmp_lines, "no-ipv6 tag:shuntlist") end
		insert_array_after(config_lines, tmp_lines, "#--2")
	end

end

--只使用gfwlist模式，GFW列表以外的域名及默认使用本地DNS
if GFWLIST == "1" and CHNLIST == "0" then DEFAULT_TAG = "chn" end

--回中国模式，中国列表以外的域名及默认使用本地DNS
if CHNLIST == "proxy" then DEFAULT_TAG = "chn" end

--全局模式，默认使用远程DNS
if only_global then
	DEFAULT_TAG = "gfw"
	if NO_IPV6_TRUST == "1" and not IS_SHUNT_NODE then 
		table.insert(config_lines, "no-ipv6")
	end
end

--是否接受直连 DNS 空响应
if DEFAULT_TAG == "none_noip" then table.insert(config_lines, "noip-as-chnip") end

if DEFAULT_TAG == nil or DEFAULT_TAG == "smart" or DEFAULT_TAG == "none_noip" then DEFAULT_TAG = "none" end

table.insert(config_lines, "default-tag " .. DEFAULT_TAG)

if DEFAULT_TAG == "none" then
	table.insert(config_lines, "verdict-cache 5000")
end

table.insert(config_lines, "hosts")

if DEFAULT_TAG == "chn" then
	log(string.format("  - 默认 DNS ：%s", DNS_LOCAL))
elseif  DEFAULT_TAG == "gfw" then
	log(string.format("  - 默认 DNS ：%s", DNS_TRUST))
else
	log(string.format("  - 默认 DNS ：%s", "智能匹配"))
end

--输出配置文件
if #config_lines > 0 then
	for i = 1, #config_lines do
		line = config_lines[i]
		if line ~= "" and not line:find("^#--") then
			print(line)
		end
	end
end

log("  - ChinaDNS-NG已作为Dnsmasq上游，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理域名)分流失效！！！")
