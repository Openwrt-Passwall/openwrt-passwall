local api = require "luci.passwall.api"
local appname = "passwall"
local uci = api.uci
local sys = api.sys
local fs = api.fs
local datatypes = api.datatypes
local TMP = {}

local function tinsert(table_name, val)
	if table_name and type(table_name) == "table" then
		if not TMP[table_name] then
			TMP[table_name] = {}
		end
		if TMP[table_name][val] then
			return false
		end
		table.insert(table_name, val)
		TMP[table_name][val] = true
		return true
	end
	return false
end

local function backup_servers()
	local DNSMASQ_DNS = uci:get("dhcp", "@dnsmasq[0]", "server")
	if DNSMASQ_DNS and #DNSMASQ_DNS > 0 then
		uci:set(appname, "@global[0]", "dnsmasq_servers", DNSMASQ_DNS)
		api.uci_save(uci, appname, true)
	end
end

local function restore_servers()
	local dns_table = {}
	local DNSMASQ_DNS = uci:get("dhcp", "@dnsmasq[0]", "server")
	if DNSMASQ_DNS and #DNSMASQ_DNS > 0 then
		for k, v in ipairs(DNSMASQ_DNS) do
			tinsert(dns_table, v)
		end
	end
	local OLD_SERVER = uci:get(appname, "@global[0]", "dnsmasq_servers")
	if OLD_SERVER and #OLD_SERVER > 0 then
		for k, v in ipairs(OLD_SERVER) do
			tinsert(dns_table, v)
		end
		uci:delete(appname, "@global[0]", "dnsmasq_servers")
		api.uci_save(uci, appname, true)
	end
	if dns_table and #dns_table > 0 then
		uci:set_list("dhcp", "@dnsmasq[0]", "server", dns_table)
		api.uci_save(uci, "dhcp", true)
	end
end

function stretch()
	local dnsmasq_server = uci:get("dhcp", "@dnsmasq[0]", "server")
	local dnsmasq_noresolv = uci:get("dhcp", "@dnsmasq[0]", "noresolv")
	local _flag
	if dnsmasq_server and #dnsmasq_server > 0 then
		for k, v in ipairs(dnsmasq_server) do
			if not v:find("/") then
				_flag = true
			end
		end
	end
	if not _flag and dnsmasq_noresolv == "1" then
		uci:delete("dhcp", "@dnsmasq[0]", "noresolv")
		local RESOLVFILE = "/tmp/resolv.conf.d/resolv.conf.auto"
		local file = io.open(RESOLVFILE, "r")
		if not file then
			RESOLVFILE = "/tmp/resolv.conf.auto"
		else
			local size = file:seek("end")
			file:close()
			if size == 0 then
				RESOLVFILE = "/tmp/resolv.conf.auto"
			end
		end
		uci:set("dhcp", "@dnsmasq[0]", "resolvfile", RESOLVFILE)
		api.uci_save(uci, "dhcp", true)
	end
end

function restart(var)
	local LOG = var["-LOG"]
	sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
	if LOG == "1" then
		api.log("重启 dnsmasq 服务")
	end
end

function logic_restart(var)
	local LOG = var["-LOG"]
	local DEFAULT_DNS = api.get_cache_var("DEFAULT_DNS")
	if DEFAULT_DNS then
		backup_servers()
		--sys.call("sed -i '/list server/d' /etc/config/dhcp >/dev/null 2>&1")
		local dns_table = {}
		local dnsmasq_server = uci:get("dhcp", "@dnsmasq[0]", "server")
		if dnsmasq_server and #dnsmasq_server > 0 then
			for k, v in ipairs(dnsmasq_server) do
				if v:find("/") then
					tinsert(dns_table, v)
				end
			end
			uci:set_list("dhcp", "@dnsmasq[0]", "server", dns_table)
			api.uci_save(uci, "dhcp", true)
		end
		sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
		restore_servers()
	else
		sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
	end
	if LOG == "1" then
		api.log("重启 dnsmasq 服务")
	end
end

function copy_instance(var)
	local LISTEN_PORT = var["-LISTEN_PORT"]
	local TMP_DNSMASQ_PATH = var["-TMP_DNSMASQ_PATH"]
	local conf_lines = {}
	local DEFAULT_DNSMASQ_CFGID = sys.exec("echo -n $(uci -q show dhcp.@dnsmasq[0] | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')")
	for line in io.lines("/tmp/etc/dnsmasq.conf." .. DEFAULT_DNSMASQ_CFGID) do
		local filter
		if line:find("passwall") then filter = true end
		if line:find("ubus") then filter = true end
		if line:find("dhcp") then filter = true end
		if line:find("server=") == 1 then filter = true end
		if line:find("port=") == 1 then filter = true end
		if line:find("conf%-dir=") == 1 then
			filter = true
			if TMP_DNSMASQ_PATH then
				local tmp_path = line:sub(1 + #"conf-dir=")
				sys.call(string.format("cp -r %s/* %s/ 2>/dev/null", tmp_path, TMP_DNSMASQ_PATH))
			end
		end
		if line:find("address=") == 1 or (line:find("server=") == 1 and line:find("/")) then filter = nil end
		if not filter then
			tinsert(conf_lines, line)
		end
	end
	tinsert(conf_lines, "port=" .. LISTEN_PORT)
	if TMP_DNSMASQ_PATH then
		sys.call("rm -rf " .. TMP_DNSMASQ_PATH .. "/*passwall*")
	end
	if var["-return"] == "1" then
		return conf_lines
	end
	if #conf_lines > 0 then
		local DNSMASQ_CONF = var["-DNSMASQ_CONF"]
		local conf_out = io.open(DNSMASQ_CONF, "a")
		conf_out:write(table.concat(conf_lines, "\n"))
		conf_out:write("\n")
		conf_out:close()
	end
end

function add_rule(var)
	local FLAG = var["-FLAG"]
	local TMP_DNSMASQ_PATH = var["-TMP_DNSMASQ_PATH"]
	local DNSMASQ_CONF_FILE = var["-DNSMASQ_CONF_FILE"]
	local LISTEN_PORT = var["-LISTEN_PORT"]
	local DEFAULT_DNS = var["-DEFAULT_DNS"]
	local LOCAL_DNS = var["-LOCAL_DNS"]
	local TUN_DNS = var["-TUN_DNS"]
	local REMOTE_FAKEDNS = var["-REMOTE_FAKEDNS"]
	local USE_DEFAULT_DNS = var["-USE_DEFAULT_DNS"]
	local CHINADNS_DNS = var["-CHINADNS_DNS"]
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
	local CACHE_PATH = api.CACHE_PATH
	local CACHE_FLAG = "dnsmasq_" .. FLAG
	local CACHE_DNS_PATH = CACHE_PATH .. "/" .. CACHE_FLAG
	local CACHE_TEXT_FILE = CACHE_DNS_PATH .. ".txt"
	local USE_CHINADNS_NG = "0"
	local IS_SHUNT_NODE = uci:get(appname, TCP_NODE, "protocol") == "_shunt"

	if IS_SHUNT_NODE then
		REMOTE_FAKEDNS = uci:get(appname, TCP_NODE, "fakedns") or "0"
	end

	local list1 = {}
	local excluded_domain = {}

	local function log(...)
		if NO_LOGIC_LOG == "1" then
			return
		end
		api.log(...)
	end

	local function check_dns(domain, dns)
		if domain == "" or domain:find("#") then
			return false
		end
		if not dns then
			return
		end
		for k,v in ipairs(list1[domain].dns) do
			if dns == v then
				return true
			end
		end
		return false
	end

	local function check_ipset(domain, ipset)
		if domain == "" or domain:find("#") then
			return false
		end
		if not ipset then
			return
		end
		for k,v in ipairs(list1[domain].ipsets) do
			if ipset == v then
				return true
			end
		end
		return false
	end

	local function set_domain_address(domain, address)
		if domain == "" or domain:find("#") then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		if not list1[domain].address then
			list1[domain].address = address
		end
	end

	local function set_domain_dns(domain, dns)
		if domain == "" or domain:find("#") then
			return
		end
		if not dns then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		for line in string.gmatch(dns, '[^' .. "," .. ']+') do
			if not check_dns(domain, line) then
				table.insert(list1[domain].dns, line)
			end
		end
	end

	local function set_domain_ipset(domain, ipset)
		if domain == "" or domain:find("#") then
			return
		end
		if not ipset then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		for line in string.gmatch(ipset, '[^' .. "," .. ']+') do
			if not check_ipset(domain, line) then
				table.insert(list1[domain].ipsets, line)
			end
		end
	end

	local function add_excluded_domain(domain)
		if domain == "" or domain:find("#") then
			return
		end
		excluded_domain[domain] = true
	end

	local function check_excluded_domain(domain)
		if domain == "" or domain:find("#") then
			return false
		end
		if excluded_domain[domain] then
			return true
		end
		local pos = domain:find(".", 1, true)
		while pos do
			if excluded_domain[domain:sub(pos + 1)] then
				return true
			end
			pos = domain:find(".", pos + 1, true)
		end
		return false
	end

	local cache_text = ""
	local nodes_address_md5 = sys.exec("echo -n $(uci show passwall | grep '\\.address') | md5sum")
	local new_rules = sys.exec("echo -n $(find /usr/share/passwall/rules -type f | xargs md5sum)")
	local new_text = TMP_DNSMASQ_PATH .. DNSMASQ_CONF_FILE .. DEFAULT_DNS .. LOCAL_DNS .. TUN_DNS .. REMOTE_FAKEDNS .. USE_DEFAULT_DNS .. CHINADNS_DNS .. USE_DIRECT_LIST .. USE_PROXY_LIST .. USE_BLOCK_LIST .. USE_GFW_LIST .. CHN_LIST .. DEFAULT_PROXY_MODE .. NO_PROXY_IPV6 .. nodes_address_md5 .. new_rules .. NFTFLAG
	if fs.access(CACHE_TEXT_FILE) then
		for line in io.lines(CACHE_TEXT_FILE) do
			cache_text = line
		end
	end

	if cache_text ~= new_text then
		api.remove(CACHE_DNS_PATH .. "*")
	end

	local dnsmasq_default_dns
	if USE_DEFAULT_DNS ~= "nil" then
		if USE_DEFAULT_DNS == "direct" then
			dnsmasq_default_dns = LOCAL_DNS
		end
		if USE_DEFAULT_DNS == "remote" then
			dnsmasq_default_dns = TUN_DNS
		end
		if USE_DEFAULT_DNS == "remote" and CHN_LIST == "direct" then
			dnsmasq_default_dns = TUN_DNS
		end
	end

	local only_global
	if DEFAULT_PROXY_MODE == "proxy" and CHN_LIST == "0" and USE_GFW_LIST == "0" then
		--没有启用中国列表和GFW列表时
		dnsmasq_default_dns = TUN_DNS
		only_global = 1
	end
	if USE_DEFAULT_DNS == "chinadns_ng" and CHINADNS_DNS ~= "0" then
		dnsmasq_default_dns = CHINADNS_DNS
		USE_CHINADNS_NG = "1"
	end

	local setflag_4= (NFTFLAG == "1") and "4#inet#passwall#" or ""
	local setflag_6= (NFTFLAG == "1") and "6#inet#passwall#" or ""

	if not fs.access(CACHE_DNS_PATH) then
		fs.mkdir(CACHE_DNS_PATH)

		--屏蔽列表
		if USE_CHINADNS_NG == "0" then
			if USE_BLOCK_LIST == "1" then
				for line in io.lines("/usr/share/passwall/rules/block_host") do
					line = api.get_std_domain(line)
					if line ~= "" and not line:find("#") and not line:find(":") then
						set_domain_address(line, "")
					end
				end
			end
		end

		local fwd_dns
		local no_ipv6

		--始终用国内DNS解析节点域名
		if true then
			fwd_dns = LOCAL_DNS
			if USE_CHINADNS_NG == "1" then
				fwd_dns = nil
			else
				local sets = {
					setflag_4 .. "passwall_vps",
					setflag_6 .. "passwall_vps6"
				}
				local function process_address(address)
					address = (address or ""):lower()
					if api.vps_domain_exclude(address) then return end
					if datatypes.hostname(address) then
						set_domain_dns(address, fwd_dns)
						set_domain_ipset(address, table.concat(sets, ","))
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
				log(string.format("  - 节点列表中的域名(vpslist)：%s", fwd_dns or "默认"))
			end
		end

		--直连（白名单）列表
		if USE_DIRECT_LIST == "1" then
			if fs.access("/usr/share/passwall/rules/direct_host") then
				fwd_dns = LOCAL_DNS
				if USE_CHINADNS_NG == "1" then
					fwd_dns = nil
				end
				if fwd_dns then
					local sets = {
						setflag_4 .. "passwall_white",
						setflag_6 .. "passwall_white6"
					}
					--始终用国内DNS解析直连（白名单）列表
					for line in io.lines("/usr/share/passwall/rules/direct_host") do
						line = api.get_std_domain(line)
						if line ~= "" and not line:find("#") and not line:find(":") then
							add_excluded_domain(line)
							set_domain_dns(line, fwd_dns)
							set_domain_ipset(line, table.concat(sets, ","))
						end
					end
					log(string.format("  - 域名白名单(whitelist)：%s", fwd_dns or "默认"))
				end
			end
		end

		--代理（黑名单）列表
		if USE_PROXY_LIST == "1" then
			if fs.access("/usr/share/passwall/rules/proxy_host") then
				fwd_dns = TUN_DNS
				if USE_CHINADNS_NG == "1" then
					fwd_dns = nil
				end
				if fwd_dns then
					local set_name = "passwall_black"
					local set6_name = "passwall_black6"
					if FLAG ~= "default" then
						set_name = "passwall_" .. FLAG .. "_black"
						set6_name = "passwall_" .. FLAG .. "_black6"
					end
					local sets = {
						setflag_4 .. set_name
					}
					if NO_PROXY_IPV6 ~= "1" then
						table.insert(sets, setflag_6 .. set6_name)
					end
					if REMOTE_FAKEDNS == "1" then
						sets = {}
					end
					--始终使用远程DNS解析代理（黑名单）列表
					for line in io.lines("/usr/share/passwall/rules/proxy_host") do
						line = api.get_std_domain(line)
						if line ~= "" and not line:find("#") and not line:find(":") then
							add_excluded_domain(line)
							if NO_PROXY_IPV6 == "1" then
								set_domain_address(line, "::")
							end
							set_domain_dns(line, fwd_dns)
							set_domain_ipset(line, table.concat(sets, ","))
						end
					end
					log(string.format("  - 代理域名表(blacklist)：%s", fwd_dns or "默认"))
				end
			end
		end

		--GFW列表
		if USE_GFW_LIST == "1" then
			if fs.access("/usr/share/passwall/rules/gfwlist") then
				fwd_dns = TUN_DNS
				if USE_CHINADNS_NG == "1" then
					fwd_dns = nil
				end
				if fwd_dns then
					local set_name = "passwall_gfw"
					local set6_name = "passwall_gfw6"
					if FLAG ~= "default" then
						set_name = "passwall_" .. FLAG .. "_gfw"
						set6_name = "passwall_" .. FLAG .. "_gfw6"
					end
					local sets = {
						setflag_4 .. set_name
					}
					if NO_PROXY_IPV6 ~= "1" then
						table.insert(sets, setflag_6 .. set6_name)
					end
					if REMOTE_FAKEDNS == "1" then
						sets = {}
					end
					for line in io.lines("/usr/share/passwall/rules/gfwlist") do
						if line ~= "" and not line:find("#") and not check_excluded_domain(line) then
							if NO_PROXY_IPV6 == "1" then
								set_domain_address(line, "::")
							end
							if dnsmasq_default_dns == fwd_dns then
								fwd_dns = nil
							else
								set_domain_dns(line, fwd_dns)
							end
							set_domain_ipset(line, table.concat(sets, ","))
						end
					end
					log(string.format("  - 防火墙域名表(gfwlist)：%s", fwd_dns or "默认"))
				end
			end
		end

		--中国列表
		if CHN_LIST ~= "0" then
			if fs.access("/usr/share/passwall/rules/chnlist") then
				fwd_dns = nil
				if CHN_LIST == "direct" then
					fwd_dns = LOCAL_DNS
				end
				if CHN_LIST == "proxy" then
					fwd_dns = TUN_DNS
				end
				if USE_CHINADNS_NG == "1" then
					fwd_dns = nil
				end
				if fwd_dns then
					local sets = {
						setflag_4 .. "passwall_chn",
						setflag_6 .. "passwall_chn6"
					}
					if CHN_LIST == "proxy" then
						if NO_PROXY_IPV6 == "1" then
							sets = {
								setflag_4 .. "passwall_chn"
							}
						end
						if REMOTE_FAKEDNS == "1" then
							sets = {}
						end
					end
					for line in io.lines("/usr/share/passwall/rules/chnlist") do
						if line ~= "" and not line:find("#") and not check_excluded_domain(line) then
							if CHN_LIST == "proxy" and NO_PROXY_IPV6 == "1" then
								set_domain_address(line, "::")
							end
							if dnsmasq_default_dns == fwd_dns then
								fwd_dns = nil
							else
								set_domain_dns(line, fwd_dns)
							end
							set_domain_ipset(line, table.concat(sets, ","))
						end
					end
					log(string.format("  - 中国域名表(chnroute)：%s", fwd_dns or "默认"))
				end
			end
		end

		--分流规则
		if IS_SHUNT_NODE and USE_CHINADNS_NG == "0" then
			local t = uci:get_all(appname, TCP_NODE)
			local default_node_id = t["default_node"] or "_direct"
			uci:foreach(appname, "shunt_rules", function(s)
				local _node_id = t[s[".name"]]
				if _node_id and _node_id ~= "_blackhole" then
					if _node_id == "_default" then
						_node_id = default_node_id
					end

					fwd_dns = nil
					no_ipv6 = nil

					local sets = {}

					if _node_id == "_direct" then
						fwd_dns = LOCAL_DNS
						if USE_DIRECT_LIST == "1" then
							table.insert(sets, setflag_4 .. "passwall_white")
							table.insert(sets, setflag_6 .. "passwall_white6")
						else
							local set_name = "passwall_shunt"
							local set6_name = "passwall_shunt6"
							if FLAG ~= "default" then
								set_name = "passwall_" .. FLAG .. "_shunt"
								set6_name = "passwall_" .. FLAG .. "_shunt6"
							end
							table.insert(sets, setflag_4 .. set_name)
							table.insert(sets, setflag_6 .. set6_name)
						end
					else
						local set_name = "passwall_shunt"
						local set6_name = "passwall_shunt6"
						if FLAG ~= "default" then
							set_name = "passwall_" .. FLAG .. "_shunt"
							set6_name = "passwall_" .. FLAG .. "_shunt6"
						end
						fwd_dns = TUN_DNS
						table.insert(sets, setflag_4 .. set_name)
						if NO_PROXY_IPV6 ~= "1" then
							table.insert(sets, setflag_6 .. set6_name)
						else
							no_ipv6 = true
						end
						if not only_global then
							if REMOTE_FAKEDNS == "1" then
								sets = {}
							end
						end
					end

					local domain_list = s.domain_list or ""
					for line in string.gmatch(domain_list, "[^\r\n]+") do
						if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("geosite:") and not line:find("ext:") then
							if line:find("domain:") or line:find("full:") then
								line = string.match(line, ":([^:]+)$")
							end
							line = api.get_std_domain(line)
							add_excluded_domain(line)

							if no_ipv6 then
								set_domain_address(line, "::")
							end
							set_domain_dns(line, fwd_dns)
							set_domain_ipset(line, table.concat(sets, ","))
						end
					end
					if _node_id ~= "_direct" then
						log(string.format("  - Sing-Box/Xray分流规则(%s)：%s", s.remarks, fwd_dns or "默认"))
					end
				end
			end)
		elseif only_global == 1 and NO_PROXY_IPV6 == "1" then
			--节点：固定节点
			--代理模式：全局模式
			--过滤代理域名 IPv6：启用
			--禁止解析所有IPv6记录
			list1["#"] = {
				dns = {},
				ipsets = {},
				address = "::"
			}
		end

		if list1 and next(list1) then
			local address_out = io.open(CACHE_DNS_PATH .. "/000-address.conf", "a")
			local server_out = io.open(CACHE_DNS_PATH .. "/001-server.conf", "a")
			local ipset_out = io.open(CACHE_DNS_PATH .. "/ipset.conf", "a")
			local set_name = "ipset"
			if NFTFLAG == "1" then
				set_name = "nftset"
			end
			for key, value in pairs(list1) do
				if value.address then
					local domain = "." .. key
					if key == "#" then
						domain = key
					end
					address_out:write(string.format("address=/%s/%s", domain, value.address) .. "\n")
				end
				if value.dns and #value.dns > 0 then
					for i, dns in ipairs(value.dns) do
						server_out:write(string.format("server=/.%s/%s", key, dns) .. "\n")
					end
				end
				if value.ipsets and #value.ipsets > 0 then
					local ipsets_str = ""
					for i, ipset in ipairs(value.ipsets) do
						ipsets_str = ipsets_str .. ipset .. ","
					end
					ipsets_str = ipsets_str:sub(1, #ipsets_str - 1)
					ipset_out:write(string.format("%s=/.%s/%s", set_name, key, ipsets_str) .. "\n")
				end
			end
			address_out:close()
			server_out:close()
			ipset_out:close()
		end

		local f_out = io.open(CACHE_TEXT_FILE, "a")
		f_out:write(new_text)
		f_out:close()
	end

	if USE_CHINADNS_NG == "0" then
		api.remove(TMP_DNSMASQ_PATH)
		fs.symlink(CACHE_DNS_PATH, TMP_DNSMASQ_PATH)
	end

	if DNSMASQ_CONF_FILE ~= "nil" then
		local conf_lines = {}
		if LISTEN_PORT then
			--Copy dnsmasq instance
			conf_lines = copy_instance({["-LISTEN_PORT"] = LISTEN_PORT, ["-TMP_DNSMASQ_PATH"] = TMP_DNSMASQ_PATH, ["-return"] = "1"})
			--dhcp.leases to hosts
			local hosts = "/tmp/etc/" .. appname .. "_tmp/dhcp-hosts"
			sys.call("touch " .. hosts)
			tinsert(conf_lines, "addn-hosts=" .. hosts)
		else
			--Modify the default dnsmasq service
		end
		if USE_CHINADNS_NG == "0" then
			tinsert(conf_lines, string.format("conf-dir=%s", TMP_DNSMASQ_PATH))
		end
		if dnsmasq_default_dns then
			for s in string.gmatch(dnsmasq_default_dns, '[^' .. "," .. ']+') do
				tinsert(conf_lines, string.format("server=%s", s))
			end
			tinsert(conf_lines, "all-servers")
			tinsert(conf_lines, "no-poll")
			tinsert(conf_lines, "no-resolv")
			if USE_CHINADNS_NG == "0" then
				log(string.format("  - 默认：%s", dnsmasq_default_dns))
			end

			if FLAG == "default" then
				api.set_cache_var("DEFAULT_DNS", DEFAULT_DNS)
			end
		end
		if #conf_lines > 0 then
			local conf_out = io.open(DNSMASQ_CONF_FILE, "a")
			conf_out:write(table.concat(conf_lines, "\n"))
			conf_out:write("\n")
			conf_out:close()
		end
	end

	if USE_CHINADNS_NG == "0" then
		log("  - PassWall必须依赖于Dnsmasq，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理域名)分流失效！！！")
	end
end

_G.stretch = stretch
_G.restart = restart
_G.logic_restart = logic_restart
_G.copy_instance = copy_instance
_G.add_rule = add_rule

if arg[1] then
	local func =_G[arg[1]]
	if func then
		func(api.get_function_args(arg))
	end
end
