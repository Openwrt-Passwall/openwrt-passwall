module("luci.passwall.api", package.seeall)
local com = require "luci.passwall.com"
bin = require "nixio".bin
fs = require "nixio.fs"
sys = require "luci.sys"
uci = require "luci.model.uci".cursor()
util = require "luci.util"
datatypes = require "luci.cbi.datatypes"
jsonc = require "luci.jsonc"
i18n = require "luci.i18n"

appname = "passwall"
curl_args = { "-skfL", "--connect-timeout 3", "--retry 3" }
command_timeout = 300
OPENWRT_ARCH = nil
DISTRIB_ARCH = nil
OPENWRT_BOARD = nil

CACHE_PATH = "/tmp/etc/" .. appname .. "_tmp"
LOG_FILE = "/tmp/log/" .. appname .. ".log"
TMP_PATH = "/tmp/etc/" .. appname
TMP_IFACE_PATH = TMP_PATH .. "/iface"

function log(...)
	local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
	local f, err = io.open(LOG_FILE, "a")
	if f and err == nil then
		f:write(result .. "\n")
		f:close()
	end
end

function is_js_luci()
	return sys.call('[ -f "/www/luci-static/resources/uci.js" ]') == 0
end

function is_old_uci()
	return sys.call("grep -E 'require[ \t]*\"uci\"' /usr/lib/lua/luci/model/uci.lua >/dev/null 2>&1") == 0
end

function uci_save(cursor, config, commit, apply)
	if is_old_uci() then
		cursor:save(config)
		if commit then
			cursor:commit(config)
			if apply then
				sys.call("/etc/init.d/" .. config .. " reload > /dev/null 2>&1 &")
			end
		end
	else
		commit = true
		if commit then
			if apply then
				cursor:commit(config)
			else
				sh_uci_commit(config)
			end
		end
	end
end

function sh_uci_get(config, section, option)
	local _, val = exec_call(string.format("uci -q get %s.%s.%s", config, section, option))
	return val
end

function sh_uci_set(config, section, option, val, commit)
	exec_call(string.format("uci -q set %s.%s.%s=\"%s\"", config, section, option, val))
	if commit then sh_uci_commit(config) end
end

function sh_uci_del(config, section, option, commit)
	exec_call(string.format("uci -q delete %s.%s.%s", config, section, option))
	if commit then sh_uci_commit(config) end
end

function sh_uci_add_list(config, section, option, val, commit)
	exec_call(string.format("uci -q del_list %s.%s.%s=\"%s\"", config, section, option, val))
	exec_call(string.format("uci -q add_list %s.%s.%s=\"%s\"", config, section, option, val))
	if commit then sh_uci_commit(config) end
end

function sh_uci_commit(config)
	exec_call(string.format("uci -q commit %s", config))
end

function set_cache_var(key, val)
	sys.call(string.format('. /usr/share/passwall/utils.sh ; set_cache_var %s "%s"', key, val))
end

function get_cache_var(key)
	local val = sys.exec(string.format('. /usr/share/passwall/utils.sh ; echo -n $(get_cache_var %s)', key))
	if val == "" then val = nil end
	return val
end

function get_new_port()
	local cmd_format = ". /usr/share/passwall/utils.sh ; echo -n $(get_new_port %s tcp,udp)"
	return tonumber(sys.exec(string.format(cmd_format, "auto")))
end

function exec_call(cmd)
	local process = io.popen(cmd .. '; echo -e "\n$?"')
	local lines = {}
	local result = ""
	local return_code
	for line in process:lines() do
		lines[#lines + 1] = line
	end
	process:close()
	if #lines > 0 then
		return_code = lines[#lines]
		for i = 1, #lines - 1 do
			result = result .. lines[i] .. ((i == #lines - 1) and "" or "\n")
		end
	end
	return tonumber(return_code), trim(result)
end

function base64Decode(text)
	if not text then return '' end
	local encoded = text:gsub("%z", ""):gsub("%c", ""):gsub("_", "/"):gsub("-", "+")
	local mod4 = #encoded % 4
	encoded = encoded .. string.sub('====', mod4 + 1)
	local result = nixio.bin.b64decode(encoded)
	if result then
		return result:gsub("%z", "")
	else
		return text
	end
end

function base64Encode(text)
	local result = nixio.bin.b64encode(text)
	return result
end

function UrlEncode(szText)
	return szText:gsub("([^%w%-_%.%~])", function(c)
		return string.format("%%%02X", string.byte(c))
	end)
end

function UrlDecode(szText)
	return szText and szText:gsub("%+", " "):gsub("%%(%x%x)", function(h)
		return string.char(tonumber(h, 16))
	end) or nil
end

--提取URL中的域名和端口(no ip)
function get_domain_port_from_url(url)
	local scheme, domain, port = string.match(url, "^(https?)://([%w%.%-]+):?(%d*)")
	if not domain then
		scheme, domain, port = string.match(url, "^(https?)://(%b[])([^:/]*)/?")
	end
	if not domain then return nil, nil end
	if domain:sub(1, 1) == "[" then domain = domain:sub(2, -2) end
	port = port ~= "" and tonumber(port) or (scheme == "https" and 443 or 80)
	if datatypes.ipaddr(domain) or datatypes.ip6addr(domain) then return nil, nil end
	return domain, port
end

--解析域名
function domainToIPv4(domain, dns)
	local Dns = dns or "223.5.5.5"
	local IPs = luci.sys.exec('nslookup %s %s | awk \'/^Name:/{getline; if ($1 == "Address:") print $2}\'' % { domain, Dns })
	for IP in string.gmatch(IPs, "%S+") do
		if datatypes.ipaddr(IP) and not datatypes.ip6addr(IP) then return IP end
	end
	return nil
end

function curl_base(url, file, args)
	if not args then args = {} end
	if file then
		args[#args + 1] = "-o " .. file
	end
	local cmd = string.format('curl %s "%s"', table_join(args), url)
	return exec_call(cmd)
end

function curl_proxy(url, file, args)
	--使用代理
	local socks_server = get_cache_var("GLOBAL_TCP_SOCKS_server")
	if socks_server and socks_server ~= "" then
		if not args then args = {} end
		local tmp_args = clone(args)
		tmp_args[#tmp_args + 1] = "-x socks5h://" .. socks_server
		return curl_base(url, file, tmp_args)
	end
	return nil, nil
end

function curl_logic(url, file, args)
	local return_code, result = curl_proxy(url, file, args)
	if not return_code or return_code ~= 0 then
		return_code, result = curl_base(url, file, args)
	end
	return return_code, result
end

function curl_direct(url, file, args)
	--直连访问
	local chn_list = uci:get(appname, "@global[0]", "chn_list") or "direct"
	local Dns = (chn_list == "proxy") and "1.1.1.1" or "223.5.5.5"
	if not args then args = {} end
	local tmp_args = clone(args)
	local domain, port = get_domain_port_from_url(url)
	if domain then
		local ip = domainToIPv4(domain, Dns)
		if ip then
			tmp_args[#tmp_args + 1] = "--resolve " .. domain .. ":" .. port .. ":" .. ip
		end
	end
	return curl_base(url, file, tmp_args)
end

function curl_auto(url, file, args)
	local localhost_proxy = uci:get(appname, "@global[0]", "localhost_proxy") or "1"
	if localhost_proxy == "1" then
		return curl_base(url, file, args) -- 当路由器本机开启代理时，采用passwall规则进行访问
	else
		local return_code, result = curl_proxy(url, file, args)
		if not return_code or return_code ~= 0 then
			return_code, result = curl_direct(url, file, args)
		end
		return return_code, result
	end
end

function url(...)
	local url = string.format("admin/services/%s", appname)
	local args = { ... }
	for i, v in pairs(args) do
		if v ~= "" then
			url = url .. "/" .. v
		end
	end
	return require "luci.dispatcher".build_url(url)
end

function trim(s)
	if type(s) ~= "string" then return "" end
	local i, j = 1, #s
	while i <= j and s:byte(i) <= 32 do i = i + 1 end
	while j >= i and s:byte(j) <= 32 do j = j - 1 end
	if i > j then return "" end
	return s:sub(i, j)
end

-- 分割字符串
function split(full, sep)
	if full then
		full = full:gsub("%z", "") -- 这里不是很清楚 有时候结尾带个\0
		local off, result = 1, {}
		while true do
			local nStart, nEnd = full:find(sep, off)
			if not nEnd then
				local res = string.sub(full, off, string.len(full))
				if #res > 0 then -- 过滤掉 \0
					table.insert(result, res)
				end
				break
			else
				table.insert(result, string.sub(full, off, nStart - 1))
				off = nEnd + 1
			end
		end
		return result
	end
	return {}
end

function is_exist(table, value)
	for index, k in ipairs(table) do
		if k == value then
			return true
		end
	end
	return false
end

function repeat_exist(table, value)
	local count = 0
	for index, k in ipairs(table) do
		if k:find("-") and k == value then
			count = count + 1
		end
	end
	if count > 1 then
		return true
	end
	return false
end

function remove(...)
	for index, value in ipairs({...}) do
		if value and #value > 0 and value ~= "/" then
			sys.call(string.format("rm -rf %s", value))
		end
	end
end

function is_install(package)
	if package and #package > 0 then
		local file_path = "/usr/lib/opkg/info"
		local file_ext = ".control"
		local has = sys.call("[ -d " .. file_path .. " ]")
		if has ~= 0 then
			file_path = "/lib/apk/packages"
			file_ext = ".list"
		end
		return sys.call(string.format('[ -s "%s/%s%s" ]', file_path, package, file_ext)) == 0
	end
	return false
end

function get_args(arg)
	local var = {}
	for i, arg_k in pairs(arg) do
		if i > 0 then
			local v = arg[i + 1]
			if v then
				if repeat_exist(arg, v) == false then
					var[arg_k] = v
				end
			end
		end
	end
	return var
end

function get_function_args(arg)
	local var = nil
	if arg and #arg > 1 then
		local param = {}
		for i = 2, #arg do
			param[#param + 1] = arg[i]
		end
		var = get_args(param)
	end
	return var
end

function strToTable(str)
	if str == nil or type(str) ~= "string" then
		return {}
	end

	return loadstring("return " .. str)()
end

function is_normal_node(e)
	if e and e.type and e.protocol and (e.protocol == "_balancing" or e.protocol == "_shunt" or e.protocol == "_iface" or e.protocol == "_urltest") then
		return false
	end
	return true
end

function is_special_node(e)
	return is_normal_node(e) == false
end

function is_ip(val)
	local str = val:match("%[(.-)%]") or val
	return datatypes.ipaddr(str) or false
end

function is_ipv6(val)
	local str = val:match("%[(.-)%]") or val
	return datatypes.ip6addr(str) or false
end

function is_local_ip(ip)
	ip = trim(ip):lower()
	ip = ip:gsub("^[%w%d]+://", "")   -- 去掉协议头
		:gsub("/.*$", "")          -- 去掉路径
		:gsub("^%[", ""):gsub("%]$", "") -- 去掉IPv6方括号
		:gsub(":%d+$", "")         -- 去掉端口
	return ip:match("^127%.") or ip:match("^10%.") or
		ip:match("^172%.1[6-9]%.") or ip:match("^172%.2[0-9]%.") or
		ip:match("^172%.3[0-1]%.") or ip:match("^192%.168%.") or
		ip == "::1" or ip:match("^f[cd]") or ip:match("^fe[89ab]")
end

function is_ipv6addrport(val)
	local address, port = val:match("%[(.-)%]:([0-9]+)$")
	if address and datatypes.ip6addr(address) and datatypes.port(port) then
		return true
	end
	return false
end

function get_ipv6_only(val)
	local result = ""
	local inner = val:match("%[(.-)%]") or val
	if datatypes.ip6addr(inner) then
		result = inner
	end
	return result
end

function get_ipv6_full(val)
	local result = ""
	if is_ipv6(val) then
		result = val
		if not val:match("%[.-%]") then
			result = "[" .. result .. "]"
		end
	end
	return result
end

function get_ip_type(val)
	if is_ipv6(val) then
		return "6"
	elseif datatypes.ip4addr(val) then
		return "4"
	end
	return ""
end

function is_mac(val)
	return datatypes.macaddr(val)
end

function ip_or_mac(val)
	if val then
		if get_ip_type(val) == "4" then
			return "ip"
		end
		if is_mac(val) then
			return "mac"
		end
	end
	return ""
end

function iprange(val)
	if val then
		local ipStart, ipEnd = val:match("^([^/]+)-([^/]+)$")
		if (ipStart and datatypes.ip4addr(ipStart)) and (ipEnd and datatypes.ip4addr(ipEnd)) then
			return true
		end
	end
	return false
end

function get_domain_from_url(url)
	local domain = string.match(url, "//([^/]+)")
	if domain then
		return domain
	end
	return url
end

function get_valid_nodes()
	local show_node_info = uci_get_type("global_other", "show_node_info", "0")
	local nodes = {}
	local default_nodes = {}
	local other_nodes = {}
	uci:foreach(appname, "nodes", function(e)
		e.id = e[".name"]
		if e.type and e.remarks then
			local type_name = e.type
			if e.type == "sing-box" then type_name = "Sing-Box" end
			if e.protocol and (e.protocol == "_balancing" or e.protocol == "_shunt" or e.protocol == "_iface" or e.protocol == "_urltest") then
				e["remark"] = trim("%s：[%s]" % {type_name .. " " .. i18n.translatef(e.protocol), e.remarks})
				e["node_type"] = "special"
				if not e.group or e.group == "" then
					default_nodes[#default_nodes + 1] = e
				else
					other_nodes[#other_nodes + 1] = e
				end
			end
			local port = e.port or e.hysteria_hop or e.hysteria2_hop
			if port and e.address then
				local address = e.address
				if is_ip(address) or datatypes.hostname(address) then
					if (e.type == "sing-box" or e.type == "Xray") and e.protocol then
						local protocol = e.protocol
						if protocol == "vmess" then
							protocol = "VMess"
						elseif protocol == "vless" then
							protocol = "VLESS"
						elseif protocol == "shadowsocks" then
							protocol = "SS"
						elseif protocol == "shadowsocksr" then
							protocol = "SSR"
						elseif protocol == "wireguard" then
							protocol = "WG"
						elseif protocol == "hysteria" then
							protocol = "HY"
						elseif protocol == "hysteria2" then
							protocol = "HY2"
						elseif protocol == "anytls" then
							protocol = "AnyTLS"
						elseif protocol == "ssh" then
							protocol = "SSH"
						else
							protocol = protocol:gsub("^%l",string.upper)
						end
						type_name = type_name .. " " .. protocol
					end
					if is_ipv6(address) then address = get_ipv6_full(address) end
					e["remark"] = trim("%s：[%s]" % {type_name, e.remarks})
					if show_node_info == "1" then
						port = port:gsub(":", "-")
						e["remark"] = trim("%s：[%s] %s:%s" % {type_name, e.remarks, address, port})
					end
					e.node_type = "normal"
					if not e.group or e.group == "" then
						default_nodes[#default_nodes + 1] = e
					else
						other_nodes[#other_nodes + 1] = e
					end
				end
			end
		end
	end)
	for i = 1, #default_nodes do nodes[#nodes + 1] = default_nodes[i] end
	for i = 1, #other_nodes do nodes[#nodes + 1] = other_nodes[i] end
	return nodes
end

function get_node_remarks(n)
	local remarks = ""
	if n then
		local type_name = n.type
		if n.type == "sing-box" then type_name = "Sing-Box" end
		if n.protocol and (n.protocol == "_balancing" or n.protocol == "_shunt" or n.protocol == "_iface" or n.protocol == "_urltest") then
			remarks = trim("%s：[%s]" % {type_name .. " " .. i18n.translatef(n.protocol), n.remarks})
		else
			if (n.type == "sing-box" or n.type == "Xray") and n.protocol then
				local protocol = n.protocol
				if protocol == "vmess" then
					protocol = "VMess"
				elseif protocol == "vless" then
					protocol = "VLESS"
				elseif protocol == "shadowsocks" then
					protocol = "SS"
				elseif protocol == "shadowsocksr" then
					protocol = "SSR"
				elseif protocol == "wireguard" then
					protocol = "WG"
				elseif protocol == "hysteria" then
					protocol = "HY"
				elseif protocol == "hysteria2" then
					protocol = "HY2"
				elseif protocol == "anytls" then
					protocol = "AnyTLS"
				elseif protocol == "ssh" then
					protocol = "SSH"
				else
					protocol = protocol:gsub("^%l",string.upper)
				end
				type_name = type_name .. " " .. protocol
			end
			remarks = trim("%s：[%s]" % {type_name, n.remarks})
		end
	end
	return remarks
end

function get_full_node_remarks(n)
	local remarks = get_node_remarks(n)
	if #remarks > 0 then
		local port = n.port or n.hysteria_hop or n.hysteria2_hop
		if n.address and port then
			port = port:gsub(":", "-")
			remarks = remarks .. " " .. n.address .. ":" .. port
		end
	end
	return remarks
end

function gen_uuid(format)
	local uuid = sys.exec("echo -n $(cat /proc/sys/kernel/random/uuid)")
	if format == nil then
		uuid = string.gsub(uuid, "-", "")
	end
	return uuid
end

function gen_short_uuid()
	return sys.exec("echo -n $(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)")
end

function uci_get_type(type, config, default)
	local value = uci:get_first(appname, type, config, default) or sys.exec("echo -n $(uci -q get " .. appname .. ".@" .. type .."[0]." .. config .. ")")
	if (value == nil or value == "") and (default and default ~= "") then
		value = default
	end
	return value
end

function uci_get_type_id(id, config, default)
	local value = uci:get(appname, id, config, default) or sys.exec("echo -n $(uci -q get " .. appname .. "." .. id .. "." .. config .. ")")
	if (value == nil or value == "") and (default and default ~= "") then
		value = default
	end
	return value
end

local function chmod_755(file)
	if file and file ~= "" then
		if not fs.access(file, "rwx", "rx", "rx") then
			fs.chmod(file, 755)
		end
	end
end

function get_customed_path(e)
	return uci_get_type("global_app", e .. "_file")
end

function finded_com(e)
	local bin = get_app_path(e)
	if not bin then return end
	local s = luci.sys.exec('echo -n $(type -t -p "%s" | head -n1)' % { bin })
	if s == "" then
		s = nil
	end
	return s
end

function finded(e)
	return luci.sys.exec('echo -n $(type -t -p "/bin/%s" -p "/usr/bin/%s" "%s" | head -n1)' % {e, e, e})
end

function is_finded(e)
	return finded(e) ~= "" and true or false
end

function clone(org)
	local function copy(org, res)
		for k,v in pairs(org) do
			if type(v) ~= "table" then
				res[k] = v;
			else
				res[k] = {};
				copy(v, res[k])
			end
		end
	end

	local res = {}
	copy(org, res)
	return res
end

function get_bin_version_cache(file, cmd)
	sys.call("mkdir -p /tmp/etc/passwall_tmp")
	if fs.access(file) then
		chmod_755(file)
		local md5 = sys.exec("echo -n $(md5sum " .. file .. " | awk '{print $1}')")
		if fs.access("/tmp/etc/passwall_tmp/" .. md5) then
			return sys.exec("echo -n $(cat /tmp/etc/passwall_tmp/%s)" % md5)
		else
			local version = sys.exec(string.format("echo -n $(%s %s)", file, cmd))
			if version and version ~= "" then
				sys.call("echo '" .. version .. "' > " .. "/tmp/etc/passwall_tmp/" .. md5)
				return version
			end
		end
	end
	return ""
end

function get_app_path(app_name)
	if com[app_name] then
		local def_path = com[app_name].default_path
		local path = uci_get_type("global_app", app_name:gsub("%-","_") .. "_file")
		path = path and (#path>0 and path or def_path) or def_path
		return path
	end
end

function get_app_version(app_name, file)
	if file == nil then file = get_app_path(app_name) end
	return get_bin_version_cache(file, com[app_name].cmd_version)
end

local function is_file(path)
	if path and #path > 1 then
		if sys.exec('[ -f "%s" ] && echo -n 1' % path) == "1" then
			return true
		end
	end
	return nil
end

local function is_dir(path)
	if path and #path > 1 then
		if sys.exec('[ -d "%s" ] && echo -n 1' % path) == "1" then
			return true
		end
	end
	return nil
end

local function get_final_dir(path)
	if is_dir(path) then
		return path
	else
		return get_final_dir(fs.dirname(path))
	end
end

local function get_free_space(dir)
	if dir == nil then dir = "/" end
	if sys.call("df -k " .. dir .. " >/dev/null 2>&1") == 0 then
		return tonumber(sys.exec("echo -n $(df -k " .. dir .. " | awk 'NR>1' | awk '{print $4}')"))
	end
	return 0
end

local function get_file_space(file)
	if file == nil then return 0 end
	if fs.access(file) then
		return tonumber(sys.exec("echo -n $(du -k " .. file .. " | awk '{print $1}')"))
	end
	return 0
end

function _unpack(t, i)
	i = i or 1
	if t[i] ~= nil then return t[i], _unpack(t, i + 1) end
end

function table_join(t, s)
	if not s then
		s = " "
	end
	local str = ""
	for index, value in ipairs(t) do
		str = str .. t[index] .. (index == #t and "" or s)
	end
	return str
end

local function exec(cmd, args, writer, timeout)
	local os = require "os"
	local nixio = require "nixio"

	local fdi, fdo = nixio.pipe()
	local pid = nixio.fork()

	if pid > 0 then
		fdo:close()

		if writer or timeout then
			local starttime = os.time()
			while true do
				if timeout and os.difftime(os.time(), starttime) >= timeout then
					nixio.kill(pid, nixio.const.SIGTERM)
					return 1
				end

				if writer then
					local buffer = fdi:read(2048)
					if buffer and #buffer > 0 then
						writer(buffer)
					end
				end

				local wpid, stat, code = nixio.waitpid(pid, "nohang")

				if wpid and stat == "exited" then return code end

				if not writer and timeout then nixio.nanosleep(1) end
			end
		else
			local wpid, stat, code = nixio.waitpid(pid)
			return wpid and stat == "exited" and code
		end
	elseif pid == 0 then
		nixio.dup(fdo, nixio.stdout)
		fdi:close()
		fdo:close()
		nixio.exece(cmd, args, nil)
		nixio.stdout:close()
		os.exit(1)
	end
end

function compare_versions(ver1, comp, ver2)
	local table = table

	if not ver1 then ver1 = "" end
	if not ver2 then ver2 = "" end

	local av1 = util.split(ver1, "[%.%-]", nil, true)
	local av2 = util.split(ver2, "[%.%-]", nil, true)

	local max = table.getn(av1)
	local n2 = table.getn(av2)
	if (max < n2) then max = n2 end

	for i = 1, max, 1 do
		local s1 = tonumber(av1[i] or 0) or 0
		local s2 = tonumber(av2[i] or 0) or 0

		if comp == "~=" and (s1 ~= s2) then return true end
		if (comp == "<" or comp == "<=") and (s1 < s2) then return true end
		if (comp == ">" or comp == ">=") and (s1 > s2) then return true end
		if (s1 ~= s2) then return false end
	end

	return not (comp == "<" or comp == ">")
end

local function auto_get_arch()
	local arch = nixio.uname().machine or ""
	if not OPENWRT_ARCH and fs.access("/usr/lib/os-release") then
		OPENWRT_ARCH = sys.exec("echo -n $(grep 'OPENWRT_ARCH' /usr/lib/os-release | awk -F '[\\042\\047]' '{print $2}')")
		OPENWRT_BOARD = sys.exec("echo -n $(grep 'OPENWRT_BOARD' /usr/lib/os-release | awk -F '[\\042\\047]' '{print $2}')")
		if OPENWRT_ARCH == "" then OPENWRT_ARCH = nil end
		if OPENWRT_BOARD == "" then OPENWRT_BOARD = nil end
	end
	if not DISTRIB_ARCH and fs.access("/etc/openwrt_release") then
		DISTRIB_ARCH = sys.exec("echo -n $(grep 'DISTRIB_ARCH' /etc/openwrt_release | awk -F '[\\042\\047]' '{print $2}')")
		if DISTRIB_ARCH == "" then DISTRIB_ARCH = nil end
	end

	if arch:match("^i[%d]86$") then
		arch = "x86"
	elseif arch:match("armv5") then  -- armv5l
		arch = "armv5"
	elseif arch:match("armv6") then
		arch = "armv6"
	elseif arch:match("armv7") then  -- armv7l
		arch = "armv7"
	end

	if OPENWRT_ARCH or DISTRIB_ARCH then
		if arch == "mips" then
			if OPENWRT_ARCH and OPENWRT_ARCH:match("mipsel") == "mipsel"
			or DISTRIB_ARCH and DISTRIB_ARCH:match("mipsel") == "mipsel" then
				arch = "mipsel"
			end
		elseif arch == "armv7" then
			if OPENWRT_ARCH and not OPENWRT_ARCH:match("vfp") and not OPENWRT_ARCH:match("neon")
			or DISTRIB_ARCH and not DISTRIB_ARCH:match("vfp") and not DISTRIB_ARCH:match("neon") then
				arch = "armv5"
			end
		end
	end

	if arch == "aarch64" and OPENWRT_BOARD and OPENWRT_BOARD:match("rockchip") ~= nil then
		arch = "rockchip"
	end

	return trim(arch)
end

function parseURL(url)
	if not url or url == "" then
		return nil
	end
	local pattern = "^(%w+)://"
	local protocol = url:match(pattern)

	if not protocol then
		--error("Invalid URL: " .. url)
		return nil
	end

	local auth_host_port = url:sub(#protocol + 4)
	local auth_pattern = "^([^@]+)@"
	local auth = auth_host_port:match(auth_pattern)
	local username, password

	if auth then
		username, password = auth:match("^([^:]+):([^:]+)$")
		auth_host_port = auth_host_port:sub(#auth + 2)
	end

	local host, port = auth_host_port:match("^([^:]+):(%d+)$")

	if not host or not port then
		--error("Invalid URL: " .. url)
		return nil
	end

	return {
		protocol = protocol,
		username = username,
		password = password,
		host = host,
		port = tonumber(port)
	}
end

local default_file_tree = {
	x86_64  = "amd64",
	x86     = "386",
	aarch64 = "arm64",
	rockchip = "arm64",
	mips    = "mips",
	mips64  = "mips64",
	mipsel  = "mipsel",
	mips64el = "mips64el",
	armv5   = "arm.*5",
	armv6   = "arm.*6[^4]*",
	armv7   = "arm.*7",
	armv8   = "arm64",
	riscv64 = "riscv64"
}

local function get_api_json(url)
	local jsonc = require "luci.jsonc"
	local return_code, content = curl_auto(url, nil, curl_args)
	if return_code ~= 0 or content == "" then return {} end
	return jsonc.parse(content) or {}
end

local function check_path(app_name)
	local path = get_app_path(app_name) or ""
	if path == "" then
		return {
			code = 1,
			error = i18n.translatef("You did not fill in the %s path. Please save and apply then update manually.", app_name)
		}
	end
	return {
		code = 0,
		app_path = path
	}
end

function to_check(arch, app_name)
	local result = check_path(app_name)
	if result.code ~= 0 then
		return result
	end

	if not arch or arch == "" then arch = auto_get_arch() end

	local file_tree = com[app_name].file_tree[arch] or default_file_tree[arch] or ""

	if file_tree == "" then
		return {
			code = 1,
			error = i18n.translate("Can't determine ARCH, or ARCH not supported.")
		}
	end

	local local_version = get_app_version(app_name)
	local match_file_name = string.format(com[app_name].match_fmt_str, file_tree)
	local json = get_api_json(com[app_name]:get_url())

	if #json > 0 then
		json = json[1]
	end

	if json.tag_name == nil then
		return {
			code = 1,
			error = i18n.translate("Get remote version info failed.")
		}
	end

	local remote_version = json.tag_name
	if com[app_name].remote_version_str_replace then
		remote_version = remote_version:gsub(com[app_name].remote_version_str_replace, "")
	end
	local has_update = compare_versions(local_version:match("[^v]+"), "<", remote_version:match("[^v]+"))
--[[
	if not has_update then
		return {
			code = 0,
			local_version = local_version,
			remote_version = remote_version
		}
	end
]]--
	local asset = {}
	for _, v in ipairs(json.assets) do
		if v.name and v.name:match(match_file_name) then
			asset = v
			break
		end
	end
	if not asset.browser_download_url then
		return {
			code = 1,
			local_version = local_version,
			remote_version = remote_version,
			html_url = json.html_url,
			data = asset,
			error = i18n.translate("New version found, but failed to get new version download url.")
		}
	end

	return {
		code = 0,
		has_update = has_update,
		local_version = local_version,
		remote_version = remote_version,
		html_url = json.html_url,
		data = asset
	}
end

function to_download(app_name, url, size)
	local result = check_path(app_name)
	if result.code ~= 0 then
		return result
	end

	if not url or url == "" then
		return {code = 1, error = i18n.translate("Download url is required.")}
	end

	sys.call("/bin/rm -f /tmp/".. app_name .."_download.*")

	local tmp_file = trim(util.exec("mktemp -u -t ".. app_name .."_download.XXXXXX"))

	if size then
		local kb1 = get_free_space("/tmp")
		if tonumber(size) > tonumber(kb1) then
			return {code = 1, error = i18n.translatef("%s not enough space.", "/tmp")}
		end
	end

	local _curl_args = clone(curl_args)
	table.insert(_curl_args, "--speed-limit 51200 --speed-time 15 --max-time 300")

	local return_code, result = curl_auto(url, tmp_file, _curl_args)
	result = return_code == 0

	if not result then
		exec("/bin/rm", {"-f", tmp_file})
		return {
			code = 1,
			error = i18n.translatef("File download failed or timed out: %s", url)
		}
	end

	return {code = 0, file = tmp_file, zip = com[app_name].zipped }
end

function to_extract(app_name, file, subfix)
	local result = check_path(app_name)
	if result.code ~= 0 then
		return result
	end

	if not file or file == "" or not fs.access(file) then
		return {code = 1, error = i18n.translate("File path required.")}
	end

	local tools_name
	if com[app_name].zipped then
		if not com[app_name].zipped_suffix or com[app_name].zipped_suffix == "zip" then
			tools_name = "unzip"
		end
		if com[app_name].zipped_suffix and com[app_name].zipped_suffix == "tar.gz" then
			tools_name = "tar"
		end
		if tools_name then
			if sys.exec("echo -n $(command -v %s)" % { tools_name }) == "" then
				exec("/bin/rm", {"-f", file})
				return {
					code = 1,
					error = i18n.translate("Not installed %s, Can't unzip!" % { tools_name })
				}
			end
		end
	end

	sys.call("/bin/rm -rf /tmp/".. app_name .."_extract.*")

	local new_file_size = get_file_space(file)
	local tmp_free_size = get_free_space("/tmp")
	if tmp_free_size <= 0 or tmp_free_size <= new_file_size then
		return {code = 1, error = i18n.translatef("%s not enough space.", "/tmp")}
	end

	local tmp_dir = trim(util.exec("mktemp -d -t ".. app_name .."_extract.XXXXXX"))

	local output = {}

	if tools_name then
		if tools_name == "unzip" then
			local bin = sys.exec("echo -n $(command -v unzip)")
			exec(bin, {"-o", file, app_name, "-d", tmp_dir}, function(chunk) output[#output + 1] = chunk end)
		elseif tools_name == "tar" then
			local bin = sys.exec("echo -n $(command -v tar)")
			if com[app_name].zipped_suffix == "tar.gz" then
				exec(bin, {"-zxf", file, "-C", tmp_dir}, function(chunk) output[#output + 1] = chunk end)
				sys.call("/bin/mv -f " .. tmp_dir .. "/*/" .. com[app_name].name:lower() .. " " .. tmp_dir)
			end
		end
	end

	local files = util.split(table.concat(output))

	exec("/bin/rm", {"-f", file})

	return {code = 0, file = tmp_dir}
end

function to_move(app_name,file)
	local result = check_path(app_name)
	if result.code ~= 0 then
		return result
	end

	local app_path = result.app_path
	local bin_path = file
	local cmd_rm_tmp = "/bin/rm -rf /tmp/" .. app_name .. "_download.*"
	if fs.stat(file, "type") == "dir" then
		bin_path = file .. "/" .. com[app_name].name:lower()
		cmd_rm_tmp = "/bin/rm -rf /tmp/" .. app_name .. "_extract.*"
	end

	if not file or file == "" then
		sys.call(cmd_rm_tmp)
		return {code = 1, error = i18n.translate("Client file is required.")}
	end

	local new_version = get_app_version(app_name, bin_path)
	if new_version == "" then
		sys.call(cmd_rm_tmp)
		return {
			code = 1,
			error = i18n.translate("The client file is not suitable for current device.") .. app_name .. "__" .. bin_path
		}
	end

	local flag = sys.call('pgrep -af "passwall/.*'.. app_name ..'" >/dev/null')
	if flag == 0 then
		sys.call("/etc/init.d/passwall stop")
	end

	local old_app_size = 0
	if fs.access(app_path) then
		old_app_size = get_file_space(app_path)
	end
	local new_app_size = get_file_space(bin_path)
	local final_dir = get_final_dir(app_path)
	local final_dir_free_size = get_free_space(final_dir)
	if final_dir_free_size > 0 then
		final_dir_free_size = final_dir_free_size + old_app_size
		if new_app_size > final_dir_free_size then
			sys.call(cmd_rm_tmp)
			return {code = 1, error = i18n.translatef("%s not enough space.", final_dir)}
		end
	end

	result = exec("/bin/mv", { "-f", bin_path, app_path }, nil, command_timeout) == 0

	sys.call(cmd_rm_tmp)
	if flag == 0 then
		sys.call("/etc/init.d/passwall restart >/dev/null 2>&1 &")
	end

	if not result or not fs.access(app_path) then
		return {
			code = 1,
			error = i18n.translatef("Can't move new file to path: %s", app_path)
		}
	end

	return {code = 0}
end

function get_version()
	local version = sys.exec("opkg list-installed luci-app-passwall 2>/dev/null | awk '{print $3}'")
	if not version or #version == 0 then
		version = sys.exec("apk list luci-app-passwall 2>/dev/null | awk '/installed/ {print $1}' | cut -d'-' -f4-")
	end
	return (version or ""):gsub("\n", ""):match("^([^-]+)")
end

function to_check_self()
	local url = "https://raw.githubusercontent.com/Openwrt-Passwall/openwrt-passwall/main/luci-app-passwall/Makefile"
	local tmp_file = "/tmp/passwall_makefile"
	local return_code, result = curl_auto(url, tmp_file, curl_args)
	result = return_code == 0
	if not result then
		exec("/bin/rm", {"-f", tmp_file})
		return {
			code = 1,
			error = i18n.translatef("Failed")
		}
	end
	local local_version  = get_version()
	local remote_version = sys.exec("echo -n $(grep '^PKG_VERSION' /tmp/passwall_makefile | head -n 1 | awk -F '=' '{print $2}')")
	exec("/bin/rm", {"-f", tmp_file})

	local has_update = compare_versions(local_version, "<", remote_version)
	if not has_update then
		return {
			code = 0,
			local_version = local_version,
			remote_version = remote_version
		}
	end
	return {
		code = 1,
		has_update = true,
		local_version = local_version,
		remote_version = remote_version,
		error = i18n.translatef("The latest version: %s, currently does not support automatic update, if you need to update, please compile or download the ipk and then manually install.", remote_version)
	}
end

function luci_types(id, m, s, type_name, option_prefix)
	local rewrite_option_table = {}
	for key, value in pairs(s.fields) do
		if key:find(option_prefix) == 1 then
			if not s.fields[key].not_rewrite then
				if s.fields[key].rewrite_option then
					if not rewrite_option_table[s.fields[key].rewrite_option] then
						rewrite_option_table[s.fields[key].rewrite_option] = 1
					else
						rewrite_option_table[s.fields[key].rewrite_option] = rewrite_option_table[s.fields[key].rewrite_option] + 1
					end
				end

				s.fields[key].cfgvalue = function(self, section)
					-- 添加自定义 custom_cfgvalue 属性，如果有自定义的 custom_cfgvalue 函数，则使用自定义的 cfgvalue 逻辑
					if self.custom_cfgvalue then
						return self:custom_cfgvalue(section)
					else
						if self.rewrite_option then
							return m:get(section, self.rewrite_option)
						else
							if self.option:find(option_prefix) == 1 then
								return m:get(section, self.option:sub(1 + #option_prefix))
							end
						end
					end
				end
				s.fields[key].write = function(self, section, value)
					if s.fields["type"]:formvalue(id) == type_name then
						-- 添加自定义 custom_write 属性，如果有自定义的 custom_write 函数，则使用自定义的 write 逻辑
						if self.custom_write then
							self:custom_write(section, value)
						else
							if self.rewrite_option then
								m:set(section, self.rewrite_option, value)
							else
								if self.option:find(option_prefix) == 1 then
									m:set(section, self.option:sub(1 + #option_prefix), value)
								end
							end
						end
					end
				end
				s.fields[key].remove = function(self, section)
					if s.fields["type"]:formvalue(id) == type_name then
						-- 添加自定义 custom_remove 属性，如果有自定义的 custom_remove 函数，则使用自定义的 remove 逻辑
						if self.custom_remove then
							self:custom_remove(section)
						else
							if self.rewrite_option and rewrite_option_table[self.rewrite_option] == 1 then
								m:del(section, self.rewrite_option)
							else
								if self.option:find(option_prefix) == 1 then
									m:del(section, self.option:sub(1 + #option_prefix))
								end
							end
						end
					end
				end
			end

			local deps = s.fields[key].deps
			if #deps > 0 then
				for index, value in ipairs(deps) do
					deps[index]["type"] = type_name
				end
			else
				s.fields[key]:depends({ type = type_name })
			end
		end
	end
end

function get_std_domain(domain)
	domain = trim(domain)
	if domain == "" then return "" end
	-- 含 # → ""
	for i = 1, #domain do
		if domain:byte(i) == 35 then return "" end -- '#'
	end
	local len = #domain
	local si, ei = 1, len
	-- 去前缀 '.'
	while si <= len and domain:byte(si) == 46 do si = si + 1 end
	-- 去后缀 '.'
	while ei >= si and domain:byte(ei) == 46 do ei = ei - 1 end
	if si > ei then return "" end
	domain = domain:sub(si, ei)
	len = #domain
	-- 是否有 '*'
	local star = false
	for i = 1, len do
		if domain:byte(i) == 42 then star = true break end
	end
	if not star then return domain end
	-- 切割 label
	local parts, pstart = {}, 1
	for i = 1, len + 1 do
		local b = (i <= len) and domain:byte(i) or 46 -- '.' 作为结束
		if b == 46 then
			parts[#parts + 1] = domain:sub(pstart, i - 1)
			pstart = i + 1
		end
	end
	-- 从右向左找含 '*' ,并删除包含 '*' 的部分及其左边部分
	for i = #parts, 1, -1 do
		local s = parts[i]
		local has = false
		for j = 1, #s do
			if s:byte(j) == 42 then has = true break end
		end
		if has then
			if i == #parts then return "" end
			local out = parts[i + 1]
			for k = i + 2, #parts do
				out = out .. "." .. parts[k]
			end
			return out
		end
	end
	return domain
end

function format_go_time(input)
	input = input and trim(input)
	local N = 0
	if input and input:match("^%d+$") then
		N = tonumber(input)
	elseif input and input ~= "" then
		for value, unit in input:gmatch("(%d+)%s*([hms])") do
			value = tonumber(value)
			if unit == "h" then
				N = N + value * 3600
			elseif unit == "m" then
				N = N + value * 60
			elseif unit == "s" then
				N = N + value
			end
		end
	end
	if N <= 0 then
		return "0s"
	end
	local result = ""
	local h = math.floor(N / 3600)
	local m = math.floor(N % 3600 / 60)
	local s = N % 60
	if h > 0 then result = result .. h .. "h" end
	if m > 0 then result = result .. m .. "m" end
	if s > 0 or result == "" then result = result .. s .. "s" end
	return result
end

function set_apply_on_parse(map)
	if not map then return end
	if is_js_luci() then
		apply_redirect(map)
		local old = map.on_after_save
		map.on_after_save = function(self)
			if old then old(self) end
			map:set("@global[0]", "timestamp", os.time())
		end
		-- 优化页面
		local cbi = require "luci.cbi"
		map:append(cbi.Template(appname .. "/cbi/optimize_cbi_ui"))
	end
end

function apply_redirect(m)
	local tmp_uci_file = "/etc/config/" .. appname .. "_redirect"
	if m.redirect and m.redirect ~= "" then
		if fs.access(tmp_uci_file) then
			local redirect
			for line in io.lines(tmp_uci_file) do
				redirect = line:match("option%s+url%s+['\"]([^'\"]+)['\"]")
				if redirect and redirect ~= "" then break end
			end
			if redirect and redirect ~= "" then
				sys.call("/bin/rm -f " .. tmp_uci_file)
				luci.http.redirect(redirect)
			end
		else
			fs.writefile(tmp_uci_file, "config redirect\n")
		end
		m.on_after_save = function(self)
			local redirect = self.redirect
			if redirect and redirect ~= "" then
				uci:set(appname .. "_redirect", "@redirect[0]", "url", redirect)
			end
		end
	else
		sys.call("/bin/rm -f " .. tmp_uci_file)
	end
end

function match_node_rule(name, rule)
	if not name then return false end
	if not rule or rule == "" then return true end
	-- split rule by &&
	local function split_and(expr)
		local t = {}
		for part in expr:gmatch("[^&]+") do
			part = part:gsub("^%s+", ""):gsub("%s+$", "")
			if part ~= "" then
				table.insert(t, part)
			end
		end
		return t
	end
	-- match single condition
	local function match_cond(str, cond)
		if cond == "" then
			return true
		end
		-- exclude: !xxx
		if cond:sub(1, 1) == "!" then
			local k = cond:sub(2)
			if k == "" then return true end
			return not str:find(k, 1, true)
		end
		-- prefix: ^xxx
		if cond:sub(1, 1) == "^" then
			local k = cond:sub(2)
			return str:sub(1, #k) == k
		end
		-- suffix: xxx$
		if cond:sub(-1) == "$" then
			local k = cond:sub(1, -2)
			return str:sub(-#k) == k
		end
		-- contains
		return str:find(cond, 1, true) ~= nil
	end
	-- AND logic
	for _, cond in ipairs(split_and(rule)) do
		if not match_cond(name, cond) then
			return false
		end
	end
	return true
end
