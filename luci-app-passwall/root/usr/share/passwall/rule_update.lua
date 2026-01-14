#!/usr/bin/lua

local api = require ("luci.passwall.api")
local name = api.appname
local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local fs = api.fs

local arg1 = arg[1]
local arg2 = arg[2]
local arg3 = arg[3]

local nftable_name = "inet passwall"
local rule_path = "/usr/share/" .. name .. "/rules"
local reboot = 0
local gfwlist_update = "0"
local chnroute_update = "0"
local chnroute6_update = "0"
local chnlist_update = "0"
local geoip_update = "0"
local geosite_update = "0"

local excluded_domain = {"apple.com","sina.cn","sina.com.cn","baidu.com","byr.cn","jlike.com","weibo.com","zhongsou.com","youdao.com","sogou.com","so.com","soso.com","aliyun.com","taobao.com","jd.com","qq.com","bing.com"}

local gfwlist_url = uci:get(name, "@global_rules[0]", "gfwlist_url") or {"https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"}
local chnroute_url = uci:get(name, "@global_rules[0]", "chnroute_url") or {"https://ispip.clang.cn/all_cn.txt"}
local chnroute6_url = uci:get(name, "@global_rules[0]", "chnroute6_url") or {"https://ispip.clang.cn/all_cn_ipv6.txt"}
local chnlist_url = uci:get(name, "@global_rules[0]", "chnlist_url") or {"https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf","https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf","https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/google.china.conf"}
local geoip_url = uci:get(name, "@global_rules[0]", "geoip_url") or "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat"
local geosite_url = uci:get(name, "@global_rules[0]", "geosite_url") or "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
local asset_location = uci:get(name, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
local use_nft = uci:get(name, "@global_forwarding[0]", "use_nft") or "0"
local geo2rule = uci:get(name, "@global_rules[0]", "geo2rule") or "0"
local geoip_update_ok, geosite_update_ok = false, false
asset_location = asset_location:match("/$") and asset_location or (asset_location .. "/")

if arg3 == "cron" then
	arg2 = nil
end

local log = function(...)
	if arg1 then
		if arg1 == "log" then
			api.log(...)
		elseif arg1 == "print" then
			local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
			print(result)
		end
	end
end

--gen cache for nftset from file
local function gen_cache(set_name, ip_type, input_file, output_file)
	local tmp_set_name = set_name .. "_tmp_" .. os.time()
	local f_in = io.open(input_file, "r")
	if not f_in then return false end
	local nft_pipe = io.popen("nft -f -", "w")
	if not nft_pipe then 
		f_in:close()
		return false 
	end
	nft_pipe:write('#!/usr/sbin/nft -f\n')
	nft_pipe:write(string.format('add table %s\n', nftable_name))
	nft_pipe:write(string.format('add set %s %s { type %s; flags interval, timeout; timeout 2d; gc-interval 1h; auto-merge; }\n', nftable_name, tmp_set_name, ip_type))
	nft_pipe:write(string.format('add element %s %s { ', nftable_name, tmp_set_name))
	local count = 0
	local batch_size = 500
	for line in f_in:lines() do
		local ip = line:match("^%s*(.-)%s*$")
		if ip and ip ~= "" then
			nft_pipe:write(ip, "timeout 365d, ")
			count = count + 1
			if count % batch_size == 0 then
				nft_pipe:write("}\n")
				nft_pipe:write(string.format('add element %s %s { ', nftable_name, tmp_set_name))
			end
		end
	end
	nft_pipe:write("}\n")
	f_in:close()

	local success = nft_pipe:close()
	if not (success == true or success == 0) then
		os.execute(string.format('nft delete set %s %s 2>/dev/null', nftable_name, tmp_set_name))
		return false
	end
	os.execute(string.format('nft list set %s %s | sed "s/%s/%s/g" > %s', nftable_name, tmp_set_name, tmp_set_name, set_name, output_file))
	os.execute(string.format('nft delete set %s %s 2>/dev/null', nftable_name, tmp_set_name))
end

-- curl
local function curl(url, file)
	local http_code = 0
	local header_str = ""
	local args = {
		"-skL",
		"--retry 3",
		"--connect-timeout 3",
		"--max-time 300",
		"--speed-limit 51200 --speed-time 15",
		'-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"',
		"--dump-header -",
		"-w '\\n%{http_code}'"
	}
	if file then
		args[#args + 1] = "-o " .. file
	end
	local return_code, result = api.curl_auto(url, nil, args)
	if result and result ~= "" then
		local body, code = result:match("^(.-)%s*([0-9]+)$")
		if code then
			http_code = tonumber(code) or 0
			header_str = body
		else
			http_code = tonumber(result:match("(%d+)%s*$")) or 0
		end
	end
	if header_str ~= "" then
		header_str = header_str:gsub("\r", "")
	end
	return http_code, header_str
end

--check excluded domain
local excluded_map = {}
for _, d in ipairs(excluded_domain) do
	excluded_map[d] = true
end
local function check_excluded_domain(value)
	if not value or value == "" then return false end
	value = value:lower()
	local eq_pos = value:find("=", 1, true)
	if eq_pos then
		value = value:sub(eq_pos + 1)
	end
	if value:sub(1,1) == "/" then
		value = value:sub(2)
	end
	local slash_pos = value:find("/", 1, true)
	local colon_pos = value:find(":", 1, true)
	local cut_pos
	if slash_pos and colon_pos then
		cut_pos = (slash_pos < colon_pos) and slash_pos or colon_pos
	else
		cut_pos = slash_pos or colon_pos
	end
	if cut_pos then
		value = value:sub(1, cut_pos - 1)
	end
	value = value:gsub("^%.*", ""):gsub("%.*$", "")
	while value do
		if excluded_map[value] then
			return true
		end
		local dot_pos = value:find(".", 1, true)
		if not dot_pos then
			break
		end
		value = value:sub(dot_pos + 1)
	end
	return false
end

-- 替代 string.find 查找 "^[#!\\[@]+"
local function is_comment_line(s)
	if not s or s == "" then return false end
	local b = s:byte(1)
	-- '#' = 35, '!' = 33, '\' = 92, '[' = 91, '@' = 64
	if b == 35 or b == 33 or b == 92 or b == 91 or b == 64 then
		return true
	end
	return false
end

-- IPv4 检测，替代 string.find "^%d+%.%d+%.%d+%.%d+"
-- IPv4 cidr检测，替代 string.find "^%d+%.%d+%.%d+%.%d+[%/][%d]+$"
local function is_ipv4(s, check_cidr)
	local dot = 0
	local seg_start = 1
	local len = #s
	local mask_start = nil
	local i = 1
	while i <= len do
		local b = s:byte(i)
		if b >= 48 and b <= 57 then
			-- 数字，继续
		elseif b == 46 then  -- "."
			dot = dot + 1
			if dot > 3 or i == seg_start then return false end
			local seg = tonumber(s:sub(seg_start, i - 1))
			if not seg or seg > 255 then return false end
			seg_start = i + 1
		elseif b == 47 then  -- "/"
			if not check_cidr then return false end
			if dot ~= 3 or i == seg_start then return false end
			local seg = tonumber(s:sub(seg_start, i - 1))
			if not seg or seg > 255 then return false end
			mask_start = i + 1
			break
		else
			return false
		end
		i = i + 1
	end
	-- 如果没有 CIDR，则检查最后一段即可
	if not check_cidr or not mask_start then
		if dot ~= 3 or seg_start > len then return false end
		local seg = tonumber(s:sub(seg_start))
		return seg and seg <= 255 or false
	end
	-- CIDR 掩码检查
	if mask_start > len then return false end
	local mask = tonumber(s:sub(mask_start))
	return mask and mask >= 0 and mask <= 32 or false
end

local function is_ipv4_cidr(s)
	return is_ipv4(s, true)
end

local function is_ipv6(s, check_cidr)
	local first = s:byte(1)
	local last = s:byte(#s)
	if first == 91 and last == 93 then  -- "[" and "]"
		s = s:sub(2, -2)
	end
	local len = #s
	local i = 1
	local seg_len = 0
	local segs = 0
	local saw_dc = false  -- 是否出现 "::"
	local b
	while i <= len do
		b = s:byte(i)
		-- CIDR 部分
		if b == 47 then  -- '/'
			if not check_cidr then
				return false
			end
			-- 处理 "/" 之前的段
			if seg_len > 0 then segs = segs + 1 end
			if (not saw_dc and segs ~= 8) or (saw_dc and segs > 8) then return false end
			-- 解析掩码
			i = i + 1
			if i > len then return false end
			local mask = 0
			while i <= len do
				b = s:byte(i)
				if b < 48 or b > 57 then return false end
				mask = mask * 10 + (b - 48)
				if mask > 128 then return false end
				i = i + 1
			end
			-- CIDR 解析成功
			return true
		end
		-- 冒号处理（: 或 ::）
		if b == 58 then
			local nextb = (i+1 <= len) and s:byte(i+1) or 0
			-- "::"
			if nextb == 58 then
				if saw_dc then return false end
				saw_dc = true
				if seg_len > 0 then segs = segs + 1 end
				seg_len = 0
				i = i + 2
			else
				-- 普通 ":"
				if seg_len == 0 then return false end
				segs = segs + 1
				seg_len = 0
				i = i + 1
			end
		else
			-- hex 数字
			local is_hex =
				(b >= 48 and b <= 57) or   -- 0-9
				(b >= 65 and b <= 70) or   -- A-F
				(b >= 97 and b <= 102)     -- a-f
			if not is_hex then return false end
			seg_len = seg_len + 1
			if seg_len > 4 then return false end
			i = i + 1
		end
	end
	if seg_len > 0 then segs = segs + 1 end
	if not saw_dc then return segs == 8 end
	return segs <= 8
end

-- IPv6 cidr检测，替代 string.find ":-[%x]+%:+[%x]-[%/][%d]+$"
local function is_ipv6_cidr(s)
	return is_ipv6(s, true)
end

-- 检测是否含有冒号，替代 string.find(line, ":")
local function has_colon(s)
	for i = 1, #s do
		if s:byte(i) == 58 then  -- ':'
			return true
		end
	end
	return false
end

-- 域名提取，替代 string.match "([%w%-]+%.[%w%.%-]+)[%/%*]*"
local function extract_domain(s)
	if not s or s == "" then return nil end
	local len = #s
	local start = nil
	local last_dot = nil
	for i = 1, len do
		local b = s:byte(i)
		-- 允许的域名字符：a-zA-Z0-9.- 
		if (b >= 48 and b <= 57) or (b >= 65 and b <= 90) or (b >= 97 and b <= 122) or b == 45 or b == 46 then
			if not start then start = i end
			if b == 46 then last_dot = i end
		else
			if start then
				if last_dot and last_dot > start then
					local domain = s:sub(start, i - 1)
					while domain:byte(1) == 46 do
						domain = domain:sub(2)
					end
					return domain
				else
					start = nil
					last_dot = nil
				end
			end
		end
	end
	if start and last_dot and last_dot > start then
		local domain = s:sub(start)
		while domain:byte(1) == 46 do
			domain = domain:sub(2)
		end
		return domain
	end
	return nil
end

local function non_file_check(file_path, header_content)
	local remote_file_size = nil
	local local_file_size = tonumber(fs.stat(file_path, "size")) or 0
	if local_file_size == 0 then
		log("下载文件为空或读取出错。")
		return true
	end
	if header_content and header_content ~= "" then
		for size in header_content:gmatch("[Cc]ontent%-[Ll]ength:%s*(%d+)") do
			local s = tonumber(size)
			if s and s > 0 then
				remote_file_size = s
			end
		end
	end
	if remote_file_size and remote_file_size ~= local_file_size then
		log(string.format("校验出错：远程 %dB, 下载 %dB", remote_file_size, local_file_size))
		return true
	end
	return false
end

local function GeoToRule(rule_name, rule_type, out_path)
	if not api.is_finded("geoview") then
		log(rule_name .. "生成失败，缺少 geoview 组件。")
		return false;
	end
	local geosite_path = asset_location .. "geosite.dat"
	local geoip_path = asset_location .. "geoip.dat"
	local file_path = (rule_type == "domain") and geosite_path or geoip_path
	local geo_arg
	if rule_type == "domain" then
		if rule_name == "gfwlist" then
			geo_arg = "-type geosite -list gfw"
		else
			geo_arg = "-type geosite -list cn"
		end
	elseif rule_type == "ip4" then
		geo_arg = "-type geoip -list cn -ipv6=false"
	elseif rule_type == "ip6" then
		geo_arg = "-type geoip -list cn -ipv4=false"
	end
	local cmd = string.format("geoview -input '%s' %s -lowmem=true -output '%s'", file_path, geo_arg, out_path)
	sys.exec(cmd)
	return true;
end

--fetch rule
local function fetch_rule(rule_name,rule_type,url,exclude_domain, max_retries)
	local sret = 200
	local max_attempts = max_retries or 2
	local rule_dataset = {}
	local file_tmp = "/tmp/" .. rule_name .. "_tmp"
	local rule_final_path = rule_path .. "/" .. rule_name
	if geo2rule == "1" then
		url = {"geo2rule"}
		log(rule_name.. " 开始生成...")
	else
		log(rule_name.. " 开始更新...")
	end

	for k, v in ipairs(url) do
        local current_file = "/tmp/" .. rule_name .. "_dl" .. k
        local success = false

        if v ~= "geo2rule" then
			for i = 1, max_attempts do
				local http_code, header = curl(v, current_file)
				if http_code == 200 and not non_file_check(current_file, header) then
					success = true
					break
				end
				os.remove(current_file)
				log(string.format("%s 第%d条规则下载失败 (HTTP:%s)，正在进行第%d次尝试...", rule_name, k, tostring(http_code), i))
			end
		else
			if not GeoToRule(rule_name, rule_type, current_file) then return 1 end
			success = true
		end

		if success then
			local f = io.open(current_file, "r")
			if f then
				if rule_name == "gfwlist" and geo2rule == "0" then
					local decode = api.base64Decode(f:read("*all"))
					for line in string.gmatch(decode, "[^\r\n]+") do
						line = line:gsub("full:", "")
						if not (is_comment_line(line) or is_ipv4(line) or has_colon(line) or (exclude_domain and check_excluded_domain(line))) then
							local match = extract_domain(line)
							if match then
								rule_dataset[match] = true
							end
						end
					end
				else
					for line in f:lines() do
						if rule_type == "domain" then
							line = line:gsub("full:", "")
							if not (is_comment_line(line) or is_ipv4(line) or has_colon(line) or (exclude_domain and check_excluded_domain(line))) then
								local match = extract_domain(line)
								if match then
									rule_dataset[match] = true
								end
							end
						elseif rule_type == "ip4" then
							local function is_0dot(s) -- "^0%..*"
								return s and s:byte(1)==48 and s:byte(2)==46
							end
							if is_ipv4_cidr(line) and not is_0dot(line) then
								rule_dataset[line] = true
							end
						elseif rule_type == "ip6" then
							local function is_double_colon_cidr(s) -- "^::(/%d+)?$"
							if not s or s:byte(1)~=58 or s:byte(2)~=58 then return false end
								local l = #s
								if l==2 then return true end
								if l==3 or s:byte(3)~=47 then return false end
								for i=4,l do
									local b=s:byte(i)
									if b<48 or b>57 then return false end
								end
								return true
							end
							if is_ipv6_cidr(line) and not is_double_colon_cidr(line) then
								rule_dataset[line] = true
							end
						end
					end
				end
				f:close()
			end
		else
			sret = 0
			log(string.format("%s 第%d条规则: %s 下载失败！", rule_name, k, v))
		end
		os.remove(current_file)
	end

	if sret == 200 then
		local result_list = {}
		for line, _ in pairs(rule_dataset) do table.insert(result_list, line) end
		table.sort(result_list)

		local out = io.open(file_tmp, "w")
		if out then
			for _, line in ipairs(result_list) do out:write(line .. "\n") end
			out:close()
		end

		local old_md5 = sys.exec(string.format("md5sum %s 2>/dev/null | awk '{print $1}'", rule_final_path)):gsub("\n", "")
		local new_md5 = sys.exec(string.format("md5sum %s 2>/dev/null | awk '{print $1}'", file_tmp)):gsub("\n", "")

		if old_md5 ~= new_md5 then
			if use_nft == "1" and (rule_type == "ip4" or rule_type == "ip6") then
				local nft_file = file_tmp .. ".nft"
				local set_name = "passwall_" .. rule_name
				if rule_name == "chnroute" then set_name = "passwall_chn"
				elseif rule_name == "chnroute6" then set_name = "passwall_chn6" end
                
				local addr_type = (rule_type == "ip4") and "ipv4_addr" or "ipv6_addr"
				gen_cache(set_name, addr_type, file_tmp, nft_file)
				os.execute(string.format("mv -f %s %s.nft", nft_file, rule_final_path))
			end
			os.execute(string.format("mv -f %s %s", file_tmp, rule_final_path))
			reboot = 1
			log(string.format("%s 更新成功，总规则数 %d 条。", rule_name, #result_list))
		else
			log(rule_name .. " 版本一致，无需更新。")
			os.remove(file_tmp)
		end
	else
		log(rule_name .. " 更新失败（部分或全部资源无法下载）。")
		os.remove(file_tmp)
	end
	return 0
end

local function fetch_geofile(geo_name, geo_type, url)
	local tmp_path = "/tmp/" .. geo_name
	local asset_path = asset_location .. geo_name
	local down_filename = url:match("^.*/([^/?#]+)")
	local sha_url = url:gsub(down_filename, down_filename .. ".sha256sum")
	local sha_path = tmp_path .. ".sha256sum"

	local function verify_sha256(sha_file)
		return sys.call("sha256sum -c " .. sha_file .. " > /dev/null 2>&1") == 0
	end

	local sha_verify, _ = curl(sha_url, sha_path) == 200
	if sha_verify then
		local f = io.open(sha_path, "r")
		if f then
			local content = f:read("*l")
			f:close()
			if content then
				content = content:gsub(down_filename, tmp_path)
				f = io.open(sha_path, "w")
				if f then
					f:write(content)
					f:close()
				end
			end
		end
		if fs.access(asset_path) then
			sys.call(string.format("cp -f %s %s", asset_path, tmp_path))
			if verify_sha256(sha_path) then
				log(geo_type .. " 版本一致，无需更新。")
				return 0
			end
		end
	end

	local sret_tmp, header = curl(url, tmp_path)
	if sret_tmp == 200 and non_file_check(tmp_path, header) then
		log(geo_type .. " 下载文件过程出错，尝试重新下载。")
		os.remove(tmp_path)
		sret_tmp, header= curl(url, tmp_path)
		if sret_tmp == 200 and non_file_check(tmp_path, header) then
			sret_tmp = 0
			log(geo_type .. " 下载文件过程出错，请检查网络或下载链接后重试！")
		end
	end
	if sret_tmp == 200 then
		if sha_verify then
			if verify_sha256(sha_path) then
				sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, tmp_path, asset_path))
				reboot = 1
				log(geo_type .. " 更新成功。")
				if geo_type == "geoip" then
					geoip_update_ok = true
				else
					geosite_update_ok = true
				end
			else
				log(geo_type .. " 更新失败，请稍后重试或更换更新URL。")
				return 1
			end
		else
			if fs.access(asset_path) and sys.call(string.format("cmp -s %s %s", tmp_path, asset_path)) == 0 then
				log(geo_type .. " 版本一致，无需更新。")
				return 0
			end
			sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, tmp_path, asset_path))
			reboot = 1
			log(geo_type .. " 更新成功。")
			if geo_type == "geoip" then
				geoip_update_ok = true
			else
				geosite_update_ok = true
			end
		end
	else
		log(geo_type .. " 更新失败，请稍后重试或更换更新URL。")
		return 1
	end
	return 0
end

local function fetch_gfwlist()
	fetch_rule("gfwlist","domain",gfwlist_url,true)
end

local function fetch_chnroute()
	fetch_rule("chnroute","ip4",chnroute_url,false)
end

local function fetch_chnroute6()
	fetch_rule("chnroute6","ip6",chnroute6_url,false)
end

local function fetch_chnlist()
	fetch_rule("chnlist","domain",chnlist_url,false)
end

local function fetch_geoip()
	fetch_geofile("geoip.dat","geoip",geoip_url)
end

local function fetch_geosite()
	fetch_geofile("geosite.dat","geosite",geosite_url)
end

if arg2 then
	string.gsub(arg2, '[^' .. "," .. ']+', function(w)
		if w == "gfwlist" then
			gfwlist_update = "1"
		end
		if w == "chnroute" then
			chnroute_update = "1"
		end
		if w == "chnroute6" then
			chnroute6_update = "1"
		end
		if w == "chnlist" then
			chnlist_update = "1"
		end
		if w == "geoip" then
			geoip_update = "1"
		end
		if w == "geosite" then
			geosite_update = "1"
		end
	end)
else
	gfwlist_update = uci:get(name, "@global_rules[0]", "gfwlist_update") or "1"
	chnroute_update = uci:get(name, "@global_rules[0]", "chnroute_update") or "1"
	chnroute6_update = uci:get(name, "@global_rules[0]", "chnroute6_update") or "1"
	chnlist_update = uci:get(name, "@global_rules[0]", "chnlist_update") or "1"
	geoip_update = uci:get(name, "@global_rules[0]", "geoip_update") or "1"
	geosite_update = uci:get(name, "@global_rules[0]", "geosite_update") or "1"
end
if gfwlist_update == "0" and chnroute_update == "0" and chnroute6_update == "0" and chnlist_update == "0" and geoip_update == "0" and geosite_update == "0" then
	os.exit(0)
end

log("开始更新规则...")
local function safe_call(func, err_msg)
	xpcall(func, function(e)
		log(e)
		log(debug.traceback())
		log(err_msg)
	end)
end

local function remove_tmp_geofile(name)
	os.remove("/tmp/" .. name .. ".dat")
	os.remove("/tmp/" .. name .. ".dat.sha256sum")
end

if geo2rule == "1" then
	if geoip_update == "1" then
		log("geoip 开始更新...")
		safe_call(fetch_geoip, "更新geoip发生错误...")
		remove_tmp_geofile("geoip")
	end

	if geosite_update == "1" then
		log("geosite 开始更新...")
		safe_call(fetch_geosite, "更新geosite发生错误...")
		remove_tmp_geofile("geosite")
	end

	-- 如果是手动更新(arg2存在)始终生成规则
	local force_generate = (arg2 ~= nil)

	if geoip_update_ok or force_generate then
		if fs.access(asset_location .. "geoip.dat") then
			safe_call(fetch_chnroute, "生成chnroute发生错误...")
			safe_call(fetch_chnroute6, "生成chnroute6发生错误...")
		else
			log("geoip.dat 文件不存在,跳过规则生成。")
		end
	end

	if geosite_update_ok or force_generate then
		if fs.access(asset_location .. "geosite.dat") then
			safe_call(fetch_gfwlist, "生成gfwlist发生错误...")
			safe_call(fetch_chnlist, "生成chnlist发生错误...")
		else
			log("geosite.dat 文件不存在,跳过规则生成。")
		end
	end
else
	if gfwlist_update == "1" then
		safe_call(fetch_gfwlist, "更新gfwlist发生错误...")
	end

	if chnroute_update == "1" then
		safe_call(fetch_chnroute, "更新chnroute发生错误...")
	end

	if chnroute6_update == "1" then
		safe_call(fetch_chnroute6, "更新chnroute6发生错误...")
	end

	if chnlist_update == "1" then
		safe_call(fetch_chnlist, "更新chnlist发生错误...")
	end

	if geoip_update == "1" then
		log("geoip 开始更新...")
		safe_call(fetch_geoip, "更新geoip发生错误...")
		remove_tmp_geofile("geoip")
	end

	if geosite_update == "1" then
		log("geosite 开始更新...")
		safe_call(fetch_geosite, "更新geosite发生错误...")
		remove_tmp_geofile("geosite")
	end
end

uci:set(name, "@global_rules[0]", "gfwlist_update", gfwlist_update)
uci:set(name, "@global_rules[0]", "chnroute_update", chnroute_update)
uci:set(name, "@global_rules[0]", "chnroute6_update", chnroute6_update)
uci:set(name, "@global_rules[0]", "chnlist_update", chnlist_update)
uci:set(name, "@global_rules[0]", "geoip_update", geoip_update)
uci:set(name, "@global_rules[0]", "geosite_update", geosite_update)
api.uci_save(uci, name, true)

if reboot == 1 then
	if arg3 == "cron" then
		if not fs.access("/var/lock/" .. name .. ".lock") then
			sys.call("touch /tmp/lock/" .. name .. "_cron.lock")
		end
	end

	log("重启服务，应用新的规则。")
	uci:set(name, "@global[0]", "flush_set", "1")
	api.uci_save(uci, name, true, true)
end
log("规则更新完毕...\n")
