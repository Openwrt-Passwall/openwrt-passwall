local api = require "luci.passwall.api"
api.set_default_cbi()

m = Map()

-- [[ Other Settings ]]--
s = m:section(NamedSection, "@global_other[0]", "global_other")

o = s:option(ListValue, "auto_detection_time", translate("Automatic detection delay"))
o:value("0", translate("Close"))
o:value("icmp", "Ping")
o:value("tcping", "TCP Ping")

o = s:option(Flag, "show_node_info", translate("Show server address and port"))
o.default = "0"

o = s:option(Value, "url_test_url", translate("URL Test Address"))
o:value("https://cp.cloudflare.com/", "Cloudflare")
o:value("https://www.gstatic.com/generate_204", "Gstatic")
o:value("https://www.google.com/generate_204", "Google")
o:value("https://www.youtube.com/generate_204", "YouTube")
o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
o:value("https://wifi.vivo.com.cn/generate_204", "VIVO (CN)")
o.default = o.keylist[3]

if true then
    m:appendTemplate("/node_list/node_list")

    if luci.http.formvalue("cbi.submit") == "1" then
        local group_order = {}
        group_order = luci.http.formvaluetable("group.order")
        if group_order then
            for k, v in pairs(group_order) do
                if v and v~= "" then
                    local new_order = {}
                    string.gsub(v, "[^" .. " " .. "]+", function(w)
                        new_order[#new_order + 1] = w
                    end)
                    for idx, name in ipairs(new_order) do
                        m.uci:reorder(m.config, name, idx - 1)
                    end
                end
            end
        end
    end
end

return api.return_map(m)
