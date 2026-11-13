-- Zray currently has no version command; read its bounded startup banner.
module("luci.passwall.util_zray_update", package.seeall)
local api = require "luci.passwall.api"

function version(file)
	local code, output = api.exec_call("/usr/share/passwall/zray_check.sh " .. api.util.shellquote(file))
	if code == 0 then
		-- exec_call also captures stderr; shell diagnostics are not versions.
		for line in output:gmatch("[^\r\n]+") do
			local value = line:match("^([0-9][%w%.%+_%-]*)%s*$")
			if value then return value end
		end
	end
	return ""
end
