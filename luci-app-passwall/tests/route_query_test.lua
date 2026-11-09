-- route_query_test.lua - 走向查询 (route query) regression suite.
--
-- Runs engine pure-logic, backend-cache and end-to-end flow tests in a plain
-- Lua 5.1 environment (no LuCI required).
--
--   lua -e 'dofile("luci-app-passwall/tests/route_query_test.lua")'
--   -- or:
--   lua luci-app-passwall/tests/route_query_test.lua
--
-- Returns nonzero exit code if any suite fails.

local here = (arg[0]:match("^(.*)[/\\]") or ".")
	.. (arg[0]:match("[/\\]") and "/" or "/")

local suites = {
	here .. "route_query_engine_test.lua",
	here .. "route_query_backend_test.lua",
	here .. "route_query_flow_test.lua",
}

local total_pass, total_fail = 0, 0
local failed_suite = nil

for _, f in ipairs(suites) do
	local chunk, err = loadfile(f)
	if not chunk then
		print("FAIL cannot load " .. f .. ": " .. tostring(err))
		total_fail = total_fail + 1
		failed_suite = f
	else
		local ok, res = pcall(chunk)
		if not ok then
			print("FAIL " .. f .. " errored: " .. tostring(res))
			total_fail = total_fail + 1
			failed_suite = f
		elseif type(res) == "table" then
			total_pass = total_pass + (res.pass or 0)
			total_fail = total_fail + (res.fail or 0)
			if res.fail and res.fail > 0 and not failed_suite then
				failed_suite = f
			end
		end
	end
end

print(string.format("route-query-test: %d passed, %d failed across %d suites", total_pass, total_fail, #suites))
if failed_suite then
	print("failing suite: " .. failed_suite)
	os.exit(1)
end
os.exit(0)