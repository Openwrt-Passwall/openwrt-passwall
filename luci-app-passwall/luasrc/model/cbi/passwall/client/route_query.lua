local api = require "luci.passwall.api"

api.set_default_cbi()

m = Map()

s = m:section(NamedSection, "@global[0]", "global", translate("Route Query"))

o = s:option(DummyValue, "_route_query", "　")
o.rawhtml = true
o.template = m:template_path("/route_query/query")

return api.return_map(m)