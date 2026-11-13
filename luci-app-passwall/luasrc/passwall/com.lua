local _M = {}

local function gh_release_url(self)
	--return "https://api.github.com/repos/" .. self.repo .. "/releases/latest"
	return "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/releases/download/api-cache/" .. string.lower(self.name) .. "-release-api.json"
end

local function gh_pre_release_url(self)
	--return "https://api.github.com/repos/" .. self.repo .. "/releases?per_page=1"
	return "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/releases/download/api-cache/" .. string.lower(self.name) .. "-pre-release-api.json"
end

-- 排序顺序定义
_M.order = {
	"geoview",
	"chinadns-ng",
	"xray",
	"zray",
	"sing-box",
	"hysteria"
}

-- PassWall uses the same cached GitHub Release API, but is not listed as a
-- downloadable component because its LuCI package update flow is handled separately.
_M.passwall = {
	name = "PassWall",
	get_url = gh_release_url
}

_M.hysteria = {
	name = "Hysteria",
	repo = "HyNetwork/hysteria",
	get_url = gh_release_url,
	cmd_version = "version | awk '/^Version:/ {print $2}'",
	remote_version_str_replace = "app/",
	zipped = false,
	default_path = "/usr/bin/hysteria",
	match_fmt_str = "linux%%-%s$",
	file_tree = {
		armv6 = "arm",
		armv7 = "arm",
		mipsel = "mipsle"
	}
}

_M["sing-box"] = {
	name = "Sing-Box",
	repo = "SagerNet/sing-box",
	get_url = gh_release_url,
	cmd_version = "version",
	zipped = true,
	zipped_suffix = "tar.gz",
	default_path = "/usr/bin/sing-box",
	match_fmt_str = "linux%%-%s",
	file_tree = {
		x86_64 = "amd64%-musl",
		x86     = "386%-musl",
		aarch64 = "arm64%-musl",
		rockchip = "arm64%-musl",
		mips    = "mips%-softfloat",
		mips64  = "mips64%-softfloat",
		mipsel  = "mipsle%-softfloat%-musl",
		mips64el = "mips64le%-softfloat",
		armv7   = "armv7%-musl",
		armv8   = "arm64%-musl",
		riscv64 = "riscv64%-musl"
	}
}

_M.zray = {
	name = "Zray",
	repo = "yunnysunny/zray",
	get_url = function(self)
		return "https://api.github.com/repos/" .. self.repo .. "/releases/latest"
	end,
	-- Zray treats its first argument as a configuration, not --version.
	cmd_version = function(file)
		return require("luci.passwall.util_zray_update").version(file)
	end,
	zipped = false,
	default_path = "/usr/bin/zray",
	match_fmt_str = "^zray%%-%s$",
	strict_arch = true,
	file_tree = {
		aarch64 = "aarch64", rockchip = "aarch64", armv8 = "aarch64",
		x86_64 = "x86_64", armv7 = "arm%-v7",
		mips = "mips%-softfloat", mipsel = "mipsel%-softfloat"
	}
}

_M.xray = {
	name = "Xray",
	repo = "XTLS/Xray-core",
	get_url = gh_pre_release_url,
	cmd_version = "version | awk '{print $2}' | sed -n 1P",
	zipped = true,
	default_path = "/usr/bin/xray",
	match_fmt_str = "linux%%-%s",
	file_tree = {
		x86_64 = "64",
		x86    = "32",
		mips   = "mips32",
		mipsel = "mips32le",
		mips64el = "mips64le"
	}
}

_M["chinadns-ng"] = {
	name = "ChinaDNS-NG",
	repo = "zfl9/chinadns-ng",
	get_url = gh_release_url,
	cmd_version = "-V | awk '{print $2}'",
	zipped = false,
	default_path = "/usr/bin/chinadns-ng",
	match_fmt_str = "%s",
	file_tree = {
		x86_64  = "wolfssl@x86_64.*x86_64@",
		x86     = "wolfssl@i386.*i686",
		mips    = "wolfssl@mips%-.*mips32%+soft_float@",
		mips64  = "wolfssl@mips64%-.*mips64%+soft_float@",
		mipsel  = "wolfssl@mipsel.*mips32%+soft_float@",
		mips64el = "wolfssl@mips64el%-.*mips64%+soft_float@",
		aarch64 = "wolfssl_noasm@aarch64.*v8a",
		rockchip = "wolfssl@aarch64.*v8a",
		armv5   = "wolfssl@arm.*v5te",
		armv6   = "wolfssl@arm.*v6t2",
		armv7   = "wolfssl@arm.*eabihf.*v7a",
		armv8   = "wolfssl_noasm@aarch64.*v8a",
		riscv64 = "wolfssl@riscv64.*"
	}
}

_M.geoview = {
	name = "Geoview",
	repo = "snowie2000/geoview",
	get_url = gh_release_url,
	cmd_version = '-version 2>/dev/null | awk \'NR==1 && $1=="Geoview" {print $2}\'',
	zipped = false,
	default_path = "/usr/bin/geoview",
	match_fmt_str = "linux%%-%s",
	file_tree = {
		mipsel = "mipsle",
		mips64el = "mips64le"
	}
}

return _M
