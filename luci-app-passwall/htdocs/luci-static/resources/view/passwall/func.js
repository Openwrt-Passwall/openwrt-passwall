function arraysEqual(a, b) {
	if (a === b) return true;
	if (a == null || b == null) return false;
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

function isBase64(str) {
	const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
	return base64Regex.test(str);
}

function decodeIfBase64(str) {
	try {
		let s = str.replace(/-/g, '+').replace(/_/g, '/');
		while (s.length % 4) s += '=';
		const decoded = decodeURIComponent(
			atob(s).split('').map(c =>
				'%' + c.charCodeAt(0).toString(16).padStart(2, '0')
			).join('')
		);
		if (btoa(unescape(encodeURIComponent(decoded))).replace(/=+$/, '') === s.replace(/=+$/, '')) {
			return decoded;
		}
	} catch (e) {}
	return str;
}

function isUUID(str) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(str);
}

function waitForElement(selector, callback) {
	const el = document.querySelector(selector);
	if (el) return callback(el);
	const observer = new MutationObserver(() => {
		const el = document.querySelector(selector);
		if (el) {
			observer.disconnect();
			callback(el);
		}
	});
	observer.observe(document.body, { childList: true, subtree: true });
}

function waitForElementId(id, callback) {
	waitForElement("#" + CSS.escape(id), callback);
	//waitForElement('[id="' + id + '"]', callback);
}

function get_current_url() {
	return window.location.origin + window.location.pathname;
}

function getOption(config, section, opt) {
	let obj;
	const id = `cbid.${config}.${section}.${opt}`;
	obj = document.getElementsByName(id)[0] || document.getElementById(id);
	if (obj) {
		const combobox = document.getElementById('cbi.combobox.' + id);
		if (combobox) {
			obj.combobox = combobox;
		}
		const div = document.getElementById(id);
		if (div && div.getElementsByTagName("li").length > 0) {
			obj = div;
		}
		return obj;
	} else {
		return null;
	}
}
