// Run from luci-app-passwall: node tests/zray_links.cjs
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let source = fs.readFileSync('luasrc/view/passwall/node_config/link_share_man.htm', 'utf8');
source = source.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
const values = {
  config: 'passwall', 'self.option': 'passwall', 'self.value': 'test',
  'current_node.type or ""': 'Zray', has_zray: '/usr/bin/zray', vless_type: 'zray'
};
source = source.replace(/<%=([\s\S]*?)%>/g, (_, key) => values[key] || '')
  .replace(/<%:([\s\S]*?)%>/g, '$1');
const fields = {};
for (const key of ['type', 'remarks', 'protocol', 'uuid', 'address', 'port', 'flow',
  'transport', 'tls_serverName', 'reality_publicKey', 'reality_shortId', 'ws_host', 'ws_path']) {
  fields[key === 'type' || key === 'remarks' ? key : `zray_${key}`] = {
    type: 'text', value: '', getElementsByTagName: () => [],
    focus() {}, blur() {}, dispatchEvent() {}
  };
}
for (const key of ['tls', 'reality', 'tls_allowInsecure']) {
  fields[`zray_${key}`] = { type: 'checkbox', checked: false, dispatchEvent() {} };
}
fields.type.value = 'Zray';
const status = {};
const byId = id => id === 'passwall-status' ? status : fields[id.replace('cbid.passwall.test.', '')];
const context = {
  URL, console,
  getOption: (_, __, key) => fields[key],
  document: {
    getElementById: byId, getElementsByName: id => byId(id) ? [byId(id)] : [],
    getElementsByClassName: () => [], querySelectorAll: () => []
  },
  sessionStorage: {setItem() {}, removeItem() {}},
  alert: message => { throw new Error(message); }
};
vm.createContext(context);
vm.runInContext(source, context);
const prefix = 'vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?';
const reality = 'security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=example.com&flow=xtls-rprx-vision';
assert.equal(context.fromUrl(prefix + reality + '#test'), true);
assert.equal(fields.zray_transport.value, 'tcp');
assert.equal(fields.zray_tls.checked, true);
assert.equal(fields.zray_reality.checked, true);
let exported = context.buildUrl(null, 'passwall', 'test');
assert.match(exported, /^vless:\/\//);
assert.match(exported, /security=reality/);
assert.match(exported, /flow=xtls-rprx-vision/);
assert.equal(context.fromUrl(prefix + reality + '&type=raw'), true);
assert.equal(fields.zray_transport.value, 'tcp');
for (const suffix of ['&type=xhttp', '&type=grpc', '&type=ws', '&fp=firefox', '&pqv=unsupported']) {
  assert.equal(context.fromUrl(prefix + reality + suffix), false, suffix);
}
assert.equal(context.fromUrl(prefix + 'security=tls&type=ws&allowInsecure=1&path=%2Fproxy'), true);
assert.equal(fields.zray_flow.value, 'none');
assert.equal(fields.zray_tls_allowInsecure.checked, true);
assert.equal(fields.zray_ws_path.value, '/proxy');
exported = context.buildUrl(null, 'passwall', 'test');
assert.match(exported, /security=tls/);
assert.match(exported, /allowinsecure=1/);
assert.equal(context.fromUrl(prefix + 'security=tls&type=ws'), false);
console.log('Zray share-link import/export checks passed');
