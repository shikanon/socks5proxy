#!/usr/bin/env node
// Verify the actual generated PAC, including direct priority and suffix boundaries.
const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const root = path.join(__dirname, '..');
const base = path.join(root, 'examples/community-pac');
const config = JSON.parse(fs.readFileSync(path.join(base, 'domains.json'), 'utf8'));
const sandbox = {shExpMatch: (str, pattern) => {
  const escaped = pattern.split('').map(c => c === '*' ? '.*' : c === '?' ? '.' :
    /[\\^$+?.()|[\]{}]/.test(c) ? '\\' + c : c).join('');
  return new RegExp('^' + escaped + '$').test(str);
}};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[2] || path.join(base, 'proxy.pac'), 'utf8'), sandbox, {timeout: 3000});
const directive = 'PROXY ' + config.proxy;
let count = 0;
function check(host, expected, url) {
  const got = sandbox.FindProxyForURL(url || 'https://' + host + '/', host);
  assert.strictEqual(got, expected, host); count++;
}
const suffixes = Object.values(config.proxy_groups).flat();
for (const suffix of suffixes) {
  for (const host of [suffix, 'api.' + suffix, suffix.toUpperCase(), suffix + '.']) check(host, directive);
}
for (const host of config.proxy_exact_hosts) check(host, directive);
for (const suffix of config.direct_suffixes) {
  check(suffix, 'DIRECT'); check('api.' + suffix, 'DIRECT');
  check(suffix, 'DIRECT', 'https://' + suffix + '/?next=https://chatgpt.com/');
}
for (const host of ['localhost', '127.0.0.1', '192.168.31.1', '::1', '[::1]', 'printer.local', 'www.baidu.com', 'example.com']) check(host, 'DIRECT');
check('www.google.com', directive);
check('x.doubao.com.google.com', directive);
check('auth.openai.com', directive);
check('auth0.openai.com', directive);
check('raw.githubusercontent.com', directive);
check('release-assets.githubusercontent.com', directive);
check('localhost', 'DIRECT', 'http://localhost:1455/auth/callback');
const community = sandbox.CommunityFindProxyForURL;
sandbox.CommunityFindProxyForURL = () => 'FALLBACK';
for (const suffix of suffixes) {
  for (const host of ['not' + suffix, suffix + '.example.com', 'x.' + suffix + '.example.com']) check(host, 'FALLBACK');
}
for (const host of config.proxy_exact_hosts) check('child.' + host, 'FALLBACK');
for (const host of ['example.cloudflare.com','example.workos.com','example.amazonaws.com']) check(host, 'FALLBACK');
sandbox.CommunityFindProxyForURL = community;
assert.deepStrictEqual(Array.from(sandbox.rules[1], x => x.length), [33,0,4398,2]);
for (const group of sandbox.rules) for (const index of [0,2]) for (const pattern of group[index]) new RegExp(pattern);
console.log(JSON.stringify({passed:true,cases:count,proxy_suffixes:suffixes.length,exact_hosts:config.proxy_exact_hosts.length,community_rules:[33,0,4398,2]},null,2));
