#!/usr/bin/env node
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {spawnSync} = require('child_process');
const {parseArguments, normalize, createEvaluator} = require('./proxy-route');
const root = path.join(__dirname, '..');
const pacFile = path.join(root, 'examples/community-pac/proxy.pac');
const evaluator = createEvaluator(fs.readFileSync(pacFile, 'utf8'));
const expected = [
  ['google.com','PROXY','社区规则'],
  ['auth.openai.com','PROXY','明确代理后缀'],
  ['raw.githubusercontent.com','PROXY','明确代理后缀'],
  ['challenges.cloudflare.com','PROXY','明确代理主机'],
  ['www.doubao.com','DIRECT','直连例外'],
  ['http://localhost:1455/auth/callback?code=DO_NOT_PRINT','DIRECT','局域网/回环'],
  ['https://example.com/?next=https://github.com/','DIRECT','社区未命中'],
  ['https://api.doubao.com/?next=https://openai.com/','DIRECT','直连例外'],
  ['HTTPS://GITHUB.COM/','PROXY','明确代理后缀'],
  ['github.com.','PROXY','明确代理后缀'],
  ['[::1]','DIRECT','局域网/回环'],
  ['::1','DIRECT','局域网/回环'],
  ['x.doubao.com.google.com','PROXY','社区规则'],
  ['x.com','PROXY','明确代理后缀'],
  ['pbs.twimg.com','PROXY','明确代理后缀'],
  ['static.xx.fbcdn.net','PROXY','明确代理后缀'],
  ['www.instagram.com','PROXY','明确代理后缀'],
  ['threads.com','PROXY','明确代理后缀'],
  ['web.whatsapp.com','PROXY','明确代理后缀'],
  ['meta.ai','PROXY','明确代理后缀']
];
for (const [input, route, reason] of expected) {
  const result = evaluator.query(input);
  assert.strictEqual(result.route, route, input);
  assert.strictEqual(result.reason, reason, input);
  assert(!JSON.stringify(result).includes('DO_NOT_PRINT'));
}
for (const input of ['https://user:secret@github.com/','github.com\ncode','file:///etc/passwd','']) assert.throws(() => normalize(input));
assert.strictEqual(parseArguments([]).list, true);
assert.throws(() => parseArguments(['--pac']));
assert.throws(() => parseArguments(['--list','github.com']));
assert.throws(() => parseArguments(['--unknown']));
const config = JSON.parse(fs.readFileSync(path.join(root, 'examples/community-pac/domains.json'), 'utf8'));
const suffixCount = Object.values(config.proxy_groups).flat().length;
const exactCount = config.proxy_exact_hosts.length;
assert.strictEqual(evaluator.explicit.length, suffixCount);
assert.strictEqual(evaluator.exact.length, exactCount);
const run = args => spawnSync(process.execPath, [path.join(__dirname, 'proxy-route.js'), ...args], {encoding: 'utf8'});
let result = run(['--offline','--json','github.com','www.doubao.com']);
assert.strictEqual(result.status, 0, result.stderr);
const report = JSON.parse(result.stdout);
assert.strictEqual(report.live, false);
assert.deepStrictEqual(report.results.map(x => x.route), ['PROXY','DIRECT']);
result = run(['--pac',pacFile,'--json','http://localhost:1455/auth/callback?code=DO_NOT_PRINT']);
assert.strictEqual(result.status,0);
assert(!result.stdout.includes('DO_NOT_PRINT'));
result = run(['--offline','--list','--json']);
assert.strictEqual(result.status,0);
assert.strictEqual(JSON.parse(result.stdout).proxy_suffixes.length,suffixCount);
result = run(['--offline','https://user:password@github.com/']);
assert.notStrictEqual(result.status,0);
assert(!result.stderr.includes('password'));
console.log(JSON.stringify({passed:true,route_cases:expected.length,cli_modes:['offline','file','json','list'],sensitive_url_not_printed:true}));
