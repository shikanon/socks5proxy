#!/usr/bin/env node
'use strict';
// Query the actual PAC; not a history of requests and not a connection probe.
const fs = require('fs');
const http = require('http');
const path = require('path');
const vm = require('vm');
const net = require('net');
const crypto = require('crypto');
const {URL, domainToASCII} = require('url');
const LIVE = 'http://127.0.0.1:8090/proxy.pac';
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_RULE_DISPLAY = 240;

function parseArguments(argv) {
  const options = {hosts: [], json: false, list: false, file: null, help: false};
  for (let i = 0; i < argv.length; i++) {
    const value = argv[i];
    if (value === '--help' || value === '-h') options.help = true;
    else if (value === '--json') options.json = true;
    else if (value === '--list') options.list = true;
    else if (value === '--pac') {
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error('--pac 需要本地 PAC 文件路径');
      options.file = argv[++i];
    } else if (value === '--offline') options.file = path.join(__dirname, '../examples/community-pac/proxy.pac');
    else if (value.startsWith('-')) throw new Error('未知参数: ' + value);
    else options.hosts.push(value);
  }
  if (options.hosts.length > 256) throw new Error('单次最多查询 256 个域名');
  if (options.list && options.hosts.length) throw new Error('--list 不与域名参数同时使用');
  if (!options.hosts.length) options.list = true;
  return options;
}

function normalize(value) {
  if (/[\x00-\x20\x7f]/.test(value)) throw new Error('域名/URL不能包含空白或控制字符');
  let input = value;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
    if (net.isIP(input) === 6) input = '[' + input + ']';
    input = 'https://' + input;
  }
  let url;
  try { url = new URL(input); } catch (_) { throw new Error('无效域名或URL'); }
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) throw new Error('仅支持HTTP/HTTPS/WebSocket URL');
  if (url.username || url.password) throw new Error('不接受包含用户名或密码的URL');
  const host = url.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!host || host.length > 253) throw new Error('无效主机名');
  if (!net.isIP(host) && (!domainToASCII(host) || !/^[a-z0-9_.-]+$/.test(host))) throw new Error('无效主机名');
  // PAC receives the real URL (paths may affect community rules); output never
  // repeats its query, fragment or an OAuth callback code.
  return {host, url: url.href};
}

function fetchLive() {
  return new Promise((resolve, reject) => {
    let bytes = 0;
    const parts = [];
    const request = http.get(LIVE, {agent: false}, response => {
      if (response.statusCode !== 200) {
        response.resume(); reject(new Error('当前 PAC 返回 HTTP ' + response.statusCode)); return;
      }
      response.on('data', part => {
        bytes += part.length;
        if (bytes > MAX_BYTES) request.destroy(new Error('PAC超过2 MiB限制'));
        else parts.push(part);
      });
      response.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
      response.on('error', reject);
    });
    const timer = setTimeout(() => request.destroy(new Error('当前 PAC 读取超时')), 5000);
    request.on('close', () => clearTimeout(timer));
    request.on('error', error => reject(new Error(error.message + '；确认代理已启动，或使用 --offline 查询仓库规则（不是当前生效规则）')));
  });
}

function inlineList(pac, name) {
  // Read only known generated JSON literals, not a guessed current config file.
  const match = new RegExp('var\\s+' + name + '\\s*=\\s*(\\[[\\s\\S]*?\\]);').exec(pac);
  if (!match) return [];
  try {
    const values = JSON.parse(match[1]);
    return Array.isArray(values) && values.every(x => typeof x === 'string') ? values : [];
  } catch (_) { return []; }
}

function isLocal(host) {
  if (!host.includes('.') || host === 'localhost' || host === '::1' || host.endsWith('.local') || /^f[cd][0-9a-f]*:/.test(host) || /^fe[89ab][0-9a-f]:/.test(host)) return true;
  const ip = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!ip) return false;
  const a = Number(ip[1]), b = Number(ip[2]);
  return a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}
const suffixMatch = (host, suffix) => host === suffix || host.endsWith('.' + suffix);

function createEvaluator(pac) {
  if (Buffer.byteLength(pac) > MAX_BYTES) throw new Error('PAC超过2 MiB限制');
  const sandbox = {
    shExpMatch: (str, pattern) => {
      const escaped = pattern.split('').map(c => c === '*' ? '.*' : c === '?' ? '.' : /[\\^$+?.()|[\]{}]/.test(c) ? '\\' + c : c).join('');
      return new RegExp('^' + escaped + '$').test(str);
    }
  };
  // Trusted local/generated PAC only. This is not a secure runner for arbitrary
  // remote JavaScript; no network-URL option, process or require is exposed.
  vm.createContext(sandbox, {codeGeneration: {strings: false, wasm: false}});
  vm.runInContext(pac, sandbox, {timeout: 3000});
  if (typeof sandbox.FindProxyForURL !== 'function') throw new Error('PAC缺少FindProxyForURL');
  const direct = inlineList(pac, 'direct');
  const explicit = [...new Set([...inlineList(pac, 'explicit'), ...inlineList(pac, 'aiProxy')])];
  const exact = inlineList(pac, 'exact');
  if (typeof sandbox.CommunityFindProxyForURL === 'function') {
    vm.runInContext(`var __routeOriginal = CommunityFindProxyForURL;
      CommunityFindProxyForURL = function(url, host) {
        __routeCommunity = true;
        var result = __routeOriginal(url, host);
        __routeRule = typeof lastRule === 'string' ? lastRule : '';
        return result;
      };`, sandbox, {timeout: 1000});
  }
  const ruleCounts = Array.isArray(sandbox.rules) ? Array.from(sandbox.rules, group => Array.from(group, rules => rules.length)) : null;
  function query(input) {
    const {host, url} = normalize(input);
    sandbox.__routeHost = host; sandbox.__routeURL = url;
    sandbox.__routeCommunity = false; sandbox.__routeRule = '';
    const directive = vm.runInContext('FindProxyForURL(__routeURL, __routeHost)', sandbox, {timeout: 200});
    if (typeof directive !== 'string') throw new Error('PAC返回值不是字符串');
    let reason = 'PAC规则';
    let match = '';
    if (sandbox.__routeCommunity) {
      match = (sandbox.__routeRule || '').slice(0, MAX_RULE_DISPLAY);
      reason = match ? '社区规则' : '社区未命中';
    } else if (directive === 'DIRECT') {
      match = direct.find(suffix => suffixMatch(host, suffix)) || '';
      reason = match ? '直连例外' : isLocal(host) ? '局域网/回环' : 'PAC直连';
    } else {
      match = explicit.find(suffix => suffixMatch(host, suffix)) || '';
      if (match) reason = '明确代理后缀';
      else if (exact.includes(host)) { match = host; reason = '明确代理主机'; }
    }
    return {host, route: directive === 'DIRECT' ? 'DIRECT' : 'PROXY', directive, reason, match};
  }
  return {query, direct, explicit, exact, ruleCounts};
}

async function main(argv) {
  const options = parseArguments(argv);
  if (options.help) {
    console.log(`用法: ./proxy-route [域名或URL ...] [--json]
      ./proxy-route --list           列出当前明确代理域名
      ./proxy-route --offline ...    查询仓库PAC，不代表当前设置
      ./proxy-route --pac 文件 ...   查询指定可信本地PAC
默认读取 ${LIVE}，不发出目标网站请求，不修改网络。
这是PAC规则选择，不是实际访问/转发日志。`);
    return;
  }
  const pac = options.file ? fs.readFileSync(options.file, 'utf8') : await fetchLive();
  const evaluator = createEvaluator(pac);
  const report = {source: options.file ? path.resolve(options.file) : LIVE, live: !options.file, mode: 'PAC规则选择；不是实际转发日志', sha256: crypto.createHash('sha256').update(pac).digest('hex')};
  if (options.list) {
    if (!evaluator.explicit.length && !evaluator.exact.length) throw new Error('此PAC不是支持的清单格式，不能列出明确域名；可逐个查询');
    report.proxy_suffixes = evaluator.explicit;
    report.proxy_exact_hosts = evaluator.exact;
    report.direct_suffixes = evaluator.direct;
    report.community_rule_counts = evaluator.ruleCounts;
  } else report.results = options.hosts.map(evaluator.query);
  if (options.json) { console.log(JSON.stringify(report, null, 2)); return; }
  console.log((report.live ? '当前回环PAC' : '本地文件PAC（非实时）') + ' · 规则查询，非访问日志');
  if (options.list) {
    console.log('明确代理后缀（包含根域名和所有子域名）');
    for (const domain of evaluator.explicit) console.log('  ' + domain);
    console.log('明确代理主机（仅精确匹配）');
    for (const host of evaluator.exact) console.log('  ' + host);
    if (evaluator.ruleCounts && evaluator.ruleCounts[1]) console.log('另保留社区规则：' + evaluator.ruleCounts[1][2] + '条代理正则、' + evaluator.ruleCounts[1][3] + '条代理通配；用域名参数查询最终结果。');
    console.log('豆包相关直连例外优先；完整清单可用 --json 查看。');
  } else {
    for (const row of report.results) {
      console.log(row.host + '  ' + (row.route === 'DIRECT' ? '直连' : '代理') + '  ' + row.directive + '  [' + row.reason + (row.match ? ': ' + row.match : '') + ']');
    }
  }
}
if (require.main === module) main(process.argv.slice(2)).catch(error => { console.error('查询失败: ' + error.message); process.exitCode = 1; });
module.exports = {parseArguments, normalize, createEvaluator, fetchLive, main};
