#!/usr/bin/env python3
"""Build complete community PAC with explicit, dot-bounded service exceptions."""
import argparse
import ipaddress
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'examples/community-pac/domains.json'


def domain(value):
    if not isinstance(value, str) or len(value) > 253 or not re.fullmatch(r'[a-z0-9.-]+', value):
        raise ValueError('Invalid ASCII domain')
    labels = value.split('.')
    if len(labels) < 2 or any(not x or len(x) > 63 or x[0] == '-' or x[-1] == '-' for x in labels):
        raise ValueError('Invalid domain labels')
    return value


def wrapper(config):
    if config.get('schema_version') != 1:
        raise ValueError('Unsupported domain-list schema')
    address = config['proxy']
    host, port = address.rsplit(':', 1)
    ip = ipaddress.ip_address(host)
    if not ip.is_loopback or ip.version != 4 or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Proxy must be an IPv4 loopback IP and valid port')
    direct = [domain(x) for x in config['direct_suffixes']]
    proxy = [domain(x) for values in config['proxy_groups'].values() for x in values]
    exact = [domain(x) for x in config['proxy_exact_hosts']]
    for values in (direct, proxy, exact):
        if len(values) != len(set(values)):
            raise ValueError('Duplicate domains')
    if set(direct) & (set(proxy) | set(exact)):
        raise ValueError('Conflicting direct/proxy domains')
    return '''// Generated from domains.json. Direct exceptions precede explicit and community rules.
function domainSuffix(host, suffix) {
    return host === suffix || host.slice(-(suffix.length + 1)) === '.' + suffix;
}
function FindProxyForURL(url, host) {
    host = host.toLowerCase().replace(/\\.$/, '').replace(/^\\[|\\]$/g, '');
    var direct = %s;
    if (host.indexOf('.') < 0 || host === 'localhost' || host === '::1' ||
        host.slice(-6) === '.local' || /^f[cd][0-9a-f]*:/.test(host) ||
        /^fe[89ab][0-9a-f]:/.test(host)) return 'DIRECT';
    var ip = /^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/.exec(host);
    if (ip && (+ip[1] === 10 || +ip[1] === 127 || +ip[1] === 0 ||
        (+ip[1] === 192 && +ip[2] === 168) ||
        (+ip[1] === 172 && +ip[2] >= 16 && +ip[2] <= 31) ||
        (+ip[1] === 169 && +ip[2] === 254))) return 'DIRECT';
    for (var i = 0; i < direct.length; i++) {
        if (domainSuffix(host, direct[i])) return 'DIRECT';
    }
    var explicit = %s;
    var exact = %s;
    for (var j = 0; j < explicit.length; j++) {
        if (domainSuffix(host, explicit[j])) return %s;
    }
    for (var k = 0; k < exact.length; k++) {
        if (host === exact[k]) return %s;
    }
    return CommunityFindProxyForURL(url, host);
}
''' % tuple(json.dumps(x, ensure_ascii=True) for x in (direct, proxy, exact, 'PROXY ' + address, 'PROXY ' + address))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=DEFAULT)
    parser.add_argument('--output', type=Path, default=DEFAULT.parent / 'proxy.pac')
    parser.add_argument('--wrapper-output', type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8'))
    script = wrapper(config)
    snapshot = args.config.parent / config['community']['snapshot']
    data = snapshot.read_text(encoding='utf-8')
    if 'function CommunityFindProxyForURL(' not in data:
        raise ValueError('Missing community PAC entry')
    # Preserve the full generated snapshot; the strict wrapper chooses priority.
    # Replace only the selected loopback endpoint.
    line = "var proxy = 'PROXY 127.0.0.1:8888';"
    if data.count(line) != 1:
        raise ValueError('Unexpected snapshot endpoint')
    data = data.replace(line, 'var proxy = ' + json.dumps('PROXY ' + config['proxy']) + ';')
    args.output.write_text(data + '\n' + script, encoding='utf-8')
    if args.wrapper_output:
        args.wrapper_output.write_text(script, encoding='utf-8')
    print('Generated ' + str(args.output))

if __name__ == '__main__':
    main()
