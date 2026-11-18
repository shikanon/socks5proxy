#!/usr/bin/env python3
"""Local native UI adapter. Fixed commands only; no shell, secrets or OAuth URLs."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import subprocess
import time
import urllib.request

LABEL = 'com.shikanon.socks5proxy.community'
MAX_JSON = 2 * 1024 * 1024

class ClientError(Exception):
    pass

def read_json(path, fallback=None):
    if not path.is_file():
        return fallback
    if path.stat().st_size > MAX_JSON:
        raise ClientError('状态文件过大，请检查运行目录。')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError):
        raise ClientError('配置或状态文件无法读取。')

def run(argv, timeout=8):
    return subprocess.run([str(x) for x in argv], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ, PATH='/usr/bin:/bin:/usr/sbin:/sbin', PYTHONDONTWRITEBYTECODE='1'))

def paths(root):
    root = Path(root).expanduser().resolve()
    if not (root / 'scripts/multi-autostart-control.py').is_file():
        raise ClientError('请选择包含代理管理脚本的 socks5proxy 项目目录。')
    base = root / 'dist/overseas-proxy'
    config = read_json(base / 'multi-server.json')
    if not isinstance(config, dict) or not config.get('domain_routes', {}).get('enabled'):
        raise ClientError('未找到已部署的域名分组配置；本版不会创建或覆盖运行配置。')
    return root, base, config

def listening(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.3):
            return True
    except OSError:
        return False

def launch_status(expected_base=None):
    service = 'gui/{}/{}'.format(os.getuid(), LABEL)
    plist = Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist')
    loaded = run(['/bin/launchctl', 'print', service])
    disabled = run(['/bin/launchctl', 'print-disabled', 'gui/' + str(os.getuid())])
    flag = re.search(r'"' + re.escape(LABEL) + r'"\s*=>\s*(true|false|enabled|disabled)', disabled.stdout)
    disabled_value = flag and flag.group(1) in ('true', 'disabled')
    on_load = False
    matching = expected_base is None
    if plist.is_file():
        try:
            job = plistlib.loads(plist.read_bytes())
            on_load = job.get('RunAtLoad') is True
            argv = job.get('ProgramArguments', [])
            if expected_base is not None and '--runtime' in argv:
                index = argv.index('--runtime')
                matching = index + 1 < len(argv) and Path(argv[index + 1]).resolve() == expected_base.resolve()
        except (ValueError, OSError, TypeError):
            pass
    pid = re.search(r'^\s*pid = (\d+)', loaded.stdout, re.MULTILINE)
    return dict(installed=plist.is_file(), loaded=loaded.returncode == 0,
                running=loaded.returncode == 0 and 'state = running' in loaded.stdout,
                autostart=on_load and not bool(disabled_value), matching=matching,
                owner_pid=int(pid.group(1)) if pid else None)

def pac_status():
    r = run(['/usr/sbin/networksetup', '-getautoproxyurl', 'Wi-Fi'])
    own = 'URL: http://127.0.0.1:8090/proxy.pac' in r.stdout and 'Enabled: Yes' in r.stdout
    protected = False
    if listening(8090):
        try:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with op.open('http://127.0.0.1:8090/proxy.pac', timeout=1) as response:
                data = response.read(MAX_JSON + 1)
            if len(data) <= MAX_JSON:
                match = re.search(r'var\s+direct\s*=\s*(\[[^;]+\]);', data.decode('utf-8'))
                protected = bool(match and all(x in json.loads(match.group(1)) for x in ['doubao.com', 'doubaowork.com', 'bytedance.com', 'larkoffice.com', 'feishu.cn']))
        except (OSError, ValueError, UnicodeError):
            pass
    return dict(pac_enabled=own, doubao_direct=protected)

def endpoint(value):
    # Addresses are configuration, never secrets or arbitrary messages.
    if isinstance(value, str) and re.fullmatch(r'[a-zA-Z0-9.\-\[\]:]{1,260}', value):
        return value
    return ''

def snapshot(root):
    root, base, config = paths(root)
    state = read_json(base / 'multi-state.json', {})
    if not isinstance(state, dict):
        raise ClientError('运行状态格式错误。')
    launch = launch_status(base)
    if launch['installed'] and not launch.get('matching', False):
        raise ClientError('启动项属于另一个运行目录；本版拒绝管理该目录，避免影响已有代理。')
    delta = time.time() - state.get('updated_at', 0)
    age = max(0, delta)
    fresh = 0 <= delta < 8 and launch['running'] and state.get('manager_pid') == launch['owner_pid']
    launch.pop('owner_pid')
    nodes = []
    for server in config.get('servers', []):
        name = server.get('name')
        if not isinstance(name, str) or not re.fullmatch('[a-z][a-z0-9_]{0,31}', name):
            continue
        health = state.get('servers', {}).get(name, {})
        nodes.append(dict(id=name, endpoint=endpoint(server.get('endpoint')),
                          healthy=fresh and health.get('healthy') is True))
    groups = []
    for name, settings in config['domain_routes'].get('groups', {}).items():
        if not re.fullmatch('[a-z][a-z0-9_]{0,31}', name):
            continue
        g = state.get('domain_routes', {}).get('groups', {}).get(name, {})
        stats = []
        for node in nodes:
            n = g.get('nodes', {}).get(node['id'], {})
            ms = n.get('median_response_ms')
            egress = state.get('domain_routes', {}).get('egress_verification', {}).get('nodes', {}).get(node['id'], {})
            checked = egress.get('checked_at')
            egress_fresh = fresh and isinstance(checked, (int, float)) and 0 <= time.time()-checked < 3600
            required = settings is not None and config['domain_routes'].get('egress_policy', {}).get('group') == name
            stats.append(dict(id=node['id'], state=n.get('state') if n.get('state') in ['reachable', 'unknown', 'unreachable', 'policy_denied'] and fresh else 'unknown',
                              response_ms=ms if isinstance(ms, (int, float)) and 0 < ms < 1e8 and fresh else None,
                              country=egress.get('country') if egress_fresh else None,
                              egress_state=egress.get('state') if egress_fresh else 'unknown',
                              eligible=not required or (egress_fresh and egress.get('eligible') is True)))
        groups.append(dict(id=name, default_server=settings.get('default_server'),
                           allowed_servers=settings.get('allowed_servers', []),
                           eligible_servers=[n['id'] for n in stats if n['eligible']], egress_required=required,
                           selected_server=g.get('preferred_available') if fresh else None,
                           selected_endpoint=endpoint(g.get('preferred_endpoint')) if fresh else '',
                           manual=g.get('manual_preference'), probing=g.get('running') is True and fresh,
                           next_probe=g.get('next_probe_at'), nodes=stats))
    port = listening(8888)
    pac = pac_status()
    return dict(ok=True, installed=launch['installed'], loaded=launch['loaded'], running=launch['running'],
                autostart=launch['autostart'], paused=(base / 'multi-paused').exists(),
                fresh=fresh, ready=fresh and state.get('ready') is True and port and listening(8090) and pac['pac_enabled'],
                http_listening=port, pac_listening=listening(8090),
                pac_enabled=pac['pac_enabled'], doubao_direct=pac['doubao_direct'],
                age_seconds=round(age, 1), nodes=nodes, groups=groups,
                interval_seconds=config['domain_routes'].get('interval_seconds', 1800))

def normalize_host(value):
    if not isinstance(value, str) or not value or len(value) > 253 or re.search(r'[\s/@?#:\\]', value):
        raise ClientError('仅输入域名，不接受完整链接或授权参数。')
    try:
        host = value.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ClientError('域名格式无效。')
    if not host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in host.split('.')):
        raise ClientError('域名格式无效。')
    return host

def query(root, value):
    root, _, _ = paths(root)
    host = normalize_host(value)
    node = next((p for p in [Path('/opt/homebrew/bin/node'), Path('/usr/local/bin/node')] if p.is_file() and os.access(p, os.X_OK)), None)
    if node is None:
        node = next((p for p in (Path.home() / 'Library/Application Support/DoubaoWork/sandbox_runtime/bases').glob('*/bin/node') if os.access(p, os.X_OK)), None)
    if node is None:
        raise ClientError('域名查询需要现有 Node.js 运行时。')
    r = run([node, root / 'scripts/proxy-route.js', '--json', host], timeout=12)
    if r.returncode:
        raise ClientError('无法读取当前 PAC，请确认代理和 PAC 服务已就绪。')
    try:
        data = json.loads(r.stdout)
        row = data['results'][0]
        if not data.get('live') or row.get('host') != host:
            raise ValueError()
    except (ValueError, KeyError, IndexError):
        raise ClientError('当前 PAC 查询结果无效。')
    return dict(ok=True, host=host, route=row.get('route'), reason=str(row.get('reason', ''))[:120],
                match=str(row.get('match', ''))[:240], live=True)

def control(root, action, group=None, server=None):
    root, base, config = paths(root)
    service = 'gui/{}/{}'.format(os.getuid(), LABEL)
    launch = launch_status(base)
    if launch['installed'] and not launch.get('matching', False):
        raise ClientError('启动项属于另一个运行目录；未执行操作。')
    if action in ('autostart-on', 'autostart-off'):
        if not launch['installed']:
            raise ClientError('未安装现有代理的登录启动项；请先完成运行环境安装。')
        r = run(['/bin/launchctl', 'enable' if action.endswith('-on') else 'disable', service])
    else:
        if action not in ('start', 'stop', 'route', 'route-auto', 'probe'):
            raise ClientError('不支持的操作。')
        argv = ['/usr/bin/python3', root / 'scripts/multi-autostart-control.py', action, '--runtime', base]
        if action in ('route', 'route-auto', 'probe'):
            groups = config['domain_routes']['groups']
            if group not in groups:
                raise ClientError('未知域名组。')
            argv += ['--group', group]
            if action == 'route':
                if server not in groups[group]['allowed_servers']:
                    raise ClientError('该组未授权使用此节点。')
                if config['domain_routes'].get('egress_policy', {}).get('group') == group:
                    view=snapshot(root)
                    item=next((x for x in view['groups'] if x['id']==group), {})
                    if server not in item.get('eligible_servers', []):
                        raise ClientError('该节点地区未通过检查，不能用于海外AI。')
                argv += ['--server', server]
        r = run(argv, timeout=115 if action == 'start' else 50)
    if r.returncode:
        # Existing scripts can print private state. Do not forward raw diagnostics.
        raise ClientError('操作未通过完成检查；可能已有部分动作生效，请刷新状态确认，不要重复点击。')
    return dict(ok=True, message={'start':'后台服务已启动并通过就绪检查。', 'stop':'代理已停止，已请求恢复本项目原网络设置。',
                                 'autostart-on':'登录后自动启动已启用。', 'autostart-off':'登录后自动启动已关闭；当前服务不受影响。',
                                 'route':'该组节点偏好已保存，仅影响后续新连接。', 'route-auto':'该组已恢复默认优先与故障回退。',
                                 'probe':'已请求该组探测；结果由后台异步更新。'}[action])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('action', choices=['snapshot', 'query', 'start', 'stop', 'route', 'route-auto', 'probe', 'autostart-on', 'autostart-off'])
    parser.add_argument('--group'); parser.add_argument('--server'); parser.add_argument('--host')
    args = parser.parse_args()
    try:
        if args.action == 'snapshot':
            result = snapshot(args.root)
        elif args.action == 'query':
            result = query(args.root, args.host)
        else:
            result = control(args.root, args.action, args.group, args.server)
    except ClientError as e:
        result = dict(ok=False, message=str(e))
    except subprocess.TimeoutExpired:
        result = dict(ok=False, message='操作等待超时；请刷新状态确认结果，不要重复点击。')
    except Exception:
        result = dict(ok=False, message='无法读取本机运行环境，请检查项目目录和访问权限。')
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))

if __name__ == '__main__':
    main()
