#!/usr/bin/env python3
"""Private-runtime HTTP client helper for multi-server-manager.py; no system network writes."""
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request

BASE = Path(__file__).resolve().parent
CLIENT = BASE / 'client'
PIDFILE = BASE / 'client.pid'
TRANSPORT = BASE / 'transport.json'
CONNECTION = BASE / 'connection.json'


def endpoint(value):
    host, port = value.rsplit(':', 1)
    ipaddress.IPv4Address(host)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid IPv4 TCP endpoint')
    return value


def cfg():
    return json.loads(TRANSPORT.read_text())


def connection_for(config):
    if config['mode'] not in ('direct', 'multi'):
        raise ValueError('This example supports random direct TCP or multi, not legacy SSH')
    endpoint(config['server'])
    if config['mode'] == 'multi':
        if config['server'] != '127.0.0.1:18900':
            raise ValueError('Invalid selector endpoint')
        for value in config['servers']:
            endpoint(value)
    previous = json.loads(CONNECTION.read_text()) if CONNECTION.exists() else {}
    previous.update(local_upstream=config['server'], local_http_proxy='127.0.0.1:8888',
                    transport='random-tcp-primary-backup' if config['mode'] == 'multi' else 'random-direct-tcp',
                    servers=config.get('servers', [config['server']]))
    return previous


def save(config):
    metadata = connection_for(config)
    before = {p: p.read_bytes() if p.exists() else None for p in (TRANSPORT, CONNECTION)}
    try:
        for path, value in ((CONNECTION, metadata), (TRANSPORT, config)):
            temporary = path.with_suffix('.tmp')
            temporary.write_text(json.dumps(value, indent=2) + '\n')
            temporary.chmod(0o600)
            temporary.replace(path)
    except Exception:
        for path, value in before.items():
            if value is not None:
                temporary = path.with_suffix('.tmp')
                temporary.write_bytes(value)
                temporary.replace(path)
        raise


def listening(port):
    with socket.socket() as probe:
        probe.settimeout(.5)
        return probe.connect_ex(('127.0.0.1', port)) == 0


def owned():
    if not PIDFILE.exists():
        return None
    value = PIDFILE.read_text().strip()
    if not value.isdigit():
        raise RuntimeError('Invalid client PID; not touching another process')
    pid = int(value)
    result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'stat=,comm='], capture_output=True, text=True)
    if result.returncode:
        return None
    fields = result.stdout.strip().split(None, 1)
    if not fields or fields[0].startswith('Z'):
        return None
    if len(fields) != 2 or os.path.realpath(fields[1]) != str(CLIENT):
        raise RuntimeError('PID belongs to another live process')
    return pid


def terminate(pid):
    # Only call with owned() or a just-created Popen handle.
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(30):
        result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
        if result.returncode or result.stdout.strip().startswith('Z'):
            return
        time.sleep(.1)
    result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'comm='], capture_output=True, text=True)
    if result.returncode == 0 and os.path.realpath(result.stdout.strip()) == str(CLIENT):
        os.kill(pid, signal.SIGKILL)


def start_client(upstream, port=8888, persist=True):
    endpoint(upstream)
    secret = (BASE / 'proxy.secret').read_text().strip()
    if not secret:
        raise RuntimeError('Missing private random secret')
    if listening(port):
        raise RuntimeError('Listener is already in use')
    with (BASE / 'client.log').open('ab') as log:
        process = subprocess.Popen([str(CLIENT), '-mode', 'proxy', '-local', f'127.0.0.1:{port}',
                                    '-server', upstream, '-type', 'random', '-passwd', secret, '-recv', 'http'],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    for _ in range(30):
        if process.poll() is not None:
            raise RuntimeError('Client exited; inspect private client.log')
        if listening(port):
            if persist:
                PIDFILE.write_text(str(process.pid) + '\n')
            return process
        time.sleep(.1)
    terminate(process.pid)
    raise RuntimeError('Client listener not ready')


def stop_client():
    pid = owned()
    if pid:
        terminate(pid)
    for _ in range(30):
        if not listening(8888):
            return
        time.sleep(.1)
    raise RuntimeError('8888 is still in use; refusing to replace another process')


def google(port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': f'http://127.0.0.1:{port}'}))
    with opener.open('https://www.google.com/', timeout=25) as response:
        if response.status != 200 or b'<title>Google</title>' not in response.read():
            raise RuntimeError('HTTPS health response invalid')


def preflight(upstream):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    process = start_client(upstream, port, False)
    try:
        google(port)
    finally:
        if process.poll() is None:
            terminate(process.pid)
        process.wait(timeout=5)
