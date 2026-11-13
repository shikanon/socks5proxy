#!/usr/bin/env python3
"""Manage only this private runtime's loopback PAC and macOS Wi-Fi/en1 proxy settings."""
from pathlib import Path
import hashlib
import json
import os
import plistlib
import signal
import socket
import subprocess
import sys
import time
import urllib.request

BASE=Path(__file__).resolve().parent
PARENT=BASE.parent
PAC_URL='http://127.0.0.1:8090/proxy.pac'
STATE=BASE/'community-state.json'
SNAPSHOT=BASE/'wifi-before-community.plist'
HELPER=BASE/'proxy-settings'

def run(*args):
    return subprocess.run([str(a) for a in args],check=True,capture_output=True,text=True).stdout

def state():
    return json.loads(STATE.read_text()) if STATE.exists() else {'active':False}

def save(s):
    tmp=STATE.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(s,indent=2)+'\n')
    tmp.replace(STATE)

def fetch():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(PAC_URL,timeout=5) as r:
        data=r.read()
        assert r.status==200 and r.headers.get_content_type()=='application/x-ns-proxy-autoconfig'
    expected=(BASE/'proxy.pac').read_bytes()+b'\n'+(BASE/'direct-first.js').read_bytes()
    assert data==expected, 'Port 8090 serves unexpected PAC; no settings changed'
    return hashlib.sha256(data).hexdigest()

def listening(port):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(('127.0.0.1',port))==0

def stop_owned(s):
    pid=s.get('pac_pid')
    if not pid: return
    check=subprocess.run(['/bin/ps','-p',str(pid),'-o','command='],capture_output=True,text=True)
    expected=s.get('pac_command')
    if check.returncode==0:
        if check.stdout.strip()!=expected:
            raise RuntimeError('PAC PID now belongs to another process; not stopping it')
        os.kill(pid,signal.SIGTERM)
        for _ in range(30):
            if not listening(8090): break
            time.sleep(.1)
        if listening(8090):
            check=subprocess.run(['/bin/ps','-p',str(pid),'-o','command='],capture_output=True,text=True)
            if check.returncode==0 and check.stdout.strip()==expected:
                os.kill(pid,signal.SIGKILL)
                for _ in range(30):
                    if not listening(8090): break
                    time.sleep(.1)
        assert not listening(8090), 'PAC listener did not exit'
    s.pop('pac_pid',None);s.pop('pac_command',None)

def start(s):
    assert listening(8888), 'Run ../start.command first; project client must be available'
    transport_path=PARENT/'transport.json'
    transport=json.loads(transport_path.read_text())
    if transport['mode'] not in ('direct','multi'):
        raise RuntimeError('This example requires direct/multi TCP, not a legacy SSH runtime')
    if not listening(8090):
        log=open(BASE/'pac-server.log','ab')
        p=subprocess.Popen([sys.executable,str(BASE/'pac-server.py')],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        log.close()
        s.update(pac_pid=p.pid,pac_command=f'{sys.executable} {BASE / "pac-server.py"}')
        save(s)
        for _ in range(30):
            if p.poll() is not None: raise RuntimeError('PAC server exited; see pac-server.log')
            if listening(8090): break
            time.sleep(.1)
    s['pac_sha256']=fetch();save(s)
    # A listening port alone does not prove the remote tunnel is ready.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({'https':'http://127.0.0.1:8888'}))
    request=urllib.request.Request('https://www.google.com/',headers={'Cache-Control':'no-cache'})
    with opener.open(request,timeout=25) as r:
        assert r.status==200 and b'<title>Google</title>' in r.read(), 'Remote Google request failed'

def restore_settings():
    before=plistlib.loads(SNAPSHOT.read_bytes())
    current=json.loads(run(HELPER,'status',SNAPSHOT))
    # Do not overwrite an unrelated PAC selected after this task.
    if current.get('ProxyAutoConfigEnable') and current.get('ProxyAutoConfigURLString')!=PAC_URL:
        raise RuntimeError('Wi-Fi now uses another PAC; not overwriting that configuration')
    run('/usr/sbin/networksetup','-setautoproxystate','Wi-Fi','off')
    # networksetup rejects an empty PAC URL. Restore the disabled state and retain
    # this task's inactive URL when the original service had no URL.
    if before.get('ProxyAutoConfigURLString'):
        run('/usr/sbin/networksetup','-setautoproxyurl','Wi-Fi',before['ProxyAutoConfigURLString'])
    run('/usr/sbin/networksetup','-setautoproxystate','Wi-Fi','on' if before.get('ProxyAutoConfigEnable',0) else 'off')
    run('/usr/sbin/networksetup','-setwebproxystate','Wi-Fi','on' if before.get('HTTPEnable',0) else 'off')
    run('/usr/sbin/networksetup','-setsecurewebproxystate','Wi-Fi','on' if before.get('HTTPSEnable',0) else 'off')
    after=json.loads(run(HELPER,'status',SNAPSHOT))
    for key in before:
        assert after.get(key)==before[key], 'Restore mismatch: '+key
    assert after.get('ProxyAutoConfigEnable',0)==before.get('ProxyAutoConfigEnable',0)
    if before.get('ProxyAutoConfigURLString'):
        assert after.get('ProxyAutoConfigURLString')==before['ProxyAutoConfigURLString']

def main():
    action=sys.argv[1] if len(sys.argv)==2 else ''
    s=state()
    if action=='start': start(s)
    elif action=='apply':
        current=json.loads(run(HELPER,'status',SNAPSHOT))
        if current.get('ProxyAutoConfigEnable') and current.get('ProxyAutoConfigURLString')!=PAC_URL:
            raise RuntimeError('Another PAC is active; not overwriting it')
        start(s)
        if not SNAPSHOT.exists(): run(HELPER,'snapshot',SNAPSHOT)
        # Snapshot is immutable for this configuration; repeat apply never overwrites it.
        s['active']=True;save(s)  # persist recovery intent before a write
        try:
            run('/usr/sbin/networksetup','-setautoproxyurl','Wi-Fi',PAC_URL)
            run('/usr/sbin/networksetup','-setautoproxystate','Wi-Fi','on')
            run('/usr/sbin/networksetup','-setwebproxystate','Wi-Fi','off')
            run('/usr/sbin/networksetup','-setsecurewebproxystate','Wi-Fi','off')
            current=json.loads(run(HELPER,'status',SNAPSHOT))
            assert current.get('ProxyAutoConfigEnable')==1 and current.get('ProxyAutoConfigURLString')==PAC_URL
            assert current.get('HTTPEnable',0)==0 and current.get('HTTPSEnable',0)==0
        except BaseException:
            restore_settings()
            s['active']=False;save(s)
            raise
    elif action in ('restore','stop'):
        if s.get('active'):
            restore_settings()
            s['active']=False;save(s)
        if action=='stop': stop_owned(s);save(s)
    elif action=='status':
        print(run(HELPER,'status',SNAPSHOT));print(json.dumps(s,indent=2))
    else: raise RuntimeError('Usage: community-control.py start|apply|restore|stop|status')
    print('Community PAC '+action+' completed')

if __name__=='__main__':
    try: main()
    except Exception as e:
        print(str(e),file=sys.stderr)
        if isinstance(e,subprocess.CalledProcessError):print(e.stderr,file=sys.stderr)
        sys.exit(1)
