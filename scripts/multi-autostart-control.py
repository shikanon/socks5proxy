#!/usr/bin/env python3
"""Install/start/stop a user-login-only launchd job for the existing PAC deployment."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time

LABEL='com.shikanon.socks5proxy.community'


def run(args,check=True):return subprocess.run(args,capture_output=True,text=True,check=check)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['install','start','stop','uninstall','status','primary','backup','backup2','latency','auto','routes','route','route-auto','probe']);parser.add_argument('--runtime',required=True,type=Path);parser.add_argument('--group');parser.add_argument('--server');args=parser.parse_args()
    base=args.runtime.resolve();domain='gui/'+str(os.getuid());service=domain+'/'+LABEL
    plist=Path.home()/'Library/LaunchAgents'/ (LABEL+'.plist')
    manager=Path(__file__).resolve().parent/'multi-server-manager.py'
    if args.action=='install':
        assert manager.is_file() and (base/'multi-server.json').is_file() and (base/'proxy.secret').is_file()
        assert not plist.exists(),'LaunchAgent already exists; inspect it before replacing'
        job={'Label':LABEL,'ProgramArguments':[sys.executable,str(manager),'--runtime',str(base)],'RunAtLoad':True,'KeepAlive':{'SuccessfulExit':False},'ThrottleInterval':15,'ProcessType':'Background','WorkingDirectory':str(Path.home()),'StandardOutPath':str(Path.home()/'Library/Logs'/(LABEL+'.log')),'StandardErrorPath':str(Path.home()/'Library/Logs'/(LABEL+'-error.log')),'ExitTimeOut':20,'EnvironmentVariables':{'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','PYTHONUNBUFFERED':'1'}}
        plist.write_bytes(plistlib.dumps(job));plist.chmod(0o600)
        with (base/'multi-paused').open('w') as f:f.write('installation preparation\n')
        # Remove the preparation marker only immediately before bootstrap.
        (base/'multi-paused').unlink()
        run(['/bin/launchctl','enable',service])
        result=run(['/bin/launchctl','bootstrap',domain,str(plist)],check=False)
        if result.returncode:raise RuntimeError('launchctl bootstrap failed: '+result.stderr.strip())
        print('User-login launch agent installed; not a pre-login system daemon')
    elif args.action=='start':
        assert plist.is_file(),'Install auto-start first'
        if (base/'multi-paused').exists():(base/'multi-paused').unlink()
        run(['/bin/launchctl','enable',service])
        if run(['/bin/launchctl','print',service],check=False).returncode:
            run(['/bin/launchctl','bootstrap',domain,str(plist)])
        else:
            state=run(['/bin/launchctl','print',service]).stdout
            if 'state = running' not in state:run(['/bin/launchctl','kickstart',service])
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            current=json.loads((base/'multi-state.json').read_text()) if (base/'multi-state.json').exists() else {}
            live=run(['/bin/launchctl','print',service],check=False)
            owned_pid='pid = '+str(current.get('manager_pid',-1))
            if current.get('ready') and time.time()-current.get('updated_at',0)<4 and live.returncode==0 and 'state = running' in live.stdout and owned_pid in live.stdout:break
            time.sleep(1)
        else:raise RuntimeError('Manager started but no verified channel is ready; see multi-state.json')
        (base/'multi-activated').write_text('Verified user-login primary/backup channel\n');(base/'multi-activated').chmod(0o600)
        print('Automatic primary/backup service started and verified')
    elif args.action in ('stop','uninstall'):
        (base/'multi-paused').write_text('User explicitly paused proxy\n');(base/'multi-paused').chmod(0o600)
        if not run(['/bin/launchctl','print',service],check=False).returncode:
            run(['/bin/launchctl','bootout',service])
        deadline=time.monotonic()+40
        while run(['/bin/launchctl','print',service],check=False).returncode==0:
            if time.monotonic()>=deadline:raise RuntimeError('launchd has not finished unloading the manager')
            time.sleep(.25)
        if args.action=='uninstall' and plist.exists():
            backup=base/'launchagent.uninstalled.plist';assert not backup.exists(),'Keep previous uninstall backup'
            plist.replace(backup)
        print('Automatic primary/backup service stopped; explicit start resumes it')
    elif args.action in ('routes','route','route-auto','probe'):
        cfg=json.loads((base/'multi-server.json').read_text()).get('domain_routes')
        if not cfg or not cfg.get('enabled'):raise RuntimeError('Domain routing is not enabled')
        if args.group and args.group not in cfg['groups']:raise RuntimeError('Unknown domain group')
        if args.action=='routes':
            state=json.loads((base/'multi-state.json').read_text());value=state.get('domain_routes',{})
            if args.group:value=value.get('groups',{}).get(args.group,{})
            print(json.dumps(value,ensure_ascii=False,indent=2))
        else:
            if not args.group:raise RuntimeError('--group is required')
            path=base/('domain-probe-request.json' if args.action=='probe' else 'domain-preferred.json')
            values=json.loads(path.read_text()) if path.exists() else {}
            if args.action=='probe':values[args.group]=time.time_ns()
            elif args.action=='route-auto':values.pop(args.group,None)
            else:
                if args.server not in cfg['groups'][args.group]['allowed_servers']:raise RuntimeError('Backend not authorized for this group')
                values[args.group]=args.server
            q=path.with_suffix('.tmp');q.write_text(json.dumps(values,indent=2)+'\n');q.chmod(0o600);q.replace(path)
            print('Domain group '+args.group+' '+args.action+' saved; other groups and established sessions unchanged')
    elif args.action in ('primary','backup','backup2','auto'):
        assert (base/'multi-server.json').is_file()
        current_config=json.loads((base/'multi-server.json').read_text())
        if current_config.get('domain_routes',{}).get('enabled'):
            path=base/'domain-preferred.json';values=json.loads(path.read_text()) if path.exists() else {}
            if args.action=='auto':values.pop('ordinary',None)
            else:
                if args.action not in current_config['domain_routes']['groups']['ordinary']['allowed_servers']:
                    raise RuntimeError('Requested backend is not authorized for the ordinary group')
                values['ordinary']=args.action
            q=path.with_suffix('.tmp');q.write_text(json.dumps(values,indent=2)+'\n');q.chmod(0o600);q.replace(path)
            print('Ordinary group preference updated; special domain groups unchanged');return
        names={s['name'] for s in json.loads((base/'multi-server.json').read_text())['servers']}
        if args.action!='auto' and args.action not in names:raise RuntimeError('Requested backend is not configured')
        preference=base/'multi-preferred'
        preference.write_text('' if args.action=='auto' else args.action+'\n');preference.chmod(0o600)
        print('New connections use automatic HTTPS latency ranking with healthy fallback' if args.action=='auto' and json.loads((base/'multi-server.json').read_text()).get('latency_selection',{}).get('enabled') else 'New connections now prefer '+args.action+'; existing connections are unchanged')
    elif args.action=='latency':
        state=json.loads((base/'multi-state.json').read_text()) if (base/'multi-state.json').exists() else {}
        print(json.dumps({'preferred_available':state.get('preferred_available'),'manual_preference':state.get('preference'),'state_age_seconds':time.time()-state.get('updated_at',0),'latency_selection':state.get('latency_selection',{'enabled':False})},ensure_ascii=False,indent=2))
    else:
        result=run(['/bin/launchctl','print',service],check=False)
        state=json.loads((base/'multi-state.json').read_text()) if (base/'multi-state.json').exists() else {}
        summary={'installed':plist.is_file(),'loaded':result.returncode==0,'running':'state = running' in result.stdout,'paused':(base/'multi-paused').exists(),'state':state}
        print(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
