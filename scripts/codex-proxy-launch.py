#!/usr/bin/env python3
"""Launch only the Codex desktop app/embedded CLI with loopback HTTP proxies; never changes global settings."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import socket
import subprocess
import sys
import time

PROXY='http://127.0.0.1:8888'
NO_PROXY='localhost,127.0.0.1,::1'
PROXY_KEYS=('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')


def proxy_environment(base):
    env=dict(base)
    for name in PROXY_KEYS:env[name]=PROXY
    for name in ('NO_PROXY','no_proxy'):env[name]=NO_PROXY
    # Node may honor environment proxies on supported versions; Chromium also gets explicit flags.
    env['NODE_USE_ENV_PROXY']='1'
    return env


def resolve_app(app):
    info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier')!='com.openai.codex':raise RuntimeError('App is not the expected Codex installation')
    executable=info.get('CFBundleExecutable')
    if not isinstance(executable,str) or Path(executable).name!=executable:raise RuntimeError('Invalid application executable')
    desktop=app/'Contents/MacOS'/executable
    cli=app/'Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'
    if not desktop.is_file() or not os.access(desktop,os.X_OK):raise RuntimeError('Desktop executable missing')
    return desktop,cli,info


def app_running(app):
    r=subprocess.run(['/bin/ps','-axo','pid=,comm='],capture_output=True,text=True,timeout=5)
    prefix=str(app/'Contents')+'/'
    paths=[f[1] for line in r.stdout.splitlines() if len(f:=line.strip().split(None,1))==2 and f[1].startswith(prefix)]
    return any('/Contents/MacOS/ChatGPT' in path or '/CodexCLI.app/Contents/MacOS/codex' in path or '/Helpers/Codex (' in path for path in paths)


def require_proxy():
    with socket.create_connection(('127.0.0.1',8888),timeout=2):pass


def chromium_flags():
    return ['--proxy-server='+PROXY,'--proxy-bypass-list=localhost;127.0.0.1;[::1]']


def launch_arguments(app,env):
    args=['/usr/bin/open','-a',str(app),'-n','--stdout','/dev/null','--stderr','/dev/null']
    for name in PROXY_KEYS+('NO_PROXY','no_proxy','NODE_USE_ENV_PROXY'):
        args+=['--env',name+'='+env[name]]
    return args+['--args']+chromium_flags()


def application_processes(app):
    result=subprocess.run(['/bin/ps','-axo','pid=,ppid=,comm='],capture_output=True,text=True,timeout=5)
    rows=[]
    for line in result.stdout.splitlines():
        fields=line.strip().split(None,2)
        if len(fields)==3 and (fields[2]==str(app/'Contents/MacOS/ChatGPT') or fields[2]==str(app/'Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex')):
            rows.append({'pid':int(fields[0]),'parent_pid':int(fields[1]),'kind':'cli' if fields[2].endswith('/codex') else 'desktop'})
    return rows


def verify_environment(pid,env):
    import re
    result=subprocess.run(['/bin/ps','eww','-p',str(pid),'-o','command='],capture_output=True,text=True,timeout=5)
    # Only expose task proxy values. Never log the complete process environment.
    values={}
    for name in PROXY_KEYS+('NO_PROXY','no_proxy','NODE_USE_ENV_PROXY'):
        match=re.search(r'(?:^|\s)'+re.escape(name)+r'=([^\s]*)',result.stdout)
        values[name]=bool(match and match.group(1)==env[name])
    return values


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,default=Path('/Applications/ChatGPT.app'))
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--cli',action='store_true',help='Run the bundled Codex CLI with the same per-process environment')
    parser.add_argument('cli_args',nargs=argparse.REMAINDER)
    args=parser.parse_args();app=args.app.resolve();desktop,cli,info=resolve_app(app)
    env=proxy_environment(os.environ)
    if args.check:
        require_proxy()
        processes=application_processes(app)
        for row in processes:row['proxy_environment_matches']=verify_environment(row['pid'],env)
        print(json.dumps({'app':str(app),'version':info.get('CFBundleShortVersionString'),
                          'proxy':PROXY,'NO_PROXY':NO_PROXY,'desktop_already_running':app_running(app),
                          'current_processes':processes,
                          'scope':'launched process and normally inherited children','system_settings_changed':False,
                          'chromium_flags':chromium_flags()},ensure_ascii=False,indent=2));return
    if args.cli:
        if not cli.is_file():raise RuntimeError('Bundled CLI not found')
        passed=args.cli_args[1:] if args.cli_args[:1]==['--'] else args.cli_args
        if not passed:passed=['--help']
        require_proxy()
        os.execve(str(cli),[str(cli)]+passed,env)
    if args.cli_args:raise RuntimeError('Unexpected arguments; CLI arguments require --cli')
    require_proxy()
    if app_running(app):raise RuntimeError('Codex is already running. Quit it normally, then launch again with this script; old processes cannot inherit new environment variables.')
    root=Path(__file__).resolve().parents[1]
    runtime=root/'dist/overseas-proxy'
    runtime.mkdir(parents=True,exist_ok=True)
    # LaunchServices receives environment explicitly; do not rely on GUI relaunch inheriting shell values.
    launched=time.time()
    result=subprocess.run(launch_arguments(app,env),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    if result.returncode:raise RuntimeError('macOS app launch failed; no global settings were modified')
    deadline=time.monotonic()+25;observed=[]
    while time.monotonic()<deadline:
        observed=[]
        for row in application_processes(app):
            row=dict(row,proxy_environment_matches=verify_environment(row['pid'],env));observed.append(row)
        if {row['kind'] for row in observed}=={'desktop','cli'} and all(all(row['proxy_environment_matches'].values()) for row in observed):break
        time.sleep(1)
    valid=bool(observed) and {r['kind'] for r in observed}=={'desktop','cli'} and all(all(r['proxy_environment_matches'].values()) for r in observed)
    record={'processes':observed,'app':str(app),'version':info.get('CFBundleShortVersionString'),
            'launched_at':launched,'proxy':PROXY,'NO_PROXY':NO_PROXY,'global_environment_changed':False,
            'system_proxy_changed':False,'application_binary_modified':False,'chromium_flags':chromium_flags(),
            'launch_method':'LaunchServices_open_explicit_environment','environment_inheritance_verified':valid}
    target=runtime/'codex-proxy-launch.json';tmp=target.with_suffix('.tmp')
    tmp.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n');tmp.chmod(0o600);tmp.replace(target)
    if not valid:raise RuntimeError('Codex started but proxy inheritance could not be verified; inspect codex-proxy-launch.json. Other apps and system settings were unchanged.')
    print('Codex主进程与内置CLI已继承专用代理环境；现有系统PAC和其他应用环境未修改。')

if __name__=='__main__':
    try:main()
    except Exception as error:print(str(error),file=sys.stderr);sys.exit(1)
