#!/usr/bin/env python3
"""Supervise this existing community PAC deployment with per-connection primary/backup TCP routing."""
import argparse
import contextlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time


def load_module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def write_json(path, data):
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    temporary.chmod(0o600);temporary.replace(path)


def validate(config):
    import ipaddress
    assert config.get('version')==1,'Unsupported multi-server configuration'
    assert config['listen']==['127.0.0.1',18900],'Selector must use assigned loopback endpoint'
    servers=config['servers'];assert 2<=len(servers)<=8,'Expected 2 to 8 backends'
    names=set();endpoints=set()
    for server in servers:
        assert server['name'] not in names and server['endpoint'] not in endpoints,'Duplicate backend'
        names.add(server['name']);endpoints.add(server['endpoint'])
        host,port=server['endpoint'].rsplit(':',1);ipaddress.IPv4Address(host)
        assert port.isdigit() and 1<=int(port)<=65535
    for field,low,high in [('probe_seconds',5,120),('probe_timeout_seconds',3,20),('connect_timeout_seconds',1,10),('failure_threshold',1,5),('recovery_threshold',1,5)]:
        assert isinstance(config[field],int) and low<=config[field]<=high,field
    return config


class Router:
    """Routes only before any application bytes; never replays payload on failure."""
    def __init__(self,config):
        self.config=config;self.stop=threading.Event();self.lock=threading.RLock()
        self.status={s['name']:{'endpoint':s['endpoint'],'healthy':False,'successes':0,'failures':0,'last_check':None,'last_error':'not checked'} for s in config['servers']}
        self.active=set();self.sessions=0;self.counts={s['name']:0 for s in config['servers']};self.slots=threading.BoundedSemaphore(128)
        self.preference=None
    def health(self,name,ok,error=''):
        with self.lock:
            item=self.status[name];item['last_check']=time.time();item['last_error']=error
            if ok:
                item['successes']+=1;item['failures']=0
                if item['successes']>=self.config['recovery_threshold']:item['healthy']=True
            else:
                item['failures']+=1;item['successes']=0
                if item['failures']>=self.config['failure_threshold']:item['healthy']=False
    def candidates(self):
        with self.lock:
            servers=[s for s in self.config['servers'] if self.status[s['name']]['healthy']]
            if self.preference:servers.sort(key=lambda s:s['name']!=self.preference)
            return servers
    def snapshot(self):
        with self.lock:
            choices=self.candidates()
            return {'preferred_available':choices[0]['name'] if choices else None,'servers':{k:dict(v) for k,v in self.status.items()},'active_sessions':self.sessions,'accepted_by_server':dict(self.counts)}
    def relay(self,client):
        upstream=None;registered=False
        try:
            for server in self.candidates():
                host,port=server['endpoint'].rsplit(':',1)
                try:
                    upstream=socket.create_connection((host,int(port)),timeout=self.config['connect_timeout_seconds'])
                    chosen=server['name'];break
                except OSError:
                    self.health(server['name'],False,'TCP connect failed')
            if upstream is None:return
            client.settimeout(300);upstream.settimeout(300)
            client.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);upstream.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            with self.lock:self.active.add(upstream);self.sessions+=1;self.counts[chosen]+=1;registered=True
            def copy(src,dst):
                try:
                    while not self.stop.is_set():
                        data=src.recv(65536)
                        if not data:break
                        dst.sendall(data)
                except OSError:
                    with contextlib.suppress(OSError):src.shutdown(socket.SHUT_RDWR)
                    with contextlib.suppress(OSError):dst.shutdown(socket.SHUT_RDWR)
                finally:
                    with contextlib.suppress(OSError):dst.shutdown(socket.SHUT_WR)
            sender=threading.Thread(target=copy,args=(client,upstream),daemon=True);sender.start()
            copy(upstream,client)
            # A peer's write-half EOF must not truncate a still-uploading client.
            # Router.close() shuts down both sockets, so shutdown still unblocks this join.
            sender.join()
        finally:
            with self.lock:
                self.active.discard(client)
                if upstream:self.active.discard(upstream)
                if registered:self.sessions-=1
            client.close()
            if upstream:upstream.close()
            self.slots.release()
    def accept(self,listener):
        while not self.stop.is_set():
            try:client,_=listener.accept()
            except socket.timeout:continue
            except OSError:break
            if not self.slots.acquire(blocking=False):client.close();continue
            with self.lock:self.active.add(client)
            threading.Thread(target=self.relay,args=(client,),daemon=True).start()
    def close(self):
        self.stop.set()
        with self.lock:
            for sock in list(self.active):
                with contextlib.suppress(OSError):sock.shutdown(socket.SHUT_RDWR)
                sock.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--runtime',required=True,type=Path);args=parser.parse_args()
    base=args.runtime.resolve();config=validate(json.loads((base/'multi-server.json').read_text()))
    ctl=load_module('direct_control',base/'direct-client-control.py');pac=load_module('pac_control',base/'community-pac/community-control.py')
    lock_file=(base/'multi-manager.lock').open('a');fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if (base/'multi-paused').exists():return
    router=Router(config);children={};probe_processes=set();probe_threads=[];process_lock=threading.Lock();ready=False;pausing=False;client=None
    statefile=base/'multi-state.json'
    # Recover health clients left by a crashed supervisor, after checking executable and target.
    if statefile.exists():
        previous=json.loads(statefile.read_text())
        for child in previous.get('health_clients',[]):
            result=subprocess.run(['/bin/ps','-p',str(child['pid']),'-o','command='],capture_output=True,text=True)
            if result.returncode==0 and str(ctl.CLIENT) in result.stdout and '-server '+child['endpoint']+' ' in result.stdout:
                ctl.terminate(child['pid'])
    def stop(_signum,_frame):router.stop.set()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(tuple(config['listen']));listener.listen(128);listener.settimeout(.5)
    threading.Thread(target=router.accept,args=(listener,),daemon=True).start()
    def state():
        with process_lock:health_children=[{'pid':p.pid,'endpoint':endpoint,'port':port} for endpoint,port,p in children.values()]
        data=router.snapshot();data.update(manager_pid=os.getpid(),selector='127.0.0.1:18900',ready=ready,health_clients=health_children,updated_at=time.time(),mode='automatic-primary-backup',preference=router.preference)
        write_json(statefile,data)
    def probe(server):
        endpoint,port,child=children[server['name']]
        while not router.stop.is_set():
            try:
                if child.poll() is not None:
                    with process_lock:
                        if router.stop.is_set():break
                        child=ctl.start_client(endpoint,port,False)
                        children[server['name']]=(endpoint,port,child)
                command=['/usr/bin/curl','--silent','--show-error','--noproxy','','--proxy','http://127.0.0.1:'+str(port),'--connect-timeout',str(config['connect_timeout_seconds']),'--max-time',str(config['probe_timeout_seconds']),'--fail','https://www.google.com/']
                with process_lock:
                    if router.stop.is_set():break
                    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    probe_processes.add(process)
                try:
                    body,_=process.communicate(timeout=config['probe_timeout_seconds']+2)
                    ok=process.returncode==0 and b'<title>Google</title>' in body
                except subprocess.TimeoutExpired:process.kill();process.communicate();ok=False
                finally:
                    with process_lock:probe_processes.discard(process)
                router.health(server['name'],ok,'' if ok else 'HTTPS Google probe failed')
            except Exception as error:router.health(server['name'],False,type(error).__name__)
            router.stop.wait(config['probe_seconds'])
    try:
        for server in config['servers']:
            with socket.socket() as portprobe:portprobe.bind(('127.0.0.1',0));port=portprobe.getsockname()[1]
            child=ctl.start_client(server['endpoint'],port,False);children[server['name']]=(server['endpoint'],port,child)
        state()
        for server in config['servers']:
            thread=threading.Thread(target=probe,args=(server,),daemon=True);probe_threads.append(thread);thread.start()
        previous_choice=None;last_reconcile=0
        while not router.stop.is_set():
            if (base/'multi-paused').exists():pausing=True;break
            preference=(base/'multi-preferred').read_text().strip() if (base/'multi-preferred').exists() else ''
            with router.lock:router.preference=preference if preference in router.status else None
            choice=router.snapshot()['preferred_available']
            if choice!=previous_choice:
                print(json.dumps({'event':'selection','preferred_available':choice}),flush=True);previous_choice=choice
            if choice and time.monotonic()-last_reconcile>10:
                # Client/PAC adoption occurs only after real HTTPS through the selector.
                last_reconcile=time.monotonic()
                try:
                    candidate={'mode':'multi','server':'127.0.0.1:18900','servers':[s['endpoint'] for s in config['servers']]}
                    if client is not None:client.poll()  # reap an exited production child
                    pid=ctl.owned()
                    command=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','command='],text=True) if pid else ''
                    if not ctl.listening(8888) or '-server 127.0.0.1:18900 ' not in command:
                        ctl.preflight('127.0.0.1:18900')
                        previous=ctl.cfg()
                        ctl.stop_client();client=None
                        try:
                            client=ctl.start_client('127.0.0.1:18900');ctl.google(8888)
                        except Exception:
                            if client:ctl.terminate(client.pid)
                            old=previous['server'] if previous['mode'] in ('direct','multi') else '127.0.0.1:18889'
                            ctl.start_client(old);ctl.save(previous)
                            raise
                    ctl.save(candidate)
                    pac.start(pac.state())
                    if not ready:
                        result=subprocess.run([sys.executable,str(base/'community-pac/community-control.py'),'apply'],capture_output=True,text=True,timeout=40)
                        if result.returncode:raise RuntimeError('PAC apply failed')
                    ready=True
                except Exception as error:
                    ready=False
                    print(json.dumps({'event':'reconcile_error','error':type(error).__name__}),flush=True)
            if not choice or not ctl.listening(8888) or not pac.listening(8090):ready=False
            state();router.stop.wait(1)
    finally:
        router.close();listener.close()
        with process_lock:
            for process in list(probe_processes):
                if process.poll() is None:process.terminate()
        for thread in probe_threads:thread.join(timeout=config['probe_timeout_seconds']+3)
        for endpoint,port,process in list(children.values()):
            if process.poll() is None:ctl.terminate(process.pid)
            with contextlib.suppress(Exception):process.wait(timeout=5)
        if pausing or (base/'multi-paused').exists():
            if pac.state().get('active'):
                with contextlib.suppress(Exception):pac.restore_settings();pstate=pac.state();pstate['active']=False;pac.save(pstate)
            with contextlib.suppress(Exception):pstate=pac.state();pac.stop_owned(pstate);pac.save(pstate)
            with contextlib.suppress(Exception):ctl.stop_client()
        if client is not None:client.poll()
        ready=False
        with contextlib.suppress(Exception):state()

if __name__=='__main__':main()
