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


LATENCY=load_module('latency_selection',Path(__file__).with_name('latency-selection.py'))
DOMAIN=load_module('domain_routing',Path(__file__).with_name('domain-routing.py'))


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
    LATENCY.validate(config.get('latency_selection'))
    DOMAIN.validate(config.get('domain_routes'),config['servers'])
    return config


class Router:
    """Routes only before any application bytes; never replays payload on failure."""
    def __init__(self,config):
        self.config=config;self.stop=threading.Event();self.lock=threading.RLock()
        self.status={s['name']:{'endpoint':s['endpoint'],'healthy':False,'successes':0,'failures':0,'last_check':None,'last_error':'not checked'} for s in config['servers']}
        self.active=set();self.sessions=0;self.counts={s['name']:0 for s in config['servers']};self.slots=threading.BoundedSemaphore(128)
        self.preference=None
        self.performance_order=[];self.performance_status={}
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
            if self.performance_order:
                positions={name:i for i,name in enumerate(self.performance_order)}
                servers.sort(key=lambda s:positions.get(s['name'],len(positions)+list(self.status).index(s['name'])))
            if self.preference:servers.sort(key=lambda s:s['name']!=self.preference)
            return servers
    def snapshot(self):
        with self.lock:
            choices=self.candidates()
            return {'preferred_available':choices[0]['name'] if choices else None,'servers':{k:dict(v) for k,v in self.status.items()},'active_sessions':self.sessions,'accepted_by_server':dict(self.counts),'latency_selection':dict(self.performance_status)}
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
    state_lock=threading.Lock();state_thread=None
    latency_file=base/'latency-state.json';latency_lock=threading.Lock();latency_thread=None
    latency_policy=LATENCY.validate(config.get('latency_selection'))
    latency_cache=None
    if latency_policy['enabled'] and latency_file.exists():
        try:latency_cache=json.loads(latency_file.read_text())
        except (ValueError,OSError):pass
    latency=LATENCY.Selection(latency_policy,config['servers'],latency_cache)
    latency_running=False;latency_error=''
    domain_config=DOMAIN.validate(config.get('domain_routes'),config['servers'])
    domain_file=base/'domain-state.json';domain_cache=None
    if domain_config and domain_file.exists():
        try:domain_cache=json.loads(domain_file.read_text())
        except (ValueError,OSError):pass
    domains=DOMAIN.Routes(domain_config,config['servers'],domain_cache) if domain_config else None
    domain_threads=[];domain_write_lock=threading.Lock();http_front=None
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
        with state_lock:
            with process_lock:health_children=[{'pid':p.pid,'endpoint':endpoint,'port':port} for endpoint,port,p in children.values()]
            with latency_lock:
                order=[] if domains else latency.route_order(time.time());summary=latency.summary(time.time(),latency_running,latency_error)
                if domains:summary=dict(summary,enabled=False,suspended_reason='domain_groups_use_independent_default_first_probes')
            with router.lock:router.performance_order=order;router.performance_status=summary
            data=router.snapshot()
            if domains:
                data['domain_routes']=domains.summary({n:v['healthy'] for n,v in data['servers'].items()})
                data['http_front_pid']=os.getpid() if http_front else None
                data['preferred_available']=data['domain_routes']['groups']['ordinary']['preferred_available']
            data.update(manager_pid=os.getpid(),selector='127.0.0.1:18900',ready=ready,health_clients=health_children,updated_at=time.time(),mode='domain-scoped-failover' if domains else 'automatic-latency-failover' if latency_policy['enabled'] else 'automatic-primary-backup',preference=router.preference)
            write_json(statefile,data)
    def heartbeat():
        # Slow PAC/HTTPS reconciliation must not hide live backend health changes.
        while not router.stop.wait(1):state()
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
    def latency_sample(server):
        with process_lock:
            if router.stop.is_set():return {'ok':False,'response_ms':None,'error':'stopping'}
            _,port,child=children[server['name']]
            if child.poll() is not None:return {'ok':False,'response_ms':None,'error':'health client unavailable'}
            process=subprocess.Popen(LATENCY.curl_arguments(port,latency_policy,config['connect_timeout_seconds']),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            probe_processes.add(process)
        try:
            try:
                output,error=process.communicate(timeout=latency_policy['timeout_seconds']+2)
            except subprocess.TimeoutExpired:
                process.kill();output,error=process.communicate()
            return LATENCY.parse_sample(process.returncode,output.decode(),error.decode())
        finally:
            with process_lock:probe_processes.discard(process)
    def latency_poll():
        nonlocal latency_running,latency_error
        # Initial startup waits for availability checks; performance cannot make a failed backend healthy.
        while not router.stop.is_set():
            if any(v['healthy'] for v in router.snapshot()['servers'].values()):break
            router.stop.wait(1)
        while not router.stop.is_set():
            with latency_lock:delay=latency.seconds_until_due(time.time());number=latency.round_count
            if delay>0:
                if router.stop.wait(min(delay,5)):break
                continue
            if router.stop.is_set():break
            start=time.time()
            with latency_lock:latency_running=True;latency_error=''
            try:
                measurement=LATENCY.measure(config['servers'],latency_policy,latency_sample,router.stop,number)
                if measurement is None:break
                healthy={name:v['healthy'] for name,v in router.snapshot()['servers'].items()}
                with latency_lock:
                    record=latency.complete(measurement,healthy,start,time.time())
                    write_json(latency_file,latency.cache())
                print(json.dumps({'event':'latency_selection','selected':record['selected'],'changed':record['selection_changed'],'reason':record['reason']}),flush=True)
            except Exception as error:
                with latency_lock:
                    latency_error=type(error).__name__
                    latency.next_probe_at=start+latency_policy['interval_seconds']
                print(json.dumps({'event':'latency_error','error':type(error).__name__}),flush=True)
            finally:
                with latency_lock:latency_running=False
    def domain_sample(server_name,target):
        import tempfile
        with tempfile.TemporaryDirectory(prefix='domain-probe-') as temporary:
            body_path=Path(temporary)/'body'
            with process_lock:
                if router.stop.is_set():return {'state':'unreachable','response_ms':None,'reason':'stopping'}
                _,port,child=children[server_name]
                if child.poll() is not None:return {'state':'unreachable','response_ms':None,'reason':'backend_client_exited'}
                command=['/usr/bin/curl','--silent','--show-error','--noproxy','','--proxy','http://127.0.0.1:'+str(port),
                         '--connect-timeout','3','--max-time','12','--max-filesize','65536','--proto','=https',
                         '--output',str(body_path),'--write-out','%{http_code}|%{ssl_verify_result}|%{time_starttransfer}']
                if target.get('method')=='HEAD':command+=['--head']
                command+=['--',target['url']]
                process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE);probe_processes.add(process)
            try:
                try:output,error=process.communicate(timeout=14)
                except subprocess.TimeoutExpired:process.kill();output,error=process.communicate()
                fields=output.decode().strip().split('|')
                if len(fields)!=3:return {'state':'unreachable','response_ms':None,'reason':'invalid_probe_output'}
                body=body_path.read_bytes()[:65536].decode('utf-8',errors='replace') if body_path.exists() else ''
                result=DOMAIN.classify_probe(process.returncode,fields[0],fields[1],body,fields[2],target['reachable_status_codes'])
                result['url']=target['url'];result['method']=target.get('method','GET')
                return result
            finally:
                with process_lock:probe_processes.discard(process)
    def domain_poll(group):
        g=domain_config['groups'][group];last_request=domains.groups[group].get('last_manual_request')
        while not router.stop.is_set():
            request=None
            try:
                request_file=base/'domain-probe-request.json'
                if request_file.exists():request=json.loads(request_file.read_text()).get(group)
            except (OSError,ValueError):pass
            if request!=last_request and request is not None:
                delay=0;last_request=request
                with domains.lock:domains.groups[group]['last_manual_request']=request
            else:delay=domains.due_in(group,time.time())
            if delay>0:
                if router.stop.wait(min(delay,5)):break
                continue
            start=time.time();domains.begin(group);rows={n:[] for n in g['probe_servers']}
            try:
                for _ in range(3):
                    for name in g['probe_servers']:
                        if router.stop.is_set():return
                        samples=[domain_sample(name,t) for t in g['probes']]
                        ranked={'policy_denied':3,'unreachable':2,'unknown':1,'reachable':0}
                        worst=max(samples,key=lambda v:ranked[v['state']])
                        combined={'state':worst['state'],'reason':worst['reason'],'response_ms':sum(v['response_ms'] for v in samples)/len(samples) if all(v['state']=='reachable' for v in samples) else None,
                                  'endpoint_results':samples,'application_access_proven':False}
                        rows[name].append(combined)
                domains.complete(group,rows,start,time.time())
                with domain_write_lock:write_json(domain_file,domains.cache())
                print(json.dumps({'event':'domain_probe','group':group,'states':{n:v['state'] for n,v in domains.groups[group]['nodes'].items()}}),flush=True)
            except Exception as error:
                domains.fail_round(group,start,type(error).__name__)
                with domain_write_lock:write_json(domain_file,domains.cache())
                print(json.dumps({'event':'domain_probe_error','group':group,'error':type(error).__name__}),flush=True)
    try:
        for server in config['servers']:
            with socket.socket() as portprobe:portprobe.bind(('127.0.0.1',0));port=portprobe.getsockname()[1]
            child=ctl.start_client(server['endpoint'],port,False);children[server['name']]=(server['endpoint'],port,child)
        state()
        state_thread=threading.Thread(target=heartbeat,daemon=True);state_thread.start()
        for server in config['servers']:
            thread=threading.Thread(target=probe,args=(server,),daemon=True);probe_threads.append(thread);thread.start()
        if latency_policy['enabled'] and not domains:
            latency_thread=threading.Thread(target=latency_poll,daemon=True);latency_thread.start()
        if domains:
            # Explicit HTTP front owns8888 only after every per-backend client is listening.
            ctl.stop_client()
            def backend(name):
                with process_lock:return ('127.0.0.1',children[name][1])
            http_front=DOMAIN.HTTPFront(domains,backend,lambda:{n:v['healthy'] for n,v in router.snapshot()['servers'].items()})
            http_front.start()
            for group in domain_config['groups']:
                thread=threading.Thread(target=domain_poll,args=(group,),daemon=True);domain_threads.append(thread);thread.start()
        previous_choice=None;last_reconcile=0
        while not router.stop.is_set():
            if (base/'multi-paused').exists():pausing=True;break
            preference=(base/'multi-preferred').read_text().strip() if (base/'multi-preferred').exists() else ''
            with router.lock:router.preference=preference if preference in router.status else None
            choice=router.snapshot()['preferred_available']
            if domains:
                preference_file=base/'domain-preferred.json'
                try:domains.set_manual(json.loads(preference_file.read_text()) if preference_file.exists() else {})
                except (ValueError,OSError):domains.set_manual({})
                domain_choices=domains.summary({n:v['healthy'] for n,v in router.snapshot()['servers'].items()})
                ordinary_choice=domain_choices['groups']['ordinary']['preferred_available']
                if ordinary_choice and time.monotonic()-last_reconcile>10:
                    last_reconcile=time.monotonic()
                    try:
                        ctl.save({'mode':'domain','server':'127.0.0.1:8888','servers':[s['endpoint'] for s in config['servers']]})
                        pac.start(pac.state())
                        if not ready:
                            result=subprocess.run([sys.executable,str(base/'community-pac/community-control.py'),'apply'],capture_output=True,text=True,timeout=40)
                            if result.returncode:raise RuntimeError('PAC apply failed')
                        ready=True
                    except Exception as error:
                        ready=False;print(json.dumps({'event':'domain_reconcile_error','error':type(error).__name__}),flush=True)
                if not ordinary_choice or not ctl.listening(8888) or not pac.listening(8090):ready=False
                router.stop.wait(1);continue
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
            router.stop.wait(1)
    finally:
        router.close();listener.close()
        if http_front:http_front.close()
        if state_thread:state_thread.join(timeout=3)
        with process_lock:
            for process in list(probe_processes):
                if process.poll() is None:process.terminate()
        for thread in probe_threads:thread.join(timeout=config['probe_timeout_seconds']+3)
        if latency_thread:latency_thread.join(timeout=latency_policy['timeout_seconds']+3)
        for thread in domain_threads:thread.join(timeout=16)
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
