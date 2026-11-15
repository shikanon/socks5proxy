#!/usr/bin/env python3
"""Isolated HTTP domain routing tests; no production proxies, accounts or network settings."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import unittest
import time
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('domain',ROOT/'scripts/domain-routing.py')
D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
SERVERS=[{'name':'primary','endpoint':'192.0.2.1:8080'},{'name':'backup','endpoint':'192.0.2.2:8080'},{'name':'backup2','endpoint':'192.0.2.3:8080'}]
CONFIG={'version':1,'enabled':True,'listen':['127.0.0.1',8888],'interval_seconds':1800,'groups':{
 'ordinary':{'default_server':'backup','allowed_servers':['backup','primary','backup2'],'probe_servers':['backup','primary','backup2'],'suffixes':[],'exact_hosts':[],'probes':[{'url':'https://www.google.com/generate_204','reachable_status_codes':[204]}]},
 'openai':{'default_server':'primary','allowed_servers':['primary','backup','backup2'],'probe_servers':['primary','backup','backup2'],'suffixes':['openai.com','chatgpt.com'],'exact_hosts':['humb.apple.com'],'probes':[{'url':'https://api.openai.com/v1/models','reachable_status_codes':[401]}]},
 'claude':{'default_server':'primary','allowed_servers':['primary','backup','backup2'],'probe_servers':['primary','backup','backup2'],'suffixes':['claude.ai','anthropic.com'],'exact_hosts':['cdn.workos.com'],'probes':[{'url':'https://api.anthropic.com/v1/messages','reachable_status_codes':[405]}]}}}


def sample(state='reachable',ms=100):return {'state':state,'response_ms':ms if state=='reachable' else None,'reason':'test','application_access_proven':False}


class UnitTests(unittest.TestCase):
    def setUp(self):self.r=D.Routes(copy.deepcopy(CONFIG),SERVERS);self.health={s['name']:True for s in SERVERS}
    def test_default_nodes_domain_boundary_and_case(self):
        for host in ['openai.com','auth.openai.com','API.OPENAI.COM.','chatgpt.com','humb.apple.com']:
            self.assertEqual(self.r.group_for(host),'openai')
        for host in ['claude.ai','api.anthropic.com','cdn.workos.com']:self.assertEqual(self.r.group_for(host),'claude')
        for host in ['openai.com.attacker.com','notopenai.com','foo.humb.apple.com','github.com','www.google.com']:self.assertEqual(self.r.group_for(host),'ordinary')
        self.assertEqual(self.r.candidates('ordinary',self.health)[0]['name'],'backup')
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'primary')
    def test_group_default_is_not_overridden_by_lower_latency(self):
        self.r.complete('openai',{'primary':[sample(ms=1000)]*3,'backup':[sample(ms=100)]*3},100,110)
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'primary')
        self.r.set_manual({'openai':'backup'})
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'backup')

    def test_auth_failures_not_application_success(self):
        for code in ['401','405']:
            v=D.classify_probe(0,code,'0','{"error":{"code":null}}','1.1',[int(code)])
            self.assertEqual(v['state'],'reachable');self.assertFalse(v['application_access_proven'])
        for code in ['403','429']:
            self.assertEqual(D.classify_probe(0,code,'0','error','1',[401])['state'],'unknown')
        self.assertEqual(D.classify_probe(28,'200','0','', '1',[200])['state'],'unreachable')
        self.assertEqual(D.classify_probe(0,'200','60','', '1',[200])['state'],'unreachable')
    def test_region_denial_failover_is_group_local(self):
        v=D.classify_probe(0,'403','0','{"error":{"code":"unsupported_country_region_territory"}}','1',[401])
        self.assertEqual(v['state'],'policy_denied')
        self.r.complete('openai',{'primary':[sample('policy_denied')]*3,'backup':[sample()]*3},100,110)
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'backup')
        self.assertEqual(self.r.candidates('claude',self.health)[0]['name'],'primary')
        self.assertEqual(self.r.candidates('ordinary',self.health)[0]['name'],'backup')
        self.assertEqual(self.r.groups['claude']['round_count'],0)
    def test_manual_independent_and_fail_closed_candidates(self):
        self.r.set_manual({'ordinary':'backup2','claude':'backup'})
        self.assertEqual(self.r.candidates('ordinary',self.health)[0]['name'],'backup2')
        self.assertEqual(self.r.candidates('claude',self.health)[0]['name'],'backup')
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'primary')
        self.r.complete('openai',{n:[sample('policy_denied')]*3 for n in self.health},100,110)
        self.assertEqual(self.r.candidates('openai',self.health),[])
    def test_probe_unknown_does_not_exclude_default(self):
        self.r.complete('openai',{'primary':[sample('unknown')]*3},100,110)
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'primary')
    def test_quorum_independent_schedule_and_cache(self):
        self.r.complete('ordinary',{'backup':[sample(),sample(),sample('unknown')]},100,110)
        self.assertEqual(self.r.groups['ordinary']['nodes']['backup']['state'],'reachable')
        self.assertEqual(self.r.due_in('ordinary',1899),1);self.assertEqual(self.r.due_in('ordinary',1900),0)
        self.assertEqual(self.r.due_in('openai',100),0)
        restored=D.Routes(CONFIG,SERVERS,json.loads(json.dumps(self.r.cache())))
        self.assertEqual(restored.due_in('ordinary',1899),1)
        self.assertEqual(restored.candidates('ordinary',self.health)[0]['name'],'backup')
        changed=copy.deepcopy(CONFIG);changed['groups']['ordinary']['default_server']='backup2'
        self.assertEqual(D.Routes(changed,SERVERS,self.r.cache()).groups['ordinary']['round_count'],0)
    def test_parser_and_invalid_framing(self):
        self.assertEqual(D.request_info(b'CONNECT AUTH.OPENAI.COM:443 HTTP/1.1\r\nHost: auth.openai.com:443\r\n\r\n')['host'],'auth.openai.com')
        self.assertEqual(D.request_info(b'GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n')['host'],'example.com')
        self.assertEqual(D.authority('[::1]:443'),('::1',443))
        for data in [b'CONNECT a:443 HTTP/1.1\r\nHost: b:443\r\n\r\n',b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',b'CONNECT a:443 HTTP/1.1\r\nContent-Length: 10\r\n\r\n',b'POST http://example.com/ HTTP/1.1\r\nContent-Length:1\r\nTransfer-Encoding: chunked\r\n\r\n',b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nHost: b\r\n\r\n']:
            with self.assertRaises(ValueError):D.request_info(data)
    def test_header_limit_pending_and_config_rejection(self):
        a,b=socket.socketpair()
        try:
            b.sendall(b'CONNECT a:443 HTTP/1.1\r\n\r\nTLS-data')
            header,pending=D.read_header(a);self.assertEqual(pending,b'TLS-data')
        finally:a.close();b.close()
        for value in [[],{'enabled':True,'version':9}]:
            with self.assertRaises(ValueError):D.validate(value,SERVERS)
        cfg=copy.deepcopy(CONFIG);cfg['groups']['openai']['suffixes'].append('doubao.com')
        with self.assertRaises(ValueError):D.validate(cfg,SERVERS)
    def test_special_probe_independent_of_google_and_transport_cooldown(self):
        self.health['primary']=False
        self.r.complete('openai',{'primary':[sample()]*3},time.time()-10,time.time())
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'primary')
        self.r.transport_failure('openai','primary')
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'backup')
        self.assertEqual(self.r.candidates('claude',{n:True for n in self.health})[0]['name'],'primary')
        self.r.transport_success('openai','primary')
        self.assertEqual(self.r.candidates('openai',self.health)[0]['name'],'primary')
    def test_no_sleep_catchup_burst(self):
        self.r.complete('ordinary',{'backup':[sample()]*3},100,6000)
        self.assertEqual(self.r.groups['ordinary']['next_probe_at'],7300)
        self.assertEqual(self.r.due_in('ordinary',7000),300)
    def test_total_header_deadline_and_oversize(self):
        for payload in [b'A'*32769,b'CONNECT a:443 HTTP/1.1\r\nX:'+b'A'*32769+b'\r\n\r\n']:
            class Reader:
                def __init__(self):self.data=payload
                def settimeout(self,value):pass
                def recv(self,size):p=self.data[:size];self.data=self.data[size:];return p
            with self.assertRaises(ValueError):D.read_header(Reader())
        a,b=socket.socketpair()
        try:
            with self.assertRaises(socket.timeout):D.read_header(a,budget=.02)
        finally:a.close();b.close()
    def test_cli_group_controls_do_not_touch_other_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);(b/'multi-server.json').write_text(json.dumps({'domain_routes':CONFIG,'servers':SERVERS}))
            (b/'domain-preferred.json').write_text(json.dumps({'claude':'backup'}))
            def call(*args):return subprocess.run(['python3',str(ROOT/'scripts/multi-autostart-control.py'),*args,'--runtime',str(b)],capture_output=True,text=True,timeout=5)
            self.assertEqual(call('route','--group','ordinary','--server','backup2').returncode,0)
            self.assertEqual(json.loads((b/'domain-preferred.json').read_text()),{'ordinary':'backup2','claude':'backup'})
            self.assertEqual(call('route-auto','--group','ordinary').returncode,0)
            self.assertEqual(json.loads((b/'domain-preferred.json').read_text()),{'claude':'backup'})
            self.assertEqual(call('probe','--group','openai').returncode,0)
            self.assertEqual(list(json.loads((b/'domain-probe-request.json').read_text())),['openai'])
            self.assertNotEqual(call('route','--group','openai','--server','foreign').returncode,0)
            self.assertEqual(call('primary').returncode,0)
            self.assertEqual(json.loads((b/'domain-preferred.json').read_text()),{'ordinary':'primary','claude':'backup'})
            limited=copy.deepcopy(CONFIG);limited['groups']['ordinary']['allowed_servers']=['backup']
            (b/'multi-server.json').write_text(json.dumps({'domain_routes':limited,'servers':SERVERS}))
            before=(b/'domain-preferred.json').read_bytes()
            self.assertNotEqual(call('primary').returncode,0)
            self.assertEqual((b/'domain-preferred.json').read_bytes(),before)
            self.assertEqual(call('auto').returncode,0)
            self.assertEqual(json.loads((b/'domain-preferred.json').read_text()),{'claude':'backup'})


class MockHTTP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2);header,pending=D.read_header(self.request);info=D.request_info(header)
            self.server.requests.append(info)
            mode=getattr(self.server,'mode','echo')
            if mode=='reject':
                self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n');return
            if mode=='invalid':self.request.sendall(b'bad-response');return
            if info['method']=='CONNECT':
                self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                if mode=='close_after_commit':
                    self.server.payloads.append(self.request.recv(1024));return
                if mode=='half_close':
                    self.request.recv(5)
                    self.request.sendall(b'FIN');self.request.shutdown(socket.SHUT_WR)
                    while True:
                        part=self.request.recv(65536)
                        if not part:break
                        self.server.payloads.append(part)
                    self.server.done.set();return
                if pending:self.request.sendall(self.server.marker+pending)
                while True:
                    part=self.request.recv(1024)
                    if not part:break
                    self.request.sendall(self.server.marker+part)
            else:
                self.server.payloads.append(pending)
                if mode=='close_after_commit':return
                self.request.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length:2\r\n\r\nOK')
        except (OSError,ValueError):pass


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.mock={};self.routes=D.Routes(copy.deepcopy(CONFIG),SERVERS);self.health={s['name']:True for s in SERVERS}
        for name,marker in [('primary',b'P:'),('backup',b'B:'),('backup2',b'C:')]:
            s=socketserver.ThreadingTCPServer(('127.0.0.1',0),MockHTTP);s.daemon_threads=True;s.marker=marker;s.requests=[];s.payloads=[];s.done=threading.Event()
            threading.Thread(target=s.serve_forever,daemon=True).start();self.mock[name]=s
        self.front=D.HTTPFront(self.routes,lambda n:self.mock[n].server_address,lambda:self.health,listen=('127.0.0.1',0));self.front.start()
    def tearDown(self):
        self.front.close()
        for s in self.mock.values():s.shutdown();s.server_close()
    def connect(self,host):
        c=socket.create_connection(self.front.address,timeout=2);c.settimeout(2)
        c.sendall(('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+':443\r\n\r\n').encode())
        response,pending=D.read_header(c);self.assertIn(b'200',response);return c
    def test_separate_domain_routes_and_existing_stream(self):
        old=self.connect('api.openai.com')
        try:
            old.sendall(b'one');self.assertEqual(old.recv(32),b'P:one')
            with self.connect('www.google.com') as c:c.sendall(b'two');self.assertEqual(c.recv(32),b'B:two')
            self.routes.set_manual({'openai':'backup2'})
            with self.connect('auth.openai.com') as c:c.sendall(b'new');self.assertEqual(c.recv(32),b'C:new')
            old.sendall(b'old');self.assertEqual(old.recv(32),b'P:old')
            with self.connect('claude.ai') as c:c.sendall(b'claude');self.assertEqual(c.recv(32),b'P:claude')
        finally:old.close()
    def test_ordinary_failure_leaves_special_unchanged(self):
        self.health['backup']=False
        with self.connect('www.google.com') as c:c.sendall(b'g');self.assertEqual(c.recv(32),b'P:g')
        with self.connect('api.openai.com') as c:c.sendall(b'a');self.assertEqual(c.recv(32),b'P:a')
    def test_no_candidate_HTTP503_not_direct(self):
        self.routes.complete('openai',{n:[sample('policy_denied')]*3 for n in self.health},100,110)
        with socket.create_connection(self.front.address,timeout=2) as c:
            c.sendall(b'CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n');header,_=D.read_header(c);self.assertIn(b'503',header)
        self.assertFalse(any(s.requests for s in self.mock.values()))
    def test_handshake_failure_retries_only_before_commit(self):
        self.mock['primary'].mode='reject'
        with self.connect('api.openai.com') as c:c.sendall(b'once');self.assertEqual(c.recv(32),b'B:once')
        self.assertEqual(len(self.mock['primary'].requests),1)
        self.assertEqual(len(self.mock['backup'].requests),1)
    def test_malformed_backend_response_can_try_next(self):
        self.mock['primary'].mode='invalid'
        with self.connect('api.openai.com') as c:c.sendall(b'ok');self.assertEqual(c.recv(32),b'B:ok')
    def test_committed_tunnel_bytes_never_replayed(self):
        self.mock['primary'].mode='close_after_commit'
        with self.connect('api.openai.com') as c:
            c.sendall(b'not-replayed');self.assertEqual(c.recv(32),b'')
        self.assertEqual(self.mock['primary'].payloads,[b'not-replayed'])
        self.assertFalse(self.mock['backup'].requests)
    def test_HTTP_post_never_replayed_after_header(self):
        self.mock['backup'].mode='close_after_commit'
        with socket.create_connection(self.front.address,timeout=2) as c:
            c.settimeout(2);c.sendall(b'POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length:4\r\n\r\nDATA');self.assertEqual(c.recv(32),b'')
        self.assertEqual(len(self.mock['backup'].requests),1)
        self.assertFalse(self.mock['primary'].requests)
    def test_half_close_does_not_truncate_upload(self):
        self.mock['primary'].mode='half_close'
        with self.connect('api.openai.com') as c:
            c.sendall(b'BEGIN')
            self.assertEqual(c.recv(32),b'FIN');self.assertEqual(c.recv(32),b'')
            payload=b'x'*131072;c.sendall(payload);c.shutdown(socket.SHUT_WR)
            self.assertTrue(self.mock['primary'].done.wait(2))
            self.assertEqual(b''.join(self.mock['primary'].payloads),payload)
    def test_front_close_releases_slots_and_connections(self):
        c=self.connect('api.openai.com');self.front.close()
        try:self.assertEqual(c.recv(32),b'')
        finally:c.close()
        for _ in range(20):
            if self.front.slots._value==128:break
            time.sleep(.05)
        self.assertEqual(self.front.slots._value,128)
    def test_absolute_HTTP_forwarding(self):
        with socket.create_connection(self.front.address,timeout=2) as c:
            c.sendall(b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n')
            response,_=D.read_header(c);self.assertIn(b'200',response)
        self.assertEqual(self.mock['backup'].requests[0]['host'],'example.com')

if __name__=='__main__':unittest.main()
