#!/usr/bin/env python3
"""Deterministic latency-policy tests; real 1800-second boundaries through a controlled clock."""
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

ROOT=Path(__file__).resolve().parent.parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v

L=module('latency',ROOT/'scripts/latency-selection.py')
M=module('manager',ROOT/'scripts/multi-server-manager.py')
SERVERS=[{'name':n,'endpoint':'192.0.2.'+str(i+1)+':8080'} for i,n in enumerate(['primary','backup','backup2'])]
POLICY=dict(L.DEFAULTS,enabled=True)


def sample(ms):return {'ok':True,'response_ms':float(ms)}

def measurement(scores):
    values={name:iter(v) for name,v in scores.items()}
    return L.measure(SERVERS,POLICY,lambda s:sample(next(values[s['name']])),threading.Event())


class LatencyTests(unittest.TestCase):
    def setUp(self):self.selection=L.Selection(POLICY,SERVERS);self.health={s['name']:True for s in SERVERS}
    def test_parse_tls_status_timeout_invalid_metrics(self):
        self.assertEqual(L.parse_sample(0,'204|1.25|0')['response_ms'],1250)
        for args in [(28,'204|1|0'),(0,'204|1|60'),(0,'200|1|0'),(0,'302|1|0'),(0,'204|nan|0'),(0,'204|inf|0'),(0,'204|0|0'),(0,'204|-1|0'),(0,'bad')]:
            self.assertFalse(L.parse_sample(*args)['ok'],args)
    def test_validation_and_disabled_compatibility(self):
        self.assertFalse(L.validate(None)['enabled'])
        for delta in [{'interval_seconds':60},{'samples':True},{'min_successful_samples':4},{'url':'http://www.google.com/generate_204'},{'url':'https://www.google.com.evil/generate_204'},{'switch_improvement_ratio':float('nan')},{'unknown':1}]:
            with self.assertRaises(ValueError):L.validate(dict(POLICY,**delta))
    def test_median_success_quorum_interleaved_order(self):
        i={n:iter([100,10000,200]) for n in self.health}
        r=L.measure(SERVERS,POLICY,lambda s:sample(next(i[s['name']])),threading.Event(),1)
        self.assertEqual(r['execution_order'],['backup','backup2','primary']*3)
        self.assertTrue(all(row['median_response_ms']==200 for row in r['measurements']))
        counts={n:0 for n in self.health}
        def probe(s):
            n=s['name'];counts[n]+=1
            return sample(300) if counts[n]==1 else {'ok':False,'response_ms':None}
        bad=L.measure(SERVERS,POLICY,probe,threading.Event());self.assertTrue(all(not row['valid'] for row in bad['measurements']))
    def test_three_round_boundaries_and_no_catchup_burst(self):
        r=measurement({n:[1000,1100,900] for n in self.health})
        self.selection.complete(r,self.health,100,110)
        self.assertEqual(self.selection.next_probe_at,1900)
        self.assertEqual(self.selection.seconds_until_due(1899),1)
        self.assertEqual(self.selection.seconds_until_due(1900),0)
        second=measurement({'primary':[1000]*3,'backup':[500]*3,'backup2':[800]*3})
        self.selection.complete(second,self.health,1900,1910)
        self.assertEqual(self.selection.selected,'backup');self.assertEqual(self.selection.next_probe_at,3700)
        third=measurement({'primary':[200]*3,'backup':[500]*3,'backup2':[800]*3})
        self.selection.complete(third,self.health,3700,3710)
        self.assertEqual(self.selection.selected,'primary');self.assertEqual(self.selection.next_probe_at,5500)
        self.selection.complete(third,self.health,5500,10000)
        self.assertGreater(self.selection.next_probe_at,10000)
        self.assertLessEqual(self.selection.next_probe_at-10000,1800)
    def test_hysteresis_requires_both_thresholds(self):
        r=measurement({'primary':[1000]*3,'backup':[1100]*3,'backup2':[1200]*3})
        self.selection.complete(r,self.health,100,110)
        for ms in [990,910,860]:
            self.selection.complete(measurement({'primary':[1000]*3,'backup':[ms]*3,'backup2':[1200]*3}),self.health,1900,1910)
            self.assertEqual(self.selection.selected,'primary')
        self.selection.complete(measurement({'primary':[1000]*3,'backup':[850]*3,'backup2':[1200]*3}),self.health,3700,3710)
        self.assertEqual(self.selection.selected,'backup')
        small=L.Selection(POLICY,SERVERS)
        small.complete(measurement({'primary':[300]*3,'backup':[400]*3,'backup2':[500]*3}),self.health,100,110)
        small.complete(measurement({'primary':[300]*3,'backup':[250]*3,'backup2':[500]*3}),self.health,1900,1910)
        self.assertEqual(small.selected,'primary')
    def test_health_is_not_changed_by_latency(self):
        health=dict(self.health,backup=False)
        self.selection.complete(measurement({'primary':[1000]*3,'backup':[100]*3,'backup2':[600]*3}),health,100,110)
        self.assertEqual(self.selection.selected,'backup2');self.assertNotIn('backup',self.selection.ranking)
        self.assertFalse(health['backup'])
    def test_all_failed_retains_recent_ranking_then_expires(self):
        self.selection.complete(measurement({'primary':[1000]*3,'backup':[500]*3,'backup2':[800]*3}),self.health,100,110)
        bad={'measurements':[{'name':n,'valid':False,'median_response_ms':None,'samples':[]} for n in self.health]}
        self.selection.complete(bad,self.health,1900,1910)
        self.assertEqual(self.selection.selected,'backup');self.assertEqual(self.selection.last_round['reason'],'no_valid_healthy_measurements')
        self.assertEqual(self.selection.route_order(1910)[0],'backup');self.assertEqual(self.selection.route_order(3711),[])
    def test_cache_preserves_due_and_rejects_changed_endpoints(self):
        self.selection.complete(measurement({'primary':[1000]*3,'backup':[500]*3,'backup2':[800]*3}),self.health,100,110)
        restored=L.Selection(POLICY,SERVERS,json.loads(json.dumps(self.selection.cache())))
        self.assertEqual(restored.next_probe_at,1900);self.assertEqual(restored.selected,'backup');self.assertEqual(restored.seconds_until_due(120),1780)
        changed=copy.deepcopy(SERVERS);changed[0]['endpoint']='192.0.2.10:8080'
        self.assertIsNone(L.Selection(POLICY,changed,self.selection.cache()).selected)
        self.assertIsNone(L.Selection(POLICY,SERVERS,[]).selected)
        corrupt=self.selection.cache();corrupt['selected']='foreign'
        self.assertIsNone(L.Selection(POLICY,SERVERS,corrupt).selected)
    def test_history_bounded_and_cache_empty(self):
        r=measurement({n:[1000]*3 for n in self.health})
        for i in range(60):self.selection.complete(r,self.health,i*1800,i*1800+10)
        self.assertEqual(len(self.selection.history),48);self.assertEqual(self.selection.round_count,60)
    def test_cancellation_does_not_publish_partial_round(self):
        stop=threading.Event()
        def cancel(s):stop.set();return sample(1)
        self.assertIsNone(L.measure(SERVERS,POLICY,cancel,stop))
    def test_manual_preference_health_filter_and_disabled_policy(self):
        cfg={'version':1,'listen':['127.0.0.1',18900],'servers':SERVERS,'probe_seconds':10,'probe_timeout_seconds':8,'connect_timeout_seconds':3,'failure_threshold':2,'recovery_threshold':2}
        router=M.Router(M.validate(cfg))
        for n in self.health:router.health(n,True);router.health(n,True)
        router.performance_order=['backup','primary','backup2']
        self.assertEqual(router.candidates()[0]['name'],'backup')
        router.preference='primary';self.assertEqual(router.candidates()[0]['name'],'primary')
        router.preference=None;router.health('backup',False);router.health('backup',False)
        self.assertEqual(router.candidates()[0]['name'],'primary')
        router.health('primary',False);router.health('primary',False)
        self.assertEqual(router.candidates()[0]['name'],'backup2')
        router.performance_order=[];self.assertEqual(router.candidates()[0]['name'],'backup2')
    def test_disabled_policy_keeps_static_order(self):
        disabled=L.Selection(dict(POLICY,enabled=False),SERVERS)
        disabled.complete(measurement({'primary':[1000]*3,'backup':[200]*3,'backup2':[800]*3}),self.health,100,110)
        self.assertEqual(disabled.route_order(120),[])
    def test_mutant_sensitivity_fastest_and_TLS(self):
        from unittest.mock import patch
        with patch.object(L,'parse_sample',lambda *args: {'ok':True,'response_ms':1}):
            with self.assertRaises(AssertionError):self.test_parse_tls_status_timeout_invalid_metrics()
        original=L.Selection.complete
        def worst(obj,*args):
            record=original(obj,*args);obj.selected='backup2';return record
        with patch.object(L.Selection,'complete',worst):
            with self.assertRaises(AssertionError):self.test_three_round_boundaries_and_no_catchup_burst()
    def test_latency_query_does_not_change_manual_preference(self):
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);(b/'multi-preferred').write_text('backup2\n')
            (b/'multi-state.json').write_text(json.dumps({'preferred_available':'backup2','preference':'backup2','updated_at':0,'latency_selection':{'enabled':True}}))
            result=subprocess.run(['python3',str(ROOT/'scripts/multi-autostart-control.py'),'latency','--runtime',str(b)],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(json.loads(result.stdout)['latency_selection']['enabled'])
            self.assertEqual((b/'multi-preferred').read_text(),'backup2\n')


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            body=self.request.recv(1024)
            if not body:break
            self.request.sendall(self.server.marker+body)


class LiveRelayTests(unittest.TestCase):
    def test_latency_reorders_new_connections_not_existing_payload(self):
        servers=[];router=None;listener=None;old=None
        try:
            endpoints=[]
            for n,marker in [('primary',b'P:'),('backup',b'B:')]:
                s=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo);s.daemon_threads=True;s.marker=marker
                threading.Thread(target=s.serve_forever,daemon=True).start();servers.append(s)
                endpoints.append({'name':n,'endpoint':'127.0.0.1:'+str(s.server_address[1])})
            cfg={'version':1,'listen':['127.0.0.1',18900],'servers':endpoints,'probe_seconds':10,'probe_timeout_seconds':8,'connect_timeout_seconds':1,'failure_threshold':2,'recovery_threshold':2}
            router=M.Router(M.validate(cfg))
            for n in ['primary','backup']:router.health(n,True);router.health(n,True)
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(.1)
            threading.Thread(target=router.accept,args=(listener,),daemon=True).start()
            old=socket.create_connection(listener.getsockname(),timeout=2);old.settimeout(2);old.sendall(b'one');self.assertEqual(old.recv(32),b'P:one')
            router.performance_order=['backup','primary']
            with socket.create_connection(listener.getsockname(),timeout=2) as new:
                new.sendall(b'two');self.assertEqual(new.recv(32),b'B:two')
            old.sendall(b'three');self.assertEqual(old.recv(32),b'P:three')
        finally:
            if old:old.close()
            if router:router.close()
            if listener:listener.close()
            for s in servers:s.shutdown();s.server_close()

if __name__=='__main__':unittest.main()
