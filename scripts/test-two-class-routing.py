#!/usr/bin/env python3
"""Two-class and strict geography oracle; isolated, no network or production writes."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
D=load('two_domain',ROOT/'scripts/domain-routing.py')
M=load('two_migration',ROOT/'scripts/two-class-routing.py')
CONFIG=json.loads((ROOT/'examples/multi-server/domain-server.example.json').read_text())
POLICY=M.POLICY

def good(country='US',ip='8.8.8.8'):
    return [dict(source=s,country=country,ip=ip,valid=True) for s in ['cloudflare','ipinfo']]
def service(state='reachable'):
    return dict(state=state,response_ms=100 if state=='reachable' else None)

class Tests(unittest.TestCase):
    def setUp(self):
        self.cfg=copy.deepcopy(CONFIG)
        self.routes=D.Routes(self.cfg['domain_routes'],self.cfg['servers'])
        self.health={s['name']:True for s in self.cfg['servers']}
        self.now=10000
        self.clock=mock.patch.object(D.time,'time',return_value=self.now);self.clock.start()
    def tearDown(self):self.clock.stop()
    def test_two_groups_and_domains(self):
        self.assertEqual(set(self.routes.groups),{'ordinary','overseas_ai'})
        for host in ['auth.openai.com','chatgpt.com','ws.chatgpt.com','api.anthropic.com','claude.ai','cdn.workos.com']:
            self.assertEqual(self.routes.group_for(host),'overseas_ai')
        for host in ['github.com','google.com','notopenai.com','openai.com.attacker.com','www.doubao.com']:
            self.assertEqual(self.routes.group_for(host),'ordinary')
    def test_unknown_denied_ordinary_unchanged(self):
        self.assertEqual(self.routes.candidates('overseas_ai',self.health),[])
        self.assertEqual(self.routes.candidates('ordinary',self.health)[0]['name'],'backup')
    def test_HK_MO_excluded_even_manual(self):
        for country in ['HK','MO']:
            self.routes.set_egress('primary',good(country),self.now)
            self.routes.set_manual({'overseas_ai':'primary'})
            self.assertEqual(self.routes.candidates('overseas_ai',self.health),[])
    def test_verified_default_preserved(self):
        self.routes.set_egress('primary',good('US'),self.now)
        self.routes.set_egress('backup2',good('SG'),self.now)
        self.assertEqual(self.routes.candidates('overseas_ai',self.health)[0]['name'],'primary')
    def test_fallback_requires_verified_country(self):
        self.routes.set_egress('primary',good('HK'),self.now)
        self.routes.set_egress('backup2',good('SG'),self.now)
        self.assertEqual(self.routes.candidates('overseas_ai',self.health)[0]['name'],'backup2')
    def test_one_source_not_enough(self):
        self.routes.set_egress('primary',good()[:1],self.now)
        self.assertEqual(self.routes.candidates('overseas_ai',self.health),[])
    def test_country_and_ip_consensus(self):
        for field,value in [('country','SG'),('ip','1.1.1.1')]:
            samples=good();samples[1][field]=value
            self.assertEqual(D.egress_consensus(samples,POLICY,self.now)['state'],'unknown')
    def test_duplicate_source_rejected(self):
        samples=good();samples[1]['source']='cloudflare'
        self.assertEqual(D.egress_consensus(samples,POLICY,self.now)['state'],'unknown')
    def test_expired_and_future_evidence(self):
        for when in [self.now-3600,self.now+1]:
            self.routes.set_egress('primary',good(),when)
            self.assertFalse(self.routes.egress_status('primary')['eligible'])
    def test_geography_never_reused_from_cache(self):
        self.routes.set_egress('primary',good(),self.now)
        cache=self.routes.cache();cache['egress']={'primary':dict(state='verified',country='US',checked_at=self.now)}
        new=D.Routes(self.cfg['domain_routes'],self.cfg['servers'],cache)
        self.assertEqual(new.candidates('overseas_ai',self.health),[])
    def test_failure_invalidates_previous(self):
        self.routes.set_egress('primary',good(),self.now)
        self.routes.set_egress('primary',[],self.now)
        self.assertEqual(self.routes.candidates('overseas_ai',self.health),[])
    def test_any_service_failure_excludes_whole_group(self):
        self.routes.set_egress('primary',good(),self.now)
        self.routes.complete('overseas_ai',{'primary':[service('unreachable')]*3},self.now-10,self.now)
        self.assertEqual(self.routes.candidates('overseas_ai',self.health),[])
    def test_policy_requires_strict_values(self):
        for field,value in [('unknown_action','allow'),('denied_country_codes',['HK']),('max_age_seconds',9999)]:
            cfg=copy.deepcopy(self.cfg['domain_routes']);cfg['egress_policy'][field]=value
            with self.assertRaises(ValueError):D.validate(cfg,self.cfg['servers'])
    def test_tls_and_status_parser(self):
        body='ip=8.8.8.8\nloc=US\n'
        self.assertTrue(D.parse_egress('cloudflare',0,'200','0',body)['valid'])
        for exit,status,tls in [(28,'200','0'),(0,'403','0'),(0,'200','60')]:
            self.assertFalse(D.parse_egress('cloudflare',exit,status,tls,body)['valid'])
    def test_bad_data_private_ip_unknown(self):
        for body in ['ip=127.0.0.1\nloc=US','ip=8.8.8.8\nloc=ZZ','ip=8.8.8.8\nloc=US\nloc=SG']:
            self.assertFalse(D.parse_egress('cloudflare',0,'200','0',body)['valid'])
        self.assertFalse(D.parse_egress('ipinfo',0,'200','0','not-json')['valid'])
    def test_cli_manual_rejects_unknown_and_accepts_verified(self):
        import tempfile, subprocess
        from datetime import datetime
        clock=lambda:datetime.now().timestamp()
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);(base/'multi-server.json').write_text(json.dumps(self.cfg))
            path=base/'domain-preferred.json';path.write_text('{}')
            args=['/usr/bin/python3',str(ROOT/'scripts/multi-autostart-control.py'),'route','--runtime',str(base),'--group','overseas_ai','--server','primary']
            state={'updated_at':clock(),'domain_routes':{'egress_verification':{'nodes':{'primary':{'state':'unknown','eligible':False,'checked_at':clock()}}}}}
            (base/'multi-state.json').write_text(json.dumps(state))
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertEqual(path.read_text(),'{}')
            state['domain_routes']['egress_verification']['nodes']['primary'].update(state='verified',eligible=True,country='US')
            (base/'multi-state.json').write_text(json.dumps(state))
            self.assertEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertEqual(json.loads(path.read_text()),{'overseas_ai':'primary'})
    def test_migration_preserves_all_and_conflict_rejected(self):
        shared=self.cfg['domain_routes']['groups']['overseas_ai'];old=copy.deepcopy(self.cfg)
        old['domain_routes'].pop('egress_policy')
        openai=copy.deepcopy(shared);claude=copy.deepcopy(shared)
        openai['suffixes']=['openai.com'];claude['suffixes']=['claude.ai']
        openai['exact_hosts']=[];claude['exact_hosts']=[]
        openai['probes']=shared['probes'][:2];claude['probes']=shared['probes'][2:]
        old['domain_routes']['groups']={'ordinary':old['domain_routes']['groups']['ordinary'],'openai':openai,'claude':claude}
        new,manual=M.migrate(old,{'ordinary':'backup2','openai':'primary'})
        self.assertEqual(new['domain_routes']['groups']['overseas_ai']['suffixes'],['openai.com','claude.ai'])
        self.assertEqual(len(new['domain_routes']['groups']['overseas_ai']['probes']),3)
        self.assertEqual(manual,{'ordinary':'backup2','overseas_ai':'primary'})
        with self.assertRaises(ValueError):M.migrate(old,{'openai':'primary','claude':'backup2'})

if __name__=='__main__':unittest.main()
