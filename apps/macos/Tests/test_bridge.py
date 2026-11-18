import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / 'bridge.py'
spec = importlib.util.spec_from_file_location('mac_bridge', MODULE)
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)

class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        (self.root / 'scripts/multi-autostart-control.py').write_text('# trusted fixture')
        self.base = self.root / 'dist/overseas-proxy'; self.base.mkdir(parents=True)
        self.config = {'servers':[{'name':'backup','endpoint':'198.51.100.20:8080'}], 'domain_routes':{'enabled':True,'interval_seconds':1800,'groups':{'ordinary':{'default_server':'backup','allowed_servers':['backup']}}}}
        (self.base / 'multi-server.json').write_text(json.dumps(self.config))
        self.state = {'ready':True,'updated_at':time.time(),'manager_pid':100,'servers':{'backup':{'healthy':True}},'domain_routes':{'groups':{'ordinary':{'preferred_available':'backup','preferred_endpoint':'198.51.100.20:8080','nodes':{}}}}}
        self.launch = dict(installed=True, loaded=True, running=True, autostart=True, owner_pid=100, matching=True)
        self.launch_mock = mock.patch.object(b, 'launch_status', side_effect=lambda *a: dict(self.launch))
        self.launch_mock.start()
    def tearDown(self):
        self.launch_mock.stop(); self.temp.cleanup()
    def snap(self):
        (self.base / 'multi-state.json').write_text(json.dumps(self.state))
        with mock.patch.object(b, 'launch_status', return_value=dict(self.launch)), mock.patch.object(b,'listening',return_value=True), mock.patch.object(b,'pac_status',return_value={'pac_enabled':True,'doubao_direct':True}):
            return b.snapshot(self.root)
    def test_live_ready(self): self.assertTrue(self.snap()['ready'])
    def test_stale_never_ready(self):
        self.state['updated_at'] = time.time()-20
        result = self.snap(); self.assertFalse(result['ready']); self.assertFalse(result['nodes'][0]['healthy'])
    def test_wrong_manager_never_ready(self):
        self.state['manager_pid'] = 101; self.assertFalse(self.snap()['ready'])
    def test_missing_pac_never_ready(self):
        (self.base / 'multi-state.json').write_text(json.dumps(self.state))
        with mock.patch.object(b,'launch_status',return_value=dict(self.launch)), mock.patch.object(b,'listening',side_effect=lambda p:p==8888), mock.patch.object(b,'pac_status',return_value={'pac_enabled':False,'doubao_direct':False}):
            self.assertFalse(b.snapshot(self.root)['ready'])
    def test_future_state_never_ready(self):
        self.state['updated_at'] = time.time()+30; self.assertFalse(self.snap()['ready'])
    def test_foreign_runtime_refused(self):
        self.launch['matching'] = False
        with self.assertRaises(b.ClientError): self.snap()
        with mock.patch.object(b, 'run') as run:
            with self.assertRaises(b.ClientError): b.control(self.root, 'stop')
            run.assert_not_called()
    def test_no_private_fields(self):
        self.state['secret']='SENSITIVE';self.state['domain_routes']['recent_routes']=[{'code':'SENSITIVE'}]
        self.assertNotIn('SENSITIVE',json.dumps(self.snap()))
    def test_normalize_host(self): self.assertEqual(b.normalize_host('GitHub.COM.'),'github.com')
    def test_oauth_url_rejected(self):
        for host in ['https://chatgpt.com/?code=TEST_ONLY','github.com/login','github.com?state=TEST_ONLY','-x','a\nb','u@github.com','127.0.0.1:8888']:
            with self.subTest(host=host), self.assertRaises(b.ClientError): b.normalize_host(host)
    def test_invalid_group_no_command(self):
        with mock.patch.object(b,'run') as run:
            with self.assertRaises(b.ClientError):b.control(self.root,'route',group='invalid',server='backup')
            run.assert_not_called()
    def test_unauthorized_node_no_command(self):
        with mock.patch.object(b,'run') as run:
            with self.assertRaises(b.ClientError):b.control(self.root,'route',group='ordinary',server='bad;echo')
            run.assert_not_called()
    def test_route_only_fixed_argv(self):
        with mock.patch.object(b,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            self.assertTrue(b.control(self.root,'route',group='ordinary',server='backup')['ok'])
            argv=run.call_args[0][0];self.assertIn('--group',argv);self.assertNotIn('sh',argv)
    def test_autostart_off_does_not_stop(self):
        with mock.patch.object(b,'launch_status',return_value=dict(self.launch)), mock.patch.object(b,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            b.control(self.root,'autostart-off');self.assertEqual(run.call_args[0][0][:2],['/bin/launchctl','disable'])
    def test_subprocess_output_not_forwarded(self):
        with mock.patch.object(b,'run',return_value=subprocess.CompletedProcess([],1,'SECRET','SECRET')):
            with self.assertRaises(b.ClientError) as context:b.control(self.root,'start')
            self.assertNotIn('SECRET',str(context.exception))
    def test_unknown_operation(self):
        with self.assertRaises(b.ClientError):b.control(self.root,'uninstall')
    def test_unconfigured_folder(self):
        with self.assertRaises(b.ClientError):b.paths(self.root/'missing')

if __name__ == '__main__': unittest.main()
