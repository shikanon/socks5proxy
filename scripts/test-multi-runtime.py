#!/usr/bin/env python3
"""Clean-checkout tests for public multi-server runtime helpers; never changes system proxies."""
import ast
import contextlib
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT/'examples/multi-server'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='multi-runtime-test-')
        self.base = Path(self.temp.name)
        self.pac = self.base/'community-pac'
        self.pac.mkdir()
        for name in ('direct-client-control.py',):
            shutil.copy2(EXAMPLE/name, self.base/name)
        for name in ('community-control.py', 'pac-server.py'):
            shutil.copy2(EXAMPLE/name, self.pac/name)
        self.ctl = module('isolated_direct', self.base/'direct-client-control.py')
        self.control = module('isolated_pac', self.pac/'community-control.py')

    def tearDown(self):
        self.temp.cleanup()

    def test_modules_and_config_are_complete(self):
        for path in EXAMPLE.glob('*.py'):
            ast.parse(path.read_text())
        manager = module('isolated_manager', ROOT/'scripts/multi-server-manager.py')
        value = json.loads((EXAMPLE/'multi-server.example.json').read_text())
        manager.validate(value)
        required_direct = ('cfg','save','owned','listening','start_client','stop_client','terminate','google','preflight')
        required_pac = ('state','save','start','stop_owned','restore_settings','listening')
        self.assertTrue(all(callable(getattr(self.ctl, name)) for name in required_direct))
        self.assertTrue(all(callable(getattr(self.control, name)) for name in required_pac))

    def test_save_does_not_need_private_historical_metadata(self):
        value = {'mode':'multi','server':'127.0.0.1:18900','servers':['192.0.2.10:8080','198.51.100.20:29889']}
        self.ctl.save(value)
        self.assertEqual(self.ctl.cfg(), value)
        self.assertEqual(json.loads((self.base/'connection.json').read_text())['servers'], value['servers'])
        self.assertEqual((self.base/'transport.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.base/'before-new-server').exists())
        with self.assertRaises(ValueError):
            self.ctl.connection_for({'mode':'multi','server':'0.0.0.0:18900','servers':[]})

    def test_zombie_and_foreign_process_identification(self):
        (self.base/'client.pid').write_text('123\n')
        with mock.patch.object(self.ctl.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='Z <defunct>\n')):
            self.assertIsNone(self.ctl.owned())
        with mock.patch.object(self.ctl.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='S /foreign/live\n')):
            with self.assertRaises(RuntimeError):
                self.ctl.owned()

    def test_other_pac_is_not_overwritten(self):
        with mock.patch.object(self.control, 'run', return_value=json.dumps({'ProxyAutoConfigEnable':1,'ProxyAutoConfigURLString':'http://127.0.0.1:45678/another.pac'})), mock.patch.object(self.control, 'start') as start, mock.patch.object(sys,'argv',['community-control.py','apply']):
            with self.assertRaises(RuntimeError):
                self.control.main()
            start.assert_not_called()

    def test_loopback_pac_and_signal_exit(self):
        (self.pac/'proxy.pac').write_text('function CommunityFindProxyForURL(){return "DIRECT";}')
        (self.pac/'direct-first.js').write_text('function FindProxyForURL(){return "DIRECT";}')
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        process = subprocess.Popen([sys.executable,str(self.pac/'pac-server.py'),'--port',str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            for _ in range(30):
                self.assertIsNone(process.poll())
                try:
                    response=opener.open(f'http://127.0.0.1:{port}/proxy.pac',timeout=1)
                    break
                except OSError:
                    time.sleep(.1)
            else:
                self.fail('PAC did not start')
            with response:
                self.assertEqual(response.read(),(self.pac/'proxy.pac').read_bytes()+b'\n'+(self.pac/'direct-first.js').read_bytes())
                self.assertEqual(response.headers.get_content_type(),'application/x-ns-proxy-autoconfig')
            for path in ('/','/proxy.secret','/../proxy.secret'):
                with self.assertRaises(urllib.error.HTTPError) as captured:
                    opener.open(f'http://127.0.0.1:{port}'+path,timeout=1)
                self.assertEqual(captured.exception.code,404)
                captured.exception.close()
        finally:
            process.terminate()
            try:
                self.assertEqual(process.wait(timeout=5),0)
            except subprocess.TimeoutExpired:
                process.kill();process.wait()
                self.fail('PAC did not exit normally')


if __name__ == '__main__':
    unittest.main()
