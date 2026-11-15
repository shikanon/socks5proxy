#!/usr/bin/env python3
"""Tests for process-scoped Codex proxy launcher; never launches real apps or changes proxies."""
import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('launcher',ROOT/'scripts/codex-proxy-launch.py');L=importlib.util.module_from_spec(s);s.loader.exec_module(L)

class Tests(unittest.TestCase):
    def test_environment_is_copy_and_all_proxy_variants_set(self):
        old={'HTTP_PROXY':'http://old.invalid:2','NO_PROXY':'*','keep':'value'}
        value=L.proxy_environment(old)
        self.assertEqual(old,{'HTTP_PROXY':'http://old.invalid:2','NO_PROXY':'*','keep':'value'})
        for key in L.PROXY_KEYS:self.assertEqual(value[key],'http://127.0.0.1:8888')
        for key in ('NO_PROXY','no_proxy'):self.assertEqual(value[key],'localhost,127.0.0.1,::1')
        self.assertEqual(value['keep'],'value')
    def test_fixed_loopback_chromium_proxy_and_callback_exception(self):
        self.assertEqual(L.chromium_flags(),['--proxy-server=http://127.0.0.1:8888','--proxy-bypass-list=localhost;127.0.0.1;[::1]'])
        self.assertNotIn('--ignore-certificate-errors',L.chromium_flags())
    def test_app_identity_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'Wrong.app';(p/'Contents').mkdir(parents=True)
            (p/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'unknown','CFBundleExecutable':'Other'}))
            with self.assertRaises(RuntimeError):L.resolve_app(p)
    def test_active_child_prevents_duplicate_launch(self):
        path=Path('/Applications/ChatGPT.app')
        output='123 /Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex\n'
        with mock.patch.object(L.subprocess,'run',return_value=SimpleNamespace(stdout=output)):
            self.assertTrue(L.app_running(path))
        output='123 /Applications/ChatGPT.app/Contents/Frameworks/X/Helpers/browser_crashpad_handler\n'
        with mock.patch.object(L.subprocess,'run',return_value=SimpleNamespace(stdout=output)):
            self.assertFalse(L.app_running(path))
    def test_launch_services_environment_is_per_application(self):
        env=L.proxy_environment({'token':'never-print'})
        args=L.launch_arguments(Path('/Applications/ChatGPT.app'),env)
        self.assertEqual(args[:4],['/usr/bin/open','-a','/Applications/ChatGPT.app','-n'])
        self.assertEqual(args.count('--env'),9)
        self.assertIn('HTTPS_PROXY=http://127.0.0.1:8888',args)
        self.assertNotIn('token=never-print',args)
        self.assertNotIn('setenv',args)
    def test_environment_verifier_returns_booleans_only(self):
        env=L.proxy_environment({});value='private=value '+' '.join(k+'='+v for k,v in env.items())
        with mock.patch.object(L.subprocess,'run',return_value=SimpleNamespace(stdout=value)):
            result=L.verify_environment(123,env)
        self.assertTrue(all(result.values()))
        self.assertNotIn('private',result)
        self.assertTrue(all(type(v) is bool for v in result.values()))
    def test_proxy_unavailable_does_not_launch(self):
        with mock.patch.object(L.socket,'create_connection',side_effect=ConnectionRefusedError):
            with self.assertRaises(ConnectionRefusedError):L.require_proxy()

if __name__=='__main__':unittest.main()
