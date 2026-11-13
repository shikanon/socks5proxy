#!/usr/bin/env python3
"""Isolated semantic tests for primary/backup routing; never touches system settings."""
import copy
import importlib.util
import socket
import socketserver
import threading
import time
import unittest
from unittest import mock
from types import SimpleNamespace
from pathlib import Path

SPEC=importlib.util.spec_from_file_location('multi',Path(__file__).with_name('multi-server-manager.py'))
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            body=self.request.recv(1024)
            if not body:break
            self.request.sendall(self.server.marker+body)

class TestRouting(unittest.TestCase):
    def setUp(self):
        self.servers=[]
        for marker in (b'P:',b'B:'):
            server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo);server.daemon_threads=True;server.marker=marker
            threading.Thread(target=server.serve_forever,daemon=True).start();self.servers.append(server)
        self.config={'version':1,'listen':['127.0.0.1',18900],'servers':[{'name':'primary','endpoint':'127.0.0.1:'+str(self.servers[0].server_address[1])},{'name':'backup','endpoint':'127.0.0.1:'+str(self.servers[1].server_address[1])}],'probe_seconds':5,'probe_timeout_seconds':3,'connect_timeout_seconds':1,'failure_threshold':2,'recovery_threshold':2}
        self.router=M.Router(M.validate(self.config));self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen();self.listener.settimeout(.1)
        threading.Thread(target=self.router.accept,args=(self.listener,),daemon=True).start()
    def tearDown(self):
        self.router.close();self.listener.close()
        for server in self.servers:server.shutdown();server.server_close()
    def ready(self):
        for name in ('primary','backup'):
            self.router.health(name,True);self.router.health(name,True)
    def connect(self):
        result=socket.create_connection(self.listener.getsockname(),timeout=2);result.settimeout(2);return result
    def test_hysteresis_and_existing_connections(self):
        self.assertEqual(self.router.candidates(),[]);self.ready()
        old=self.connect();self.addCleanup(old.close);old.sendall(b'one');self.assertEqual(old.recv(32),b'P:one')
        self.router.health('primary',False);self.assertEqual(self.router.candidates()[0]['name'],'primary')
        self.router.health('primary',False);self.assertEqual(self.router.candidates()[0]['name'],'backup')
        with self.connect() as new:new.sendall(b'two');self.assertEqual(new.recv(32),b'B:two')
        old.sendall(b'three');self.assertEqual(old.recv(32),b'P:three')
        self.router.health('primary',True);self.assertEqual(self.router.candidates()[0]['name'],'backup')
        self.router.health('primary',True);self.assertEqual(self.router.candidates()[0]['name'],'primary')
        with self.connect() as new:new.sendall(b'four');self.assertEqual(new.recv(32),b'P:four')
    def test_connect_failure_can_try_backup_before_payload(self):
        self.ready();self.servers[0].shutdown();self.servers[0].server_close()
        with self.connect() as client:client.sendall(b'safe');self.assertEqual(client.recv(32),b'B:safe')
    def test_no_healthy_backend_no_direct_route(self):
        with self.connect() as client:
            try:body=client.recv(32)
            except ConnectionResetError:body=b''
            self.assertEqual(body,b'')
    def test_preference_is_not_payload_replay(self):
        self.ready();self.router.preference='backup'
        with self.connect() as client:client.sendall(b'hello');self.assertEqual(client.recv(32),b'B:hello')
    def test_server_write_half_close_does_not_truncate_upload(self):
        self.ready();server_done=threading.Event();received=[]
        def receive_after_eof():
            conn,_=half_listener.accept()
            with conn:
                conn.settimeout(8);conn.shutdown(socket.SHUT_WR)
                received.append(conn.recv(32));server_done.set()
        half_listener=socket.socket();half_listener.bind(('127.0.0.1',0));half_listener.listen()
        self.addCleanup(half_listener.close)
        threading.Thread(target=receive_after_eof,daemon=True).start()
        self.router.config['servers'][0]['endpoint']='127.0.0.1:'+str(half_listener.getsockname()[1])
        with self.connect() as client:
            self.assertEqual(client.recv(32),b'')
            time.sleep(3.2)
            client.sendall(b'after-half-close');client.shutdown(socket.SHUT_WR)
            self.assertTrue(server_done.wait(2));self.assertEqual(received,[b'after-half-close'])
    def test_validation(self):
        bad=copy.deepcopy(self.config);bad['listen']=['0.0.0.0',18900]
        with self.assertRaises(AssertionError):M.validate(bad)
        bad=copy.deepcopy(self.config);bad['servers'][1]=bad['servers'][0]
        with self.assertRaises(AssertionError):M.validate(bad)

class TestClientOwnership(unittest.TestCase):
    def test_exited_zombie_is_not_foreign_live_process(self):
        path=Path(__file__).resolve().parent.parent/'examples/multi-server/direct-client-control.py'
        if not path.exists():self.skipTest('Existing deployment client control not installed')
        spec=importlib.util.spec_from_file_location('test_direct',path)
        ctl=importlib.util.module_from_spec(spec);spec.loader.exec_module(ctl)
        pidfile=mock.Mock();pidfile.exists.return_value=True;pidfile.read_text.return_value='123\n'
        with mock.patch.object(ctl,'PIDFILE',pidfile),mock.patch.object(ctl.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='Z <defunct>\n')):
            self.assertIsNone(ctl.owned())
        with mock.patch.object(ctl,'PIDFILE',pidfile),mock.patch.object(ctl.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='S /unrelated/program\n')):
            with self.assertRaises(RuntimeError):ctl.owned()

if __name__=='__main__':unittest.main()
