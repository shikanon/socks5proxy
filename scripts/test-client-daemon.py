#!/usr/bin/env python3
"""Check service definitions without installing a service."""
import importlib.util
import pathlib
import plistlib
import subprocess
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("client_daemon", pathlib.Path(__file__).with_name("client-daemon.py"))
daemon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daemon)


class Definitions(unittest.TestCase):
    def test_mac(self):
        b, c = pathlib.Path("/opt/proxy app/client"), pathlib.Path("/etc/proxy/client.json")
        p = plistlib.loads(daemon.render("darwin", b, c).encode())
        self.assertEqual(p["ProgramArguments"], daemon.args_for(b, c))
        self.assertTrue(p["KeepAlive"])
        self.assertEqual(p["ExitTimeOut"], 45)

    def test_linux(self):
        text = daemon.render("linux", pathlib.Path("/opt/10%/$app/client"), pathlib.Path("/etc/proxy/client.json"))
        self.assertIn('ExecStart="/opt/10%%/$$app/client"', text)
        self.assertIn("-recover-network", text)
        self.assertIn("KillMode=mixed", text)
        self.assertIn("Restart=always", text)
        self.assertIn("WorkingDirectory=/opt/10%%/$app\n", text)

    def test_windows(self):
        b, c = pathlib.Path("/proxy app/client.exe"), pathlib.Path("/proxy config/client.json")
        root = ET.fromstring(daemon.render("windows", b, c))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.findtext(".//t:Exec/t:Arguments", namespaces=ns), subprocess.list2cmdline(daemon.args_for(b, c)[1:]))
        self.assertEqual(root.findtext(".//t:UserId", namespaces=ns), "S-1-5-18")
        self.assertEqual(root.findtext(".//t:ExecutionTimeLimit", namespaces=ns), "PT0S")


if __name__ == "__main__":
    unittest.main()
