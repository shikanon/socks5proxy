#!/usr/bin/env python3
"""Install a desktop tunnel supervisor. Rendering never changes OS services."""

import argparse
import ctypes
import json
import os
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

LABEL = "com.shikanon.socks5proxy.client"
UNIT = "socks5proxy-client.service"
TASK = "Socks5ProxyClient"


def args_for(binary, config):
    return [str(binary), "-mode", "tunnel", "-config", str(config), "-daemon"]


def systemd_quote(value):
    # systemd expands % specifiers and $ environment references in ExecStart.
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def render(platform, binary, config):
    args = args_for(binary, config)
    if platform == "darwin":
        return plistlib.dumps({
            "Label": LABEL, "ProgramArguments": args,
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 5,
            "ExitTimeOut": 45, "WorkingDirectory": str(binary.parent),
            "StandardOutPath": "/var/log/socks5proxy-client.log",
            "StandardErrorPath": "/var/log/socks5proxy-client.log",
        }).decode()
    if platform == "linux":
        command = " ".join(systemd_quote(a) for a in args)
        recovery = " ".join(systemd_quote(a) for a in [str(binary), "-config", str(config), "-recover-network"])
        return f"""[Unit]
Description=Socks5Proxy tunnel watchdog
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={command}
ExecStopPost={recovery}
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=40
WorkingDirectory={str(binary.parent).replace('%', '%%')}

[Install]
WantedBy=multi-user.target
"""
    ns = "http://schemas.microsoft.com/windows/2004/02/mit/task"
    ET.register_namespace("", ns)
    root = ET.Element(f"{{{ns}}}Task", version="1.4")
    def sub(parent, tag, value=None, **attrs):
        e = ET.SubElement(parent, f"{{{ns}}}{tag}", attrs)
        if value is not None:
            e.text = value
        return e
    info = sub(root, "RegistrationInfo")
    sub(info, "Description", LABEL)
    triggers = sub(root, "Triggers")
    trigger = sub(triggers, "BootTrigger")
    sub(trigger, "Enabled", "true")
    principals = sub(root, "Principals")
    principal = sub(principals, "Principal", id="System")
    sub(principal, "UserId", "S-1-5-18")
    sub(principal, "RunLevel", "HighestAvailable")
    settings = sub(root, "Settings")
    sub(settings, "MultipleInstancesPolicy", "IgnoreNew")
    sub(settings, "DisallowStartIfOnBatteries", "false")
    sub(settings, "StopIfGoingOnBatteries", "false")
    sub(settings, "AllowHardTerminate", "true")
    sub(settings, "StartWhenAvailable", "true")
    sub(settings, "ExecutionTimeLimit", "PT0S")
    restart = sub(settings, "RestartOnFailure")
    sub(restart, "Interval", "PT1M")
    sub(restart, "Count", "999")
    actions = sub(root, "Actions", Context="System")
    action = sub(actions, "Exec")
    sub(action, "Command", str(binary))
    sub(action, "Arguments", subprocess.list2cmdline(args[1:]))
    sub(action, "WorkingDirectory", str(binary.parent))
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def run(args, capture=False):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout


def admin(platform):
    if platform == "windows":
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError("Run in an Administrator terminal.")
    elif os.geteuid() != 0:
        raise RuntimeError("Run with sudo/root.")


def validate(binary, config, platform):
    if not binary.is_file() or (platform != "windows" and not os.access(binary, os.X_OK)):
        raise RuntimeError(f"Executable unavailable: {binary}")
    data = json.loads(config.read_text())
    if not isinstance(data, dict) or not data.get("server") or not data.get("client_id"):
        raise RuntimeError("Config requires server and client_id.")
    credential = "table_file" if data.get("transport") == "tcp-table" else "token_file"
    if not data.get(credential):
        raise RuntimeError(f"Config requires {credential}.")
    paths = [binary, config]
    for key in (credential, "ca"):
        if data.get(key):
            p = pathlib.Path(data[key])
            if not p.is_absolute():
                p = config.parent / p
            if not p.is_file():
                raise RuntimeError(f"File unavailable: {p}")
            paths.append(p.resolve())
    if platform != "windows":
        for p in paths:
            if p.stat().st_uid != 0 or p.stat().st_mode & 0o022:
                raise RuntimeError(f"Service files must be root-owned and not group/world-writable: {p}")
            for parent in p.parents:
                if parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022:
                    raise RuntimeError(f"Service directories must be root-owned and not group/world-writable: {parent}")
        for p in paths[1:]:
            if p.stat().st_mode & 0o077:
                raise RuntimeError(f"Config/credentials must have mode 600: {p}")
    elif not (binary.parent / "wintun.dll").is_file():
        raise RuntimeError("Put the matching wintun.dll beside the executable.")


def check_identity(platform, binary, config):
    """Do not stop/uninstall a similarly named job pointing at other files."""
    expected = args_for(binary, config)
    if platform == "darwin":
        path = pathlib.Path("/Library/LaunchDaemons") / (LABEL + ".plist")
        if plistlib.loads(path.read_bytes()).get("ProgramArguments") != expected:
            raise RuntimeError("Installed launchd job does not match --binary/--config.")
    elif platform == "linux":
        path = pathlib.Path("/etc/systemd/system") / UNIT
        expected_start = "ExecStart=" + " ".join(systemd_quote(a) for a in expected)
        if expected_start not in path.read_text().splitlines():
            raise RuntimeError("Installed systemd service does not match --binary/--config.")
    else:
        xml = run(["schtasks.exe", "/Query", "/TN", TASK, "/XML"], capture=True)
        root = ET.fromstring(xml)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        if (root.findtext(".//t:Exec/t:Command", namespaces=ns) != str(binary) or
                root.findtext(".//t:Exec/t:Arguments", namespaces=ns) != subprocess.list2cmdline(expected[1:])):
            raise RuntimeError("Installed scheduled task does not match --binary/--config.")


def recover(binary, config):
    run([str(binary), "-config", str(config), "-recover-network"])


def windows_stop(binary, config):
    # Task Scheduler may terminate just its main process. Stop only verified
    # executable/config matches, including the supervised child, then recover.
    state = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                 f"(Get-ScheduledTask -TaskName '{TASK}' -ErrorAction Stop).State.ToString()"], capture=True).strip()
    if state == "Running":
        run(["schtasks.exe", "/End", "/TN", TASK])
    b = str(binary).replace("'", "''")
    c = str(config).replace("'", "''")
    # Command-line token matching prevents a prefix config from matching.
    script = f"""$ErrorActionPreference='Stop'
$wanted='-config "' + '{c}' + '"'
$wantedBare='-config ' + '{c}'
$p=@(Get-CimInstance Win32_Process | Where-Object {{
  $_.ExecutablePath -eq '{b}' -and $_.CommandLine -and
  ($_.CommandLine.Contains($wanted) -or
   ($_.CommandLine.Contains($wantedBare) -and
    ($_.CommandLine.EndsWith($wantedBare) -or $_.CommandLine.Contains($wantedBare + ' '))))
}})
$processes=@($p | ForEach-Object {{ Get-Process -Id $_.ProcessId -ErrorAction Stop }})
foreach ($x in $processes) {{ Stop-Process -InputObject $x -Force -ErrorAction Stop }}
foreach ($x in $processes) {{
  if (!$x.WaitForExit(15000)) {{ throw 'Client process did not exit' }}
}}
"""
    run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    recover(binary, config)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["render", "install", "start", "stop", "status", "uninstall"])
    p.add_argument("--binary", type=pathlib.Path, required=True)
    p.add_argument("--config", type=pathlib.Path, required=True)
    p.add_argument("--platform", choices=["darwin", "linux", "windows"], help="Render target only")
    a = p.parse_args()
    binary, config = a.binary.resolve(), a.config.resolve()
    platform = a.platform or ("windows" if os.name == "nt" else sys.platform)
    if platform not in ("darwin", "linux", "windows"):
        raise RuntimeError("Supported platforms: macOS, Linux, Windows.")
    if a.action == "render":
        print(render(platform, binary, config), end="")
        return
    if a.platform:
        raise RuntimeError("--platform is only allowed with render.")
    admin(platform)
    if a.action == "install":
        validate(binary, config, platform)
        text = render(platform, binary, config)
        if platform in ("darwin", "linux"):
            path = (pathlib.Path("/Library/LaunchDaemons") / (LABEL + ".plist") if platform == "darwin"
                    else pathlib.Path("/etc/systemd/system") / UNIT)
            # Exclusive creation protects any existing service definition.
            with path.open("x") as f:
                f.write(text)
            path.chmod(0o644)
            if platform == "darwin":
                run(["launchctl", "bootstrap", "system", str(path)])
            else:
                run(["systemctl", "daemon-reload"])
                run(["systemctl", "enable", "--now", UNIT])
        else:
            result = subprocess.run(["schtasks.exe", "/Query", "/TN", TASK], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                raise RuntimeError("Scheduled task already exists.")
            with tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / "task.xml"
                path.write_text("<?xml version='1.0' encoding='UTF-16'?>" + text.split("?>", 1)[1], encoding="utf-16")
                run(["schtasks.exe", "/Create", "/TN", TASK, "/XML", str(path)])
            run(["schtasks.exe", "/Run", "/TN", TASK])
        return
    check_identity(platform, binary, config)
    if a.action == "status":
        if platform == "darwin":
            run(["launchctl", "print", "system/" + LABEL])
        elif platform == "linux":
            run(["systemctl", "status", "--no-pager", UNIT])
        else:
            run(["schtasks.exe", "/Query", "/TN", TASK, "/V", "/FO", "LIST"])
        run([str(binary), "-config", str(config), "-status"])
        return
    if a.action == "start":
        if platform == "darwin":
            path = "/Library/LaunchDaemons/" + LABEL + ".plist"
            registered = subprocess.run(["launchctl", "print", "system/" + LABEL], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            run(["launchctl", "kickstart", "system/" + LABEL] if registered.returncode == 0 else ["launchctl", "bootstrap", "system", path])
        elif platform == "linux":
            run(["systemctl", "start", UNIT])
        else:
            run(["schtasks.exe", "/Run", "/TN", TASK])
        return
    if platform == "darwin":
        registered = subprocess.run(["launchctl", "print", "system/" + LABEL], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if registered.returncode == 0:
            run(["launchctl", "bootout", "system/" + LABEL])
        recover(binary, config)
        if a.action == "uninstall":
            (pathlib.Path("/Library/LaunchDaemons") / (LABEL + ".plist")).unlink()
    elif platform == "linux":
        run(["systemctl", "stop", UNIT])
        recover(binary, config)
        if a.action == "uninstall":
            run(["systemctl", "disable", UNIT])
            (pathlib.Path("/etc/systemd/system") / UNIT).unlink()
            run(["systemctl", "daemon-reload"])
    else:
        windows_stop(binary, config)
        if a.action == "uninstall":
            run(["schtasks.exe", "/Delete", "/TN", TASK, "/F"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"client-daemon: {exc}", file=sys.stderr)
        sys.exit(1)
