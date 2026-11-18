#!/usr/bin/env python3
"""Build a native macOS management app, without production secrets or proxy binaries."""
import argparse
import hashlib
import json
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/macos-client')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    target = args.output / 'Socks5Proxy.app'
    if target.exists():
        raise RuntimeError('Output already exists; use a fresh --output directory.')
    with tempfile.TemporaryDirectory(prefix='macos-client-build-', dir=args.output) as temporary:
        app = Path(temporary) / 'Socks5Proxy.app'
        macos = app / 'Contents/MacOS'; macos.mkdir(parents=True)
        resources = app / 'Contents/Resources'; resources.mkdir()
        command = ['xcrun', 'swiftc', '-O', '-parse-as-library', '-swift-version', '5',
                   '-target', 'arm64-apple-macosx13.0', '-sdk', sdk,
                   *[str(p) for p in sorted((SOURCE / 'Sources').glob('*.swift'))],
                   '-o', str(macos / 'Socks5Proxy')]
        subprocess.run(command, check=True)
        shutil.copyfile(SOURCE / 'bridge.py', resources / 'bridge.py')
        shutil.copyfile(SOURCE / 'Tests/demo.json', resources / 'demo.json')
        info = dict(CFBundleIdentifier='com.shikanon.socks5proxy.mac', CFBundleName='Socks5Proxy',
                    CFBundleDisplayName='Socks5Proxy', CFBundleExecutable='Socks5Proxy',
                    CFBundlePackageType='APPL', CFBundleShortVersionString='0.2.1', CFBundleVersion='3',
                    LSMultipleInstancesProhibited=True, SPSingleInstanceVersion=1,
                    LSMinimumSystemVersion='13.0', NSHighResolutionCapable=True,
                    NSPrincipalClass='NSApplication', NSHumanReadableCopyright='Socks5Proxy contributors')
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(app)], check=True)
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True)
        app.rename(target)
    manifest = {p.relative_to(target).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(target.rglob('*')) if p.is_file()}
    (args.output / 'app-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(app=str(target), architecture='arm64', minimum_macos='13.0',
                          signing='ad-hoc local development; not notarized',
                          production_secrets_bundled=False, proxy_core_bundled=False), indent=2))

if __name__ == '__main__':
    main()
