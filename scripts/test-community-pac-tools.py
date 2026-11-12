#!/usr/bin/env python3
"""Test PAC generation, input validation and the isolated loopback HTTP server."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]


def main():
    spec=importlib.util.spec_from_file_location('builder',ROOT/'scripts/build-community-pac.py')
    builder=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    config=json.loads((ROOT/'examples/community-pac/domains.json').read_text())
    rejected=0
    for value in ('example.com\nalert(1)','*.example.com','a..example.com'):
        bad=copy.deepcopy(config)
        bad['proxy_exact_hosts'].append(value)
        try:
            builder.wrapper(bad)
        except ValueError:
            rejected+=1
        else:
            raise AssertionError('invalid domain was accepted')
    bad=copy.deepcopy(config)
    bad['proxy']='0.0.0.0:8888'
    try:
        builder.wrapper(bad)
    except ValueError:
        rejected+=1
    else:
        raise AssertionError('non-loopback proxy was accepted')
    with tempfile.TemporaryDirectory(prefix='community-pac-test-') as directory:
        output=Path(directory)/'proxy.pac'
        subprocess.run(['python3',str(ROOT/'scripts/build-community-pac.py'),'--output',str(output)],check=True)
        assert output.read_bytes()==(ROOT/'examples/community-pac/proxy.pac').read_bytes()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0))
            port=probe.getsockname()[1]
        process=subprocess.Popen(['python3',str(ROOT/'scripts/serve-community-pac.py'),'--pac',str(output),'--port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base='http://127.0.0.1:'+str(port)
        try:
            for _ in range(30):
                assert process.poll() is None,'PAC HTTP process exited'
                try:
                    response=opener.open(base+'/proxy.pac',timeout=1)
                    break
                except OSError:
                    time.sleep(.1)
            else:
                raise AssertionError('PAC HTTP process not ready')
            with response:
                assert response.read()==output.read_bytes()
                assert response.headers.get_content_type()=='application/x-ns-proxy-autoconfig'
            for suffix in ('/','/proxy.secret','/domains.json','/../proxy.secret'):
                try:
                    opener.open(base+suffix,timeout=1)
                except urllib.error.HTTPError as error:
                    assert error.code==404
                else:
                    raise AssertionError('arbitrary path was served')
        finally:
            process.terminate()
            try:
                assert process.wait(timeout=5)==0,'PAC HTTP process unclean exit'
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError('PAC HTTP process did not stop')
    print(json.dumps({'passed':True,'invalid_inputs_rejected':rejected,'generated_byte_equal':True,'loopback_http':True,'arbitrary_paths_404':True,'clean_shutdown':True}))

if __name__=='__main__':main()
