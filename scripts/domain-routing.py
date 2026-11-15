#!/usr/bin/env python3
"""Domain-scoped HTTP CONNECT routing and independently persisted probe decisions; no TLS interception."""
import contextlib
from datetime import datetime
import hashlib
import ipaddress
import json
import math
import re
import socket
import select
import threading
import time
from urllib.parse import urlsplit

HEADER_LIMIT = 32768
REGION_CODES = {'unsupported_country_region_territory', 'unsupported_country', 'country_not_supported', 'unsupported_region'}


def host_name(value):
    if not isinstance(value,str) or not value or any(c in value for c in '\x00\r\n\t /?#@'):
        raise ValueError('Invalid host')
    host=value.rstrip('.').lower()
    try:return str(ipaddress.ip_address(host))
    except ValueError:pass
    host=host.encode('idna').decode('ascii')
    if len(host)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in host.split('.')):
        raise ValueError('Invalid DNS host')
    return host


def suffix_match(host,suffix):return host==suffix or host.endswith('.'+suffix)


def validate(raw,servers):
    if raw is None:return None
    if not isinstance(raw,dict):raise ValueError('Domain routes must be object')
    if raw.get('enabled') is False:return None
    if raw.get('version')!=1 or raw.get('enabled') is not True:
        raise ValueError('Unsupported domain route config')
    if raw.get('listen')!=['127.0.0.1',8888]:raise ValueError('Domain front must use fixed local HTTP8888')
    if raw.get('interval_seconds')!=1800:raise ValueError('Domain probes must run every1800seconds')
    groups=raw.get('groups');names={s['name'] for s in servers}
    if not isinstance(groups,dict) or not 1<=len(groups)<=8 or 'ordinary' not in groups:raise ValueError('Missing ordinary group')
    suffixes=set();exact=set()
    for name,g in groups.items():
        if not re.fullmatch('[a-z][a-z0-9_]{0,31}',name):raise ValueError('Invalid group name')
        allowed=g.get('allowed_servers');probes=g.get('probe_servers')
        if (not isinstance(allowed,list) or not allowed or len(set(allowed))!=len(allowed) or any(s not in names for s in allowed)
            or not isinstance(probes,list) or not probes or len(set(probes))!=len(probes) or any(s not in names for s in probes)
            or not set(allowed).issubset(probes)):
            raise ValueError('Invalid authorized candidate list')
        if g.get('default_server') not in allowed:raise ValueError('Default must be an authorized node')
        for kind,seen in [('suffixes',suffixes),('exact_hosts',exact)]:
            values=g.get(kind,[])
            if not isinstance(values,list):raise ValueError('Invalid domain list')
            for item in values:
                if host_name(item)!=item or item in seen:raise ValueError('Noncanonical or duplicate domain')
                if any(suffix_match(item,d) for d in ['doubao.com','doubaowork.com','bytedance.com','feishu.cn','larkoffice.com']):
                    raise ValueError('Protected DIRECT host must not be a proxy group')
                seen.add(item)
        if name=='ordinary' and (g.get('suffixes') or g.get('exact_hosts')):raise ValueError('ordinary is unmatched default')
        targets=g.get('probes')
        if not isinstance(targets,list) or not 1<=len(targets)<=4:raise ValueError('Missing probe targets')
        for target in targets:
            url=urlsplit(target.get('url',''))
            if url.scheme!='https' or not url.hostname or url.username or url.password or url.fragment or url.port not in (None,443):
                raise ValueError('Probe target must be HTTPS without credentials')
            if target.get('method','GET') not in ['GET','HEAD']:raise ValueError('Probe must be read-only')
            codes=target.get('reachable_status_codes')
            if not isinstance(codes,list) or not codes or any(type(c) is not int or c<200 or c>499 or c==403 for c in codes):
                raise ValueError('Explicit reachability codes required;403 is uncertain')
    return raw


def authority(value):
    if value.startswith('['):
        end=value.find(']')
        if end<0 or value[end+1:end+2]!=':':raise ValueError('CONNECT IPv6 port required')
        host=value[1:end];port=value[end+2:]
    else:
        host,separator,port=value.rpartition(':')
        if not separator or ':' in host:raise ValueError('CONNECT authority must have explicit port')
    host=host_name(host)
    if not port.isascii() or not port.isdigit() or len(port)>5 or not 1<=int(port)<=65535:raise ValueError('Invalid port')
    return host,int(port)


def read_header(conn,budget=5):
    data=bytearray();deadline=time.monotonic()+budget
    while b'\r\n\r\n' not in data:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise socket.timeout('Total header budget exceeded')
        conn.settimeout(remaining)
        part=conn.recv(min(4096,HEADER_LIMIT+1-len(data)))
        if not part:raise ValueError('Premature header EOF')
        data.extend(part)
        split=data.find(b'\r\n\r\n')
        if (split<0 and len(data)>HEADER_LIMIT) or split+4>HEADER_LIMIT:raise ValueError('Header exceeds32KiB')
    end=data.index(b'\r\n\r\n')+4
    return bytes(data[:end]),bytes(data[end:])


def request_info(header):
    text=header.decode('iso-8859-1');lines=text[:-4].split('\r\n')
    parts=lines[0].split(' ')
    if len(parts)!=3 or not re.fullmatch('[A-Z]{1,20}',parts[0]) or parts[2] not in ['HTTP/1.1','HTTP/1.0']:
        raise ValueError('Invalid request line')
    method,target,_=parts;fields={}
    for line in lines[1:]:
        if not line or line[0].isspace() or ':' not in line:raise ValueError('Invalid folded header')
        key,value=line.split(':',1);key=key.lower()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+",key):raise ValueError('Invalid header name')
        if any(ord(c)<32 and c!='\t' for c in value):raise ValueError('Control in header')
        fields.setdefault(key,[]).append(value.strip())
    if len(fields.get('host',[]))>1:raise ValueError('Ambiguous Host')
    if 'content-length' in fields and ('transfer-encoding' in fields or len(fields['content-length'])!=1):
        raise ValueError('Ambiguous framing')
    if 'content-length' in fields and not fields['content-length'][0].isdigit():raise ValueError('Invalid content length')
    if 'transfer-encoding' in fields and fields['transfer-encoding']!=['chunked']:raise ValueError('Unsupported transfer encoding')
    if method=='CONNECT':
        host,port=authority(target)
        if fields.get('host') and authority(fields['host'][0])!=(host,port):raise ValueError('Conflicting CONNECT Host')
        if 'transfer-encoding' in fields or fields.get('content-length',['0'])!=['0']:raise ValueError('CONNECT body not supported')
    else:
        u=urlsplit(target)
        if u.scheme!='http' or not u.hostname or u.username or u.password or u.fragment:raise ValueError('Absolute HTTP proxy URL required')
        host,port=host_name(u.hostname),u.port or 80
        if fields.get('host'):
            h=urlsplit('http://'+fields['host'][0])
            if host_name(h.hostname)!=(host) or (h.port or 80)!=port or h.path:raise ValueError('Conflicting HTTP Host')
    return {'method':method,'host':host,'port':port}


def classify_probe(exit_code,status,tls,body,elapsed,expected):
    result={'state':'unknown','network_reached':False,'application_access_proven':False,
            'curl_exit':exit_code,'http_code':status,'tls_verify_result':tls,'response_ms':None,'reason':'uncertain'}
    if exit_code!=0 or tls!='0' or status=='000':
        result.update(state='unreachable',reason='transport_or_TLS_failure');return result
    result['network_reached']=True
    try:
        obj=json.loads(body)
        def codes(value):
            if isinstance(value,dict):
                for k,v in value.items():
                    if k in ['code','type'] and isinstance(v,str):yield v.lower()
                    yield from codes(v)
            elif isinstance(value,list):
                for v in value:yield from codes(v)
        region=any(code in REGION_CODES for code in codes(obj))
    except (ValueError,TypeError):region=False
    normalized=body.lower()
    region=region or any(p in normalized for p in ['unsupported_country_region_territory','not available in your country','not supported in your country','not available in your region'])
    if region:
        result.update(state='policy_denied',reason='explicit_region_denial');return result
    try:code=int(status);ms=float(elapsed)*1000
    except ValueError:return result
    if code>=500:
        result.update(state='unreachable',reason='server_error');return result
    if code==403:result['reason']='403_unknown_bot_auth_or_policy'
    elif code==429:result['reason']='rate_limit_unknown'
    elif code in expected and math.isfinite(ms) and ms>0:
        result.update(state='reachable',reason='reachability_only' if code>=400 else 'public_endpoint_reachable',response_ms=ms)
    return result


class Routes:
    def __init__(self,config,servers,cache=None):
        self.config=validate(config,servers);self.servers={s['name']:dict(s) for s in servers}
        self.lock=threading.RLock();self.manual={};self.counts={n:0 for n in self.config['groups']};self.recent=[];self.transport_failures={}
        self.fingerprint=hashlib.sha256(json.dumps({'config':config,'servers':servers},sort_keys=True).encode()).hexdigest()
        self.groups={n:{'last_probe_at':None,'next_probe_at':None,'round_count':0,'running':False,'nodes':{},'last_error':''} for n in self.config['groups']}
        if isinstance(cache,dict) and cache.get('fingerprint')==self.fingerprint:
            for n,g in cache.get('groups',{}).items():
                if n in self.groups and isinstance(g,dict):
                    try:
                        if type(g['round_count']) is not int or not isinstance(g['nodes'],dict):raise ValueError()
                        for f in ['last_probe_at','next_probe_at']:
                            if g[f] is not None and (type(g[f]) not in (int,float) or not math.isfinite(g[f])):raise ValueError()
                        self.groups[n].update(g,running=False)
                    except (ValueError,KeyError):pass
    def group_for(self,host):
        host=host_name(host)
        for name,g in self.config['groups'].items():
            if name!='ordinary' and host in g.get('exact_hosts',[]):return name
        matches=[(len(suffix),name) for name,g in self.config['groups'].items() if name!='ordinary' for suffix in g.get('suffixes',[]) if suffix_match(host,suffix)]
        return max(matches)[1] if matches else 'ordinary'
    def set_manual(self,values):
        with self.lock:
            clean={}
            if isinstance(values,dict):
                for n,s in values.items():
                    if n in self.groups and (s is None or s in self.config['groups'][n]['allowed_servers']):
                        if s is not None:clean[n]=s
            self.manual=clean
    def candidates(self,group,healthy):
        with self.lock:
            g=self.config['groups'][group]
            order=[g['default_server']]+[s for s in g['allowed_servers'] if s!=g['default_server']]
            if group in self.manual:order=[self.manual[group]]+[s for s in order if s!=self.manual[group]]
            states=self.groups[group]['nodes']
            return [self.servers[n] for n in order
                    if self.transport_failures.get((group,n),{}).get('retry_at',0)<=time.time()
                    and (healthy.get(n,False) if group=='ordinary' else bool(states.get(n,{}).get('state') in ['reachable','unknown'] or (not states.get(n) and healthy.get(n,False))))
                    and states.get(n,{}).get('state') not in ['policy_denied','unreachable']]
    def transport_failure(self,group,server):
        with self.lock:self.transport_failures[(group,server)]={'retry_at':time.time()+20,'reason':'precommit_backend_handshake_failed'}
    def transport_success(self,group,server):
        with self.lock:self.transport_failures.pop((group,server),None)
    def due_in(self,group,now):
        with self.lock:
            due=self.groups[group]['next_probe_at'];return 0 if due is None else max(0,min(1800,due-now))
    def begin(self,group):
        with self.lock:self.groups[group]['running']=True
    def complete(self,group,rows,started,finished):
        with self.lock:
            nodes={}
            for name,samples in rows.items():
                good=[v['response_ms'] for v in samples if v['state']=='reachable']
                state='policy_denied' if any(v['state']=='policy_denied' for v in samples) else ('reachable' if len(good)>=2 else 'unreachable' if sum(v['state']=='unreachable' for v in samples)>=2 else 'unknown')
                import statistics
                nodes[name]={'state':state,'median_response_ms':statistics.median(good) if len(good)>=2 else None,
                             'successful_samples':len(good),'samples':samples,'routing_authorized':name in self.config['groups'][group]['allowed_servers']}
            info=self.groups[group];next_at=started+1800*(max(1,int((finished-started)//1800)+1))
            for name in nodes:
                if nodes[name]['state']=='reachable':self.transport_failures.pop((group,name),None)
            info.update(nodes=nodes,last_probe_started_at=started,last_probe_at=finished,next_probe_at=next_at,round_count=info['round_count']+1,running=False,last_error='')
    def fail_round(self,group,started,error):
        with self.lock:self.groups[group].update(next_probe_at=started+1800,running=False,last_error=error)
    def record(self,group,host,server):
        with self.lock:
            self.counts[group]+=1
            self.recent=(self.recent+[{'group':group,'host':host,'server':server,'at':time.time()}])[-32:]
    def cache(self):
        with self.lock:return json.loads(json.dumps({'version':1,'fingerprint':self.fingerprint,'groups':self.groups}))
    def summary(self,healthy):
        with self.lock:
            result={}
            for name,info in self.groups.items():
                g=self.config['groups'][name];choices=self.candidates(name,healthy)
                result[name]=dict(info,default_server=g['default_server'],default_endpoint=self.servers[g['default_server']]['endpoint'],
                                  allowed_servers=g['allowed_servers'],manual_preference=self.manual.get(name),
                                  preferred_available=choices[0]['name'] if choices else None,
                                  preferred_endpoint=choices[0]['endpoint'] if choices else None,
                                  next_probe_local=datetime.fromtimestamp(info['next_probe_at']).astimezone().isoformat(timespec='seconds') if info['next_probe_at'] else None,
                                  accepted_connections=self.counts[name],suffixes=g.get('suffixes',[]),exact_hosts=g.get('exact_hosts',[]),
                                  transport_cooldowns={n:v for (group,n),v in self.transport_failures.items() if group==name and v['retry_at']>time.time()},
                                  selection_policy='manual_then_default_then_fallback',availability_source='google_health_and_group_probe' if name=='ordinary' else 'independent_group_probe')
            return {'enabled':True,'http_proxy':'127.0.0.1:8888','interval_seconds':1800,'groups':result,'recent_routes':list(self.recent),
                    'TLS_interception':False,'application_authentication_verified':False}


class HTTPFront:
    def __init__(self,routes,backends,health,listen=('127.0.0.1',8888)):
        self.routes=routes;self.backends=backends;self.health=health
        self.stop=threading.Event();self.lock=threading.Lock();self.active=set();self.slots=threading.BoundedSemaphore(128)
        self.listener=socket.socket();self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:
            self.listener.bind(listen);self.listener.listen(128);self.listener.settimeout(.5)
        except OSError:
            self.listener.close();raise
        self.address=self.listener.getsockname()
    def start(self):
        self.thread=threading.Thread(target=self.accept,daemon=True);self.thread.start()
    def accept(self):
        while not self.stop.is_set():
            try:conn,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            if not self.slots.acquire(blocking=False):conn.close();continue
            with self.lock:self.active.add(conn)
            threading.Thread(target=self.session,args=(conn,),daemon=True).start()
    def error(self,conn,code):
        reason={400:'Bad Request',502:'Bad Gateway',503:'Service Unavailable'}.get(code,'Error')
        with contextlib.suppress(OSError):conn.sendall(('HTTP/1.1 '+str(code)+' '+reason+'\r\nConnection: close\r\nContent-Length:0\r\n\r\n').encode())
    def session(self,conn):
        upstream=None;committed=False
        try:
            conn.settimeout(5);header,pending=read_header(conn);info=request_info(header)
            group=self.routes.group_for(info['host']);candidates=self.routes.candidates(group,self.health())
            if not candidates:self.error(conn,503);return
            for server in candidates:
                try:
                    upstream=socket.create_connection(self.backends(server['name']),timeout=3)
                    with self.lock:self.active.add(upstream)
                    upstream.settimeout(10)
                    if info['method']=='CONNECT':
                        host=('['+info['host']+']') if ':' in info['host'] else info['host'];target=host+':'+str(info['port'])
                        upstream.sendall(('CONNECT '+target+' HTTP/1.1\r\nHost: '+target+'\r\n\r\n').encode())
                        try:response,extra=read_header(upstream,budget=10)
                        except ValueError as error:raise OSError('Invalid backend CONNECT response') from error
                        line=response.split(b'\r\n',1)[0].split()
                        if len(line)<2 or line[0] not in (b'HTTP/1.0',b'HTTP/1.1') or line[1]!=b'200':raise OSError('Upstream CONNECT failed')
                        committed=True
                        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                        if extra:conn.sendall(extra)
                    else:
                        committed=True;upstream.sendall(header)
                    if pending:upstream.sendall(pending)
                    self.routes.transport_success(group,server['name'])
                    self.routes.record(group,info['host'],server['name'])
                    break
                except OSError:
                    if upstream:
                        with self.lock:self.active.discard(upstream)
                        upstream.close();upstream=None
                    if committed:return  # Never retry after a response or application bytes are committed.
                    self.routes.transport_failure(group,server['name'])
            if upstream is None:self.error(conn,502);return
            # One shared bidirectional idle clock; half-close preserves uploads and TCP backpressure.
            conn.setblocking(False);upstream.setblocking(False)
            peers={conn:upstream,upstream:conn};buffers={conn:bytearray(),upstream:bytearray()}
            readers={conn,upstream};write_closed=set();last_activity=time.monotonic()
            while not self.stop.is_set():
                if time.monotonic()-last_activity>=300:break
                for dst in peers:
                    if peers[dst] not in readers and not buffers[dst] and dst not in write_closed:
                        with contextlib.suppress(OSError):dst.shutdown(socket.SHUT_WR)
                        write_closed.add(dst)
                if not readers and not any(buffers.values()):break
                readable=[src for src in readers if len(buffers[peers[src]])<262144]
                writable=[dst for dst in peers if buffers[dst]]
                can_read,can_write,_=select.select(readable,writable,[],.5)
                for src in can_read:
                    try:data=src.recv(65536)
                    except BlockingIOError:continue
                    if data:
                        buffers[peers[src]].extend(data);last_activity=time.monotonic()
                    else:readers.discard(src)
                for dst in can_write:
                    try:sent=dst.send(buffers[dst])
                    except BlockingIOError:continue
                    if sent<=0:raise OSError('Relay send returned zero')
                    del buffers[dst][:sent];last_activity=time.monotonic()
        except (ValueError,UnicodeError):
            if not committed:self.error(conn,400)
        except OSError:pass
        finally:
            with self.lock:self.active.discard(conn);self.active.discard(upstream)
            conn.close()
            if upstream:upstream.close()
            self.slots.release()
    def close(self):
        self.stop.set();self.listener.close()
        with self.lock:
            for conn in list(self.active):
                with contextlib.suppress(OSError):conn.shutdown(socket.SHUT_RDWR);conn.close()
        if hasattr(self,'thread'):self.thread.join(timeout=2)
