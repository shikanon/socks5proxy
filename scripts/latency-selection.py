#!/usr/bin/env python3
"""Bounded end-to-end HTTPS latency polling and stable ranking; no network or process control."""
import hashlib
from datetime import datetime
import json
import math
import statistics
from urllib.parse import urlsplit

DEFAULTS = {
    'enabled': False,
    'interval_seconds': 1800,
    'url': 'https://www.google.com/generate_204',
    'samples': 3,
    'min_successful_samples': 2,
    'timeout_seconds': 8,
    'switch_improvement_ratio': 0.15,
    'switch_improvement_ms': 100,
    'history_rounds': 48,
}
METRIC = 'https_time_starttransfer_ms'


def validate(raw):
    if raw is None:
        return dict(DEFAULTS)
    if not isinstance(raw, dict) or set(raw) - set(DEFAULTS):
        raise ValueError('Unknown latency policy fields')
    value = dict(DEFAULTS, **raw)
    if type(value['enabled']) is not bool:
        raise ValueError('enabled must be Boolean')
    for key, low, high in [('interval_seconds', 1800, 86400), ('samples', 3, 9),
                          ('min_successful_samples', 2, 9), ('timeout_seconds', 3, 20),
                          ('history_rounds', 1, 96)]:
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError('Invalid latency setting: ' + key)
    if value['min_successful_samples'] > value['samples']:
        raise ValueError('Successful samples exceed total samples')
    for key, low, high in [('switch_improvement_ratio', 0, 0.9), ('switch_improvement_ms', 0, 60000)]:
        n = value[key]
        if type(n) not in (int, float) or not math.isfinite(n) or not low <= n <= high:
            raise ValueError('Invalid hysteresis setting: ' + key)
    target = urlsplit(value['url'])
    if value['url'] != DEFAULTS['url']:
        raise ValueError('Current probe contract requires the fixed Google HTTPS 204 target')
    if (target.scheme != 'https' or not target.hostname or target.username or target.password
            or target.fragment or target.port not in (None, 443)):
        raise ValueError('Latency target must be credential-free HTTPS on port 443')
    return value


def curl_arguments(port, policy, connect_timeout):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid private probe port')
    return ['/usr/bin/curl', '--silent', '--show-error', '--noproxy', '',
            '--proxy', 'http://127.0.0.1:' + str(port), '--connect-timeout', str(connect_timeout),
            '--max-time', str(policy['timeout_seconds']), '--proto', '=https',
            '--output', '/dev/null', '--write-out', '%{http_code}|%{time_starttransfer}|%{ssl_verify_result}',
            '--', policy['url']]


def parse_sample(exit_code, stdout, stderr=''):
    result = {'ok': False, 'curl_exit': exit_code, 'raw_metrics': stdout.strip(),
              'error': stderr.strip()[:500], 'response_ms': None}
    try:
        status, elapsed, tls = stdout.strip().split('|')
        ms = float(elapsed) * 1000
        result.update(http_code=status, tls_verify_result=tls)
        if exit_code == 0 and status == '204' and tls == '0' and math.isfinite(ms) and ms > 0:
            result.update(ok=True, response_ms=ms, error='')
        elif not result['error']:
            result['error'] = 'HTTPS status, timing or TLS validation did not pass'
    except (ValueError, OverflowError):
        if not result['error']:
            result['error'] = 'Invalid curl measurement'
    return result


def measure(servers, policy, sample, stop, round_number=0):
    """Three interleaved passes prevent all of one backend being measured first."""
    rows = {s['name']: {'name': s['name'], 'endpoint': s['endpoint'], 'samples': []} for s in servers}
    offset = round_number % len(servers)
    order = servers[offset:] + servers[:offset]
    execution_order = []
    for _ in range(policy['samples']):
        for server in order:
            if stop.is_set():
                return None
            try:
                result = sample(server)
            except Exception as error:
                result = {'ok': False, 'response_ms': None, 'error': type(error).__name__}
            rows[server['name']]['samples'].append(result)
            execution_order.append(server['name'])
        if stop.is_set():
            return None
    for row in rows.values():
        good = [v['response_ms'] for v in row['samples'] if v.get('ok') and
                type(v.get('response_ms')) in (float, int) and math.isfinite(v['response_ms']) and v['response_ms'] > 0]
        row['successful_samples'] = len(good)
        row['valid'] = len(good) >= policy['min_successful_samples']
        row['median_response_ms'] = statistics.median(good) if row['valid'] else None
    return {'measurements': [rows[s['name']] for s in servers], 'execution_order': execution_order}


class Selection:
    """Only scheduled completed rounds can change performance preference."""
    def __init__(self, policy, servers, cache=None):
        self.policy = validate(policy)
        self.servers = [dict(s) for s in servers]
        self.names = [s['name'] for s in servers]
        raw = json.dumps({'policy': self.policy, 'servers': self.servers}, sort_keys=True).encode()
        self.fingerprint = hashlib.sha256(raw).hexdigest()
        self.selected = None
        self.ranking = []
        self.last_valid_at = None
        self.last_round = None
        self.next_probe_at = None
        self.round_count = 0
        self.history = []
        if isinstance(cache, dict) and cache.get('version') == 1 and cache.get('config_fingerprint') == self.fingerprint:
            try:
                selected = cache['selected']
                ranking = cache['ranking']
                if selected is not None and selected not in self.names:
                    raise ValueError('Unknown cached backend')
                if not isinstance(ranking, list) or len(set(ranking)) != len(ranking) or any(n not in self.names for n in ranking):
                    raise ValueError('Invalid cached ranking')
                for key in ['next_probe_at', 'last_valid_at']:
                    n = cache[key]
                    if n is not None and (type(n) not in (int, float) or not math.isfinite(n)):
                        raise ValueError('Invalid cached timestamp')
                if type(cache['round_count']) is not int or cache['round_count'] < 0:
                    raise ValueError('Invalid cached counter')
                if not isinstance(cache['history'], list) or any(not isinstance(row, dict) for row in cache['history']):
                    raise ValueError('Invalid cached history')
                self.selected, self.ranking = selected, list(ranking)
                self.next_probe_at, self.last_valid_at = cache['next_probe_at'], cache['last_valid_at']
                self.round_count = cache['round_count']
                self.history = cache['history'][-self.policy['history_rounds']:]
                self.last_round = self.history[-1] if self.history else None
            except (KeyError, ValueError, TypeError):
                # A corrupt cache never changes authorized server or source settings.
                self.selected, self.ranking = None, []
                self.next_probe_at, self.last_valid_at = None, None
                self.round_count, self.history, self.last_round = 0, [], None

    def seconds_until_due(self, now):
        if self.next_probe_at is None:
            return 0
        return max(0, min(self.policy['interval_seconds'], self.next_probe_at - now))

    def route_order(self, now):
        if (not self.policy['enabled'] or self.last_valid_at is None
                or now - self.last_valid_at > 2 * self.policy['interval_seconds']
                or now < self.last_valid_at):
            return []
        return list(self.ranking)

    def complete(self, measurement, healthy, started_at, finished_at):
        old = self.selected
        scores = {row['name']: row['median_response_ms'] for row in measurement['measurements']
                  if row['name'] in self.names and row['valid'] and healthy.get(row['name'], False)
                  and type(row['median_response_ms']) in (int, float)
                  and math.isfinite(row['median_response_ms']) and row['median_response_ms'] > 0}
        ordered = sorted(scores, key=lambda name: (scores[name], self.names.index(name)))
        reason = 'no_valid_healthy_measurements'
        if ordered:
            best = ordered[0]
            if old not in scores:
                self.selected = best
                reason = 'initial_selection' if old is None else 'incumbent_not_eligible'
            elif best == old:
                reason = 'incumbent_fastest'
            else:
                improvement = scores[old] - scores[best]
                ratio = improvement / scores[old]
                if improvement >= self.policy['switch_improvement_ms'] and ratio >= self.policy['switch_improvement_ratio']:
                    self.selected = best
                    reason = 'challenger_exceeds_hysteresis'
                else:
                    reason = 'improvement_below_hysteresis'
            self.ranking = [self.selected] + [n for n in ordered if n != self.selected]
            self.last_valid_at = finished_at
        self.round_count += 1
        next_due = started_at + self.policy['interval_seconds']
        # Long runs and sleep never generate a burst of missed rounds.
        while next_due <= finished_at:
            next_due += self.policy['interval_seconds']
        self.next_probe_at = next_due
        record = dict(measurement, started_at=started_at, finished_at=finished_at, round_number=self.round_count,
                      selected_before=old, selected=self.selected, ranking=list(self.ranking),
                      selection_changed=self.selected != old, reason=reason,
                      eligible_health={n: bool(healthy.get(n, False)) for n in self.names},
                      metric=METRIC, target=self.policy['url'])
        self.last_round = record
        self.history = (self.history + [record])[-self.policy['history_rounds']:]
        return record

    def cache(self):
        return {'version': 1, 'config_fingerprint': self.fingerprint, 'selected': self.selected,
                'ranking': self.ranking, 'last_valid_at': self.last_valid_at,
                'next_probe_at': self.next_probe_at, 'round_count': self.round_count, 'history': self.history}

    def summary(self, now, running=False, error=''):
        last = self.last_round or {}
        def local_time(value):
            return datetime.fromtimestamp(value).astimezone().isoformat(timespec='seconds') if value is not None else None
        return {'enabled': self.policy['enabled'], 'metric': METRIC, 'target': self.policy['url'],
                'interval_seconds': self.policy['interval_seconds'], 'samples_per_server': self.policy['samples'],
                'min_successful_samples': self.policy['min_successful_samples'],
                'switch_improvement_ratio': self.policy['switch_improvement_ratio'],
                'switch_improvement_ms': self.policy['switch_improvement_ms'],
                'selected': self.selected, 'active_ranking': self.route_order(now),
                'last_probe_started_at': last.get('started_at'), 'last_probe_finished_at': last.get('finished_at'),
                'next_probe_at': self.next_probe_at, 'last_probe_local': local_time(last.get('finished_at')),
                'next_probe_local': local_time(self.next_probe_at), 'round_count': self.round_count, 'running': running,
                'last_selection_reason': last.get('reason'), 'last_error': error,
                'latest_measurements': last.get('measurements', []), 'history_file': 'latency-state.json'}
