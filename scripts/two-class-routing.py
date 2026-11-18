#!/usr/bin/env python3
"""Pure migration: unify AI groups, preserving defaults and every domain/probe."""
import copy

POLICY = {'group':'overseas_ai', 'denied_country_codes':['HK','MO'],
          'unknown_action':'deny', 'interval_seconds':1800, 'max_age_seconds':3600}

def migrate(config, preferences=None):
    result = copy.deepcopy(config)
    routes = result['domain_routes']; groups = routes['groups']
    if set(groups) != {'ordinary', 'openai', 'claude'}:
        raise ValueError('Expected explicit ordinary/openai/claude source groups')
    first, second = groups['openai'], groups['claude']
    if first['default_server'] != second['default_server']:
        raise ValueError('AI defaults conflict; confirm a shared default')
    if first['allowed_servers'] != second['allowed_servers'] or first['probe_servers'] != second['probe_servers']:
        raise ValueError('AI authorized node sets differ; confirm shared candidates')
    shared = copy.deepcopy(first)
    for field in ['suffixes','exact_hosts','probes']:
        for value in second[field]:
            if value not in shared[field]: shared[field].append(copy.deepcopy(value))
    if len(shared['probes']) > 4:raise ValueError('Too many merged probes')
    routes['groups'] = {'ordinary':groups['ordinary'], 'overseas_ai':shared}
    routes['egress_policy'] = copy.deepcopy(POLICY)
    preferences = preferences or {}
    if any(k not in groups for k in preferences):raise ValueError('Unknown preference')
    ai = {preferences[k] for k in ['openai','claude'] if preferences.get(k) is not None}
    if len(ai) > 1:raise ValueError('AI manual preferences conflict')
    manual = {'ordinary':preferences['ordinary']} if preferences.get('ordinary') is not None else {}
    if ai:manual['overseas_ai'] = ai.pop()
    return result, manual
