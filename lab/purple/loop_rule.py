#!/usr/bin/env python3
"""Deploy structured candidate rules only to the separately owned local lab.

This optional demo adapter never receives arbitrary SPL, changes the existing
CRS search, connects to cloud Splunk, or grants the product search user writes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse

from bootstrap_splunk import (APP, INDEX, Client, HTTPError, LabError, content,
                              ensure_saved_search_acl, private_read, private_write)

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-runtime/purple-lab'
PREFIX = 'artex_loop_'
OWNER = 'AegisLoop isolated lab rule; '
FIELDS = frozenset(('method', 'path', 'request_target', 'query_string', 'target',
                    'action', 'status', 'rule_id', 'event_kind', 'matched_rules',
                    'message', 'engine_mode'))


def literal(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t') + '"'


def validate(rule):
    if not isinstance(rule, dict) or set(rule) != {'name', 'any'}:
        raise LabError('규칙은 name과 any만 포함해야 합니다')
    if not isinstance(rule['name'], str) or not 1 <= len(rule['name']) <= 120:
        raise LabError('규칙 이름은 1~120자여야 합니다')
    branches = rule['any']
    if not isinstance(branches, list) or not 1 <= len(branches) <= 24:
        raise LabError('규칙 분기는 1~24개여야 합니다')
    for branch in branches:
        if not isinstance(branch, dict) or set(branch) != {'all'} or not isinstance(branch['all'], list) or not 1 <= len(branch['all']) <= 12:
            raise LabError('각 분기는 all 조건 1~12개를 포함해야 합니다')
        for c in branch['all']:
            if not isinstance(c, dict) or set(c) != {'field', 'op', 'value', 'case_sensitive'}:
                raise LabError('조건 필드 구성이 올바르지 않습니다')
            if not isinstance(c['field'], str) or c['field'] not in FIELDS or c['op'] not in ('equals', 'contains'):
                raise LabError('실습의 관측 필드와 equals/contains만 사용할 수 있습니다')
            if not isinstance(c['value'], str) or not 1 <= len(c['value']) <= 256 or any(ord(ch) < 32 for ch in c['value']):
                raise LabError('조건 값은 제어문자 없는 1~256자여야 합니다')
            if not isinstance(c['case_sensitive'], bool):
                raise LabError('case_sensitive는 boolean이어야 합니다')
            if re.search(r'(?i)AEGIS_VERIFY_|X-ARTEX-Verification|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', c['value']):
                raise LabError('실행 식별자는 탐지 규칙의 조건으로 사용할 수 없습니다')
    return rule


def expression(rule):
    validate(rule)
    branches = []
    for branch in rule['any']:
        conditions = []
        for c in branch['all']:
            field = "'" + c['field'] + "'"
            observed = 'tostring(' + field + ')'
            expected = literal(c['value'])
            if not c['case_sensitive']:
                observed, expected = 'lower(' + observed + ')', 'lower(' + expected + ')'
            if c['op'] == 'equals':
                match = observed + '=' + expected
            else:
                value = c['value'] if c['case_sensitive'] else c['value'].lower()
                match = 'match(' + observed + ',' + literal(re.escape(value)) + ')'
            conditions.append('(isnotnull(' + field + ') AND mvcount(' + field + ')=1 AND ' + match + ')')
            if c['field'] in ('path', 'request_target', 'query_string'):
                flag = "'" + c['field'] + "_truncated'"
                conditions[-1] = '(coalesce(lower(tostring(' + flag + ')),"false")!="true" AND coalesce(tostring(' + flag + '),"0")!="1" AND ' + conditions[-1] + ')'
        branches.append('(' + ' AND '.join(conditions) + ')')
    return '(' + ' OR '.join(branches) + ')'


def digest(rule):
    # Same field order and escaping as json.Marshal(closedloop.Rule) in Go;
    # native alerts must attribute the exact server-held rule, not another hash.
    ordered = {'name': rule['name'], 'any': [{'all': [
        {k: c[k] for k in ('field', 'op', 'value', 'case_sensitive')}
        for c in branch['all']]} for branch in rule['any']]}
    raw = json.dumps(ordered, ensure_ascii=False, separators=(',', ':'))
    for character, escaped in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'), ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        raw = raw.replace(character, escaped)
    return hashlib.sha256(raw.encode()).hexdigest()


def saved_name(value):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,39}', value):
        raise LabError('배포 이름은 영문 소문자·숫자·밑줄·하이픈 1~40자여야 합니다')
    return PREFIX + value


def values(rule, name, enabled_since):
    sha = digest(rule)
    # index/target/sourcetype/action and window are fixed by this lab adapter.
    # An alert is written by Splunk's real logevent action, never fabricated by
    # the exporter. A request UUID is attribution data, not a rule condition.
    search = ('index="' + INDEX + '" sourcetype="artex:lab:audit" | fields _raw _time | spath '
              '| where _time>=' + f'{enabled_since:.6f}' + ' AND target="purple-lab-target:8080" '
              '| where isnotnull(id) AND isnotnull(artex_verification_id) '
              '| where ' + expression(rule) + ' '
              '| eval audit_event_id=id, alert_id="' + name + ':".id '
              '| dedup alert_id '
              '| eval alert_payload=json_object("id",alert_id,"event_kind","alert",'
              '"artex_verification_id",artex_verification_id,"request_uid",request_uid,'
              '"audit_event_id",id,"timestamp",timestamp,"event_epoch",tonumber(_time),'
              '"alert_created_at",strftime(now(),"%Y-%m-%dT%H:%M:%S.%3N%:z"),'
              '"target",target,"path",path,"action",action,"rule_id",rule_id,'
              '"detection_rule_id","' + name + '","rule_sha256","' + sha + '",'
              '"detection_engine","splunk_saved_search",'
              '"message","AegisLoop structured candidate matched a real native audit") '
              '| fields alert_id alert_payload audit_event_id artex_verification_id request_uid _time')
    return {'search': search, 'description': OWNER + sha, 'disabled': '0',
            'is_scheduled': '1', 'cron_schedule': '* * * * *',
            'dispatch.earliest_time': '-3m', 'dispatch.latest_time': 'now',
            'dispatch.max_time': '45', 'alert_type': 'number of events',
            'alert_comparator': 'greater than', 'alert_threshold': '0',
            'alert.digest_mode': '0', 'alert.track': '1', 'alert.suppress': '1',
            'alert.suppress.fields': 'alert_id', 'alert.suppress.period': '10m',
            'alert.expires': '24h', 'alert.severity': '4', 'actions': 'logevent',
            'action.logevent': '1', 'action.logevent.param.event': '$result.alert_payload$',
            'action.logevent.param.index': INDEX,
            'action.logevent.param.sourcetype': 'artex:lab:alert',
            'action.logevent.param.source': name,
            'action.logevent.param.host': 'purple-lab-splunk'}


def resource(name):
    return '/servicesNS/nobody/' + APP + '/saved/searches/' + urllib.parse.quote(name, safe='')


def lookup(client, name):
    try:
        response = client.request('GET', resource(name))
    except HTTPError as error:
        if error.status == 404:
            return None
        raise
    row = content(response)
    if not row.get('description', '').startswith(OWNER):
        raise LabError('같은 이름의 규칙 소유자를 확인할 수 없어 변경하지 않습니다')
    return row


def deploy(client, rule, name, now=None):
    validate(rule)
    if not name.startswith(PREFIX) or saved_name(name[len(PREFIX):]) != name:
        raise LabError('관리하는 실습 규칙 이름만 배포할 수 있습니다')
    previous = lookup(client, name)
    settings = values(rule, name, time.time() if now is None else now)
    if previous is None:
        client.request('POST', '/servicesNS/nobody/' + APP + '/saved/searches', {'name': name, **settings})
    else:
        client.request('POST', resource(name), settings)
    ensure_saved_search_acl(client, resource(name))
    actual = lookup(client, name)
    if actual is None or actual.get('disabled') not in (False, 0, '0', 'false', 'False') or any(str(actual.get(k, '')) != str(settings[k]) for k in ('search', 'description', 'actions')):
        raise LabError('원격 규칙의 검색식·활성 상태를 확인하지 못했습니다')
    return {'saved_search': name, 'rule_sha256': digest(rule), 'enabled': True,
            'scope': 'isolated_local_lab', 'remote_search_verified': True}


def duplicate_safe(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise LabError('규칙 JSON에 중복 키가 있습니다')
        out[key] = value
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('deploy', 'status', 'disable'))
    parser.add_argument('--name', required=True)
    parser.add_argument('--rule', type=Path)
    args = parser.parse_args()
    try:
        name = saved_name(args.name)
        rule = None
        if args.operation == 'deploy':
            if args.rule is None or args.rule.stat().st_size > 65536:
                raise LabError('64 KiB 이하의 구조화 규칙 JSON 파일을 지정하세요')
            rule = validate(json.loads(args.rule.read_text(), object_pairs_hook=duplicate_safe))
        client = Client('https://127.0.0.1:18089', private_read(STATE/'splunk-management.sha256'), 'admin', private_read(STATE/'splunk-admin-password'))
        if args.operation == 'deploy':
            result = deploy(client, rule, name)
            private_write(STATE/(name + '.json'), json.dumps({'rule': rule, **result}, ensure_ascii=False, indent=2)+'\n')
        else:
            actual = lookup(client, name)
            if actual is None:
                raise LabError('관리하는 실습 규칙을 찾을 수 없습니다')
            if args.operation == 'disable':
                client.request('POST', resource(name), {'disabled': '1'})
                actual = lookup(client, name)
            result = {'saved_search': name, 'enabled': str(actual.get('disabled')) in ('0', 'False', 'false'), 'scope': 'isolated_local_lab'}
            if args.operation == 'disable' and result['enabled']:
                raise LabError('실습 규칙 비활성화를 확인하지 못했습니다')
        print(json.dumps(result, ensure_ascii=False))
    except (LabError, OSError, ValueError, TypeError, KeyError):
        print('실습 규칙 작업에 실패했습니다. 규칙 형식·실습 Splunk 상태·사설 인증 파일을 확인하세요.')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
