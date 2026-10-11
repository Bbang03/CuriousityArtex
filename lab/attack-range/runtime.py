"""Pinned, fixed-scope adapter for the owned Windows Atomic/Splunk range.

No user commands, targets, free SPL, credential responses, or synthetic events.
"""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import urllib.parse
from uuid import UUID
import xml.etree.ElementTree as ET

CATALOG = {
    'whoami': ('T1033', 'aab580c7-cc30-4a7c-b5a9-46a29066b022', 'whoami.exe'),
    'tasklist': ('T1057', 'c5806a4f-62b8-4900-980b-c7ec004e9908', 'tasklist.exe'),
    'systeminfo': ('T1082', '66703791-c902-4560-8770-42b8a91f7667', 'systeminfo.exe'),
}
FIELDS = frozenset(('Image', 'CommandLine', 'ParentImage', 'EventCode', 'User'))
PREFIX = 'aegis_range_'
OWNER = 'AegisLoop owned Windows range; '
MAX_EVENTS = 5000
NATIVE_SETTLE_SECONDS = 150


class RangeError(Exception):
    """A sanitized error, safe to expose. Never wrap raw transport errors."""


class RemoteError(RangeError):
    def __init__(self, status):
        self.status = status
        super().__init__('Splunk 관리 API가 요청을 거부했습니다 (HTTP %d).' % status)


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def epoch(value):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError, AttributeError):
        raise RangeError('증거 시각 형식을 확인하지 못했습니다.') from None


def uuid_string(value):
    if not isinstance(value, str):
        raise RangeError('UUID 형식이 올바르지 않습니다.')
    try:
        result = str(UUID(value))
    except (ValueError, AttributeError):
        raise RangeError('UUID 형식이 올바르지 않습니다.') from None
    if result != value.lower():
        raise RangeError('정규 UUID 형식이 필요합니다.')
    return result


def duplicate_safe(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RangeError('JSON에 중복 필드가 있습니다.')
        result[key] = value
    return result


def json_read(data):
    try:
        return json.loads(data, object_pairs_hook=duplicate_safe, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        raise RangeError('JSON 형식이 올바르지 않습니다.') from None


def private_read(path, maximum=65536):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise RangeError('비공개 설정 파일 권한은 600 또는 400이어야 합니다.')
            data = handle.read(maximum + 1)
    except OSError:
        raise RangeError('비공개 설정 파일을 읽지 못했습니다.') from None
    if not data or len(data) > maximum:
        raise RangeError('비공개 설정 파일 크기가 올바르지 않습니다.')
    return data


def load_config(path):
    return validate_config(json_read(private_read(path)))


def validate_config(c):
    if not isinstance(c, dict):
        raise RangeError('실습 설정 형식이 올바르지 않습니다.')
    c = copy.deepcopy(c)
    required = ('name', 'router_host', 'ssh_key', 'known_hosts', 'windows_host', 'windows_hostname', 'windows_user',
                'windows_password', 'splunk_host', 'splunk_user', 'splunk_password', 'splunk_tls_sha256', 'scenarios')
    if any(not c.get(k) for k in required):
        raise RangeError('실습 연결 설정에 필수 항목이 없습니다.')
    if c.get('router_user') != 'ubuntu' or c.get('splunk_user') != 'admin' or c.get('index') != 'win' or c.get('alert_index') != 'aegis_range_alerts':
        raise RangeError('고정된 실습 사용자와 로그 인덱스만 허용됩니다.')
    if not isinstance(c['router_host'], str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', c['router_host']):
        raise RangeError('SSH 라우터 설정이 올바르지 않습니다.')
    for key in ('windows_host', 'splunk_host'):
        try:
            address = ipaddress.ip_address(c[key])
            if address.version != 4 or not any(address in ipaddress.ip_network(network) for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
                raise ValueError()
        except (ValueError, TypeError):
            raise RangeError('실습 내부 주소 설정이 올바르지 않습니다.') from None
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', c['windows_hostname']):
        raise RangeError('Windows 호스트 이름이 올바르지 않습니다.')
    if not re.fullmatch(r'[0-9a-f]{64}', c['splunk_tls_sha256']):
        raise RangeError('Splunk 인증서 핀 형식이 올바르지 않습니다.')
    for key in ('ssh_key', 'known_hosts'):
        if not isinstance(c[key], str) or not c[key].startswith('/') or '\n' in c[key]:
            raise RangeError('SSH 파일 경로가 올바르지 않습니다.')
    if c.get('sysmon_source', 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational') != 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' or c.get('sysmon_sourcetype', 'XmlWinEventLog') != 'XmlWinEventLog':
        raise RangeError('고정된 Sysmon 원본 로그만 허용됩니다.')
    scenarios = c['scenarios']
    if not isinstance(scenarios, list) or len(scenarios) != len(CATALOG):
        raise RangeError('등록된 Atomic 시나리오 세 개가 필요합니다.')
    seen = set()
    for s in scenarios:
        if not isinstance(s, dict) or s.get('id') not in CATALOG or s['id'] in seen:
            raise RangeError('Atomic 시나리오 목록이 올바르지 않습니다.')
        seen.add(s['id'])
        if (s.get('technique'), s.get('atomic_guid'), s.get('image')) != CATALOG[s['id']]:
            raise RangeError('등록된 Atomic GUID와 실행 파일만 허용됩니다.')
        if not re.fullmatch(r'[0-9a-f]{64}', s.get('yaml_sha256', '')):
            raise RangeError('설치된 Atomic YAML의 SHA256 확인이 필요합니다.')
        if not isinstance(s.get('name'), str) or not 1 <= len(s['name']) <= 120 or not isinstance(s.get('description'), str) or len(s['description']) > 1000:
            raise RangeError('Atomic 시나리오 설명이 올바르지 않습니다.')
    return c


def literal(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def validate_rule(rule):
    if isinstance(rule, dict) and rule.get('kind') == 'scheduled_task_chain':
        from chain_runtime import validate_chain_rule
        return validate_chain_rule(rule)
    if not isinstance(rule, dict) or set(rule) != {'name', 'any'} or not isinstance(rule['name'], str) or not 1 <= len(rule['name']) <= 120 or any(ord(c) < 32 for c in rule['name']):
        raise RangeError('규칙 이름과 any 조건을 확인하세요.')
    if not isinstance(rule['any'], list) or not 1 <= len(rule['any']) <= 24:
        raise RangeError('규칙 분기는 1~24개여야 합니다.')
    for b in rule['any']:
        if not isinstance(b, dict) or set(b) != {'all'} or not isinstance(b['all'], list) or not 1 <= len(b['all']) <= 12:
            raise RangeError('규칙의 all 조건은 1~12개여야 합니다.')
        for c in b['all']:
            if not isinstance(c, dict) or set(c) != {'field', 'op', 'value', 'case_sensitive'} or c['field'] not in FIELDS or c['op'] not in ('equals', 'contains') or not isinstance(c['case_sensitive'], bool):
                raise RangeError('허용된 Sysmon 필드의 equals/contains 조건만 사용할 수 있습니다.')
            if not isinstance(c['value'], str) or not 1 <= len(c['value'].encode('utf-8')) <= 1024 or any(ord(ch) < 32 for ch in c['value']):
                raise RangeError('규칙 값은 제어문자 없는 1~1024바이트여야 합니다.')
            if re.search(r'(?i)aegisloop[\\/]runs|correlation|AEGIS_VERIFY_|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', c['value']):
                raise RangeError('실행 식별자는 탐지 규칙으로 사용할 수 없습니다.')
    return copy.deepcopy(rule)


def rule_digest(rule):
    rule = validate_rule(rule)
    if rule.get('kind') == 'scheduled_task_chain':
        ordered = {key: rule[key] for key in ('kind', 'name', 'profile')}
    else:
        ordered = {'name': rule['name'], 'any': [{'all': [{k: c[k] for k in ('field', 'op', 'value', 'case_sensitive')} for c in b['all']]} for b in rule['any']]}
    raw = json.dumps(ordered, ensure_ascii=False, separators=(',', ':'))
    for ch, escaped in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'), ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        raw = raw.replace(ch, escaped)
    return hashlib.sha256(raw.encode()).hexdigest()


def rule_expression(rule):
    rule = validate_rule(rule)
    branches = []
    for b in rule['any']:
        terms = []
        for c in b['all']:
            field = "'" + c['field'] + "'"
            observed = 'tostring(' + field + ')'
            value = c['value']
            if not c['case_sensitive']:
                observed, value = 'lower(' + observed + ')', value.lower()
            condition = observed + '=' + literal(value) if c['op'] == 'equals' else 'match(' + observed + ',' + literal(re.escape(value)) + ')'
            terms.append('(isnotnull(' + field + ') AND mvcount(' + field + ')=1 AND ' + condition + ')')
        branches.append('(' + ' AND '.join(terms) + ')')
    return '(' + ' OR '.join(branches) + ')'


def baseline_rule():
    return {'name': 'Windows 현재 사용자 탐색 기본 규칙', 'any': [{'all': [{'field': 'Image', 'op': 'contains', 'value': '\\whoami.exe', 'case_sensitive': False}]}]}


def sysmon_extract():
    fields = ['Image', 'CommandLine', 'ParentImage', 'User', 'ProcessGuid', 'ParentProcessGuid']
    spl = ''
    for field in fields:
        pattern = "(?s)<Data\\s+Name=['\"]" + field + "['\"]>(?<" + field + ">[^<]*)</Data>"
        spl += ' | rex field=_raw ' + literal(pattern)
    spl += ' | rex field=_raw "<EventID>(?<EventCode>[0-9]+)</EventID>" | rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"'
    # Decode the five named XML entities, ampersand last. Numeric entities are
    # conservatively not interpreted by this bounded native rule adapter.
    for field in fields + ['Computer']:
        expression = field
        for old, new in (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&apos;', "'"), ('&amp;', '&')):
            expression = 'replace(' + expression + ',' + literal(old) + ',' + literal(new) + ')'
        spl += ' | eval ' + field + '=' + expression
    return spl


def rule_search(c, rule, name, enabled_since):
    if isinstance(rule, dict) and rule.get('kind') == 'scheduled_task_chain':
        if not re.fullmatch(r'aegis_range_[a-f0-9]{32}_(baseline|candidate)', name) or not isinstance(enabled_since, (float, int)) or enabled_since < 0:
            raise RangeError('관리되는 규칙과 활성 시각만 허용됩니다.')
        from chain_runtime import rule_search as chain_rule_search
        return chain_rule_search(c, rule, name, enabled_since)
    if not re.fullmatch(r'aegis_range_[a-f0-9]{32}_(baseline|candidate)', name):
        raise RangeError('관리되는 시연 규칙 이름만 허용됩니다.')
    if not isinstance(enabled_since, (float, int)) or enabled_since < 0:
        raise RangeError('규칙 활성 시각이 올바르지 않습니다.')
    return ('index="win" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" sourcetype="XmlWinEventLog"'
            + sysmon_extract() + ' | where EventCode="1" AND lower(Computer)=' + literal(c['windows_hostname'].lower())
            + ' AND _time>=' + format(enabled_since, '.6f') + ' | where ' + rule_expression(rule)
            + ' | eval audit_process_guid=lower(trim(ProcessGuid,"{}")), alert_id=' + literal(name + ':') + '.audit_process_guid'
            + ' | where match(audit_process_guid,"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$") | dedup alert_id'
            + ' | eval alert_payload=json_object("event_kind","alert","id",alert_id,"audit_process_guid",audit_process_guid,'
            '"host",Computer,"Image",Image,"event_epoch",tonumber(_time),"alert_created_at",strftime(now(),"%Y-%m-%dT%H:%M:%S.%3N%:z"),'
            '"detection_rule_id",' + literal(name) + ',"rule_sha256",' + literal(rule_digest(rule)) + ',"detection_engine","splunk_saved_search")'
            + ' | fields alert_id alert_payload audit_process_guid _time')


class Tunnel:
    def __init__(self, config):
        self.config, self.process, self.lock = config, None, threading.Lock()

    def ensure(self):
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                return
            c = self.config
            command = ['ssh', '-N', '-T', '-i', c['ssh_key'], '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes',
                       '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + c['known_hosts'], '-o', 'GlobalKnownHostsFile=/dev/null',
                       '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15',
                       '-o', 'ServerAliveCountMax=2', '-L', '127.0.0.1:15985:' + c['windows_host'] + ':5985',
                       '-L', '127.0.0.1:15889:' + c['splunk_host'] + ':8089', 'ubuntu@' + c['router_host']]
            try:
                self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if self.process.poll() is not None:
                        break
                    try:
                        for port in (15985, 15889):
                            with socket.create_connection(('127.0.0.1', port), timeout=.5):
                                pass
                        # ExitOnForwardFailure must get a chance to reject occupied ports.
                        time.sleep(.25)
                        if self.process.poll() is None:
                            return
                    except OSError:
                        time.sleep(.2)
                self.close()
            except OSError:
                self.close()
            raise RangeError('고정된 SSH 터널을 연결하지 못했습니다.')

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None


def valid_certificate(der):
    fd, filename = tempfile.mkstemp(suffix='.pem')
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        cert = ssl._ssl._test_decode_cert(filename)
        now = time.time()
        if not ssl.cert_time_to_seconds(cert['notBefore']) <= now <= ssl.cert_time_to_seconds(cert['notAfter']):
            raise RangeError('Splunk 인증서가 만료됐거나 아직 유효하지 않습니다.')
    except (ssl.SSLError, KeyError, ValueError):
        raise RangeError('Splunk 인증서의 유효 기간을 확인하지 못했습니다.') from None
    finally:
        os.unlink(filename)


class Splunk:
    def __init__(self, config, tunnel):
        self.config, self.tunnel = config, tunnel

    def raw(self, method, path, form=None, limit=16 << 20):
        self.tunnel.ensure()
        if not re.fullmatch(r'/services(?:NS/admin/search)?/[A-Za-z0-9_/.%?-]+', path):
            raise RangeError('고정된 Splunk API만 허용됩니다.')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        connection = http.client.HTTPSConnection('127.0.0.1', 15889, timeout=25, context=context)
        try:
            connection.connect()
            der = connection.sock.getpeercert(binary_form=True)
            valid_certificate(der)
            if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self.config['splunk_tls_sha256']):
                raise RangeError('Splunk 인증서가 설정된 핀과 다릅니다.')
            credentials = base64.b64encode((self.config['splunk_user'] + ':' + self.config['splunk_password']).encode()).decode()
            headers = {'Authorization': 'Basic ' + credentials, 'Accept': 'application/json'}
            body = None
            if form is not None:
                body = urllib.parse.urlencode(form).encode()
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            if method == 'GET' and form is not None:
                query = urllib.parse.urlencode({'output_mode': 'json', **form})
                body = None
            else:
                query = 'output_mode=json'
            connection.request(method, path + '?' + query, body, headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise RemoteError(response.status)
            data = response.read(limit + 1)
            if len(data) > limit:
                raise RangeError('Splunk 응답이 조회 한도를 넘었습니다.')
            return data
        except (OSError, ssl.SSLError, http.client.HTTPException):
            raise RangeError('Splunk 연결을 완료하지 못했습니다.') from None
        finally:
            connection.close()

    def request(self, method, path, form=None):
        data = self.raw(method, path, form)
        return json_read(data) if data else {}

    def search(self, spl, start, finish):
        # A completed job and resultCount establish empty-result completeness;
        # export's missing terminal marker can never be interpreted as no alert.
        result = {'rows': [], 'complete': False, 'warnings': [], 'search': spl, 'window_start': start, 'window_end': finish, 'collected_at': utcnow()}
        originals = []
        try:
            data = self.raw('POST', '/services/search/jobs', {'search': spl, 'earliest_time': format(start, '.6f'), 'latest_time': format(finish, '.6f'), 'exec_mode': 'normal', 'auto_cancel': '60', 'max_time': '45'})
            originals.append(data)
            sid = json_read(data).get('sid')
            if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', sid):
                raise RangeError('Splunk 검색 작업 ID를 확인하지 못했습니다.')
            deadline = time.monotonic() + 50
            job = None
            while time.monotonic() < deadline:
                raw = self.raw('GET', '/services/search/jobs/' + sid)
                originals.append(raw)
                entry = json_read(raw).get('entry', [])
                if len(entry) != 1:
                    raise RangeError('Splunk 검색 상태를 확인하지 못했습니다.')
                job = entry[0].get('content', {})
                if str(job.get('isFailed', '0')).lower() in ('1', 'true') or job.get('dispatchState') == 'FAILED':
                    raise RangeError('Splunk 검색이 정상 완료되지 않았습니다.')
                if str(job.get('isDone', '0')).lower() in ('1', 'true'):
                    break
                time.sleep(.5)
            else:
                raise RangeError('Splunk 검색 작업의 완료 대기 시간이 초과됐습니다.')
            if job.get('dispatchState') != 'DONE' or str(job.get('isFinalized', '0')).lower() in ('1', 'true'):
                raise RangeError('Splunk 검색이 부분 결과로 종료됐습니다.')
            raw = self.raw('GET', '/services/search/jobs/' + sid + '/results', {'count': MAX_EVENTS + 1, 'offset': 0})
            originals.append(raw)
            response = json_read(raw)
            rows = response.get('results')
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise RangeError('Splunk 원본 검색 결과 형식을 확인하지 못했습니다.')
            result['rows'] = rows[:MAX_EVENTS]
            messages = list(response.get('messages', [])) + list(job.get('messages', []))
            if any(str(m.get('type', '')).upper() not in ('INFO', 'DEBUG') for m in messages if isinstance(m, dict)):
                result['warnings'].append('Splunk 검색 진단 메시지가 있어 완전성을 확인할 수 없습니다.')
            count = int(job.get('resultCount', -1))
            if len(rows) > MAX_EVENTS or count != len(rows):
                result['warnings'].append('Splunk 결과 제한 또는 누락이 있어 전체 로그 범위를 확인할 수 없습니다.')
            result['complete'] = not result['warnings'] and count == len(rows)
        except (RangeError, ValueError, TypeError):
            result['warnings'].append('Splunk 원본 검색을 정상 완료하지 못했습니다. 부분 결과로 판정하지 않습니다.')
        result['raw_responses'] = [base64.b64encode(raw).decode() for raw in originals]
        result['response_sha256'] = [hashlib.sha256(raw).hexdigest() for raw in originals]
        return result

    def ensure_alert_index(self):
        resource = '/services/data/indexes/aegis_range_alerts'
        try:
            actual = self.request('GET', resource)
        except RemoteError as error:
            if error.status != 404:
                raise
            self.request('POST', '/services/data/indexes', {'name': 'aegis_range_alerts', 'maxTotalDataSizeMB': '256', 'frozenTimePeriodInSecs': '604800'})
            actual = self.request('GET', resource)
        entries = actual.get('entry', [])
        row = entries[0].get('content', {}) if len(entries) == 1 else {}
        if not 1 <= int(row.get('maxTotalDataSizeMB', 0)) <= 256 or str(row.get('disabled', '0')).lower() not in ('0', 'false'):
            raise RangeError('전용 경보 인덱스의 활성 상태와 256MB 제한을 확인하지 못했습니다.')

    def deploy(self, rule, name):
        self.ensure_alert_index()
        resource = '/servicesNS/admin/search/saved/searches/' + urllib.parse.quote(name, safe='')
        since = time.time()
        settings = {'search': rule_search(self.config, rule, name, since), 'description': OWNER + rule_digest(rule),
                    'disabled': '0', 'is_scheduled': '1', 'cron_schedule': '* * * * *',
                    'dispatch.earliest_time': '-15m', 'dispatch.latest_time': 'now', 'dispatch.max_time': '45',
                    'alert_type': 'number of events', 'alert_comparator': 'greater than', 'alert_threshold': '0',
                    'alert.digest_mode': '0', 'alert.track': '1', 'alert.suppress': '1',
                    'alert.suppress.fields': 'alert_id', 'alert.suppress.period': '10m', 'alert.expires': '24h',
                    'actions': 'logevent', 'action.logevent': '1', 'action.logevent.param.event': '$result.alert_payload$',
                    'action.logevent.param.index': 'aegis_range_alerts', 'action.logevent.param.sourcetype': 'aegis:range:alert',
                    'action.logevent.param.source': name, 'action.logevent.param.host': self.config['windows_hostname']}
        try:
            previous = self.request('GET', resource)
        except RemoteError as e:
            if e.status != 404:
                raise
            previous = None
        if previous is not None:
            entries = previous.get('entry', [])
            if len(entries) != 1 or not entries[0].get('content', {}).get('description', '').startswith(OWNER):
                raise RangeError('동일 이름의 기존 규칙 소유권을 확인할 수 없어 변경하지 않습니다.')
        self.request('POST', resource if previous else '/servicesNS/admin/search/saved/searches', settings if previous else {'name': name, **settings})
        # Private ownership and no sharing prevents other product users changing
        # the bridge-owned search; real scheduling runs as this private owner.
        self.request('POST', resource + '/acl', {'owner': self.config['splunk_user'], 'sharing': 'user', 'perms.read': self.config['splunk_user'], 'perms.write': self.config['splunk_user']})
        actual = self.request('GET', resource)
        entries = actual.get('entry', [])
        row = entries[0].get('content', {}) if len(entries) == 1 else {}
        if str(row.get('disabled')).lower() not in ('0', 'false') or any(str(row.get(k, '')) != str(settings[k]) for k in ('search', 'description', 'actions', 'action.logevent.param.index', 'cron_schedule', 'action.logevent.param.event', 'action.logevent.param.sourcetype')) or any(str(row.get(k, '')).lower() not in ('1', 'true') for k in ('is_scheduled', 'action.logevent')):
            raise RangeError('원격 규칙의 검색식과 활성 상태를 검증하지 못했습니다.')
        return {'rule_id': name, 'rule_sha256': rule_digest(rule), 'enabled_at': since, 'verified': True, 'search': settings['search'], 'settings': copy.deepcopy(settings)}



    def scheduler_proof(self, deployment, start, finish):
        """Prove a real scheduled, successful job covered this execution window.

        Absence/errors are inconclusive, never no-detection. This reads history
        and jobs only; it does not dispatch a shadow or manually run an alert.
        """
        result = {'complete': False, 'jobs': [], 'raw_responses': [], 'warnings': []}
        originals = []
        name = deployment['rule_id']
        resource = '/servicesNS/admin/search/saved/searches/' + urllib.parse.quote(name, safe='')
        try:
            raw = self.raw('GET', resource)
            originals.append(raw)
            entries = json_read(raw).get('entry', [])
            settings = entries[0].get('content', {}) if len(entries) == 1 else {}
            if settings.get('search') != deployment['search'] or settings.get('description') != OWNER + deployment['rule_sha256'] or str(settings.get('disabled')).lower() not in ('0', 'false') or str(settings.get('is_scheduled')).lower() not in ('1', 'true') or settings.get('actions') != 'logevent':
                raise RangeError('배포된 네이티브 규칙의 원격 상태가 변경됐습니다.')
            expected = deployment.get('settings', {})
            if any(str(settings.get(k, '')) != str(expected[k]) for k in ('cron_schedule', 'action.logevent.param.index', 'action.logevent.param.event', 'action.logevent.param.sourcetype') if k in expected) or str(settings.get('action.logevent')).lower() not in ('1', 'true'):
                raise RangeError('네이티브 경보 동작의 활성 상태를 확인하지 못했습니다.')
            raw = self.raw('GET', resource + '/history', {'count': 30, 'sort_dir': 'desc'})
            originals.append(raw)
            history = json_read(raw).get('entry', [])
            if not isinstance(history, list):
                raise RangeError('네이티브 예약 검색 이력을 확인하지 못했습니다.')
            for row in history[:30]:
                metadata = row.get('content', {})
                sid = row.get('name', metadata.get('sid', ''))
                if not isinstance(sid, str) or not re.fullmatch(r'scheduler__[A-Za-z0-9_.-]{1,200}', sid):
                    continue
                if str(metadata.get('isScheduled')).lower() not in ('1', 'true') or str(metadata.get('isDone')).lower() not in ('1', 'true') or str(metadata.get('isFinalized', '0')).lower() in ('1', 'true') or str(metadata.get('isZombie', '0')).lower() in ('1', 'true'):
                    continue
                raw_job = self.raw('GET', '/services/search/jobs/' + sid)
                originals.append(raw_job)
                entries = json_read(raw_job).get('entry', [])
                job = entries[0].get('content', {}) if len(entries) == 1 else {}
                if job.get('dispatchState') != 'DONE' or str(job.get('isDone')).lower() not in ('1', 'true') or str(job.get('isFailed', '0')).lower() in ('1', 'true') or str(job.get('isFinalized', '0')).lower() in ('1', 'true') or str(job.get('isSavedSearch')).lower() not in ('1', 'true') or job.get('label') != name:
                    continue
                # Splunk expands a saved search by adding exactly one leading
                # `search`. A duplicate token becomes an unintended raw keyword
                # filter and must not count as a healthy detector execution.
                if deployment['search'].lstrip().startswith('search ') or job.get('search', '').strip() != 'search ' + deployment['search'].strip():
                    continue
                search_start = float(job.get('searchEarliestTime', -1))
                search_finish = float(job.get('searchLatestTime', -1))
                diagnostic = job.get('messages', [])
                if diagnostic and (not isinstance(diagnostic, list) or any(str(m.get('type', '')).upper() not in ('INFO', 'DEBUG') for m in diagnostic if isinstance(m, dict))):
                    continue
                # Full execution window plus deployment cutoff must be covered.
                if search_start <= start and search_finish >= finish and search_finish >= deployment['enabled_at']:
                    result['jobs'].append({'sid': sid, 'earliest_time': search_start, 'latest_time': search_finish, 'dispatch_state': 'DONE', 'scheduled': True})
                    result['complete'] = True
                    break
            if not result['complete']:
                result['warnings'].append('실행 전체 범위를 포함한 실제 예약 검색의 정상 완료가 확인되지 않았습니다.')
        except (RangeError, ValueError, TypeError, AttributeError):
            result['warnings'].append('네이티브 예약 검색 실행 이력을 검증하지 못했습니다.')
        result['raw_responses'] = [base64.b64encode(raw).decode() for raw in originals]
        result['response_sha256'] = [hashlib.sha256(raw).hexdigest() for raw in originals]
        return result


def process_guid(value):
    try:
        return str(UUID(value.strip('{}')))
    except (ValueError, TypeError, AttributeError):
        raise RangeError('Sysmon 프로세스 GUID 형식을 확인하지 못했습니다.') from None


def parse_sysmon(row, c):
    if row.get('source') != 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' or row.get('sourcetype') != 'XmlWinEventLog' or str(row.get('host', '')).lower() != c['windows_hostname'].lower():
        raise RangeError('Sysmon 로그 출처와 고정된 호스트 범위가 다릅니다.')
    raw = row.get('_raw')
    if not isinstance(raw, str) or len(raw.encode()) > 128 << 10 or re.search(r'<!DOCTYPE|<!ENTITY', raw, re.I):
        raise RangeError('Sysmon XML 원본을 확인하지 못했습니다.')
    try:
        root = ET.fromstring(raw)
        def local(tag):
            return tag.split('}')[-1]
        system = next(n for n in root if local(n.tag) == 'System')
        system_values = {local(n.tag): n for n in system}
        if system_values['Provider'].get('Name') != 'Microsoft-Windows-Sysmon' or system_values['Channel'].text != 'Microsoft-Windows-Sysmon/Operational' or (system_values['Computer'].text or '').lower() != c['windows_hostname'].lower():
            raise RangeError('Sysmon XML의 원본 공급자와 호스트가 다릅니다.')
        if system_values['EventID'].text != '1':
            return None
        timestamp = epoch(system_values['TimeCreated'].get('SystemTime'))
        event_data = next(n for n in root if local(n.tag) == 'EventData')
        values = {}
        for element in event_data:
            name = element.get('Name')
            if name in values:
                raise RangeError('Sysmon XML에 중복 필드가 있습니다.')
            values[name] = element.text or ''
        values.update({'ProcessGuid': process_guid(values.get('ProcessGuid')), 'ParentProcessGuid': process_guid(values.get('ParentProcessGuid')), 'EventCode': '1', 'event_epoch': timestamp, 'Computer': c['windows_hostname'], 'native': copy.deepcopy(row)})
        if not values.get('Image') or not values.get('CommandLine'):
            raise RangeError('Sysmon 실행 파일 및 명령줄 필드가 없습니다.')
        # Splunk's event time must represent the native SystemTime, not ingestion.
        if abs(float(row.get('native_event_epoch', row.get('_time'))) - timestamp) > 2:
            raise RangeError('Sysmon 원본 시각과 Splunk 이벤트 시각이 일치하지 않습니다.')
        return values
    except (ET.ParseError, KeyError, StopIteration, ValueError, TypeError):
        raise RangeError('Sysmon XML의 필수 원본 필드를 해석하지 못했습니다.') from None


def ancestry(events, anchors):
    by_guid = {}
    for event in events:
        guid = event['ProcessGuid']
        if guid in by_guid and by_guid[guid] != event:
            raise RangeError('같은 ProcessGuid에 상충하는 원본 이벤트가 있습니다.')
        by_guid[guid] = event
    attributed, unknown = {}, []
    claimed = set()
    for scenario_id, path in anchors.items():
        roots = {guid for guid, e in by_guid.items() if path.lower() in e['CommandLine'].lower() and e['Image'].lower().endswith('\\powershell.exe')}
        # A unique real wrapper command is the anchor; descendants must form
        # actual ProcessGuid->ParentProcessGuid links, not share a text marker.
        if len(roots) != 1:
            unknown.append(scenario_id)
            attributed[scenario_id] = []
            continue
        reached = set(roots)
        for _ in range(len(by_guid)):
            expanded = {guid for guid, e in by_guid.items() if e['ParentProcessGuid'] in reached} - reached
            if not expanded:
                break
            reached |= expanded
        descendants = [by_guid[guid] for guid in reached - roots]
        expected = CATALOG[scenario_id][2]
        expected_events = [e for e in descendants if e['Image'].replace('/', '\\').rsplit('\\', 1)[-1].lower() == expected]
        if not expected_events or claimed.intersection(reached):
            unknown.append(scenario_id)
        claimed |= reached
        attributed[scenario_id] = expected_events
    return attributed, unknown


class Runtime:
    def __init__(self, config):
        self.config = validate_config(config)
        self.tunnel = Tunnel(config)
        self.splunk = Splunk(config, self.tunnel)

    def ready(self):
        self.splunk.request('GET', '/services/server/info')
        return True

    def deploy(self, cycle_id, role, rule):
        return self.splunk.deploy(rule, PREFIX + uuid_string(cycle_id).replace('-', '') + '_' + role)

    def execute(self, scenario_id, phase_id, anchor_id):
        if scenario_id not in CATALOG:
            raise RangeError('등록된 Atomic 시나리오만 실행할 수 있습니다.')
        phase_id, anchor_id = uuid_string(phase_id), uuid_string(anchor_id)
        s = next(s for s in self.config['scenarios'] if s['id'] == scenario_id)
        path = 'C:\\AegisLoop\\runs\\' + phase_id + '\\' + anchor_id + '\\run.ps1'
        wrapper = ("$ErrorActionPreference = 'Stop'\n"
                   "$atomic = 'C:\\AtomicRedTeam\\atomics\\" + s['technique'] + "\\" + s['technique'] + ".yaml'\n"
                   "if ((Get-FileHash -Algorithm SHA256 -LiteralPath $atomic).Hash.ToLowerInvariant() -ne '" + s['yaml_sha256'] + "') { throw 'Atomic YAML integrity mismatch' }\n"
                   "Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -Force\n"
                   "Invoke-AtomicTest " + s['technique'] + " -TestGuids '" + s['atomic_guid'] + "' -PathToAtomicsFolder 'C:\\AtomicRedTeam\\atomics' -TimeoutSeconds 45\n"
                   "if ($LASTEXITCODE) { exit $LASTEXITCODE }\n")
        encoded = base64.b64encode(wrapper.encode('utf-8')).decode()
        outer = ("$ErrorActionPreference = 'Stop'; $path = '" + path + "'; "
                 "New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null; "
                 "[IO.File]::WriteAllBytes($path,[Convert]::FromBase64String('" + encoded + "')); "
                 "& 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File $path; exit $LASTEXITCODE")
        self.tunnel.ensure()
        try:
            import winrm
            session = winrm.Session('http://127.0.0.1:15985/wsman', auth=(self.config['windows_user'], self.config['windows_password']), transport='ntlm', message_encryption='always', read_timeout_sec=100, operation_timeout_sec=80)
            started = utcnow()
            response = session.run_ps(outer)
            finished = utcnow()
            stdout, stderr = response.std_out[:65536], response.std_err[:65536]
            return {'scenario_id': scenario_id, 'name': s['name'], 'status': 'completed' if response.status_code == 0 else 'failed',
                    'exit_code': response.status_code, 'summary': '설치된 Atomic 단일 시험 실행이 완료되었습니다.' if response.status_code == 0 else 'Atomic 시험 실행이 실패했습니다. 원본 실행 결과를 확인하세요.',
                    'correlation_id': anchor_id, 'anchor_path': path, 'started_at': started, 'finished_at': finished,
                    'stdout_base64': base64.b64encode(stdout).decode(), 'stderr_base64': base64.b64encode(stderr).decode(),
                    'output_truncated': len(response.std_out) > 65536 or len(response.std_err) > 65536, 'atomic_guid': s['atomic_guid'], 'yaml_sha256': s['yaml_sha256']}
        except Exception:
            raise RangeError('Windows Atomic 실행 연결이 실패했습니다. 자동으로 재실행하지 않습니다.') from None

    def execute_chain(self, case_id, phase_id, run_id):
        from chain_runtime import execute
        return execute(self, case_id, phase_id, run_id)

    def collect(self, phase, deployment):
        if phase.get('kind') == 'scheduled_task_chain':
            from chain_runtime import collect
            return collect(self, phase, deployment)
        start, finish = epoch(phase['started_at']) - 3, epoch(phase['finished_at']) + 3
        if finish - start > 600 or finish <= start:
            raise RangeError('실행 증거의 시간 범위를 확인하지 못했습니다.')
        audit = self.splunk.search('search index="win" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" sourcetype="XmlWinEventLog" host=' + literal(self.config['windows_hostname']) + ' | eval native_event_epoch=tonumber(_time) | fields _raw _time native_event_epoch host source sourcetype | head 5001', start, finish)
        alerts = self.splunk.search('search index="aegis_range_alerts" sourcetype="aegis:range:alert" source=' + literal(deployment['rule_id']) + ' | fields _raw _time host source sourcetype | head 5001', start, time.time() + 1)
        scheduler = self.splunk.scheduler_proof(deployment, start, finish)
        warnings = list(audit['warnings']) + list(alerts['warnings']) + list(scheduler['warnings'])
        events = []
        for row in audit['rows']:
            try:
                event = parse_sysmon(row, self.config)
                if event is not None:
                    if not start <= event['event_epoch'] <= finish:
                        raise RangeError('Sysmon 이벤트가 실행 시간 범위를 벗어났습니다.')
                    events.append(event)
            except RangeError:
                warnings.append('일부 원본 Sysmon 이벤트의 출처·필드·시각 검증이 실패했습니다.')
        anchors = {r['scenario_id']: r['anchor_path'] for r in phase['results'] if r.get('anchor_path')}
        try:
            attributed, unknown = ancestry(events, anchors)
        except RangeError:
            attributed, unknown = {}, list(anchors)
            warnings.append('Sysmon 프로세스 계보의 일관성을 확인하지 못했습니다.')
        all_ids = [r['scenario_id'] for r in phase['results']]
        unknown = set(unknown) | {r['scenario_id'] for r in phase['results'] if r['status'] != 'completed'} | (set(all_ids) - set(anchors))
        scoped_alerts = []
        attributed_guids = {e['ProcessGuid'] for group in attributed.values() for e in group}
        native_matches = set()
        for row in alerts['rows']:
            try:
                if row.get('source') != deployment['rule_id'] or row.get('sourcetype') != 'aegis:range:alert':
                    raise ValueError()
                alert = json_read(row['_raw'])
                if not isinstance(alert, dict) or alert.get('event_kind') != 'alert' or alert.get('detection_rule_id') != deployment['rule_id'] or alert.get('rule_sha256') != deployment['rule_sha256'] or str(alert.get('host', '')).lower() != self.config['windows_hostname'].lower() or alert.get('detection_engine') != 'splunk_saved_search':
                    raise ValueError()
                guid = process_guid(alert.get('audit_process_guid'))
                event_time = float(alert.get('event_epoch'))
                created = epoch(alert.get('alert_created_at'))
                if not math.isfinite(event_time) or not math.isfinite(created) or created < event_time - 3 or created > time.time() + 3:
                    raise ValueError()
                if not start <= event_time <= finish:
                    # Valid alerts for another execution/background activity
                    # stay in originals but do not make this window incomplete.
                    continue
                matching = next((event for event in events if event['ProcessGuid'] == guid), None)
                if not matching or abs(matching['event_epoch'] - event_time) > 2:
                    # Overlapping baseline alerts from other phases are retained
                    # as originals but cannot become this phase's detections.
                    continue
                if guid in attributed_guids:
                    native_matches.add(guid)
                    scoped_alerts.append(copy.deepcopy(row))
            except (RangeError, ValueError, TypeError, KeyError):
                warnings.append('일부 네이티브 경보의 규칙·해시·호스트·시각 귀속을 확인하지 못했습니다.')
        complete = audit['complete'] and alerts['complete'] and scheduler['complete'] and not warnings
        settled = time.time() >= epoch(phase['finished_at']) + NATIVE_SETTLE_SECONDS
        detected, missed = [], []
        for sid in all_ids:
            if any(event['ProcessGuid'] in native_matches for event in attributed.get(sid, [])) and sid not in unknown:
                detected.append(sid)
            elif sid not in unknown and complete and settled:
                missed.append(sid)
            else:
                unknown.add(sid)
        if not settled:
            warnings.append('네이티브 예약 검색의 대기 시간이 끝나지 않아 무경보를 미탐으로 판정하지 않습니다.')
        public = {'complete': complete and settled, 'audit_count': sum(len(v) for v in attributed.values()), 'alert_count': len({process_guid(json_read(r['_raw'])['audit_process_guid']) for r in scoped_alerts}),
                  'detected_scenarios': detected, 'missed_scenarios': missed, 'unknown_scenarios': [s for s in all_ids if s in unknown], 'events': [], 'warnings': list(dict.fromkeys(warnings))}
        return {'public': public, 'native_audit': audit, 'native_alerts': alerts, 'scheduler_proof': scheduler, 'attributed_events': attributed, 'scoped_alerts': scoped_alerts, 'rule_deployment': copy.deepcopy(deployment), 'collected_at': utcnow()}
