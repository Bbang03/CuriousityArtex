#!/usr/bin/env python3
"""Exercise real local WAF requests and actual Splunk-created alert events.

These independent checks never create ARTEX findings or verification runs and
must not be submitted as evidence for another ARTEX-generated UUID.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import control
from bootstrap_splunk import Client, LabError

spec = importlib.util.spec_from_file_location('lab_collector',
        control.ROOT / 'lab/purple/collector/collector.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def request(path, identifier=None):
    headers = {'Host': 'purple-lab-target:8080', 'User-Agent': 'ARTEX-local-lab-check'}
    if identifier: headers['X-ARTEX-Verification-ID'] = identifier
    req = urllib.request.Request('http://127.0.0.1:18790' + path, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), control.NoRedirect())
    try:
        with opener.open(req, timeout=15) as response:
            data, status = response.read(1 << 20), response.status
    except urllib.error.HTTPError as error:
        data, status = error.read(1 << 20), error.code
    return {'path': path.split('?')[0], 'http_status': status,
            'response_bytes': len(data), 'response_sha256': hashlib.sha256(data).hexdigest()}


def ready():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if request('/healthz')['http_status'] == 200: return
        except (OSError, urllib.error.URLError, http.client.HTTPException): pass
        time.sleep(1)
    raise RuntimeError('실습 WAF가 준비되지 않았습니다.')


def native_events(identifier):
    path = control.EVIDENCE / 'logs/modsec_audit.log'
    if not path.exists(): return []
    events = []
    for raw, _ in collector.native_frames(path.read_bytes()):
        event = collector.normalize_native(raw)
        if event.get('artex_verification_id') == identifier:
            events.append(event)
    return events


def splunk_events(client, kind, identifier, start):
    search = f'search index=artex_lab sourcetype="artex:lab:{kind}" | fields _raw _time | spath | where artex_verification_id="{identifier}" | head 100'
    rows, warnings = client.export(search, start - 30, time.time() + 1)
    if warnings: raise RuntimeError('Splunk 검색 경고로 환경 확인을 완료할 수 없습니다.')
    return [json.loads(row['_raw']) for row in rows]


def target_file_fingerprint():
    """Read only the pinned lab image's fixed training file, never host data."""
    result = control.compose('exec', '-T', 'juice-shop', '/nodejs/bin/node', '-e',
        'const fs=require("fs"),crypto=require("crypto");'
        'const b=fs.readFileSync("/juice-shop/ftp/acquisitions.md");'
        'process.stdout.write(JSON.stringify({bytes:b.length,'
        'sha256:crypto.createHash("sha256").update(b).digest("hex")}))', capture=True)
    fingerprint = json.loads(result.stdout)
    if (not isinstance(fingerprint.get('bytes'), int) or fingerprint['bytes'] <= 0
            or not isinstance(fingerprint.get('sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', fingerprint['sha256'])):
        raise RuntimeError('고정 연습파일의 바이트 수·SHA-256을 확인하지 못했습니다.')
    return fingerprint


def run_case(name, value, expected, client=None, alerts=True, file_fingerprint=None):
    control.mode(value)
    ready()
    if client:
        control.bootstrap('detection', 'on' if alerts else 'off')
        time.sleep(1.1)
    identifier = str(uuid.uuid4())
    started = time.time()
    responses = [request(path, identifier) for path in
        ('/', '/ftp/acquisitions.md', '/rest/products/search?q=%27%20OR%201%3D1--')]
    file_response = responses[1]
    file_match = (file_fingerprint is not None
        and file_response['response_bytes'] == file_fingerprint['bytes']
        and file_response['response_sha256'] == file_fingerprint['sha256'])
    if file_fingerprint is not None:
        if expected == 'allowed' and (file_response['http_status'] != 200 or not file_match):
            raise RuntimeError('연습파일 HTTP 응답이 대상 파일의 전체 바이트·SHA-256과 일치하지 않습니다.')
        if expected == 'blocked' and (file_response['http_status'] != 403 or file_match):
            raise RuntimeError('WAF 차단 구간에서 연습파일 전달 중단을 확인하지 못했습니다.')
    deadline = time.monotonic() + 45
    events = []
    while time.monotonic() < deadline:
        events = native_events(identifier)
        if len(events) >= 3: break
        time.sleep(1)
    if len(events) != 3: raise RuntimeError('발송한 세 요청의 native 감사 근거가 모두 확인되지 않았습니다.')
    normal = [e for e in events if e['path'] == '/']
    attack = [e for e in events if e['path'] != '/']
    if len(normal) != 1 or normal[0]['action'] != 'allowed':
        raise RuntimeError('정상 대조 요청이 WAF 정책을 통과하지 못했습니다.')
    if normal[0]['matched_rules']:
        raise RuntimeError('정상 대조 요청에 WAF 규칙이 일치했습니다. 오탐 설정을 확인하세요.')
    if len(attack) != 2 or any(e['action'] != expected for e in attack):
        raise RuntimeError('공격 요청의 WAF 실제 정책 조치가 기대값과 다릅니다.')
    if not any('1001001' in e['rule_ids'] for e in attack):
        raise RuntimeError('FTP 보호 규칙의 일치 근거가 없습니다.')
    if not any('942100' in e['rule_ids'] for e in attack):
        raise RuntimeError('표준 CRS SQLi 규칙의 일치 근거가 없습니다.')
    result = {'name': name, 'verification_id': identifier,
              'started_at': datetime.fromtimestamp(started, timezone.utc).isoformat(),
              'responses': responses, 'native_audit': events,
              'expected_action': expected, 'waf_verified': True,
              'splunk_verified': False}
    if file_fingerprint is not None:
        result['training_file_exposure'] = {
            'path': '/ftp/acquisitions.md',
            'target_file': file_fingerprint,
            'http_status': file_response['http_status'],
            'response_bytes': file_response['response_bytes'],
            'response_sha256': file_response['response_sha256'],
            'full_file_bytes_match': file_match,
            'known_training_file_delivered': file_response['http_status'] == 200 and file_match,
            'scope': 'fixed OWASP Juice Shop training file only; not enterprise data',
        }
    if client:
        deadline = time.monotonic() + 150
        indexed, found = [], []
        while time.monotonic() < deadline:
            indexed = splunk_events(client, 'audit', identifier, started)
            found = splunk_events(client, 'alert', identifier, started)
            if len(indexed) == 3 and (len(found) >= 2 if alerts else time.time() - started >= 65):
                break
            time.sleep(3)
        if len(indexed) != 3: raise RuntimeError('Splunk에 실제 감사 로그 세 건이 모두 수집되지 않았습니다.')
        if alerts:
            if len(found) != 2 or any(e.get('detection_engine') != 'splunk_saved_search' for e in found):
                raise RuntimeError('실제 Splunk saved search 경보 두 건을 확인하지 못했습니다.')
            if {e.get('audit_event_id') for e in found} != {e['id'] for e in attack}:
                raise RuntimeError('Splunk 경보와 원본 공격 감사 이벤트가 연결되지 않습니다.')
            originals = {e['id']: e for e in attack}
            for alert in found:
                original = originals[alert['audit_event_id']]
                rules = alert.get('rule_ids')
                if (not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules)
                        or set(rules) != set(original['rule_ids'])
                        or not isinstance(alert.get('rule_id'), str)
                        or alert['rule_id'] not in rules
                        or alert.get('artex_verification_id') != identifier
                        or alert.get('action') != original['action']
                        or alert.get('timestamp') != original['timestamp']):
                    raise RuntimeError('Splunk 경보의 규칙·실행 식별자·조치·원래 시각이 감사 근거와 다릅니다.')
        elif found:
            raise RuntimeError('비활성 탐지 규칙 실행에서 경보가 발생했습니다.')
        result.update({'splunk_verified': True, 'splunk_audit_count': len(indexed),
                       'splunk_alert_count': len(found), 'alerts_enabled': alerts,
                       'alerts': found})
    print(name + ': WAF 실제 조치 확인' + (' · Splunk 실제 경보 확인' if client else ' · Splunk 미실행'), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--waf-only', action='store_true')
    args = parser.parse_args()
    client = None
    if not args.waf_only:
        client = Client('https://127.0.0.1:18089',
            (control.STATE / 'splunk-management.sha256').read_text().strip(),
            'artex_lab_search', (control.STATE / 'splunk-search-password').read_text().strip())
        client.request('GET', '/services/server/info')
    report = {'checked_at': datetime.now(timezone.utc).isoformat(),
              'kind': 'independent_local_environment_check', 'target': control.TARGET,
              'waf_only': args.waf_only, 'cases': []}
    try:
        file_fingerprint = target_file_fingerprint()
        report['cases'].append(run_case('탐지 전용', 'detection', 'allowed', client,
            file_fingerprint=file_fingerprint))
        report['cases'].append(run_case('실제 차단', 'blocking', 'blocked', client,
            file_fingerprint=file_fingerprint))
        if client:
            report['cases'].append(run_case('경보 비활성', 'detection', 'allowed', client, False,
                file_fingerprint=file_fingerprint))
        report['passed'] = True
    except (RuntimeError, LabError, OSError, ValueError, urllib.error.URLError,
            http.client.HTTPException, subprocess.SubprocessError) as exc:
        report['passed'] = False
        print(str(exc) if isinstance(exc, (RuntimeError, LabError)) else '실제 환경 확인 실패', flush=True)
    finally:
        control.mode('detection')
        if client: control.bootstrap('detection', 'on')
        file = control.EVIDENCE / ('waf-check.json' if args.waf_only else 'environment-check.json')
        control.save_json(file, report)
        print('검증 기록:', file)
    return 0 if report.get('passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
