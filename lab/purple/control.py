#!/usr/bin/env python3
"""Control only the optional, localhost-bound purple-team practice project."""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from bootstrap_splunk import LabError

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-runtime/purple-lab'
EVIDENCE = ROOT / 'evidence-local/purple-lab'
COMPOSE = ROOT / 'docker-compose.purple-lab.yml'
TARGET = 'http://purple-lab-target:8080'


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)


def initialize(accept=False):
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    EVIDENCE.chmod(0o700)
    logs = EVIDENCE / 'logs'
    logs.mkdir(exist_ok=True)
    # The unprivileged official WAF must append its audit file here. The host
    # parent remains private; no credentials are stored in this directory.
    logs.chmod(0o777)
    for name in ('splunk-admin-password', 'splunk-search-password', 'hec-token'):
        path = STATE / name
        if not path.exists():
            value = str(uuid.uuid4()) if name == 'hec-token' else secrets.token_hex(32)
            path.write_text(value + '\n')
        if not path.read_text().strip():
            raise RuntimeError('기존 실습 비밀 파일이 비어 있습니다. 자동 교체하지 않습니다.')
        path.chmod(0o600)
    if accept:
        save_json(STATE / 'terms-acceptance.json', {
            'accepted_at': datetime.now(timezone.utc).isoformat(),
            'terms': 'https://www.splunk.com/en_us/legal/splunk-general-terms.html',
            'scope': 'local artex-purple-lab Splunk instance',
        })
    modefile = STATE / 'waf-mode'
    if not modefile.exists():
        modefile.write_text('DetectionOnly\n')
    mode = modefile.read_text().strip()
    if mode not in ('DetectionOnly', 'On'):
        raise RuntimeError('실습 WAF 모드 파일을 확인하세요.')
    accepted = (STATE / 'terms-acceptance.json').exists()
    entries = {
        'LAB_SPLUNK_PASSWORD': (STATE / 'splunk-admin-password').read_text().strip(),
        'LAB_WAF_MODE': mode,
        'LAB_SPLUNK_START_ARGS': '--accept-license' if accepted else '--no-prompt',
        'LAB_SPLUNK_GENERAL_TERMS': '--accept-sgt-current-at-splunk-com' if accepted else 'not-accepted',
    }
    envfile = STATE / 'compose.env'
    envfile.write_text(''.join(f'{k}={v}\n' for k, v in entries.items()))
    envfile.chmod(0o600)


def compose(*args, capture=False):
    cmd = ['docker', 'compose', '--project-name', 'artex-purple-lab', '--env-file',
           str(STATE / 'compose.env'), '-f', str(COMPOSE), *args]
    return subprocess.run(cmd, cwd=ROOT, check=True, text=True,
                          capture_output=capture)


def bootstrap(*args):
    subprocess.run([sys.executable, str(ROOT / 'lab/purple/bootstrap_splunk.py'),
                    '--state-dir', str(STATE), '--url', 'https://127.0.0.1:18089',
                    '--hec-url', 'https://127.0.0.1:18088', *args], check=True)


def start(accept=False):
    initialize(accept)
    if not (STATE / 'terms-acceptance.json').exists():
        raise RuntimeError('Splunk 약관 확인 후 start --accept-splunk-terms로 실행하세요. init은 약관에 동의하지 않습니다.')
    compose('up', '-d', 'juice-shop', 'waf', 'splunk')
    # Docker creates the parent of the read-only metadata file as root. Only
    # this volume directory must be writable for Splunk's REST-created ACLs;
    # the shipped default.meta and app configuration remain read-only.
    compose('exec', '-T', '--user', '0', 'splunk', 'chown',
            'splunk:splunk', '/opt/splunk/etc/apps/artex_lab/metadata')
    print('Splunk 초기화를 기다립니다. Apple Silicon에서는 첫 실행이 오래 걸릴 수 있습니다.', flush=True)
    bootstrap('configure', '--trust-local-new-instance')
    compose('up', '-d', 'collector')
    print('실습 대상 http://localhost:18790 / Splunk http://localhost:18000')
    print('다음: ./scripts/purple-lab.sh connect 그리고 새 WAF 대상에서 ARTEX 진단')


def status():
    compose('ps')
    print('WAF:', (STATE / 'waf-mode').read_text().strip())
    path = EVIDENCE / 'logs/collector-status.json'
    if path.exists():
        data = json.loads(path.read_text())
        print('수집기:', json.dumps({k: data.get(k) for k in
              ('updated_at', 'healthy', 'hec_healthy', 'pending_count')}, ensure_ascii=False))
    print('계정 정보는 .local-runtime/purple-lab/의 비공개 파일에만 보관합니다.')


def mode(value):
    initialize()
    selected = {'detection': 'DetectionOnly', 'blocking': 'On'}[value]
    (STATE / 'waf-mode').write_text(selected + '\n')
    initialize()
    compose('up', '-d', '--no-deps', '--force-recreate', 'waf')
    wait_for_waf()
    print('WAF 모드:', selected, '(전환 전후 수집 구간을 하나로 합치지 마세요.)')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def wait_for_waf():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request('http://127.0.0.1:18790/healthz',
                headers={'Host': 'purple-lab-target:8080'})
            with opener.open(request, timeout=5) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            pass
        time.sleep(1)
    raise RuntimeError('모드 변경 후 WAF가 준비되지 않았습니다. 실습 상태를 확인하세요.')


def artex_request(path, data=None):
    key = (ROOT / '.local-runtime/jwt.key').read_bytes().strip()
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
    now = int(time.time())
    message = enc(b'{"alg":"HS256","typ":"JWT"}') + '.' + enc(json.dumps(
        {'sub': 'ARTEX', 'iat': now, 'exp': now + 120}).encode())
    token = message + '.' + enc(hmac.new(key, message.encode(), hashlib.sha256).digest())
    req = urllib.request.Request('http://127.0.0.1:8787' + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=30) as response:
        return json.load(response)


def connect():
    from bootstrap_splunk import Client
    pin = (STATE / 'splunk-management.sha256').read_text().strip()
    password = (STATE / 'splunk-search-password').read_text().strip()
    client = Client('https://127.0.0.1:18089', pin, 'artex_lab_search', password)
    client.request('GET', '/services/server/info')
    inspect = subprocess.run(['docker', 'inspect', '--format',
       '{{json .NetworkSettings.Networks}}', 'artex-local-artex-1'],
       check=True, capture_output=True, text=True)
    if 'artex-purple-lab-front' not in json.loads(inspect.stdout):
        subprocess.run(['docker', 'network', 'connect', 'artex-purple-lab-front',
                        'artex-local-artex-1'], check=True)
    sources = artex_request('/api/purple/sources').get('sources', [])
    matching = [s for s in sources if s.get('name') == '로컬 Purple 실습 Splunk']
    expected = {'base_url': 'https://purple-lab-splunk:8089',
                'index': 'artex_lab', 'audit_sourcetype': 'artex:lab:audit',
                'alert_sourcetype': 'artex:lab:alert',
                'correlation_field': 'artex_verification_id', 'action_field': 'action',
                'tls_fingerprint': pin}
    if not matching:
        source = artex_request('/api/purple/sources', {
            'name': '로컬 Purple 실습 Splunk', 'enabled': True,
            'config': expected,
            'username': 'artex_lab_search', 'password': password})
        source_id = source['id']
    else:
        if len(matching) != 1 or matching[0].get('config') != expected or not matching[0].get('enabled') or not matching[0].get('credential_set'):
            raise RuntimeError('같은 이름의 기존 실습 연결이 현재 설정과 다릅니다. 연결 관리에서 확인하세요.')
        source_id = matching[0]['id']
    if artex_request(f'/api/purple/sources/{source_id}/test', {}).get('ok') is not True:
        raise RuntimeError('ARTEX에서 실습 Splunk 연결 확인에 실패했습니다.')
    asset = artex_request('/api/assets', {'assets': [{'type': 'service',
        'url': TARGET, 'page_title': 'Purple lab: Juice Shop via WAF'}]})
    rows = asset.get('results', [])
    if asset.get('errors') or len(rows) != 1 or rows[0].get('type') != 'service' or not str(rows[0].get('id', '')).isdigit() or int(rows[0]['id']) <= 0:
        raise RuntimeError('실습 WAF 자산 등록에 실패했습니다. ARTEX 자산 목록을 확인하세요.')
    save_json(STATE / 'artex-connection.json', {'source_id': source_id, 'target': TARGET,
               'asset_result': asset})
    print('ARTEX에 새 실습 Splunk 연결과 WAF 자산을 등록했습니다. source_id=', source_id)
    print('새 작업의 점검 대상:', TARGET, '(기존 취약점의 대상은 변경하지 않습니다.)')


def export_logs(verification_id, start, end):
    # Export real Splunk results, including alert events created by its rule.
    from bootstrap_splunk import Client
    identifier = str(uuid.UUID(verification_id))
    first = datetime.fromisoformat(start.replace('Z', '+00:00'))
    last = datetime.fromisoformat(end.replace('Z', '+00:00'))
    if first.tzinfo is None or last.tzinfo is None or not first < last:
        raise RuntimeError('시작·종료 시각은 시간대가 있는 ISO 8601 형식이어야 합니다.')
    if (last - first).total_seconds() > 86400 or last.timestamp() > time.time():
        raise RuntimeError('방어 검증 내보내기는 과거 24시간 이내 구간으로 나누세요.')
    client = Client('https://127.0.0.1:18089',
        (STATE / 'splunk-management.sha256').read_text().strip(), 'artex_lab_search',
        (STATE / 'splunk-search-password').read_text().strip())
    folder = EVIDENCE / ('export-' + identifier + '-' + str(int(time.time())))
    folder.mkdir(parents=True)
    metadata = {'verification_id': identifier, 'start': start, 'end': end,
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'completeness_confirmed': False, 'files': {}}
    for kind in ('audit', 'alert'):
        search = f'search index=artex_lab sourcetype="artex:lab:{kind}" | fields _raw _time | spath | where artex_verification_id="{identifier}" | head 10001'
        rows, warnings = client.export(search, first.timestamp(), last.timestamp())
        if warnings or len(rows) > 10000:
            raise RuntimeError('Splunk 내보내기에 경고 또는 이벤트 한도 초과가 있습니다.')
        if any(not isinstance(row.get('_raw'), str) for row in rows):
            raise RuntimeError('Splunk 검색 결과에 원문이 없습니다.')
        raw = ''.join(row['_raw'] + '\n' for row in rows)
        file = folder / (kind + '.jsonl')
        file.write_text(raw)
        file.chmod(0o600)
        metadata['files'][kind] = {'count': len(rows),
             'sha256': hashlib.sha256(raw.encode()).hexdigest()}
    save_json(folder / 'manifest.json', metadata)
    print('실제 감사·Splunk 경보 파일:', folder)
    print('원본 수집·기간·수집기 상태를 확인한 뒤 전체 내보내기 확인을 선택하세요.')


def main():
    parser = argparse.ArgumentParser(description='별도 Juice Shop·WAF·Splunk 실습 환경')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init')
    commands.add_parser('start').add_argument('--accept-splunk-terms', action='store_true')
    commands.add_parser('status')
    commands.add_parser('stop')
    commands.add_parser('connect')
    commands.add_parser('check').add_argument('--waf-only', action='store_true')
    commands.add_parser('mode').add_argument('value', choices=['detection', 'blocking'])
    commands.add_parser('alerts').add_argument('value', choices=['on', 'off'])
    commands.add_parser('loop-rule', help='격리된 로컬 실습 Splunk에 구조화 규칙 배포').add_argument('arguments', nargs=argparse.REMAINDER)
    p = commands.add_parser('export')
    p.add_argument('--uuid', required=True)
    p.add_argument('--start', required=True)
    p.add_argument('--end', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'init':
            initialize()
            print('로컬 실습 비밀·폴더 준비 완료. 아직 컨테이너를 실행하지 않았습니다.')
        elif args.command == 'start': start(args.accept_splunk_terms)
        elif args.command == 'stop': compose('stop')
        elif args.command == 'status': status()
        elif args.command == 'mode': mode(args.value)
        elif args.command == 'alerts': bootstrap('detection', args.value)
        elif args.command == 'loop-rule':
            subprocess.run([sys.executable, str(ROOT / 'lab/purple/loop_rule.py'), *args.arguments], check=True)
        elif args.command == 'connect': connect()
        elif args.command == 'export': export_logs(args.uuid, args.start, args.end)
        elif args.command == 'check':
            subprocess.run([sys.executable, str(ROOT / 'lab/purple/check.py'),
                            *(['--waf-only'] if args.waf_only else [])], check=True)
    except (OSError, ValueError, RuntimeError, LabError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        # Never print server bodies, subprocess output or credentials.
        if isinstance(exc, (RuntimeError, LabError)): print(str(exc), file=sys.stderr)
        else: print('실습 작업에 실패했습니다. 실행 상태·권한·연결을 확인하세요.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
