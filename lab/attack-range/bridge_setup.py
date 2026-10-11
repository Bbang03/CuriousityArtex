#!/usr/bin/env python3
"""Connect an existing owned Attack Range; never call a cloud provisioning API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import socket
import ssl
import stat
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'aegis-attack-range-api:fc9b9e719d88'
CATALOG = [
    ('whoami', '현재 사용자 탐색', 'T1033', 'aab580c7-cc30-4a7c-b5a9-46a29066b022', 'whoami.exe', 'whoami #{whoami_args}'),
    ('tasklist', '실행 프로세스 탐색', 'T1057', 'c5806a4f-62b8-4900-980b-c7ec004e9908', 'tasklist.exe', 'tasklist'),
    ('systeminfo', '시스템 정보 탐색', 'T1082', '66703791-c902-4560-8770-42b8a91f7667', 'systeminfo.exe', 'systeminfo\nreg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum'),
]


def private_write(path, value):
    if path.is_symlink():
        raise RuntimeError('설정 파일의 심볼릭 링크는 허용되지 않습니다')
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('x') as handle:
        os.chmod(temporary, 0o600)
        handle.write(value)
    temporary.replace(path)


def prepare(session, output):
    import winrm
    import yaml
    cfg = json.loads((session / 'private-config.json').read_text())
    metadata = json.loads((session / 'prepare.json').read_text())
    state = json.loads((session / 'terraform/terraform.tfstate').read_text())
    session_id = str(uuid.UUID(metadata['range_id']))
    routers = [i['attributes'] for r in state['resources']
               if r.get('module') == 'module.router' and r['type'] == 'aws_instance'
               for i in r['instances']]
    if len(routers) != 1 or routers[0].get('tags_all', {}).get('AegisLoopSession') != session_id:
        raise RuntimeError('배포 상태와 실습 소유 태그가 일치하지 않습니다')
    import ipaddress
    router = str(ipaddress.IPv4Address(routers[0]['public_ip']))
    windows = [s for s in cfg['attack_range'] if s.get('windows')]
    splunk = [s for s in cfg['attack_range'] if s.get('name') == 'splunk']
    if len(windows) != 1 or len(splunk) != 1 or windows[0]['ip_last_octet'] != 11 or splunk[0]['ip_last_octet'] != 10:
        raise RuntimeError('현재 연결기는 Windows 1대·Splunk 1대의 기존 실습 구성을 지원합니다')
    wp = next(r['vars']['ludus_ar_windows_password'] for r in windows[0]['roles']
              if 'ludus_ar_windows_password' in r.get('vars', {}))
    sp = json.loads((session / 'provisioning/ansible/verify-vars.json').read_text())['private_splunk_password']
    command = ['ssh', '-i', str(session / 'sshkey'), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(session / 'known_hosts'),
               '-o', 'ConnectTimeout=15', '-o', 'ExitOnForwardFailure=yes', '-N',
               '-L', '127.0.0.1:15985:10.0.2.11:5985', '-L', '127.0.0.1:15889:10.0.2.10:8089',
               'ubuntu@' + router]
    with (output / 'setup-ssh.log').open('w') as log:
        child = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            for _ in range(25):
                if child.poll() is not None:
                    raise RuntimeError('기존 실습 SSH 연결을 확인하세요')
                try:
                    socket.create_connection(('127.0.0.1', 15985), 1).close()
                    break
                except OSError:
                    time.sleep(1)
            else:
                raise RuntimeError('기존 실습 SSH 연결이 지연됐습니다')
            # The first certificate is observed only inside the pinned SSH tunnel.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection(('127.0.0.1', 15889), 10) as sock:
                with context.wrap_socket(sock, server_hostname='splunk') as tls:
                    pin = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            previous = output / 'config.json'
            if previous.exists() and json.loads(previous.read_text()).get('splunk_tls_sha256') != pin:
                raise RuntimeError('Splunk 인증서가 기존 연결과 다릅니다. 자동 변경하지 않습니다')
            remote = winrm.Session('http://127.0.0.1:15985/wsman', auth=('Administrator', wp),
                                   transport='ntlm', message_encryption='always',
                                   read_timeout_sec=60, operation_timeout_sec=45)
            script = r'''$ErrorActionPreference='Stop'; $rows=@(); foreach($id in @('T1033','T1057','T1082')) { $p='C:\AtomicRedTeam\atomics\'+$id+'\'+$id+'.yaml'; $rows += [pscustomobject]@{id=$id;content=[string](Get-Content -Raw -LiteralPath $p);hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash} }; [pscustomobject]@{hostname=$env:COMPUTERNAME;atomics=$rows} | ConvertTo-Json -Depth 6 -Compress'''
            result = remote.run_ps(script)
            if result.status_code != 0:
                raise RuntimeError('설치된 Windows 테스트 목록을 읽지 못했습니다')
            observed = json.loads(result.std_out.decode('utf-8-sig'))
            atomics = {item['id']: item for item in observed['atomics']}
            scenarios = []
            for sid, name, technique, guid, image, expected in CATALOG:
                record = atomics[technique]
                tests = yaml.safe_load(record['content'])['atomic_tests']
                selected = [(i, t) for i, t in enumerate(tests, 1) if t['auto_generated_guid'] == guid]
                if len(selected) != 1 or selected[0][1]['executor']['command'].strip().replace('\r\n', '\n') != expected:
                    raise RuntimeError('설치된 Atomic 내용이 지원 시나리오와 다릅니다')
                scenarios.append(dict(id=sid, name=name, description=name + ' 단일 Atomic 테스트',
                                      technique=technique, atomic_guid=guid, image=image,
                                      test_numbers=[selected[0][0]], yaml_sha256=record['hash'].lower()))
            config = dict(name='AWS Attack Range Windows', router_host=router, router_user='ubuntu',
                          ssh_key='/run/range/sshkey', known_hosts='/run/range/known_hosts',
                          windows_host='10.0.2.11', windows_hostname=observed['hostname'],
                          windows_user='Administrator', windows_password=wp,
                          splunk_host='10.0.2.10', splunk_user='admin', splunk_password=sp,
                          splunk_tls_sha256=pin, index='win', alert_index='aegis_range_alerts',
                          sysmon_source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
                          sysmon_sourcetype='XmlWinEventLog', scenarios=scenarios)
            private_write(previous, json.dumps(config, ensure_ascii=False, indent=2) + '\n')
            token = output / 'token'
            if token.is_symlink():
                raise RuntimeError('연결 토큰은 일반 비공개 파일이어야 합니다')
            if token.exists():
                mode = token.stat().st_mode
                if not stat.S_ISREG(mode) or mode & 0o077 or not re.fullmatch(r'[A-Za-z0-9_-]{64}\n?', token.read_text()):
                    raise RuntimeError('기존 연결 토큰의 형식 또는 파일 권한을 확인하세요')
            else:
                private_write(token, secrets.token_urlsafe(48) + '\n')
            print('기존 AWS Windows·Splunk 연결과 설치된 단일 Atomic 3개를 준비했습니다.')
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.inside:
        prepare(args.session, Path('/output'))
        return
    session = args.session.resolve(strict=True)
    for name in ('private-config.json', 'prepare.json', 'sshkey', 'known_hosts', 'terraform/terraform.tfstate'):
        if not (session / name).is_file():
            raise RuntimeError('기존 배포의 설정·상태·SSH 파일을 확인하세요')
    output = ROOT / '.local-runtime/attack-range/bridge'
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    subprocess.run(['docker', 'run', '--rm', '--entrypoint', 'python',
                    '-v', str(ROOT) + ':/src:ro', '-v', str(session) + ':/session:ro',
                    '-v', str(output) + ':/output', IMAGE,
                    '/src/lab/attack-range/bridge_setup.py', '--inside', '--session', '/session'], check=True)
    private_write(output / 'compose.env', 'ARTEX_RANGE_SESSION_DIR=' + json.dumps(str(session), ensure_ascii=False) + '\n')
    (output / 'state').mkdir(exist_ok=True, mode=0o700)
    print('다음: ./scripts/local-start.sh → /closed-loop/?tab=range')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, StopIteration, subprocess.CalledProcessError):
        raise SystemExit('연결 준비 실패: 기존 실습 상태와 비공개 setup-ssh.log를 확인하세요. 암호는 출력하지 않습니다.')
