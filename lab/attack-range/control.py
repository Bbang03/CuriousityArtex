#!/usr/bin/env python3
"""Install and inspect the optional official Attack Range management plane.

This controller never provisions a cloud lab or runs a simulation. Only the
explicit SSO commands authenticate through the user's interactive AWS flow;
the user's existing cloud credential directories are never read or mounted.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-runtime/attack-range'
SOURCE = STATE / 'upstream'
MANIFEST = ROOT / 'lab/attack-range/upstream.json'
COMPOSE = ROOT / 'docker-compose.attack-range.yml'
PROJECT = 'aegis-attack-range'
MAX_RESPONSE = 2 * 1024 * 1024
READ_PATHS = ('/health', '/templates', '/configs', '/attack-range/list', '/openapi/openapi.json')


class RangeError(RuntimeError):
    pass


def manifest():
    value = json.loads(MANIFEST.read_text())
    sha = value.get('commit', '')
    if value.get('repository') != 'https://github.com/splunk/attack_range.git' or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise RangeError('공식 저장소와 고정 커밋 정보를 확인하세요.')
    for service in ('api', 'app'):
        if value.get(service + '_image') != f'aegis-attack-range-{service}:{sha[:12]}':
            raise RangeError('이미지 태그와 고정 커밋이 일치하지 않습니다.')
    if value.get('api_url') != 'http://127.0.0.1:4000' or value.get('app_url') != 'http://127.0.0.1:4321':
        raise RangeError('관리 주소는 지정된 localhost 포트만 사용할 수 있습니다.')
    return value


def private_dir(path):
    if path.is_symlink():
        raise RangeError('런타임 폴더의 심볼릭 링크는 사용할 수 없습니다.')
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def private_json(path, value):
    if path.is_symlink():
        raise RangeError('런타임 기록의 심볼릭 링크는 사용할 수 없습니다.')
    private_dir(path.parent)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)


def run(*args, cwd=None, capture=False, timeout=None):
    # Keep stdout/stderr away from error messages: config/CLI failures can
    # include credential material. Build logs still stream to the operator.
    return subprocess.run(list(args), cwd=cwd or ROOT, check=True, text=True,
                          capture_output=capture, timeout=timeout)


def git(*args, capture=True, source=None):
    return run('git', '-C', str(source or SOURCE), *args, capture=capture, timeout=180)


def verify_source(value=None, source=None):
    value = value or manifest()
    source = source or SOURCE
    if source.is_symlink() or not (source / '.git').is_dir():
        raise RangeError('Attack Range 소스가 없습니다. init을 먼저 실행하세요.')
    if git('rev-parse', 'HEAD', source=source).stdout.strip() != value['commit']:
        raise RangeError('기존 Attack Range 소스의 커밋이 다릅니다. 자동 교체하지 않습니다.')
    if git('remote', 'get-url', 'origin', source=source).stdout.strip() != value['repository']:
        raise RangeError('기존 Attack Range 소스의 origin이 공식 저장소와 다릅니다.')
    if git('status', '--porcelain=v1', '--untracked-files=all', source=source).stdout.strip():
        raise RangeError('Attack Range 소스에 로컬 변경이 있습니다. 덮어쓰거나 빌드하지 않습니다.')
    for relative in ('api/Dockerfile', 'app/Dockerfile'):
        path = source / relative
        if not path.is_file() or path.is_symlink():
            raise RangeError('고정 소스의 공식 Dockerfile이 없습니다.')
    return value


def initialize():
    os.umask(0o077)
    value = manifest()
    private_dir(STATE)
    if not SOURCE.exists():
        # Publish a new source directory only after a complete verified
        # checkout. A failed fetch must not leave a partial SOURCE that blocks
        # retries, and cleanup must never remove an existing user's checkout.
        temporary_source = Path(tempfile.mkdtemp(prefix='.upstream-install-', dir=STATE))
        try:
            run('git', 'init', '--quiet', str(temporary_source), capture=True)
            git('remote', 'add', 'origin', value['repository'], source=temporary_source)
            git('fetch', '--depth=1', 'origin', value['commit'], source=temporary_source)
            git('checkout', '--detach', value['commit'], source=temporary_source)
            verify_source(value, source=temporary_source)
            if SOURCE.exists() or SOURCE.is_symlink():
                raise RangeError('설치 중 기존 소스 경로가 생겼습니다. 자동 교체하지 않습니다.')
            temporary_source.rename(SOURCE)
        finally:
            if temporary_source.exists():
                shutil.rmtree(temporary_source)
    verify_source(value)
    # These are isolated state directories, never $HOME/.aws or ~/.azure.
    # Existing keys/configs are preserved; initialization creates no keys.
    for name in ('config', 'ssh_keys', 'wireguard_config', 'logs',
                 'cloud-disabled', 'cloud-disabled/aws',
                 'cloud-disabled/azure', 'cloud-disabled/gcloud'):
        private_dir(STATE / name)
    print('Attack Range 공식 고정 소스와 비공개 런타임 폴더 준비 완료.')


def compose(*args, capture=False):
    return run('docker', 'compose', '--project-name', PROJECT, '-f', str(COMPOSE),
               *args, capture=capture)


def build():
    initialize()
    # The existing Splunk practice stack also uses substantial memory. Avoid
    # Compose building Python/cloud CLIs and the Node frontend concurrently.
    compose('build', 'api')
    compose('build', 'app')
    value = manifest()
    images = {}
    for service in ('api', 'app'):
        tag = value[service + '_image']
        image = run('docker', 'image', 'inspect', '--format', '{{.Id}}', tag, capture=True).stdout.strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise RangeError('빌드 이미지 ID를 확인할 수 없습니다.')
        images[service] = {'tag': tag, 'image_id': image}
    private_json(STATE / 'installation.json', {
        'recorded_at': datetime.now(timezone.utc).isoformat(),
        'repository': value['repository'], 'commit': value['commit'],
        'compose_sha256': hashlib.sha256(COMPOSE.read_bytes()).hexdigest(),
        'images': images, 'cloud_credentials_connected': False,
        'cloud_lab_provisioned': False,
    })


def start():
    initialize()
    compose('up', '-d', '--no-build', '--wait', '--wait-timeout', '180', 'api', 'app')
    print('Attack Range UI: http://localhost:4321 / API: http://localhost:4000')
    print('관리 서비스가 준비됐습니다. 클라우드 실습 서버는 아직 구축하지 않았습니다.')


def sso(action):
    """Authenticate only through the user's interactive IAM Identity Center flow.

    The temporary CLI container does not join the management network or pass
    credentials to its API. AWS account/role selection stays in the wizard.
    """
    os.umask(0o077)
    if action not in ('configure', 'login'):
        raise RangeError('지원하는 AWS SSO 작업이 아닙니다.')
    private_dir(STATE)
    auth_dir = STATE / 'aws-sso'
    private_dir(auth_dir)
    if action == 'login':
        config = auth_dir / 'config'
        if config.is_symlink() or not config.is_file():
            raise RangeError('SSO 프로필이 없습니다. sso-configure로 aegisloop 프로필을 먼저 설정하세요.')
    cli_args = (['configure', 'sso'] if action == 'configure'
                else ['sso', 'login', '--profile', 'aegisloop'])
    print('브라우저에서 AWS SSO 로그인과 계정·역할 선택을 직접 완료하세요.', flush=True)
    if action == 'configure':
        print('CLI profile name 입력에는 aegisloop를 사용하세요.', flush=True)
    run('docker', 'run', '--rm', '-it', '--memory', '512m', '--cpus', '1',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '--env', 'AWS_EC2_METADATA_DISABLED=true',
        '--mount', f'type=bind,source={auth_dir},target=/root/.aws',
        '--entrypoint', 'aws', manifest()['api_image'],
        *cli_args, '--use-device-code', '--no-browser')
    print('AWS SSO 로그인 단계가 종료됐습니다. 클라우드 서버 생성이나 API 자격 증명 연결은 수행하지 않았습니다.')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get(path, *, ui=False, expect_json=True):
    if (ui and path != '/') or (not ui and path not in READ_PATHS):
        raise RangeError('doctor는 지정된 조회 경로만 사용할 수 있습니다.')
    value = manifest()
    base = value['app_url' if ui else 'api_url']
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(base + path, method='GET')
    with opener.open(req, timeout=30) as response:
        if response.status != 200:
            raise RangeError('관리 조회가 정상 응답하지 않았습니다.')
        body = response.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise RangeError('관리 조회 응답이 한도를 초과했습니다.')
    if expect_json:
        decoded = json.loads(body)
        if not isinstance(decoded, dict):
            raise RangeError('관리 조회 JSON 형식이 올바르지 않습니다.')
        return decoded
    return len(body)


def list_count(value, field):
    items = value.get(field)
    if not isinstance(items, list):
        raise RangeError('관리 조회의 목록 형식이 올바르지 않습니다.')
    return len(items)


def openapi_route_count(value):
    version = value.get('openapi')
    paths = value.get('paths')
    if not isinstance(version, str) or not re.fullmatch(r'3\.\d+\.\d+', version) or not isinstance(paths, dict):
        raise RangeError('관리 API의 OpenAPI 문서 형식이 올바르지 않습니다.')
    return len(paths)


def doctor():
    value = verify_source()
    health = get('/health')
    if health.get('status') != 'healthy':
        raise RangeError('Attack Range API health가 healthy가 아닙니다.')
    templates = get('/templates')
    configs = get('/configs')
    ranges = get('/attack-range/list')
    spec = get('/openapi/openapi.json')
    report = {
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'upstream_commit': value['commit'],
        'management_healthy': True,
        'api_reported_version': str(health.get('version', 'unknown'))[:80],
        'template_count': list_count(templates, 'templates'),
        'saved_config_count': list_count(configs, 'configs'),
        'listed_range_count': list_count(ranges, 'attack_ranges'),
        'openapi_route_count': openapi_route_count(spec),
        'ui_bytes': get('/', ui=True, expect_json=False),
        'provider_flags_are_authentication_proof': False,
        'cloud_credentials_connected': False,
        'cloud_lab_provisioned_by_this_check': False,
        'simulation_executed_by_this_check': False,
        'checked_paths': list(READ_PATHS) + ['UI /'],
    }
    private_json(STATE / 'doctor.json', report)
    print('관리 API·템플릿·설정 목록·실습 목록·OpenAPI 문서·웹 UI 조회 확인 완료.')
    print('템플릿:', report['template_count'], '/ 저장 설정:', report['saved_config_count'],
          '/ 실습 목록:', report['listed_range_count'])
    print('available 표시는 클라우드 인증·서버 구축 증명이 아닙니다.')
    return report


def main():
    parser = argparse.ArgumentParser(description='선택적 공식 Attack Range 로컬 관리 서비스')
    parser.add_argument('command', choices=['init', 'build', 'start', 'status', 'stop', 'doctor', 'install', 'sso-configure', 'sso-login'])
    args = parser.parse_args()
    try:
        if args.command == 'init': initialize()
        elif args.command == 'build': build()
        elif args.command == 'start': start()
        elif args.command == 'status': compose('ps')
        elif args.command == 'stop': compose('stop')
        elif args.command == 'doctor': doctor()
        elif args.command == 'sso-configure': sso('configure')
        elif args.command == 'sso-login': sso('login')
        else:
            build()
            start()
            doctor()
    except (OSError, ValueError, RangeError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        if isinstance(exc, RangeError):
            print(str(exc), file=sys.stderr)
        else:
            print('Attack Range 작업에 실패했습니다. Docker·네트워크·고정 소스 상태를 확인하세요.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
