#!/usr/bin/env python3
"""Prepare and inspect an AWS Windows range plan without provisioning resources.

There is deliberately no AWS login, key import, Terraform init/plan/apply,
remote backend, or destroy operation in this helper. The operator runs Terraform
separately after authentication, then supplies its private JSON plan for review.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-runtime/attack-range'
SOURCE = STATE / 'upstream'
MANIFEST = ROOT / 'lab/attack-range/upstream.json'
TEMPLATE = 'templates/aws/splunk_windows_aws.yml'
REGION = 'eu-central-1'
ALLOWED_REGIONS = ('eu-central-1', 'ap-northeast-2')
LIFECYCLE_MODES = ('automatic', 'manual')
WINDOWS_INSTANCE_TYPES = ('t3.large', 't3.medium')
TERRAFORM_VERSION = '1.14.4'
MAX_JSON = 32 * 1024 * 1024
VPC_CIDR = '10.0.0.0/16'
TAGS = ('AegisLoopProject', 'AegisLoopSession', 'AegisLoopExpiresAt')


class PlanError(RuntimeError):
    pass


def private_dir(path):
    if path.is_symlink():
        raise PlanError('비공개 작업 폴더에 심볼릭 링크를 사용할 수 없습니다.')
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def private_write(path, content):
    if path.is_symlink():
        raise PlanError('비공개 파일에 심볼릭 링크를 사용할 수 없습니다.')
    private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(content if isinstance(content, bytes) else content.encode('utf-8'))


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def utc_text(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise PlanError('JSON 파일 경로·크기를 확인하세요.')
    return json.loads(path.read_bytes())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, text=True,
                          capture_output=True, timeout=180, **kwargs)


def verify_source():
    value = read_json(MANIFEST)
    commit = value.get('commit', '')
    if value.get('repository') != 'https://github.com/splunk/attack_range.git' or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise PlanError('공식 저장소·고정 커밋을 확인하세요.')
    if value.get('api_image') != 'aegis-attack-range-api:' + commit[:12]:
        raise PlanError('공식 API 이미지 태그가 고정 커밋과 다릅니다.')
    if SOURCE.is_symlink() or not (SOURCE / '.git').is_dir():
        raise PlanError('고정 공식 소스를 먼저 설치하세요.')
    git = lambda *args: run('git', '-C', str(SOURCE), *args).stdout.strip()
    if git('rev-parse', 'HEAD') != commit or git('remote', 'get-url', 'origin') != value['repository']:
        raise PlanError('공식 소스의 커밋 또는 저장소가 다릅니다.')
    if git('status', '--porcelain=v1', '--untracked-files=all'):
        raise PlanError('공식 소스에 변경이 있습니다. 원본을 자동으로 교체하지 않습니다.')
    return value


def load_template(image):
    """Parse the public pinned YAML using the already installed official image."""
    path = SOURCE / TEMPLATE
    if path.is_symlink() or not path.is_file():
        raise PlanError('고정 Windows 템플릿이 없습니다.')
    script = 'import json,sys,yaml; print(json.dumps(yaml.safe_load(sys.stdin.read())))'
    result = run('docker', 'run', '--rm', '-i', '--network', 'none', '--read-only',
                 '--memory', '512m', '--cpus', '1', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges:true', '--entrypoint',
                 'python', image, '-c', script, input=path.read_text())
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise PlanError('공식 템플릿 형식이 올바르지 않습니다.')
    return value


def whitelist(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise PlanError('허용 주소는 공개 IPv4 한 개의 /32 형식이어야 합니다.') from exc
    address = network.network_address
    if (network.version != 4 or network.prefixlen != 32 or not address.is_global
            or address.is_multicast or address.is_reserved):
        raise PlanError('허용 주소는 공개 IPv4 한 개의 /32 형식이어야 합니다.')
    return str(network)


def exact_version(value):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
        raise PlanError('공급자·모듈 버전은 X.Y.Z 고정값이어야 합니다.')
    return value


def checked_region(value):
    if value not in ALLOWED_REGIONS:
        raise PlanError('지원 리전은 Frankfurt(eu-central-1) 또는 서울(ap-northeast-2)입니다.')
    return value


def checked_lifecycle(mode, hours):
    if mode not in LIFECYCLE_MODES or type(hours) is not int:
        raise PlanError('종료 방식과 계획 기간을 확인하세요.')
    if (mode == 'automatic' and hours != 4) or (mode == 'manual' and not 1 <= hours <= 168):
        raise PlanError('자동 종료 계획은 4시간, 수동 종료 계획은 최대 168시간입니다.')
    return {
        'lifecycle_mode': mode, 'planned_session_hours': hours,
        'manual_cleanup_required': mode == 'manual',
        'automatic_cleanup_required': mode == 'automatic',
        'cleanup_responsibility': 'user' if mode == 'manual' else 'operator_verified_scheduler',
        'planned_end_semantics': 'manual_cleanup_target' if mode == 'manual' else 'verified_scheduler_target',
    }


def checked_windows_instance(value):
    if value not in WINDOWS_INSTANCE_TYPES:
        raise PlanError('Windows 대상 타입은 t3.large 또는 t3.medium만 허용합니다.')
    return value


def preparation_options(preparation):
    # Previously prepared four-hour plans remain readable. Manual plans must
    # explicitly identify the user's cleanup responsibility in their metadata.
    defaults = checked_lifecycle('automatic', 4)
    options = checked_lifecycle(preparation.get('lifecycle_mode', 'automatic'),
                                preparation.get('planned_session_hours', 4))
    for field in ('manual_cleanup_required', 'automatic_cleanup_required',
                  'cleanup_responsibility', 'planned_end_semantics'):
        value = preparation.get(field, defaults[field])
        check(type(value) is type(options[field]) and value == options[field],
              '준비 자료의 종료 책임·계획 기간 설명이 일치하지 않습니다.')
    return options, checked_windows_instance(preparation.get('windows_instance_type', 't3.large'))


def replace_passwords(value, password):
    """Replace all declared password fields and every repeated stock password."""
    count = 0
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if isinstance(key, str) and 'password' in key.lower() and isinstance(item, str):
                result[key] = password
                count += 1
            else:
                result[key], replaced = replace_passwords(item, password)
                count += replaced
        return result, count
    if isinstance(value, list):
        result = []
        for item in value:
            changed, replaced = replace_passwords(item, password)
            result.append(changed)
            count += replaced
        return result, count
    if value == 'changeme123!':
        return password, 1
    return value, 0


def checked_template(value, *, windows_instance_type='t3.large'):
    hosts = value.get('attack_range')
    if not isinstance(hosts, list) or len(hosts) != 2:
        raise PlanError('공식 Windows 단일 대상 구성이 아닙니다.')
    expected = {'splunk': ('t3.xlarge', True, False, 10),
                'win': (checked_windows_instance(windows_instance_type), False, True, 11)}
    for host in hosts:
        if not isinstance(host, dict) or host.get('name') not in expected:
            raise PlanError('허용하지 않은 대상 서버입니다.')
        instance, linux, windows, octet = expected.pop(host['name'])
        if (host.get('instance_type') != instance or bool(host.get('linux')) != linux
                or bool(host.get('windows')) != windows or host.get('ip_last_octet') != octet
                or host.get('network', 'mgmt') != 'mgmt' or host.get('zeek') or host.get('zeek_monitor')):
            raise PlanError('공식 Windows 단일 대상의 서버 조건이 다릅니다.')
    if expected or value.get('general', {}).get('cloud_provider') != 'aws':
        raise PlanError('AWS 단일 Windows 템플릿을 사용하세요.')


def patch_once(text, pattern, replacement):
    changed, count = re.subn(pattern, replacement, text, count=0)
    if count != 1:
        raise PlanError('고정 소스의 수정 위치가 예상과 다릅니다.')
    return changed


def prepare(allowed_ip, aws_version, vpc_version, *, region=REGION, ttl_hours=4,
            lifecycle_mode='automatic', windows_instance_type='t3.large', now=None):
    os.umask(0o077)
    allowed_ip = whitelist(allowed_ip)
    region = checked_region(region)
    lifecycle = checked_lifecycle(lifecycle_mode, ttl_hours)
    windows_instance_type = checked_windows_instance(windows_instance_type)
    aws_version, vpc_version = exact_version(aws_version), exact_version(vpc_version)
    manifest = verify_source()
    template = load_template(manifest['api_image'])
    checked_template(template)
    for host in template['attack_range']:
        if host['name'] == 'win':
            host['instance_type'] = windows_instance_type
    password = 'Aa1!' + secrets.token_hex(20)  # Safe in both stock shell and PowerShell user_data.
    template, password_fields = replace_passwords(template, password)
    if password_fields < 6 or 'changeme123!' in json.dumps(template):
        raise PlanError('기본 암호가 모두 교체되지 않았습니다.')
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = now + timedelta(hours=ttl_hours)
    range_id = str(uuid.uuid4())
    template['general'].update({
        'attack_range_id': range_id, 'attack_range_name': 'aegisloop-windows',
        'key_name': range_id, 'ip_whitelist': allowed_ip,
        'status': 'prepared_not_provisioned',
    })
    template['aws']['region'] = region
    template['aws'].setdefault('aws_default_tags', {}).update({
        TAGS[0]: 'AegisLoop', TAGS[1]: range_id, TAGS[2]: utc_text(expires),
    })
    base = STATE / 'aws-plans'
    private_dir(base)
    base = base.resolve()
    final = base / range_id
    temporary = Path(tempfile.mkdtemp(prefix='.prepare-', dir=base))
    try:
        tfdir = temporary / 'terraform'
        private_dir(tfdir)
        tracked = run('git', '-C', str(SOURCE), 'ls-files', '-z', 'terraform/aws').stdout.split('\0')
        original = {}
        for relative in filter(None, tracked):
            rel = Path(relative)
            if rel.is_absolute() or '..' in rel.parts or rel.parts[:2] != ('terraform', 'aws'):
                raise PlanError('소스 경로가 예상과 다릅니다.')
            if rel.name in ('backend.tf', 'versions.tf'):
                raise PlanError('고정 상류 소스에 예상하지 않은 backend/versions 파일이 있습니다.')
            source = SOURCE / rel
            if source.is_symlink() or not source.is_file():
                raise PlanError('소스 파일에 심볼릭 링크를 사용할 수 없습니다.')
            destination = tfdir / rel.relative_to('terraform/aws')
            private_write(destination, source.read_bytes())
            original[str(destination.relative_to(tfdir))] = sha256(source)
        if not original:
            raise PlanError('Terraform 소스를 복사하지 못했습니다.')
        network = tfdir / 'modules/network/resources.tf'
        text = patch_once(network.read_text(),
                          r'(source\s*=\s*"terraform-aws-modules/vpc/aws")',
                          r'\1\n  version = "' + vpc_version + '"\n'
                          '  manage_default_security_group = false')
        network.write_text(text)
        server = tfdir / 'modules/generic-server/resources.tf'
        text = patch_once(server.read_text(),
                          r'(  private_ip\s*=\s*var\.private_ip\n)',
                          r'\1  associate_public_ip_address = false\n')
        text = patch_once(text, r'(description = "Allow all inbound traffic"[\s\S]*?cidr_blocks = )\["0\.0\.0\.0/0"\]',
                          r'\1["' + VPC_CIDR + '"]')
        server.write_text(text)
        resources = tfdir / 'resources.tf'
        text = resources.read_text()
        for name in ('router', 'attack_range_servers'):
            text = patch_once(text, r'(module "' + name + r'" \{\n)',
                              r'\1  resource_tags = var.aws.aws_default_tags\n')
        resources.write_text(text)
        for module in ('router', 'generic-server'):
            module_dir = tfdir / 'modules' / module
            resources = module_dir / 'resources.tf'
            text = patch_once(resources.read_text(), r'(  private_ip\s*=\s*var\.private_ip\n)',
                              r'\1  volume_tags = var.resource_tags\n  disable_api_termination = false\n')
            resources.write_text(text)
            variable_path = module_dir / 'variables.tf'
            variable_path.write_text(variable_path.read_text() +
                                     '\nvariable "resource_tags" {\n  type = map(string)\n}\n')
        versions = ('terraform {\n  required_version = "= ' + TERRAFORM_VERSION + '"\n'
                    '  required_providers {\n    aws = {\n      source = "hashicorp/aws"\n'
                    '      version = "= ' + aws_version + '"\n    }\n  }\n}\n')
        private_write(tfdir / 'versions.tf', versions)
        values = {key: template[key] for key in ('general', 'aws', 'attack_range')}
        private_write(temporary / 'terraform.tfvars.json', json_bytes(values))
        private_write(temporary / 'private-config.json', json_bytes(template))
        hashes = {str(path.relative_to(tfdir)): sha256(path) for path in tfdir.rglob('*') if path.is_file()}
        preparation = {
            'format_version': 1, 'prepared_at': utc_text(now), 'expires_at': utc_text(expires),
            'range_id': range_id, 'region': region, 'whitelist': allowed_ip,
            'upstream_commit': manifest['commit'], 'upstream_template': TEMPLATE,
            'terraform_version': TERRAFORM_VERSION, 'aws_provider_version': aws_version,
            'vpc_module_version': vpc_version, 'password_fields_replaced': password_fields,
            'root': str(final), 'terraform_dir': str(final / 'terraform'),
            'tfvars_path': str(final / 'terraform.tfvars.json'),
            'tfvars_sha256': sha256(temporary / 'terraform.tfvars.json'),
            'source_sha256': hashes, 'upstream_source_sha256': original,
            'source_changes': ['versions.tf', 'resources.tf', 'modules/network/resources.tf',
                               'modules/generic-server/resources.tf', 'modules/generic-server/variables.tf',
                               'modules/router/resources.tf', 'modules/router/variables.tf'],
            'local_backend': True, 'ssh_key_imported': False, 's3_backend_created': False,
            'cloud_resources_provisioned': False, 'ttl_scheduler_installed': False,
            'daily_budget_usd': 10, 'windows_instance_type': windows_instance_type,
            **lifecycle,
        }
        private_write(temporary / 'prepare.json', json_bytes(preparation))
        if final.exists():
            raise PlanError('기존 준비 상태를 교체하지 않습니다.')
        temporary.rename(final)
        return final / 'prepare.json'
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify_preparation(path, *, require_dependencies=True):
    preparation = read_json(path)
    region = checked_region(preparation.get('region'))
    _, windows_instance_type = preparation_options(preparation)
    root = path.parent.resolve()
    if preparation.get('root') != str(root) or preparation.get('terraform_dir') != str(root / 'terraform'):
        raise PlanError('준비 자료의 경로가 일치하지 않습니다.')
    verify_source()
    if preparation.get('upstream_commit') != read_json(MANIFEST).get('commit'):
        raise PlanError('준비 자료의 상류 커밋이 다릅니다.')
    tfdir = root / 'terraform'
    for relative, digest in preparation.get('source_sha256', {}).items():
        rel = Path(relative)
        if rel.is_absolute() or '..' in rel.parts:
            raise PlanError('준비 소스의 경로가 올바르지 않습니다.')
        item = tfdir / rel
        if item.is_symlink() or not item.is_file() or sha256(item) != digest:
            raise PlanError('준비 이후 Terraform 소스가 변경되었습니다.')
    tfvars = root / 'terraform.tfvars.json'
    if tfvars.is_symlink() or sha256(tfvars) != preparation.get('tfvars_sha256'):
        raise PlanError('준비 이후 Terraform 변수가 변경되었습니다.')
    variables = read_json(tfvars)
    if variables.get('aws', {}).get('region') != region:
        raise PlanError('준비 자료와 Terraform 변수의 AWS 리전이 다릅니다.')
    checked_template(variables, windows_instance_type=windows_instance_type)
    for item in tfdir.glob('*.tf'):
        if re.search(r'backend\s+"', item.read_text()):
            raise PlanError('사전 plan에 원격 backend를 사용할 수 없습니다.')
    allowed = set(preparation.get('source_sha256', {}))
    actual = {str(item.relative_to(tfdir)) for item in tfdir.rglob('*.tf')
              if '.terraform' not in item.relative_to(tfdir).parts}
    if not actual.issubset(allowed):
        raise PlanError('준비 이후 추가 Terraform 소스가 발견되었습니다.')
    if require_dependencies:
        lock = tfdir / '.terraform.lock.hcl'
        if not lock.is_file() or lock.is_symlink():
            raise PlanError('Terraform 공급자 lock 파일이 없습니다.')
        pattern = r'provider "registry\.terraform\.io/hashicorp/aws"\s*\{([^}]+)\}'
        match = re.search(pattern, lock.read_text())
        version = re.search(r'version\s*=\s*"([^"]+)"', match.group(1)) if match else None
        if not version or version.group(1) != preparation.get('aws_provider_version'):
            raise PlanError('AWS 공급자 lock 버전이 준비 자료와 다릅니다.')
        modules = read_json(tfdir / '.terraform/modules/modules.json')
        vpc = [item for item in modules.get('Modules', []) if item.get('Key') == 'networkModule.vpc']
        if len(vpc) != 1 or vpc[0].get('Version') != preparation.get('vpc_module_version') or vpc[0].get('Source') != 'registry.terraform.io/terraform-aws-modules/vpc/aws':
            raise PlanError('VPC 모듈 설치 버전이 준비 자료와 다릅니다.')
    return preparation


def check(condition, message):
    if not condition:
        raise PlanError(message)


def known(after, unknown, key, message):
    check(key in after and unknown.get(key) is not True, message)
    return after[key]


def ami_metadata(plan):
    result = {}
    def collect(module):
        for resource in module.get('resources', []):
            if resource.get('mode') == 'data' and resource.get('type') == 'aws_ami':
                values = resource.get('values', {})
                if isinstance(values.get('id'), str):
                    result[values['id']] = values
        for child in module.get('child_modules', []):
            collect(child)
    # Refreshed AMI data may only be present in prior_state for saved plans;
    # newer planned values/change values take precedence for the same AMI ID.
    collect(plan.get('prior_state', {}).get('values', {}).get('root_module', {}))
    collect(plan.get('planned_values', {}).get('root_module', {}))
    for resource in plan.get('resource_changes', []):
        if resource.get('mode') == 'data' and resource.get('type') == 'aws_ami':
            values = resource.get('change', {}).get('after', {}) or {}
            if isinstance(values.get('id'), str):
                result[values['id']] = values
    return result


def only_root_ami(metadata):
    if not isinstance(metadata, dict) or not metadata.get('root_device_name'):
        return False
    mappings = metadata.get('block_device_mappings')
    if not isinstance(mappings, list) or not mappings:
        return False
    roots = 0
    for mapping in mappings:
        if not isinstance(mapping, dict) or not isinstance(mapping.get('device_name'), str):
            return False
        ebs = mapping.get('ebs')
        # AWS 6.68 returns an EBS object. Retain the older one-element list
        # form only when its sole object is explicitly nonempty.
        if isinstance(ebs, list) and len(ebs) == 1 and isinstance(ebs[0], dict):
            ebs = ebs[0]
        if isinstance(ebs, dict) and ebs:
            if (mapping['device_name'] != metadata['root_device_name']
                    or mapping.get('virtual_name') or mapping.get('no_device')):
                return False
            roots += 1
        elif (mapping.get('ebs') == {} and mapping['device_name'] != metadata['root_device_name']
              and isinstance(mapping.get('virtual_name'), str)
              and re.fullmatch(r'ephemeral[0-9]+', mapping['virtual_name'])
              and not mapping.get('no_device')):
            # These explicitly declared instance-store mappings create no EBS
            # volumes; the fixed t3 instances have no instance-store disks.
            continue
        else:
            return False
    return roots == 1


def validate_plan(plan, preparation, *, now=None):
    """Fail closed on extra, changed, unknown, or publicly exposed resources."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    lifecycle, windows_instance_type = preparation_options(preparation)
    try:
        expires = datetime.fromisoformat(preparation['expires_at'].replace('Z', '+00:00'))
        created = datetime.fromisoformat(preparation['prepared_at'].replace('Z', '+00:00'))
    except (KeyError, ValueError, TypeError) as exc:
        raise PlanError('준비 자료의 만료 시간이 올바르지 않습니다.') from exc
    check(expires.tzinfo is not None and created.tzinfo is not None,
          '준비 자료의 시간대가 없습니다.')
    check(utc_text(expires) == preparation['expires_at'] and utc_text(created) == preparation['prepared_at'],
          '준비 자료의 시간은 UTC Z 형식이어야 합니다.')
    check(created <= now < expires and expires - created == timedelta(hours=lifecycle['planned_session_hours']),
          '준비 자료가 만료됐거나 명시한 계획 기간과 다릅니다.')
    region = checked_region(preparation.get('region'))
    whitelist(preparation.get('whitelist', ''))
    check(plan.get('terraform_version') == preparation.get('terraform_version') == TERRAFORM_VERSION,
          'Terraform 실행 버전이 고정값과 다릅니다.')
    check(str(plan.get('format_version', '')).startswith('1.'), 'Terraform JSON plan 형식을 확인하세요.')
    check(plan.get('errored') is not True and plan.get('complete') is not False,
          '완전한 정상 Terraform plan이 아닙니다.')
    check(not plan.get('deferred_changes'), '아직 확정되지 않은 자원 변경이 있습니다.')
    variables = plan.get('variables', {})
    expected_tags = {TAGS[0]: 'AegisLoop', TAGS[1]: preparation.get('range_id'),
                     TAGS[2]: preparation['expires_at']}
    check(variables.get('aws', {}).get('value', {}).get('region') == region,
          'plan의 AWS 리전이 준비 자료와 다릅니다.')
    general = variables.get('general', {}).get('value', {})
    check(general.get('attack_range_id') == preparation.get('range_id') and
          general.get('key_name') == preparation.get('range_id') and
          general.get('ip_whitelist') == preparation.get('whitelist'),
          'plan의 대상 UUID·키 이름·허용 주소가 다릅니다.')
    hosts = variables.get('attack_range', {}).get('value')
    check(isinstance(hosts, list), 'plan의 대상 서버 변수가 없습니다.')
    checked_template({'general': {'cloud_provider': 'aws'}, 'attack_range': hosts},
                     windows_instance_type=windows_instance_type)
    check('changeme123!' not in json.dumps(variables), 'plan에 상류 기본 암호가 남아 있습니다.')
    changes = plan.get('resource_changes')
    check(isinstance(changes, list), '자원 변경 목록이 없는 plan입니다.')
    amis = ami_metadata(plan)
    counts = {}
    seen = set()
    instance_summary = []
    specs = {
        'module.router.aws_instance.router': ('t3.small', 30, True, '10.0.1.10'),
        'module.attack_range_servers["splunk"].aws_instance.this': ('t3.xlarge', 60, False, '10.0.2.10'),
        'module.attack_range_servers["win"].aws_instance.this': (windows_instance_type, 60, False, '10.0.2.11'),
    }
    sg_specs = {
        'module.router.aws_security_group.default': [(22, 22, 'tcp', preparation['whitelist']),
                                                     (51820, 51820, 'udp', preparation['whitelist'])],
        'module.attack_range_servers["splunk"].aws_security_group.this': [(0, 0, '-1', VPC_CIDR)],
        'module.attack_range_servers["win"].aws_security_group.this': [(0, 0, '-1', VPC_CIDR)],
    }
    network_limits = {
        'aws_vpc': 1, 'aws_subnet': 2, 'aws_internet_gateway': 1, 'aws_eip': 1,
        'aws_nat_gateway': 1, 'aws_route_table': 2, 'aws_route': 2,
        'aws_route_table_association': 2, 'aws_default_network_acl': 1,
        'aws_default_route_table': 1, 'aws_default_security_group': 1,
    }
    network_names = {
        'aws_vpc.this[0]', 'aws_subnet.public[0]', 'aws_subnet.private[0]',
        'aws_internet_gateway.this[0]', 'aws_eip.nat[0]', 'aws_nat_gateway.this[0]',
        'aws_route_table.public[0]', 'aws_route_table.private[0]',
        'aws_route.public_internet_gateway[0]', 'aws_route.private_nat_gateway[0]',
        'aws_route_table_association.public[0]', 'aws_route_table_association.private[0]',
        'aws_default_network_acl.this[0]', 'aws_default_route_table.default[0]',
        'aws_default_security_group.this[0]',
    }
    for resource in changes:
        if resource.get('mode') == 'data':
            continue
        check(resource.get('mode') == 'managed', '알 수 없는 자원 모드입니다.')
        address, kind = resource.get('address'), resource.get('type')
        check(isinstance(address, str) and address not in seen, '중복되거나 잘못된 자원 주소입니다.')
        seen.add(address)
        change = resource.get('change', {})
        check(change.get('actions') == ['create'], '기존 자원 변경·삭제·교체는 고정된 범위가 아닙니다.')
        after, unknown = change.get('after'), change.get('after_unknown', {})
        check(isinstance(after, dict) and isinstance(unknown, dict), '자원 계획 값이 올바르지 않습니다.')
        counts[kind] = counts.get(kind, 0) + 1
        if kind == 'aws_instance':
            check(address in specs, '허용하지 않은 EC2 서버가 추가되었습니다.')
            instance, size, public, private_ip = specs[address]
            check(known(after, unknown, 'instance_type', 'EC2 타입이 미확정입니다.') == instance, 'EC2 타입이 고정된 구성과 다릅니다.')
            check(known(after, unknown, 'associate_public_ip_address', 'EC2 공인 IP 조건이 미확정입니다.') is public,
                  'Router 이외 EC2에 공인 IP가 설정됐습니다.')
            check(known(after, unknown, 'disable_api_termination', 'EC2 종료 보호 조건이 미확정입니다.') is False,
                  'EC2 종료 보호가 켜져 있으면 계획한 자원 정리를 수행할 수 없습니다.')
            check(known(after, unknown, 'private_ip', 'EC2 사설 IP가 미확정입니다.') == private_ip,
                  'EC2 사설 IP가 고정된 구성과 다릅니다.')
            ami = known(after, unknown, 'ami', '실제 AMI가 미확정입니다.')
            check(isinstance(ami, str) and re.fullmatch(r'ami-[0-9a-f]{8,17}', ami) and only_root_ami(amis.get(ami)),
                  '선택된 AMI 또는 AMI 디스크 조건을 확인할 수 없습니다.')
            blocks = after.get('root_block_device')
            check(isinstance(blocks, list) and len(blocks) == 1, 'EC2 루트 디스크 조건이 미확정입니다.')
            block = blocks[0]
            block_unknown = unknown.get('root_block_device', [{}])
            check(block_unknown is not True, 'EC2 루트 디스크가 미확정입니다.')
            if isinstance(block_unknown, list):
                block_unknown = block_unknown[0] if block_unknown else {}
            check(isinstance(block_unknown, dict), 'EC2 루트 디스크 조건을 확인하세요.')
            for field in ('volume_size', 'volume_type', 'encrypted', 'delete_on_termination'):
                known(block, block_unknown, field, 'EC2 루트 디스크 필수 조건이 미확정입니다.')
            check(block.get('volume_size') == size and block.get('volume_type') == 'gp3'
                  and block.get('encrypted') is True and block.get('delete_on_termination') is True,
                  'EC2 디스크 용량·종류·암호화·종료 삭제 조건이 다릅니다.')
            check(not after.get('ebs_block_device'), '추가 EBS 디스크는 고정된 범위가 아닙니다.')
            if unknown.get('ebs_block_device'):
                # AWS marks the optional/computed EBS set unknown on a fresh
                # instance. The already resolved AMI mappings must prove that
                # it contains only the separately checked root volume.
                check(only_root_ami(amis.get(after.get('ami'))),
                      'AMI의 추가 디스크 여부가 미확정입니다.')
            volume_tags = known(after, unknown, 'volume_tags', 'EC2 디스크 소유 태그가 미확정입니다.')
            check(isinstance(volume_tags, dict) and all(volume_tags.get(key) == value for key, value in expected_tags.items()),
                  'EC2 디스크 소유·만료 태그가 누락되었습니다.')
            instance_summary.append({'name': address, 'instance_type': instance, 'root_gib': size,
                                     'public_ip_associated': public, 'resolved_ami_id': ami})
        elif kind == 'aws_security_group':
            check(address in sg_specs, '허용하지 않은 보안 그룹입니다.')
            ingress = known(after, unknown, 'ingress', '수신 규칙이 미확정입니다.')
            check(isinstance(ingress, list) and len(ingress) == len(sg_specs[address]), '수신 규칙 수가 다릅니다.')
            actual_rules = []
            for rule in ingress:
                cidrs = rule.get('cidr_blocks')
                check(isinstance(cidrs, list) and len(cidrs) == 1 and not rule.get('ipv6_cidr_blocks')
                      and not rule.get('prefix_list_ids') and not rule.get('security_groups') and not rule.get('self'),
                      '허용하지 않은 수신 출처가 포함되었습니다.')
                actual_rules.append((rule.get('from_port'), rule.get('to_port'), rule.get('protocol'), cidrs[0]))
            check(set(actual_rules) == set(sg_specs[address]), '공개 또는 사설 수신 규칙이 고정된 범위와 다릅니다.')
        else:
            prefix = 'module.networkModule.module.vpc.'
            check(address.startswith(prefix) and address[len(prefix):] in network_names and kind in network_limits,
                  '승인하지 않은 추가 자원입니다.')
            check(counts[kind] <= network_limits[kind], '네트워크 자원 수가 고정된 범위를 넘습니다.')
            if kind == 'aws_vpc':
                check(known(after, unknown, 'cidr_block', 'VPC CIDR가 미확정입니다.') == VPC_CIDR,
                      'VPC CIDR가 고정된 구성과 다릅니다.')
            if kind == 'aws_subnet':
                cidr = known(after, unknown, 'cidr_block', '서브넷 CIDR가 미확정입니다.')
                expected_cidr = '10.0.1.0/24' if address.endswith('public[0]') else '10.0.2.0/24'
                check(cidr == expected_cidr, '승인하지 않은 서브넷입니다.')
                check(known(after, unknown, 'map_public_ip_on_launch', '서브넷 공인 IP 조건이 미확정입니다.') is False,
                      '서브넷의 자동 공인 IP 할당이 켜져 있습니다.')
                check(after.get('assign_ipv6_address_on_creation') in (False, None) and
                      not unknown.get('assign_ipv6_address_on_creation'), 'IPv6 자동 할당은 고정된 범위가 아닙니다.')
            if kind == 'aws_route':
                check(known(after, unknown, 'destination_cidr_block', '라우트 범위가 미확정입니다.') == '0.0.0.0/0'
                      and not after.get('destination_ipv6_cidr_block'), '승인하지 않은 라우트입니다.')
            if kind == 'aws_eip':
                check(known(after, unknown, 'domain', 'EIP 종류가 미확정입니다.') == 'vpc', 'EIP 종류가 다릅니다.')
            if kind == 'aws_nat_gateway':
                check(known(after, unknown, 'connectivity_type', 'NAT 종류가 미확정입니다.') == 'public', 'NAT 종류가 다릅니다.')
            if kind in ('aws_default_security_group', 'aws_default_network_acl', 'aws_default_route_table'):
                # Default network objects must not expand public connectivity.
                if kind == 'aws_default_security_group':
                    check(not after.get('ingress') and not unknown.get('ingress'), 'VPC 기본 보안 그룹 수신 규칙이 추가되었습니다.')
        if kind not in ('aws_route', 'aws_route_table_association'):
            # AWS routes and route-table associations do not support tags.
            tags = after.get('tags_all')
            unknown_tags = unknown.get('tags_all', {})
            check(unknown_tags is not True and isinstance(tags, dict) and
                  all(tags.get(key) == value for key, value in expected_tags.items()),
                  '식별·만료 태그가 누락됐거나 미확정입니다.')
            if isinstance(unknown_tags, dict):
                check(not any(unknown_tags.get(key) for key in expected_tags), '필수 소유 태그가 미확정입니다.')
    for kind, count in {'aws_instance': 3, 'aws_security_group': 3, 'aws_vpc': 1, 'aws_subnet': 2,
                        'aws_internet_gateway': 1, 'aws_eip': 1, 'aws_nat_gateway': 1,
                        'aws_route_table': 2, 'aws_route': 2, 'aws_route_table_association': 2}.items():
        check(counts.get(kind) == count, '필수 자원 수가 고정된 구성과 다릅니다: ' + kind)
    check(set(specs).issubset(seen) and set(sg_specs).issubset(seen), '필수 서버·보안 그룹이 없습니다.')
    warnings = ['구조 검토는 IAM 생성 권한이나 실제 비용 상한을 입증하지 않습니다.',
                'SSH 키·S3 backend는 아직 생성하지 않은 사전 plan입니다.',
                '공식 build는 이 saved plan을 자동으로 적용하지 않습니다.']
    if lifecycle['lifecycle_mode'] == 'manual':
        warnings.append('수동 종료 계획입니다. 만료 태그는 종료 예약이 아니며 사용자가 전체 자원을 직접 정리해야 합니다.')
    else:
        warnings.append('만료 태그만으로 자원이 종료되지 않습니다. 종료 장치를 별도로 검증하세요.')
    if windows_instance_type == 't3.medium':
        warnings.append('Windows 4 GiB 구성의 역할 설치·성능은 실제 호스트에서 별도로 검증해야 합니다.')
    return {
        'checked_at': utc_text(now), 'range_id': preparation['range_id'], 'region': region,
        'structural_plan_checks_passed': True, 'resource_counts': counts,
        'instances': sorted(instance_summary, key=lambda item: item['name']), 'root_storage_gib': 150,
        'estimated_public_ipv4_count': 2, 'expires_at': preparation['expires_at'],
        'source_commit': preparation['upstream_commit'], 'ttl_scheduler_verified': False,
        **lifecycle, 'windows_instance_type': windows_instance_type,
        'daily_budget_usd': preparation.get('daily_budget_usd', 10),
        'cost_cap_guaranteed': False, 'ssh_key_imported_by_this_check': False,
        's3_backend_created_by_this_check': False, 'cloud_resources_provisioned_by_this_check': False,
        'warnings': warnings,
    }


def main():
    parser = argparse.ArgumentParser(description='AWS Windows 단일 대상의 비공개 사전 plan 준비·검토')
    commands = parser.add_subparsers(dest='command', required=True)
    initial = commands.add_parser('prepare')
    initial.add_argument('--whitelist', required=True)
    initial.add_argument('--region', default=REGION, choices=ALLOWED_REGIONS)
    initial.add_argument('--lifecycle-mode', default='automatic', choices=LIFECYCLE_MODES)
    initial.add_argument('--session-hours', default=4, type=int)
    initial.add_argument('--windows-instance-type', default='t3.large', choices=WINDOWS_INSTANCE_TYPES)
    initial.add_argument('--aws-provider-version', required=True)
    initial.add_argument('--vpc-module-version', required=True)
    review = commands.add_parser('validate-plan')
    review.add_argument('plan_json', type=Path)
    review.add_argument('--preparation', type=Path, required=True)
    try:
        args = parser.parse_args()
        if args.command == 'prepare':
            path = prepare(args.whitelist, args.aws_provider_version, args.vpc_module_version,
                           region=args.region, ttl_hours=args.session_hours,
                           lifecycle_mode=args.lifecycle_mode,
                           windows_instance_type=args.windows_instance_type)
            print('비공개 준비 자료:', path)
            print('Terraform·AWS 작업은 실행하지 않았습니다. plan 검증과 종료 방식 확인이 필요합니다.')
        else:
            preparation = verify_preparation(args.preparation)
            report = validate_plan(read_json(args.plan_json), preparation)
            report['plan_json_sha256'] = sha256(args.plan_json)
            report['provider_lock_sha256'] = sha256(args.preparation.parent / 'terraform/.terraform.lock.hcl')
            output = args.preparation.parent / ('review-' + secrets.token_hex(4) + '.json')
            private_write(output, json_bytes(report))
            print('사전 plan 구조 검토 통과. 서버 3대, gp3 총 150 GiB, NAT 1개.')
            print('비공개 검토 기록:', output)
            print('자원 생성·비용 상한·자동 종료가 검증된 상태는 아닙니다.')
    except (PlanError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print(str(exc) if isinstance(exc, PlanError) else '준비·검토에 실패했습니다. 비공개 파일과 고정 소스를 확인하세요.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
