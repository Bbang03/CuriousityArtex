#!/usr/bin/env python3
"""Offline controller policy for one TTL deployment, with admin-created roles.

This is a policy for the specifically named controller APIs, not an SDK-source
or Terraform-plan baseline. It never discovers credentials, calls AWS, or
uploads policies. Runtime role policies come from the separately reviewed TTL
bundle; the controller cannot create roles or edit their policies.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('aegis_ttl', Path(__file__).with_name('aws_ttl.py'))
ttl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ttl)
STATE = Path(__file__).resolve().parents[2] / '.local-runtime/attack-range'
SAR_ROOT = 'https://servicereference.us-east-1.amazonaws.com/v1'


def documents(session, *, ttl_bundle='<TTL_BUNDLE>'):
    ttl.runtime.validate_session(session)
    identifier, account, region = (session[key] for key in ('session_id', 'account_id', 'region'))
    name = 'aegisloop-ttl-' + identifier
    cleanup_role = f'arn:aws:iam::{account}:role/{name}-cleanup'
    scheduler_role = f'arn:aws:iam::{account}:role/{name}-scheduler'
    function = f'arn:aws:lambda:{region}:{account}:function:{name}'
    group = f'arn:aws:scheduler:{region}:{account}:schedule-group/{name}'
    schedule = f'arn:aws:scheduler:{region}:{account}:schedule/{name}/expiry'
    log_group = f'arn:aws:logs:{region}:{account}:log-group:/aws/lambda/{name}'
    quota = f'arn:aws:servicequotas:{region}:{account}:ec2/L-1216C47A'
    tags = {ttl.runtime.OWNER_TAG: identifier, ttl.runtime.EXPIRY_TAG: session['expires_at']}
    regional = {'StringEquals': {'aws:RequestedRegion': region}}
    creation = {'StringEquals': {'aws:RequestedRegion': region,
                                **{'aws:RequestTag/' + key: value for key, value in tags.items()}},
                'ForAllValues:StringEquals': {'aws:TagKeys': list(tags)},
                'Null': {'aws:TagKeys': 'false'},
                'DateLessThan': {'aws:CurrentTime': session['expires_at']}}

    def statement(sid, actions, resources, condition=None):
        result = {'Sid': sid, 'Effect': 'Allow', 'Action': actions, 'Resource': resources}
        if condition:
            result['Condition'] = condition
        return result

    policy = {'Version': '2012-10-17', 'Statement': [
        statement('ReadTwoAdminCreatedRoles', ['iam:GetRole', 'iam:GetRolePolicy',
                                              'iam:ListRolePolicies', 'iam:ListAttachedRolePolicies'],
                  [cleanup_role, scheduler_role]),
        statement('PassCleanupRoleOnlyToLambda', ['iam:PassRole'], [cleanup_role],
                  {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}}),
        statement('PassSchedulerRoleOnlyToScheduler', ['iam:PassRole'], [scheduler_role],
                  {'StringEquals': {'iam:PassedToService': 'scheduler.amazonaws.com'}}),
        statement('CreateOneTaggedFunctionBeforeExpiry', ['lambda:CreateFunction', 'lambda:TagResource'],
                  [function], creation),
        statement('InspectAndInvokeOneFunction', ['lambda:GetFunctionConfiguration', 'lambda:InvokeFunction'],
                  [function], regional),
        statement('CreateOneTaggedLogGroupBeforeExpiry',
                  ['logs:CreateLogGroup', 'logs:TagLogGroup', 'logs:TagResource'],
                  [log_group, log_group + ':*'], creation),
        statement('SetOneLogGroupRetention', ['logs:PutRetentionPolicy'],
                  [log_group, log_group + ':*'], regional),
        statement('CreateOneTaggedScheduleGroupBeforeExpiry',
                  ['scheduler:CreateScheduleGroup', 'scheduler:TagResource'], [group], creation),
        statement('ReadOneScheduleGroup', ['scheduler:GetScheduleGroup'], [group], regional),
        statement('CreateOneExpiryScheduleBeforeExpiry', ['scheduler:CreateSchedule'], [schedule],
                  regional | {'DateLessThan': {'aws:CurrentTime': session['expires_at']}}),
        statement('ReadOneExpirySchedule', ['scheduler:GetSchedule'], [schedule], regional),
        statement('ReadStandardOnDemandVcpuQuota', ['servicequotas:GetServiceQuota'], [quota],
                  {'StringEquals': {'aws:RequestedRegion': region, 'servicequotas:service': 'ec2'}}),
    ]}
    policy_size = len(json.dumps(policy, separators=(',', ':')))
    if policy_size > 6144:
        raise ValueError('Controller policy exceeds the customer managed policy size limit')
    review = {
        'session_id': identifier, 'account_id': account, 'region': region,
        'expires_at': session['expires_at'], 'cloud_calls_performed': False,
        'policy_uploaded': False, 'admin_precreated_runtime_roles_required': True,
        'runtime_role_arns': [cleanup_role, scheduler_role], 'required_creation_tags': tags,
        'expected_inline_policy_names': ['aegisloop-session-runtime'],
        'expected_attached_managed_policy_arns': [], 'complete_trust_document_match_required': True,
        'function_arn': function, 'schedule_group_arn': group, 'schedule_arn': schedule,
        'log_group_arn': log_group, 'reviewed_ttl_runtime_policies_required': True,
        'scope': 'TTL installation, exact lookup and one EC2 vCPU quota read; no Terraform or EC2 provisioning',
        'quota_arn': quota, 'planned_additional_standard_vcpus': 8,
        'managed_policy_compact_character_count': policy_size,
        'recommended_attachment': 'administrator-created customer managed policy',
        'requirements': [
            'An administrator first creates the two roles using the separately reviewed TTL trust and runtime policies.',
            'Each role must have exactly the expected inline policy, zero attached managed policies and the complete matching trust document.',
            'The controller policy cannot create roles, edit role policies, or attach managed policies.',
            'Function, log-group and schedule-group creation must send exactly the two required tags.',
            'Use GetFunctionConfiguration; GetFunction and broad account/list operations are not permitted.',
            'Create a standard on-demand ZIP function without Layers, VPC configuration or CapacityProviderConfig.',
            'This document intentionally does not permit policy upload or change any principal permissions.',
            'An IAM user inline policy cannot hold this document; use a customer managed policy created by the administrator.',
            'GetServiceQuota is read only; no quota increase request or unrelated quota access is permitted.',
            'The policy is review material; actual IAM evaluation and remote inspect remain required.',
        ],
        'sar_sources': [f'{SAR_ROOT}/{service}/{service}.json' for service in ('iam', 'lambda', 'logs', 'scheduler', 'servicequotas')],
        'named_api_operations': {
            'iam': ['GetRole', 'GetRolePolicy', 'ListRolePolicies', 'ListAttachedRolePolicies'],
            'lambda': ['CreateFunction', 'GetFunctionConfiguration', 'Invoke'],
            'logs': ['CreateLogGroup', 'PutRetentionPolicy'],
            'scheduler': ['CreateScheduleGroup', 'CreateSchedule', 'GetScheduleGroup', 'GetSchedule'],
            'servicequotas': ['GetServiceQuota'],
        },
    }
    prefix = ['aws', '--profile', '<ADMIN_PROFILE>', '--region', region, '--no-cli-pager']
    role_commands = []
    for suffix, stem in (('cleanup', 'lambda'), ('scheduler', 'scheduler')):
        role_name = name + '-' + suffix
        role_commands.extend([
            prefix + ['iam', 'create-role', '--role-name', role_name,
                      '--assume-role-policy-document', 'file://' + str(ttl_bundle) + '/' + stem + '-trust.json',
                      '--description', 'One reviewed AegisLoop session runtime role'],
            prefix + ['iam', 'put-role-policy', '--role-name', role_name,
                      '--policy-name', 'aegisloop-session-runtime',
                      '--policy-document', 'file://' + str(ttl_bundle) + '/' + stem + '-policy.json'],
            prefix + ['iam', 'get-role', '--role-name', role_name],
            prefix + ['iam', 'get-role-policy', '--role-name', role_name,
                      '--policy-name', 'aegisloop-session-runtime'],
            prefix + ['iam', 'list-role-policies', '--role-name', role_name],
            prefix + ['iam', 'list-attached-role-policies', '--role-name', role_name],
        ])
    recipe = {
        'session_id': identifier, 'account_id': account, 'region': region,
        'expires_at': session['expires_at'], 'executed': False, 'commands_are_argv_arrays': True,
        'administrator_only': True, 'commands': role_commands,
        'before_execution': [
            'Review lambda-trust/policy and scheduler-trust/policy in the exact TTL bundle.',
            'Replace <ADMIN_PROFILE> with an administrator-authorized profile for the stated account.',
            'Confirm account identity and session expiry; these commands are not executed by the generator.',
            'Do not overwrite roles that already exist; compare their complete trust/policy documents first.',
            'Verify exactly one inline policy named aegisloop-session-runtime and zero attached managed policies per role.',
            'Attach controller-policy.json to the actual controller principal using the administrator workflow.',
            'Do not grant the controller CreateRole or PutRolePolicy.',
            'Save the accepted roles and controller policy as private deployment evidence.',
        ],
    }
    guide = (
        'Attack Range AWS 세션 관리자 준비 절차\n\n'
        f'대상 계정: {account}\n리전: {region}\n세션: {identifier}\n만료(UTC): {session["expires_at"]}\n\n'
        '이 자료는 검토용입니다. 생성기가 AWS 작업이나 권한 변경을 수행하지 않습니다.\n'
        '기존 공격 범위 실행 계정에 AdministratorAccess를 추가하지 않습니다.\n\n'
        '1. 관리자가 TTL bundle의 lambda-trust.json/lambda-policy.json과\n'
        '   scheduler-trust.json/scheduler-policy.json을 먼저 검토합니다.\n'
        '2. 관리자가 아래 역할 두 개를 생성합니다. 기존에 있으면 덮어쓰지 않고\n'
        '   신뢰 정책과 모든 권한 정책이 검토 자료와 일치하는지 확인합니다.\n'
        f'   {name}-cleanup\n   {name}-scheduler\n'
        '   CLI 작업 순서는 admin-roles-recipe.json에 인자 배열로 기록돼 있습니다.\n'
        '   각 역할에는 aegisloop-session-runtime 인라인 정책 하나만 있어야 하며\n'
        '   연결된 관리형 정책은 0개여야 합니다. 신뢰 정책 전체와 인라인 정책\n'
        '   내용도 검토한 TTL 자료와 완전히 일치해야 합니다.\n'
        '3. 관리자가 controller-policy.json으로 고객 관리형 IAM 정책을 생성해\n'
        '   실제 Attack Range 실행 주체에 연결합니다. CLI profile 이름과 IAM\n'
        '   사용자/역할 이름은 다를 수 있으므로 실제 주체 ARN을 먼저 확인합니다.\n'
        f'   정책 크기: {policy_size}/6144자. IAM 사용자 인라인 정책 한도 2048자를 넘으므로\n'
        '   사용자 인라인 정책으로 붙이지 않습니다.\n'
        '4. 실행 계정으로 역할의 신뢰 정책 전체, 인라인 정책 목록/내용, 연결된\n'
        '   관리형 정책 목록을 조회해 위 조건을 독립적으로 확인한 뒤 TTL function,\n'
        '   log group, schedule group 및 expiry schedule을 생성합니다. 함수는\n'
        '   Layers/VPC/CapacityProviderConfig 없는 일반 Python ZIP 방식입니다.\n'
        '   함수·log group·schedule group 생성 요청에는 아래 두 태그만 넣습니다.\n'
        f'   AegisLoopSession={identifier}\n   AegisLoopExpiresAt={session["expires_at"]}\n'
        '5. Lambda inspect 동기 호출 결과의 FunctionError 부재, inspect_complete,\n'
        '   errors/pending 없음과 생성 전 유료 자원 없음까지 검증합니다.\n'
        '6. EC2 Standard On-Demand vCPU 한도(L-1216C47A)를 조회합니다.\n'
        '   기존 사용량을 제외한 여유가 이번 구성의 8 vCPU 이상이어야 합니다.\n'
        '   여유가 없으면 유료 Terraform apply를 진행하지 않습니다.\n'
        '7. 검증된 저장 plan의 SHA와 모든 소유/만료 태그가 일치하고 아직\n'
        '   만료되지 않았는지 확인한 뒤에만 실행 담당자가 적용합니다.\n\n'
        '허용된 컨트롤러 문서는 역할/주체 권한을 수정하지 못합니다. Terraform 및\n'
        'EC2 생성 권한은 이 정책에 포함되지 않으며 따로 검증해야 합니다.\n'
    )
    return {'controller-policy.json': policy, 'controller-review.json': review,
            'admin-roles-recipe.json': recipe, 'admin-instructions.txt': guide}


def write_artifacts(session, destination, *, ttl_bundle='<TTL_BUNDLE>'):
    data = documents(session, ttl_bundle=ttl_bundle)
    path = Path(destination)
    if STATE.is_symlink():
        raise ValueError('Private runtime directory cannot be a symbolic link')
    if path.is_symlink() or path.exists():
        raise ValueError('Use a new private output directory; no existing files are replaced')
    if not path.resolve().is_relative_to(STATE.resolve()):
        raise ValueError('Controller review files must remain inside the ignored private runtime directory')
    os.umask(0o077)
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    for name, value in data.items():
        file = path / name
        file.write_text(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        file.chmod(0o600)
    return path


def main():
    parser = argparse.ArgumentParser(description='Offline exact-session TTL controller permission review')
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.session.is_symlink() or args.session.stat().st_size > 16384:
            raise ValueError('Invalid session document')
        write_artifacts(json.loads(args.session.read_bytes()), args.output, ttl_bundle=args.session.parent.resolve())
    except (ValueError, TypeError, OSError):
        print('컨트롤러 권한 자료 생성 실패: 세션·비공개 출력 경로를 확인하세요.')
        return 1
    print('검토용 컨트롤러 권한 자료 생성 완료. AWS 호출·권한 변경은 수행하지 않았습니다.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
