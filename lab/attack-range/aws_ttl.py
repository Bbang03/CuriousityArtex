#!/usr/bin/env python3
"""Generate reviewable TTL IAM documents/Lambda bundle. Never calls AWS.

EC2 resource/tag conditions verified against AWS Service Authorization:
https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import uuid
import zipfile
from datetime import datetime, timezone

CLEANUP = Path(__file__).with_name('aws_cleanup.py')
SPEC = importlib.util.spec_from_file_location('aegis_cleanup', CLEANUP)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def event(session, mode='cleanup'):
    return {key: session[key] for key in ('session_id', 'account_id', 'region')} | {'mode': mode}


def documents(session):
    runtime.validate_session(session)
    identifier, account, region = (session[key] for key in ('session_id', 'account_id', 'region'))
    name = 'aegisloop-ttl-' + identifier
    lambda_arn = f'arn:aws:lambda:{region}:{account}:function:{name}'
    lambda_role = f'arn:aws:iam::{account}:role/{name}-cleanup'
    scheduler_role = f'arn:aws:iam::{account}:role/{name}-scheduler'
    group_arn = f'arn:aws:scheduler:{region}:{account}:schedule-group/{name}'
    conditions = {'StringEquals': {'ec2:ResourceTag/' + runtime.OWNER_TAG: identifier,
                                    'ec2:ResourceTag/' + runtime.EXPIRY_TAG: session['expires_at'],
                                    'aws:RequestedRegion': region},
                  'DateGreaterThanEquals': {'aws:CurrentTime': session['expires_at']}}
    statements = [{'Sid': 'RegionalInventory', 'Effect': 'Allow',
                   'Action': ['ec2:DescribeInstances', 'ec2:DescribeNatGateways', 'ec2:DescribeAddresses',
                              'ec2:DescribeVolumes', 'ec2:DescribeKeyPairs'],
                   'Resource': '*', 'Condition': {'StringEquals': {'aws:RequestedRegion': region}}}]
    for action, resource in (('TerminateInstances', 'instance'), ('DeleteNatGateway', 'natgateway'),
                             ('ReleaseAddress', 'elastic-ip'), ('DeleteVolume', 'volume'), ('DeleteKeyPair', 'key-pair')):
        condition = json.loads(json.dumps(conditions))
        if action == 'DeleteKeyPair':
            condition['StringEquals']['ec2:KeyPairName'] = identifier
        statements.append({'Effect': 'Allow', 'Action': 'ec2:' + action,
                           'Resource': f'arn:aws:ec2:{region}:{account}:{resource}/*', 'Condition': condition})
    bucket_arn = 'arn:aws:s3:::terraform-state-' + identifier
    statements.extend([
        {'Effect': 'Allow', 'Action': ['s3:ListBucket', 's3:ListBucketVersions'], 'Resource': bucket_arn,
         'Condition': {'StringEquals': {'s3:ResourceAccount': account}}},
        {'Effect': 'Allow', 'Action': 's3:DeleteBucket', 'Resource': bucket_arn,
         'Condition': {'StringEquals': {'s3:ResourceAccount': account},
                       'DateGreaterThanEquals': {'aws:CurrentTime': session['expires_at']}}},
        {'Effect': 'Allow', 'Action': ['s3:DeleteObject', 's3:DeleteObjectVersion'], 'Resource': bucket_arn + '/*',
         'Condition': {'StringEquals': {'s3:ResourceAccount': account},
                       'DateGreaterThanEquals': {'aws:CurrentTime': session['expires_at']}}},
        {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
         'Resource': f'arn:aws:logs:{region}:{account}:log-group:/aws/lambda/{name}:*'},
    ])
    policy = lambda statement: {'Version': '2012-10-17', 'Statement': statement}
    return {
        'session.json': session,
        'lambda-trust.json': policy([{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]),
        'lambda-policy.json': policy(statements),
        'scheduler-trust.json': policy([{'Effect': 'Allow', 'Principal': {'Service': 'scheduler.amazonaws.com'},
                                        'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {'aws:SourceAccount': account},
                                        'ArnEquals': {'aws:SourceArn': group_arn}}}]),
        'scheduler-policy.json': policy([{'Effect': 'Allow', 'Action': 'lambda:InvokeFunction', 'Resource': lambda_arn}]),
        'scheduler-pass-role.json': policy([{'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': scheduler_role,
                                            'Condition': {'StringEquals': {'iam:PassedToService': 'scheduler.amazonaws.com'}}}]),
        'lambda-create.json': {'FunctionName': name, 'Runtime': 'python3.12', 'Role': lambda_role,
                               'Handler': 'aws_cleanup.handler', 'Timeout': 300, 'MemorySize': 128,
                               'Description': 'Expiry cleanup for one AegisLoop practice session',
                               'Tags': {runtime.OWNER_TAG: identifier, runtime.EXPIRY_TAG: session['expires_at']}},
        'schedule-create.json': {'Name': 'expiry', 'GroupName': name, 'ScheduleExpression': 'rate(5 minutes)',
                                 'StartDate': session['expires_at'], 'FlexibleTimeWindow': {'Mode': 'OFF'}, 'State': 'ENABLED',
                                 'Target': {'Arn': lambda_arn, 'RoleArn': scheduler_role,
                                            'Input': json.dumps(event(session), separators=(',', ':')),
                                            'RetryPolicy': {'MaximumEventAgeInSeconds': 3600, 'MaximumRetryAttempts': 10}}},
        'inspect-event.json': event(session, 'inspect'),
        'required-resource-tags.json': {runtime.OWNER_TAG: identifier, runtime.EXPIRY_TAG: session['expires_at']},
        'review.json': {'session_id': identifier, 'lambda_function': name, 'lambda_role_arn': lambda_role,
                        'scheduler_role_arn': scheduler_role, 'schedule_group': name,
                        'log_group': '/aws/lambda/' + name, 'log_retention_days': 1,
                        'needs_separate_iam_review': True, 'cloud_resources_created': False,
                        'limits': ['Only tagged paid resources are covered; missing ownership tags prevent cleanup.',
                                   'Unpaid VPC resources require normal Terraform destroy later.',
                                   'Keep a private Terraform state backup before TTL removes the remote state bucket.',
                                   'Stopping resource creation at expiry is also required.',
                                   'Logs/schedule/roles remain until explicit controller cleanup.',
                                   'A 10 USD budget is not a hard billing cap.']},
    }


def write_artifacts(session, destination):
    data = documents(session)
    destination = Path(destination)
    if destination.is_symlink() or destination.exists():
        raise ValueError('Use a new private output directory; existing review files are not replaced')
    os.umask(0o077)
    destination.mkdir(parents=True, mode=0o700)
    for name, value in data.items():
        path = destination / name
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        path.chmod(0o600)
    archive = destination / 'lambda.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as output:
        output.write(CLEANUP, 'aws_cleanup.py')
        output.write(destination / 'session.json', 'session.json')
    archive.chmod(0o600)
    return destination


def main():
    parser = argparse.ArgumentParser(description='AWS TTL review bundle generator; no cloud calls')
    parser.add_argument('--account-id', required=True)
    parser.add_argument('--region', required=True)
    parser.add_argument('--expires-at', required=True)
    parser.add_argument('--session-id', default=None)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    session = {'schema_version': 1, 'account_id': args.account_id, 'region': args.region,
               'session_id': args.session_id or str(uuid.uuid4()),
               'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
               'expires_at': args.expires_at}
    try:
        write_artifacts(session, args.output)
    except (ValueError, TypeError, OSError):
        print('TTL 자료 생성 실패: 세션·기한·출력 폴더를 확인하세요.')
        return 1
    print('검토용 IAM·Lambda·예약 자료 생성 완료. AWS 호출·권한 부여·자원 생성은 수행하지 않았습니다.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
