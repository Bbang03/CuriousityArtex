"""Expiry cleanup Lambda for one fixed, tagged Attack Range session.

Deploy with a reviewed session.json and session-scoped IAM policy. This module
does not discover credentials or call AWS when imported. boto3 is imported only
inside the handler after the event and Lambda account/region guard passes.
"""
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

OWNER_TAG = 'AegisLoopSession'
EXPIRY_TAG = 'AegisLoopExpiresAt'
MAX_RESOURCES = 200
MAX_S3_PASSES = 50


def instant(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timezone is required')
    return parsed.astimezone(timezone.utc)


def validate_session(value):
    required = {'schema_version', 'session_id', 'account_id', 'region', 'created_at', 'expires_at'}
    if not isinstance(value, dict) or set(value) != required or value['schema_version'] != 1:
        raise ValueError('Invalid session schema')
    if not isinstance(value['session_id'], str) or str(uuid.UUID(value['session_id'])) != value['session_id']:
        raise ValueError('Session UUID must be canonical')
    if not re.fullmatch(r'[0-9]{12}', value['account_id']) or not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]', value['region']):
        raise ValueError('Invalid AWS account or region')
    start, end = instant(value['created_at']), instant(value['expires_at'])
    if not 0 < (end - start).total_seconds() <= 4 * 3600:
        raise ValueError('Session must expire within four hours')
    if end.isoformat().replace('+00:00', 'Z') != value['expires_at']:
        raise ValueError('Expiry must be canonical UTC ISO 8601')
    return value


def owned(resource, session):
    tags = {t.get('Key'): t.get('Value') for t in resource.get('Tags', []) if isinstance(t, dict)}
    return tags.get(OWNER_TAG) == session['session_id'] and tags.get(EXPIRY_TAG) == session['expires_at']


def error_code(exc):
    response = getattr(exc, 'response', {})
    code = response.get('Error', {}).get('Code', 'OperationFailed')
    return code if isinstance(code, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', code) else 'OperationFailed'


def guard(session, event, context_arn, now):
    validate_session(session)
    expected = f"arn:aws:lambda:{session['region']}:{session['account_id']}:function:aegisloop-ttl-{session['session_id']}"
    if context_arn not in (expected, expected + ':$LATEST'):
        return 'wrong_runtime'
    if not isinstance(event, dict) or set(event) != {'session_id', 'account_id', 'region', 'mode'}:
        return 'wrong_event'
    if any(event[key] != session[key] for key in ('session_id', 'account_id', 'region')):
        return 'wrong_session'
    if event['mode'] not in ('cleanup', 'inspect'):
        return 'wrong_mode'
    if now < instant(session['expires_at']).timestamp() and event['mode'] == 'cleanup':
        return 'not_expired'
    return None


def cleanup(session, event, context_arn, *, ec2, s3, sts, now=None, remaining_ms=None):
    """One bounded pass. A later pass confirms asynchronous resource deletion.

    inspect performs reads only. Neither a requested deletion nor a previous
    successful invocation is presented as proof of complete cleanup.
    """
    now = time.time() if now is None else now
    reason = guard(session, event, context_arn, now)
    report = {'session_id': session['session_id'], 'scope': 'fixed_session_tagged_resources',
              'status': 'refused' if reason else 'inspecting',
              'reason': reason, 'observed': {}, 'requested': {}, 'errors': [], 'pending': []}
    if reason:
        return report
    mutate = event['mode'] == 'cleanup'
    deadline = time.monotonic() + 260

    def enough():
        return time.monotonic() < deadline and (remaining_ms is None or remaining_ms() > 10000)

    def issue(stage, code):
        report['errors'].append({'stage': stage, 'code': code})

    def request(stage, operation, **kwargs):
        if not enough():
            issue(stage, 'TimeBudgetExhausted')
            return None
        try:
            return operation(**kwargs)
        except Exception as exc:
            issue(stage, error_code(exc))
            return None

    identity = request('identity', sts.get_caller_identity)
    if identity is None or identity.get('Account') != session['account_id']:
        report.update(status='refused', reason='wrong_aws_account')
        return report
    # Filters reduce reads, but every returned item is checked again locally.
    filters = [{'Name': 'tag:' + OWNER_TAG, 'Values': [session['session_id']]},
               {'Name': 'tag:' + EXPIRY_TAG, 'Values': [session['expires_at']]}]

    def resources(stage, operation, list_key, nested=None, filter_arg='Filters'):
        items, token = [], None
        while enough():
            args = {filter_arg: filters}
            if token:
                args['NextToken'] = token
            page = request(stage, operation, **args)
            if page is None:
                return items
            rows = page.get(list_key, [])
            if nested:
                rows = [entry for row in rows for entry in row.get(nested, [])]
            for row in rows:
                if owned(row, session):
                    items.append(row)
                    if len(items) > MAX_RESOURCES:
                        issue(stage, 'ResourceLimitExceeded')
                        return []
            token = page.get('NextToken')
            if not token:
                return items
        issue(stage, 'TimeBudgetExhausted')
        return items

    instances = resources('instances', ec2.describe_instances, 'Reservations', 'Instances')
    active = [i for i in instances if i.get('State', {}).get('Name') != 'terminated']
    report['observed']['instances'] = len(active)
    for instance in active:
        if mutate and instance.get('State', {}).get('Name') != 'shutting-down':
            response = request('terminate', ec2.terminate_instances, InstanceIds=[instance['InstanceId']])
            if response is not None:
                report['requested']['instances'] = report['requested'].get('instances', 0) + 1
    nats = resources('nat_gateways', ec2.describe_nat_gateways, 'NatGateways', filter_arg='Filter')
    active_nats = [n for n in nats if n.get('State') != 'deleted']
    report['observed']['nat_gateways'] = len(active_nats)
    for nat in active_nats:
        if mutate and nat.get('State') != 'deleting':
            if request('delete_nat', ec2.delete_nat_gateway, NatGatewayId=nat['NatGatewayId']) is not None:
                report['requested']['nat_gateways'] = report['requested'].get('nat_gateways', 0) + 1
    addresses = resources('elastic_ips', ec2.describe_addresses, 'Addresses')
    report['observed']['elastic_ips'] = len(addresses)
    for address in addresses:
        if address.get('AssociationId'):
            report['pending'].append('associated_elastic_ip')
        elif mutate and request('release_eip', ec2.release_address, AllocationId=address['AllocationId']) is not None:
            report['requested']['elastic_ips'] = report['requested'].get('elastic_ips', 0) + 1
    volumes = resources('volumes', ec2.describe_volumes, 'Volumes')
    report['observed']['volumes'] = len(volumes)
    for volume in volumes:
        if volume.get('State') != 'available' or volume.get('Attachments'):
            report['pending'].append('attached_or_pending_volume')
        elif mutate and request('delete_volume', ec2.delete_volume, VolumeId=volume['VolumeId']) is not None:
            report['requested']['volumes'] = report['requested'].get('volumes', 0) + 1
    keys = resources('key_pairs', ec2.describe_key_pairs, 'KeyPairs')
    keys = [key for key in keys if key.get('KeyName') == session['session_id']]
    report['observed']['key_pairs'] = len(keys)
    # Retain recovery keys and Terraform state while paid resources still exist
    # or any inventory operation failed. A later five-minute pass will proceed.
    infrastructure_remaining = sum(report['observed'][key] for key in ('instances', 'nat_gateways', 'elastic_ips', 'volumes'))
    if mutate and not infrastructure_remaining and not report['errors']:
        for key in keys:
            if request('delete_key', ec2.delete_key_pair, KeyPairId=key['KeyPairId']) is not None:
                report['requested']['key_pairs'] = report['requested'].get('key_pairs', 0) + 1
    bucket = 'terraform-state-' + session['session_id']
    bucket_args = {'Bucket': bucket, 'ExpectedBucketOwner': session['account_id']}
    try:
        if not enough():
            raise TimeoutError()
        s3.head_bucket(**bucket_args)
        report['observed']['state_bucket'] = 1
    except Exception as exc:
        code = error_code(exc)
        report['observed']['state_bucket'] = 0 if code in ('404', 'NoSuchBucket', 'NotFound') else None
        if report['observed']['state_bucket'] is None:
            issue('state_bucket', code)
    if mutate and report['observed']['state_bucket'] == 1 and not infrastructure_remaining and not report['errors']:
        empty = False
        for _ in range(MAX_S3_PASSES):
            page = request('state_versions', s3.list_object_versions, **bucket_args, MaxKeys=1000)
            if page is None:
                break
            entries = [{'Key': entry['Key'], 'VersionId': entry['VersionId']}
                       for kind in ('Versions', 'DeleteMarkers') for entry in page.get(kind, [])]
            if not entries:
                objects = request('state_objects', s3.list_objects_v2, **bucket_args, MaxKeys=1000)
                if objects is None:
                    break
                entries = [{'Key': entry['Key']} for entry in objects.get('Contents', [])]
            if not entries:
                empty = True
                break
            response = request('delete_state_objects', s3.delete_objects, **bucket_args,
                               Delete={'Objects': entries, 'Quiet': True})
            if response is None:
                break
            if response.get('Errors'):
                issue('delete_state_objects', 'PartialDeleteFailure')
                break
            report['requested']['state_objects'] = report['requested'].get('state_objects', 0) + len(entries)
        if empty:
            if request('delete_state_bucket', s3.delete_bucket, **bucket_args) is not None:
                report['requested']['state_bucket'] = 1
        elif not report['errors']:
            report['pending'].append('state_bucket_pass_limit')
    report['status'] = (('inspect_incomplete' if report['errors'] or report['pending'] else 'inspect_complete') if not mutate else
                        'retry_required' if report['errors'] or report['pending'] or any(report['observed'].values()) else
                        'owned_paid_resources_absent')
    return report


def handler(event, context):
    session = validate_session(json.loads(Path(__file__).with_name('session.json').read_text()))
    arn = getattr(context, 'invoked_function_arn', '')
    reason = guard(session, event, arn, time.time())
    if reason:
        report = {'session_id': session['session_id'], 'status': 'refused', 'reason': reason}
        print(json.dumps(report, separators=(',', ':')))
        return report
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 2, 'mode': 'standard'})
    clients = {name: boto3.client(name, region_name=session['region'], config=config) for name in ('ec2', 's3', 'sts')}
    report = cleanup(session, event, arn, **clients, remaining_ms=context.get_remaining_time_in_millis)
    # Scheduler invokes Lambda asynchronously and discards its return payload.
    # Persist only our bounded aggregate report, never SDK response bodies.
    print(json.dumps(report, separators=(',', ':')))
    return report
