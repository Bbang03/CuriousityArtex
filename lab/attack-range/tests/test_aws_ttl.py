import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

FOLDER = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, FOLDER / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cleanup = load('aws_cleanup')
ttl = load('aws_ttl')
SESSION = {'schema_version': 1, 'session_id': '11111111-2222-4333-8444-555555555555',
           'account_id': '123456789012', 'region': 'ap-northeast-2',
           'created_at': '2026-10-10T00:00:00Z', 'expires_at': '2026-10-10T04:00:00Z'}
NOW = cleanup.instant('2026-10-10T04:05:00Z').timestamp()
ARN = f"arn:aws:lambda:{SESSION['region']}:{SESSION['account_id']}:function:aegisloop-ttl-{SESSION['session_id']}"


def tags(session=SESSION):
    return [{'Key': cleanup.OWNER_TAG, 'Value': session['session_id']},
            {'Key': cleanup.EXPIRY_TAG, 'Value': session['expires_at']}]


class Failure(Exception):
    def __init__(self, code='AccessDenied'):
        self.response = {'Error': {'Code': code, 'Message': 'private-details-must-not-be-returned'}}


class FakeSTS:
    def __init__(self, account=SESSION['account_id']):
        self.account = account
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        return {'Account': self.account}


class FakeEC2:
    def __init__(self):
        self.instances, self.nats, self.addresses, self.volumes, self.keys = [], [], [], [], []
        self.calls, self.reads = [], []
        self.fail = None
        self.instance_pages = None

    def _read(self, operation, kwargs):
        self.reads.append((operation, kwargs))
        filter_key = 'Filter' if operation == 'nats' else 'Filters'
        if filter_key not in kwargs:
            raise Failure('IncorrectFilterParameter')

    def describe_instances(self, **kwargs):
        self._read('instances', kwargs)
        if self.instance_pages is not None:
            return self.instance_pages.pop(0)
        return {'Reservations': [{'Instances': self.instances}]}

    def describe_nat_gateways(self, **kwargs):
        self._read('nats', kwargs)
        return {'NatGateways': self.nats}

    def describe_addresses(self, **kwargs):
        self._read('addresses', kwargs)
        return {'Addresses': self.addresses}

    def describe_volumes(self, **kwargs):
        self._read('volumes', kwargs)
        return {'Volumes': self.volumes}

    def describe_key_pairs(self, **kwargs):
        self._read('keys', kwargs)
        return {'KeyPairs': self.keys}

    def _change(self, action, values):
        self.calls.append((action, values))
        if action == self.fail:
            raise Failure()
        return {}

    def terminate_instances(self, **kwargs): return self._change('terminate', kwargs)
    def delete_nat_gateway(self, **kwargs): return self._change('delete_nat', kwargs)
    def release_address(self, **kwargs): return self._change('release_eip', kwargs)
    def delete_volume(self, **kwargs): return self._change('delete_volume', kwargs)
    def delete_key_pair(self, **kwargs): return self._change('delete_key', kwargs)


class FakeS3:
    def __init__(self, present=False):
        self.present = present
        self.calls, self.reads = [], []
        self.versions, self.markers, self.objects = [], [], []
        self.partial_failure = False

    def _owner(self, args):
        if args.get('ExpectedBucketOwner') != SESSION['account_id'] or args.get('Bucket') != 'terraform-state-' + SESSION['session_id']:
            raise Failure('UnsafeBucketScope')

    def head_bucket(self, **kwargs):
        self._owner(kwargs)
        self.reads.append('head')
        if not self.present:
            raise Failure('404')
        return {}

    def list_object_versions(self, **kwargs):
        self._owner(kwargs)
        self.reads.append('versions')
        return {'Versions': self.versions, 'DeleteMarkers': self.markers}

    def list_objects_v2(self, **kwargs):
        self._owner(kwargs)
        self.reads.append('objects')
        return {'Contents': self.objects}

    def delete_objects(self, **kwargs):
        self._owner(kwargs)
        self.calls.append(('objects', kwargs))
        if self.partial_failure:
            return {'Errors': [{'Code': 'AccessDenied', 'Message': 'private-error'}]}
        self.versions, self.markers, self.objects = [], [], []
        return {}

    def delete_bucket(self, **kwargs):
        self._owner(kwargs)
        self.calls.append(('bucket', kwargs))
        self.present = False
        return {}


class CleanupTests(unittest.TestCase):
    def run_cleanup(self, ec2=None, s3=None, sts=None, event=None, arn=ARN, now=NOW, **kwargs):
        return cleanup.cleanup(SESSION, event or ttl.event(SESSION), arn, ec2=ec2 or FakeEC2(),
                               s3=s3 or FakeS3(), sts=sts or FakeSTS(), now=now, **kwargs)

    def test_wrong_event_runtime_and_unexpired_session_do_not_call_aws(self):
        cases = [(ttl.event(SESSION) | {'account_id': '000000000000'}, ARN, NOW),
                 (ttl.event(SESSION) | {'session_id': '00000000-0000-4000-8000-000000000000'}, ARN, NOW),
                 (ttl.event(SESSION), ARN.replace('ap-northeast-2', 'us-east-1'), NOW),
                 (ttl.event(SESSION), ARN, NOW - 3600),
                 (ttl.event(SESSION) | {'force': True}, ARN, NOW)]
        for event, arn, now in cases:
            ec2, s3, sts = FakeEC2(), FakeS3(True), FakeSTS()
            report = self.run_cleanup(ec2, s3, sts, event, arn, now)
            self.assertEqual(report['status'], 'refused')
            self.assertFalse(ec2.reads or ec2.calls or s3.reads or s3.calls or sts.calls)

    def test_aws_account_mismatch_stops_before_resource_inventory(self):
        ec2, s3 = FakeEC2(), FakeS3(True)
        report = self.run_cleanup(ec2, s3, FakeSTS('999999999999'))
        self.assertEqual(report['reason'], 'wrong_aws_account')
        self.assertFalse(ec2.reads or ec2.calls or s3.reads or s3.calls)

    def test_owned_resources_only_and_async_nat_is_retried_in_future_pass(self):
        ec2, s3 = FakeEC2(), FakeS3(True)
        ec2.instances = [{'InstanceId': 'i-owned', 'State': {'Name': 'running'}, 'Tags': tags()},
                         {'InstanceId': 'i-foreign', 'State': {'Name': 'running'}, 'Tags': []}]
        ec2.nats = [{'NatGatewayId': 'nat-owned', 'State': 'available', 'Tags': tags()},
                    {'NatGatewayId': 'nat-foreign', 'State': 'available', 'Tags': []}]
        ec2.addresses = [{'AllocationId': 'eipalloc-owned', 'AssociationId': 'eipassoc-pending', 'Tags': tags()},
                         {'AllocationId': 'eipalloc-foreign', 'Tags': []}]
        ec2.volumes = [{'VolumeId': 'vol-owned', 'State': 'in-use', 'Attachments': [{}], 'Tags': tags()},
                       {'VolumeId': 'vol-foreign', 'State': 'available', 'Tags': []}]
        report = self.run_cleanup(ec2, s3)
        self.assertEqual(ec2.calls, [('terminate', {'InstanceIds': ['i-owned']}), ('delete_nat', {'NatGatewayId': 'nat-owned'})])
        self.assertEqual(report['status'], 'retry_required')
        self.assertFalse(s3.calls)  # Terraform recovery state retained.
        ec2.calls = []
        ec2.instances[0]['State']['Name'] = 'terminated'
        ec2.nats[0]['State'] = 'deleting'
        self.run_cleanup(ec2, s3)
        self.assertFalse(ec2.calls)
        ec2.nats[0]['State'] = 'deleted'
        del ec2.addresses[0]['AssociationId']
        ec2.volumes[0].update(State='available', Attachments=[])
        self.run_cleanup(ec2, s3)
        self.assertEqual(ec2.calls, [('release_eip', {'AllocationId': 'eipalloc-owned'}), ('delete_volume', {'VolumeId': 'vol-owned'})])
        self.assertFalse(s3.calls)

    def test_partial_ec2_failure_does_not_hide_errors_or_delete_recovery_state(self):
        ec2, s3 = FakeEC2(), FakeS3(True)
        ec2.instances = [{'InstanceId': 'i-own', 'State': {'Name': 'running'}, 'Tags': tags()}]
        ec2.fail = 'terminate'
        report = self.run_cleanup(ec2, s3)
        self.assertEqual(report['errors'], [{'stage': 'terminate', 'code': 'AccessDenied'}])
        self.assertNotIn('private-details', json.dumps(report))
        self.assertFalse(s3.calls)

    def test_inspect_cannot_mutate_even_after_expiry(self):
        ec2, s3 = FakeEC2(), FakeS3(True)
        ec2.instances = [{'InstanceId': 'i-own', 'State': {'Name': 'running'}, 'Tags': tags()}]
        report = self.run_cleanup(ec2, s3, event=ttl.event(SESSION, 'inspect'))
        self.assertEqual(report['observed']['instances'], 1)
        self.assertEqual(report['status'], 'inspect_complete')
        self.assertFalse(ec2.calls or s3.calls)

    def test_failed_inventory_cannot_claim_inspect_completion(self):
        ec2, s3 = FakeEC2(), FakeS3()
        with patch.object(ec2, 'describe_instances', side_effect=Failure()):
            report = self.run_cleanup(ec2, s3, event=ttl.event(SESSION, 'inspect'))
        self.assertEqual(report['status'], 'inspect_incomplete')
        self.assertTrue(report['errors'])
        self.assertFalse(ec2.calls or s3.calls or report['requested'])
        self.assertNotIn('private-details', json.dumps(report))

    def test_versioned_bucket_cleanup_checks_partial_errors_and_confirms_on_next_pass(self):
        s3 = FakeS3(True)
        s3.versions = [{'Key': 'terraform.tfstate', 'VersionId': 'v1'}]
        s3.markers = [{'Key': 'terraform.tfstate', 'VersionId': 'marker'}]
        s3.partial_failure = True
        first = self.run_cleanup(s3=s3)
        self.assertEqual(first['errors'], [{'stage': 'delete_state_objects', 'code': 'PartialDeleteFailure'}])
        self.assertNotIn('bucket', [call[0] for call in s3.calls])
        s3.partial_failure = False
        second = self.run_cleanup(s3=s3)
        self.assertEqual(second['requested']['state_objects'], 2)
        self.assertEqual(second['status'], 'retry_required')
        third = self.run_cleanup(s3=s3)
        self.assertEqual(third['status'], 'owned_paid_resources_absent')
        self.assertTrue(all(values['ExpectedBucketOwner'] == SESSION['account_id'] for _, values in s3.calls))

    def test_ssh_key_requires_both_ownership_tags_and_exact_uuid_name(self):
        ec2 = FakeEC2()
        ec2.keys = [{'KeyName': SESSION['session_id'], 'KeyPairId': 'key-own', 'Tags': tags()},
                    {'KeyName': 'foreign', 'KeyPairId': 'key-foreign', 'Tags': tags()},
                    {'KeyName': SESSION['session_id'], 'KeyPairId': 'key-untagged', 'Tags': []}]
        self.run_cleanup(ec2)
        self.assertEqual(ec2.calls, [('delete_key', {'KeyPairId': 'key-own'})])

    def test_inventory_pagination_filters_and_bounds_are_applied(self):
        ec2 = FakeEC2()
        ec2.instance_pages = [{'Reservations': [{'Instances': [{'InstanceId': 'i-first', 'State': {'Name': 'running'}, 'Tags': tags()}]}], 'NextToken': 'next'},
                              {'Reservations': [{'Instances': [{'InstanceId': 'i-second', 'State': {'Name': 'terminated'}, 'Tags': tags()}]}]}]
        report = self.run_cleanup(ec2)
        self.assertEqual(report['observed']['instances'], 1)
        self.assertEqual(ec2.reads[1][1]['NextToken'], 'next')
        self.assertTrue(all(filters[0]['Values'] == [SESSION['session_id']] for _, params in ec2.reads for filters in [params.get('Filters', params.get('Filter'))]))

    def test_time_budget_exhaustion_prevents_mutation(self):
        ec2, s3 = FakeEC2(), FakeS3(True)
        report = self.run_cleanup(ec2, s3, remaining_ms=lambda: 5000)
        self.assertEqual(report['errors'][0]['code'], 'TimeBudgetExhausted')
        self.assertFalse(ec2.calls or s3.calls or ec2.reads or s3.reads)

    def test_resource_limit_refuses_bulk_delete_and_retains_recovery_state(self):
        ec2, s3 = FakeEC2(), FakeS3(True)
        ec2.instances = [{'InstanceId': f'i-{number}', 'State': {'Name': 'running'}, 'Tags': tags()}
                         for number in range(cleanup.MAX_RESOURCES + 1)]
        report = self.run_cleanup(ec2, s3)
        self.assertIn({'stage': 'instances', 'code': 'ResourceLimitExceeded'}, report['errors'])
        self.assertFalse(ec2.calls or s3.calls)

    def test_owner_uuid_without_fixed_expiry_tag_is_not_sufficient_to_delete(self):
        ec2 = FakeEC2()
        ec2.instances = [{'InstanceId': 'i-wrong-expiry', 'State': {'Name': 'running'},
                          'Tags': [{'Key': cleanup.OWNER_TAG, 'Value': SESSION['session_id']},
                                   {'Key': cleanup.EXPIRY_TAG, 'Value': '2026-10-11T04:00:00Z'}]}]
        self.run_cleanup(ec2)
        self.assertFalse(ec2.calls)

    def test_handler_logs_guard_report_without_sdk_import_or_private_event_fields(self):
        class Context:
            invoked_function_arn = ARN

        with patch.object(cleanup.Path, 'read_text', return_value=json.dumps(SESSION)), patch.object(cleanup.time, 'time', return_value=NOW), patch('builtins.print') as output:
            report = cleanup.handler(ttl.event(SESSION) | {'private': 'do-not-log'}, Context())
        self.assertEqual(report['reason'], 'wrong_event')
        self.assertEqual(json.loads(output.call_args.args[0]), report)
        self.assertNotIn('do-not-log', output.call_args.args[0])


class PolicyTests(unittest.TestCase):
    def test_destructive_ec2_permissions_are_session_tagged_regional_and_expiry_guarded(self):
        docs = ttl.documents(SESSION)
        statements = docs['lambda-policy.json']['Statement']
        destructive = [s for s in statements if isinstance(s['Action'], str) and s['Action'].startswith('ec2:')]
        self.assertEqual(len(destructive), 5)
        for statement in destructive:
            self.assertIn(f":{SESSION['region']}:{SESSION['account_id']}:", statement['Resource'])
            self.assertNotEqual(statement['Resource'], '*')
            conditions = statement['Condition']
            self.assertEqual(conditions['StringEquals']['ec2:ResourceTag/' + cleanup.OWNER_TAG], SESSION['session_id'])
            self.assertEqual(conditions['DateGreaterThanEquals']['aws:CurrentTime'], SESSION['expires_at'])
        key_policy = next(s for s in destructive if s['Action'] == 'ec2:DeleteKeyPair')
        self.assertEqual(key_policy['Condition']['StringEquals']['ec2:KeyPairName'], SESSION['session_id'])
        self.assertNotIn('AdministratorAccess', json.dumps(docs))
        self.assertNotIn('ec2:CreateTags', json.dumps(docs))

    def test_scheduler_only_invokes_exact_lambda_and_passes_one_scheduler_role(self):
        docs = ttl.documents(SESSION)
        invoke = docs['scheduler-policy.json']['Statement'][0]
        self.assertEqual(invoke['Action'], 'lambda:InvokeFunction')
        self.assertEqual(invoke['Resource'], ARN)
        passing = docs['scheduler-pass-role.json']['Statement'][0]
        self.assertEqual(passing['Condition']['StringEquals']['iam:PassedToService'], 'scheduler.amazonaws.com')
        self.assertEqual(passing['Resource'], docs['review.json']['scheduler_role_arn'])
        schedule = docs['schedule-create.json']
        self.assertEqual(schedule['ScheduleExpression'], 'rate(5 minutes)')
        self.assertEqual(schedule['StartDate'], SESSION['expires_at'])
        self.assertEqual(json.loads(schedule['Target']['Input']), ttl.event(SESSION))

    def test_s3_permissions_use_exact_bucket_and_resource_account(self):
        statements = ttl.documents(SESSION)['lambda-policy.json']['Statement']
        for statement in statements:
            action = statement['Action']
            if (isinstance(action, list) and action[0].startswith('s3:')) or (isinstance(action, str) and action.startswith('s3:')):
                self.assertTrue(statement['Resource'].startswith('arn:aws:s3:::terraform-state-' + SESSION['session_id']))
                self.assertEqual(statement['Condition']['StringEquals']['s3:ResourceAccount'], SESSION['account_id'])

    def test_bundle_is_private_has_no_credentials_and_existing_files_are_not_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'review'
            ttl.write_artifacts(SESSION, destination)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in destination.iterdir()))
            with zipfile.ZipFile(destination / 'lambda.zip') as archive:
                self.assertEqual(set(archive.namelist()), {'aws_cleanup.py', 'session.json'})
                self.assertEqual(json.loads(archive.read('session.json')), SESSION)
            with self.assertRaises(ValueError):
                ttl.write_artifacts(SESSION, destination)

    def test_session_duration_wrong_account_and_noncanonical_expiry_are_rejected(self):
        for change in ({'expires_at': '2026-10-10T04:00:01Z'}, {'account_id': '*'},
                       {'region': '*'}, {'expires_at': '2026-10-10T04:00:00'},
                       {'expires_at': '2026-10-10T13:00:00+09:00'}, {'session_id': '../other'}):
            with self.assertRaises((ValueError, TypeError)):
                ttl.documents(SESSION | change)


if __name__ == '__main__':
    unittest.main()
