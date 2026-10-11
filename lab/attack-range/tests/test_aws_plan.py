import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'aws_plan.py'
SPEC = importlib.util.spec_from_file_location('aegis_aws_plan', MODULE)
planner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(planner)
NOW = datetime(2026, 10, 10, 14, 0, tzinfo=timezone.utc)
SESSION = '00000000-0000-4000-8000-000000000001'
PIN = {'repository': 'https://github.com/splunk/attack_range.git', 'commit': 'f' * 40,
       'api_image': 'aegis-attack-range-api:' + 'f' * 12}


def template():
    return {
        'general': {'cloud_provider': 'aws', 'attack_range_password': 'changeme123!',
                    'ip_whitelist': '0.0.0.0/0'},
        'aws': {'region': 'eu-central-1', 'aws_default_tags': {}},
        'attack_range': [
            {'name': 'splunk', 'instance_type': 't3.xlarge', 'linux': True, 'ip_last_octet': 10,
             'roles': [{'vars': {'ludus_ar_splunk_password': 'changeme123!'}},
                       {'vars': {'ar_guacamole_password': 'changeme123!',
                                 'servers': [{'password': 'changeme123!'}, {'password': 'changeme123!'}]}}]},
            {'name': 'win', 'instance_type': 't3.large', 'windows': True, 'ip_last_octet': 11,
             'roles': [{'vars': {'ludus_ar_windows_password': 'changeme123!'}}]},
        ],
    }


def preparation(region=planner.REGION, *, lifecycle_mode='automatic', hours=4,
                windows_instance_type='t3.large'):
    return {'range_id': SESSION, 'region': region, 'whitelist': '8.8.8.8/32',
            'prepared_at': planner.utc_text(NOW), 'expires_at': planner.utc_text(NOW + timedelta(hours=hours)),
            'terraform_version': planner.TERRAFORM_VERSION, 'upstream_commit': PIN['commit'],
            'daily_budget_usd': 10, 'windows_instance_type': windows_instance_type,
            **planner.checked_lifecycle(lifecycle_mode, hours)}


def fixture(region=planner.REGION, *, lifecycle_mode='automatic', hours=4,
            windows_instance_type='t3.large'):
    prepared = preparation(region, lifecycle_mode=lifecycle_mode, hours=hours,
                           windows_instance_type=windows_instance_type)
    tags = {planner.TAGS[0]: 'AegisLoop', planner.TAGS[1]: SESSION,
            planner.TAGS[2]: prepared['expires_at']}
    configuration, _ = planner.replace_passwords(template(), 'SyntheticTestPasswordOnly!')
    configuration['aws']['region'] = region
    configuration['attack_range'][1]['instance_type'] = windows_instance_type
    configuration['general'].update({'attack_range_id': SESSION, 'key_name': SESSION,
                                     'ip_whitelist': prepared['whitelist']})
    changes = []

    def add(address, kind, values, unknown=None):
        if kind not in ('aws_route', 'aws_route_table_association'):
            values['tags_all'] = dict(tags)
        changes.append({'mode': 'managed', 'address': address, 'type': kind,
                        'change': {'actions': ['create'], 'after': values,
                                   'after_unknown': unknown or {}}})

    for name, instance, size, public, ip in (
            ('router', 't3.small', 30, True, '10.0.1.10'),
            ('splunk', 't3.xlarge', 60, False, '10.0.2.10'),
            ('win', windows_instance_type, 60, False, '10.0.2.11')):
        address = ('module.router.aws_instance.router' if name == 'router' else
                   'module.attack_range_servers["' + name + '"].aws_instance.this')
        add(address, 'aws_instance', {
            'instance_type': instance, 'private_ip': ip, 'associate_public_ip_address': public,
            'disable_api_termination': False,
            'ami': 'ami-' + ('0' if name != 'win' else '1') * 17,
            'root_block_device': [{'volume_size': size, 'volume_type': 'gp3',
                                   'encrypted': True, 'delete_on_termination': True}],
            'ebs_block_device': [], 'volume_tags': dict(tags),
        }, {'root_block_device': [{'device_name': True, 'kms_key_id': True}]})
        sg_address = address.replace('aws_instance.router', 'aws_security_group.default').replace('aws_instance.this', 'aws_security_group.this')
        rules = [(22, 22, 'tcp', prepared['whitelist']), (51820, 51820, 'udp', prepared['whitelist'])] if public else [(0, 0, '-1', planner.VPC_CIDR)]
        add(sg_address, 'aws_security_group', {
            'ingress': [{'from_port': start, 'to_port': end, 'protocol': protocol,
                         'cidr_blocks': [cidr], 'ipv6_cidr_blocks': [], 'security_groups': [],
                         'prefix_list_ids': [], 'self': False} for start, end, protocol, cidr in rules],
        })
    prefix = 'module.networkModule.module.vpc.'
    for resource, values in (
            ('aws_vpc.this[0]', {'cidr_block': planner.VPC_CIDR}),
            ('aws_subnet.public[0]', {'cidr_block': '10.0.1.0/24', 'map_public_ip_on_launch': False}),
            ('aws_subnet.private[0]', {'cidr_block': '10.0.2.0/24', 'map_public_ip_on_launch': False}),
            ('aws_internet_gateway.this[0]', {}), ('aws_eip.nat[0]', {'domain': 'vpc'}),
            ('aws_nat_gateway.this[0]', {'connectivity_type': 'public'}),
            ('aws_route_table.public[0]', {}), ('aws_route_table.private[0]', {}),
            ('aws_route.public_internet_gateway[0]', {'destination_cidr_block': '0.0.0.0/0'}),
            ('aws_route.private_nat_gateway[0]', {'destination_cidr_block': '0.0.0.0/0'}),
            ('aws_route_table_association.public[0]', {}), ('aws_route_table_association.private[0]', {}),
            ('aws_default_network_acl.this[0]', {}), ('aws_default_route_table.default[0]', {}),
            ('aws_default_security_group.this[0]', {'ingress': []})):
        add(prefix + resource, resource.split('.')[0], values)
    for name in ('0', '1'):
        changes.append({'mode': 'data', 'type': 'aws_ami', 'change': {'after': {
            'id': 'ami-' + name * 17, 'root_device_name': '/dev/sda1',
            'block_device_mappings': [{'device_name': '/dev/sda1', 'ebs': {'snapshot_id': 'snap-synthetic'}}],
        }}})
    return {'format_version': '1.2', 'terraform_version': planner.TERRAFORM_VERSION,
            'complete': True, 'errored': False, 'variables': {key: {'value': configuration[key]}
                                                             for key in ('general', 'aws', 'attack_range')},
            'resource_changes': changes}, prepared


def selected(plan, kind, index=0):
    return [item for item in plan['resource_changes'] if item['type'] == kind][index]


class PlanChecks(unittest.TestCase):
    def setUp(self):
        self.plan, self.prepared = fixture()

    def review(self):
        return planner.validate_plan(self.plan, self.prepared, now=NOW + timedelta(minutes=1))

    def test_expected_plan_passes_without_claiming_cloud_or_ttl_completion(self):
        report = self.review()
        self.assertEqual(report['resource_counts']['aws_instance'], 3)
        self.assertEqual(report['root_storage_gib'], 150)
        self.assertFalse(report['ttl_scheduler_verified'])
        self.assertFalse(report['cloud_resources_provisioned_by_this_check'])
        self.assertFalse(report['cost_cap_guaranteed'])
        self.assertNotIn('SyntheticTestPasswordOnly', json.dumps(report))
        self.assertEqual(report['lifecycle_mode'], 'automatic')
        self.assertEqual(report['planned_session_hours'], 4)
        self.assertTrue(report['automatic_cleanup_required'])
        self.assertFalse(report['manual_cleanup_required'])

    def test_manual_week_remains_valid_without_claiming_scheduled_shutdown(self):
        plan, prepared = fixture('ap-northeast-2', lifecycle_mode='manual', hours=168,
                                 windows_instance_type='t3.medium')
        report = planner.validate_plan(plan, prepared, now=NOW + timedelta(days=6))
        self.assertEqual(report['planned_session_hours'], 168)
        self.assertEqual(report['lifecycle_mode'], 'manual')
        self.assertEqual(report['cleanup_responsibility'], 'user')
        self.assertEqual(report['planned_end_semantics'], 'manual_cleanup_target')
        self.assertTrue(report['manual_cleanup_required'])
        self.assertFalse(report['automatic_cleanup_required'])
        self.assertFalse(report['ttl_scheduler_verified'])
        self.assertFalse(report['cost_cap_guaranteed'])
        self.assertEqual(report['daily_budget_usd'], 10)
        self.assertEqual(report['windows_instance_type'], 't3.medium')
        self.assertEqual(report['root_storage_gib'], 150)
        self.assertEqual(report['resource_counts']['aws_instance'], 3)
        self.assertTrue(any('종료 예약이 아니며' in warning for warning in report['warnings']))
        with self.assertRaises(planner.PlanError):
            planner.validate_plan(plan, prepared, now=NOW + timedelta(hours=168))

    def test_manual_lifecycle_needs_explicit_user_cleanup_and_matching_duration(self):
        plan, prepared = fixture(lifecycle_mode='manual', hours=168)
        for field, value in (('lifecycle_mode', 'automatic'), ('planned_session_hours', 4),
                             ('manual_cleanup_required', False), ('automatic_cleanup_required', True),
                             ('cleanup_responsibility', 'operator_verified_scheduler'),
                             ('planned_end_semantics', 'verified_scheduler_target')):
            bad = prepared | {field: value}
            with self.subTest(field=field), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, bad, now=NOW)
        for field in ('manual_cleanup_required', 'automatic_cleanup_required',
                      'cleanup_responsibility', 'planned_end_semantics'):
            bad = dict(prepared)
            bad.pop(field)
            with self.subTest(missing_field=field), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, bad, now=NOW)

    def test_selected_windows_type_must_match_variables_and_actual_instance(self):
        plan, prepared = fixture(lifecycle_mode='manual', hours=168, windows_instance_type='t3.medium')
        for expected_type in ('t3.large', 't3.micro', 'm5.large'):
            for location in ('variable', 'instance'):
                bad = copy.deepcopy(plan)
                if location == 'variable':
                    bad['variables']['attack_range']['value'][1]['instance_type'] = expected_type
                else:
                    selected(bad, 'aws_instance', 2)['change']['after']['instance_type'] = expected_type
                with self.subTest(instance_type=expected_type, location=location), self.assertRaises(planner.PlanError):
                    planner.validate_plan(bad, prepared, now=NOW)
        for location in ('router', 'splunk'):
            bad = copy.deepcopy(plan)
            selected(bad, 'aws_instance', 0 if location == 'router' else 1)['change']['after']['instance_type'] = 't3.medium'
            with self.subTest(non_windows=location), self.assertRaises(planner.PlanError):
                planner.validate_plan(bad, prepared, now=NOW)

    def test_legacy_four_hour_preparation_remains_valid(self):
        for field in ('lifecycle_mode', 'manual_cleanup_required', 'automatic_cleanup_required',
                      'cleanup_responsibility', 'planned_end_semantics', 'windows_instance_type'):
            self.prepared.pop(field)
        report = self.review()
        self.assertEqual(report['lifecycle_mode'], 'automatic')
        self.assertEqual(report['windows_instance_type'], 't3.large')

    def test_region_is_supported_and_must_match_preparation(self):
        for region in planner.ALLOWED_REGIONS:
            plan, prepared = fixture(region)
            with self.subTest(region=region):
                report = planner.validate_plan(plan, prepared, now=NOW)
                self.assertEqual(report['region'], region)
                plan['variables']['aws']['value']['region'] = (
                    'ap-northeast-2' if region == 'eu-central-1' else 'eu-central-1')
                with self.assertRaises(planner.PlanError):
                    planner.validate_plan(plan, prepared, now=NOW)
        for region in ('us-east-1', 'ap-northeast-1', '', None):
            plan, prepared = fixture(region)
            with self.subTest(unsupported_region=region), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, prepared, now=NOW)

    def test_rejects_extra_server_and_other_resource_types(self):
        for kind, address in [('aws_instance', 'module.attack_range_servers["extra"].aws_instance.this'),
                              ('aws_s3_bucket', 'aws_s3_bucket.unreviewed')]:
            with self.subTest(kind=kind):
                plan = copy.deepcopy(self.plan)
                extra = copy.deepcopy(selected(plan, 'aws_instance'))
                extra['type'], extra['address'] = kind, address
                plan['resource_changes'].append(extra)
                with self.assertRaises(planner.PlanError):
                    planner.validate_plan(plan, self.prepared, now=NOW)

    def test_rejects_existing_resource_mutation(self):
        for actions in (['update'], ['delete'], ['delete', 'create'], ['no-op']):
            selected(self.plan, 'aws_instance')['change']['actions'] = actions
            with self.subTest(actions=actions), self.assertRaises(planner.PlanError):
                self.review()

    def test_rejects_unknown_or_wrong_required_disk_fields(self):
        resource = selected(self.plan, 'aws_instance')
        for field, value in [('encrypted', False), ('delete_on_termination', False),
                             ('volume_size', 500), ('volume_type', 'io2')]:
            plan = copy.deepcopy(self.plan)
            selected(plan, 'aws_instance')['change']['after']['root_block_device'][0][field] = value
            with self.subTest(field=field), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, self.prepared, now=NOW)
        resource['change']['after_unknown']['root_block_device'][0]['encrypted'] = True
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_rejects_private_host_public_ip(self):
        selected(self.plan, 'aws_instance', 1)['change']['after']['associate_public_ip_address'] = True
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_rejects_unknown_public_ip_condition(self):
        selected(self.plan, 'aws_instance', 1)['change']['after_unknown']['associate_public_ip_address'] = True
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_rejects_termination_protection_that_prevents_ttl_cleanup(self):
        resource = selected(self.plan, 'aws_instance')
        resource['change']['after']['disable_api_termination'] = True
        with self.assertRaises(planner.PlanError):
            self.review()
        resource['change']['after']['disable_api_termination'] = False
        resource['change']['after_unknown']['disable_api_termination'] = True
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_rejects_open_router_ingress_and_ipv6(self):
        rule = selected(self.plan, 'aws_security_group')['change']['after']['ingress'][0]
        for field, value in [('cidr_blocks', ['0.0.0.0/0']), ('ipv6_cidr_blocks', ['::/0'])]:
            plan = copy.deepcopy(self.plan)
            selected(plan, 'aws_security_group')['change']['after']['ingress'][0][field] = value
            with self.subTest(field=field), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, self.prepared, now=NOW)
        rule['to_port'] = 65535
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_rejects_unbounded_private_ingress(self):
        selected(self.plan, 'aws_security_group', 1)['change']['after']['ingress'][0]['cidr_blocks'] = ['0.0.0.0/0']
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_unmanaged_default_security_group_is_optional_but_unknown_rules_fail(self):
        default = selected(self.plan, 'aws_default_security_group')
        default['change']['after']['ingress'] = None
        default['change']['after_unknown']['ingress'] = True
        with self.assertRaises(planner.PlanError):
            self.review()
        self.plan['resource_changes'].remove(default)
        report = self.review()
        self.assertNotIn('aws_default_security_group', report['resource_counts'])
        self.assertEqual(report['resource_counts']['aws_security_group'], 3)

    def test_rejects_missing_or_wrong_instance_volume_tags(self):
        for kind, field in [('aws_instance', 'volume_tags'), ('aws_subnet', 'tags_all')]:
            plan = copy.deepcopy(self.plan)
            selected(plan, kind)['change']['after'][field].pop(planner.TAGS[1])
            with self.subTest(kind=kind), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, self.prepared, now=NOW)

    def test_rejects_additional_nat_gateway(self):
        extra = copy.deepcopy(selected(self.plan, 'aws_nat_gateway'))
        extra['address'] = extra['address'].replace('[0]', '[1]')
        self.plan['resource_changes'].append(extra)
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_rejects_missing_or_duplicate_resource(self):
        self.plan['resource_changes'].pop()
        self.plan['resource_changes'].pop(0)
        with self.assertRaises(planner.PlanError):
            self.review()
        self.plan, _ = fixture()
        self.plan['resource_changes'].append(copy.deepcopy(self.plan['resource_changes'][0]))
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_rejects_extra_ebs_disk(self):
        selected(self.plan, 'aws_instance')['change']['after']['ebs_block_device'] = [{'device_name': '/dev/sdb'}]
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_computed_ebs_requires_known_root_only_ami(self):
        resource = selected(self.plan, 'aws_instance')
        resource['change']['after']['ami'] = 'ami-' + '2' * 17
        resource['change']['after_unknown']['ebs_block_device'] = True
        with self.assertRaises(planner.PlanError):
            self.review()
        ami = {'id': 'ami-' + '2' * 17, 'root_device_name': '/dev/sda1',
               'block_device_mappings': [{'device_name': '/dev/sda1', 'ebs': {'snapshot_id': 'snap-synthetic'}}]}
        self.plan['resource_changes'].append({'mode': 'data', 'type': 'aws_ami',
                                             'change': {'after': ami}})
        self.review()
        ami['block_device_mappings'].append({'device_name': '/dev/sdb', 'ebs': {'snapshot_id': 'snap-extra'}})
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_resolved_ami_in_prior_state_with_explicit_ephemeral_mappings(self):
        data = [item for item in self.plan['resource_changes'] if item.get('mode') == 'data']
        self.plan['resource_changes'] = [item for item in self.plan['resource_changes']
                                         if item.get('mode') != 'data']
        resources = []
        for index, resource in enumerate(data):
            values = copy.deepcopy(resource['change']['after'])
            # Exact current-provider structure: Ubuntu has two virtual
            # mappings, Windows has 26, with an empty EBS object on each.
            for number in range(2 if index == 0 else 26):
                values['block_device_mappings'].append({
                    'device_name': '/dev/sd' + str(number + 2),
                    'virtual_name': 'ephemeral' + str(number), 'ebs': {},
                })
            resources.append({'mode': 'data', 'type': 'aws_ami', 'values': values})
        self.plan['prior_state'] = {'values': {'root_module': {'child_modules': [
            {'resources': resources},
        ]}}}
        for resource in self.plan['resource_changes']:
            if resource['type'] == 'aws_instance':
                resource['change']['after_unknown']['ebs_block_device'] = True
        self.review()
        mappings = resources[0]['values']['block_device_mappings']
        mappings.append({'device_name': '/dev/sdz', 'ebs': {'snapshot_id': 'snap-extra'}})
        with self.assertRaises(planner.PlanError):
            self.review()

    def test_ami_mappings_reject_empty_root_unknown_or_unclassified_disks(self):
        root = {'device_name': '/dev/sda1', 'ebs': {'snapshot_id': 'snap-synthetic'}}
        for extra in ({'device_name': '/dev/sdb', 'ebs': {}},
                      {'device_name': '/dev/sdb', 'virtual_name': 'unknown', 'ebs': {}},
                      {'device_name': '/dev/sdb', 'virtual_name': 'ephemeral0', 'ebs': None},
                      {'device_name': '/dev/sdb', 'virtual_name': 'ephemeral0'},
                      {'device_name': '/dev/sda1', 'virtual_name': 'ephemeral0', 'ebs': {}},
                      {'device_name': '/dev/sdb', 'virtual_name': 'ephemeral0', 'ebs': {'volume_size': 10}},
                      copy.deepcopy(root)):
            with self.subTest(extra=extra):
                self.assertFalse(planner.only_root_ami({'root_device_name': '/dev/sda1',
                                                       'block_device_mappings': [root, extra]}))
        for ebs in ({}, None, [], [{}]):
            with self.subTest(empty_root=ebs):
                self.assertFalse(planner.only_root_ami({'root_device_name': '/dev/sda1',
                    'block_device_mappings': [{'device_name': '/dev/sda1', 'ebs': ebs}]}))

    def test_rejects_default_password_and_mismatched_scope(self):
        for group, field, value in [('general', 'attack_range_password', 'changeme123!'),
                                    ('general', 'ip_whitelist', '0.0.0.0/0'),
                                    ('general', 'key_name', 'other-key'), ('aws', 'region', 'us-east-1')]:
            plan = copy.deepcopy(self.plan)
            plan['variables'][group]['value'][field] = value
            with self.subTest(field=field), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, self.prepared, now=NOW)

    def test_rejects_expired_partial_or_errored_plan(self):
        with self.assertRaises(planner.PlanError):
            planner.validate_plan(self.plan, self.prepared, now=NOW + timedelta(hours=4))
        for field, value in [('complete', False), ('errored', True), ('deferred_changes', [{}]),
                              ('terraform_version', '1.15.0')]:
            plan = copy.deepcopy(self.plan)
            plan[field] = value
            with self.subTest(field=field), self.assertRaises(planner.PlanError):
                planner.validate_plan(plan, self.prepared, now=NOW)


class PreparationTests(unittest.TestCase):
    def test_whitelist_rejects_networks_private_reserved_ipv6_and_multicast(self):
        for value in ('0.0.0.0/0', '10.1.2.3/32', '8.8.8.8/24', '192.0.2.1/32',
                      '::1/128', '224.0.0.1/32', '8.8.8.8;touch /tmp/test', ''):
            with self.subTest(value=value), self.assertRaises(planner.PlanError):
                planner.whitelist(value)
        self.assertEqual(planner.whitelist('8.8.8.8/32'), '8.8.8.8/32')

    def test_password_replacement_covers_role_and_nested_guacamole_passwords(self):
        changed, count = planner.replace_passwords(template(), 'SyntheticReplacement!')
        self.assertEqual(count, 6)
        self.assertNotIn('changeme123!', json.dumps(changed))
        self.assertIn('changeme123!', json.dumps(template()))

    def test_rejects_wrong_template_or_version(self):
        value = template()
        value['attack_range'][1]['name'] = 'splunk'
        with self.assertRaises(planner.PlanError):
            planner.checked_template(value)
        for version in ('latest', '>= 6.0', '6.68.0;true', '6.68'):
            with self.assertRaises(planner.PlanError):
                planner.exact_version(version)

    def fake_sources(self, source):
        values = {
            'resources.tf': 'module "router" {\n  source = "./modules/router"\n}\nmodule "attack_range_servers" {\n  source = "./modules/generic-server"\n}\n',
            'main.tf': 'provider "aws" {\n  region = var.aws.region\n}\n',
            'modules/network/resources.tf': 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n',
            'modules/generic-server/resources.tf': 'resource "aws_security_group" "this" {\n  ingress {\n    description = "Allow all inbound traffic"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_instance" "this" {\n  private_ip = var.private_ip\n}\n',
            'modules/generic-server/variables.tf': 'variable "private_ip" {\n  type = string\n}\n',
            'modules/router/resources.tf': 'resource "aws_instance" "router" {\n  private_ip = var.private_ip\n}\n',
            'modules/router/variables.tf': 'variable "private_ip" {\n  type = string\n}\n',
        }
        for relative, text in values.items():
            target = source / 'terraform/aws' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        return values

    def test_prepare_uses_private_scratch_preserves_source_and_existing_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            source, state = Path(folder) / 'upstream', Path(folder) / 'state'
            originals = self.fake_sources(source)
            private_key = state / 'ssh_keys/existing.key'
            private_key.parent.mkdir(parents=True)
            private_key.write_text('ExistingSyntheticFixtureKey')
            tracked = '\0'.join('terraform/aws/' + name for name in originals) + '\0'
            with patch.object(planner, 'SOURCE', source), patch.object(planner, 'STATE', state), \
                    patch.object(planner, 'verify_source', return_value=PIN), \
                    patch.object(planner, 'load_template', return_value=template()), \
                    patch.object(planner, 'run', return_value=subprocess.CompletedProcess([], 0, stdout=tracked)):
                prepared = planner.prepare('8.8.8.8/32', '6.68.0', '6.7.3', now=NOW)
            value = json.loads(prepared.read_text())
            self.assertFalse(value['cloud_resources_provisioned'])
            self.assertFalse(value['ttl_scheduler_installed'])
            self.assertEqual(value['lifecycle_mode'], 'automatic')
            self.assertEqual(value['planned_session_hours'], 4)
            self.assertEqual(value['windows_instance_type'], 't3.large')
            self.assertEqual(value['password_fields_replaced'], 6)
            self.assertEqual(value['aws_provider_version'], '6.68.0')
            self.assertEqual(value['region'], 'eu-central-1')
            self.assertEqual(private_key.read_text(), 'ExistingSyntheticFixtureKey')
            for relative, text in originals.items():
                self.assertEqual((source / 'terraform/aws' / relative).read_text(), text)
            for item in prepared.parent.rglob('*'):
                self.assertEqual(item.stat().st_mode & 0o777, 0o700 if item.is_dir() else 0o600)
            private = json.loads((prepared.parent / 'private-config.json').read_text())
            self.assertNotIn('changeme123!', json.dumps(private))
            tfdir = prepared.parent / 'terraform'
            versions = (tfdir / 'versions.tf').read_text()
            self.assertIn('required_providers {\n    aws = {', versions)
            self.assertNotIn('required_providers {\n    aws {', versions)
            self.assertIn('version = "6.7.3"', (tfdir / 'modules/network/resources.tf').read_text())
            self.assertIn('manage_default_security_group = false',
                          (tfdir / 'modules/network/resources.tf').read_text())
            self.assertIn('associate_public_ip_address = false', (tfdir / 'modules/generic-server/resources.tf').read_text())
            self.assertIn('volume_tags = var.resource_tags', (tfdir / 'modules/router/resources.tf').read_text())
            self.assertEqual(private['aws']['aws_default_tags'][planner.TAGS[1]], value['range_id'])
            # Shared contract with the independent TTL document generator:
            # exact ownership keys and canonical UTC expiry must agree.
            ttl_path = MODULE.with_name('aws_ttl.py')
            ttl_spec = importlib.util.spec_from_file_location('aegis_ttl_integration', ttl_path)
            ttl = importlib.util.module_from_spec(ttl_spec)
            ttl_spec.loader.exec_module(ttl)
            session = {'schema_version': 1, 'session_id': value['range_id'],
                       'account_id': '111111111111', 'region': value['region'],
                       'created_at': value['prepared_at'], 'expires_at': value['expires_at']}
            tags = ttl.documents(session)['required-resource-tags.json']
            for key, expected in tags.items():
                self.assertEqual(private['aws']['aws_default_tags'][key], expected)
            self.assertTrue(value['expires_at'].endswith('Z'))
            with patch.object(planner, 'verify_source', return_value=PIN), patch.object(planner, 'read_json', wraps=planner.read_json) as read:
                def files(path):
                    if path == planner.MANIFEST:
                        return PIN
                    return json.loads(path.read_bytes())
                read.side_effect = files
                planner.verify_preparation(prepared, require_dependencies=False)
                (tfdir / 'main.tf').write_text('modified')
                with self.assertRaises(planner.PlanError):
                    planner.verify_preparation(prepared, require_dependencies=False)

    def test_prepare_seoul_persists_region_in_all_inputs_and_checks_match(self):
        with tempfile.TemporaryDirectory() as folder:
            source, state = Path(folder) / 'upstream', Path(folder) / 'state'
            originals = self.fake_sources(source)
            tracked = '\0'.join('terraform/aws/' + name for name in originals) + '\0'
            with patch.object(planner, 'SOURCE', source), patch.object(planner, 'STATE', state), \
                    patch.object(planner, 'verify_source', return_value=PIN), \
                    patch.object(planner, 'load_template', return_value=template()), \
                    patch.object(planner, 'run', return_value=subprocess.CompletedProcess([], 0, stdout=tracked)):
                prepared = planner.prepare('8.8.8.8/32', '6.68.0', '6.7.3',
                                           region='ap-northeast-2', now=NOW)
            value = json.loads(prepared.read_text())
            self.assertEqual(value['region'], 'ap-northeast-2')
            for name in ('private-config.json', 'terraform.tfvars.json'):
                self.assertEqual(json.loads((prepared.parent / name).read_text())['aws']['region'],
                                 'ap-northeast-2')
            with patch.object(planner, 'verify_source', return_value=PIN), \
                    patch.object(planner, 'MANIFEST', prepared.parent / 'manifest.json'):
                planner.MANIFEST.write_text(json.dumps(PIN))
                planner.verify_preparation(prepared, require_dependencies=False)
                value['region'] = 'eu-central-1'
                prepared.write_text(json.dumps(value))
                with self.assertRaises(planner.PlanError):
                    planner.verify_preparation(prepared, require_dependencies=False)

    def test_prepare_unsupported_region_fails_before_source_or_runtime_access(self):
        with patch.object(planner, 'verify_source') as source, patch.object(planner, 'run') as run:
            for region in ('us-east-1', 'ap-northeast-1', '', None):
                with self.subTest(region=region), self.assertRaises(planner.PlanError):
                    planner.prepare('8.8.8.8/32', '6.68.0', '6.7.3', region=region, now=NOW)
            source.assert_not_called()
            run.assert_not_called()

    def test_manual_prepare_week_with_medium_preserves_guards_and_user_responsibility(self):
        with tempfile.TemporaryDirectory() as folder:
            source, state = Path(folder) / 'upstream', Path(folder) / 'state'
            originals = self.fake_sources(source)
            tracked = '\0'.join('terraform/aws/' + name for name in originals) + '\0'
            with patch.object(planner, 'SOURCE', source), patch.object(planner, 'STATE', state), \
                    patch.object(planner, 'verify_source', return_value=PIN), \
                    patch.object(planner, 'load_template', return_value=template()), \
                    patch.object(planner, 'run', return_value=subprocess.CompletedProcess([], 0, stdout=tracked)) as run:
                prepared = planner.prepare('8.8.8.8/32', '6.68.0', '6.7.3', region='ap-northeast-2',
                                           ttl_hours=168, lifecycle_mode='manual',
                                           windows_instance_type='t3.medium', now=NOW)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0], 'git')
            value = json.loads(prepared.read_text())
            self.assertEqual(value['expires_at'], planner.utc_text(NOW + timedelta(days=7)))
            self.assertEqual(value['cleanup_responsibility'], 'user')
            self.assertTrue(value['manual_cleanup_required'])
            self.assertFalse(value['automatic_cleanup_required'])
            self.assertFalse(value['ttl_scheduler_installed'])
            self.assertTrue(value['local_backend'])
            self.assertFalse(value['ssh_key_imported'])
            self.assertFalse(value['s3_backend_created'])
            self.assertFalse(value['cloud_resources_provisioned'])
            self.assertEqual(value['daily_budget_usd'], 10)
            variables = json.loads((prepared.parent / 'terraform.tfvars.json').read_text())
            self.assertEqual(variables['attack_range'][1]['instance_type'], 't3.medium')
            self.assertEqual(variables['attack_range'][0]['instance_type'], 't3.xlarge')
            self.assertEqual(variables['aws']['aws_default_tags'][planner.TAGS[2]], value['expires_at'])
            self.assertEqual(variables['general']['ip_whitelist'], '8.8.8.8/32')
            self.assertNotIn('changeme123!', json.dumps(variables))
            for relative, text in originals.items():
                self.assertEqual((source / 'terraform/aws' / relative).read_text(), text)
            with patch.object(planner, 'verify_source', return_value=PIN), \
                    patch.object(planner, 'MANIFEST', prepared.parent / 'manifest.json'):
                planner.MANIFEST.write_text(json.dumps(PIN))
                planner.verify_preparation(prepared, require_dependencies=False)
                value['windows_instance_type'] = 't3.large'
                prepared.write_text(json.dumps(value))
                with self.assertRaises(planner.PlanError):
                    planner.verify_preparation(prepared, require_dependencies=False)

    def test_prepare_invalid_lifecycle_or_windows_type_fails_before_runtime_access(self):
        with patch.object(planner, 'verify_source') as source, patch.object(planner, 'run') as run:
            for mode, hours in (('automatic', 168), ('automatic', 3), ('manual', 0), ('manual', 169),
                                ('unknown', 4), ('manual', 4.0), ('manual', True)):
                with self.subTest(mode=mode, hours=hours), self.assertRaises(planner.PlanError):
                    planner.prepare('8.8.8.8/32', '6.68.0', '6.7.3',
                                    lifecycle_mode=mode, ttl_hours=hours, now=NOW)
            for instance_type in ('t3.micro', 'm5.large', '', None):
                with self.subTest(instance_type=instance_type), self.assertRaises(planner.PlanError):
                    planner.prepare('8.8.8.8/32', '6.68.0', '6.7.3',
                                    windows_instance_type=instance_type, now=NOW)
            source.assert_not_called()
            run.assert_not_called()

    def test_yaml_loader_has_no_network_or_credential_mount(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            target = source / planner.TEMPLATE
            target.parent.mkdir(parents=True)
            target.write_text('general: {}\n')
            with patch.object(planner, 'SOURCE', source), patch.object(planner, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='{}')) as run:
                planner.load_template(PIN['api_image'])
            args = run.call_args.args
            self.assertIn('none', args)
            self.assertIn('--read-only', args)
            self.assertNotIn('--mount', args)
            self.assertNotIn('aws', args)

    def test_private_files_reject_symlinks_or_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'existing.json'
            target.write_text('preserved')
            with self.assertRaises(FileExistsError):
                planner.private_write(target, 'replacement')
            link = Path(folder) / 'link.json'
            link.symlink_to(target)
            with self.assertRaises(planner.PlanError):
                planner.private_write(link, 'replacement')
            self.assertEqual(target.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
