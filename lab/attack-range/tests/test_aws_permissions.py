import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

FOLDER = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('aws_permissions', FOLDER / 'aws_permissions.py')
permissions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(permissions)
SESSION = {'schema_version': 1, 'session_id': '11111111-2222-4333-8444-555555555555',
           'account_id': '123456789012', 'region': 'ap-northeast-2',
           'created_at': '2026-10-10T00:00:00Z', 'expires_at': '2026-10-10T04:00:00Z'}


class ControllerPolicyTests(unittest.TestCase):
    def test_admin_created_roles_cannot_be_changed_or_replaced_by_controller(self):
        documents = permissions.documents(SESSION)
        statements = documents['controller-policy.json']['Statement']
        actions = {action for statement in statements for action in statement['Action']}
        iam = {action for action in actions if action.startswith('iam:')}
        self.assertEqual(iam, {'iam:GetRole', 'iam:GetRolePolicy', 'iam:PassRole',
                               'iam:ListRolePolicies', 'iam:ListAttachedRolePolicies'})
        self.assertTrue(documents['controller-review.json']['admin_precreated_runtime_roles_required'])
        self.assertFalse(any(action.endswith('*') for action in actions))
        self.assertFalse(actions & {'lambda:GetAccountSettings', 'scheduler:ListScheduleGroups', 'iam:GetUser'})

    def test_pass_roles_are_distinct_exact_arns_and_matching_service_only(self):
        statements = permissions.documents(SESSION)['controller-policy.json']['Statement']
        grants = [statement for statement in statements if statement['Action'] == ['iam:PassRole']]
        self.assertEqual(len(grants), 2)
        for statement in grants:
            self.assertEqual(len(statement['Resource']), 1)
            arn = statement['Resource'][0]
            self.assertNotIn('*', arn)
            self.assertIn(SESSION['account_id'], arn)
            self.assertIn(SESSION['session_id'], arn)
            service = statement['Condition']['StringEquals']['iam:PassedToService']
            self.assertEqual(service, 'lambda.amazonaws.com' if arn.endswith('-cleanup') else 'scheduler.amazonaws.com')

    def test_creation_requires_fixed_tags_and_expiry_without_vacuous_allow(self):
        statements = permissions.documents(SESSION)['controller-policy.json']['Statement']
        for statement in statements:
            if any(action in statement['Action'] for action in ('lambda:CreateFunction', 'logs:CreateLogGroup', 'scheduler:CreateScheduleGroup')):
                condition = statement['Condition']
                self.assertEqual(condition['DateLessThan']['aws:CurrentTime'], SESSION['expires_at'])
                self.assertEqual(condition['Null']['aws:TagKeys'], 'false')
                self.assertEqual(set(condition['ForAllValues:StringEquals']['aws:TagKeys']),
                                 {'AegisLoopSession', 'AegisLoopExpiresAt'})
                self.assertEqual(condition['StringEquals']['aws:RequestTag/AegisLoopSession'], SESSION['session_id'])
                self.assertEqual(condition['StringEquals']['aws:RequestTag/AegisLoopExpiresAt'], SESSION['expires_at'])

    def test_regional_resources_have_exact_session_names_and_region_condition(self):
        statements = permissions.documents(SESSION)['controller-policy.json']['Statement']
        for statement in statements:
            if all(action.startswith('iam:') for action in statement['Action']):
                continue
            self.assertEqual(statement['Condition']['StringEquals']['aws:RequestedRegion'], SESSION['region'])
            for resource in statement['Resource']:
                self.assertIn(':' + SESSION['account_id'] + ':', resource)
                self.assertIn(':' + SESSION['region'] + ':', resource)
                if not resource.startswith('arn:aws:servicequotas:'):
                    self.assertIn(SESSION['session_id'], resource)
                self.assertTrue('*' not in resource or resource.endswith(':*'))
            if 'scheduler:CreateSchedule' in statement['Action']:
                self.assertTrue(statement['Resource'][0].endswith('/expiry'))

    def test_private_files_only_no_clobber_or_output_outside_ignored_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / 'state'
            with patch.object(permissions, 'STATE', base):
                destination = permissions.write_artifacts(SESSION, base / 'review')
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
                for file in destination.iterdir():
                    self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                    if file.suffix == '.json':
                        json.loads(file.read_text())
                with self.assertRaises(ValueError):
                    permissions.write_artifacts(SESSION, destination)
                with self.assertRaises(ValueError):
                    permissions.write_artifacts(SESSION, Path(temporary) / 'public')
            alias = Path(temporary) / 'alias'
            alias.symlink_to(base, target_is_directory=True)
            with patch.object(permissions, 'STATE', alias), self.assertRaises(ValueError):
                permissions.write_artifacts(SESSION, alias / 'elsewhere')

    def test_invalid_or_oversized_session_is_rejected_before_any_output(self):
        for invalid in (SESSION | {'account_id': 'wrong'}, SESSION | {'expires_at': '2026-10-10T05:00:00Z'},
                        SESSION | {'credential': 'never-accepted'}):
            with self.assertRaises(ValueError):
                permissions.documents(invalid)

    def test_role_mutations_are_admin_recipe_only_and_use_reviewed_bundle_files(self):
        docs = permissions.documents(SESSION, ttl_bundle='/private/review/ttl')
        recipe = docs['admin-roles-recipe.json']
        self.assertFalse(recipe['executed'])
        self.assertTrue(recipe['administrator_only'])
        self.assertEqual(len(recipe['commands']), 12)
        for command in recipe['commands']:
            self.assertEqual(command[:3], ['aws', '--profile', '<ADMIN_PROFILE>'])
            self.assertIn(SESSION['region'], command)
            self.assertTrue(any(SESSION['session_id'] in arg for arg in command))
            if 'put-role-policy' in command:
                document = command[command.index('--policy-document') + 1]
                self.assertTrue(document.startswith('file:///private/review/ttl/'))
                self.assertTrue(document.endswith('-policy.json'))

    def test_quota_read_uses_official_exact_standard_vcpu_arn(self):
        docs = permissions.documents(SESSION)
        statements = docs['controller-policy.json']['Statement']
        quota = [s for s in statements if any(a.startswith('servicequotas:') for a in s['Action'])]
        self.assertEqual(len(quota), 1)
        self.assertEqual(quota[0]['Action'], ['servicequotas:GetServiceQuota'])
        self.assertEqual(quota[0]['Resource'], ['arn:aws:servicequotas:ap-northeast-2:123456789012:ec2/L-1216C47A'])
        self.assertEqual(quota[0]['Condition']['StringEquals']['servicequotas:service'], 'ec2')
        self.assertEqual(quota[0]['Condition']['StringEquals']['aws:RequestedRegion'], SESSION['region'])
        self.assertLessEqual(docs['controller-review.json']['managed_policy_compact_character_count'], 6144)
        self.assertIn('고객 관리형', docs['admin-instructions.txt'])

    def test_entire_role_permission_inventory_is_exact_role_scoped_and_required(self):
        docs = permissions.documents(SESSION)
        grants = [s for s in docs['controller-policy.json']['Statement'] if 'iam:ListRolePolicies' in s['Action']]
        self.assertEqual(len(grants), 1)
        self.assertIn('iam:ListAttachedRolePolicies', grants[0]['Action'])
        self.assertEqual(len(grants[0]['Resource']), 2)
        self.assertTrue(all('*' not in arn and SESSION['session_id'] in arn for arn in grants[0]['Resource']))
        review = docs['controller-review.json']
        self.assertEqual(review['expected_inline_policy_names'], ['aegisloop-session-runtime'])
        self.assertEqual(review['expected_attached_managed_policy_arns'], [])
        self.assertTrue(review['complete_trust_document_match_required'])


if __name__ == '__main__':
    unittest.main()
