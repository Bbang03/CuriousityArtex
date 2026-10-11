import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'control.py'
SPEC = importlib.util.spec_from_file_location('attack_range_control', SOURCE)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)
PIN = control.manifest()


def result(text=''):
    return subprocess.CompletedProcess([], 0, stdout=text, stderr='')


class ControlTests(unittest.TestCase):
    def test_existing_source_changes_are_rejected_without_fetch_or_checkout(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'upstream'
            (source / '.git').mkdir(parents=True)
            calls = []

            def fake_git(*args, **kwargs):
                calls.append(args)
                if args[:1] == ('rev-parse',): return result(PIN['commit'])
                if args[:1] == ('remote',): return result(PIN['repository'])
                return result(' M api/app.py\n')

            with patch.object(control, 'SOURCE', source), patch.object(control, 'git', fake_git):
                with self.assertRaisesRegex(control.RangeError, '로컬 변경'):
                    control.verify_source()
            self.assertEqual(len(calls), 3)
            self.assertFalse(any('fetch' in c or 'checkout' in c for c in calls))

    def test_wrong_commit_is_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            (source / '.git').mkdir()
            with patch.object(control, 'SOURCE', source), patch.object(control, 'git', return_value=result('0' * 40)) as git:
                with self.assertRaisesRegex(control.RangeError, '커밋'):
                    control.verify_source()
            self.assertEqual(git.call_count, 1)

    def test_initialize_preserves_existing_private_config_and_key(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'state'
            source = state / 'upstream'
            source.mkdir(parents=True)
            (state / 'ssh_keys').mkdir()
            (state / 'config').mkdir()
            key = state / 'ssh_keys/test.key'
            config = state / 'config/existing.yml'
            key.write_bytes(b'existing-key-for-offline-test')
            config.write_bytes(b'general: preserved\n')
            with patch.object(control, 'STATE', state), patch.object(control, 'SOURCE', source), patch.object(control, 'verify_source', return_value=PIN), patch.object(control, 'run') as run:
                control.initialize()
                control.initialize()
            run.assert_not_called()
            self.assertEqual(key.read_bytes(), b'existing-key-for-offline-test')
            self.assertEqual(config.read_bytes(), b'general: preserved\n')
            for name in ('config', 'ssh_keys', 'cloud-disabled/aws', 'cloud-disabled/azure', 'cloud-disabled/gcloud'):
                self.assertEqual((state / name).stat().st_mode & 0o777, 0o700)

    def test_failed_new_fetch_cleans_only_temporary_checkout_and_retry_succeeds(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'state'
            source = state / 'upstream'
            state.mkdir()
            preserved = state / 'existing.key'
            preserved.write_bytes(b'previous-state')
            should_fail = True
            fetch_sources = []

            def fake_run(*args, **kwargs):
                nonlocal should_fail
                if args[:2] == ('git', 'init'):
                    (Path(args[-1]) / '.git').mkdir()
                    return result()
                self.assertEqual(args[:2], ('git', '-C'))
                temporary = Path(args[2])
                if args[3] in ('fetch', 'checkout'):
                    self.assertNotEqual(temporary, source)
                if args[3] == 'fetch':
                    fetch_sources.append(temporary)
                    if should_fail:
                        should_fail = False
                        raise subprocess.CalledProcessError(1, args)
                elif args[3] == 'checkout':
                    for name in ('api/Dockerfile', 'app/Dockerfile'):
                        file = temporary / name
                        file.parent.mkdir()
                        file.write_text('FROM offline-test\n')
                elif args[3] == 'rev-parse': return result(PIN['commit'])
                elif args[3:5] == ('remote', 'get-url'): return result(PIN['repository'])
                return result()

            with patch.object(control, 'STATE', state), patch.object(control, 'SOURCE', source), patch.object(control, 'run', fake_run):
                with self.assertRaises(subprocess.CalledProcessError):
                    control.initialize()
                self.assertFalse(source.exists())
                self.assertFalse(any(state.glob('.upstream-install-*')))
                self.assertEqual(preserved.read_bytes(), b'previous-state')
                control.initialize()
            self.assertTrue((source / 'api/Dockerfile').is_file())
            self.assertTrue((source / 'app/Dockerfile').is_file())
            self.assertFalse(any(state.glob('.upstream-install-*')))
            self.assertEqual(preserved.read_bytes(), b'previous-state')
            self.assertEqual(len(fetch_sources), 2)
            self.assertNotEqual(fetch_sources[0], fetch_sources[1])

    def test_private_paths_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'target'
            target.mkdir()
            link = Path(folder) / 'link'
            link.symlink_to(target)
            with self.assertRaises(control.RangeError):
                control.private_dir(link)
            file = target / 'record.json'
            file.write_text('preserved')
            file_link = Path(folder) / 'record.json'
            file_link.symlink_to(file)
            with self.assertRaises(control.RangeError):
                control.private_json(file_link, {})
            self.assertEqual(file.read_text(), 'preserved')

    def test_doctor_uses_only_read_paths_and_saves_aggregate_without_secrets(self):
        calls = []

        def fake_get(path, **kwargs):
            calls.append((path, kwargs))
            if path == '/health': return {'status': 'healthy', 'version': '1.0.0'}
            if path == '/templates': return {'templates': [{}], 'provider_availability': {'aws': {'available': True}}}
            if path == '/configs': return {'configs': [{'private': 'DO-NOT-EXPORT'}]}
            if path == '/attack-range/list': return {'attack_ranges': [{'result': {'password': 'DO-NOT-EXPORT'}}]}
            if path == '/openapi/openapi.json': return {'openapi': '3.1.0', 'paths': {'/health': {}, '/templates': {}}}
            return 120

        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            with patch.object(control, 'STATE', state), patch.object(control, 'verify_source', return_value=PIN), patch.object(control, 'get', fake_get), patch.object(control, 'compose') as compose:
                report = control.doctor()
            compose.assert_not_called()
            self.assertEqual([c[0] for c in calls], list(control.READ_PATHS) + ['/'])
            self.assertFalse(report['provider_flags_are_authentication_proof'])
            self.assertFalse(report['cloud_lab_provisioned_by_this_check'])
            self.assertEqual(report['openapi_route_count'], 2)
            self.assertNotIn('swagger_bytes', report)
            self.assertNotIn('DO-NOT-EXPORT', (state / 'doctor.json').read_text())
            self.assertEqual((state / 'doctor.json').stat().st_mode & 0o777, 0o600)

    def test_openapi_route_count_rejects_invalid_documents(self):
        for document in ({}, {'openapi': 3.1, 'paths': {}}, {'openapi': '3.1.0', 'paths': []}, {'openapi': '', 'paths': {}}):
            with self.assertRaises(control.RangeError):
                control.openapi_route_count(document)
        self.assertEqual(control.openapi_route_count({'openapi': '3.1.0', 'paths': {'/health': {}}}), 1)

    def test_get_rejects_non_read_endpoints_before_network(self):
        with patch.object(control.urllib.request, 'build_opener') as network:
            for path in ('/attack-range/build', '/attack-range/simulate', '/providers/aws/check', '//example.com'):
                with self.assertRaises(control.RangeError):
                    control.get(path)
            with self.assertRaises(control.RangeError):
                control.get('/attack-range/build', ui=True)
            network.assert_not_called()

    def test_get_has_no_proxy_or_redirect_and_bounds_response(self):
        class Response:
            status = 200

            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, count):
                self.requested = count
                return b'x' * (control.MAX_RESPONSE + 1)

        response = Response()
        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return response

        opener = Opener()
        with patch.object(control.urllib.request, 'build_opener', return_value=opener) as builder:
            with self.assertRaisesRegex(control.RangeError, '한도'):
                control.get('/health')
        self.assertEqual(opener.request.get_method(), 'GET')
        self.assertEqual(opener.request.full_url, 'http://127.0.0.1:4000/health')
        self.assertEqual(builder.call_args.args[0].proxies, {})
        self.assertIsInstance(builder.call_args.args[1], control.NoRedirect)
        self.assertEqual(response.requested, control.MAX_RESPONSE + 1)

    def test_compose_only_targets_separate_project(self):
        with patch.object(control, 'run', return_value=result()) as run:
            control.compose('stop')
        args = run.call_args.args
        self.assertIn('aegis-attack-range', args)
        self.assertNotIn('artex-local', args)
        self.assertEqual(args[-1], 'stop')

    def test_start_never_builds_or_deletes_state(self):
        with patch.object(control, 'initialize') as initialize, patch.object(control, 'compose') as compose:
            control.start()
        initialize.assert_called_once()
        compose.assert_called_once_with('up', '-d', '--no-build', '--wait', '--wait-timeout', '180', 'api', 'app')

    def test_build_is_sequential_and_records_image_ids_without_configs(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(control, 'STATE', Path(folder)), patch.object(control, 'initialize'), patch.object(control, 'compose') as compose, patch.object(control, 'run', return_value=result('sha256:' + 'a' * 64)):
                control.build()
            self.assertEqual([call.args for call in compose.call_args_list], [('build', 'api'), ('build', 'app')])
            record = json.loads((Path(folder) / 'installation.json').read_text())
            self.assertEqual(record['commit'], PIN['commit'])
            self.assertEqual(record['images']['api']['image_id'], 'sha256:' + 'a' * 64)
            self.assertFalse(record['cloud_lab_provisioned'])

    def test_sso_configuration_uses_isolated_credentials_and_only_official_login_wizard(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'state'
            with patch.object(control, 'STATE', state), patch.object(control, 'run', return_value=result()) as run:
                control.sso('configure')
            args = run.call_args.args
            self.assertEqual(args[:4], ('docker', 'run', '--rm', '-it'))
            self.assertIn('512m', args)
            self.assertIn('no-new-privileges:true', args)
            self.assertIn('AWS_EC2_METADATA_DISABLED=true', args)
            self.assertIn(f'type=bind,source={state / "aws-sso"},target=/root/.aws', args)
            self.assertEqual(args.count('--mount'), 1)
            self.assertEqual(args[-4:], ('configure', 'sso', '--use-device-code', '--no-browser'))
            self.assertFalse(any('docker.sock' in arg or '/.azure' in arg or '--privileged' == arg for arg in args))
            self.assertEqual((state / 'aws-sso').stat().st_mode & 0o777, 0o700)
            self.assertNotIn(str(Path.home() / '.aws'), args)

    def test_sso_login_preserves_existing_config_cache_and_requires_profile_config(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'state'
            with patch.object(control, 'STATE', state), patch.object(control, 'run', return_value=result()) as run:
                with self.assertRaisesRegex(control.RangeError, '프로필'):
                    control.sso('login')
                run.assert_not_called()
                config = state / 'aws-sso/config'
                cache = state / 'aws-sso/sso/cache/test.json'
                config.write_bytes(b'[profile aegisloop]\nsso_session = offline-test\n')
                cache.parent.mkdir(parents=True)
                cache.write_bytes(b'offline-cache-preserved')
                control.sso('login')
            self.assertEqual(config.read_bytes(), b'[profile aegisloop]\nsso_session = offline-test\n')
            self.assertEqual(cache.read_bytes(), b'offline-cache-preserved')
            self.assertEqual(run.call_args.args[-6:], ('sso', 'login', '--profile', 'aegisloop', '--use-device-code', '--no-browser'))

    def test_sso_rejects_unknown_action_before_launch(self):
        with patch.object(control, 'run') as run:
            with self.assertRaises(control.RangeError):
                control.sso('build')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
