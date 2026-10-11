import hashlib
import base64
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import stat
import shutil
import threading
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
import zipfile

MODULE = Path(__file__).with_name('runner.py')
spec = importlib.util.spec_from_file_location('offensive_runner', MODULE)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.service = runner.Runner(data_dir=self.root / 'runs', token='local-test-token-that-is-long-enough', benchmark=self.root / 'benchmark', schema=self.root / 'schema', rules=Path(__file__).parent / 'rules/java-security.yml')
        self.service.tool_version = lambda executable: 'test-version'

    def tearDown(self):
        self.tmp.cleanup()

    def new(self, kind='source'):
        return self.service.create({'kind': kind, 'target_id': 'benchmark' if kind == 'source' else 'crapi'}, asynchronous=False)

    def test_rejects_arbitrary_targets_and_parameters(self):
        for body in ({'kind': 'source', 'target_id': 'crapi'}, {'kind': 'api', 'target_id': 'external'}, {'kind': 'api', 'target_id': 'crapi', 'url': 'https://outside.test'}, {'kind': 'source', 'target_id': 'benchmark', 'command': 'echo x'}):
            with self.assertRaises(ValueError):
                self.service.create(body, asynchronous=False)
        self.assertEqual(self.service.list(), [])

    def test_only_one_scan_at_a_time_and_restart_recovers(self):
        first = self.new()
        with self.assertRaises(RuntimeError):
            self.new('api')
        self.service.recover()
        recovered = self.service.get(first['id'])
        self.assertEqual(recovered['status'], 'interrupted')
        self.assertTrue(recovered['finished_at'])
        self.new('api')

    def test_execute_failure_is_preserved(self):
        item = self.new()
        self.service.execute(item['id'])
        final = self.service.get(item['id'])
        self.assertEqual(final['status'], 'failed')
        self.assertIn('not mounted', final['error'])
        self.assertTrue(final['finished_at'])

    def test_immutable_binding_and_parallel_race(self):
        item = self.new()
        with self.assertRaises(RuntimeError):
            self.service.bind(item['id'], {'task_id': '1'})
        item['status'] = 'completed'
        self.service.save(item)
        successes, failures = [], []
        def attempt(task_id):
            try:
                successes.append(self.service.bind(item['id'], {'task_id': task_id}))
            except RuntimeError:
                failures.append(task_id)
        threads = [threading.Thread(target=attempt, args=(str(i),)) for i in range(1, 6)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 4)
        chosen = successes[0]['task_id']
        self.assertEqual(self.service.bind(item['id'], {'task_id': chosen})['task_id'], chosen)

    def test_artifacts_manifest_hash_and_path_boundary(self):
        item = self.new()
        self.service.publish(item, 'assessment.json', {'answer': 1})
        self.service.save(item)
        self.assertEqual(json.loads(self.service.artifact(item['id'], 'assessment.json')), {'answer': 1})
        with self.assertRaises(ValueError): self.service.artifact(item['id'], '../run.json')
        with self.assertRaises(LookupError): self.service.artifact(item['id'], 'run.json')
        (self.service.path(item['id']) / 'assessment.json').write_text('tampered')
        with self.assertRaises(RuntimeError): self.service.artifact(item['id'], 'assessment.json')
        with self.assertRaises(ValueError): self.service.get('../../other')

    def test_secret_redaction_nested_har_and_text(self):
        item = self.new('api')
        document = {'authorization': 'Bearer SECRET-A', 'headers': [{'name': 'Authorization', 'value': 'Bearer SECRET-B'}, {'name': 'Cookie', 'value': 'private=1'}], 'response': {'text': '{"token":"SECRET-C", "password":"SECRET-D"}'}, 'output': 'Authorization: Bearer SECRET-E\nordinary message'}
        self.service.publish(item, 'http.har', document, ['SECRET-C'])
        self.service.save(item)
        content = self.service.artifact(item['id'], 'http.har').decode()
        for secret in ('SECRET-A', 'SECRET-B', 'SECRET-C', 'SECRET-D', 'SECRET-E', 'private=1'):
            self.assertNotIn(secret, content)
        self.assertIn('ordinary message', content)

    def test_schema_subset_does_not_follow_external_servers_or_refs(self):
        schema = {'openapi': '3.0.1', 'servers': [{'url': 'https://external.test'}], 'paths': {'/identity/api/v2/user/dashboard': {'servers': [{'url': 'https://other.test'}], 'get': {'servers': [{'url': 'https://third.test'}], 'responses': {'200': {'description': 'ok'}}}, 'post': {'responses': {}}}, '/identity/api/v2/user/videos/convert_video': {'get': {}}, '/workshop/api/shop/products/{id}': {'get': {}}, '/outside': {'get': {}}}}
        scoped = self.service.prepare_schema(schema)
        self.assertEqual(list(scoped['paths']), ['/identity/api/v2/user/dashboard'])
        self.assertEqual(list(scoped['paths']['/identity/api/v2/user/dashboard']), ['get'])
        self.assertEqual(scoped['servers'], [{'url': self.service.url}])
        self.assertNotIn('external.test', json.dumps(scoped))
        schema['components'] = {'schemas': {'bad': {'$ref': 'https://outside.test/schema'}}}
        with self.assertRaises(ValueError): self.service.prepare_schema(schema)

    def test_fixed_target_url_requires_origin(self):
        for url in ('file:///tmp/a', 'http://user:pass@host', 'http://host/path', 'http://host?x=1', 'http://host#x'):
            with self.assertRaises(ValueError): runner.fixed_url(url)
        self.assertEqual(runner.fixed_url('http://crapi-web:80/'), 'http://crapi-web:80')

    def test_schema_artifact_preserves_credential_property_types(self):
        item = self.new('api')
        schema = {'openapi': '3.0.1', 'paths': {}, 'components': {'schemas': {'Login': {'type': 'object', 'properties': {'password': {'type': 'string'}, 'token': {'type': 'string'}}}}}}
        self.service.publish(item, 'scoped-openapi.json', schema, schema=True)
        self.service.save(item)
        self.assertEqual(json.loads(self.service.artifact(item['id'], 'scoped-openapi.json')), schema)
        with self.assertRaises(ValueError): self.service.publish(item, 'other.json', schema, schema=True)

    def test_command_deadline_and_no_shell(self):
        import sys
        with tempfile.TemporaryDirectory() as folder:
            code, output, timeout = self.service.command([sys.executable, '-c', 'import time; print("ok",flush=True); time.sleep(10)'], folder, timeout=0.1)
            self.assertTrue(timeout)
            self.assertNotEqual(code, 0)
            self.assertIn('ok', output)


class HTTPTests(unittest.TestCase):
    setUp = RunnerTests.setUp
    tearDown = RunnerTests.tearDown
    def test_health_no_auth_mutations_need_auth(self):
        server = runner.http.server.ThreadingHTTPServer(('127.0.0.1', 0), runner.Handler)
        server.runner = self.service
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = 'http://127.0.0.1:' + str(server.server_port)
        try:
            self.assertEqual(json.load(urllib.request.urlopen(base + '/health'))['status'], 'ok')
            for path in ('/runs', '/catalog'):
                with self.assertRaises(urllib.error.HTTPError) as caught: urllib.request.urlopen(base + path)
                self.assertEqual(caught.exception.code, 401)
            request = urllib.request.Request(base + '/runs', headers={'Authorization': 'Bearer ' + self.service.token})
            self.assertEqual(json.load(urllib.request.urlopen(request)), {'runs': []})
            request = urllib.request.Request(base + '/runs', data=json.dumps({'kind': 'api', 'target_id': 'external'}).encode(), headers={'Authorization': 'Bearer ' + self.service.token})
            with self.assertRaises(urllib.error.HTTPError) as caught: urllib.request.urlopen(request)
            self.assertEqual(caught.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class UploadTests(unittest.TestCase):
    setUp = RunnerTests.setUp
    tearDown = RunnerTests.tearDown

    def zip_content(self, files):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, content in files:
                archive.writestr(name, content)
        return stream.getvalue()

    def upload(self, kind='api', content=None, **extra):
        if content is None:
            content = json.dumps(self.schema()).encode() if kind == 'api' else self.zip_content([('app.py', 'import os\nos.system(input())\n')])
        body = {'kind': kind, 'name': 'Uploaded API' if kind == 'api' else 'Uploaded source', 'filename': 'schema.json' if kind == 'api' else 'source.zip', 'content_base64': base64.b64encode(content).decode()}
        if kind == 'api': body['base_url'] = 'http://host.docker.internal:18888/api'
        return self.service.register_target({**body, **extra})

    def schema(self):
        return {'openapi': '3.0.3', 'info': {'title': 'Test', 'version': '1'}, 'servers': [{'url': 'https://wrong.test'}], 'paths': {'/items': {'get': {'responses': {'200': {'description': 'OK'}}}, 'post': {'responses': {'201': {'description': 'created'}}}}, '/health': {'head': {'responses': {'200': {'description': 'OK'}}}}}, 'components': {'schemas': {'Response': {'type': 'object', 'properties': {'token': {'type': 'string', 'example': 'do-not-store'}, 'servers': {'type': 'array', 'items': {'type': 'string'}}, 'example': {'type': 'string'}, 'default': {'type': 'integer'}, '$ref': {'type': 'string'}, 'x-custom': {'type': 'string'}}}}}}

    def test_api_upload_preserves_property_names_and_binds_cleaned_schema(self):
        target = self.upload()
        stored = self.service.get_target(target['id'])
        self.assertEqual(stored['origin'], 'upload')
        self.assertEqual(stored['url'], 'http://host.docker.internal:18888/api')
        self.assertEqual([op['id'] for op in stored['operations']], ['HEAD /health', 'GET /items'])
        blob = (self.service.target_path(target['id']) / 'openapi.json').read_bytes()
        self.assertEqual(hashlib.sha256(blob).hexdigest(), stored['schema_sha256'])
        self.assertNotIn(b'do-not-store', blob)
        self.assertNotIn(b'wrong.test', blob)
        properties = json.loads(blob)['components']['schemas']['Response']['properties']
        self.assertEqual(set(properties), {'token', 'servers', 'example', 'default', '$ref', 'x-custom'})
        self.assertEqual(properties['token'], {'type': 'string'})

    def test_yaml_aliases_depth_duplicate_keys_and_external_refs_rejected(self):
        documents = [b'openapi: 3.0.0\npaths: &p {}\nother: *p\n', b'openapi: 3.0.0\nopenapi: 3.1.0\npaths: {}', ('[' * 81 + '0' + ']' * 81).encode()]
        schema = self.schema()
        schema['components']['schemas']['Other'] = {'$ref': 'https://external.test/schema.json'}
        documents.append(json.dumps(schema).encode())
        for document in documents:
            with self.subTest(document=document[:40]):
                with self.assertRaises(ValueError): self.upload(content=document)
        self.assertEqual(list(self.service.targets_root.glob('*/target.json')), [])
        self.assertEqual(list(self.service.targets_root.glob('.upload-*')), [])

    def test_yaml_document_supported(self):
        document = b'openapi: 3.0.3\ninfo:\n  title: example\n  version: "1"\npaths:\n  /items:\n    get:\n      responses:\n        "200":\n          description: ok\n'
        target = self.upload(content=document, filename='schema.yaml')
        self.assertEqual(target['operations'][0]['id'], 'GET /items')

    def test_reject_unsafe_or_unsupported_api_scopes(self):
        for bad in ['//elsewhere', '/../outside', '/%2e%2e/outside', '/%2f%2fevil.test', '/bad%00path', '/bad%09path', '/bad%7fpath', '/bad?query', '/bad\\path']:
            schema = self.schema()
            schema['paths'] = {bad: {'get': {'responses': {'200': {'description': 'ok'}}}}}
            with self.subTest(path=bad):
                with self.assertRaises(ValueError): self.upload(content=json.dumps(schema).encode())
        schema['paths'] = {'/write': {'post': {'responses': {'200': {'description': 'ok'}}}}}
        with self.assertRaises(ValueError): self.upload(content=json.dumps(schema).encode())
        for url in ('http://127.0.0.1:3000', 'http://[::1]', 'http://169.254.169.254', 'http://offensive-runner:8090', 'http://host.docker.internal:8787', 'http://a:password@api.test', 'http://api.test?token=a', 'http://api.test/../admin'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError): self.upload(base_url=url)
        with patch.object(runner.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('169.254.169.254', 80))]):
            with self.assertRaises(ValueError): runner.target_url('http://rebind.example.test', resolve=True)

    def test_source_upload_languages_exclusions_and_immutable_hashes(self):
        files = [('repo/main.py', 'print("hello")'), ('repo/src/app.ts', 'const x = 1;'), ('repo/node_modules/pkg/a.js', 'ignored'), ('repo/.git/config', 'ignored'), ('repo/.env', 'TOKEN=SECRET'), ('repo/readme.md', 'ignored')]
        target = self.upload('source', self.zip_content(files))
        self.assertEqual(target['file_count'], 2)
        self.assertEqual(target['languages'], ['Python', 'TypeScript'])
        self.assertEqual(target['omitted_file_count'], 4)
        folder = self.service.target_path(target['id'])
        self.assertFalse((folder / 'source/repo/.env').exists())
        self.assertEqual(target['source_path'], f"/app/data/offensive/targets/{target['id']}/source")
        run = self.service.create({'kind': 'source', 'target_id': target['id']}, asynchronous=False)
        self.assertEqual(len(self.service.source_scope(run)[2]), 2)
        (folder / 'source/repo/main.py').write_text('changed')
        with self.assertRaises(ValueError): self.service.source_scope(run)

    def test_source_archives_reject_traversal_links_collisions_and_expansion(self):
        for bad in ('../escape.py', '/absolute.py', 'C:/windows.py', 'foo\\bar.py', 'foo/../bar.py'):
            with self.subTest(path=bad):
                with self.assertRaises(ValueError): self.upload('source', self.zip_content([(bad, 'print(1)')]))
        with self.assertRaises(ValueError): self.upload('source', self.zip_content([('app.py', '1'), ('APP.py', '2')]))
        link = zipfile.ZipInfo('link.py')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError): self.upload('source', self.zip_content([(link, '/etc/passwd')]))
        with patch.object(runner, 'MAX_EXPANDED', 4):
            with self.assertRaises(ValueError): self.upload('source', self.zip_content([('app.py', 'print(1)')]))
        with self.assertRaises(ValueError): self.upload('source', self.zip_content([('README.md', 'no supported code')]))
        self.assertEqual(list(self.service.targets_root.glob('*/target.json')), [])
        self.assertFalse((self.root / 'escape.py').exists())

    def test_run_selection_rejects_foreign_methods_paths_and_source_auth(self):
        target = self.upload()
        for operation_ids in (['POST /items'], ['GET /unknown'], ['GET /items', 'GET /items']):
            with self.assertRaises(ValueError): self.service.create({'kind': 'api', 'target_id': target['id'], 'operation_ids': operation_ids}, asynchronous=False)
        source = self.upload('source')
        with self.assertRaises(ValueError): self.service.create({'kind': 'source', 'target_id': source['id'], 'bearer_token': 'secret'}, asynchronous=False)
        schema = self.schema()
        schema['paths']['/items']['get']['servers'] = [{'url': 'https://different.test'}]
        scoped = self.service.prepare_schema(schema, target, ['HEAD /health'])
        self.assertEqual(scoped['paths'], {'/health': schema['paths']['/health']})
        self.assertEqual(scoped['servers'], [{'url': target['url']}])

    def test_bearer_is_transient_redacted_and_scan_uses_uploaded_scope(self):
        target = self.upload()
        token = 'private-upload-token-123456'
        run = self.service.create({'kind': 'api', 'target_id': target['id'], 'operation_ids': ['HEAD /health'], 'bearer_token': token}, asynchronous=False)
        self.assertNotIn(token, json.dumps(run))
        called = []
        def command(argv, tmp, **kwargs):
            called.append(argv)
            self.assertEqual(argv[argv.index('--url') + 1], target['url'])
            self.assertEqual(json.loads((tmp / 'scoped-openapi.json').read_text())['paths'].keys(), {'/health'})
            self.assertIn('Authorization: Bearer ' + token, argv)
            (tmp / 'junit.xml').write_text('<testsuites><testsuite><testcase name="HEAD /health"/></testsuite></testsuites>')
            (tmp / 'http.har').write_text(json.dumps({'log': {'entries': [{'request': {'headers': [{'name': 'Authorization', 'value': 'Bearer ' + token}]}, 'response': {'status': 200, 'content': {'text': token}}}]}}))
            return 0, 'completed ' + token, False
        with patch.object(self.service, 'command', side_effect=command), patch.object(self.service, 'lab_auth', side_effect=AssertionError('must not create accounts')), patch.object(runner.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('192.168.65.254', 18888))]):
            self.service.execute(run['id'], token)
        final = self.service.get(run['id'])
        self.assertEqual(final['status'], 'completed', final)
        self.assertEqual(final['operation_ids'], ['HEAD /health'])
        self.assertEqual(len(called), 1)
        for file in self.service.path(run['id']).glob('*'):
            self.assertNotIn(token, file.read_text(), file.name)
        assessment = json.loads(self.service.artifact(run['id'], 'assessment.json'))
        self.assertTrue(assessment['authenticated'])

    def test_modified_schema_is_not_executed(self):
        target = self.upload()
        run = self.service.create({'kind': 'api', 'target_id': target['id']}, asynchronous=False)
        (self.service.target_path(target['id']) / 'openapi.json').write_text('{}')
        with patch.object(runner.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('192.168.65.254', 18888))]), patch.object(self.service, 'command', side_effect=AssertionError('must not execute')):
            self.service.execute(run['id'])
        self.assertEqual(self.service.get(run['id'])['status'], 'failed')
        self.assertIn('integrity', self.service.get(run['id'])['error'])

    def test_installed_rules_scan_multiple_languages_without_executing_sources(self):
        if not shutil.which(self.service.semgrep):
            self.skipTest('Semgrep runtime not installed; run in the offensive runner image')
        files = [('main.py', 'import os\nraise RuntimeError("source must not execute")\ndef candidate(value):\n    os.system(value)\n'), ('app.ts', 'function candidate(value: string) { return eval(value); }\n'), ('view.js', 'function render(value) { document.body.innerHTML = value; }\n'), ('Main.java', 'class Main { void candidate(String value) throws Exception { Runtime.getRuntime().exec(value); } }\n')]
        target = self.upload('source', self.zip_content(files))
        run = self.service.create({'kind': 'source', 'target_id': target['id']}, asynchronous=False)
        self.service.execute(run['id'])
        final = self.service.get(run['id'])
        self.assertEqual(final['status'], 'completed', final)
        self.assertEqual({candidate['file'] for candidate in final['candidates']}, {'main.py', 'app.ts', 'view.js', 'Main.java'})
        self.assertTrue(all(candidate['verification'] == 'candidate' for candidate in final['candidates']))
        report = json.loads(self.service.artifact(run['id'], 'semgrep.json'))
        self.assertEqual(report.get('errors'), [])


if __name__ == '__main__':
    unittest.main()
