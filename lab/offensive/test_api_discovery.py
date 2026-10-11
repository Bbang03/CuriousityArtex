import base64
import hashlib
import http.server
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import api_discovery as discovery
import runner


class DiscoveryTests(unittest.TestCase):
    def har(self, requests):
        return json.dumps({'log': {'entries': [{'request': item, 'response': {'content': {'text': 'NEVER-STORE-RESPONSE'}}} for item in requests]}}).encode()

    def test_har_keeps_only_paths_and_safe_names_and_maps_explicit_origin(self):
        raw = self.har([
            {'method': 'GET', 'url': 'http://localhost:18888/api/items?limit=PRIVATE-VALUE&token=PRIVATE-TOKEN', 'headers': [{'name': 'Authorization', 'value': 'NEVER-STORE-HEADER'}], 'cookies': [{'value': 'NEVER-STORE-COOKIE'}], 'postData': {'text': 'NEVER-STORE-BODY'}},
            {'method': 'HEAD', 'url': 'http://localhost:18888/api/health'},
            {'method': 'POST', 'url': 'http://localhost:18888/api/create'},
            {'method': 'GET', 'url': 'https://unrelated.test/api/items'},
            {'method': 'GET', 'url': 'http://localhost:18888/apix/escape'},
            {'method': 'GET', 'url': 'http://localhost:18888/api/%252e%252e/escape'},
            {'method': 'GET', 'url': 'http://localhost:18888/api/main.js'},
        ])
        schema, operations, report = discovery.from_har(raw, 'http://host.docker.internal:18888/api', 'http://localhost:18888')
        self.assertEqual([x['id'] for x in operations], ['GET /api/items', 'HEAD /api/health'])
        self.assertEqual(operations[0]['query_parameters'], ['limit'])
        self.assertEqual(schema['servers'], [{'url': 'http://host.docker.internal:18888'}])
        serialized = json.dumps([schema, operations, report])
        for secret in ('PRIVATE-VALUE', 'PRIVATE-TOKEN', 'NEVER-STORE'):
            self.assertNotIn(secret, serialized)
        self.assertEqual(report['omitted']['other_origin'], 1)
        self.assertEqual(report['omitted']['other_method'], 1)
        with self.assertRaises(ValueError):
            discovery.from_har(raw, 'http://host.docker.internal:18888/api')

    def test_invalid_har_and_secret_path_are_not_registered(self):
        for content in (b'{}', b'[]', b'null', b'not JSON', self.har([{'method': 'GET', 'url': 'http://lab/api/token/SECRET'}])):
            with self.assertRaises(ValueError):
                discovery.from_har(content, 'http://lab')
        for address in ('http://user:password@lab', 'http://lab/api', 'http://lab/?secret=x', '//lab'):
            with self.assertRaises(ValueError): discovery.har_origin(address)

    def test_url_direct_json_preserves_exact_path_without_duplicate_prefix(self):
        requested = []
        def fetch(url, timeout):
            requested.append(url)
            return 401, 'application/json', b'{"error":"authentication required"}'
        schema, operations, report = discovery.from_url('http://api.test/api/items', runner.target_url, fetch)
        self.assertEqual(requested, ['http://api.test/api/items'])
        self.assertEqual(schema['servers'], [{'url': 'http://api.test'}])
        self.assertEqual(operations[0]['path'], '/api/items')
        self.assertEqual(operations[0]['confidence'], 'observed')

    def test_static_discovery_follows_only_scope_and_never_replays_query(self):
        requested = []
        def fetch(url, timeout):
            requested.append(url)
            if url.endswith('/app'):
                return 200, 'text/html', b'<script src="/app/main.js?token=secret"></script><script src="https://elsewhere.test/x.js"></script><a href="/app/api/items?limit=secret">Items</a><a href="/apple/api/escape">Escape</a>'
            return 200, 'text/javascript', b'fetch("/app/api/health",{method:"GET"}); fetch("/app/api/change",{method:"POST"}); map.get("false-positive");'
        schema, operations, report = discovery.from_url('http://api.test/app', runner.target_url, fetch)
        self.assertEqual(requested, ['http://api.test/app', 'http://api.test/app/main.js'])
        self.assertEqual([x['id'] for x in operations], ['GET /app/api/health', 'GET /app/api/items'])
        self.assertNotIn('secret', json.dumps(schema))
        self.assertTrue(all(x['confidence'] == 'candidate' for x in operations))

    def test_generic_literal_concatenation_not_cross_product_or_map_get(self):
        js = 'const p="service/",q="other/",urls={GET_ITEMS:"api/items",POST_ITEM:"api/change"}; function read(){const x=p+urls.GET_ITEMS;fetch(x,{method:"GET"})} function write(){const x=q+urls.POST_ITEM;fetch(x,{method:"POST"})} map.get("id");'
        self.assertEqual(discovery.static_js_paths(js), ['service/api/items'])

    def test_request_budget_and_redirect_without_following(self):
        calls = []
        def fetch(url, timeout):
            calls.append(url)
            return 200, 'text/html', ('<a href="/api/item">API</a>' + ''.join(f'<a href="/page{i}">page</a>' for i in range(100))).encode()
        _, _, report = discovery.from_url('http://lab', runner.target_url, fetch)
        self.assertEqual(len(calls), 20)
        self.assertIn('crawl_limit', report['omitted'])
        with self.assertRaises(ValueError):
            discovery.from_url('http://lab', runner.target_url, lambda url, timeout: (302, '', b''))

    def test_dns_deadline_and_blocked_resolved_addresses(self):
        def slow(*args, **kwargs):
            time.sleep(0.2)
            return []
        started = time.monotonic()
        with patch.object(discovery.socket, 'getaddrinfo', side_effect=slow):
            with self.assertRaisesRegex(ValueError, 'DNS lookup'):
                discovery.checked_fetch('http://lab/', 0.02, runner.target_url)
        self.assertLess(time.monotonic() - started, 0.15)
        for address in ('127.0.0.1', '169.254.169.254', '::ffff:127.0.0.1'):
            with patch.object(discovery.socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 80))]):
                with self.assertRaisesRegex(ValueError, 'blocked address'):
                    discovery.checked_fetch('http://lab/', 0.1, runner.target_url)

    def test_tcp_connect_uses_only_budget_remaining_after_dns(self):
        captured = []
        def resolve(*args, **kwargs):
            time.sleep(0.05)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.2', 80))]
        def connect(address, timeout, source_address):
            captured.append((address, timeout))
            raise OSError('simulated connect failure')
        with patch.object(discovery.socket, 'getaddrinfo', side_effect=resolve), patch.object(discovery.socket, 'create_connection', side_effect=connect):
            with self.assertRaisesRegex(OSError, 'simulated connect failure'):
                discovery.checked_fetch('http://lab/', 0.2, runner.target_url)
        self.assertEqual(captured[0][0], ('10.0.0.2', 80))
        self.assertGreater(captured[0][1], 0)
        self.assertLess(captured[0][1], 0.17)

    def test_header_and_body_trickle_are_bounded(self):
        class Trickle(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                try:
                    if self.path == '/headers':
                        self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Long: ')
                    else:
                        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n')
                    for _ in range(100):
                        self.wfile.write(b'a'); self.wfile.flush(); time.sleep(0.01)
                except (OSError, BrokenPipeError):
                    pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Trickle)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        try:
            with patch.object(discovery.socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.2', 80))]), patch.object(discovery.socket, 'create_connection', side_effect=lambda *args, **kwargs: self.local_socket(server.server_port)):
                for path in ('headers', 'body'):
                    started = time.monotonic()
                    with self.assertRaises((ValueError, OSError, http.client.HTTPException)):
                        discovery.checked_fetch('http://lab/' + path, 0.08, runner.target_url)
                    self.assertLess(time.monotonic()-started, 0.3)
        finally:
            server.shutdown(); server.server_close(); worker.join()

    def test_cumulative_budget_charges_failed_streams_and_caps_final_response(self):
        requests = []
        class Stream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                requests.append(self.path)
                try:
                    # An unknown-length body must be stopped at the exact read
                    # boundary, without an extra probe byte to detect overflow.
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/javascript')
                    self.end_headers()
                    self.wfile.write(b'a' * 64)
                    self.wfile.flush()
                except OSError:
                    pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Stream)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        budget = {'used': 0, 'remaining': 40}
        try:
            with patch.object(discovery, 'MAX_RESPONSE', 16), patch.object(discovery.socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.2', 80))]), patch.object(discovery.socket, 'create_connection', side_effect=lambda *args, **kwargs: self.local_socket(server.server_port)):
                for expected in (16, 32, 40):
                    with self.assertRaisesRegex(ValueError, 'response-byte budget'):
                        discovery.checked_fetch('http://lab/stream', 0.5, runner.target_url, budget)
                    self.assertEqual(budget['used'], expected)
                    self.assertEqual(budget['remaining'], 40-expected)
                with self.assertRaisesRegex(ValueError, 'total response-byte budget'):
                    discovery.checked_fetch('http://lab/stream', 0.5, runner.target_url, budget)
            self.assertEqual(len(requests), 3)
        finally:
            server.shutdown(); server.server_close(); worker.join()

    @staticmethod
    def local_socket(port):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect(('127.0.0.1', port))
        return connection


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = runner.Runner(data_dir=Path(self.tmp.name)/'runs', token='discovery-test-shared-token-long-enough')
        self.service.tool_version = lambda _: 'test-version'
    def tearDown(self):
        self.tmp.cleanup()

    def test_har_registration_no_raw_material_persisted(self):
        raw = DiscoveryTests().har([{'method': 'GET', 'url': 'http://localhost:18888/api/items?limit=PRIVATE-VALUE', 'headers': [{'name': 'Cookie', 'value': 'NEVER-STORE'}]}])
        target = self.service.register_target({'kind': 'api', 'input_mode': 'har', 'name': 'Traffic', 'base_url': 'http://host.docker.internal:18888/api', 'har_origin': 'http://localhost:18888', 'filename': 'capture.har', 'content_base64': base64.b64encode(raw).decode()})
        self.assertEqual(target['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(target['url'], 'http://host.docker.internal:18888')
        self.assertEqual(target['scope_url'], 'http://host.docker.internal:18888/api')
        for path in self.service.target_path(target['id']).iterdir():
            self.assertNotIn(b'PRIVATE-VALUE', path.read_bytes())
            self.assertNotIn(b'NEVER-STORE', path.read_bytes())
        self.assertEqual({p.name for p in self.service.target_path(target['id']).iterdir()}, {'openapi.json', 'discovery.json', 'target.json'})

    def test_url_registration_requires_no_file_and_normalizes_default_port(self):
        original = discovery.from_url
        with patch.object(runner.api_discovery, 'from_url', side_effect=lambda url, validator: original(url, validator, lambda *_: (200, 'application/json', b'{}'))):
            target = self.service.register_target({'kind': 'api', 'input_mode': 'url', 'name': 'Direct API', 'base_url': 'http://lab:80/api/items'})
        self.assertEqual(target['url'], 'http://lab')
        self.assertEqual(target['scope_url'], 'http://lab/api/items')
        self.assertEqual(target['sha256'], target['schema_sha256'])

    def test_url_registration_preserves_directory_seed_trailing_slash(self):
        original = discovery.from_url
        calls = []
        def fetch(url, timeout):
            calls.append(url)
            return 200, 'text/html', b'<a href="api/items">Items</a>'
        with patch.object(runner.api_discovery, 'from_url', side_effect=lambda url, validator: original(url, validator, fetch)):
            target = self.service.register_target({'kind': 'api', 'input_mode': 'url', 'name': 'Mounted API', 'base_url': 'http://lab/app/'})
        self.assertEqual(calls, ['http://lab/app/'])
        self.assertEqual(target['operations'][0]['path'], '/app/api/items')

    def test_discovered_run_uses_only_server_error_check_and_exposes_auth_limit(self):
        raw = DiscoveryTests().har([{'method': 'GET', 'url': 'http://lab/api/items'}])
        target = self.service.register_target({'kind': 'api', 'input_mode': 'har', 'name': 'Traffic', 'base_url': 'http://lab/api', 'filename': 'capture.har', 'content_base64': base64.b64encode(raw).decode()})
        run = self.service.create({'kind': 'api', 'target_id': target['id'], 'operation_ids': ['GET /api/items']}, asynchronous=False)
        captured = []
        def command(argv, cwd, **kwargs):
            captured.extend(argv)
            Path(argv[argv.index('--report-junit-path')+1]).write_text('<testsuites><testsuite><testcase name="GET /api/items"/></testsuite></testsuites>')
            Path(argv[argv.index('--report-har-path')+1]).write_text(json.dumps({'log': {'entries': [{'request': {'method': 'GET', 'url': 'http://lab/api/items'}, 'response': {'status': 401}}]}}))
            return 0, '', False
        with patch.object(self.service, 'command', side_effect=command), patch.object(runner, 'target_url', side_effect=lambda url, resolve=False: url):
            with tempfile.TemporaryDirectory() as tmp:
                self.service.scan_api(run, Path(tmp))
        self.assertEqual(captured[captured.index('--checks')+1], 'not_a_server_error')
        self.assertTrue(any('401/403' in item for item in run['limitations']))
        self.assertIn('응답 확인 1개', run['summary'])
        self.assertIn('discovery.json', {item['name'] for item in run['artifacts']})


if __name__ == '__main__':
    unittest.main()
