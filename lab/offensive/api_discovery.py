"""Bounded API inventories from HAR or static web content. Never executes JavaScript."""
from __future__ import annotations

import collections
import hashlib
import html.parser
import http.client
import ipaddress
import json
import queue
import re
import socket
import threading
import time
import urllib.parse

MAX_HAR = 16 * 1024 * 1024
MAX_OPERATIONS = 500
MAX_REQUESTS = 20
MAX_SECONDS = 30
MAX_RESPONSE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
SECRET_NAME = re.compile(r'password|passwd|secret|token|auth|cookie|session|api.?key|credential|signature|csrf|jwt', re.I)
PARAM_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,79}$')
API_PATH = re.compile(r'(?:^|/)(?:api|rest|graphql|v[1-9][0-9]*)(?:/|$)', re.I)
STATIC_EXT = ('.js', '.mjs', '.css', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.woff2', '.map', '.gif')


def origin(value):
    p = urllib.parse.urlsplit(value)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('HTTP(S) origin without credentials is required')
    try:
        port = p.port
    except ValueError:
        raise ValueError('invalid origin port')
    host = p.hostname.lower().rstrip('.')
    if ':' in host:
        host = '[' + host + ']'
    if port and port != (443 if p.scheme == 'https' else 80):
        host += ':' + str(port)
    return p.scheme + '://' + host


def har_origin(value):
    if not isinstance(value, str) or len(value) > 2048 or '\\' in value or any(ord(c) < 33 for c in value):
        raise ValueError('HAR original address is invalid')
    p = urllib.parse.urlsplit(value)
    if p.path not in ('', '/') or p.query or p.fragment:
        raise ValueError('HAR original address must be an origin without a path or query')
    return origin(value)


def safe_path(path):
    if not path or not path.startswith('/') or len(path) > 500:
        raise ValueError('invalid discovered path')
    decoded = path
    # Reject multiply encoded traversal as well as its single-encoded form.
    for _ in range(4):
        next_value = urllib.parse.unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if '%' in decoded or any(c in decoded for c in ('\\', '?', '#', '{', '}', '<', '>')) or '//' in decoded or '://' in decoded or any(ord(c) < 33 or ord(c) == 127 for c in decoded) or any(part in ('.', '..') for part in decoded.split('/')) or re.search(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.|/(?:token|password|secret|api[-_]key)/[^/]+', decoded, re.I):
        raise ValueError('discovered path escapes the registered scope or is unresolved')
    return path


def within(path, prefix):
    # Scope root, exact endpoint, and descendants are allowed; sibling prefixes are not.
    prefix = prefix.rstrip('/')
    return not prefix or path == prefix or path.startswith(prefix + '/')


def query_names(query, extra=()):
    values = [name for name, _ in urllib.parse.parse_qsl(query, max_num_fields=1000, keep_blank_values=True)]
    values.extend(extra)
    return sorted({name for name in values if isinstance(name, str) and PARAM_NAME.fullmatch(name) and not SECRET_NAME.search(name)})[:50]


def make_schema(base, operations):
    paths = {}
    for operation in operations:
        params = [{'name': name, 'in': 'query', 'required': False, 'schema': {'type': 'string', 'maxLength': 32}} for name in operation.get('query_parameters', [])]
        paths.setdefault(operation['path'], {})[operation['method'].lower()] = {
            'responses': {'default': {'description': 'Discovered request; no response contract inferred'}},
            **({'parameters': params} if params else {}),
        }
    return {'openapi': '3.0.3', 'info': {'title': 'Discovered API request inventory (not a response contract)', 'version': '1'}, 'servers': [{'url': base}], 'paths': paths}


def from_har(content, base_url, original_origin=''):
    if not content or len(content) > MAX_HAR:
        raise ValueError('HAR upload limit is 16 MiB')
    try:
        document = json.loads(content.decode('utf-8-sig'))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('upload a valid UTF-8 HAR JSON document')
    if not isinstance(document, dict) or not isinstance(document.get('log'), dict) or not isinstance(document['log'].get('entries'), list):
        raise ValueError('HAR log.entries array is required')
    entries = document['log']['entries']
    if len(entries) > 100000:
        raise ValueError('HAR may contain at most 100,000 entries')
    runtime_origin = origin(base_url)
    accepted_origin = har_origin(original_origin) if original_origin else runtime_origin
    prefix = urllib.parse.urlsplit(base_url).path
    operations, omitted = {}, collections.Counter()
    for entry in entries:
        request = entry.get('request') if isinstance(entry, dict) else None
        if not isinstance(request, dict) or not isinstance(request.get('url'), str):
            omitted['invalid_request'] += 1
            continue
        try:
            parsed = urllib.parse.urlsplit(request['url'])
            if origin(request['url']) != accepted_origin:
                omitted['other_origin'] += 1
                continue
            path = safe_path(parsed.path or '/')
            if not within(path, prefix):
                omitted['outside_prefix'] += 1
                continue
            method = request.get('method', '').upper()
            if method not in ('GET', 'HEAD'):
                omitted['other_method'] += 1
                continue
            if path.lower().endswith(STATIC_EXT):
                omitted['static_asset'] += 1
                continue
            key = method + ' ' + path
            if key not in operations and len(operations) >= MAX_OPERATIONS:
                omitted['operation_limit'] += 1
                continue
            names = query_names(parsed.query, (p.get('name') for p in request.get('queryString', []) if isinstance(p, dict)))
            previous = operations.get(key, {})
            operations[key] = {'id': key, 'method': method, 'path': path, 'source': 'har_request', 'confidence': 'observed', 'query_parameters': sorted(set(previous.get('query_parameters', [])) | set(names))[:50]}
        except (ValueError, TypeError, AttributeError):
            omitted['invalid_request'] += 1
    if not operations:
        raise ValueError('HAR에서 선택한 주소·경로 범위의 GET/HEAD 요청을 찾지 못했습니다. HAR 원본 주소와 대상 범위를 확인하세요.')
    result = sorted(operations.values(), key=lambda item: item['id'])
    report = {'mode': 'har', 'summary': f'HAR 요청 {len(entries)}건에서 GET/HEAD 작업 {len(result)}개를 추출했습니다.', 'requests': 0, 'entries': len(entries), 'omitted': dict(omitted), 'har_origin': accepted_origin, 'runtime_origin': runtime_origin, 'scope_url': base_url, 'warnings': ['HAR에서 관측한 요청 목록이며 API 응답 명세가 아닙니다. 서버 오류만 검사하고 응답 스키마 일치 여부는 판정하지 않습니다.', '원본 HAR는 저장하지 않습니다. 기존 헤더·쿠키·쿼리 값·본문·응답 본문은 저장하거나 재전송하지 않으며 안전한 쿼리 이름만 사용합니다.', 'GET/HEAD 이외의 요청과 지정한 출처·경로 밖의 요청, 정적 파일은 제외했습니다. 관측되지 않은 API는 포함하지 않습니다.', '요청 경로는 근거로 보존합니다. 명확한 토큰 경로는 제외하지만 경로 자체에 포함된 임의의 개인 정보·비밀 값은 업로드 전에 제거하세요.']}
    if accepted_origin != runtime_origin:
        report['warnings'].append('사용자가 지정한 HAR 원본 출처의 경로를 등록한 실행 주소에 명시적으로 대응시켰습니다.')
    return make_schema(runtime_origin, result), result, report


class Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script' and values.get('src'):
            self.scripts.append(values['src'])
        elif tag == 'a' and values.get('href'):
            self.links.append(values['href'])


def static_js_paths(text):
    """Resolve only literal fetch/get URLs and literal-variable + literal-object-member pairs.

    No eval, source maps, general JavaScript interpretation, route dictionaries, or
    Cartesian product of service prefixes and endpoints. Ambiguous names are discarded.
    All static findings remain inferred GET candidates, not observed API responses.
    """
    literal = r'"([^"\\\r\n]{1,500})"|\'([^\'\\\r\n]{1,500})\''
    constants = collections.defaultdict(set)
    for m in re.finditer(r'(?:[,;]|\b(?:const|let|var)\s+)([A-Za-z_$][\w$]*)\s*=\s*(?:' + literal + ')', text):
        constants[m[1]].add(m[2] or m[3])
    objects = collections.defaultdict(lambda: collections.defaultdict(set))
    for obj in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*=\s*\{([^{}]{1,20000})\}', text):
        for member in re.finditer(r'(?:^|,)\s*([A-Za-z_$][\w$]*)\s*:\s*(?:' + literal + ')', obj[2]):
            objects[obj[1]][member[1]].add(member[2] or member[3])
    found = set()
    # Literal fetch and .get calls preserve explicit read methods when available.
    for m in re.finditer(r'(?:\bfetch|\baxios\.get)\s*\(\s*(?:' + literal + ')', text):
        context = text[m.end():m.end() + 250]
        method = re.search(r'\bmethod\s*:\s*["\']([A-Z]+)["\']', context)
        if not method or method[1] in ('GET', 'HEAD'):
            found.add(m[1] or m[2])
    for m in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*\+\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)', text):
        if not re.search(r'(?:\bconst\s+|\blet\s+|\bvar\s+|[,;])\s*[A-Za-z_$][\w$]*\s*=\s*$', text[max(0, m.start()-80):m.start()]):
            continue
        left, right = constants[m[1]], objects[m[2]][m[3]]
        if len(left) != 1 or len(right) != 1:
            continue
        path = next(iter(left)) + next(iter(right))
        # Require an actual nearby read request in the same straight-line expression.
        context = re.split(r'\bfunction\b', text[m.end():m.end() + 700], maxsplit=1)[0]
        method = re.search(r'\bmethod\s*:\s*["\']([A-Z]+)["\']', context)
        if method and method[1] in ('GET', 'HEAD') and re.search(r'\bfetch\s*\(|\.get\s*\(', context[:method.start()+1]):
            found.add(path)
    return sorted(found)[:MAX_OPERATIONS]


def checked_fetch(url, timeout, validate_url, byte_budget=None):
    """Resolve and pin the connection to a checked IP; no proxies or redirects."""
    deadline = time.monotonic() + timeout
    response_limit = min(MAX_RESPONSE, byte_budget['remaining']) if byte_budget is not None else MAX_RESPONSE
    if response_limit <= 0:
        raise ValueError('discovery total response-byte budget exhausted')
    validate_url(url)
    p = urllib.parse.urlsplit(url)
    port = p.port or (443 if p.scheme == 'https' else 80)
    resolved = queue.Queue(maxsize=1)
    def resolve():
        try:
            resolved.put((socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM), None))
        except OSError as error:
            resolved.put((None, error))
    # A slow OS resolver cannot hold a request worker beyond its deadline.
    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses, error = resolved.get(timeout=max(0.001, deadline-time.monotonic()))
    except queue.Empty:
        raise ValueError('discovery DNS lookup exceeded the request deadline')
    if error:
        raise error
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split('%')[0])
        mapped = ip.ipv4_mapped if ip.version == 6 else None
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or (mapped and (mapped.is_loopback or mapped.is_link_local or mapped.is_unspecified or mapped.is_multicast)):
            raise ValueError('discovery resolved to a blocked address')
    if not addresses:
        raise ValueError('discovery host did not resolve')
    ip = addresses[0][4][0]
    def remaining_timeout():
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise ValueError('discovery connection exceeded the request deadline')
        return remaining
    connection = (http.client.HTTPSConnection if p.scheme == 'https' else http.client.HTTPConnection)(p.hostname, port, timeout=remaining_timeout())
    # HTTPSConnection still verifies the certificate and SNI against the original host.
    # Recompute when connect actually starts: DNS and setup consumed part of the
    # same request budget, and the watchdog cannot shut down an uncreated socket.
    connection._create_connection = lambda address, timeout=None, source_address=None, **kwargs: socket.create_connection((ip, port), remaining_timeout(), source_address)
    active_socket = [None]
    expired = threading.Event()
    def abort():
        expired.set()
        live = connection.sock or active_socket[0]
        if live:
            try:
                live.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        # The reading thread owns HTTPResponse.close(); closing it concurrently
        # can race its buffered reader. Socket shutdown is enough to interrupt it.
    watchdog = threading.Timer(max(0.001, deadline-time.monotonic()), abort)
    watchdog.daemon = True
    watchdog.start()
    try:
        connection.request('GET', p.path or '/', headers={'User-Agent': 'AegisLoop-API-Discovery/1', 'Accept': 'text/html,application/json,text/javascript,*/*;q=0.1', 'Accept-Encoding': 'identity'})
        connected_socket = connection.sock
        active_socket[0] = connected_socket
        response = connection.getresponse()
        if expired.is_set() or time.monotonic() >= deadline:
            raise ValueError('discovery response exceeded the request deadline')
        if 300 <= response.status < 400:
            return response.status, '', b''
        if response.getheader('Content-Encoding', 'identity').lower() not in ('identity', ''):
            raise ValueError('compressed discovery response skipped')
        if int(response.getheader('Content-Length', '0')) > response_limit:
            raise ValueError('discovery response exceeds the remaining response-byte budget')
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('discovery response exceeded the request deadline')
            if connected_socket:
                connected_socket.settimeout(remaining)
            available = response_limit - size
            if available <= 0:
                if response.length == 0:
                    break
                # Unknown/chunked lengths at the exact boundary are conservatively
                # skipped rather than reading one more byte outside the budget.
                raise ValueError('discovery response exhausted the response-byte budget')
            chunk = response.read1(min(64 * 1024, available))
            if byte_budget is not None:
                # Charge immediately, including a chunk arriving at the deadline
                # and all bytes from responses later rejected or interrupted.
                byte_budget['used'] += len(chunk)
                byte_budget['remaining'] -= len(chunk)
            if expired.is_set() or time.monotonic() >= deadline:
                raise ValueError('discovery response exceeded the request deadline')
            if not chunk:
                break
            size += len(chunk)
            chunks.append(chunk)
        data = b''.join(chunks)
        return response.status, response.getheader('Content-Type', '').lower(), data
    finally:
        watchdog.cancel()
        connection.close()


def from_url(base_url, validate_url, fetch=None):
    runtime_origin = origin(base_url)
    prefix = safe_path(urllib.parse.urlsplit(base_url).path or '/')
    seed = runtime_origin + prefix
    deadline = time.monotonic() + MAX_SECONDS
    queue = collections.deque([(seed, 'page', 0)])
    visited, operations, omitted = set(), {}, collections.Counter()
    requested = pages = 0
    byte_budget = {'used': 0, 'remaining': MAX_TOTAL}
    custom_fetch = fetch is not None
    fetch = fetch or (lambda url, timeout: checked_fetch(url, timeout, validate_url, byte_budget))

    def scoped(candidate, document):
        # Reject protocol-relative links instead of treating them as trusted same origin.
        if not isinstance(candidate, str) or candidate.startswith('//') or '\\' in candidate or len(candidate) > 2048:
            raise ValueError('invalid link')
        candidate = urllib.parse.urljoin(document, candidate)
        p = urllib.parse.urlsplit(candidate)
        if origin(candidate) != runtime_origin:
            raise ValueError('other origin')
        path = safe_path(p.path or '/')
        if not within(path, prefix):
            raise ValueError('outside path scope')
        return runtime_origin + path, query_names(p.query)

    def add(candidate, document, source, confidence):
        try:
            clean, names = scoped(candidate, document)
        except (ValueError, TypeError):
            omitted['outside_or_unresolved'] += 1
            return
        path = urllib.parse.urlsplit(clean).path
        key = 'GET ' + path
        if key not in operations and len(operations) >= MAX_OPERATIONS:
            omitted['operation_limit'] += 1
            return
        previous = operations.get(key, {})
        operations[key] = {'id': key, 'method': 'GET', 'path': path, 'source': source if not previous or confidence == 'observed' else previous['source'], 'confidence': 'observed' if confidence == 'observed' or previous.get('confidence') == 'observed' else 'candidate', 'query_parameters': sorted(set(names) | set(previous.get('query_parameters', [])))[:50]}

    while queue and requested < MAX_REQUESTS and time.monotonic() < deadline and byte_budget['remaining'] > 0:
        current, kind, depth = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        requested += 1
        try:
            status, content_type, data = fetch(current, min(4, max(0.1, deadline - time.monotonic())))
        except (ValueError, OSError, http.client.HTTPException):
            omitted['fetch_failed_or_size_limit'] += 1
            continue
        if custom_fetch:
            # Injected test fetchers return an already bounded response buffer.
            if len(data) > byte_budget['remaining']:
                omitted['byte_limit'] += 1
                break
            byte_budget['used'] += len(data)
            byte_budget['remaining'] -= len(data)
        if 300 <= status < 400:
            omitted['redirect_not_followed'] += 1
            continue
        if 'json' in content_type:
            add(current, current, 'http_json_response', 'observed')
            continue
        text = data.decode('utf-8', errors='replace')
        if kind == 'script' or 'javascript' in content_type:
            for path in static_js_paths(text):
                add(path, seed, 'static_javascript', 'candidate')
            continue
        if 'html' not in content_type and not text.lstrip().lower().startswith(('<!doctype html', '<html')):
            omitted['unsupported_content'] += 1
            continue
        pages += 1
        parser = Links()
        parser.feed(text)
        for script in parser.scripts[:50]:
            try:
                url, _ = scoped(script, current)
                if url not in visited:
                    queue.append((url, 'script', depth))
            except ValueError:
                omitted['outside_or_unresolved'] += 1
        for link in parser.links[:100]:
            try:
                url, _ = scoped(link, current)
                path = urllib.parse.urlsplit(url).path
                if API_PATH.search(path):
                    add(link, current, 'html_link', 'candidate')
                elif depth < 2 and not path.lower().endswith(STATIC_EXT) and url not in visited:
                    queue.append((url, 'page', depth + 1))
            except ValueError:
                omitted['outside_or_unresolved'] += 1
    if queue:
        omitted['crawl_limit'] += len(queue)
    if byte_budget['remaining'] <= 0:
        omitted['byte_limit'] += 1
    if not operations:
        raise ValueError(f'URL 탐색 {requested}회에서 API 경로를 확인하지 못했습니다. 로그인 후 저장한 HAR 또는 실제 JSON API 주소를 사용하세요. 리다이렉트·동적 JavaScript 실행은 지원하지 않습니다.')
    result = sorted(operations.values(), key=lambda item: item['id'])
    report = {'mode': 'url', 'summary': f'URL 탐색 {requested}회에서 GET 작업 후보 {len(result)}개를 찾았습니다.', 'requests': requested, 'pages': pages, 'bytes_read': byte_budget['used'], 'omitted': dict(omitted), 'scope_url': base_url, 'warnings': ['HTML 링크와 정적 JavaScript 문자열에서 찾은 경로는 추정 후보입니다. 인증 후 동적 호출과 계산된 경로는 누락될 수 있습니다.', '동일 출처·입력 경로 안에서 최대 20회·30초·응답 본문 합계 8 MiB만 읽습니다. 실패·중단 응답의 수신 본문도 한도에 포함하며 리다이렉트, JavaScript 실행, 사전식 경로 대입은 하지 않습니다.', '생성된 문서는 요청 목록이며 응답 계약이 아닙니다. 진단에서는 서버 오류만 검사하고 응답 스키마 일치 여부는 판정하지 않습니다.', '발견한 경로를 선택한 뒤 진단을 실행하세요. 미발견은 API 또는 취약점이 없다는 뜻이 아닙니다.']}
    return make_schema(runtime_origin, result), result, report
