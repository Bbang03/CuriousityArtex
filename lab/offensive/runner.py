"""Bounded Offensive assessments of immutable uploaded targets and bundled examples."""
from __future__ import annotations

import datetime as dt
import base64
import binascii
import hashlib
import hmac
import http.server
import json
import io
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile

import api_discovery

MAX_ARTIFACT = 16 * 1024 * 1024
MAX_CANDIDATES = 100
MAX_RUNS = 100
MAX_SCHEMA = 8 * 1024 * 1024
MAX_ZIP = 20 * 1024 * 1024
MAX_UPLOAD_BODY = 28 * 1024 * 1024
MAX_EXPANDED = 100 * 1024 * 1024
MAX_FILES = 10000
MAX_OPERATIONS = 40
SOURCE_EXTENSIONS = {'.java': 'Java', '.py': 'Python', '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript'}
SKIP_DIRECTORIES = {'.git', '.svn', '.hg', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', 'dist', 'build', 'target', '.next', '.aws', '.ssh'}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SECRET_KEYS = re.compile(r"^(authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|access_token|refresh_token|token|api[-_]key|jwt)$", re.I)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def redact(value, secrets_to_hide=()):
    if isinstance(value, dict):
        # HAR represents headers as name/value objects.
        if isinstance(value.get("name"), str) and SECRET_KEYS.match(value["name"]):
            return {**value, "value": "[REDACTED]"}
        return {str(k): "[REDACTED]" if SECRET_KEYS.match(str(k)) else redact(v, secrets_to_hide) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets_to_hide) for v in value]
    if not isinstance(value, str):
        return value
    for secret in secrets_to_hide:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?i)(authorization|proxy-authorization)(\s*[:=]\s*)([^\r\n]+)", r"\1\2[REDACTED]", value)
    value = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", value)
    value = re.sub(r'(?i)(["\']?(?:password|access_token|refresh_token|api_key|token|secret)["\']?\s*[:=]\s*)["\']?[^\s,"\'}]+', r'\1[REDACTED]', value)
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fixed_url(value):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("OFFENSIVE_CRAPI_URL must be an HTTP origin without credentials or paths")
    # Target comes only from operator configuration, never a request/model parameter.
    return value.rstrip("/")


def target_url(value, resolve=False):
    """The user chooses a single origin and optional prefix, never schema-provided hosts."""
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 or c == '\\' for c in value):
        raise ValueError("API base URL is invalid")
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("API base URL must be http(s), without credentials, query, or fragment")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("API port is invalid")
    host = parts.hostname.lower().rstrip('.')
    denied = {'localhost', 'metadata.google.internal', 'metadata', 'instance-data', 'offensive-runner', 'artex', 'artex-local-artex-1'}
    if host in denied or host.endswith(('.localhost', '.internal.metadata.google')) or port in (8090, 8787, 8788):
        raise ValueError("loopback, metadata, and management endpoints cannot be assessment targets")
    decoded_path = urllib.parse.unquote(parts.path)
    if '\\' in decoded_path or '//' in decoded_path or any(p in ('.', '..') for p in decoded_path.split('/')) or any(ord(c) < 32 for c in decoded_path):
        raise ValueError("API base path is invalid")
    def check_address(address):
        ip = ipaddress.ip_address(address.split('%')[0])
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or (ip.version == 6 and ip.ipv4_mapped and (ip.ipv4_mapped.is_loopback or ip.ipv4_mapped.is_link_local)):
            raise ValueError("loopback, link-local, and metadata addresses cannot be assessment targets")
    try:
        check_address(host)
    except ValueError as exc:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise exc
    if resolve:
        try:
            addresses = socket.getaddrinfo(host, port or (443 if parts.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError("API host could not be resolved from the assessment runner")
        for entry in addresses:
            check_address(entry[4][0])
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip('/'), '', ''))


def parse_schema(content):
    if len(content) > MAX_SCHEMA:
        raise ValueError("OpenAPI document exceeds 8 MiB")
    import yaml
    try:
        decoded = content.decode('utf-8-sig')
        # Reject aliases before constructing Python objects: no YAML alias expansion or cycles.
        nodes = 0
        depth = 0
        for event in yaml.parse(decoded):
            nodes += 1
            if isinstance(event, yaml.events.AliasEvent):
                raise ValueError("YAML aliases are unsupported; upload an expanded OpenAPI document")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
            if nodes > 200000 or depth > 80:
                raise ValueError("OpenAPI document is too complex")
        class UniqueLoader(yaml.SafeLoader):
            pass
        def unique_mapping(loader, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if not isinstance(key, (str, int)) or key in result:
                    raise ValueError("duplicate or unsupported OpenAPI mapping key")
                result[key] = loader.construct_object(value_node, deep=deep)
            return result
        UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
        schema = yaml.load(decoded, Loader=UniqueLoader)
    except (UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise ValueError("upload a valid UTF-8 OpenAPI JSON or YAML document") from exc
    if not isinstance(schema, dict) or not isinstance(schema.get('paths'), dict) or not (str(schema.get('openapi', '')).startswith('3.') or schema.get('swagger') == '2.0'):
        raise ValueError("OpenAPI 3.x or Swagger 2.0 with paths is required")
    return schema


def schema_operations(schema):
    operations = []
    if not all(isinstance(path, str) for path in schema['paths']):
        raise ValueError('OpenAPI path names must be strings')
    for path, item in sorted(schema['paths'].items()):
        if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or len(path) > 500:
            raise ValueError("OpenAPI paths must be relative paths beginning with one slash")
        decoded = urllib.parse.unquote(path)
        if any(c in decoded for c in ('\\', '?', '#')) or any(ord(c) < 32 or ord(c) == 127 for c in decoded) or '://' in decoded or '//' in decoded or any(p in ('.', '..') for p in decoded.split('/')):
            raise ValueError("OpenAPI path escapes the registered API scope")
        if not isinstance(item, dict) or '$ref' in item:
            raise ValueError("OpenAPI path items must be inline operation objects")
        for method in ('get', 'head'):
            if method in item:
                if not isinstance(item[method], dict) or not isinstance(item[method].get('responses'), dict):
                    raise ValueError("OpenAPI operations require response definitions")
                operations.append({'id': f'{method.upper()} {path}', 'method': method.upper(), 'path': path})
    if not operations:
        raise ValueError("this version requires at least one GET or HEAD operation")
    if len(operations) > 500:
        raise ValueError("upload an OpenAPI scope with no more than 500 GET/HEAD operations")
    return operations


def clean_schema(value, named_map=False):
    """Keep schema structure, remove alternate destinations and credential-bearing examples."""
    if isinstance(value, dict):
        if not named_map and '$ref' in value and (not isinstance(value['$ref'], str) or not value['$ref'].startswith('#/')):
            raise ValueError("external schema references are not allowed")
        if named_map:
            # A response can legitimately contain fields called `servers`, `example`, or `$ref`.
            return {str(k): clean_schema(v) for k, v in value.items()}
        maps = {'properties', 'patternProperties', 'definitions', '$defs', 'schemas', 'paths', 'responses', 'content', 'headers', 'securitySchemes', 'requestBodies', 'parameters', 'encoding', 'dependentSchemas'}
        return {str(k): clean_schema(v, named_map=k in maps and isinstance(v, dict)) for k, v in value.items() if k not in ('servers', 'links', 'callbacks', 'externalDocs', 'example', 'examples', 'default') and not str(k).startswith('x-')}
    if isinstance(value, list):
        return [clean_schema(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ValueError("OpenAPI values must be JSON-compatible")


class Runner:
    def __init__(self, data_dir=None, token=None, benchmark=None, schema=None, rules=None):
        self.root = Path(data_dir or os.getenv("OFFENSIVE_DATA_DIR", "/data/offensive/runs"))
        self.root.mkdir(parents=True, exist_ok=True)
        self.targets_root = Path(os.getenv("OFFENSIVE_TARGETS_DIR", str(self.root.parent / "targets")))
        self.targets_root.mkdir(parents=True, exist_ok=True)
        if token is None:
            token_path = os.getenv("ARTEX_OFFENSIVE_TOKEN_FILE", "")
            token = Path(token_path).read_text().strip() if token_path else ""
        if len(token) < 24:
            raise ValueError("ARTEX_OFFENSIVE_TOKEN_FILE must contain a shared token of at least 24 characters")
        self.token = token
        self.benchmark = Path(benchmark or os.getenv("OFFENSIVE_BENCHMARK_PATH", "/opt/benchmark"))
        self.schema_root = Path(schema or os.getenv("OFFENSIVE_SCHEMA_PATH", "/opt/crapi-schema"))
        self.rules = Path(rules or os.getenv("OFFENSIVE_RULES_PATH", "/app/rules/java-security.yml"))
        self.url = fixed_url(os.getenv("OFFENSIVE_CRAPI_URL", "http://crapi-web:80"))
        self.semgrep = os.getenv("SEMGREP_BIN", "/opt/semgrep/bin/semgrep")
        self.st = os.getenv("SCHEMATHESIS_BIN", "/opt/schemathesis/bin/st")
        self.lock = threading.RLock()
        self.opener = urllib.request.build_opener(NoRedirect)
        self.version_cache = {}
        self.recover()

    def target_path(self, target_id):
        if not isinstance(target_id, str) or not UUID_RE.fullmatch(target_id):
            raise ValueError("invalid uploaded target ID")
        path = self.targets_root / target_id
        if path.is_symlink():
            raise ValueError("invalid target directory")
        return path

    def example_target(self, target_id):
        if target_id == 'crapi':
            return {'id': 'crapi', 'kind': 'api', 'name': 'OWASP crAPI', 'origin': 'example', 'url': self.url, 'revision': os.getenv('OFFENSIVE_CRAPI_REVISION', 'unknown'), 'operations': []}
        if target_id == 'benchmark':
            return {'id': 'benchmark', 'kind': 'source', 'name': 'OWASP Benchmark Java', 'origin': 'example', 'source_path': '/app/offensive/benchmark', 'revision': os.getenv('OFFENSIVE_BENCHMARK_REVISION', 'unknown'), 'languages': ['Java']}
        raise ValueError('unknown example target')

    def get_target(self, target_id):
        if target_id in ('crapi', 'benchmark'):
            return self.example_target(target_id)
        path = self.target_path(target_id) / 'target.json'
        try:
            if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise ValueError('invalid target metadata')
            target = json.loads(path.read_text())
        except FileNotFoundError:
            raise ValueError('registered target was not found')
        if target.get('id') != target_id or target.get('kind') not in ('api', 'source') or target.get('origin') != 'upload':
            raise ValueError('invalid target metadata')
        return target

    def register_target(self, body):
        if not isinstance(body, dict):
            raise ValueError('target registration must be an object')
        mode = body.get('input_mode', 'openapi')
        if mode not in ('openapi', 'har', 'url') or (body.get('kind') == 'source' and mode != 'openapi'):
            raise ValueError('unsupported target input mode')
        required = {'kind', 'name'} if mode == 'url' else {'kind', 'name', 'filename', 'content_base64'}
        optional = {'base_url', 'input_mode'} | ({'har_origin'} if mode == 'har' else set())
        if not required <= set(body) or set(body) - required - optional:
            raise ValueError('provide target metadata and the file required by the selected input mode')
        kind, name, filename = body['kind'], body['name'], body.get('filename', '')
        if kind not in ('api', 'source') or not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or any(ord(c) < 32 for c in name):
            raise ValueError('target kind or name is invalid')
        if mode != 'url' and (not isinstance(filename, str) or not 1 <= len(filename) <= 255 or '/' in filename or '\\' in filename or any(ord(c) < 32 for c in filename)):
            raise ValueError('upload filename is invalid')
        encoded = body.get('content_base64', '')
        if not isinstance(encoded, str) or len(encoded) > MAX_UPLOAD_BODY:
            raise ValueError('upload exceeds the configured limit')
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError('upload content must be base64')
        if mode != 'url' and (not content or len(content) > (api_discovery.MAX_HAR if mode == 'har' else MAX_SCHEMA if kind == 'api' else MAX_ZIP)):
            raise ValueError('OpenAPI limit is 8 MiB; HAR limit is 16 MiB; source ZIP limit is 20 MiB')
        if kind == 'source' and body.get('base_url'):
            raise ValueError('source targets do not accept an API URL')
        target_id = str(uuid.uuid4())
        target = {'id': target_id, 'kind': kind, 'name': name.strip(), 'filename': filename, 'origin': 'upload', 'created_at': now(), 'sha256': hashlib.sha256(content).hexdigest()}
        # A failed upload never becomes visible in the catalog.
        with tempfile.TemporaryDirectory(prefix='.upload-', dir=self.targets_root) as tmp:
            folder = Path(tmp)
            if kind == 'api':
                url = target_url(body.get('base_url', ''))
                if mode == 'url' and urllib.parse.urlsplit(body['base_url']).path.endswith('/'):
                    url += '/'
                if mode in ('har', 'url'):
                    scope_url = api_discovery.origin(url) + urllib.parse.urlsplit(url).path
                    if mode == 'har':
                        if Path(filename).suffix.lower() not in ('.har', '.json'):
                            raise ValueError('upload a .har or HAR .json file')
                        schema, operations, discovery = api_discovery.from_har(content, scope_url, body.get('har_origin', ''))
                    else:
                        schema, operations, discovery = api_discovery.from_url(scope_url, target_url)
                    url = api_discovery.origin(url)
                    discovery_blob = json.dumps(discovery, ensure_ascii=False, indent=2).encode()
                    (folder / 'discovery.json').write_bytes(discovery_blob)
                    target.update(scope_url=scope_url, discovery=discovery, discovery_sha256=hashlib.sha256(discovery_blob).hexdigest())
                    if mode == 'har':
                        target['har_origin'] = discovery['har_origin']
                else:
                    if Path(filename).suffix.lower() not in ('.json', '.yaml', '.yml'):
                        raise ValueError('upload an OpenAPI .json, .yaml, or .yml file')
                    schema = clean_schema(parse_schema(content))
                    operations = schema_operations(schema)
                    if schema.get('swagger'):
                        parsed = urllib.parse.urlsplit(url)
                        schema.update(host=parsed.netloc, schemes=[parsed.scheme], basePath=parsed.path or '/')
                    else:
                        schema['servers'] = [{'url': url}]
                blob = json.dumps(schema, ensure_ascii=False, indent=2).encode()
                (folder / 'openapi.json').write_bytes(blob)
                if mode == 'url':
                    target['sha256'] = hashlib.sha256(blob).hexdigest()
                target.update(input_mode=mode, url=url, operations=operations, schema_sha256=hashlib.sha256(blob).hexdigest(), detail='찾은 GET/HEAD 경로 중 검사할 항목을 선택하세요. 응답 계약 없이 서버 오류를 검사하며 보안 취약점 확정과는 구분합니다.' if mode in ('har', 'url') else '업로드한 명세의 GET/HEAD 작업을 선택합니다. 주소 연결과 인증은 실행 시 확인합니다. 예제·기본값과 명세 내 다른 서버는 사용하지 않습니다.')
            else:
                if Path(filename).suffix.lower() != '.zip':
                    raise ValueError('upload a .zip source archive')
                target.update(self.extract_source(content, folder / 'source'))
                target.update(source_path=f'/app/data/offensive/targets/{target_id}/source', detail='업로드한 Java·Python·JavaScript·TypeScript 소스를 로컬 규칙으로 분석합니다. 프로젝트 코드나 빌드 스크립트는 실행하지 않습니다.')
            metadata = json.dumps(target, ensure_ascii=False, indent=2).encode()
            if len(metadata) > 1024 * 1024:
                raise ValueError('target inventory metadata exceeds 1 MiB; narrow the API scope or HAR capture')
            (folder / 'target.json').write_bytes(metadata)
            os.rename(folder, self.target_path(target_id))
        return {**target, 'ready': bool(self.tool_version(self.st if kind == 'api' else self.semgrep))}

    def extract_source(self, content, destination):
        try:
            archive = zipfile.ZipFile(io.BytesIO(content))
        except zipfile.BadZipFile:
            raise ValueError('source upload is not a valid ZIP archive')
        with archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise ValueError('ZIP may contain at most 10,000 entries')
            total = 0
            seen = set()
            accepted = []
            skipped = {}
            for entry in entries:
                raw = entry.filename
                path = PurePosixPath(raw)
                if not raw or '\\' in raw or raw.startswith('/') or re.match(r'^[A-Za-z]:', raw) or any(p in ('', '.', '..') for p in raw.rstrip('/').split('/')) or any(ord(c) < 32 for c in raw):
                    raise ValueError('ZIP contains an unsafe path')
                key = str(path).casefold()
                if key in seen:
                    raise ValueError('ZIP contains duplicate or case-colliding paths')
                seen.add(key)
                mode = (entry.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR) or (entry.flag_bits & 1):
                    raise ValueError('ZIP links, special files, and encrypted files are unsupported')
                total += entry.file_size
                if total > MAX_EXPANDED or (entry.file_size > 1024 * 1024 and entry.file_size > max(1, entry.compress_size) * 1000):
                    raise ValueError('ZIP exceeds expansion limits (100 MiB)')
                if entry.is_dir():
                    continue
                lower_parts = [part.lower() for part in path.parts]
                basename = path.name.lower()
                if any(part in SKIP_DIRECTORIES for part in lower_parts[:-1]) or basename == '.env' or basename.startswith('.env.') or basename in ('credentials', 'id_rsa', 'id_ed25519') or path.suffix.lower() in ('.pem', '.key', '.p12', '.pfx'):
                    reason = '의존성·빌드 결과·버전 관리·인증 파일'
                elif path.suffix.lower() not in SOURCE_EXTENSIONS:
                    reason = '지원하지 않는 파일 형식'
                elif entry.file_size > 1000000:
                    reason = '1 MB를 초과하는 소스 파일'
                else:
                    accepted.append((entry, path))
                    continue
                skipped[reason] = skipped.get(reason, 0) + 1
            if not accepted:
                raise ValueError('ZIP contains no supported Java, Python, JavaScript, or TypeScript source files')
            destination.mkdir(parents=True)
            manifest = []
            try:
                for entry, relative in accepted:
                    path = destination.joinpath(*relative.parts)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(entry) as stream:
                        data = stream.read(1000001)
                    if len(data) != entry.file_size or len(data) > 1000000 or b'\x00' in data:
                        raise ValueError('source file is binary or exceeds its ZIP metadata limit')
                    path.write_bytes(data)
                    path.chmod(0o644)
                    manifest.append({'file': relative.as_posix(), 'sha256': hashlib.sha256(data).hexdigest()})
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as exc:
                raise ValueError('ZIP extraction failed; check archive integrity and paths') from exc
            manifest_blob = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode()
            (destination.parent / 'source-manifest.json').write_bytes(manifest_blob)
            return {'file_count': len(manifest), 'languages': sorted({SOURCE_EXTENSIONS[path.suffix.lower()] for _, path in accepted}), 'omitted_file_count': sum(skipped.values()), 'omissions': [{'reason': reason, 'count': count} for reason, count in sorted(skipped.items())], 'manifest_sha256': hashlib.sha256(manifest_blob).hexdigest()}

    def path(self, run_id):
        if not isinstance(run_id, str) or not UUID_RE.fullmatch(run_id):
            raise ValueError("invalid run ID")
        path = self.root / run_id
        if path.is_symlink():
            raise ValueError("invalid run directory")
        return path

    def recover(self):
        for path in self.root.glob("*/run.json"):
            try:
                run = json.loads(path.read_text())
                if run.get("status") in ("running", "queued"):
                    run.update(status="interrupted", finished_at=now(), error="Runner restarted before the scan finished. Start a new assessment.")
                    self.save(run)
            except (ValueError, OSError):
                continue

    def save(self, run):
        folder = self.path(run["id"])
        folder.mkdir(exist_ok=True)
        temporary = folder / ".run.json.tmp"
        temporary.write_text(json.dumps(redact(run, (self.token,)), ensure_ascii=False, indent=2))
        os.replace(temporary, folder / "run.json")

    def get(self, run_id):
        with self.lock:
            try:
                return json.loads((self.path(run_id) / "run.json").read_text())
            except FileNotFoundError:
                raise LookupError("assessment not found")

    def list(self):
        with self.lock:
            runs = []
            for path in self.root.glob("*/run.json"):
                try:
                    runs.append(self.get(path.parent.name))
                except (ValueError, LookupError, OSError):
                    continue
            return sorted(runs, key=lambda r: r.get("created_at", ""), reverse=True)[:MAX_RUNS]

    def tool_version(self, executable):
        if executable in self.version_cache:
            return self.version_cache[executable]
        if not shutil.which(executable):
            return ""
        try:
            version = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=12, env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}).stdout.strip().splitlines()[-1]
        except (OSError, subprocess.SubprocessError, IndexError):
            return ""
        self.version_cache[executable] = version[:120]
        return self.version_cache[executable]

    def schema_file(self):
        import yaml
        paths = [self.schema_root] if self.schema_root.is_file() else sorted(self.schema_root.rglob("*"))
        candidates = []
        for path in paths:
            if path.suffix.lower() not in (".json", ".yaml", ".yml") or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
                continue
            try:
                schema = yaml.safe_load(path.read_text())
                if isinstance(schema, dict) and isinstance(schema.get("paths"), dict) and (schema.get("openapi") or schema.get("swagger")):
                    candidates.append((len(schema["paths"]), path, schema))
            except (ValueError, OSError, yaml.YAMLError):
                continue
        if not candidates:
            raise ValueError("official crAPI OpenAPI schema is not mounted")
        _, path, schema = max(candidates, key=lambda item: item[0])
        return path, schema

    def catalog(self):
        semgrep, st = self.tool_version(self.semgrep), self.tool_version(self.st)
        try:
            self.schema_file()
            schema_ready = True
        except (ValueError, ImportError):
            schema_ready = False
        try:
            response = self.opener.open(self.url + "/", timeout=3)
            alive = response.status < 500
            response.close()
        except urllib.error.HTTPError as exc:
            alive = exc.code < 500
        except (OSError, urllib.error.URLError):
            alive = False
        source_ready = (self.benchmark / "src/main/java/org/owasp/benchmark/testcode").is_dir()
        targets = [
            {**self.example_target('crapi'), "ready": bool(st and schema_ready and alive), "detail": "설치된 예제: 공식 OpenAPI의 GET 작업을 제한된 예제로 검사합니다. 인증·인가 전체 검증은 ARTEX 후속 조사가 필요합니다." if alive else "crAPI 서비스 연결을 확인하세요."},
            {**self.example_target('benchmark'), "ready": bool(semgrep and source_ready and self.rules.is_file()), "detail": "설치된 예제: Java 소스와 로컬 검토 규칙으로 정적 후보를 찾습니다. 정답 데이터는 검사 대상에서 제외됩니다."}
        ]
        for path in sorted(self.targets_root.glob('*/target.json')):
            try:
                target = self.get_target(path.parent.name)
                targets.append({**target, 'ready': bool(st if target['kind'] == 'api' else semgrep)})
            except (ValueError, OSError, KeyError):
                continue
        return {"targets": targets, "tools": [{"id": "semgrep", "version": semgrep, "available": bool(semgrep)}, {"id": "schemathesis", "version": st, "available": bool(st)}]}

    def create(self, body, asynchronous=True):
        if not isinstance(body, dict) or not {'kind', 'target_id'} <= set(body) or set(body) - {'kind', 'target_id', 'operation_ids', 'bearer_token'}:
            raise ValueError("only registered targets and supported assessment options are allowed")
        target = self.get_target(body['target_id'])
        if body['kind'] != target['kind']:
            raise ValueError('target kind does not match the registered target')
        bearer = body.get('bearer_token', '')
        if not isinstance(bearer, str) or len(bearer) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in bearer):
            raise ValueError('bearer token is invalid')
        operations = body.get('operation_ids', [])
        if not isinstance(operations, list) or not all(isinstance(v, str) for v in operations) or len(operations) != len(set(operations)):
            raise ValueError('select distinct registered API operations')
        if body['kind'] == 'source' and (operations or bearer):
            raise ValueError('source assessments do not accept API authentication or operations')
        if target['kind'] == 'api' and target['origin'] == 'upload':
            valid = {item['id'] for item in target['operations']}
            if not operations:
                operations = sorted(valid)[:MAX_OPERATIONS]
            if len(operations) > MAX_OPERATIONS or any(item not in valid for item in operations):
                raise ValueError('select 1–40 GET/HEAD operations from the uploaded document')
        elif operations:
            raise ValueError('bundled examples use their predefined operation scope')
        with self.lock:
            if any(r.get("status") in ("queued", "running") for r in self.list()):
                raise RuntimeError("another assessment is running")
            run_id = str(uuid.uuid4())
            source = body["kind"] == "source"
            run = {"id": run_id, "kind": body['kind'], "target_id": target['id'], 'target_snapshot': target, 'operation_ids': operations, "status": "queued", "created_at": now(), "tool": "semgrep" if source else "schemathesis", "tool_version": self.tool_version(self.semgrep if source else self.st), "target": target.get('source_path') if source else target['url'], "source_revision": target.get('revision', target.get('sha256', 'unknown')), "summary": "진단 대기 중", "candidates": [], "limitations": [], "artifacts": []}
            if not run["tool_version"]:
                raise ValueError("diagnosis tool is not available")
            self.save(run)
            if asynchronous:
                threading.Thread(target=self.execute, args=(run_id, bearer), daemon=True).start()
            return run

    def bind(self, run_id, body):
        if not isinstance(body, dict) or set(body) != {"task_id"} or not isinstance(body["task_id"], str) or not re.fullmatch(r"[1-9][0-9]{0,18}", body["task_id"]):
            raise ValueError("task_id must be a positive integer string")
        with self.lock:
            run = self.get(run_id)
            if run.get("status") != "completed":
                raise RuntimeError("only a completed assessment can be associated with ARTEX")
            if run.get("task_id") and run["task_id"] != body["task_id"]:
                raise RuntimeError("this assessment is already associated with an ARTEX task")
            run["task_id"] = body["task_id"]
            self.save(run)
            return run

    def artifact(self, run_id, name):
        run = self.get(run_id)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", name):
            raise ValueError("invalid artifact name")
        if not any(a["name"] == name for a in run.get("artifacts", [])):
            raise LookupError("artifact not found")
        path = self.path(run_id) / name
        if path.is_symlink() or path.stat().st_size > MAX_ARTIFACT:
            raise ValueError("invalid artifact")
        content = path.read_bytes()
        manifest = next(a for a in run["artifacts"] if a["name"] == name)
        if hashlib.sha256(content).hexdigest() != manifest["sha256"]:
            raise RuntimeError("artifact integrity check failed")
        return content

    def publish(self, run, name, content, hidden=(), schema=False):
        if schema:
            # OpenAPI property names such as `password` describe types, not credentials.
            # This is the exact fixed schema used by the scanner; credentials are CLI-only.
            if name != "scoped-openapi.json" or not isinstance(content, dict) or "paths" not in content:
                raise ValueError("invalid schema artifact")
        else:
            content = redact(content, (self.token, *hidden))
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False, indent=2)
        blob = content.encode()
        if len(blob) > MAX_ARTIFACT:
            raise ValueError("artifact exceeds the configured maximum")
        (self.path(run["id"]) / name).write_bytes(blob)
        run["artifacts"].append({"name": name, "path": f"/app/data/offensive/runs/{run['id']}/{name}", "sha256": hashlib.sha256(blob).hexdigest()})

    def command(self, argv, workdir, timeout=180, hidden=()):
        # No shell interpolation. Temporary raw output is removed before results are published.
        output = Path(workdir) / "command-output.txt"
        with output.open("wb") as sink:
            process = subprocess.Popen(argv, cwd=workdir, stdout=sink, stderr=subprocess.STDOUT, start_new_session=True, env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "NO_COLOR": "1", "HYPOTHESIS_STORAGE_DIRECTORY": str(Path(workdir) / "hypothesis")})
            deadline = time.monotonic() + timeout
            timed_out = False
            while process.poll() is None:
                if time.monotonic() >= deadline or output.stat().st_size > MAX_ARTIFACT:
                    os.killpg(process.pid, signal.SIGKILL)
                    timed_out = True
                    break
                time.sleep(0.15)
            process.wait()
        text = output.read_bytes()[:MAX_ARTIFACT].decode(errors="replace")
        return process.returncode, redact(text, (self.token, *hidden)), timed_out

    def execute(self, run_id, bearer_token=''):
        with self.lock:
            run = self.get(run_id)
            run.update(status="running", started_at=now(), summary="진단 도구 실행 중")
            self.save(run)
        try:
            with tempfile.TemporaryDirectory(prefix="aegis-offensive-") as tmp:
                if run["kind"] == "source":
                    self.scan_source(run, Path(tmp))
                else:
                    self.scan_api(run, Path(tmp), bearer_token)
            run["status"] = "completed"
        except Exception as exc:
            run.update(status="failed", error=redact(str(exc), (self.token, bearer_token))[:2000], summary="진단을 완료하지 못했습니다. 실행 오류와 남은 근거를 확인하세요.")
        finally:
            run["finished_at"] = now()
            # Stable review input for the ARTEX worker, without recursive self-hashing.
            self.publish(run, "report.json", dict(run))
            with self.lock:
                self.save(run)

    def source_scope(self, run):
        target = run.get('target_snapshot', self.example_target('benchmark'))
        if target.get('origin') == 'upload':
            current = self.get_target(target['id'])
            if current != target:
                raise ValueError('registered target metadata changed after this run was created')
            folder = self.target_path(target['id'])
            source = folder / 'source'
            if source.is_symlink() or any(path.is_symlink() for path in source.rglob('*')):
                raise ValueError('uploaded source cannot contain symbolic links')
            manifest_path = folder / 'source-manifest.json'
            blob = manifest_path.read_bytes()
            if hashlib.sha256(blob).hexdigest() != target['manifest_sha256']:
                raise ValueError('source manifest integrity check failed')
            manifest = json.loads(blob)
            actual_files = {path.relative_to(source).as_posix() for path in source.rglob('*') if path.is_file() or path.is_symlink()}
            if actual_files != {item['file'] for item in manifest}:
                raise ValueError('uploaded source inventory changed after registration')
            for item in manifest:
                path = source / item['file']
                if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
                    raise ValueError('uploaded source integrity check failed')
            return source, source, manifest
        source = self.benchmark / 'src/main/java/org/owasp/benchmark/testcode'
        manifest = [{'file': path.relative_to(self.benchmark).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(source.rglob('*.java')) if path.is_file() and not path.is_symlink()]
        return source, self.benchmark, manifest

    def scan_source(self, run, tmp):
        source, source_root, source_manifest = self.source_scope(run)
        uploaded = run.get('target_snapshot', {}).get('origin') == 'upload'
        if not source.is_dir() or not self.rules.is_file():
            raise ValueError('source or local Semgrep rules are not mounted')
        rule_files = [self.rules]
        if uploaded:
            extra = self.rules.parent / 'uploaded-security.yml'
            if not extra.is_file():
                raise ValueError('uploaded-source rules are not mounted')
            rule_files.append(extra)
        report = tmp / 'semgrep.json'
        argv = [self.semgrep, 'scan']
        for rules in rule_files:
            argv += ['--config', str(rules)]
        argv += ['--json', '--output', str(report), '--metrics=off', '--disable-version-check', '--jobs', '2', '--timeout', '5', '--max-target-bytes', '1000000', '--no-git-ignore']
        for extension in (sorted(SOURCE_EXTENSIONS) if uploaded else ['.java']):
            argv += ['--include', '*' + extension]
        argv += [str(source)]
        code, output, timed_out = self.command(argv, tmp, timeout=240)
        self.publish(run, 'tool-output.txt', output)
        if timed_out:
            raise ValueError('Semgrep exceeded the 240-second or output-size limit')
        if code not in (0, 1) or not report.is_file():
            raise ValueError(f'Semgrep did not produce a complete report (exit {code})')
        if report.stat().st_size > MAX_ARTIFACT:
            raise ValueError('Semgrep report exceeds the 16 MiB evidence limit')
        result = json.loads(report.read_text())
        findings = result.get('results', [])
        candidates = []
        snippets = []
        for result_item in findings[:MAX_CANDIDATES]:
            file_path = Path(result_item.get('path', ''))
            try:
                relative = file_path.resolve().relative_to(source_root.resolve()).as_posix()
            except ValueError:
                continue
            line = int(result_item.get('start', {}).get('line', 1))
            extra = result_item.get('extra', {})
            candidates.append({'id': f'C{len(candidates)+1:04d}', 'title': str(result_item.get('check_id', 'Semgrep candidate')), 'severity': 'medium' if extra.get('severity') in ('WARNING', 'ERROR') else 'low', 'verification': 'candidate', 'rule_id': result_item.get('check_id', ''), 'file': relative, 'line': line, 'message': extra.get('message', ''), 'evidence': {'source_revision': run['source_revision'], 'start_line': line, 'end_line': result_item.get('end', {}).get('line', line), 'static_only': True}})
            if len(snippets) < 20 and file_path.is_file() and not file_path.is_symlink():
                lines = file_path.read_text(errors='replace').splitlines()
                first = max(0, line - 12)
                snippets.append({'candidate_id': candidates[-1]['id'], 'file': relative, 'start_line': first + 1, 'content': '\n'.join(lines[first:line+12])})
        run['candidates'] = candidates
        scanned = len(result.get('paths', {}).get('scanned', []))
        if not scanned:
            raise ValueError('Semgrep did not analyze a supported source file; inspect tool output')
        run['summary'] = f'Semgrep 소스 {scanned}개 분석, 정적 후보 {len(findings)}건. 웹에는 {len(candidates)}건을 표시합니다. 실제 악용 가능성은 ARTEX 검토가 필요합니다.'
        run['limitations'] = ['Java·Python·JavaScript·TypeScript의 위험한 API를 찾는 제한된 로컬 규칙입니다. 전체 취약점 진단 또는 정확도 평가가 아닙니다.' if uploaded else '로컬 규칙 5개로 Java의 위험한 API 사용 지점을 찾는 제한된 정적 분석입니다. 전체 취약점 진단 또는 정확도 평가가 아닙니다.', '도달 가능한 사용자 입력, 정화, 방어 분기, 보안 용도를 검토하기 전에는 취약점으로 확정하지 않습니다.', '소스나 빌드 스크립트를 실행하지 않았으며 동적 PoC를 수행하지 않았습니다. 업로드에서 제외된 파일과 지원하지 않는 언어는 분석하지 않았습니다.' if uploaded else '동적 PoC는 실행하지 않았습니다. Benchmark 정답 파일과 테스트 라벨은 분석 입력으로 사용하지 않았습니다.']
        if uploaded:
            target = run['target_snapshot']
            run['limitations'].append('소스에 직접 포함된 비밀 값은 자동 제거를 보장하지 않습니다. 업로드와 AI 검토 전에 민감 정보를 제거하세요.')
            for omission in target.get('omissions', []):
                run['limitations'].append(f"업로드 제외: {omission['reason']} {omission['count']}개")
        if len(findings) > MAX_CANDIDATES:
            run['limitations'].append(f'UI와 ARTEX 검토 입력은 최초 {MAX_CANDIDATES}개 후보로 제한합니다. 전체 도구 결과는 semgrep.json에서 확인하세요.')
        if result.get('errors'):
            run['limitations'].append(f"Semgrep가 분석 오류 {len(result['errors'])}건을 보고했습니다. 원문 결과의 errors를 확인하세요.")
        app_path = run['target']
        normalized = json.loads(json.dumps(result).replace(str(source_root), app_path))
        self.publish(run, 'semgrep.json', normalized)
        self.publish(run, 'source-context.json', snippets)
        self.publish(run, 'source-manifest.json', source_manifest)
        import yaml
        combined_rules = {'rules': [rule for file in rule_files for rule in yaml.safe_load(file.read_text())['rules']]}
        self.publish(run, 'rules.yml', yaml.safe_dump(combined_rules, allow_unicode=True, sort_keys=False))
        self.publish(run, 'assessment.json', {'tool': run['tool'], 'tool_version': run['tool_version'], 'source_revision': run['source_revision'], 'target_snapshot': run.get('target_snapshot', {}), 'candidates': candidates, 'candidate_total': len(findings), 'limitations': run['limitations'], 'source_files_scanned': scanned})

    def prepare_schema(self, schema, target=None, operation_ids=None):
        target = target or self.example_target('crapi')
        if target.get('origin') == 'upload':
            registered = {item['id'] for item in schema_operations(schema)}
            chosen = set(operation_ids or [])
            if not chosen or len(chosen) > MAX_OPERATIONS or not chosen <= registered:
                raise ValueError('select 1–40 registered GET/HEAD operations')
        else:
            # Bundled crAPI maintains its previously reviewed GET subset.
            allowed = {'/identity/api/v2/user/dashboard', '/identity/api/v2/vehicle/vehicles', '/community/api/v2/community/posts/recent', '/workshop/api/shop/products', '/workshop/api/shop/orders/all', '/workshop/api/management/users/all'}
            chosen = {'GET ' + path for path in schema['paths'] if path in allowed and isinstance(schema['paths'][path], dict) and 'get' in schema['paths'][path]}
        selected = {}
        for path, item in sorted(schema['paths'].items()):
            if not isinstance(item, dict):
                continue
            methods = {method: item[method] for method in ('get', 'head') if method in item and f'{method.upper()} {path}' in chosen}
            if methods:
                selected[path] = {**({'parameters': item['parameters']} if 'parameters' in item else {}), **methods}
        if not selected:
            raise ValueError('schema has no supported selected GET/HEAD operations')
        # Validate all references, including components outside the selected paths.
        normalized = clean_schema(schema)
        normalized['paths'] = clean_schema({'paths': selected})['paths']
        url = target['url']
        if normalized.get('swagger'):
            parsed = urllib.parse.urlsplit(url)
            normalized.update(host=parsed.netloc, schemes=[parsed.scheme], basePath=parsed.path or '/')
        else:
            normalized['servers'] = [{'url': url}]
        return normalized

    def lab_auth(self):
        # Create one disposable ordinary lab account; credentials never leave temporary memory.
        email = f"aegis-{secrets.token_hex(6)}@example.invalid"
        password = "Aegis!" + secrets.token_urlsafe(18) + "1aA"
        def request(path, body):
            req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
            with self.opener.open(req, timeout=8) as response:
                return json.loads(response.read(128 * 1024))
        try:
            request("/identity/api/auth/signup", {"name": "Aegis local assessment", "email": email, "number": "555" + str(secrets.randbelow(10000000)).zfill(7), "password": password})
            response = request("/identity/api/auth/login", {"email": email, "password": password})
            token = response.get("token", response.get("access_token", ""))
            return token if isinstance(token, str) and 10 < len(token) < 8192 else "", [email, password]
        except (ValueError, OSError, urllib.error.URLError):
            return "", [email, password]

    def scan_api(self, run, tmp, bearer_token=''):
        target = run.get('target_snapshot', self.example_target('crapi'))
        uploaded = target.get('origin') == 'upload'
        discovered = target.get('input_mode') in ('url', 'har')
        url = target['url']
        if uploaded:
            if self.get_target(target['id']) != target:
                raise ValueError('registered target metadata changed after this run was created')
            url = target_url(url, resolve=True)
            original = self.target_path(target['id']) / 'openapi.json'
            content = original.read_bytes()
            if original.is_symlink() or hashlib.sha256(content).hexdigest() != target['schema_sha256']:
                raise ValueError('registered OpenAPI integrity check failed')
            schema = json.loads(content)
            if discovered:
                discovery_path = self.target_path(target['id']) / 'discovery.json'
                discovery_content = discovery_path.read_bytes()
                if discovery_path.is_symlink() or hashlib.sha256(discovery_content).hexdigest() != target.get('discovery_sha256'):
                    raise ValueError('registered discovery evidence integrity check failed')
                self.publish(run, 'discovery.json', json.loads(discovery_content))
        else:
            original, schema = self.schema_file()
        scoped = self.prepare_schema(schema, target, run.get('operation_ids'))
        schema_file = tmp / "scoped-openapi.json"
        schema_file.write_text(json.dumps(scoped))
        if bearer_token:
            token, hidden = bearer_token, [bearer_token]
        elif uploaded:
            token, hidden = '', []
        else:
            token, hidden = self.lab_auth()
            hidden.append(token)
        junit = tmp / "junit.xml"
        har = tmp / "http.har"
        checks = 'not_a_server_error' if discovered else 'not_a_server_error,status_code_conformance,response_schema_conformance'
        argv = [self.st, "run", str(schema_file), "--url", url, "--workers", "1", "--phases", "fuzzing", "--max-examples", "5", "--max-failures", "20", "--checks", checks, "--rate-limit", "3/s", "--request-timeout", "5", "--max-redirects", "0", "--seed", "20261011", "--no-shrink", "--report", "junit,har", "--report-junit-path", str(junit), "--report-har-path", str(har), "--output-sanitize", "true"]
        if token:
            argv += ["--header", "Authorization: Bearer " + token]
        code, output, timed_out = self.command(argv, tmp, timeout=125, hidden=hidden)
        self.publish(run, "tool-output.txt", output, hidden)
        self.publish(run, "scoped-openapi.json", scoped, schema=True)
        if timed_out:
            raise ValueError("Schemathesis exceeded the 125-second or output-size limit")
        if code not in (0, 1) or not junit.is_file() or not har.is_file():
            raise ValueError(f"Schemathesis did not produce complete reports (exit {code})")
        if any(path.stat().st_size > MAX_ARTIFACT for path in (junit, har)):
            raise ValueError("Schemathesis report exceeds the 16 MiB evidence limit")
        tree = ET.fromstring(junit.read_text())
        failures, errors, cases = [], [], list(tree.iter("testcase"))
        for case in cases:
            for failure in case.findall("failure"):
                failures.append({"id": f"C{len(failures)+1:04d}", "title": case.get("name", "API response check"), "severity": "info", "verification": "candidate", "rule_id": "schemathesis-response-check", "message": redact((failure.text or failure.get("message", ""))[:8000], hidden), "evidence": {"operation": case.get("name", ""), "check_kind": "server_error_only" if discovered else "schema_or_server_error", "security_impact_confirmed": False}})
            errors.extend((item.text or item.get("message", ""))[:2000] for item in case.findall("error"))
        raw_har = json.loads(har.read_text())
        entries = raw_har.get("log", {}).get("entries", [])
        actual = [item for item in entries if isinstance(item.get("response", {}).get("status"), int) and item["response"]["status"] > 0]
        if not actual:
            raise ValueError("no completed HTTP response was recorded; this run is not a successful diagnosis")
        run["candidates"] = failures[:MAX_CANDIDATES]
        run["summary"] = f"실제 HTTP 응답 {len(actual)}건, API 작업 {len(cases)}개, 응답 검사 후보 {len(failures)}건. 보안 취약점 확정과 구분하세요."
        selected_operations = [f'{method.upper()} {path}' for path, item in scoped['paths'].items() for method in ('get', 'head') if method in item]
        run['operation_ids'] = selected_operations
        run['limitations'] = [f"선택된 GET/HEAD 작업 {len(selected_operations)}개를 검사했습니다. 생성·수정·삭제, 다중 계정 인가, 전체 공격 경로를 검증하지 않았습니다.", "스키마 불일치와 서버 오류는 검토 후보이며 보안 취약점을 의미하지 않습니다. ARTEX 후속 조사에서 영향과 재현 조건을 확인하세요.", "작업당 예제 한도 5개, 초당 3회, 프로세스 제한 125초를 적용했습니다. 제한된 예제 검사이며 전체 API 커버리지를 보장하지 않습니다.", "이번 실행에 입력한 Bearer 토큰으로 요청했습니다. 토큰은 저장하거나 ARTEX에 전달하지 않습니다." if uploaded and token else "등록한 대상에 무인증 요청으로 검사했습니다. 인증 필요 API의 진단 범위가 제한됩니다." if uploaded else "임시 일반 사용자로 인증한 요청을 검사했습니다. 관리자 권한과 다른 사용자의 데이터는 검증하지 않았습니다." if token else "임시 계정 인증을 준비하지 못해 무인증 요청으로 검사했습니다. 인증 필요 API의 진단 범위가 제한됩니다."]
        status_counts = {}
        for entry in actual:
            status = str(entry['response']['status'])
            status_counts[status] = status_counts.get(status, 0) + 1
        exercised = sorted({str(entry.get('request', {}).get('method', '')).upper() + ' ' + urllib.parse.urlsplit(entry.get('request', {}).get('url', '')).path for entry in actual} & set(selected_operations))
        if discovered:
            run['summary'] = f"실제 HTTP 응답 {len(actual)}건, 선택 작업 {len(selected_operations)}개 중 응답 확인 {len(exercised)}개, 서버 오류 후보 {len(failures)}건. 취약점 없음 또는 API 전체 검사 완료를 뜻하지 않습니다."
            run['limitations'][1] = 'HAR·URL에서 생성한 요청 목록에는 응답 계약이 없습니다. 응답 스키마·상태 코드 계약 검사는 하지 않으며 서버 오류만 검토 후보로 기록합니다.'
            run['limitations'].extend(target.get('discovery', {}).get('warnings', []))
            if len(exercised) < len(selected_operations):
                run['limitations'].append(f'선택 작업 중 {len(selected_operations)-len(exercised)}개는 완료된 응답 근거가 없습니다. 도구 한도·실패·연결 상태를 확인하세요.')
        if status_counts.get('401') or status_counts.get('403'):
            run['limitations'].append('401/403 응답이 있습니다. 인증·권한 제한으로 해당 API의 기능과 보안 동작을 충분히 검사하지 못했을 수 있습니다.')
        if status_counts.get('404') or status_counts.get('405'):
            run['limitations'].append('404/405 응답이 있습니다. 경로 또는 HTTP 메서드가 실제 API와 일치하는지 검토하세요. 취약점이 없다는 뜻은 아닙니다.')
        if uploaded and not discovered:
            run['limitations'].append('명세의 예제·기본값과 다른 서버 설정은 제거했고 외부 참조·리다이렉트는 사용하지 않았습니다. GET/HEAD 요청도 서비스 구현에 따라 부작용이 있을 수 있습니다.')
        if errors:
            run["limitations"].append(f"도구 실행 중 API 작업 오류 {len(errors)}건이 보고되었습니다. 일부 작업은 검사되지 않았습니다.")
        self.publish(run, "http.har", raw_har, hidden)
        self.publish(run, "junit.xml", junit.read_text(), hidden)
        self.publish(run, "assessment.json", {"tool": run["tool"], "tool_version": run["tool_version"], "source_revision": run["source_revision"], "schema_file": original.name, "schema_sha256": hashlib.sha256(original.read_bytes()).hexdigest(), "input_mode": target.get('input_mode', 'openapi'), "checks": checks.split(','), "selected_operations": selected_operations, "exercised_operations": exercised if discovered else None, "status_counts": status_counts, "target_snapshot": target, "http_response_count": len(actual), "authenticated": bool(token), "candidates": run["candidates"], "errors": errors, "limitations": run["limitations"]}, hidden)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "AegisOffensive/1"

    def log_message(self, *_):
        pass  # Never log request headers, credentials, or result payloads.

    def send_json(self, code, body):
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def dispatch(self):
        runner = self.server.runner
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.query or parsed.fragment or urllib.parse.unquote(parsed.path) != parsed.path:
            return self.send_json(400, {"error": "invalid path"})
        path = parsed.path.strip("/").split("/")
        if self.command == "GET" and path == ["health"]:
            return self.send_json(200, {"status": "ok"})
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + runner.token):
            return self.send_json(401, {"error": "authentication required"})
        body = None
        if self.command == "POST":
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("chunked requests are unsupported")
            length = int(self.headers.get("Content-Length", "0"))
            limit = MAX_UPLOAD_BODY if path == ['targets'] else 64 * 1024
            if not 0 < length <= limit:
                raise ValueError('request body exceeds the configured limit')
            body = json.loads(self.rfile.read(length))
        if self.command == "GET" and path == ["catalog"]:
            return self.send_json(200, runner.catalog())
        if self.command == 'POST' and path == ['targets']:
            return self.send_json(201, runner.register_target(body))
        if path == ["runs"]:
            if self.command == "GET":
                return self.send_json(200, {"runs": runner.list()})
            if self.command == "POST":
                return self.send_json(202, runner.create(body))
        if len(path) >= 2 and path[0] == "runs":
            if self.command == "GET" and len(path) == 2:
                return self.send_json(200, runner.get(path[1]))
            if self.command == "POST" and len(path) == 3 and path[2] == "task":
                return self.send_json(200, runner.bind(path[1], body))
            if self.command == "GET" and len(path) == 4 and path[2] == "artifacts":
                data = runner.artifact(path[1], path[3])
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", 'attachment; filename="' + path[3] + '"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return self.wfile.write(data)
        return self.send_json(404, {"error": "route not found"})

    def handle_method(self):
        self.connection.settimeout(45)
        try:
            self.dispatch()
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)[:300]})
        except LookupError as exc:
            self.send_json(404, {"error": str(exc)[:300]})
        except RuntimeError as exc:
            self.send_json(409, {"error": str(exc)[:300]})
        except (OSError, KeyError, TypeError):
            self.send_json(500, {"error": "runner operation failed"})

    do_GET = handle_method
    do_POST = handle_method


def main():
    runner = Runner()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", int(os.getenv("OFFENSIVE_PORT", "8090"))), Handler)
    server.runner = runner
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
