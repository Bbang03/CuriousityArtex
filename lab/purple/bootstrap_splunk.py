#!/usr/bin/env python3
"""Configure only the separately created ARTEX local lab Splunk instance.

No secrets are printed. This does not start Splunk or accept its license. First
certificate trust requires an explicit option and a loopback management address;
subsequent calls require the exact stored, unexpired leaf certificate.
"""

import argparse
import base64
import configparser
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import tempfile
import time
import urllib.parse
from uuid import UUID


APP = "artex_lab"
INDEX = "artex_lab"
SEARCH_USER = "artex_lab_search"
SEARCH_ROLE = "artex_lab_search"
SAVED_SEARCH = "artex_lab_crs_match_detection"
ROOT = Path(__file__).resolve().parent


class LabError(Exception):
    """A safe-to-display failure; never contains a Splunk response or secret."""


class LabConnectionError(LabError):
    """Temporary transport unavailability, distinct from rejected trust/auth."""


class HTTPError(LabError):
    def __init__(self, status, method=None, path=None):
        self.status = status
        resource = path.split("?", 1)[0] if path else ""
        if method in ("GET", "POST") and len(resource) < 200 and re.fullmatch(r"/services[A-Za-z0-9_/-]*", resource):
            super().__init__(f"Splunk 관리 API {method} {resource}: HTTP {status}")
        else:
            super().__init__(f"Splunk 관리 API 응답: HTTP {status}")


def private_read(path, *, minimum=1):
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise LabError("실습 인증 파일은 일반 파일이며 권한이 600 또는 400이어야 합니다")
            value = handle.read(8193).strip()
    except OSError:
        raise LabError("실습 인증 파일을 읽지 못했습니다") from None
    if len(value) < minimum or len(value) > 8192 or any(c.isspace() for c in value):
        raise LabError("실습 인증 파일의 값이 비어 있거나 올바르지 않습니다")
    return value


def private_write(path, value):
    path = Path(path)
    if path.is_symlink():
        raise LabError("실습 인증 파일에 심볼릭 링크를 사용할 수 없습니다")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".lab-secret-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parsed_url(url):
    endpoint = urllib.parse.urlsplit(url)
    if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username
            or endpoint.password or endpoint.path not in ("", "/")
            or endpoint.query or endpoint.fragment):
        raise LabError("Splunk 관리 주소는 경로와 계정 정보가 없는 HTTPS 주소여야 합니다")
    try:
        port = endpoint.port or 443
    except ValueError:
        raise LabError("Splunk 포트가 올바르지 않습니다") from None
    return endpoint.hostname, port


def valid_certificate(der):
    """Check dates even when a self-signed exact leaf pin replaces PKI trust."""
    descriptor, filename = tempfile.mkstemp(prefix="artex-lab-certificate-", suffix=".pem")
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der))
        info = ssl._ssl._test_decode_cert(filename)
        now = time.time()
        if now < ssl.cert_time_to_seconds(info["notBefore"]) or now > ssl.cert_time_to_seconds(info["notAfter"]):
            raise LabError("Splunk 인증서가 아직 유효하지 않거나 만료됐습니다")
    except (ssl.SSLError, KeyError, ValueError):
        raise LabError("Splunk 인증서 유효 기간을 확인하지 못했습니다") from None
    finally:
        os.unlink(filename)


def tls_context():
    # Replaces PKI only after an exact certificate comparison before any auth.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def peer_pin(url):
    host, port = parsed_url(url)
    try:
        with socket.create_connection((host, port), timeout=10) as connection:
            with tls_context().wrap_socket(connection, server_hostname=host) as secured:
                der = secured.getpeercert(binary_form=True)
                valid_certificate(der)
                return hashlib.sha256(der).hexdigest()
    except (OSError, ssl.SSLError):
        raise LabConnectionError("Splunk TLS 연결을 확인하지 못했습니다") from None


def ensure_pin(url, path, *, trust_new=False):
    path = Path(path)
    if path.exists():
        pin = private_read(path)
        if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
            raise LabError("저장된 Splunk 인증서 핀 형식이 올바르지 않습니다")
        if peer_pin(url) != pin:
            raise LabError("Splunk 인증서가 저장된 핀과 다릅니다. 자동으로 신뢰를 변경하지 않습니다")
        return pin
    if not trust_new:
        raise LabError("새 실습 인스턴스의 인증서 초기 신뢰 옵션이 필요합니다")
    host, _ = parsed_url(url)
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if not local:
        raise LabError("초기 인증서 신뢰는 새로 만든 로컬 실습 인스턴스에서만 허용됩니다")
    pin = peer_pin(url)
    private_write(path, pin + "\n")
    return pin


class Client:
    def __init__(self, url, pin, username, password, timeout=20):
        self.host, self.port = parsed_url(url)
        self.pin = pin
        self.username = username
        self.password = password
        self.timeout = timeout

    def raw(self, method, path, form=None, limit=4 << 20):
        if not path.startswith("/services") or "\r" in path or "\n" in path:
            raise LabError("허용되지 않은 Splunk API 경로입니다")
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=tls_context())
        try:
            connection.connect()
            der = connection.sock.getpeercert(binary_form=True)
            valid_certificate(der)
            if hashlib.sha256(der).hexdigest() != self.pin:
                raise LabError("Splunk 인증서가 저장된 핀과 다릅니다")
            # Credentials are assembled/transmitted only after TLS pin validation.
            auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
            headers = {"Authorization": "Basic " + auth, "Accept": "application/json"}
            body = None
            if form is not None:
                body = urllib.parse.urlencode(form, doseq=True).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            separator = "&" if "?" in path else "?"
            connection.request(method, path + separator + "output_mode=json", body=body, headers=headers)
            response = connection.getresponse()
            if response.status < 200 or response.status >= 300:
                raise HTTPError(response.status, method, path)
            data = response.read(limit + 1)
            if len(data) > limit:
                raise LabError("Splunk 응답이 실습 조회 한도를 넘었습니다")
            return data
        except (OSError, http.client.HTTPException, ssl.SSLError):
            raise LabConnectionError("Splunk 관리 API 연결에 실패했습니다") from None
        finally:
            connection.close()

    def request(self, method, path, form=None, limit=4 << 20):
        data = self.raw(method, path, form, limit)
        try:
            return json.loads(data) if data else {}
        except (ValueError, UnicodeError):
            raise LabError("Splunk JSON 응답 형식을 확인하지 못했습니다") from None

    def export(self, search, earliest, latest):
        data = self.raw("POST", "/services/search/v2/jobs/export", {
            "search": search, "earliest_time": earliest, "latest_time": latest,
            "output_mode": "json", "preview": "false",
        }, limit=32 << 20)
        results, warnings = [], []
        for line in data.splitlines():
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError):
                raise LabError("Splunk 검색 응답이 올바르지 않습니다") from None
            if row.get("preview"):
                raise LabError("Splunk가 확정되지 않은 검색 결과를 반환했습니다")
            for message in row.get("messages", []):
                kind = message.get("type", "")
                if kind in ("ERROR", "FATAL"):
                    raise LabError("Splunk 검색이 완료되지 않았습니다")
                if kind == "WARN":
                    warnings.append("Splunk 검색 경고가 있어 조회 완전성을 확인해야 합니다")
            if row.get("error"):
                raise LabError("Splunk 검색이 실패했습니다")
            if isinstance(row.get("result"), dict):
                results.append(row["result"])
        return results, warnings


def content(response):
    entries = response.get("entry", [])
    if not entries:
        raise LabError("Splunk 설정 응답에 항목이 없습니다")
    return entries[0].get("content", {})


def upsert(client, collection, name, values):
    resource = collection + "/" + urllib.parse.quote(name, safe="")
    try:
        client.request("GET", resource)
    except HTTPError as error:
        if error.status != 404:
            raise
        return client.request("POST", collection, {"name": name, **values})
    return client.request("POST", resource, values)


def saved_search_values(enabled_since=0):
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    config.read(ROOT / "splunk/templates/savedsearches.conf", encoding="utf-8")
    values = dict(config[SAVED_SEARCH])
    values["search"] = values["search"].replace("ARTEX_ENABLED_SINCE", f"{float(enabled_since):.6f}")
    return values


def configure_reader_role(client):
    resource = "/services/authorization/roles/" + SEARCH_ROLE
    values = {
        "capabilities": ["search", "rest_access_server_endpoints"],
        "imported_roles": "", "srchIndexesAllowed": INDEX,
        "srchIndexesDefault": INDEX, "srchFilter": 'index="artex_lab"',
        "srchJobsQuota": "3", "cumulativeSrchJobsQuota": "3",
        "rtSrchJobsQuota": "0", "srchDiskQuota": "64",
    }
    upsert(client, "/services/authorization/roles", SEARCH_ROLE, values)
    role = content(client.request("GET", resource))
    # Splunk 10.4 role creation inherits enabled settings from [default].
    # An explicit role update writes disabled overrides for omitted capabilities.
    if set(role.get("capabilities", [])) != set(values["capabilities"]):
        client.request("POST", resource, values)
        role = content(client.request("GET", resource))
    if (set(role.get("capabilities", [])) != set(values["capabilities"])
            or role.get("imported_roles", [])
            or set(role.get("srchIndexesAllowed", [])) != {INDEX}
            or set(role.get("srchIndexesDefault", [])) != {INDEX}
            or role.get("srchFilter") != values["srchFilter"]):
        raise LabError("실습 검색 역할의 최소 권한 또는 인덱스 범위를 확인할 수 없습니다")


def saved_search_acl_matches(response):
    entries = response.get("entry", [])
    if not entries:
        return False
    acl = entries[0].get("acl", {})
    perms = acl.get("perms") or {}
    return (acl.get("app") == APP and acl.get("owner") == "admin"
            and acl.get("sharing") == "app"
            and set(perms.get("read", [])) == {"admin"}
            and set(perms.get("write", [])) == {"admin"})


def ensure_saved_search_acl(client, resource):
    if saved_search_acl_matches(client.request("GET", resource)):
        return
    try:
        client.request("POST", resource + "/acl", {
            "owner": "admin", "sharing": "app", "perms.read": "admin", "perms.write": "admin",
        })
    except HTTPError as error:
        if error.status != 409:
            raise
        # A concurrent move is accepted only if the resulting ACL is exact.
        if not saved_search_acl_matches(client.request("GET", resource)):
            raise
        return
    if not saved_search_acl_matches(client.request("GET", resource)):
        raise LabError("실습 경보의 소유자와 접근 권한을 확인할 수 없습니다")


def remove_legacy_personal_copy(client, app_resource):
    # Older bootstrap versions POSTed in admin's namespace after sharing the
    # rule, creating an identically named private copy. Remove only that exact
    # generated copy, and only when the correctly owned app rule already exists.
    try:
        shared = client.request("GET", app_resource)
    except HTTPError as error:
        if error.status == 404:
            return
        raise
    if not saved_search_acl_matches(shared):
        return
    personal = "/servicesNS/admin/" + APP + "/saved/searches/" + SAVED_SEARCH
    candidate = client.request("GET", personal)
    acl = candidate.get("entry", [{}])[0].get("acl", {})
    if acl.get("sharing") == "user" and acl.get("owner") == "admin" and acl.get("app") == APP:
        client.request("DELETE", personal)


def configure(client, state, *, connector_url):
    # Only named lab resources are changed; no production index or role is used.
    # The default index stanza is owned by the mounted artex_lab app. An
    # unqualified /services POST sees it on GET but cannot update its stanza.
    upsert(client, "/servicesNS/nobody/" + APP + "/data/indexes", INDEX, {
        "maxTotalDataSizeMB": "256", "maxDataSize": "16",
        "frozenTimePeriodInSecs": "604800", "maxHotBuckets": "2",
    })
    configure_reader_role(client)
    upsert(client, "/services/authentication/users", SEARCH_USER, {
        "password": private_read(state / "splunk-search-password", minimum=24),
        "roles": SEARCH_ROLE, "realname": "ARTEX lab index search only",
        "force-change-pass": "0",
    })
    client.request("POST", "/services/data/inputs/http/http", {
        "disabled": "0", "enableSSL": "1", "port": "8088",
    })
    token = private_read(state / "hec-token", minimum=32)
    try:
        UUID(token)
    except ValueError:
        raise LabError("HEC 실습 토큰은 UUID 형식이어야 합니다. 기존 값을 자동 교체하지 않습니다") from None
    hec_values = {
        "index": INDEX, "indexes": INDEX, "sourcetype": "artex:lab:audit",
        "disabled": "0", "useACK": "0",
    }
    # Splunk permits a caller-specified token on creation, but token values are
    # immutable through the ordinary update endpoint. Never rotate silently.
    hec_collection = "/services/data/inputs/http"
    hec_resource = hec_collection + "/artex_lab_audit"
    try:
        previous_hec = content(client.request("GET", hec_resource))
    except HTTPError as error:
        if error.status != 404:
            raise
        client.request("POST", hec_collection, {"name": "artex_lab_audit", "token": token, **hec_values})
    else:
        if not hmac.compare_digest(str(previous_hec.get("token", "")).lower(), token.lower()):
            raise LabError("저장된 HEC 토큰과 실습 Splunk 설정이 다릅니다. 자동으로 교체하지 않습니다")
        client.request("POST", hec_resource, hec_values)
    enabled_since = time.time()
    values = saved_search_values(enabled_since)
    # Shared app objects must be updated through nobody's namespace. POSTing
    # through admin's user namespace would create a new private shadow copy.
    collection = "/servicesNS/nobody/" + APP + "/saved/searches"
    remove_legacy_personal_copy(client, collection + "/" + SAVED_SEARCH)
    # Preserve a deliberately disabled rule across ordinary bootstrap reruns.
    try:
        previous = content(client.request("GET", collection + "/" + SAVED_SEARCH))
        values["disabled"] = str(previous.get("disabled", "0")).lower()
        # Ordinary restarts preserve the enabled epoch. Explicit off -> on
        # starts a new epoch so off-period attacks cannot be retroactively
        # turned into successful detection by the three-minute lookback.
        cutoff = re.search(r"\|\s*where\s+_time\s*>=\s*(\d+(?:\.\d+)?)\s*\|", previous.get("search", ""))
        if cutoff:
            enabled_since = float(cutoff.group(1))
            values["search"] = saved_search_values(enabled_since)["search"]
    except HTTPError as error:
        if error.status != 404:
            raise
    upsert(client, collection, SAVED_SEARCH, values)
    ensure_saved_search_acl(client, collection + "/" + SAVED_SEARCH)
    pin = private_read(state / "splunk-management.sha256")
    template = {
        "name": "Local purple lab Splunk", "enabled": True,
        "username": SEARCH_USER,
        "password_file": "splunk-search-password",
        "config": {
            "base_url": connector_url, "index": INDEX,
            "audit_sourcetype": "artex:lab:audit", "alert_sourcetype": "artex:lab:alert",
            "correlation_field": "artex_verification_id", "action_field": "action",
            "tls_fingerprint": pin,
        },
    }
    private_write(state / "connector-template.json", json.dumps(template, ensure_ascii=False, indent=2) + "\n")
    private_write(state / "detection-state.json", json.dumps({
        "enabled_since": enabled_since,
        "enabled": str(values["disabled"]).lower() in ("0", "false"),
    }, indent=2) + "\n")


def readiness(url, pin_path, trust_new, deadline):
    while True:
        try:
            return ensure_pin(url, pin_path, trust_new=trust_new)
        except LabConnectionError:
            # A restart can temporarily close an existing pinned service. Retry
            # transport only; rejected or changed trust is never reinitialized.
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def set_detection(client, state, mode):
    if mode not in ("on", "off"):
        raise LabError("실습 경보 모드는 on 또는 off여야 합니다")
    resource = "/servicesNS/nobody/" + APP + "/saved/searches/" + SAVED_SEARCH
    current = content(client.request("GET", resource))
    changes = {"disabled": "0" if mode == "on" else "1"}
    enabled_since = None
    if mode == "on":
        currently_enabled = str(current.get("disabled", "0")).lower() in ("0", "false")
        if currently_enabled:
            cutoff = re.search(r"\|\s*where\s+_time\s*>=\s*(\d+(?:\.\d+)?)\s*\|", current.get("search", ""))
            if not cutoff:
                raise LabError("활성 실습 경보의 시작 시각을 확인하지 못했습니다. 조회 범위를 자동 축소하지 않습니다")
            enabled_since = float(cutoff.group(1))
        else:
            enabled_since = time.time()
        # Repeated on refreshes the template without excluding pending events.
        # Only off -> on excludes the intentionally unmonitored interval.
        changes["search"] = saved_search_values(enabled_since)["search"]
    client.request("POST", resource, changes)
    private_write(state / "detection-state.json", json.dumps({
        "enabled": mode == "on", "changed_at": time.time(),
        "enabled_since": enabled_since,
    }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path(".local-runtime/purple-lab"))
    parser.add_argument("--url", default="https://127.0.0.1:18089")
    parser.add_argument("--hec-url", default="https://127.0.0.1:18088")
    parser.add_argument("--connector-url", default="https://purple-lab-splunk:8089")
    parser.add_argument("--wait-seconds", type=int, default=900)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("configure")
    initialize.add_argument("--trust-local-new-instance", action="store_true")
    detection = commands.add_parser("detection")
    detection.add_argument("mode", choices=("on", "off"))
    commands.add_parser("status")
    args = parser.parse_args()
    state = args.state_dir
    if state.is_symlink():
        raise LabError("실습 인증 폴더에 심볼릭 링크를 사용할 수 없습니다")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state, 0o700)
    trust_new = getattr(args, "trust_local_new_instance", False)
    deadline = time.monotonic() + max(0, min(args.wait_seconds, 900))
    pin = readiness(args.url, state / "splunk-management.sha256", trust_new, deadline)
    client = Client(args.url, pin, "admin", private_read(state / "splunk-admin-password", minimum=24))
    if args.command == "configure":
        while True:
            try:
                client.request("GET", "/services/server/info")
                break
            except LabConnectionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
            except HTTPError as error:
                if error.status not in (500, 502, 503, 504) or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        configure(client, state, connector_url=args.connector_url)
        readiness(args.hec_url, state / "splunk-hec.sha256", trust_new, deadline)
        reader = Client(args.url, pin, SEARCH_USER, private_read(state / "splunk-search-password", minimum=24))
        reader.request("GET", "/services/server/info")
        reader.export('search index="artex_lab" | head 1', "-5m", "now")
        print("Splunk 실습 인덱스·검색 계정·HEC·실제 경보 규칙 설정 완료 (인증 정보는 로컬 파일에 보관)")
    elif args.command == "detection":
        set_detection(client, state, args.mode)
        print("Splunk 실습 경보 규칙: " + args.mode + " (이미 실행 중인 검색은 완료될 수 있음)")
    else:
        saved = content(client.request("GET", "/servicesNS/nobody/" + APP + "/saved/searches/" + SAVED_SEARCH))
        role = content(client.request("GET", "/services/authorization/roles/" + SEARCH_ROLE))
        index = content(client.request("GET", "/services/data/indexes/" + INDEX))
        print(json.dumps({
            "index": INDEX, "maxTotalDataSizeMB": index.get("maxTotalDataSizeMB"),
            "saved_search": SAVED_SEARCH,
            "detection_enabled": str(saved.get("disabled", "0")).lower() in ("0", "false"),
            "search_user": SEARCH_USER, "search_indexes": role.get("srchIndexesAllowed"),
            "search_capabilities": role.get("capabilities"), "imported_roles": role.get("imported_roles"),
        }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except LabError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Splunk 실습 설정을 중지했습니다", file=sys.stderr)
        sys.exit(130)
