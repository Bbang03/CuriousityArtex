#!/usr/bin/env python3
"""Authenticated internal bridge for the explicitly configured owned range.

State is durable, originals are export-only, and an interrupted attack is never
resumed automatically. Only one execution/collection/deployment job runs.
"""
import argparse
import copy
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import threading
import time
from uuid import uuid4

from runtime import (CATALOG, NATIVE_SETTLE_SECONDS, RangeError, Runtime,
                     baseline_rule, epoch, json_read, load_config, private_read,
                     rule_digest, utcnow, uuid_string, validate_rule)

ACTIVE = frozenset(('running', 'collecting', 'deploying', 'queued'))
CHAIN_PACK_ID = 'ps_task_chain'
CHAIN_KIND = 'scheduled_task_chain'
CHAIN_COMMON_CASES = ('chain_attack', 'chain_benign')
CHAIN_VARIANT_CASE = 'chain_variant'


def chain_baseline_rule():
    return {'kind': CHAIN_KIND, 'name': 'PowerShell 실행 기준 규칙', 'profile': 'powershell_broad'}


class APIError(RangeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def atomic_write(path, value):
    if path.is_symlink():
        raise RangeError('저장 파일에 심볼릭 링크를 사용할 수 없습니다.')
    fd, temporary = tempfile.mkstemp(prefix='.range-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def public_phase(phase):
    if phase is None:
        return None
    keys = ('id', 'status', 'started_at', 'finished_at')
    result = {key: phase.get(key) for key in keys}
    result['kind'] = phase.get('kind', 'discovery')
    result['results'] = [{key: copy.deepcopy(r.get(key)) for key in ('scenario_id', 'case_id', 'name', 'label', 'status', 'exit_code', 'summary', 'expected', 'variant', 'execution_verified', 'cleanup_verified')} for r in phase.get('results', [])]
    result['evidence'] = copy.deepcopy(phase.get('evidence', {}).get('public')) if phase.get('evidence') else None
    return result


def chain_metrics(cases, case_ids, unknown_ids=()):
    """Count only the declared paired cases, preserving missing/failed unknowns."""
    by_id, duplicates = {}, set()
    for case in cases:
        if not isinstance(case, dict):
            continue
        identifier = case.get('case_id')
        if identifier in by_id:
            duplicates.add(identifier)
        by_id[identifier] = case
    result = {'true_positives': 0, 'false_negatives': 0, 'false_positives': 0,
              'true_negatives': 0, 'unknown': 0, 'attack_total': 0, 'benign_total': 0}
    for identifier in case_ids:
        expected = 'benign' if identifier == 'chain_benign' else 'attack'
        result['benign_total' if expected == 'benign' else 'attack_total'] += 1
        case = by_id.get(identifier, {})
        verdict = case.get('verdict') if identifier not in duplicates and identifier not in unknown_ids and case.get('execution_verified') is True and case.get('expected') == expected else 'unknown'
        key = {'attack': {'detected': 'true_positives', 'missed': 'false_negatives'},
               'benign': {'false_positive': 'false_positives', 'true_negative': 'true_negatives'}}[expected].get(verdict, 'unknown')
        result[key] += 1
    return result


def chain_comparison(baseline, current):
    reasons = []
    baseline_metrics = chain_metrics(baseline.get('cases', []), CHAIN_COMMON_CASES, baseline.get('unknown_scenarios', [])) if baseline else None
    current_metrics = chain_metrics(current.get('cases', []), CHAIN_COMMON_CASES, current.get('unknown_scenarios', [])) if current else None
    if not baseline or not current:
        reasons.append('기준 공격·정상 표본과 재실행의 실제 로그 수집을 모두 완료해야 합니다.')
    if not baseline.get('complete') or not current.get('complete'):
        reasons.append('공통 표본의 원본 수집 범위와 네이티브 예약 검색 완료를 확인해야 합니다.')
    if (baseline_metrics and baseline_metrics['unknown']) or (current_metrics and current_metrics['unknown']):
        reasons.append('공통 공격·정상 표본에 실행 실패 또는 귀속 불명이 있어 비교를 확정할 수 없습니다.')
    variant = next((copy.deepcopy(case) for case in current.get('cases', []) if isinstance(case, dict) and case.get('case_id') == CHAIN_VARIANT_CASE), None)
    return {'kind': CHAIN_KIND, 'comparable': not reasons, 'common_case_ids': list(CHAIN_COMMON_CASES),
            'baseline_metrics': baseline_metrics, 'current_metrics': current_metrics, 'heldout_variant': variant,
            'baseline_detected': baseline_metrics['true_positives'] if baseline_metrics else 0,
            'current_detected': current_metrics['true_positives'] if current_metrics else 0,
            'total_scenarios': 1, 'reasons': reasons}


def comparison(cycle):
    baseline = (cycle.get('baseline') or {}).get('evidence', {}).get('public', {}) if (cycle.get('baseline') or {}).get('evidence') else {}
    current = (cycle.get('current') or {}).get('evidence', {}).get('public', {}) if (cycle.get('current') or {}).get('evidence') else {}
    if cycle.get('kind') == CHAIN_KIND:
        return chain_comparison(baseline, current)
    reasons = []
    if not baseline or not current:
        reasons.append('기준 실행과 재실행의 실제 로그 수집을 모두 완료해야 합니다.')
    if not baseline.get('complete') or not current.get('complete'):
        reasons.append('원본 수집 범위와 네이티브 예약 검색 대기 완료가 확인되어야 합니다.')
    if baseline.get('unknown_scenarios') or current.get('unknown_scenarios'):
        reasons.append('귀속 불명 또는 실패한 시나리오가 있어 비교를 확정할 수 없습니다.')
    return {'comparable': not reasons, 'baseline_detected': len(baseline.get('detected_scenarios', [])),
            'current_detected': len(current.get('detected_scenarios', [])), 'total_scenarios': len(cycle['scenario_ids']), 'reasons': reasons}


def public_cycle(cycle):
    result = {key: copy.deepcopy(cycle.get(key)) for key in ('id', 'name', 'status', 'revision', 'scenario_ids', 'baseline_rule', 'candidate_rule', 'candidate_note', 'candidate_explanation', 'error', 'created_at')}
    result['baseline'], result['current'] = public_phase(cycle.get('baseline')), public_phase(cycle.get('current'))
    result['kind'] = cycle.get('kind', 'discovery')
    result['comparison'] = comparison(cycle)
    return result


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        if self.directory.is_symlink():
            raise RangeError('상태 저장 경로에 심볼릭 링크를 사용할 수 없습니다.')
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        lock_path = self.directory / '.lock'
        self.handle = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.handle)
            raise RangeError('다른 실행 브리지가 상태 저장소를 사용 중입니다.') from None
        self.lock = threading.RLock()
        self.cycles = {}
        for path in self.directory.glob('*.json'):
            if not re.fullmatch(r'[0-9a-f-]{36}\.json', path.name):
                continue
            cycle = json_read(private_read(path, maximum=64 << 20))
            if not isinstance(cycle, dict) or uuid_string(cycle.get('id')) + '.json' != path.name:
                raise RangeError('저장된 실행 상태 형식을 확인하지 못했습니다.')
            self.cycles[cycle['id']] = cycle
            if cycle.get('status') in ACTIVE:
                cycle['status'] = 'interrupted'
                cycle['error'] = '브리지 재시작 중 작업이 중단됐습니다. 공격을 자동으로 재실행하지 않습니다.'
                for phase in (cycle.get('baseline'), cycle.get('current')):
                    if phase and phase.get('status') in ACTIVE:
                        phase['status'] = 'interrupted'
                self.save(cycle)

    def save(self, cycle):
        with self.lock:
            atomic_write(self.directory / (uuid_string(cycle['id']) + '.json'), cycle)
            self.cycles[cycle['id']] = cycle

    def get(self, identifier):
        identifier = uuid_string(identifier)
        if identifier not in self.cycles:
            raise APIError(404, '해당 실행 사이클을 찾지 못했습니다.')
        return self.cycles[identifier]

    def close(self):
        os.close(self.handle)


class Bridge:
    def __init__(self, config, store, runtime=None, settle_seconds=NATIVE_SETTLE_SECONDS):
        self.config, self.store = config, store
        self.runtime = runtime if runtime is not None else Runtime(config)
        self.lock = threading.RLock()
        self.busy = None
        self.worker = None
        self.stop = threading.Event()
        self.settle_seconds = settle_seconds
        self.ready_checked = 0

    def status(self):
        message = 'AWS 실습 환경 연결이 구성되었습니다.'
        ready = False
        try:
            if time.monotonic() - self.ready_checked > 15:
                self.runtime.ready()
                self.ready_checked = time.monotonic()
            ready = True
        except RangeError:
            message = '실습 환경의 SSH 및 고정 인증서 연결을 확인하지 못했습니다.'
        return {'configured': True, 'ready': ready, 'message': message,
                'environment': {'name': self.config['name'], 'host': self.config['windows_hostname'], 'telemetry_source': 'Windows 감사·PowerShell·TaskScheduler·Sysmon → Splunk 네이티브 경보'},
                'scenarios': [{**{key: s[key] for key in ('id', 'name', 'technique', 'description')}, 'kind': 'discovery'} for s in self.config['scenarios']] +
                             [{'id': CHAIN_PACK_ID, 'kind': CHAIN_KIND, 'name': 'PowerShell → 예약작업 → 지연 실행',
                               'technique': 'T1059.001 / T1053.005', 'description': '실제 예약작업 공격과 정상 PowerShell을 비교하고, 행위 규칙 개선 뒤 새 변형 공격을 검증합니다.'}]}

    def _start_job(self, cycle, operation, function):
        if self.busy is not None:
            raise APIError(409, '다른 실행·수집·규칙 배포가 진행 중입니다.')
        self.busy = (cycle['id'], operation)
        self.store.save(cycle)
        def run():
            try:
                function()
            except Exception as error:
                with self.lock:
                    cycle['status'] = 'failed'
                    cycle['error'] = str(error) if isinstance(error, RangeError) else '작업을 정상 완료하지 못했습니다. 자동 공격 재실행은 하지 않습니다.'
                    phase = cycle.get('current') or cycle.get('baseline')
                    if phase and phase.get('status') in ACTIVE:
                        phase['status'] = 'failed'
                        if not phase.get('finished_at'):
                            phase['finished_at'] = utcnow()
                    self.store.save(cycle)
            finally:
                with self.lock:
                    self.busy = None
        self.worker = threading.Thread(target=run, name='range-' + operation, daemon=True)
        self.worker.start()

    def _phase(self, kind='discovery'):
        return {'id': str(uuid4()), 'kind': kind, 'status': 'queued', 'started_at': None, 'finished_at': None, 'results': [], 'evidence': None}

    def create(self, body):
        if not isinstance(body, dict) or set(body) != {'request_id', 'name', 'scenario_ids'}:
            raise APIError(400, 'request_id, name, scenario_ids를 지정하세요.')
        identifier = uuid_string(body['request_id'])
        name, ids = body['name'], body['scenario_ids']
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120 or any(ord(ch) < 32 for ch in name):
            raise APIError(400, '실행 이름은 1~120자여야 합니다.')
        if not isinstance(ids, list) or not 1 <= len(ids) <= len(CATALOG) or any(not isinstance(s, str) or s not in CATALOG and s != CHAIN_PACK_ID for s in ids) or len(set(ids)) != len(ids):
            raise APIError(400, '등록된 시나리오를 하나 이상 선택하세요.')
        if CHAIN_PACK_ID in ids and ids != [CHAIN_PACK_ID]:
            raise APIError(400, '예약작업 공격 체인은 단일 Atomic 시나리오와 섞지 않고 별도 실행하세요.')
        kind = CHAIN_KIND if ids == [CHAIN_PACK_ID] else 'discovery'
        normalized = {'request_id': identifier, 'name': name.strip(), 'scenario_ids': sorted(ids)}
        request_hash = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        with self.lock:
            existing = self.store.cycles.get(identifier)
            if existing:
                if existing['request_sha256'] != request_hash:
                    raise APIError(409, '같은 request_id에 다른 실행 요청을 사용할 수 없습니다.')
                return public_cycle(existing), 200
            if self.busy:
                raise APIError(409, '다른 실행·수집·규칙 배포가 진행 중입니다.')
            if len(self.store.cycles) >= 100:
                raise APIError(409, '보존된 사이클이 한도 100개에 도달했습니다.')
            cycle = {'id': identifier, 'name': normalized['name'], 'scenario_ids': normalized['scenario_ids'], 'request_sha256': request_hash,
                     'kind': kind, 'status': 'running', 'revision': 1, 'created_at': utcnow(), 'error': '',
                     'baseline_rule': chain_baseline_rule() if kind == CHAIN_KIND else baseline_rule(), 'candidate_rule': None,
                     'baseline': self._phase(kind), 'current': None, 'deployments': {}, 'candidate_note': ''}
            self._start_job(cycle, 'baseline', lambda: self._execute(cycle, 'baseline'))
            return public_cycle(cycle), 202

    def _execute(self, cycle, role):
        phase = cycle['baseline'] if role == 'baseline' else cycle['current']
        rule = cycle['baseline_rule'] if role == 'baseline' else cycle['candidate_rule']
        if role == 'baseline':
            deployment = self.runtime.deploy(cycle['id'], role, rule)
            with self.lock:
                cycle['deployments'][role] = deployment
                self.store.save(cycle)
        elif not cycle['deployments'].get('candidate', {}).get('verified'):
            raise RangeError('후보 규칙의 실제 배포가 확인되지 않았습니다.')
        with self.lock:
            phase['status'] = 'running'
            phase['started_at'] = utcnow()
            self.store.save(cycle)
        chained = cycle.get('kind') == CHAIN_KIND
        identifiers = list(CHAIN_COMMON_CASES) + ([CHAIN_VARIANT_CASE] if role == 'candidate' else []) if chained else cycle['scenario_ids']
        for sid in identifiers:
            if self.stop.is_set():
                raise RangeError('브리지 종료로 실행이 중단됐습니다. 자동으로 재실행하지 않습니다.')
            result = self.runtime.execute_chain(sid, phase['id'], str(uuid4())) if chained else self.runtime.execute(sid, phase['id'], str(uuid4()))
            with self.lock:
                phase['results'].append(result)
                self.store.save(cycle)
        with self.lock:
            phase['status'] = 'awaiting_collection'
            phase['finished_at'] = utcnow()
            cycle['status'] = 'awaiting_collection'
            self.store.save(cycle)

    def collect(self, identifier, body):
        if not isinstance(body, dict) or set(body) - {'expected_revision'}:
            raise APIError(400, '수집 요청 형식이 올바르지 않습니다.')
        with self.lock:
            cycle = self.store.get(identifier)
            self._revision(cycle, body, optional=True)
            if self.busy:
                if self.busy == (cycle['id'], 'collect'):
                    return public_cycle(cycle), 202
                raise APIError(409, '다른 작업이 진행 중입니다.')
            phase = cycle.get('current') or cycle['baseline']
            if not phase.get('finished_at') or phase['status'] in ('failed', 'interrupted'):
                raise APIError(409, '실제 실행이 완료된 후에 로그를 수집하세요.')
            if len(phase.get('collections', [])) >= 10:
                raise APIError(409, '동일 실행의 원본 수집 한도 10회에 도달했습니다.')
            if phase.get('evidence') and phase['evidence']['public']['complete'] and not phase['evidence']['public'].get('unknown_scenarios', []):
                return public_cycle(cycle), 200
            cycle['status'] = phase['status'] = 'collecting'
            cycle['error'] = ''
            self._start_job(cycle, 'collect', lambda: self._collect(cycle, phase))
            return public_cycle(cycle), 202

    def _collect(self, cycle, phase):
        # A negative requires a complete observation window after a real
        # scheduled search can finish; requests remain responsive while waiting.
        deadline = epoch(phase['finished_at']) + self.settle_seconds
        while time.time() < deadline:
            if self.stop.wait(min(1, max(0, deadline - time.time()))):
                raise RangeError('브리지 종료로 원본 로그 수집이 중단됐습니다.')
        role = 'candidate' if phase is cycle.get('current') else 'baseline'
        evidence = self.runtime.collect(phase, cycle['deployments'][role])
        with self.lock:
            # Keep every immutable collection attempt, including partial/error
            # originals; refreshing a partial collection never erases history.
            phase.setdefault('collections', []).append(evidence)
            phase['evidence'] = evidence
            phase['status'] = cycle['status'] = 'completed' if evidence['public']['complete'] and not evidence['public'].get('unknown_scenarios', []) else 'inconclusive'
            self.store.save(cycle)

    @staticmethod
    def _revision(cycle, body, optional=False):
        value = body.get('expected_revision')
        if value is None and optional:
            return
        if not isinstance(value, int) or isinstance(value, bool) or value != cycle['revision']:
            raise APIError(409, '실행 상태가 변경됐습니다. 최신 revision으로 다시 요청하세요.')

    def suggest(self, identifier, body):
        if not isinstance(body, dict) or set(body) - {'expected_revision'}:
            raise APIError(400, '후보 제안 요청 형식이 올바르지 않습니다.')
        with self.lock:
            cycle = self.store.get(identifier)
            self._revision(cycle, body, optional=True)
            if self.busy:
                raise APIError(409, '진행 중인 작업을 완료한 후 제안하세요.')
            evidence = cycle['baseline'].get('evidence')
            if not evidence:
                raise APIError(409, '기준 실행의 실제 Sysmon 로그를 먼저 수집하세요.')
            if cycle.get('kind') == CHAIN_KIND:
                return self._suggest_chain(evidence)
            candidate = copy.deepcopy(cycle['baseline_rule'])
            candidate['name'] = '실제 Atomic 프로세스 관측 기반 개선 후보'
            seen = set()
            for sid in cycle['scenario_ids']:
                for event in evidence.get('attributed_events', {}).get(sid, []):
                    image = event.get('Image', '')
                    if sid != 'whoami' and image.lower() not in seen and image.replace('/', '\\').rsplit('\\', 1)[-1].lower() == CATALOG[sid][2]:
                        seen.add(image.lower())
                        candidate['any'].append({'all': [{'field': 'Image', 'op': 'equals', 'value': image, 'case_sensitive': False}]})
            candidate = validate_rule(candidate)
            warnings = ['기준 실행에서 실제 관측한 프로세스만 제안합니다. 정상 활동 구분과 오탐률은 별도 정상 표본 검증이 필요합니다.']
            if not seen:
                warnings.append('추가 실행 파일의 실제 프로세스 계보를 확인하지 못해 새 조건을 제안하지 않았습니다.')
            if not evidence['public']['complete']:
                warnings.append('기준 로그 수집이 불완전합니다. 원본 출처와 수집 범위를 확인하세요.')
            return {'candidate_rule': candidate, 'warnings': warnings}, 200

    @staticmethod
    def _suggest_chain(evidence):
        public = evidence['public']
        cases = [case for case in public.get('cases', []) if isinstance(case, dict) and case.get('case_id') in CHAIN_COMMON_CASES]
        metrics = chain_metrics(cases, CHAIN_COMMON_CASES, public.get('unknown_scenarios', []))
        if not public.get('complete') or metrics['unknown']:
            raise APIError(409, '기준 공격·정상 표본의 실행과 전체 로그 수집을 확인한 뒤 행위 규칙을 제안하세요.')
        causes = []
        if metrics['false_positives']:
            causes.append('PowerShell 실행만 보는 기준 규칙이 정상 PowerShell 활동도 경보로 분류했습니다.')
        if metrics['false_negatives']:
            causes.append('기준 규칙이 실제 공격 체인의 예약작업·지연 실행 근거를 충분히 반영하지 못했습니다.')
        if not causes:
            causes.append('현재 공통 표본에서 오탐·미탐은 확인되지 않았지만 실행 파일 중심 규칙을 행위 상관 규칙으로 검증할 수 있습니다.')
        facts = [case.get('label', case['case_id']) + ': ' + str(case.get('verdict', 'unknown')) + ' — ' + str(case.get('reason', '')) for case in cases]
        return {'candidate_rule': {'kind': CHAIN_KIND, 'name': '예약작업 등록과 지연 실행 행위 규칙', 'profile': 'task_behavior'},
                'warnings': ['실제 기준 실행의 근거를 바탕으로 고정 행위 프로필을 제안합니다. 새 변형 공격은 후보 배포 뒤 처음 실행하며 기준 후보 생성에 사용하지 않습니다.'],
                'explanation': {'summary': 'PowerShell 실행 여부에서 예약작업 등록·지연 실행 근거의 상관분석으로 탐지 기준을 개선합니다.',
                                'causes': causes, 'evidence': facts,
                                'improvements': ['예약작업 등록과 연결된 지연 실행의 실제 로그를 상관분석합니다.', '정상 PowerShell 실행과 공격 체인의 행위를 구분합니다.'],
                                'limitations': ['이 제안은 고정된 실습 행위 프로필이며 범용 운영 탐지 정책이 아닙니다.', '한 정상 표본의 결과로 운영 오탐률을 추정하지 않습니다.', '개선 효과와 변형 공격 탐지는 새 실제 실행의 수집 근거로 확인해야 합니다.']}}, 200

    def candidate(self, identifier, body):
        if not isinstance(body, dict) or set(body) != {'expected_revision', 'rule', 'note'} or not isinstance(body['note'], str) or len(body['note']) > 2000:
            raise APIError(400, 'expected_revision, rule, note를 지정하세요.')
        rule = validate_rule(body['rule'])
        with self.lock:
            cycle = self.store.get(identifier)
            if (rule.get('kind') == CHAIN_KIND) != (cycle.get('kind') == CHAIN_KIND):
                raise APIError(400, '단일 Atomic 규칙과 예약작업 체인 규칙을 서로 바꿀 수 없습니다.')
            if cycle.get('kind') == CHAIN_KIND and rule.get('profile') != 'task_behavior':
                raise APIError(400, '체인 개선 후보는 task_behavior 행위 프로필을 사용하세요.')
            explanation = None
            if cycle.get('kind') == CHAIN_KIND:
                if not body['note'].strip():
                    raise APIError(400, '기준 실행의 문제와 후보 개선 근거를 검토 기록에 적어주세요.')
                evidence = cycle['baseline'].get('evidence')
                if not evidence:
                    raise APIError(409, '기준 공격·정상 표본의 실제 로그를 먼저 수집하세요.')
                # Direct POST must satisfy the same evidence requirements as
                # suggestion. A client cannot bypass incomplete/unknown cases.
                suggestion, _ = self._suggest_chain(evidence)
                explanation = suggestion['explanation']
            # Same successful request is idempotent even after revision advanced.
            if cycle.get('candidate_rule') == rule and cycle.get('candidate_note') == body['note'] and body['expected_revision'] == cycle['revision'] - 1 and cycle['deployments'].get('candidate', {}).get('verified'):
                return public_cycle(cycle), 200
            self._revision(cycle, body)
            if self.busy:
                raise APIError(409, '다른 실행·수집·규칙 배포가 진행 중입니다.')
            if cycle.get('current') or not cycle['baseline'].get('evidence'):
                raise APIError(409, '기준 로그 수집 이후 재실행 전에 후보 규칙을 배포하세요.')
            cycle['deployments'].pop('candidate', None)
            cycle['candidate_rule'] = rule
            cycle['candidate_note'] = body['note']
            if explanation is not None:
                cycle['candidate_explanation'] = copy.deepcopy(explanation)
            cycle['status'], cycle['error'] = 'deploying', ''
            self._start_job(cycle, 'candidate', lambda: self._deploy_candidate(cycle, rule))
            return public_cycle(cycle), 202

    def _deploy_candidate(self, cycle, rule):
        deployment = self.runtime.deploy(cycle['id'], 'candidate', rule)
        with self.lock:
            cycle['deployments']['candidate'] = deployment
            cycle.setdefault('candidate_history', []).append({'rule': copy.deepcopy(rule), 'deployment': copy.deepcopy(deployment), 'note': cycle['candidate_note'], 'explanation': copy.deepcopy(cycle.get('candidate_explanation')), 'deployed_at': utcnow(), 'revision': cycle['revision'] + 1})
            cycle['revision'] += 1
            cycle['status'] = 'candidate_ready'
            self.store.save(cycle)

    def rerun(self, identifier, body):
        if not isinstance(body, dict) or set(body) != {'expected_revision'}:
            raise APIError(400, 'expected_revision을 지정하세요.')
        with self.lock:
            cycle = self.store.get(identifier)
            self._revision(cycle, body)
            if cycle.get('current'):
                return public_cycle(cycle), 202 if cycle['status'] in ACTIVE else 200
            if self.busy:
                raise APIError(409, '다른 작업이 진행 중입니다.')
            if not cycle['deployments'].get('candidate', {}).get('verified'):
                raise APIError(409, '후보 규칙의 실제 배포를 완료하세요.')
            cycle['current'] = self._phase(cycle.get('kind', 'discovery'))
            cycle['status'], cycle['error'] = 'running', ''
            self._start_job(cycle, 'rerun', lambda: self._execute(cycle, 'candidate'))
            return public_cycle(cycle), 202

    def dispatch(self, method, path, body):
        if path == '/status' and method == 'GET':
            return self.status(), 200
        if path == '/cycles':
            if method == 'GET':
                with self.lock:
                    return {'cycles': [public_cycle(c) for c in sorted(self.store.cycles.values(), key=lambda c: c['created_at'], reverse=True)]}, 200
            if method == 'POST':
                return self.create(body)
        match = re.fullmatch(r'/cycles/([0-9a-f-]{36})(?:/(collect|suggest|candidate|rerun|export))?', path)
        if match:
            identifier, operation = match.groups()
            if method == 'GET' and operation in (None, 'export'):
                with self.lock:
                    cycle = self.store.get(identifier)
                    if operation == 'export':
                        return {'format': 'aegis.range.native.v1', 'exported_at': utcnow(), 'provenance': 'actual_owned_windows_atomic_and_splunk', 'cycle': copy.deepcopy(cycle)}, 200
                    return public_cycle(cycle), 200
            if method == 'POST' and operation in ('collect', 'suggest', 'candidate', 'rerun'):
                return getattr(self, operation)(identifier, body)
        raise APIError(404, '지원하지 않는 실행 브리지 API입니다.')

    def shutdown(self):
        self.stop.set()
        if self.worker:
            self.worker.join(timeout=5)
        self.runtime.tunnel.close()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, bridge, token):
        self.bridge, self.token = bridge, token
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = 'AegisRange/1'
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')

    def handle_request(self, method):
        status, data = 500, {'error': '작업을 완료하지 못했습니다.'}
        try:
            auth = self.headers.get('Authorization', '')
            if not hmac.compare_digest(auth.encode(), ('Bearer ' + self.server.token).encode()):
                raise APIError(401, '실행 브리지 인증이 필요합니다.')
            if '?' in self.path or '#' in self.path or '%' in self.path:
                raise APIError(400, '정규 API 경로만 허용됩니다.')
            body = {}
            if method == 'POST':
                if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                    raise APIError(400, '크기가 제한된 JSON 요청을 사용하세요.')
                try:
                    length = int(self.headers.get('Content-Length', '-1'))
                except ValueError:
                    raise APIError(400, '요청 크기 형식이 올바르지 않습니다.') from None
                if not 0 <= length <= 65536:
                    raise APIError(413, '요청은 64 KiB 이하여야 합니다.')
                self.connection.settimeout(10)
                body = json_read(self.rfile.read(length)) if length else {}
            data, status = self.server.bridge.dispatch(method, self.path, body)
        except APIError as error:
            data, status = {'error': str(error)}, error.status
        except RangeError as error:
            data, status = {'error': str(error)}, 400
        except Exception:
            pass
        encoded = json.dumps(data, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=os.environ.get('ARTEX_RANGE_CONFIG', '/run/range/config.json'))
    parser.add_argument('--token-file', default=os.environ.get('ARTEX_RANGE_TOKEN_FILE', '/run/range/token'))
    parser.add_argument('--state', default=os.environ.get('ARTEX_RANGE_STATE_DIR', '/var/lib/aegis-range'))
    parser.add_argument('--listen', default='0.0.0.0')
    parser.add_argument('--port', default=8091, type=int)
    args = parser.parse_args()
    store, bridge = None, None
    try:
        config = load_config(args.config)
        token = private_read(args.token_file, maximum=256).decode().strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{32,200}', token):
            raise RangeError('실행 브리지 토큰 형식이 올바르지 않습니다.')
        store = Store(args.state)
        bridge = Bridge(config, store)
        server = Server((args.listen, args.port), bridge, token)
        def terminate(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        server.serve_forever(poll_interval=.5)
        server.server_close()
    except (RangeError, OSError, ValueError):
        print('실행 브리지 시작에 실패했습니다. 비공개 설정·토큰·상태 디렉터리를 확인하세요.', flush=True)
        return 1
    finally:
        if bridge:
            bridge.shutdown()
        if store:
            store.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
