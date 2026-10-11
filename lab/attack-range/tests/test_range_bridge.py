import copy
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bridge
from test_range_runtime import config


class FakeRuntime:
    def __init__(self):
        self.calls = []
        self.block = threading.Event()
        self.block.set()
        self.tunnel = type('Tunnel', (), {'close': lambda _: None})()
    def ready(self):
        return True
    def deploy(self, identifier, role, rule):
        self.calls.append(('deploy', role))
        return {'rule_id': 'aegis_range_' + identifier.replace('-', '') + '_' + role, 'rule_sha256': bridge.rule_digest(rule), 'verified': True}
    def execute(self, sid, phase, anchor):
        self.calls.append(('execute', sid))
        self.block.wait(timeout=2)
        return {'scenario_id': sid, 'name': sid, 'status': 'completed', 'exit_code': 0, 'summary': 'native Atomic completed',
                'anchor_path': 'C:\\AegisLoop\\runs\\' + phase + '\\' + anchor + '\\run.ps1', 'stdout_base64': 'SECRET_OUTPUT', 'started_at': bridge.utcnow(), 'finished_at': bridge.utcnow()}
    def collect(self, phase, deployment):
        self.calls.append(('collect', phase['id']))
        ids = [r['scenario_id'] for r in phase['results']]
        return {'public': {'complete': True, 'audit_count': len(ids), 'alert_count': 1, 'detected_scenarios': ['whoami'], 'missed_scenarios': [sid for sid in ids if sid != 'whoami'], 'unknown_scenarios': [], 'events': [], 'warnings': []},
                'native_audit': {'rows': [{'_raw': 'SECRET_RAW'}]}, 'attributed_events': {sid: [{'Image': 'C:\\Windows\\System32\\' + sid + '.exe'}] for sid in ids}}


class ChainRuntime(FakeRuntime):
    def execute_chain(self, case_id, phase_id, run_id):
        self.calls.append(('execute_chain', case_id, phase_id, run_id))
        self.block.wait(timeout=2)
        return {'case_id': case_id, 'scenario_id': case_id, 'label': case_id, 'status': 'completed', 'exit_code': 0,
                'summary': 'actual chain observed', 'expected': 'benign' if case_id == 'chain_benign' else 'attack',
                'variant': case_id == 'chain_variant', 'execution_verified': True, 'cleanup_verified': True,
                'task_name': 'PRIVATE_TASK', 'anchor_path': 'PRIVATE_SCRIPT', 'execution_receipt': {'raw': 'SECRET_RECEIPT'},
                'stdout_base64': 'SECRET_OUTPUT', 'started_at': bridge.utcnow(), 'finished_at': bridge.utcnow()}
    def collect(self, phase, deployment):
        if phase.get('kind') != bridge.CHAIN_KIND:
            return super().collect(phase, deployment)
        self.calls.append(('collect_chain', phase['id']))
        candidate = deployment['rule_id'].endswith('_candidate')
        cases = []
        for r in phase['results']:
            case = {key: r[key] for key in ('case_id', 'label', 'expected', 'variant', 'execution_verified')}
            case.update({'verdict': 'true_negative' if candidate else 'false_positive'} if r['expected'] == 'benign' else {'verdict': 'detected'})
            case.update({'alert_count': int(case['verdict'] != 'true_negative'), 'latency_seconds': 1.5 if case['verdict'] != 'true_negative' else None,
                         'reason': 'native original proof', 'stages': [{'name': 'task registered', 'status': 'observed', 'time': bridge.utcnow(), 'evidence': 'actual task event'}]})
            cases.append(case)
        metrics = bridge.chain_metrics(cases, [r['case_id'] for r in phase['results']])
        return {'public': {'complete': True, 'metrics': metrics, 'cases': cases, 'unknown_scenarios': [],
                           'detected_scenarios': [case['case_id'] for case in cases if case['alert_count']],
                           'missed_scenarios': [], 'warnings': [], 'timeline': [], 'analysis': {'summary': 'native proof', 'gaps': [], 'recommendations': []}},
                'native_audit': {'rows': [{'_raw': 'SECRET_CHAIN_RAW'}]}}


class BridgeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = bridge.Store(self.directory.name)
        self.runtime = FakeRuntime()
        self.app = bridge.Bridge(config(), self.store, self.runtime, settle_seconds=0)
        self.identifier = str(uuid4())
        self.request = {'request_id': self.identifier, 'name': 'Owned demonstration', 'scenario_ids': ['whoami', 'tasklist', 'systeminfo']}
    def tearDown(self):
        self.runtime.block.set()
        if self.app.worker:
            self.app.worker.join(3)
        self.store.close()
        self.directory.cleanup()
    def wait(self):
        self.app.worker.join(3)
        self.assertFalse(self.app.worker.is_alive())
    def test_complete_workflow_actual_execution_redaction_and_idempotence(self):
        cycle, status = self.app.create(self.request)
        self.assertEqual(status, 202)
        self.wait()
        self.assertEqual(len([c for c in self.runtime.calls if c[0] == 'execute']), 3)
        self.app.create(self.request)
        self.assertEqual(len([c for c in self.runtime.calls if c[0] == 'execute']), 3)
        self.app.collect(self.identifier, {})
        self.wait()
        suggestion, _ = self.app.suggest(self.identifier, {})
        self.assertEqual(len(suggestion['candidate_rule']['any']), 3)
        body = {'expected_revision': 1, 'rule': suggestion['candidate_rule'], 'note': 'observed native processes'}
        self.app.candidate(self.identifier, body)
        self.wait()
        self.assertEqual(self.store.get(self.identifier)['revision'], 2)
        self.app.candidate(self.identifier, body)
        self.app.rerun(self.identifier, {'expected_revision': 2})
        self.wait()
        self.app.rerun(self.identifier, {'expected_revision': 2})
        self.assertEqual(len([c for c in self.runtime.calls if c[0] == 'execute']), 6)
        self.app.collect(self.identifier, {})
        self.wait()
        public, _ = self.app.dispatch('GET', '/cycles/' + self.identifier, {})
        self.assertTrue(public['comparison']['comparable'])
        self.assertEqual(public['candidate_note'], 'observed native processes')
        self.assertNotIn('SECRET', json.dumps(public))
        exported, _ = self.app.dispatch('GET', '/cycles/' + self.identifier + '/export', {})
        self.assertIn('SECRET_RAW', json.dumps(exported))
        self.assertIn('SECRET_OUTPUT', json.dumps(exported))
        self.assertNotIn('SECRET_WINDOWS', json.dumps(exported))
    def test_concurrent_run_and_revision_rejected(self):
        self.runtime.block.clear()
        self.app.create(self.request)
        with self.assertRaises(bridge.APIError) as error:
            self.app.create({**self.request, 'request_id': str(uuid4())})
        self.assertEqual(error.exception.status, 409)
        with self.assertRaises(bridge.APIError):
            self.app.rerun(self.identifier, {'expected_revision': 999})
        self.runtime.block.set()
        self.wait()
        with self.assertRaises(bridge.APIError):
            self.app.create({**self.request, 'name': 'changed'})
    def test_restart_interrupted_never_executes(self):
        self.app.create(self.request)
        self.wait()
        cycle = self.store.get(self.identifier)
        cycle['status'] = cycle['baseline']['status'] = 'running'
        self.store.save(cycle)
        self.store.close()
        self.store = bridge.Store(self.directory.name)
        self.assertEqual(self.store.get(self.identifier)['status'], 'interrupted')
        self.assertEqual(len(self.runtime.calls), 4)
        app = bridge.Bridge(config(), self.store, self.runtime)
        with self.assertRaises(bridge.APIError):
            app.collect(self.identifier, {})
    def test_status_readonly_and_http_authentication(self):
        server = bridge.Server(('127.0.0.1', 0), self.app, 'a' * 40)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        try:
            client = http.client.HTTPConnection('127.0.0.1', server.server_port)
            client.request('GET', '/status'); response = client.getresponse()
            self.assertEqual(response.status, 401); response.read()
            client.request('GET', '/status', headers={'Authorization': 'Bearer ' + 'a' * 40})
            response = client.getresponse(); result = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertTrue(result['ready'])
            self.assertFalse(self.runtime.calls)
            client.request('POST', '/cycles', body='{"request_id":1,"request_id":2}', headers={'Authorization': 'Bearer ' + 'a' * 40, 'Content-Type': 'application/json'})
            response = client.getresponse(); self.assertEqual(response.status, 400); response.read()
            self.assertFalse(self.runtime.calls)
            client.close()
        finally:
            server.shutdown(); server.server_close(); worker.join(2)

    def use_chain(self):
        self.runtime = ChainRuntime()
        self.app.runtime = self.runtime
        self.request['scenario_ids'] = [bridge.CHAIN_PACK_ID]

    def test_chain_workflow_separates_paired_metrics_and_heldout(self):
        self.use_chain()
        cycle, status = self.app.create(self.request)
        self.assertEqual((status, cycle['kind']), (202, bridge.CHAIN_KIND))
        self.assertIsNone(cycle['comparison']['baseline_metrics'])
        self.wait()
        baseline_calls = [c for c in self.runtime.calls if c[0] == 'execute_chain']
        self.assertEqual([c[1] for c in baseline_calls], list(bridge.CHAIN_COMMON_CASES))
        self.assertEqual(cycle['baseline']['kind'], bridge.CHAIN_KIND)
        self.app.collect(self.identifier, {}); self.wait()
        suggestion, _ = self.app.suggest(self.identifier, {})
        self.assertEqual(suggestion['candidate_rule']['profile'], 'task_behavior')
        self.assertTrue(suggestion['explanation']['causes'])
        self.assertNotIn('chain_variant', json.dumps(suggestion))
        candidate = {'expected_revision': 1, 'rule': suggestion['candidate_rule'], 'note': 'native behavior proof'}
        self.app.candidate(self.identifier, candidate); self.wait()
        self.app.candidate(self.identifier, candidate)
        self.app.rerun(self.identifier, {'expected_revision': 2}); self.wait()
        calls = [c for c in self.runtime.calls if c[0] == 'execute_chain']
        self.assertEqual([c[1] for c in calls], list(bridge.CHAIN_COMMON_CASES) * 2 + [bridge.CHAIN_VARIANT_CASE])
        self.assertNotEqual(calls[0][2], calls[2][2])
        self.assertEqual(len({c[3] for c in calls}), 5)
        self.app.rerun(self.identifier, {'expected_revision': 2})
        self.assertEqual(len([c for c in self.runtime.calls if c[0] == 'execute_chain']), 5)
        self.app.collect(self.identifier, {}); self.wait()
        public, _ = self.app.dispatch('GET', '/cycles/' + self.identifier, {})
        comparison = public['comparison']
        self.assertTrue(comparison['comparable'])
        self.assertEqual(comparison['baseline_metrics']['false_positives'], 1)
        self.assertEqual(comparison['current_metrics']['false_positives'], 0)
        self.assertEqual(comparison['current_metrics']['true_negatives'], 1)
        self.assertEqual(comparison['current_metrics']['attack_total'], 1)
        self.assertEqual(public['current']['evidence']['metrics']['attack_total'], 2)
        self.assertEqual(comparison['heldout_variant']['case_id'], 'chain_variant')
        self.assertEqual(public['candidate_explanation'], suggestion['explanation'])
        self.assertNotIn('SECRET', json.dumps(public))
        self.assertNotIn('PRIVATE', json.dumps(public))
        self.assertTrue(public['current']['results'][0]['cleanup_verified'])
        exported, _ = self.app.dispatch('GET', '/cycles/' + self.identifier + '/export', {})
        self.assertIn('SECRET_RECEIPT', json.dumps(exported))
        with self.assertRaises(bridge.APIError):
            self.app.candidate(self.identifier, {**candidate, 'expected_revision': 2, 'note': 'change after current'})

    def test_chain_mixing_and_rule_kind_crossovers_rejected(self):
        status = self.app.status()
        self.assertEqual([s['id'] for s in status['scenarios']][-1], bridge.CHAIN_PACK_ID)
        with self.assertRaises(bridge.APIError) as error:
            self.app.create({**self.request, 'scenario_ids': [bridge.CHAIN_PACK_ID, 'whoami']})
        self.assertEqual(error.exception.status, 400)
        self.assertFalse(self.runtime.calls)
        self.use_chain()
        self.app.create(self.request); self.wait()
        self.app.collect(self.identifier, {}); self.wait()
        for rule in (bridge.baseline_rule(), bridge.chain_baseline_rule()):
            with self.assertRaises(bridge.APIError) as error:
                self.app.candidate(self.identifier, {'expected_revision': 1, 'rule': rule, 'note': 'invalid crossover'})
            self.assertEqual(error.exception.status, 400)
        old = self.store.get(self.identifier)
        old.pop('kind')
        old['baseline_rule'] = bridge.baseline_rule()
        with self.assertRaises(bridge.APIError):
            self.app.candidate(self.identifier, {'expected_revision': 1, 'rule': {'kind': bridge.CHAIN_KIND, 'name': 'candidate', 'profile': 'task_behavior'}, 'note': 'invalid crossover'})

    def test_chain_unknown_and_partial_do_not_become_confirmed_metrics(self):
        cases = [{'case_id': 'chain_attack', 'expected': 'attack', 'execution_verified': False, 'verdict': 'detected'},
                 {'case_id': 'chain_benign', 'expected': 'benign', 'execution_verified': True, 'verdict': 'true_negative'}]
        metrics = bridge.chain_metrics(cases, bridge.CHAIN_COMMON_CASES)
        self.assertEqual((metrics['true_positives'], metrics['unknown'], metrics['true_negatives']), (0, 1, 1))
        duplicate = bridge.chain_metrics(cases + [cases[1]], bridge.CHAIN_COMMON_CASES)
        self.assertEqual(duplicate['unknown'], 2)
        public = {'complete': True, 'cases': cases, 'unknown_scenarios': ['chain_attack']}
        self.assertFalse(bridge.chain_comparison(public, public)['comparable'])
        with self.assertRaises(bridge.APIError):
            bridge.Bridge._suggest_chain({'public': public})
        cases[0]['execution_verified'] = True
        public['complete'] = False
        with self.assertRaises(bridge.APIError):
            bridge.Bridge._suggest_chain({'public': public})
        public['complete'] = True
        public['unknown_scenarios'] = []
        current = copy.deepcopy(public)
        current['cases'].append({'case_id': 'chain_variant', 'expected': 'attack', 'execution_verified': False, 'verdict': 'unknown'})
        compared = bridge.chain_comparison(public, current)
        self.assertTrue(compared['comparable'])
        self.assertEqual(compared['current_metrics']['attack_total'], 1)
        self.assertEqual(compared['heldout_variant']['verdict'], 'unknown')

    def test_chain_direct_candidate_requires_complete_evidence_and_review(self):
        self.use_chain()
        self.app.create(self.request); self.wait()
        body = {'expected_revision': 1, 'rule': {'kind': bridge.CHAIN_KIND, 'name': 'reviewed candidate', 'profile': 'task_behavior'}, 'note': 'actual task behavior evidence'}
        with self.assertRaises(bridge.APIError) as error:
            self.app.candidate(self.identifier, body)
        self.assertEqual(error.exception.status, 409)
        self.app.collect(self.identifier, {}); self.wait()
        cycle = self.store.get(self.identifier)
        baseline = cycle['baseline']['evidence']['public']
        baseline['complete'] = False
        with self.assertRaises(bridge.APIError) as error:
            self.app.candidate(self.identifier, body)
        self.assertEqual(error.exception.status, 409)
        baseline['complete'] = True
        baseline['unknown_scenarios'] = ['chain_attack']
        with self.assertRaises(bridge.APIError) as error:
            self.app.candidate(self.identifier, body)
        self.assertEqual(error.exception.status, 409)
        baseline['unknown_scenarios'] = []
        with self.assertRaises(bridge.APIError) as error:
            self.app.candidate(self.identifier, {**body, 'note': ' \n\t '})
        self.assertEqual(error.exception.status, 400)
        self.assertFalse(cycle.get('candidate_rule'))
        self.assertEqual([c[1] for c in self.runtime.calls if c[0] == 'deploy'], ['baseline'])

    def test_chain_failed_candidate_cannot_rerun_and_can_retry_deployment(self):
        self.use_chain()
        self.app.create(self.request); self.wait()
        self.app.collect(self.identifier, {}); self.wait()
        suggestion, _ = self.app.suggest(self.identifier, {})
        body = {'expected_revision': 1, 'rule': suggestion['candidate_rule'], 'note': 'reviewed actual task creation'}
        original_deploy = self.runtime.deploy
        def fail_candidate(identifier, role, rule):
            if role == 'candidate':
                raise bridge.RangeError('Native candidate deployment failed')
            return original_deploy(identifier, role, rule)
        self.runtime.deploy = fail_candidate
        self.app.candidate(self.identifier, body); self.wait()
        cycle = self.store.get(self.identifier)
        self.assertEqual((cycle['status'], cycle['revision']), ('failed', 1))
        self.assertNotIn('candidate', cycle['deployments'])
        with self.assertRaises(bridge.APIError):
            self.app.rerun(self.identifier, {'expected_revision': 1})
        self.assertEqual(len([c for c in self.runtime.calls if c[0] == 'execute_chain']), 2)
        self.runtime.deploy = original_deploy
        self.app.candidate(self.identifier, body); self.wait()
        self.assertEqual((cycle['status'], cycle['revision']), ('candidate_ready', 2))
        self.assertEqual(len(cycle['candidate_history']), 1)
        self.assertEqual(cycle['candidate_history'][0]['explanation'], cycle['candidate_explanation'])

    def test_chain_restart_does_not_repeat_interrupted_rerun(self):
        self.use_chain()
        self.app.create(self.request); self.wait()
        self.app.collect(self.identifier, {}); self.wait()
        suggestion, _ = self.app.suggest(self.identifier, {})
        self.app.candidate(self.identifier, {'expected_revision': 1, 'rule': suggestion['candidate_rule'], 'note': 'reviewed evidence'}); self.wait()
        cycle = self.store.get(self.identifier)
        cycle['current'] = self.app._phase(bridge.CHAIN_KIND)
        cycle['status'] = cycle['current']['status'] = 'running'
        cycle['current']['started_at'] = bridge.utcnow()
        self.store.save(cycle)
        self.store.close()
        self.store = bridge.Store(self.directory.name)
        self.app = bridge.Bridge(config(), self.store, self.runtime, settle_seconds=0)
        calls = len(self.runtime.calls)
        self.assertEqual(self.store.get(self.identifier)['status'], 'interrupted')
        self.app.rerun(self.identifier, {'expected_revision': 2})
        self.assertEqual(len(self.runtime.calls), calls)
        with self.assertRaises(bridge.APIError):
            self.app.collect(self.identifier, {})
        with self.assertRaises(bridge.APIError):
            self.app.candidate(self.identifier, {'expected_revision': 2, 'rule': suggestion['candidate_rule'], 'note': 'change after interrupted run'})

    def test_complete_query_with_unknown_chain_can_recollect_without_execution(self):
        self.use_chain()
        self.app.create(self.request); self.wait()
        original_collect = self.runtime.collect
        attempts = []
        def delayed_originals(phase, deployment):
            evidence = original_collect(phase, deployment)
            attempts.append(phase['id'])
            if len(attempts) == 1:
                # The search completed but native ancestry has not arrived.
                evidence['public']['unknown_scenarios'] = ['chain_attack']
                evidence['public']['cases'][0]['execution_verified'] = False
                evidence['public']['cases'][0]['verdict'] = 'unknown'
            return evidence
        self.runtime.collect = delayed_originals
        self.app.collect(self.identifier, {}); self.wait()
        self.assertEqual(self.store.get(self.identifier)['status'], 'inconclusive')
        with self.assertRaises(bridge.APIError):
            self.app.suggest(self.identifier, {})
        _, status = self.app.collect(self.identifier, {})
        self.assertEqual(status, 202)
        self.wait()
        phase = self.store.get(self.identifier)['baseline']
        self.assertEqual(len(phase['collections']), 2)
        self.assertEqual(phase['collections'][0]['public']['unknown_scenarios'], ['chain_attack'])
        self.assertFalse(phase['collections'][1]['public']['unknown_scenarios'])
        self.assertEqual(self.store.get(self.identifier)['status'], 'completed')
        self.assertEqual(len([c for c in self.runtime.calls if c[0] == 'execute_chain']), 2)


if __name__ == '__main__':
    unittest.main()
