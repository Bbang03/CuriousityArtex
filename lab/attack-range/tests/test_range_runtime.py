import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtime


def config():
    return {'name': 'Owned test range', 'router_host': 'router.example.test', 'router_user': 'ubuntu',
            'ssh_key': '/run/range/key', 'known_hosts': '/run/range/known_hosts', 'windows_host': '10.0.2.11',
            'windows_hostname': 'WINDOWS-LAB', 'windows_user': 'Administrator', 'windows_password': 'SECRET_WINDOWS',
            'splunk_host': '10.0.2.10', 'splunk_user': 'admin', 'splunk_password': 'SECRET_SPLUNK',
            'splunk_tls_sha256': 'a' * 64, 'index': 'win', 'alert_index': 'aegis_range_alerts',
            'scenarios': [{'id': key, 'name': key, 'description': 'installed native Atomic', 'technique': value[0],
                           'atomic_guid': value[1], 'image': value[2], 'yaml_sha256': 'b' * 64} for key, value in runtime.CATALOG.items()]}


def event(guid=None, parent=None, image='C:\\Windows\\System32\\whoami.exe', command='whoami', when=None, host='WINDOWS-LAB'):
    guid, parent = guid or str(uuid4()), parent or str(uuid4())
    when = when if when is not None else datetime.now(timezone.utc).timestamp()
    stamp = datetime.fromtimestamp(when, timezone.utc).isoformat().replace('+00:00', 'Z')
    raw = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
           "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><TimeCreated SystemTime='" + stamp + "'/>"
           '<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>' + host + '</Computer></System><EventData>'
           "<Data Name='Image'>" + image + "</Data><Data Name='CommandLine'>" + command + "</Data>"
           "<Data Name='ProcessGuid'>{" + guid + "}</Data><Data Name='ParentProcessGuid'>{" + parent + "}</Data></EventData></Event>")
    return {'_raw': raw, '_time': 'Splunk display format', 'native_event_epoch': str(when), 'host': host,
            'source': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', 'sourcetype': 'XmlWinEventLog'}


class RuntimeTest(unittest.TestCase):
    def test_scope_and_commands_are_not_configurable(self):
        c = config()
        self.assertEqual(runtime.validate_config(c)['index'], 'win')
        for key, value in [('index', '*'), ('router_user', 'root'), ('windows_host', '203.0.113.5'), ('windows_hostname', 'x | search index=*')]:
            bad = copy.deepcopy(c); bad[key] = value
            with self.assertRaises(runtime.RangeError):
                runtime.validate_config(bad)
        bad = copy.deepcopy(c); bad['scenarios'][0]['atomic_guid'] = str(uuid4())
        with self.assertRaises(runtime.RangeError):
            runtime.validate_config(bad)

    def test_structured_compiler_scopes_and_escapes_spl(self):
        rule = runtime.baseline_rule()
        rule['any'][0]['all'][0]['value'] = '") | search index=* <script>.*'
        compiled = runtime.rule_search(config(), rule, 'aegis_range_' + 'a' * 32 + '_baseline', 100)
        self.assertTrue(compiled.startswith('index="win" source='))
        self.assertIn('lower(Computer)="windows-lab" AND _time>=100.000000', compiled)
        self.assertIn('match(lower(tostring(\'Image\'))', compiled)
        self.assertIn('mvcount(\'Image\')=1', compiled)
        self.assertIn('\\\\.\\\\*', compiled)
        self.assertNotIn('index="aegis_range_alerts"', compiled)
        self.assertFalse(compiled.startswith('search '))
        self.assertTrue(('search ' + compiled).startswith('search index='))
        for field in ['ProcessGuid', 'label', '_time', 'host']:
            bad = runtime.baseline_rule(); bad['any'][0]['all'][0]['field'] = field
            with self.assertRaises(runtime.RangeError):
                runtime.validate_rule(bad)
        bad = runtime.baseline_rule(); bad['any'][0]['all'][0]['value'] = str(uuid4())
        with self.assertRaises(runtime.RangeError):
            runtime.validate_rule(bad)

    def test_digest_is_order_stable_and_go_html_escaped(self):
        r = runtime.baseline_rule()
        r['name'] = '<>&한글'
        reordered = {'any': r['any'], 'name': r['name']}
        self.assertEqual(runtime.rule_digest(r), runtime.rule_digest(reordered))
        ordered = json.dumps(r, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
        self.assertEqual(runtime.rule_digest(r), hashlib.sha256(ordered.encode()).hexdigest())

    def test_native_xml_time_source_and_duplicate_rejection(self):
        row = event()
        parsed = runtime.parse_sysmon(row, config())
        self.assertEqual(parsed['Image'], 'C:\\Windows\\System32\\whoami.exe')
        self.assertEqual(parsed['native']['_raw'], row['_raw'])
        for mutate in [lambda r: r.update(host='OTHER'), lambda r: r.update(native_event_epoch='1'), lambda r: r.update(_raw=r['_raw'].replace('</EventData>', "<Data Name='Image'>fake</Data></EventData>")), lambda r: r.update(_raw='<!DOCTYPE x [<!ENTITY x "y">]>' + r['_raw'])]:
            bad = copy.deepcopy(row); mutate(bad)
            with self.assertRaises(runtime.RangeError):
                runtime.parse_sysmon(bad, config())

    def test_ancestry_requires_actual_descendant_not_uuid_text(self):
        root, child, unrelated = str(uuid4()), str(uuid4()), str(uuid4())
        path = 'C:\\AegisLoop\\runs\\' + str(uuid4()) + '\\run.ps1'
        rows = [event(root, image='C:\\Windows\\System32\\powershell.exe', command='powershell -File ' + path),
                event(child, root), event(unrelated, command='whoami ' + path)]
        parsed = [runtime.parse_sysmon(row, config()) for row in rows]
        attributed, unknown = runtime.ancestry(parsed, {'whoami': path})
        self.assertEqual([e['ProcessGuid'] for e in attributed['whoami']], [child])
        self.assertFalse(unknown)
        missing, unknown = runtime.ancestry([parsed[0], parsed[2]], {'whoami': path})
        self.assertEqual(unknown, ['whoami'])
        self.assertFalse(missing['whoami'])

    def test_actual_alert_needs_hash_guid_and_complete_wait(self):
        now = datetime.now(timezone.utc).timestamp()
        root, child = str(uuid4()), str(uuid4())
        path = 'C:\\AegisLoop\\runs\\' + str(uuid4()) + '\\run.ps1'
        phase = {'started_at': datetime.fromtimestamp(now - 201, timezone.utc).isoformat(), 'finished_at': datetime.fromtimestamp(now - 180, timezone.utc).isoformat(),
                 'results': [{'scenario_id': 'whoami', 'status': 'completed', 'anchor_path': path}]}
        deployment = {'rule_id': 'aegis_range_' + 'a' * 32 + '_baseline', 'rule_sha256': 'b' * 64}
        rows = [event(root, image='C:\\Windows\\System32\\powershell.exe', command='powershell -File ' + path, when=now - 195), event(child, root, when=now - 190)]
        alert = {'event_kind': 'alert', 'detection_rule_id': deployment['rule_id'], 'rule_sha256': deployment['rule_sha256'], 'host': 'WINDOWS-LAB', 'detection_engine': 'splunk_saved_search', 'audit_process_guid': child, 'event_epoch': now - 190, 'alert_created_at': datetime.fromtimestamp(now - 100, timezone.utc).isoformat()}
        alert_row = {'_raw': json.dumps(alert), 'source': deployment['rule_id'], 'sourcetype': 'aegis:range:alert'}
        rt = runtime.Runtime(config())
        class Source:
            def scheduler_proof(self, *args):
                return {'complete': True, 'warnings': []}
            def __init__(self, alerts_complete=True, value=alert_row):
                self.alerts_complete, self.value = alerts_complete, value
            def search(self, query, *_):
                is_alert = 'aegis_range_alerts' in query
                return {'rows': [self.value] if is_alert and self.value else rows if not is_alert else [], 'complete': self.alerts_complete if is_alert else True, 'warnings': []}
        rt.splunk = Source()
        self.assertEqual(rt.collect(phase, deployment)['public']['detected_scenarios'], ['whoami'])
        background_guid = str(uuid4())
        background = event(background_guid, when=now - 190)
        background_alert = {**alert, 'audit_process_guid': background_guid}
        class BackgroundSource(Source):
            def search(self, query, *args):
                result = super().search(query, *args)
                if 'aegis_range_alerts' not in query:
                    result['rows'] = [*rows, background]
                else:
                    result['rows'] = [alert_row, {**alert_row, '_raw': json.dumps(background_alert)}]
                return result
        rt.splunk = BackgroundSource()
        self.assertEqual(rt.collect(phase, deployment)['public']['alert_count'], 1)
        rt.splunk = Source(value=None)
        self.assertEqual(rt.collect(phase, deployment)['public']['missed_scenarios'], ['whoami'])
        rt.splunk = Source(alerts_complete=False, value=None)
        result = rt.collect(phase, deployment)['public']
        self.assertEqual(result['unknown_scenarios'], ['whoami'])
        self.assertFalse(result['missed_scenarios'])
        wrong = copy.deepcopy(alert); wrong['rule_sha256'] = 'c' * 64
        rt.splunk = Source(value={**alert_row, '_raw': json.dumps(wrong)})
        self.assertFalse(rt.collect(phase, deployment)['public']['detected_scenarios'])

    def test_other_phase_alerts_are_ignored_but_malformed_times_warn(self):
        now = datetime.now(timezone.utc).timestamp()
        parent, child = str(uuid4()), str(uuid4())
        path = 'C:\\AegisLoop\\runs\\' + str(uuid4()) + '\\run.ps1'
        phase = {'started_at': datetime.fromtimestamp(now - 201, timezone.utc).isoformat(), 'finished_at': datetime.fromtimestamp(now - 180, timezone.utc).isoformat(),
                 'results': [{'scenario_id': 'whoami', 'status': 'completed', 'anchor_path': path}]}
        deployment = {'rule_id': 'aegis_range_' + 'a' * 32 + '_baseline', 'rule_sha256': 'b' * 64}
        audit = [event(parent, image='C:\\Windows\\System32\\powershell.exe', command='powershell -File ' + path, when=now - 195), event(child, parent, when=now - 190)]
        # A genuine, correctly attributed rule alert can be indexed now while
        # its original event belongs to a different (earlier/later) execution.
        alert = {'event_kind': 'alert', 'detection_rule_id': deployment['rule_id'], 'rule_sha256': deployment['rule_sha256'], 'host': 'WINDOWS-LAB',
                 'detection_engine': 'splunk_saved_search', 'audit_process_guid': str(uuid4()), 'event_epoch': now - 250,
                 'alert_created_at': datetime.fromtimestamp(now - 30, timezone.utc).isoformat()}
        class Source:
            def __init__(self, payload):
                self.payload = payload
            def scheduler_proof(self, *_):
                return {'complete': True, 'warnings': []}
            def search(self, query, *_):
                rows = [{'_raw': json.dumps(self.payload), 'source': deployment['rule_id'], 'sourcetype': 'aegis:range:alert'}] if 'aegis_range_alerts' in query else audit
                return {'rows': rows, 'complete': True, 'warnings': []}
        rt = runtime.Runtime(config())
        for outside in (now - 250, now - 100):
            rt.splunk = Source({**alert, 'event_epoch': outside})
            result = rt.collect(phase, deployment)
            self.assertTrue(result['public']['complete'])
            self.assertFalse(result['public']['warnings'])
            self.assertEqual(result['public']['alert_count'], 0)
            self.assertEqual(result['public']['missed_scenarios'], ['whoami'])
            self.assertEqual(len(result['native_alerts']['rows']), 1)
        for invalid in ('not-a-time', 'nan', 'inf', '-inf'):
            rt.splunk = Source({**alert, 'event_epoch': invalid})
            result = rt.collect(phase, deployment)['public']
            self.assertFalse(result['complete'])
            self.assertTrue(result['warnings'])
            self.assertEqual(result['unknown_scenarios'], ['whoami'])
        rt.splunk = Source({**alert, 'alert_created_at': 'not-a-time'})
        self.assertFalse(rt.collect(phase, deployment)['public']['complete'])

    def test_job_empty_done_vs_failed_and_truncated(self):
        class Source(runtime.Splunk):
            def __init__(self, state='DONE', count=0):
                self.state, self.count = state, count
            def raw(self, method, path, form=None, limit=None):
                if path.endswith('/jobs'):
                    return b'{"sid":"test_sid"}'
                if path.endswith('/results'):
                    return b'{"results":[]}'
                return json.dumps({'entry': [{'content': {'isDone': True, 'isFailed': self.state == 'FAILED', 'dispatchState': self.state, 'resultCount': self.count}}]}).encode()
        self.assertTrue(Source().search('fixed', 1, 2)['complete'])
        self.assertFalse(Source('FAILED').search('fixed', 1, 2)['complete'])
        self.assertFalse(Source(count=1).search('fixed', 1, 2)['complete'])

    def test_scheduler_proof_requires_scheduled_completed_covering_job(self):
        name = 'aegis_range_' + 'a' * 32 + '_baseline'
        deployment = {'rule_id': name, 'rule_sha256': 'b' * 64, 'enabled_at': 100, 'search': 'fixed scoped search'}
        class Source(runtime.Splunk):
            def __init__(self, latest=300, finalized=False, scheduled=True, label=name, duplicate_search=False):
                self.latest, self.finalized, self.scheduled, self.label, self.duplicate_search = latest, finalized, scheduled, label, duplicate_search
            def raw(self, method, path, form=None):
                if path.endswith('/history'):
                    content = {'isScheduled': self.scheduled, 'isDone': True, 'isFinalized': False}
                    return json.dumps({'entry': [{'name': 'scheduler__admin__range_test', 'content': content}]}).encode()
                if '/search/jobs/' in path:
                    content = {'dispatchState': 'DONE', 'isDone': True, 'isFailed': False, 'isFinalized': self.finalized,
                               'isSavedSearch': True, 'label': self.label, 'search': ('search search ' if self.duplicate_search else 'search ') + deployment['search'], 'searchEarliestTime': 90, 'searchLatestTime': self.latest}
                else:
                    content = {'search': deployment['search'], 'description': runtime.OWNER + deployment['rule_sha256'],
                               'disabled': False, 'is_scheduled': True, 'actions': 'logevent', 'action.logevent': True}
                return json.dumps({'entry': [{'content': content}]}).encode()
        self.assertTrue(Source().scheduler_proof(deployment, 110, 250)['complete'])
        self.assertFalse(Source(latest=200).scheduler_proof(deployment, 110, 250)['complete'])
        self.assertFalse(Source(finalized=True).scheduler_proof(deployment, 110, 250)['complete'])
        self.assertFalse(Source(scheduled=False).scheduler_proof(deployment, 110, 250)['complete'])
        self.assertFalse(Source(label='foreign').scheduler_proof(deployment, 110, 250)['complete'])
        self.assertFalse(Source(duplicate_search=True).scheduler_proof(deployment, 110, 250)['complete'])

    def test_pin_checked_before_credentials(self):
        connection = unittest.mock.MagicMock()
        connection.sock.getpeercert.return_value = b'wrong-cert'
        tunnel = unittest.mock.Mock()
        with patch('runtime.http.client.HTTPSConnection', return_value=connection), patch('runtime.valid_certificate'):
            with self.assertRaises(runtime.RangeError):
                runtime.Splunk(config(), tunnel).raw('GET', '/services/server/info')
        connection.request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
