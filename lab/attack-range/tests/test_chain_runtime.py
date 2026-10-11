import base64
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time
import types
import unittest
from unittest.mock import patch
from uuid import uuid4
from xml.sax.saxutils import escape, quoteattr

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtime
import chain_runtime as chain
from test_range_runtime import config


def stamp(at):
    return datetime.fromtimestamp(at, timezone.utc).isoformat().replace('+00:00', 'Z')


def xml_event(source, code, at, values, actor_pid=3010):
    provider, channel, _ = chain.SOURCES[source]
    raw = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name=' + quoteattr(provider) + '/><EventID>' + str(code) + '</EventID><TimeCreated SystemTime=' + quoteattr(stamp(at)) + '/><Execution ProcessID=' + quoteattr(str(actor_pid)) + '/><Channel>' + channel + '</Channel><Computer>WINDOWS-LAB</Computer></System><EventData>'
    raw += ''.join('<Data Name=' + quoteattr(k) + '>' + escape(str(v)) + '</Data>' for k, v in values.items()) + '</EventData></Event>'
    return {'_raw': raw, '_time': 'Splunk display date', 'native_event_epoch': str(at), 'host': 'WINDOWS-LAB', 'sourcetype': 'XmlWinEventLog', 'source': source}


def fixture(case='chain_attack', start=None, actor=3010):
    start = start or time.time() - 400
    run = str(uuid4()); phase = str(uuid4()); root = str(uuid4()); child = str(uuid4())
    path = 'C:\\AegisLoop\\runs\\' + phase + '\\' + run + '\\register.ps1'
    task = 'AegisLoop-' + run
    output = 'C:\\Windows\\Temp\\' + run + '\\outcome.json'
    ps = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    sources = list(chain.SOURCES)
    task_xml = '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>' + ps + '</Command><Arguments>-EncodedCommand test</Arguments><WorkingDirectory>C:\\Windows\\Temp</WorkingDirectory></Exec></Actions></Task>'
    rows = [xml_event(sources[0], 1, start + 1, {'ProcessGuid': '{' + root + '}', 'ParentProcessGuid': '{' + str(uuid4()) + '}', 'ProcessId': actor, 'Image': ps, 'CommandLine': ps + ' -File ' + path}),
            xml_event(sources[1], 4104, start + 2, {'ScriptBlockText': 'Register-ScheduledTask example'}, actor),
            xml_event(sources[1], 4103, start + 3, {'Payload': 'CommandInvocation(Register-ScheduledTask): "Register-ScheduledTask"\nParameterBinding(Register-ScheduledTask): name="TaskName"; value="' + task + '"'}, actor),
            xml_event(sources[3], 4698, start + 4, {'TaskName': '\\' + task, 'TaskContent': task_xml, 'ClientProcessId': '9999'}),
            xml_event(sources[2], 129, start + 24, {'TaskName': '\\' + task, 'ProcessID': actor + 100}),
            xml_event(sources[0], 1, start + 24, {'ProcessGuid': '{' + child + '}', 'ParentProcessGuid': '{' + str(uuid4()) + '}', 'ProcessId': actor + 100, 'Image': ps, 'CommandLine': ps + ' -EncodedCommand test'}),
            xml_event(sources[2], 200, start + 24, {'TaskName': '\\' + task, 'ActionName': ps}),
            xml_event(sources[2], 201, start + 25, {'TaskName': '\\' + task, 'ActionName': ps, 'ResultCode': '0'}),
            xml_event(sources[0], 11, start + 25, {'ProcessGuid': '{' + child + '}', 'ProcessId': actor + 100, 'Image': ps, 'TargetFilename': output})]
    result = {'case_id': case, 'scenario_id': case, 'anchor_path': path, 'task_name': task, 'correlation_id': run, 'started_at': stamp(start), 'finished_at': stamp(start + 28), 'status': 'completed', 'execution_verified': True, 'cleanup_verified': True, 'execution_receipt': {'output_path': output, 'cleaned_at': stamp(start + 27)}}
    return result, rows, root, child


class Source:
    def __init__(self, rows, alert_guids, deployment, count=20, complete=True):
        self.rows, self.alert_guids, self.deployment, self.count, self.complete = rows, alert_guids, deployment, count, complete
    def scheduler_proof(self, _, start, finish):
        return {'complete': True, 'warnings': [], 'jobs': [{'earliest_time': start - 600, 'latest_time': finish + 10}]}
    def search(self, query, *_):
        if 'stats count by source' in query:
            return {'rows': [{'source': s, 'count': self.count} for s in chain.SOURCES], 'complete': self.complete, 'warnings': []}
        if 'aegis_range_alerts' not in query:
            return {'rows': self.rows, 'complete': self.complete, 'warnings': []}
        alerts = []
        for guid in self.alert_guids:
            event = next((chain.parse(row, config()) for row in self.rows if 'Sysmon' in row['source'] and '<EventID>1</EventID>' in row['_raw'] and guid in row['_raw']), None)
            value = {'event_kind': 'alert', 'detection_engine': 'splunk_saved_search', 'detection_rule_id': self.deployment['rule_id'], 'rule_sha256': self.deployment['rule_sha256'], 'host': 'WINDOWS-LAB', 'audit_process_guid': guid, 'event_epoch': event['epoch'], 'alert_created_at': stamp(event['epoch'] + 80)}
            alerts.append({'_raw': json.dumps(value), 'source': self.deployment['rule_id'], 'sourcetype': 'aegis:range:alert'})
        return {'rows': alerts, 'complete': self.complete, 'warnings': []}


def collect(results, rows, guids, count=20, complete=True):
    phase = {'kind': chain.KIND, 'started_at': min(r['started_at'] for r in results), 'finished_at': max(r['finished_at'] for r in results), 'results': results}
    deployment = {'rule_id': 'aegis_range_' + 'a' * 32 + '_baseline', 'rule_sha256': 'b' * 64}
    rt = runtime.Runtime(config()); rt.splunk = Source(rows, guids, deployment, count, complete)
    return chain.collect(rt, phase, deployment)


class ChainTest(unittest.TestCase):
    def test_native_rule_uses_behavior_and_multiple_sources_without_run_features(self):
        rule = chain.candidate()
        search = runtime.rule_search(config(), rule, 'aegis_range_' + 'a' * 32 + '_candidate', 100)
        self.assertTrue(search.startswith('index="win"'))
        self.assertFalse(search.startswith('search '))
        for word in ('4103', '4104', '4698', '129', '200', 'TaskProcessPID', 'CreatorPID', 'ParameterBinding', 'WorkingDirectory', 'encodedcommand', 'windowstyle'):
            self.assertIn(word, search)
        for excluded in ('chain_attack', 'chain_benign', 'outcome.json', 'operation.ps1', 'maintenance', 'AegisLoop-'):
            self.assertNotIn(excluded, search)
        self.assertEqual(runtime.rule_digest(rule), runtime.rule_digest(dict(reversed(list(rule.items())))))
        for bad in ({**rule, 'profile': 'arbitrary'}, {**rule, 'any': []}, {**rule, 'command': 'anything'}):
            with self.assertRaises(runtime.RangeError): runtime.validate_rule(bad)

    def test_actual_parameter_binding_resolves_actor_despite_broker_pid(self):
        result, rows, root, child = fixture()
        parsed = [chain.parse(row, config()) for row in rows]
        links = chain.correlate(result, parsed)
        self.assertTrue(links['verified'], links['gaps'])
        self.assertEqual(links['guids'], {root, child})
        self.assertEqual(len(links['stages']), 4)
        no_binding = [e for e in parsed if e['event_code'] != '4103']
        self.assertFalse(chain.correlate(result, no_binding)['verified'])
        unrelated = copy.deepcopy(parsed); unrelated[2]['system_pid'] += 1
        self.assertFalse(chain.correlate(result, unrelated)['verified'])

    def test_missing_native_action_or_invalid_time_cannot_be_truth_negative(self):
        result, rows, _, _ = fixture()
        bad = copy.deepcopy(rows[3]); bad['_raw'] = bad['_raw'].replace(escape(chain.parse(bad, config())['values']['TaskContent']), escape('<Task/>'))
        with self.assertRaises(runtime.RangeError): chain.action_values(chain.parse(bad, config()))
        bad = copy.deepcopy(rows[0]); bad['native_event_epoch'] = 'NaN'
        with self.assertRaises(runtime.RangeError): chain.parse(bad, config())
        rows = [r for r in rows if '<EventID>11</EventID>' not in r['_raw']]
        public = collect([result], rows, [])['public']
        self.assertEqual(public['cases'][0]['verdict'], 'unknown')
        self.assertEqual(public['metrics']['false_negatives'], 0)

    def test_paired_tp_fp_and_candidate_tp_tn_and_export_privacy(self):
        one, rows1, root1, child1 = fixture(start=time.time()-500, actor=1000)
        two, rows2, root2, child2 = fixture('chain_benign', start=time.time()-460, actor=2000)
        output = collect([one,two], rows1+rows2, [root1,root2])
        self.assertEqual(output['public']['metrics']['true_positives'], 1)
        self.assertEqual(output['public']['metrics']['false_positives'], 1)
        self.assertEqual(output['public']['alert_count'], 2)
        public = json.dumps(output['public'])
        self.assertNotIn(one['task_name'], public); self.assertNotIn('ScriptBlockText', public)
        self.assertIn('ScriptBlockText', json.dumps(output['native_audit']))
        improved = collect([one,two], rows1+rows2, [child1])['public']
        self.assertEqual(improved['metrics']['true_positives'], 1)
        self.assertEqual(improved['metrics']['true_negatives'], 1)
        self.assertEqual(improved['metrics']['false_positives'], 0)
        variant, rows3, _, child3 = fixture('chain_variant', start=time.time()-420, actor=3000)
        heldout = collect([one,two,variant], rows1+rows2+rows3, [child1,child3])['public']
        self.assertEqual(heldout['metrics']['true_positives'], 2)
        self.assertEqual(heldout['metrics']['benign_total'], 1)

    def test_limits_or_conflicting_guid_or_failed_cleanup_stay_unknown(self):
        result, rows, _, child = fixture()
        for count, complete in [(5001,True),(20,False)]:
            public = collect([result],rows,[],count,complete)['public']
            self.assertFalse(public['complete']); self.assertEqual(public['cases'][0]['verdict'],'unknown')
        conflict = copy.deepcopy(rows[0]); conflict['_raw'] = conflict['_raw'].replace(' -File ', ' -Wrong ')
        public = collect([result], rows+[conflict], [])['public']
        self.assertFalse(public['complete']); self.assertEqual(public['metrics']['unknown'],1)
        result['cleanup_verified'] = False
        public = collect([result], rows, [child])['public']
        self.assertEqual(public['cases'][0]['verdict'],'unknown'); self.assertEqual(public['metrics']['true_positives'],0)

    def test_fixed_execution_upload_is_bounded_and_requires_independent_receipt(self):
        phase,run = str(uuid4()),str(uuid4())
        responses=[]; commands=[]
        outer,anchor,task = chain.script('chain_variant',phase,run)
        receipt={'run_id':run,'task_name':task,'execution_verified':True,'cleanup_verified':True,'last_task_result':0,'result_sha256':'a'*64,'registered_at':stamp(time.time()),'completed_at':stamp(time.time()),'cleaned_at':stamp(time.time())}
        class Session:
            def run_ps(self,command):
                commands.append(command)
                stdout=json.dumps(receipt).encode() if command.startswith("$ErrorActionPreference='Stop';$p='") and 'exit $code' in command else b''
                return types.SimpleNamespace(status_code=0,std_out=stdout,std_err=b'')
        rt=runtime.Runtime(config());rt.tunnel=types.SimpleNamespace(ensure=lambda:None)
        with patch.dict(sys.modules, {'winrm':types.SimpleNamespace(Session=lambda *a,**kw:Session())}):
            result=chain.execute(rt,'chain_variant',phase,run)
        self.assertTrue(result['execution_verified'])
        for command in commands:
            self.assertLess(len(base64.b64encode(command.encode('utf-16-le')))+100,8191)
        chunks=[base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)",c)[1]) for c in commands if '$f=[IO.File]::Open' in c]
        source=b''.join(chunks).decode()
        self.assertIn("$child='$output = '",source)
        self.assertIn('cache-check.ps1',source);self.assertIn('WindowStyle Hidden',source)
        self.assertIn('Unregister-ScheduledTask',source)
        self.assertIn('public static extern uint GetLongPathName',source)
        self.assertIn('output_path=(Get-AegisLongPath $output)',source)
        self.assertLess(source.index('$work=Get-AegisLongPath $work'), source.index("$child='$output = '"))
        with self.assertRaises(runtime.RangeError):chain.script('arbitrary',phase,run)


if __name__=='__main__':unittest.main()
