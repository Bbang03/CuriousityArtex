import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from loop_rule import LabError, expression, saved_name, validate, values, duplicate_safe, digest


def rule(value='<script>'):
    return {'name': 'Observed query payload', 'any': [{'all': [
        {'field': 'query_string', 'op': 'contains', 'value': value, 'case_sensitive': False}
    ]}]}


class LoopRuleTests(unittest.TestCase):
    def test_search_and_alert_scope_are_fixed(self):
        settings = values(rule(), saved_name('test'), 1234)
        search = settings['search']
        self.assertTrue(search.startswith('index="artex_lab" sourcetype="artex:lab:audit"'))
        self.assertIn('| fields _raw _time | spath', search)
        self.assertIn('target="purple-lab-target:8080"', search)
        self.assertIn('_time>=1234.000000', search)
        self.assertIn('"detection_engine","splunk_saved_search"', search)
        self.assertEqual(settings['action.logevent.param.sourcetype'], 'artex:lab:alert')
        self.assertEqual(settings['action.logevent.param.index'], 'artex_lab')
        self.assertEqual(settings['cron_schedule'], '* * * * *')

    def test_saved_search_scheduler_adds_one_search_command(self):
        # A saved search is an implicit search expression. The actual scheduler
        # prefixes it with `search`; including that token in the saved value
        # creates `search search index=...`, filtering for the keyword search.
        saved = values(rule(), saved_name('test'), 1234)['search']
        actual_job = 'search ' + saved
        self.assertTrue(actual_job.startswith('search index="artex_lab"'))
        self.assertFalse(actual_job.startswith('search search '))

    def test_injection_and_wildcards_are_literal_data(self):
        text = expression(rule('" | outputlookup stolen | where *%'))
        self.assertIn('outputlookup', text)
        self.assertIn('\\\\|', text)
        self.assertIn('\\\\*%', text)
        self.assertIn('match(', text)
        self.assertNotIn('like(', text)
        self.assertTrue(text.endswith(')))'))

    def test_identifiers_and_labels_cannot_be_detector_features(self):
        for field in ('label', 'id', '_time', 'event_id', 'artex_verification_id'):
            r = rule(); r['any'][0]['all'][0]['field'] = field
            with self.subTest(field=field), self.assertRaises(LabError): validate(r)
        for value in ('AEGIS_VERIFY_demo', '36e1c3df-0f65-47cd-a8dc-966b66a05b67'):
            with self.assertRaises(LabError): validate(rule(value))

    def test_malformed_and_unbounded_rules_are_rejected(self):
        samples = [None, {}, {'name':'x','any':[]}, {**rule(),'search':'| delete'}]
        for key, value in [('field', []), ('case_sensitive', 'false'), ('value', '\n'), ('op','regex')]:
            r = copy.deepcopy(rule()); r['any'][0]['all'][0][key] = value; samples.append(r)
        for r in samples:
            with self.subTest(rule=r), self.assertRaises(LabError): validate(r)

    def test_rule_name_cannot_escape_managed_namespace(self):
        for name in ('../other', 'UPPER', '', 'x'*41, 'x|delete'):
            with self.assertRaises(LabError): saved_name(name)
        self.assertEqual(saved_name('candidate-v1'), 'artex_loop_candidate-v1')

    def test_duplicate_json_keys_are_not_silently_overwritten(self):
        with self.assertRaises(LabError):
            json.loads('{"name":"one","name":"two","any":[]}', object_pairs_hook=duplicate_safe)

    def test_hash_matches_go_struct_order_and_html_escaping(self):
        import hashlib
        raw = b'{"name":"Observed query payload","any":[{"all":[{"field":"query_string","op":"contains","value":"\\u003cscript\\u003e","case_sensitive":false}]}]}'
        self.assertEqual(digest(rule()), hashlib.sha256(raw).hexdigest())

    def test_truncated_observations_cannot_emit_false_native_verdicts(self):
        self.assertIn("'query_string_truncated'", expression(rule()))


if __name__ == '__main__': unittest.main()
