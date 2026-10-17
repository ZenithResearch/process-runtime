from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from process_runtime.authoring import import_document
from process_runtime.compiler import compile_draft
from process_runtime.domain import DomainError, Snapshot
from process_runtime.shadow import compare_shadow, run_shadow

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads((ROOT / path).read_text())


def scenario(name):
    process = 'personal-review-v1' if name.startswith('personal') else 'development-sop-v1'
    return load(f'resources/processes/{process}.json'), load(f'tests/fixtures/shadow/{name}.json')


class ProcessResourceTests(unittest.TestCase):
    def test_all_nine_upstream_handlers_and_outputs_are_accounted_for(self):
        legacy = load('resources/sources/personal-review-v1.json')
        migration = load('resources/processes/personal-review-v1.migration.json')
        draft = load('resources/processes/personal-review-v1.json')
        steps = {step['step_id']: step for step in draft['steps']}
        self.assertEqual(set(steps), set(legacy['handlers']))
        self.assertEqual(len(steps), 9)
        renames = migration['classified_differences'][1]['ports']
        for step_id, source in legacy['handlers'].items():
            self.assertIn('review.' + source['handler'], steps[step_id]['capabilities'])
            expected={renames.get(port, port) for port in source['outputs']}
            if step_id=='step_7':expected|={'review_packet','review_packet_status'}
            self.assertEqual(set(steps[step_id]['outputs']), expected)
        self.assertEqual(steps['step_2']['depends_on'], ['step_1'])
        self.assertEqual(steps['step_3']['depends_on'], ['step_1'])
        self.assertEqual(steps['step_9']['depends_on'], ['step_8'])
        self.assertEqual(steps['step_8']['bindings']['review_packet']['step_id'], 'step_7')
        self.assertEqual(steps['step_8']['bindings']['review_packet_status']['step_id'], 'step_7')
        for key, name in [('profile', 'personal-review-v1.json'), ('markdown', 'personal-review-legacy.md')]:
            self.assertEqual(hashlib.sha256((ROOT / 'resources/sources' / name).read_bytes()).hexdigest(), migration['source_hashes'][key])

    def test_markdown_json_and_retained_compilation_are_identical(self):
        for name in ('personal-review-v1', 'development-sop-v1'):
            with self.subTest(process=name):
                draft = load(f'resources/processes/{name}.json')
                source = import_document((ROOT / f'resources/processes/{name}.md').read_bytes(), source_id=name, media_type='text/markdown')
                self.assertTrue(source.accepted)
                self.assertEqual(source.draft.value, draft)
                self.assertEqual(compile_draft(source.draft).snapshot.value, load(f'resources/processes/{name}.compiled.json'))

    def test_development_resource_has_independent_branches_and_no_service_aggregate(self):
        draft = load('resources/processes/development-sop-v1.json')
        self.assertEqual(set(draft['inputs']), {'change_request', 'repository_snapshot'})
        steps = {step['step_id']: step for step in draft['steps']}
        self.assertEqual(steps['unit-tests']['depends_on'], ['implement'])
        self.assertEqual(steps['contract-tests']['depends_on'], ['implement'])
        self.assertEqual(set(steps['review']['depends_on']), {'unit-tests', 'contract-tests'})
        self.assertNotIn('service', json.dumps(draft).lower())
        self.assertNotIn('case', json.dumps(draft).lower())


class ShadowExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reports = {}
        for name in ('personal-review-success', 'personal-review-failure', 'development-success', 'development-failure'):
            cls.reports[name] = run_shadow(*scenario(name))

    def test_success_and_failure_reports_match_retained_golden_semantics(self):
        for name, report in self.reports.items():
            with self.subTest(scenario=name):
                golden = Snapshot.of(load(f'tests/fixtures/shadow/{name}.golden.json'))
                result = compare_shadow(report, golden).value
                self.assertTrue(result['matches'], result['divergences'])
                self.assertEqual(result['divergences'], [])
                self.assertEqual(report.value['authority_mode'], 'local_dev_untrusted')
                self.assertEqual(report.value['external_effects'], 'forbidden')

    def test_receipt_normalization_is_stable_across_fresh_databases_and_attempt_ids(self):
        again = run_shadow(*scenario('personal-review-success'))
        self.assertEqual(again.digest, self.reports['personal-review-success'].digest)
        for step in again.value['steps']:
            self.assertEqual(step['receipt_digest'], Snapshot.of(step['receipt']).digest)
            self.assertEqual(step['output_digest'], step['receipt']['output_digest'])
            self.assertEqual(step['input_digest'], step['receipt']['input_digest'])

    def test_failed_branch_does_not_discard_parallel_completion_or_unlock_join(self):
        review = self.reports['personal-review-failure'].value
        self.assertEqual(review['runnable_trace'][1]['runnable'], ['step_2', 'step_3'])
        self.assertEqual([(s['step_id'], s['outcome']) for s in review['steps']], [('step_1', 'succeeded'), ('step_2', 'failed'), ('step_3', 'succeeded')])
        self.assertEqual(review['final_step_states']['step_4'], 'waiting')
        development = self.reports['development-failure'].value
        self.assertEqual(development['final_step_states']['contract-tests'], 'failed')
        self.assertEqual(development['final_step_states']['unit-tests'], 'succeeded')
        self.assertEqual(development['final_step_states']['review'], 'waiting')
        self.assertEqual(development['run_state'], 'failed')

    def test_every_divergence_is_classified_and_goldens_are_not_changed(self):
        original = self.reports['personal-review-success']
        altered = original.value
        altered['runnable_trace'][0]['runnable'] = ['step_2']
        altered['steps'][0]['output_digest'] = '0' * 64
        altered['steps'][0]['receipt_digest'] = '1' * 64
        altered['failures'] = [{'step_id': 'step_1', 'reason': 'changed'}]
        result = compare_shadow(Snapshot.of(altered), original).value
        self.assertFalse(result['matches'])
        self.assertEqual({d['category'] for d in result['divergences']}, {'runnable', 'output', 'receipt', 'failure'})
        self.assertEqual(original.value['failures'], [])

    def test_fixture_cannot_register_callable_invoke_effect_or_change_output_type(self):
        draft, fixture = scenario('development-success')
        for replacement in ({'outcome': 'dispatch', 'integration': 'network'}, {'outcome': 'succeeded', 'outputs': {}, 'handler': 'os.system'}):
            changed = deepcopy(fixture); changed['steps']['scope'] = replacement
            with self.assertRaises(DomainError):
                run_shadow(draft, changed)
        fixture['steps']['unit-tests']['outputs']['passed'] = 'true'
        with self.assertRaises(DomainError) as caught:
            run_shadow(draft, fixture)
        self.assertEqual(caught.exception.code, 'type_mismatch')


if __name__ == '__main__':
    unittest.main()
