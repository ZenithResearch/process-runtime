import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from process_runtime.authority import resource_for as receiver_resource
from process_runtime.domain import Snapshot
from process_runtime_client import resource_for, command_envelope, RuntimeClient, RuntimeClientError

ROOT=Path(__file__).resolve().parents[1]

class PublicClientContractTests(unittest.TestCase):
    def test_all_resources_match_receiver_and_generated_fixtures(self):
        fixtures=json.loads((ROOT/'contracts/consumer-fixtures-v1.json').read_text())
        for value in fixtures['commands']+fixtures['queries']:
            self.assertEqual(resource_for(value),receiver_resource(Snapshot.of(value)))
            if value['schema']=='runtime.command.v1':
                self.assertEqual(value['resource'],resource_for(value))
                self.assertEqual(command_envelope(value['operation'],request_id=value['request_id'],expected_version=value['expected_version'],payload=value['payload']),value)

    def test_generated_artifacts_are_current_and_sdk_imports_no_runtime_internals(self):
        spec=importlib.util.spec_from_file_location('client_generator',ROOT/'scripts/export_client.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            module.ROOT=Path(folder);module.TARGET=Path(folder)/'sdk';module.TARGET.mkdir();(Path(folder)/'contracts').mkdir()
            module.generate()
            for name in ('generated.py','runtime-v1.schema.json','resource-templates-v1.json'):
                self.assertEqual((module.TARGET/name).read_bytes(),(ROOT/'src/process_runtime_client'/name).read_bytes())
            self.assertEqual((Path(folder)/'contracts/openapi-v1.json').read_bytes(),(ROOT/'contracts/openapi-v1.json').read_bytes())
        for source in (ROOT/'src/process_runtime_client').glob('*.py'):
            for node in ast.walk(ast.parse(source.read_text())):
                if isinstance(node,ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith('process_runtime.'))
                elif isinstance(node,ast.Import):
                    self.assertFalse(any(item.name.startswith('process_runtime.') for item in node.names))

    def test_bounded_cursor_subscription_backpressure_and_gap_detection(self):
        event=json.loads((ROOT/'contracts/consumer-fixtures-v1.json').read_text())['event']
        second={**event,'event_id':'event-two','sequence':2}
        pages=[{'events':[event],'next_cursor':1,'high_watermark':2}, {'events':[second],'next_cursor':2,'high_watermark':2}]
        class FixtureClient(RuntimeClient):
            def __init__(self, pages):self.pages=iter(pages);self.calls=0
            def query(self, value, evidence=None):self.calls+=1;return {'data':next(self.pages)}
        client=FixtureClient(pages);stream=client.event_pages(limit=1)
        self.assertEqual(client.calls,0)
        self.assertEqual(next(stream)['next_cursor'],1);self.assertEqual(client.calls,1)
        self.assertEqual(next(stream)['next_cursor'],2);self.assertEqual(client.calls,2)
        with self.assertRaises(StopIteration):next(stream)
        for malformed in ({'events':[second],'next_cursor':2,'high_watermark':2}, {'events':[event,event],'next_cursor':2,'high_watermark':2}, {'events':[],'next_cursor':0,'high_watermark':2}, {'events':[event],'next_cursor':9,'high_watermark':2}):
            with self.subTest(malformed=malformed),self.assertRaises(RuntimeClientError) as caught:
                list(FixtureClient([malformed]).event_pages())
            self.assertEqual(caught.exception.code,'cursor_gap')
        self.assertEqual(len(list(FixtureClient(pages).event_pages(limit=1,max_pages=1))),1)

if __name__=='__main__':unittest.main()
