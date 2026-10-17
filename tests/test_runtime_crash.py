"""Abrupt process death around the real application's completion transaction."""
from pathlib import Path
import json
import os
import subprocess
import sys
import unittest
import test_application as fixtures
from process_runtime.application import Runtime
from process_runtime.sqlite_store import SQLiteStore

class ApplicationCrashTests(unittest.TestCase):
    def test_completion_outputs_receipt_result_and_state_recover_atomically(self):
        fixture=fixtures.RuntimeApplicationTests('test_dag_readiness_and_immutable_output_before_downstream_claim')
        fixture.setUp()
        try:
            claim=fixture.claim()
            command=fixture.envelope('executor.complete',{**fixture.binding(claim),'outputs':{'answer':14}},fixture.step()['version'],'crash-complete')
            command_file=Path(fixture.temp.name)/'command.json';command_file.write_text(json.dumps(command))
            fixture.store.close()
            code='''import json,os,sys
from contextlib import contextmanager
from process_runtime.sqlite_store import SQLiteStore
from process_runtime.application import Runtime
from test_application import TestVerifier
store=SQLiteStore(sys.argv[1]);original=store.transaction
if sys.argv[3]=='before':
 @contextmanager
 def crashing():
  with original() as tx:
   def die(result): os._exit(71)
   tx.record_result=die
   yield tx
 store.transaction=crashing
runtime=Runtime(store,verifier=TestVerifier(),environment='test',allow_local_dev_untrusted=True,clock=lambda:1000)
runtime.execute(json.load(open(sys.argv[2])))
os._exit(72)
'''
            tests_dir = str(Path(__file__).resolve().parent)
            installed = os.environ.get('PROCESS_RUNTIME_CRASH_INSTALLED') == '1'
            import_paths = (tests_dir,) if installed else (str(Path(__file__).resolve().parents[1]/'src'), tests_dir)
            env = {**os.environ, 'PYTHONPATH': os.pathsep.join(import_paths)}
            child_code = code
            if installed:
                # Fixtures may be imported, but component code must come from the wheel.
                child_code = ('import sys; from pathlib import Path; import process_runtime; '
                              'assert Path(process_runtime.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()), '
                              '"Crash child must use installed process-runtime";\n' + code)
            for phase in ('before','after'):
                result=subprocess.run([sys.executable,'-c',child_code,str(fixture.path),str(command_file),phase],env=env,capture_output=True,timeout=20)
                self.assertEqual(result.returncode,71 if phase=='before' else 72,result.stderr.decode())
                fixture.store=SQLiteStore(fixture.path)
                fixture.runtime=Runtime(fixture.store,verifier=fixtures.TestVerifier(),environment='test',allow_local_dev_untrusted=True,clock=lambda:1000)
                step=fixture.step()
                self.assertEqual(step['state'],'running' if phase=='before' else 'succeeded')
                if phase=='after':
                    duplicate=fixture.runtime.execute(command)
                    self.assertTrue(duplicate['duplicate'])
                    output=fixture.query('output.get',{'run_id':'run-1','step_id':'z-source','attempt_id':claim['result']['attempt_id']})
                    receipt=fixture.query('receipt.get',{'receipt_id':duplicate['result']['receipt_id']})
                    self.assertEqual(output['output_digest'],receipt['output_digest'])
                fixture.store.close()
        finally:
            fixture.tearDown()

if __name__=='__main__':unittest.main()
