from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib import request, error
import uuid

from process_runtime.application import Runtime
from process_runtime.authority import LocalDevUntrustedVerifier
from process_runtime.http_api import make_server
from process_runtime.sqlite_store import SQLiteStore
from process_runtime_client import RuntimeClient, RuntimeClientError, LocalDevAuthority, exact_retry
from process_runtime_client.generated import TypedRuntimeClient


class HttpClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.runtime = Runtime(self.store, verifier=LocalDevUntrustedVerifier("integration-operator"), environment="test", allow_local_dev_untrusted=True)
        self.server = make_server(self.runtime)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.client = TypedRuntimeClient(self.endpoint, authority=LocalDevAuthority(environment="test"))

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.store.close(); self.temp.cleanup()

    def actor_command(self, identifier="actor-1"):
        return {"schema":"runtime.command.v1", "operation":"actor.register", "request_id":str(uuid.uuid4()),
                "resource":"actors/"+identifier, "expected_version":None, "payload":{"actor_id":identifier,"capabilities":[],"resources":[]}}

    def test_readiness_requires_available_storage_and_explicit_local_authority(self):
        with request.urlopen(self.endpoint+"/ready",timeout=2) as response:
            self.assertTrue(json.load(response)["ready"])
        from process_runtime.authority import DenyAllVerifier
        self.runtime.verifier=DenyAllVerifier()
        with self.assertRaises(error.HTTPError) as caught:
            request.urlopen(self.endpoint+"/ready",timeout=2)
        self.assertEqual(caught.exception.code,503)
        self.assertEqual(json.load(caught.exception)["checks"]["authority"],"default_deny")
        self.runtime.verifier=LocalDevUntrustedVerifier("integration-operator")
        def unavailable():
            raise OSError("unavailable")
        self.store.check_ready=unavailable
        with self.assertRaises(error.HTTPError) as caught:
            request.urlopen(self.endpoint+"/ready",timeout=2)
        self.assertEqual(json.load(caught.exception)["checks"]["storage"],"unavailable")
        with request.urlopen(self.endpoint+"/live",timeout=2) as response:
            self.assertTrue(json.load(response)["live"])

    def test_generated_client_command_query_and_error_contract(self):
        result = self.client.actor_register(request_id="register", resource="actors/actor-1", expected_version=None,
                                           payload={"actor_id":"actor-1","capabilities":[],"resources":[]})
        self.assertEqual(result["result"]["subject_id"], "integration-operator")
        work = self.client.work_list({"actor_id":"actor-1","limit":10})
        self.assertEqual(work["data"]["work"], [])
        with self.assertRaises(RuntimeClientError) as caught:
            RuntimeClient(self.endpoint).execute(self.actor_command())
        self.assertEqual(caught.exception.code, "unauthenticated")
        with self.assertRaises(RuntimeClientError) as caught:
            self.client.actor_advertise(request_id="stale",resource="actors/actor-1",expected_version=3,
                                       payload={"actor_id":"actor-1","capabilities":[],"resources":[]})
        self.assertEqual(caught.exception.code, "version_conflict")
        self.assertFalse(caught.exception.uncertain)

    def test_lost_http_response_retries_exact_intent_without_duplicate_mutation(self):
        original = self.runtime.execute
        delayed = [True]
        def execute(command, evidence):
            result = original(command, evidence)
            if delayed[0]:
                delayed[0] = False
                time.sleep(0.1)
            return result
        self.runtime.execute = execute
        self.client.timeout = 0.02
        command = self.actor_command()
        with self.assertRaises(RuntimeClientError) as caught:
            self.client.execute(command)
        self.assertTrue(caught.exception.uncertain)
        self.client.timeout = 1
        retried = self.client.execute(exact_retry(command))
        self.assertTrue(retried["duplicate"])
        events = self.client.events_list({"after":0,"limit":100})["data"]["events"]
        self.assertEqual(len([e for e in events if e["kind"]=="actor.registered"]), 1)

    def test_http_duplicate_json_and_unknown_contract_fail_closed(self):
        bad = [b'{"schema":"runtime.transport.v1","schema":"runtime.transport.v1"}',
               json.dumps({"schema":"runtime.transport.v9","request":{},"authority_base64":""}).encode(),
               json.dumps({"schema":"runtime.transport.v1","request":self.actor_command(),"authority_base64":""}).encode()]
        for body in bad:
            with self.assertRaises(error.HTTPError) as caught:
                request.urlopen(request.Request(self.endpoint+"/v1/commands",data=body,headers={"Content-Type":"application/json"}),timeout=2)
            value=json.loads(caught.exception.read())
            self.assertEqual(value["schema"],"runtime.error.v1")
        self.assertEqual(self.store.event_high_watermark(), 0)

    def test_malformed_success_or_wrong_correlation_is_uncertain(self):
        for response in ({"schema":"wrong"}, {"schema":"runtime.result.v1","operation":"actor.register","request_id":"wrong-request", "resource":"actors/actor-1", "duplicate":False,"version":1,"result":{}}):
            class BadHandler(BaseHTTPRequestHandler):
                def log_message(self,*args): pass
                def do_POST(self):
                    self.rfile.read(int(self.headers['Content-Length']))
                    raw=json.dumps(response).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            server=ThreadingHTTPServer(('127.0.0.1',0),BadHandler)
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            try:
                client=RuntimeClient(f'http://127.0.0.1:{server.server_port}',authority=LocalDevAuthority(environment='test'))
                with self.assertRaises(RuntimeClientError) as caught:
                    client.execute(self.actor_command())
                self.assertEqual(caught.exception.code,'incompatible_version');self.assertTrue(caught.exception.uncertain)
            finally:
                server.shutdown();server.server_close();worker.join()

    def test_query_proof_cannot_be_replayed_or_changed_into_authority(self):
        command=self.actor_command();self.client.execute(command)
        query={"schema":"runtime.query.v1","operation":"work.list","payload":{"actor_id":"actor-1","limit":10}}
        evidence=LocalDevAuthority(environment='test')(query)
        self.client.query(query,evidence)
        with self.assertRaises(RuntimeClientError) as caught:
            self.client.query(query,evidence)
        self.assertEqual(caught.exception.code,'replay_rejected')
        with self.assertRaises(ValueError):
            LocalDevAuthority(environment='production')
        with self.assertRaises(ValueError):
            RuntimeClient('http://example.invalid')

if __name__=='__main__':
    unittest.main()
