"""Receiver-owned config and installed CLI tests; synthetic public fixtures only."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib import error, request

from process_runtime.authority import DEFAULT_AUDIENCE, PermissionRule, VerifierKey, operation_name, resource_for
from process_runtime.domain import DomainError, Snapshot
from process_runtime.receiver_config import CONFIG_SCHEMA, POLICY_SCHEMA, load_receiver_configuration
from process_runtime_client import LocalDevAuthority, RuntimeClient, RuntimeClientError

ROOT = Path(__file__).resolve().parents[1]


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True))
    path.chmod(0o600)


def public_policy(fixture, *, start=999000, end=1200000, requests=None):
    body = Snapshot(fixture['request'])
    bodies = requests or [body]
    key = VerifierKey('synthetic-verifier', fixture['public_key_hex'], not_before=start//1000, not_after=end//1000)
    return {'schema': POLICY_SCHEMA, 'audience': DEFAULT_AUDIENCE, 'keys': [asdict(key)],
            'descriptors': [{'operation': operation_name(item), 'fingerprint': 'a'*64, 'handler_id': 'runtime-v1'} for item in bodies],
            'permissions': [asdict(PermissionRule('synthetic-subject', operation_name(item), resource_for(item), 'allow', start, end, key_id='synthetic-holder')) for item in bodies],
            'revoked_subject_keys': []}


@unittest.skipUnless(os.environ.get('PROCESS_RUNTIME_NATIVE_VERIFIER'), 'Explicit pinned native helper required')
class ReceiverConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='runtime-receiver-config-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.helper = self.directory/'verifier'
        shutil.copyfile(os.environ['PROCESS_RUNTIME_NATIVE_VERIFIER'], self.helper)
        self.helper.chmod(0o700)
        fixture_data = json.loads((ROOT/'tests/fixtures/authority/native-secs-v4.json').read_text())
        self.fixture = next(item for item in fixture_data['fixtures'] if item['name']=='command')
        self.policy_file = self.directory/'policy.json'
        self.policy = public_policy(self.fixture)
        write(self.policy_file, self.policy)
        self.config_file = self.directory/'receiver.json'
        self.config = {'schema': CONFIG_SCHEMA, 'audience': DEFAULT_AUDIENCE,
                       'native_verifier': {'executable': str(self.helper), 'sha256': hashlib.sha256(self.helper.read_bytes()).hexdigest()},
                       'policy_file': str(self.policy_file)}
        write(self.config_file, self.config)

    def verify(self, verifier):
        return verifier.verify(envelope=Snapshot.of(self.fixture['envelope']).text.encode(),
                               command=Snapshot(self.fixture['request']), now_ms=1001000)

    def test_pinned_native_public_fixture_verifies_but_never_claims_qualification(self):
        verifier = load_receiver_configuration(self.config_file)
        result = self.verify(verifier)
        self.assertEqual(result.subject_id, 'synthetic-subject')
        self.assertEqual(result.mode, 'production_verified')
        self.assertEqual(verifier.verification_status(), {'authority':'configured_native_unqualified','verification':'available','qualification':'unqualified'})

    def test_policy_reload_revocation_deny_and_descriptor_mismatch_reject(self):
        verifier = load_receiver_configuration(self.config_file)
        self.verify(verifier)
        variants=[]
        revoked=deepcopy(self.policy);revoked['revoked_subject_keys']=[{'subject_id':'synthetic-subject','key_id':'synthetic-holder'}];variants.append(revoked)
        denied=deepcopy(self.policy);denied['permissions'].append({**denied['permissions'][0],'effect':'deny'});variants.append(denied)
        wrong=deepcopy(self.policy);wrong['descriptors'][0]['fingerprint']='b'*64;variants.append(wrong)
        wrong=deepcopy(self.policy);wrong['descriptors'][0]['handler_id']='other';variants.append(wrong)
        revoked_key=deepcopy(self.policy);revoked_key['keys'][0]['status']='revoked';variants.append(revoked_key)
        for policy in variants:
            write(self.policy_file,policy)
            with self.subTest(policy=policy),self.assertRaises(DomainError):self.verify(verifier)
        write(self.policy_file,self.policy)
        self.verify(verifier)

    def test_policy_revocation_during_native_verification_denies_before_return(self):
        verifier=load_receiver_configuration(self.config_file)
        original=verifier.native_helper.verify
        def late_revoke(value):
            result=original(value)
            changed=deepcopy(self.policy);changed['revoked_subject_keys']=[{'subject_id':'synthetic-subject','key_id':'synthetic-holder'}]
            write(self.policy_file,changed)
            return result
        verifier.native_helper.verify=late_revoke
        with self.assertRaises(DomainError) as caught:self.verify(verifier)
        self.assertEqual(caught.exception.code,'forbidden')

    def test_receiver_permission_and_verifier_key_time_bounds_survive_native_latency(self):
        from test_application import RuntimeApplicationTests
        fixture_data=json.loads((ROOT/'tests/fixtures/authority/native-secs-v4.json').read_text())
        query_fixture=next(item for item in fixture_data['fixtures'] if item['name']=='query')
        for bound in ('allow_expiry','future_deny','verifier_key_expiry'):
            with self.subTest(bound=bound):
                f=RuntimeApplicationTests();f.setUp()
                try:
                    policy=public_policy(query_fixture)
                    deadline=1001500
                    if bound=='allow_expiry':
                        policy['permissions'][0]['not_after_ms']=deadline
                    elif bound=='future_deny':
                        policy['permissions'].append({**policy['permissions'][0],
                            'effect':'deny','not_before_ms':deadline})
                    else:
                        deadline=1002000;policy['keys'][0]['not_after']=deadline//1000
                    write(self.policy_file,policy)
                    verifier=load_receiver_configuration(self.config_file)
                    original=verifier.native_helper.verify
                    def elapsed(value):
                        output=original(value)
                        f.now[0]=deadline
                        return output
                    verifier.native_helper.verify=elapsed
                    f.runtime.verifier=verifier;f.now[0]=1001000
                    before=f.store.event_high_watermark()
                    with self.assertRaises(DomainError) as caught:
                        f.runtime.query(json.loads(query_fixture['request']),
                            Snapshot.of(query_fixture['envelope']).text.encode())
                    self.assertEqual(caught.exception.code,'unauthenticated')
                    self.assertEqual(f.store.event_high_watermark(),before)
                finally:f.tearDown()

    def test_binary_tampering_or_permission_change_disables_verification(self):
        for mutate in (lambda:self.helper.write_bytes(self.helper.read_bytes()+b'tamper'),lambda:self.helper.chmod(0o777)):
            verifier=load_receiver_configuration(self.config_file)
            mutate()
            self.assertEqual(verifier.verification_status()['verification'],'unavailable')
            with self.assertRaises(DomainError):self.verify(verifier)
            shutil.copyfile(os.environ['PROCESS_RUNTIME_NATIVE_VERIFIER'],self.helper);self.helper.chmod(0o700)

    def test_configuration_unknown_fields_relative_paths_hashes_and_flags_fail_closed(self):
        variants=[]
        for field,value in (('schema','runtime.receiver-configuration.v9'),('qualification',True),('policy_file','policy.json')):
            changed=deepcopy(self.config);changed[field]=value;variants.append(changed)
        for field,value in (('executable','verifier'),('executable',str(self.directory/'missing')),('sha256','0'*64),('private_seed','secret-marker')):
            changed=deepcopy(self.config);changed['native_verifier'][field]=value;variants.append(changed)
        for changed in variants:
            write(self.config_file,changed)
            with self.subTest(changed=changed),self.assertRaises(ValueError):load_receiver_configuration(self.config_file)
        with self.assertRaises(ValueError):load_receiver_configuration('relative-config.json')

    def test_duplicate_nonfinite_unknown_and_unbounded_policy_fields_fail_closed(self):
        variants=[]
        for field,value in (('schema','runtime.receiver-policy.v9'),('audience','runtime://other'),('secret','secret-marker')):
            changed=deepcopy(self.policy);changed[field]=value;variants.append(changed)
        duplicate=deepcopy(self.policy);duplicate['keys'].append(duplicate['keys'][0]);variants.append(duplicate)
        duplicate=deepcopy(self.policy);duplicate['descriptors'].append(duplicate['descriptors'][0]);variants.append(duplicate)
        invalid=deepcopy(self.policy);invalid['permissions'][0]['resource']='runs/*';variants.append(invalid)
        invalid=deepcopy(self.policy);invalid['permissions'][0]['not_after_ms']=True;variants.append(invalid)
        invalid=deepcopy(self.policy);invalid['keys'][0]['not_after']=True;variants.append(invalid)
        for changed in variants:
            write(self.policy_file,changed)
            with self.subTest(changed=changed),self.assertRaises(ValueError):load_receiver_configuration(self.config_file)
        for raw in ('{"schema":1,"schema":2}', '{"keys":NaN}', 'x'*262145):
            self.policy_file.write_text(raw);self.policy_file.chmod(0o600)
            with self.subTest(raw=raw[:20]),self.assertRaises(ValueError):load_receiver_configuration(self.config_file)

    def test_shared_symlink_hardlink_or_missing_policy_and_config_are_rejected(self):
        for target in (self.config_file,self.policy_file):
            target.chmod(0o644)
            with self.assertRaises(ValueError):load_receiver_configuration(self.config_file)
            target.chmod(0o600)
            link=target.with_suffix('.link');os.link(target,link)
            with self.assertRaises(ValueError):load_receiver_configuration(self.config_file)
            link.unlink()
            data=target.read_bytes();target.unlink();target.symlink_to(link)
            with self.assertRaises(ValueError):load_receiver_configuration(self.config_file)
            target.unlink();target.write_bytes(data);target.chmod(0o600)
        self.policy_file.unlink()
        with self.assertRaises(ValueError):load_receiver_configuration(self.config_file)

    def test_untrusted_ancestor_directory_and_alias_path_are_rejected(self):
        shared=self.directory/'shared';shared.mkdir(mode=0o700)
        private=shared/'private';private.mkdir(mode=0o700)
        alternate=private/'policy.json';write(alternate,self.policy)
        changed={**self.config,'policy_file':str(alternate)};write(self.config_file,changed)
        shared.chmod(0o777)
        with self.assertRaises(ValueError):load_receiver_configuration(self.config_file)
        shared.chmod(0o700)
        alias=self.directory/'alias';alias.symlink_to(private,target_is_directory=True)
        write(self.config_file,{**changed,'policy_file':str(alias/'policy.json')})
        with self.assertRaises(ValueError):load_receiver_configuration(self.config_file)

    def test_cli_rejects_unsafe_configuration_before_database_creation_and_redacts(self):
        database=self.directory/'must-not-exist.db'
        bad={**self.config,'schema':'secret-marker'};write(self.config_file,bad)
        argv=[sys.executable,'-I','-m','process_runtime','--database',str(database),'--receiver-config',str(self.config_file)]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertFalse(database.exists())
        self.assertNotIn('secret-marker',result.stderr)
        self.assertNotIn(str(self.config_file),result.stderr)
        self.assertIn('initialization rejected',result.stderr)
        for flag in ('--receiver-config', '--admission-policy'):
            result=subprocess.run([sys.executable,'-I','-m','process_runtime','--database',str(database),flag,''],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2);self.assertFalse(database.exists())
        write(self.config_file,self.config)
        for flags in (['--local-dev-untrusted'],['--environment','test','--local-dev-untrusted']):
            result=subprocess.run(argv+flags,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2);self.assertFalse(database.exists())


@unittest.skipUnless(os.environ.get('PROCESS_RUNTIME_FRESH_NATIVE_FIXTURES') and os.environ.get('PROCESS_RUNTIME_NATIVE_VERIFIER'), 'Fresh synthetic public native fixtures and explicit helper required')
class InstalledReceiverCLITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='runtime-native-cli-');self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name).resolve()
        data=json.loads(Path(os.environ['PROCESS_RUNTIME_FRESH_NATIVE_FIXTURES']).read_text())
        self.fixtures={item['name']:item for item in data['fixtures']}
        self.policy_file=self.directory/'policy.json'
        register=self.fixtures['actor-register'];query=self.fixtures['events-list']
        self.policy=public_policy(register,start=register['now_ms']-1000,end=register['expires_at_ms']+1000,
                                  requests=[Snapshot(register['request']),Snapshot(query['request'])])
        write(self.policy_file,self.policy)
        helper=Path(os.environ['PROCESS_RUNTIME_NATIVE_VERIFIER']).resolve()
        self.config_file=self.directory/'receiver.json'
        write(self.config_file,{'schema':CONFIG_SCHEMA,'audience':DEFAULT_AUDIENCE,'native_verifier':{'executable':str(helper),'sha256':hashlib.sha256(helper.read_bytes()).hexdigest()},'policy_file':str(self.policy_file)})
        self.admission=self.directory/'admission.json'
        write(self.admission,{'schema':'runtime.new-run-admission.v1','enabled':False,'composition_digest':'a'*64})
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        self.endpoint=f'http://127.0.0.1:{port}'
        self.process=subprocess.Popen([sys.executable,'-I','-m','process_runtime','--database',str(self.directory/'runtime.db'),'--port',str(port),'--receiver-config',str(self.config_file),'--admission-policy',str(self.admission)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.addCleanup(self.stop)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if self.process.poll() is not None:self.fail('Runtime CLI exited before liveness')
            try:
                with request.urlopen(self.endpoint+'/live',timeout=.2) as response:
                    if response.status==200:break
            except OSError:time.sleep(.02)
        else:self.fail('Runtime CLI did not become live')
        self.client=RuntimeClient(self.endpoint)

    def stop(self):
        if self.process.poll() is None:self.process.terminate()
        self.process.communicate(timeout=10)

    def call(self,name):
        fixture=self.fixtures[name];body=json.loads(fixture['request']);proof=Snapshot.of(fixture['envelope']).text.encode()
        method=self.client.execute if body['schema']=='runtime.command.v1' else self.client.query
        return method(body,evidence=proof)

    def readiness(self):
        with self.assertRaises(error.HTTPError) as caught:request.urlopen(self.endpoint+'/ready',timeout=2)
        self.assertEqual(caught.exception.code,503)
        return json.load(caught.exception)

    def test_installed_cli_native_command_query_exact_retry_replay_and_revocation(self):
        result=self.call('actor-register')
        self.assertEqual(result['result']['subject_id'],'synthetic-subject')
        self.assertTrue(self.call('actor-register')['duplicate'])
        events=self.call('events-list')
        self.assertEqual(len(events['data']['events']),1)
        self.assertEqual(events['data']['events'][0]['data']['authority_mode'],'production_verified')
        with self.assertRaises(RuntimeClientError) as caught:self.call('events-list')
        self.assertEqual(caught.exception.code,'replay_rejected')
        revoked=deepcopy(self.policy);revoked['revoked_subject_keys']=[{'subject_id':'synthetic-subject','key_id':'synthetic-holder'}]
        write(self.policy_file,revoked)
        with self.assertRaises(RuntimeClientError) as caught:self.call('actor-register')
        self.assertEqual(caught.exception.code,'forbidden')

    def test_configured_verification_remains_unqualified_and_admission_is_preserved(self):
        value=self.readiness()
        self.assertFalse(value['ready'])
        self.assertEqual(value['checks']['authority'],'configured_native_unqualified')
        self.assertEqual(value['checks']['verification'],'available')
        self.assertEqual(value['checks']['qualification'],'unqualified')
        self.assertEqual(value['checks']['admission']['new_runs'],'closed')
        self.assertNotIn(str(self.directory),json.dumps(value))
        self.policy_file.write_text('{secret-marker');self.policy_file.chmod(0o600)
        value=self.readiness();self.assertEqual(value['checks']['verification'],'unavailable')
        with self.assertRaises(RuntimeClientError):self.call('actor-register')

    def test_wrong_native_bindings_and_delivery_identity_cannot_authorize(self):
        for name in ('wrong-operation','wrong-resource','wrong-opcode','wrong-audience','wrong-subject','wrong-key','wrong-descriptor','wrong-handler','expired'):
            with self.subTest(name=name),self.assertRaises(RuntimeClientError):self.call(name)
        body=json.loads(self.fixtures['actor-register']['request'])
        for evidence in (b'{}',b'{"matrix_user":"synthetic-subject"}',LocalDevAuthority(environment='test')(body)):
            with self.subTest(evidence=evidence),self.assertRaises(RuntimeClientError):self.client.execute(body,evidence=evidence)
        # Negative proofs produced no execution event; a fresh authenticated query confirms it.
        self.assertEqual(self.call('events-list')['data']['events'],[])


if __name__=='__main__':unittest.main()
