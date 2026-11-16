"""New mocked verifier/preflight deltas only; never launch SSH, SDK, HTTP or a full controller."""
import ast,builtins,hashlib,json,os,re,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import yaml
R=Path(__file__).resolve().parents[2]
CT=(R/'.github/ci/hosted_caps.py').read_text();VT=(R/'tools/test_verifier.py').read_text();WT=(R/'.github/workflows/verify.yml').read_text()
CONTRACT={'caseASTSHA256': '5d1b262ced0acc065ce32c0be08398675f8f2fb21a959bf1047d171d581d0975', 'caseIDs': ['test_actual_known_key_signature_and_archive', 'test_crlf_single_line_and_untrusted_comment_are_safe', 'test_forged_single_line_comment_does_not_authorize_attacker', 'test_noncanonical_blob_and_controls_are_rejected', 'test_second_bare_key_and_extra_blank_line_are_rejected', 'test_tampered_selected_archive_fails_after_valid_signature', 'test_valid_pinned_first_key_cannot_inject_attacker_principal', 'test_wrong_case_fingerprint_and_wrong_signature_fail'], 'run': 8, 'attemptScenarios': 27, 'modes': ['normal', 'python -O', 'PYTHONOPTIMIZE=1']}
INPUT=len(CT.encode())+len(VT.encode())+len(WT.encode())+len(json.dumps(CONTRACT).encode())
C={n.name:n for n in ast.parse(CT).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};V={n.name:n for n in ast.parse(VT).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def compile_nodes(nodes,names,env):exec(compile(ast.fix_missing_locations(ast.Module(body=[nodes[n] for n in names],type_ignores=[])),'<mocked-source-delta>','exec'),env)
def count(data):
 global INPUT
 INPUT+=len(data)
 if INPUT>524288:raise RuntimeError('INPUT_CAP')
 return data
class Deltas(unittest.TestCase):
 def setUp(self):
  parent=Path(os.environ['MATCHING10_SOURCE_FIXTURE_TEMP']).resolve();self.t=tempfile.TemporaryDirectory(prefix='verifier-delta-',dir=parent);self.addCleanup(self.t.cleanup);self.run=Path(self.t.name).resolve();self.assertTrue(self.run.is_relative_to(parent))
  self.c={'Path':Path,'json':json,'hashlib':hashlib,'os':os,'re':re,'time':time,'sys':SimpleNamespace(executable='FAKE_PYTHON',flags=SimpleNamespace(utf8_mode=True))}
  compile_nodes(C,('Failure','need','unique','load','save','remaining','select_purpose','observe_locked_restore_log','replace_small_diagnostic','capture_payload_diagnostic','run_verifier_preflight','command','worker','export_evidence'),self.c)
  cases=tuple(CONTRACT['caseIDs']);self.v={'Path':Path,'json':json,'hashlib':hashlib,'os':os,'re':re,'argparse':__import__('argparse'),'sys':SimpleNamespace(executable='FAKE_PYTHON',flags=SimpleNamespace(utf8_mode=True)),'shutil':SimpleNamespace(which=lambda x:str(self.run/'fake-ssh')),'tempfile':tempfile,'subprocess':SimpleNamespace(TimeoutExpired=subprocess.TimeoutExpired,CalledProcessError=subprocess.CalledProcessError),'unittest':unittest,'CASE_IDS':cases,'PIN':'SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU','ROOT':self.run/'fake-repo','__builtins__':dict(builtins.__dict__)}
  compile_nodes(V,('failure_data','emit_lifecycle','tool_identity','observed_run','run_suite','main'),self.v)
  self.v['ROOT'].mkdir();(self.v['ROOT']/'SIGNING-PUBLIC-KEY.pub').write_bytes(count(b'FAKE_PUBLIC_ONLY'));(self.run/'fake-ssh').write_bytes(count(b'FAKE_EXECUTABLE_NOT_RUN'))
  self.v['tool_identity']=lambda p,k:{'kind':k,'bytes':1,'sha256':'0'*64}
  self.v['__builtins__']['__import__']=lambda name,*a,**k:SimpleNamespace() if name=='verify_downloads' else builtins.__import__(name,*a,**k)
  def fake_run(argv,**kwargs):
   if '-q' in argv:Path(argv[-1]).with_suffix('.pub').write_bytes(count(b'FAKE_GENERATED_PUBLIC'))
   return subprocess.CompletedProcess([],0,b'',b'')
  self.v['subprocess'].run=fake_run;self.out=self.run/'results'
  self.v['run_suite']=lambda *a:{'status':'PASS','run':8,'failures':0,'errors':0,'subprocessScenarios':27,'modes':['normal','python -O','PYTHONOPTIMIZE=1']}
 def main(self):
  with patch.dict(os.environ,{'MATCHING10_DIAGNOSTIC_ROOT':str(self.run)}),patch.object(sys,'argv',['fixture','--out',str(self.out)]):return self.v['main']()
 def lifecycle(self):return json.loads((self.run/'verifier-lifecycle.json').read_bytes())
 def test01_typed_failure_redacts_text(self):
  error=FileNotFoundError(2,'ENV_SECRET /private?x');data=self.v['failure_data'](error);self.assertEqual(data['category'],'FileNotFoundError');self.assertEqual(data['errno'],2);self.assertNotIn('ENV_SECRET',json.dumps(data))
 def test02_lifecycle_cap(self):
  with self.assertRaises(ValueError):self.v['emit_lifecycle'](self.run,{'x':count(b'A'*9000).decode()})
  self.v['subprocess'].run=lambda *a,**k:subprocess.CompletedProcess([],0,b'line\r\n',b'')
  state={};result=self.v['observed_run'](self.run,state,'FIXTURE_VERIFY',[],1,text=True)
  self.assertEqual(result.stdout,'line\n');self.assertEqual(state['lastSubprocess']['stdoutSHA256'],hashlib.sha256(b'line\r\n').hexdigest())
 def test03_output_setup_failure_is_durable(self):
  self.out.mkdir();self.assertEqual(self.main(),1);self.assertEqual(self.lifecycle()['phase'],'OUTPUT_SETUP');self.assertEqual(self.lifecycle()['status'],'FAILED')
 def test04_import_failure_is_durable(self):
  original=self.v['__builtins__']['__import__']
  def failed(name,*a,**k):
   if name=='verify_downloads':raise ModuleNotFoundError('PRIVATE_PATH')
   return original(name,*a,**k)
  self.v['__builtins__']['__import__']=failed;self.assertEqual(self.main(),1);self.assertEqual(self.lifecycle()['phase'],'VERIFIER_IMPORT');self.assertNotIn('PRIVATE_PATH',json.dumps(self.lifecycle()))
 def test05_keygen_failure_is_typed_no_suite(self):
  def failed(*a,**k):raise subprocess.CalledProcessError(7,['PRIVATE_ARGV'],stderr=b'PRIVATE_STDERR')
  self.v['subprocess'].run=failed;self.assertEqual(self.main(),1);value=self.lifecycle();self.assertEqual(value['phase'],'DISPOSABLE_KEYGEN');self.assertEqual(value['failure']['exitCode'],7);self.assertNotIn('PRIVATE',json.dumps(value))
 def test06_timeout_preserves_primary_and_hashes(self):
  error=subprocess.TimeoutExpired(['PRIVATE_ARGV'],1,output=b'secret-output',stderr=b'secret-error')
  def failed(*a,**k):raise error
  self.v['subprocess'].run=failed;state={}
  with self.assertRaises(subprocess.TimeoutExpired) as raised:self.v['observed_run'](self.run,state,'FIXTURE_VERIFY',[],1)
  self.assertIs(raised.exception,error);self.assertEqual(state['lastSubprocess']['stderrSHA256'],hashlib.sha256(b'secret-error').hexdigest());self.assertNotIn('secret-error',json.dumps(state))
 def test07_final_write_failure_is_not_pass(self):
  def suite(*a):(self.out/'receipt.json').mkdir();return {'status':'PASS','run':8,'subprocessScenarios':27,'modes':['normal','python -O','PYTHONOPTIMIZE=1']}
  self.v['run_suite']=suite;self.assertEqual(self.main(),1);self.assertEqual(self.lifecycle()['phase'],'FINAL_RECEIPT');self.assertEqual(self.lifecycle()['status'],'FAILED')
 def test08_original_cases_and_pin_preserved(self):
  node=next(n for n in ast.walk(ast.parse(VT)) if isinstance(n,ast.ClassDef) and n.name=='Cases');self.assertEqual(hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest(),CONTRACT['caseASTSHA256']);self.assertEqual(len([n for n in node.body if isinstance(n,ast.FunctionDef)]),8);self.assertIn('counter==27',VT);self.assertIn(self.v['PIN'],VT)
 def test09_default_full(self):
  for event in ('push','pull_request','workflow_dispatch'):self.assertEqual(self.c['select_purpose'](event,{},'linux-x64','full'),'full')
 def test10_release_conflict(self):
  with self.assertRaises(self.c['Failure']):self.c['select_purpose']('workflow_dispatch',{'verifier_preflight':True,'verify_release':True},'win-x64','verifier-sdk0')
 def test11_wrong_rid_or_event_denied(self):
  with self.assertRaises(self.c['Failure']):self.c['select_purpose']('workflow_dispatch',{'verifier_preflight':True},'linux-x64','verifier-sdk0')
  with self.assertRaises(self.c['Failure']):self.c['select_purpose']('push',{},'win-x64','verifier-sdk0')
 def test12_mocked_sdk0_branch_before_sdk(self):
  ctx={'runRoot':str(self.run),'workspace':str(self.run),'rid':'win-x64','purpose':'verifier-sdk0','nonce':'n','binding':{'source':'s','controllerSHA256':'c'},'environment':{},'deadlineMono':time.monotonic()+30}
  (self.run/'release.json').write_text(json.dumps({'pid':42,'start':'birth','nonce':'n'}))
  self.c.update(child_context=lambda *a:ctx,windows_api=lambda:(SimpleNamespace(GetCurrentProcess=lambda:0),None,None,None,None,None,None,lambda h:'birth',None),os=SimpleNamespace(getpid=lambda:42,fsync=os.fsync,replace=os.replace),budget=lambda *a:None)
  calls=[];self.c['verifier_input_guard']=lambda x:calls.append('source');self.c['run_verifier_preflight']=lambda x:calls.append('fixture')
  def forbidden(*a):raise AssertionError('SDK_OR_FULL_INPUT_CALLED')
  self.c['shared_sdk']=self.c['input_policy']=self.c['consumer_denials']=forbidden
  self.assertEqual(self.c['worker'](self.run/'context.json','hash'),0);self.assertEqual(calls,['source','fixture']);result=json.loads((self.run/'child-result.json').read_bytes());self.assertEqual(result['SDKProcessesStartedByController'],0);self.assertFalse(result['payloadReleased']);self.assertFalse((self.run/'package-admission.json').exists())
 def test13_requested_mode_must_match_event(self):
  with self.assertRaises(self.c['Failure']):self.c['select_purpose']('workflow_dispatch',{'verifier_preflight':True},'win-x64','full')
  self.assertEqual(self.c['select_purpose']('workflow_dispatch',{'verifier_preflight':'true','verify_release':'false'},'win-x64','verifier-sdk0'),'verifier-sdk0')
 def test14_workflow_optin_and_default_matrix(self):
  data=yaml.load(WT,Loader=yaml.BaseLoader);self.assertEqual(set(data['jobs']),{'ci_policy','verify','aggregate'});expression=data['jobs']['verify']['strategy']['matrix']['include'];arrays=re.findall(r"'(\[.*?\])'",expression);self.assertEqual([len(json.loads(value)) for value in arrays],[1,2]);self.assertEqual(json.loads(arrays[0])[0]['rid'],'win-x64');self.assertEqual(data['on']['workflow_dispatch']['inputs']['verifier_preflight']['default'],'false');self.assertIn('&& 5 || 20',data['jobs']['verify']['timeout-minutes']);self.assertIn('inputs.verifier_preflight != true',data['jobs']['aggregate']['if'])
 def test15_command_failure_not_masked_by_diagnostic(self):
  fake=SimpleNamespace(returncode=1,poll=lambda:1);self.c.update(stage=lambda *a:None,budget=lambda *a:None,subprocess=SimpleNamespace(Popen=lambda *a,**k:fake,STDOUT=1,TimeoutExpired=subprocess.TimeoutExpired))
  def failed(*a):raise ValueError('SECONDARY')
  self.c['capture_payload_diagnostic']=failed
  with self.assertRaises(self.c['Failure']) as raised:self.c['command']({'runRoot':str(self.run),'workspace':str(self.run),'environment':{},'SDKLaunchAttempts':0,'SDKProcessesStarted':0},['FAKE'],'original-native-payload',1)
  self.assertEqual(raised.exception.cause,'COMMAND_FAILED')
 def test16_preflight_missing_or_wrong_suite_receipt_fails(self):
  self.c['command']=lambda *a,**k:None;self.c['remaining']=lambda *a:1
  (self.run/'verifier-suite-receipt.json').write_text(json.dumps({'status':'PASS','run':7,'subprocessScenarios':27}))
  with self.assertRaises(self.c['Failure']):self.c['run_verifier_preflight']({'runRoot':str(self.run),'workspace':str(self.run),'purpose':'verifier-sdk0','rid':'win-x64','SDKProcessesStarted':0})
 def test17_profile_and_guard_order_static(self):
  self.assertIn('BOOTSTRAP_MONO + 240',CT);self.assertIn('268435456 if binding["purpose"] == "verifier-sdk0" else 4294967296',CT);worker=ast.get_source_segment(CT,C['worker']);self.assertLess(worker.index('release.json'),worker.index('run_verifier_preflight(ctx)'));self.assertLess(worker.index('run_verifier_preflight(ctx)'),worker.index('shared_sdk(ctx)'));self.assertIn('"MARK_STAGE_FULL_ONLY"',CT);self.assertIn('"actualOriginalJobMember": True',CT)
 def test18_exact_export_never_copies_private_keys(self):
  (self.run/'verifier-private').mkdir();(self.run/'verifier-private'/'private-key').write_bytes(count(b'PRIVATE_KEY_SENTINEL'))
  (self.run/'verifier-lifecycle.json').write_text('{"phase":"ENTRY"}')
  workspace=self.run/'workspace';workspace.mkdir();self.c['export_evidence']({'runRoot':str(self.run),'workspace':str(workspace),'sdkStage':str(self.run/'absent-sdk'),'rid':'win-x64'})
  files=list((workspace/'artifacts/hosted-cap-proof').iterdir());self.assertEqual([f.name for f in files],['verifier-lifecycle.json']);self.assertNotIn('PRIVATE_KEY',files[0].read_text());self.assertIn('incremental <= 32768',CT)
if __name__=='__main__':
 start=time.monotonic();suite=unittest.defaultTestLoader.loadTestsFromTestCase(Deltas)
 if suite.countTestCases()!=18:raise RuntimeError('EXACT18')
 result=unittest.TextTestRunner().run(suite);elapsed=time.monotonic()-start
 print(json.dumps({'tests':result.testsRun,'inputBytes':INPUT,'seconds':elapsed,'SDK':0,'SSH':0,'HTTP':0,'native':0,'optimization':sys.flags.optimize}))
 raise SystemExit(0 if result.wasSuccessful() and INPUT<=524288 and elapsed<=30 else 1)
