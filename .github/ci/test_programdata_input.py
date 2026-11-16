"""Twelve ProgramData/identity mock inputs only; no SSH/SDK/network/product execution."""
import argparse,ast,builtins,hashlib,io,json,sys,time,unittest
from pathlib import Path,PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch
R=Path(__file__).resolve().parents[2]
S={name:(R/name).read_bytes() for name in ('.github/ci/hosted_caps.py','tools/test_verifier.py')}
INPUT=sum(map(len,S.values()))+Path(__file__).stat().st_size
if INPUT>524288:raise RuntimeError('INPUT_CAP')
A={name:ast.parse(data) for name,data in S.items()}
IDENTITY={'bytes':861184,'sha256':'c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f'}
VALID='C:\\Synthetic Program Data\\ '
class Metadata:
 def __init__(self,exists=True,error=False):self.exists=exists;self.error=error;self.seen=[]
 def __call__(self,value):self.seen.append(value);return self
 def is_dir(self):
  if self.error:raise OSError('PRIVATE_PATH_OR_ENV_MUST_NOT_ESCAPE')
  return self.exists
class FakePath:
 def __init__(self,value):self.value=str(value)
 def resolve(self,**kw):return self
 def is_dir(self):return True
 def is_symlink(self):return False
 def mkdir(self,**kw):pass
 def __truediv__(self,part):return FakePath(self.value+'/'+str(part))
 def __str__(self):return self.value

def compile_selected(name,names,env):
 nodes={n.name:n for n in A[name].body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 exec(compile(ast.fix_missing_locations(ast.Module(body=[nodes[n] for n in names],type_ignores=[])),'<selected-programdata-source>','exec'),env)
 return nodes
class Inputs(unittest.TestCase):
 def setUp(self):
  self.meta=Metadata();shared={'Path':self.meta,'PureWindowsPath':PureWindowsPath,'hashlib':hashlib}
  self.c=dict(shared);self.v=dict(shared,WINDOWS_SSH_IDENTITY=dict(IDENTITY))
  self.cn=compile_selected('.github/ci/hosted_caps.py',('Failure','need','forward_windows_programdata'),self.c)
  self.vn=compile_selected('tools/test_verifier.py',('programdata_observation','enforce_ssh_identity','failure_data'),self.v)
 def reject(self,env,code):
  child={'UNCHANGED':'synthetic'}
  with self.assertRaises(self.c['Failure']) as ce:self.c['forward_windows_programdata'](env,child,True)
  self.assertEqual(ce.exception.cause,code);self.assertEqual(child,{'UNCHANGED':'synthetic'})
  with self.assertRaises(ValueError) as ve:self.v['programdata_observation'](env,True)
  self.assertEqual(self.v['failure_data'](ve.exception)['inputCode'],code)
  self.assertNotIn('PRIVATE_PATH',str(ce.exception)+json.dumps(self.v['failure_data'](ve.exception)))
 def test01_missing(self):self.reject({},'PROGRAMDATA_MISSING');self.assertEqual(self.meta.seen,[])
 def test02_empty(self):self.reject({'ProgramData':''},'PROGRAMDATA_EMPTY');self.assertEqual(self.meta.seen,[])
 def test03_relative(self):self.reject({'ProgramData':'relative/folder'},'PROGRAMDATA_NOT_ABSOLUTE');self.assertEqual(self.meta.seen,[])
 def test04_controls(self):self.reject({'ProgramData':VALID+'\x00\r\n'},'PROGRAMDATA_CONTROLS');self.assertEqual(self.meta.seen,[])
 def test05_nonexistent(self):self.meta.exists=False;self.reject({'ProgramData':VALID},'PROGRAMDATA_NOT_DIRECTORY');self.assertEqual(self.meta.seen,[VALID,VALID])
 def test06_exact_value_and_safe_observation(self):
  child={'UNCHANGED':'synthetic'};actual=self.c['forward_windows_programdata']({'ProgramData':VALID},child,True)
  expected={'applicable':True,'present':True,'nonempty':True,'absolute':True,'existingDirectory':True,'valueSHA256':hashlib.sha256(VALID.encode('utf-8',errors='surrogatepass')).hexdigest()}
  self.assertEqual(child,{'UNCHANGED':'synthetic','ProgramData':VALID});self.assertEqual(actual,expected)
  self.assertEqual(self.v['programdata_observation'](child,True),expected);self.assertEqual(self.meta.seen,[VALID,VALID])
  self.assertNotIn(VALID,json.dumps(actual));self.assertEqual(set(actual),set(expected))
 def test07_linux_unchanged(self):
  child={'PATH':'synthetic'};self.assertEqual(self.c['forward_windows_programdata']({},child,False),{'applicable':False})
  self.assertEqual(child,{'PATH':'synthetic'});self.assertEqual(self.v['programdata_observation']({},False),{'applicable':False})
  self.v['enforce_ssh_identity']({'bytes':1,'sha256':'different-linux-identity'},False);self.assertEqual(self.meta.seen,[])
 def test08_metadata_failure_redacted(self):self.meta.error=True;self.reject({'ProgramData':VALID},'PROGRAMDATA_DIRECTORY_METADATA_UNKNOWN')
 def test09_missing_fails_before_ssh(self):
  events=[];receipts=[]
  env=dict(self.v,Path=FakePath,argparse=argparse,os=SimpleNamespace(name='nt',environ={'MATCHING10_DIAGNOSTIC_ROOT':'OWNED_SYNTHETIC'}),sys=sys,
           shutil=SimpleNamespace(which=lambda *a:events.append('SSH_SELECTION')),CASE_IDS=(),__builtins__=dict(builtins.__dict__))
  env['__builtins__']['__import__']=lambda name,*a,**kw:SimpleNamespace() if name=='verify_downloads' else builtins.__import__(name,*a,**kw)
  compile_selected('tools/test_verifier.py',('main',),env)
  env['emit_lifecycle']=lambda root,state:receipts.append(json.loads(json.dumps(state)))
  env['tool_identity']=lambda *a:events.append('TOOL_IDENTITY')
  env['observed_run']=lambda *a,**kw:events.append('SSH_LAUNCH')
  with patch.object(sys,'argv',['mock','--out','SYNTHETIC_RESULTS']):self.assertEqual(env['main'](),1)
  self.assertEqual(events,[]);self.assertEqual(receipts[-1]['phase'],'PROGRAMDATA_INPUT')
  self.assertEqual(receipts[-1]['failure']['inputCode'],'PROGRAMDATA_MISSING')
 def test10_known_identity_before_first_launch(self):
  self.v['enforce_ssh_identity'](dict(IDENTITY),True)
  main=next(n for n in A['tools/test_verifier.py'].body if isinstance(n,ast.FunctionDef) and n.name=='main')
  calls={n.func.id:n.lineno for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in ('programdata_observation','enforce_ssh_identity','observed_run')}
  self.assertLess(calls['programdata_observation'],calls['enforce_ssh_identity']);self.assertLess(calls['enforce_ssh_identity'],calls['observed_run'])
 def test11_hash_drift_holds(self):
  with self.assertRaises(ValueError) as error:self.v['enforce_ssh_identity']({**IDENTITY,'sha256':'0'*64},True)
  self.assertEqual(self.v['failure_data'](error.exception)['inputCode'],'SSH_IDENTITY_DRIFT')
 def test12_size_drift_holds(self):
  with self.assertRaises(ValueError) as error:self.v['enforce_ssh_identity']({**IDENTITY,'bytes':IDENTITY['bytes']+1},True)
  self.assertEqual(self.v['failure_data'](error.exception)['inputCode'],'SSH_IDENTITY_DRIFT')
if __name__=='__main__':
 started=time.monotonic();stream=io.StringIO();suite=unittest.defaultTestLoader.loadTestsFromTestCase(Inputs)
 result=unittest.TextTestRunner(stream=stream,verbosity=0).run(suite)
 report={'status':'PASS' if result.wasSuccessful() and result.testsRun==12 else 'FAIL','tests':result.testsRun,'inputBytes':INPUT,'seconds':time.monotonic()-started,'liveSSHSDKHTTPNative':0}
 if report['status']!='PASS':print(stream.getvalue()[:24000],file=sys.stderr)
 print(json.dumps(report,sort_keys=True));raise SystemExit(0 if report['status']=='PASS' else 1)
