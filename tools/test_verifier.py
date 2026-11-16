"""Original eight pinned-signature regressions with bounded failure-aware receipts."""
import argparse,hashlib,json,locale,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PIN='SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU'
CASE_IDS = ('test_actual_known_key_signature_and_archive', 'test_crlf_single_line_and_untrusted_comment_are_safe', 'test_forged_single_line_comment_does_not_authorize_attacker', 'test_noncanonical_blob_and_controls_are_rejected', 'test_second_bare_key_and_extra_blank_line_are_rejected', 'test_tampered_selected_archive_fails_after_valid_signature', 'test_valid_pinned_first_key_cannot_inject_attacker_principal', 'test_wrong_case_fingerprint_and_wrong_signature_fail')


def failure_data(error):
    names={'FileNotFoundError','FileExistsError','IsADirectoryError','PermissionError','CalledProcessError','TimeoutExpired','OSError','ValueError','ImportError','ModuleNotFoundError','UnicodeDecodeError'}
    return {'category':type(error).__name__ if type(error).__name__ in names else 'UNKNOWN_EXCEPTION',
            'exitCode':getattr(error,'returncode',None) if type(getattr(error,'returncode',None)) is int else None,
            'errno':getattr(error,'errno',None) if type(getattr(error,'errno',None)) is int else None,
            'winerror':getattr(error,'winerror',None) if type(getattr(error,'winerror',None)) is int else None}


def emit_lifecycle(root,state):
    data=(json.dumps(state,sort_keys=True)+'\n').encode()
    if len(data)>8192:raise ValueError('DIAGNOSTIC_CAP')
    target=root/'verifier-lifecycle.json';temporary=root/'verifier-lifecycle.new'
    with temporary.open('wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,target)


def tool_identity(path,kind):
    path=Path(path).resolve(strict=True);size=path.stat().st_size
    if not path.is_file() or size>67108864:raise ValueError('TOOL_IDENTITY_CAP')
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(65536),b''):digest.update(chunk)
    return {'kind':kind,'bytes':size,'sha256':digest.hexdigest()}


def observed_run(root,state,role,argv,timeout,check=False,text=False,env=None):
    if role not in ('DISPOSABLE_KEYGEN','ATTACKER_SIGN','FIXTURE_VERIFY'):raise ValueError('SUBPROCESS_ROLE')
    state.update(phase=role,status='RUNNING',lastSubprocess={'role':role,'exitCode':None});emit_lifecycle(root,state)
    try:
        result=subprocess.run(argv,capture_output=True,text=False,env=env,timeout=timeout)
        observations={}
        for label,value in (('stdout',result.stdout),('stderr',result.stderr)):
            data=value.encode('utf-8',errors='replace') if isinstance(value,str) else value or b''
            if len(data)>8388608:raise ValueError('SUBPROCESS_OUTPUT_CAP')
            observations[label+'Bytes']=len(data);observations[label+'SHA256']=hashlib.sha256(data).hexdigest()
        state['lastSubprocess']={'role':role,'exitCode':result.returncode,**observations};emit_lifecycle(root,state)
        if observations['stdoutBytes']+observations['stderrBytes']>8388608:raise ValueError('SUBPROCESS_OUTPUT_CAP')
        if check:result.check_returncode()
        if text:
            encoding='utf-8' if sys.flags.utf8_mode else locale.getencoding()
            result.stdout=result.stdout.decode(encoding).replace('\r\n','\n').replace('\r','\n')
            result.stderr=result.stderr.decode(encoding).replace('\r\n','\n').replace('\r','\n')
        return result
    except Exception as error:
        state.update(status='FAILED',failure=failure_data(error))
        if isinstance(error,(subprocess.TimeoutExpired,subprocess.CalledProcessError)):
            stats={'role':role,'exitCode':getattr(error,'returncode',None)}
            for label in ('stdout','stderr'):
                value=getattr(error,label,None);data=value.encode('utf-8',errors='replace') if isinstance(value,str) else value
                stats[label+'Bytes']=len(data) if isinstance(data,bytes) else None
                stats[label+'SHA256']=hashlib.sha256(data).hexdigest() if isinstance(data,bytes) and len(data)<=8388608 else None
            state['lastSubprocess']=stats
        try:emit_lifecycle(root,state)
        except Exception:pass
        raise


def run_suite(a,fixture,attacker,public,evil,verify_downloads,root,state,ssh):
    counter=0
    def attempt(key=public,pin=PIN,forged=False,tamper=False,mode='normal'):
        nonlocal counter
        counter+=1;state['attemptScenarios']=counter;folder=a.out/('case-'+str(counter));folder.mkdir()
        for name in ['fixture.zip','SHA256SUMS.txt','SHA256SUMS.txt.sig']:shutil.copy2(fixture/name,folder/name)
        (folder/'SIGNING-PUBLIC-KEY.pub').write_bytes(key)
        if forged:
            (folder/'SHA256SUMS.txt.sig').unlink()
            observed_run(root,state,'ATTACKER_SIGN',[ssh,'-Y','sign','-f',str(attacker),'-n','file',str(folder/'SHA256SUMS.txt')],15,check=True)
        if tamper:
            data=bytearray((folder/'fixture.zip').read_bytes());data[0]^=1;(folder/'fixture.zip').write_bytes(data)
        env=os.environ.copy();env.pop('PYTHONOPTIMIZE',None)
        if mode=='env':env['PYTHONOPTIMIZE']='1'
        result=observed_run(root,state,'FIXTURE_VERIFY',[sys.executable]+(['-O'] if mode=='flag' else [])+[str(ROOT/'tools/verify_downloads.py'),'--directory',str(folder),'--work',str(folder/'verification'),'--archive','fixture.zip','--trusted-fingerprint',pin],20,text=True,env=env)
        return result,folder
    class Cases(unittest.TestCase):
        def test_actual_known_key_signature_and_archive(self):
            for mode in ['normal','flag','env']:
                result,folder=attempt(mode=mode);self.assertEqual(0,result.returncode,result.stderr)
                self.assertEqual('PINNED_SIGNATURE_AND_PRESENT_ARCHIVES_VERIFIED',json.loads(result.stdout)['status'])
                self.assertEqual('pouriajamali '+verify_downloads.canonical_key(public)[0]+'\n',(folder/'verification/allowed-signers').read_text())
        def test_valid_pinned_first_key_cannot_inject_attacker_principal(self):
            for mode in ['normal','flag','env']:
                result,_=attempt(public.strip()+b'\npouriajamali '+evil+b'\n',forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
        def test_second_bare_key_and_extra_blank_line_are_rejected(self):
            for value in [public.strip()+b'\n'+evil+b'\n',public+b'\n']:
                with self.assertRaises(ValueError):verify_downloads.canonical_key(value)
                for mode in ['normal','flag','env']:
                    result,_=attempt(value,forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
        def test_forged_single_line_comment_does_not_authorize_attacker(self):
            base=verify_downloads.canonical_key(public)[0].encode()
            for mode in ['normal','flag','env']:
                result,folder=attempt(base+b' pouriajamali '+evil+b'\n',forged=True,mode=mode)
                self.assertNotEqual(0,result.returncode)
                self.assertEqual('pouriajamali '+base.decode()+'\n',(folder/'verification/allowed-signers').read_text())
        def test_wrong_case_fingerprint_and_wrong_signature_fail(self):
            for mode in ['normal','flag','env']:
                result,_=attempt(pin='sha256:'+PIN.split(':')[1],mode=mode);self.assertNotEqual(0,result.returncode)
                result,_=attempt(forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
                result,_=attempt(key=evil+b'\n',forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
        def test_noncanonical_blob_and_controls_are_rejected(self):
            base=verify_downloads.canonical_key(public)[0].encode()
            for value in [base+b'=\n',base+b'\0comment\n',b'restrict '+base+b'\n',base+b'\rCOMMENT\n',b'ssh-ed25519 AAAA\n']:
                with self.assertRaises(ValueError):verify_downloads.canonical_key(value)
        def test_crlf_single_line_and_untrusted_comment_are_safe(self):
            base,fingerprint=verify_downloads.canonical_key(public)
            self.assertEqual((base,fingerprint),verify_downloads.canonical_key(base.encode()+b' arbitrary-comment\r\n'))
        def test_tampered_selected_archive_fails_after_valid_signature(self):
            for mode in ['normal','flag','env']:
                result,_=attempt(tamper=True,mode=mode);self.assertNotEqual(0,result.returncode)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    passed=result.wasSuccessful() and result.testsRun==8 and counter==27
    return {'status':'PASS' if passed else 'FAIL','run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'subprocessScenarios':counter,'modes':['normal','python -O','PYTHONOPTIMIZE=1'],'scope':'Original pinned fixture and attacker-signature prerequisite only; not SDK/product acceptance','originalPrivateKeyReadOrCopied':False,'disposablePrivateKeyMustRemainPrivate':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
    root=None;state={'schema':'matching10/verifier-lifecycle/v1','phase':'ENTRY','status':'STARTED','testsExpected':8,'attemptScenariosExpected':27,'attemptScenarios':0,'caseIDs':list(CASE_IDS)}
    try:
        value=os.environ.get('MATCHING10_DIAGNOSTIC_ROOT')
        if not value:raise ValueError('OWNED_DIAGNOSTIC_ROOT_REQUIRED')
        root=Path(value).resolve(strict=True)
        if not root.is_dir() or Path(value).is_symlink():raise ValueError('OWNED_DIAGNOSTIC_ROOT_REQUIRED')
        emit_lifecycle(root,state)
        state['phase']='OUTPUT_SETUP';emit_lifecycle(root,state);a.out.mkdir(parents=True,exist_ok=False)
        state['phase']='VERIFIER_IMPORT';emit_lifecycle(root,state)
        import verify_downloads
        state['phase']='TOOL_IDENTITY';emit_lifecycle(root,state)
        ssh=shutil.which('ssh-keygen')
        if not ssh:raise FileNotFoundError('EXISTING_SSH_EXECUTABLE_NOT_RESOLVED')
        ssh=str(Path(ssh).resolve(strict=True))
        state['tools']={'ssh':tool_identity(ssh,'EXISTING_RESOLVED_SSH'),'python':tool_identity(sys.executable,'CURRENT_PYTHON')}
        state['phase']='PRIVATE_KEY_SETUP';emit_lifecycle(root,state)
        key_directory=Path(tempfile.mkdtemp(prefix='verifier-private-',dir=root))
        if os.name=='posix':os.chmod(key_directory,0o700)
        attacker=key_directory/'disposable-attacker-key'
        observed_run(root,state,'DISPOSABLE_KEYGEN',[ssh,'-q','-t','ed25519','-N','','-C','DISPOSABLE_TEST_KEY','-f',str(attacker)],20,check=True)
        state['phase']='FIXTURE_SETUP';emit_lifecycle(root,state)
        public=(ROOT/'SIGNING-PUBLIC-KEY.pub').read_bytes();evil=attacker.with_suffix('.pub').read_bytes().strip()
        state['phase']='SUITE_ENTRY';emit_lifecycle(root,state)
        receipt=run_suite(a,ROOT/'tests/provenance-fixture',attacker,public,evil,verify_downloads,root,state,ssh)
        state.update(phase='SUITE_COMPLETED',status=receipt['status'],testsRun=receipt['run'],attemptScenarios=receipt['subprocessScenarios']);emit_lifecycle(root,state)
        state['phase']='FINAL_RECEIPT';emit_lifecycle(root,state)
        data=(json.dumps(receipt,indent=2)+'\n').encode()
        if len(data)>8192:raise ValueError('RECEIPT_CAP')
        (a.out/'receipt.json').write_bytes(data)
        (root/'verifier-suite-receipt.json').write_bytes(data)
        state['phase']='FINAL_RECEIPT_WRITTEN';emit_lifecycle(root,state)
        return 0 if receipt['status']=='PASS' else 1
    except Exception as error:
        state.update(status='FAIL_UNKNOWN' if root is None else 'FAILED',failure=failure_data(error))
        if root is not None:
            try:emit_lifecycle(root,state)
            except Exception:pass
        return 1

if __name__=='__main__':raise SystemExit(main())
