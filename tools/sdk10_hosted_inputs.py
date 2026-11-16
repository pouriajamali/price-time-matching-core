"""Shared source-only SDK10 hosted adapter; caller owns actual caps/admission."""
import sys,os,json,hashlib,pathlib,zipfile,tarfile,stat,time,argparse,urllib.request
sys.dont_write_bytecode=True
START=time.monotonic()
DEADLINE=None
def path(value): return pathlib.Path(value)
def require(ok,why):
 if not ok:raise RuntimeError(why)
 if time.monotonic()-START>300 or (DEADLINE is not None and time.time()>=DEADLINE):raise RuntimeError('SDK10 shared materialization deadline')
def sha(p,alg='sha256'):
 h=hashlib.new(alg)
 with open(p,'rb') as f:
  while data:=f.read(65536):h.update(data);require(True,'budget')
 return h.hexdigest()
def literal(p):
 p=path(p);require(p.is_absolute() and '..' not in p.parts,'absolute literal path')
 for q in list(reversed(p.parents))+[p]:
  try:s=os.lstat(q)
  except FileNotFoundError:continue
  require(not stat.S_ISLNK(s.st_mode) and not(getattr(s,'st_file_attributes',0)&0x400),'literal reparse/link ancestor')
 return p
parser=argparse.ArgumentParser()
parser.add_argument('--project-id',choices=['10','12'],required=True)
parser.add_argument('--rid',choices=['win-x64','linux-x64'],required=True)
parser.add_argument('--deadline-unix',type=int,required=True)
args=parser.parse_args();rid=args.rid
DEADLINE=args.deadline_unix
require(time.time()<DEADLINE<=time.time()+300,'same own-stage remaining window, maximum300s')
require((rid=='win-x64')==(os.name=='nt'),'matching native extraction host')
require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='X64','hosted X64 only')
require(os.environ.get('RUNNER_OS')==('Windows' if rid=='win-x64' else 'Linux'),'matching runner OS')
workspace=literal(os.environ['GITHUB_WORKSPACE']);temporary=literal(os.environ['RUNNER_TEMP'])
source=literal(pathlib.Path(__file__).absolute())
require(source==workspace/'tools/sdk10_hosted_inputs.py','fixed checked-out source path')
catalog_path=literal(source.with_name('sdk10-inputs.lock.json'))
require(sha(catalog_path)=='582017ddb5fedcddcffcc66effb7dcb3f9b54949ed81ca3b033b15d78bfa44c8','closed shared catalog')
catalog=json.loads(catalog_path.read_bytes())
require(os.environ.get('GITHUB_REPOSITORY')==catalog['projects'][args.project_id],'own project/repository')
inventory=literal(source.with_name(catalog['inventory']['file']))
require(inventory.stat().st_size==catalog['inventory']['bytes'] and sha(inventory)==catalog['inventory']['sha256'],'sealed full member inventory')
raw=catalog['rids'][rid]
stage=literal(temporary/('sdk10-input-'+args.project_id+'-'+rid))
require(not os.path.lexists(stage) and temporary.resolve() in stage.resolve().parents,'fresh owned hosted stage')
stage.mkdir(exist_ok=False)
archive=literal(stage/raw['name']);part=literal(stage/(raw['name']+'.part'))
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):raise RuntimeError('SDK URL redirect denied; no fallback')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
try:
 request=urllib.request.Request(raw['url'],headers={'User-Agent':'sdk10-shared-bounded-input'})
 require(True,'before one fixed raw acquisition')
 with opener.open(request,timeout=max(.001,min(15,DEADLINE-time.time()))) as response:
  require(response.status==200 and response.geturl()==raw['url'],'exact official SDK response')
  length=response.headers.get('Content-Length')
  require(length is None or int(length)==raw['bytes'],'raw content-length')
  n=0;h256=hashlib.sha256();h512=hashlib.sha512()
  with part.open('xb') as output:
   while True:
    require(True,'raw download deadline')
    data=response.read(min(65536,raw['bytes']-n+1))
    if not data:break
    require(n+len(data)<=raw['bytes'],'closed raw byte cap')
    output.write(data);h256.update(data);h512.update(data);n+=len(data)
  require(n==raw['bytes'] and h256.hexdigest()==raw['rawSha256'] and h512.hexdigest()==raw['rawSha512'],'exact raw SDK bytes/hash')
 part.rename(archive)
except Exception as error:
 record={'schema':'sdk10-input-failure/v1','projectId':args.project_id,'rid':rid,'stage':'RAW_ACQUISITION','exceptionType':type(error).__name__,'message':str(error)[:1024],'partBytes':part.stat().st_size if part.exists() else 0,'SDKCalls':0,'noRetry':True}
 with (stage/'input-failure.json').open('x',encoding='utf-8') as output:json.dump(record,output,indent=2)
 raise
require(archive.stat().st_size==raw['bytes'] and sha(archive,'sha512')==raw['rawSha512'] and sha(archive)==raw['rawSha256'],'actual raw identity')
target=literal(stage/'sdk')
require(not os.path.lexists(target) and stage.resolve() in target.resolve().parents,'fresh owned SDK root')
name=raw['name']
expected={}
with open(inventory,encoding='utf-8') as f:
 for line in f:
  x=json.loads(line)
  if x.get('archive')==name and 'type' in x:
   require(x['path'] not in expected,'duplicate sealed path');expected[x['path']]=x
require(len(expected)==(5578 if rid=='win-x64' else 5631),'exact SDK inventory cardinality')
held=open(archive,'rb');container=zipfile.ZipFile(held) if rid=='win-x64' else tarfile.open(fileobj=held,mode='r:gz')
fixed=[];seen=set()
try:
 # Validate ALL headers, types, literal ancestors, modes, sizes and collision set
 # against full approved inventory BEFORE creating target or any member file.
 for item in (container.infolist() if rid=='win-x64' else container):
  require(len(fixed)<50000,'member count cap')
  name_in=item.filename if rid=='win-x64' else item.name
  require('\\' not in name_in and '\x00' not in name_in and ':' not in name_in and not name_in.startswith('/') and '..' not in name_in.split('/'),'unsafe name')
  normalized=pathlib.PurePosixPath(name_in).as_posix()
  if rid=='win-x64':
   mode=(item.external_attr>>16)&0xffff;typ=stat.S_IFMT(mode)
   require(typ in (0,stat.S_IFREG,stat.S_IFDIR) and not(item.flag_bits&1),'ZIP special/encrypted')
   kind='directory' if item.is_dir() else 'file';size=item.file_size
  else:
   require(item.isfile() or item.isdir(),'no SDK links/devices/special')
   require(not item.pax_headers or set(item.pax_headers)<=set(['path','size']),'unreviewed PAX semantics')
   mode=item.mode;kind='directory' if item.isdir() else 'file';size=item.size
  require(not(mode&0o6000),'privileged mode')
  key=normalized.casefold() if rid=='win-x64' else normalized
  require(key not in seen and normalized in expected,'duplicate/unsealed member');seen.add(key)
  e=expected[normalized]
  require(e['type']==kind and e['bytes']==size and e['mode']==mode,'exact type/size/mode')
  dest=literal(target/normalized)
  require(dest.resolve()==target.resolve() or target.resolve() in dest.resolve().parents,'final containment')
  fixed.append((item,e,dest))
 require(len(fixed)==len(expected),'complete inventory set')
 for _,e,_ in fixed:
  for p in pathlib.PurePosixPath(e['path']).parents:
   if p.as_posix() in expected:require(expected[p.as_posix()]['type']=='directory','file prefix collision')
 target.mkdir(parents=True,exist_ok=False)
 files=0;expanded=0
 for item,e,dest in fixed:
  require(True,'budget');literal(dest)
  if e['type']=='directory':
   dest.mkdir(parents=True,exist_ok=True)
   if rid=='linux-x64':os.chmod(dest,e['mode']&0o777)
   continue
  dest.parent.mkdir(parents=True,exist_ok=True);literal(dest)
  h=hashlib.sha256();n=0
  source=container.open(item) if rid=='win-x64' else container.extractfile(item)
  with source,open(dest,'xb') as output:
   while data:=source.read(65536):
    require(n+len(data)<=e['bytes'],'member size cap');h.update(data);output.write(data);n+=len(data)
  require(n==e['bytes'] and h.hexdigest()==e['sha256'],'materialized payload differs from approved inventory')
  if rid=='linux-x64':os.chmod(dest,e['mode']&0o777)
  files+=1;expanded+=n
 require(sha(archive)==raw['rawSha256'],'raw unchanged after materialization')
 # Same full member postcondition as the existing Linux verifier, also accounting
 # for ZIP's implicit directories on Windows. No SDK executable is invoked.
 actual_files=set();actual_dirs=set()
 allowed_dirs=set()
 for e in expected.values():
  if e['type']=='directory' and e['path']!='.':allowed_dirs.add(e['path'])
  for parent in pathlib.PurePosixPath(e['path']).parents:
   if parent.as_posix()!='.':allowed_dirs.add(parent.as_posix())
 for p in target.rglob('*'):
  literal(p);relative=p.relative_to(target).as_posix();info=os.lstat(p)
  require(not stat.S_ISLNK(info.st_mode) and not(getattr(info,'st_file_attributes',0)&0x400),'disk link/reparse')
  if stat.S_ISDIR(info.st_mode):
   require(relative in allowed_dirs,'unapproved disk directory');actual_dirs.add(relative)
  else:
   require(stat.S_ISREG(info.st_mode) and relative in expected,'unapproved disk file')
   e=expected[relative]
   require(e['type']=='file' and info.st_size==e['bytes'] and sha(p)==e['sha256'],'disk payload readback')
   actual_files.add(relative)
  if rid=='linux-x64':
   require(relative in expected and stat.S_IMODE(info.st_mode)==(expected[relative]['mode']&0o777),'exact Linux disk mode')
 require(actual_files=={e['path'] for e in expected.values() if e['type']=='file'} and actual_dirs==allowed_dirs,'exact on-disk inventory')
 require(expanded==raw['expandedBytes'] and expanded<=4294967296,'exact expanded byte ceiling')
 evidence=stage/'evidence';evidence.mkdir(exist_ok=False)
 report={'status':'EXACT_SDK_MATERIALIZED_ALL_FILES_MATCH_SEALED_INVENTORY','rid':rid,'rawArchive':str(archive),'rawSha256':raw['rawSha256'],'rawSha512':raw['rawSha512'],'sdkRoot':str(target),'memberCount':len(fixed),'files':files,'expandedBytes':expanded,'validatedAllBeforeWrite':True,'sourceSha256':sha(pathlib.Path(__file__)),'seconds':time.monotonic()-START,'executedSdk':False,'noLinks':True,'projectId':args.project_id,'catalogSha256':sha(catalog_path),'inventorySha256':sha(inventory),'fullDiskMemberSetChecked':True}
 with open(evidence/('sdk-materialization-'+rid+'.json'),'x',encoding='utf-8') as f:json.dump(report,f,indent=2)
 print(json.dumps(report))
finally:container.close();held.close()
