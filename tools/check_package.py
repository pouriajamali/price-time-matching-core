"""Inspect exact payload/notices/actual runtime graph and execute bounded native input checks."""
import argparse,hashlib,json,os,platform,subprocess
from pathlib import Path,PurePosixPath
def require(ok,message):
    if not ok:raise ValueError(message)
def main():
    p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--commit',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();package=a.package.resolve();a.out.parent.mkdir(parents=True,exist_ok=True);require(not a.out.exists(),'Receipt exists');manifest=json.loads((package/'BUILD-MANIFEST.json').read_text());require(manifest['sourceCommit']==a.commit,'Commit');expected=set();checks=[]
    for item in manifest['files']:
        relative=PurePosixPath(item['path']);require(not relative.is_absolute() and '..' not in relative.parts and item['path'] not in expected,'Manifest framing');expected.add(item['path']);file=package/relative;require(file.is_file() and not file.is_symlink() and file.stat().st_size==item['bytes'] and hashlib.sha256(file.read_bytes()).hexdigest()==item['sha256'],'Payload bytes')
    require({f.relative_to(package).as_posix() for f in package.rglob('*') if f.is_file()}==expected|{'BUILD-MANIFEST.json'},'File set');checks.append('exact-payload-set-size-sha256')
    dependencies=json.loads((package/'DEPENDENCIES.json').read_text())['packages'];bom=json.loads((package/'SBOM.spdx.json').read_text());require(len(dependencies)==1 and len(bom['packages'])==2,'Actual graph');dep=dependencies[0];require(dep['id']=='Microsoft.NETCore.App.Runtime.'+manifest['rid'] and dep['version']=='10.0.14','Actual runtime');checks.append('actual-single-runtime-shipped-graph')
    license_file=package/dep['licenseFile'];require(license_file.stat().st_size>=300 and hashlib.sha256(license_file.read_bytes()).hexdigest()==dep['licenseSha256'],'Original license');require((package/dep['copyrightFile']).read_text(encoding='utf-8').strip()==dep['copyright'] and any('THIRD-PARTY-NOTICES' in f.name.upper() for f in (package/'licenses').iterdir()),'Original notices');checks.append('full-runtime-license-copyright-and-notices')
    component=next(c for c in bom['packages'] if c['name']==dep['id']);require(component['checksums']==[{'algorithm':'SHA512','checksumValue':dep['rawSignedNupkgSha512']}],'Raw NuGet archive checksum');checks.append('raw-archive-sha512-separate-normalized-identity')
    cli=package/('matching.exe' if os.name=='nt' else 'matching')
    def run(*args):return subprocess.run([str(cli),*map(str,args)],capture_output=True,text=True,timeout=20)
    require(run('help').returncode==0 and 'Synthetic single-writer' in run('help').stdout,'Help');version=run('version');require(version.returncode==0 and a.commit in version.stdout,'Actual binary source');checks.append('actual-native-help-version-source')
    private=a.out.parent/(a.out.stem+'-private-checks');private.mkdir(exist_ok=False);input_file=private/'command.jsonl';input_file.write_text('{"kind":"cancel","orderId":"a"}\n')
    target=private/'invalid';require(run('run',input_file,target,'other').returncode==2 and not target.exists(),'Unsupported variant');checks.append('unsupported-variant-rejected-before-output')
    malformed=private/'malformed.jsonl';malformed.write_text('{"kind":"cancel","orderId":"a"}\n{}\n');target=private/'malformed';require(run('run',malformed,target).returncode==2 and not target.exists(),'Full-file schema preflight');checks.append('late-malformed-frame-rejected-before-effects')
    receipt=dict(status='PASS',os=platform.system(),sourceCommit=a.commit,rid=manifest['rid'],payloadFiles=len(expected),shippedComponents=1,checkCount=len(checks),checks=checks);a.out.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':main()
