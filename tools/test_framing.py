"""Native byte-framing regressions: terminal bare CR must fail before output/engine creation."""
import argparse,json,subprocess
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--cli',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();cli=a.cli.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    command=b'{"kind":"cancel","orderId":"unknown"}';unicode_command='{"kind":"limit","orderId":"unicode","side":"\u00e9","priceTicks":1,"quantity":1}'.encode('utf-8')
    def padded(value,size):
        if len(value)>size:raise ValueError('Fixture size')
        return value+b' '*(size-len(value))
    cases=[('lf',command+b'\n',True,1),('crlf',command+b'\r\n',True,1),('eof-without-newline',command,True,1),('mixed-lines',command+b'\n'+command+b'\r\n'+command,True,3),('frame4096-eof',padded(command,4096),True,1),('frame4096-crlf',padded(command,4096)+b'\r\n',True,1),('utf8-frame4096-eof',padded(unicode_command,4096),True,1),('multiple-crlf-eof',command+b'\r\n'+command,True,2),('single-bare-cr-eof',command+b'\r',False,0),('multiple-lf-bare-cr-eof',command+b'\n'+command+b'\r',False,0),('multiple-crlf-bare-cr-eof',command+b'\r\n'+command+b'\r',False,0),('frame4096-bare-cr-eof',padded(command,4096)+b'\r',False,0),('physical4096-bare-cr-eof',padded(command,4095)+b'\r',False,0),('frame4097-eof',padded(command,4097),False,0),('frame4097-crlf',padded(command,4097)+b'\r\n',False,0),('utf8-frame4097-eof',padded(unicode_command,4097),False,0)]
    results=[]
    for name,data,allowed,count in cases:
        source=out/(name+'.jsonl');source.write_bytes(data);destination=out/(name+'-output');result=subprocess.run([str(cli),'run',str(source),str(destination)],capture_output=True,timeout=20);expected=0 if allowed else 2;ok=result.returncode==expected and destination.exists()==allowed
        if allowed and ok:
            receipt=json.loads((destination/'receipt.json').read_text());events=(destination/'events.jsonl').read_text().splitlines();ok=receipt['status']=='COMPLETE_NOT_INDEPENDENT_PROOF' and receipt['commands']==count and len(events)==count
        results.append(dict(case=name,inputBytes=len(data),expectedExit=expected,actualExit=result.returncode,expectedOutputCreated=allowed,outputCreated=destination.exists(),passed=ok))
    receipt=dict(status='PASS' if all(r['passed'] for r in results) else 'FAIL',tests=len(results),passed=sum(r['passed'] for r in results),failed=sum(not r['passed'] for r in results),cases=results,boundary='Actual native apphost; denied framing creates no output. Positive controls retain LF/CRLF/final row without newline and exact UTF-8 byte caps. No matcher changes or market activity.')
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:receipt[k] for k in ['status','tests','passed','failed']}));raise SystemExit(0 if receipt['status']=='PASS' else 1)
if __name__=='__main__':main()
