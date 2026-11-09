"""Bounded fixed-seed native replay, independent oracle, deterministic parity and hostile frames."""
import argparse,copy,hashlib,json,platform,random,shutil,subprocess,sys
from pathlib import Path
import oracle
def require(ok,message):
    if not ok:raise ValueError(message)
def main():
    p=argparse.ArgumentParser();p.add_argument('--cli',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();cli=a.cli.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    def call(*args,expected=0):
        result=subprocess.run([str(cli),*map(str,args)],capture_output=True,timeout=90);require(result.returncode==expected,'Native command failed '+repr(args[:1]));return result
    source=call('version').stdout.decode().strip();histories=[]
    simple=[json.loads(line) for line in (Path(__file__).resolve().parents[1]/'examples/priority.jsonl').read_text().splitlines()];histories.append(('priority',simple))
    for seed in [11,7021,20261109]:
        rng=random.Random(seed);commands=[]
        for i in range(600):
            if i%5==0:c=dict(kind='cancel',orderId='o'+str(rng.randrange(i+1)))
            else:c=dict(kind='limit',orderId='o'+str(i if i%17 else max(1,i-1)),side=rng.choice(['buy','sell']),priceTicks=rng.randint(95,105),quantity=rng.randint(1,20))
            if i%53==0:c=dict(kind='limit',orderId='bad'+str(i),side='buy',priceTicks=0,quantity=1)
            commands.append(c)
        histories.append(('seed-'+str(seed),commands))
    results=[];run_count=0
    for name,commands in histories:
        file=out/(name+'.jsonl');file.write_text(''.join(json.dumps(c,separators=(',',':'))+'\n' for c in commands),encoding='utf-8',newline='\n');runs=[]
        for variant in ['scan','indexed','replay']:
            target=out/(name+'-'+variant);call('run',file,target,'indexed' if variant=='replay' else variant);result=oracle.verify(file,target);runs.append(target);run_count+=1
        for candidate in runs[1:]:
            for filename in ['events.jsonl','final.json']:require((candidate/filename).read_bytes()==(runs[0]/filename).read_bytes(),'Deterministic baseline/indexed/replay mismatch')
        results.append(dict(history=name,**result))
    hostile={'duplicate':b'{"kind":"cancel","orderId":"a","orderId":"b"}\n','missing':b'{}\n','unknown':b'{"kind":"cancel","orderId":"a","live":true}\n','null':b'{"kind":"cancel","orderId":null}\n','blank':b'\n','bare-cr':b'{"kind":"cancel",\r"orderId":"a"}\n','invalid-utf8':b'\xff\n','oversized-frame':b' '*4097+b'\n','oversized-file':b' '* (8*1024*1024+1),'late-malformed':b'{"kind":"cancel","orderId":"a"}\n{\n','bom':b'\xef\xbb\xbf{}\n','number-string':b'{"kind":"limit","orderId":"a","side":"buy","priceTicks":"1","quantity":1}\n'}
    for name,value in hostile.items():
        file=out/('deny-'+name+'.jsonl');file.write_bytes(value);target=out/('deny-'+name);call('run',file,target,expected=2);require(not target.exists(),'Full frame preflight before engine/output creation')
    subprocess.run([sys.executable,str(Path(__file__).with_name('test_framing.py')),'--cli',str(cli),'--out',str(out/'framing')],check=True,timeout=120)
    framing=json.loads((out/'framing/receipt.json').read_text());require(framing['status']=='PASS' and framing['tests']==16 and framing['failed']==0,'Native byte framing')
    # Oracle falsification: each mutation must fail independently.
    original=out/'priority-indexed';input_file=out/'priority.jsonl';negative=[]
    for mode in ['trade-price','trade-maker','trade-order','trade-id','trade-quantity','state-hash','missing-event','final-conservation']:
        target=out/('oracle-deny-'+mode);shutil.copytree(original,target);records=[json.loads(l) for l in (target/'events.jsonl').read_text().splitlines()];trade_record=next(r for r in records if len(r['result']['trades'])==2)
        if mode=='trade-price':trade_record['result']['trades'][0]['priceTicks']+=1
        elif mode=='trade-maker':trade_record['result']['trades'][0]['makerId']='second'
        elif mode=='trade-order':trade_record['result']['trades'].reverse()
        elif mode=='trade-id':trade_record['result']['trades'][0]['tradeId']='999:1'
        elif mode=='trade-quantity':trade_record['result']['trades'][0]['quantity']+=1
        elif mode=='state-hash':records[-1]['stateHash']='0'*64
        elif mode=='missing-event':records.pop()
        else:
            final=json.loads((target/'final.json').read_text());final['orders'][0]['cancelledQuantity']+=1;(target/'final.json').write_text(json.dumps(final))
        (target/'events.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
        try:oracle.verify(input_file,target)
        except ValueError:negative.append(mode)
        else:raise ValueError('Oracle accepted corruption '+mode)
    receipt=dict(status='PASS_CORRECTNESS_NOT_A_SPEED_CLAIM',os=platform.system(),sourceVersion=source,histories=len(histories),nativeRuns=run_count,commandsPerImplementation=sum(len(c) for _,c in histories),results=results,hostileFrames=len(hostile),byteFramingRegressions=framing['tests'],oracleRegressions=len(negative),boundary='Native CLI with full per-command ledger hashes; two C# representations and independent Python scan model. No latency benchmark, network, persistent book or venue claim.')
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':main()
