"""Independent integer scan model; verify every result, ordered trade and complete ledger hash.

No .NET library is imported and no order-book split/index implementation is copied.
"""
import argparse,hashlib,json,re
from pathlib import Path
MAX=2**63-1
def require(ok,message):
    if not ok:raise ValueError(message)
def state_hash(state):
    text=''.join(str(state[k])+'\n' for k in ['acceptedSequence','acceptedQuantity','executedQuantity','cancelledQuantity','executedNotional'])
    for o in state['orders']:text+='|'.join(str(o[k]) for k in ['orderId','side','priceTicks','acceptedSequence','acceptedQuantity','remainingQuantity','executedQuantity','cancelledQuantity'])+'\n'
    return hashlib.sha256(text.encode('ascii')).hexdigest()
class Model:
    def __init__(self):self.orders={};self.seq=0;self.accepted=0;self.executed=0;self.cancelled=0;self.notional=0
    def snapshot(self):
        orders=sorted(self.orders.values(),key=lambda o:o['orderId']);rest=[o for o in orders if o['remainingQuantity']]
        bids=sorted((o for o in rest if o['side']=='buy'),key=lambda o:(-o['priceTicks'],o['acceptedSequence']))
        asks=sorted((o for o in rest if o['side']=='sell'),key=lambda o:(o['priceTicks'],o['acceptedSequence']))
        for o in orders:require(o['acceptedQuantity']==o['remainingQuantity']+o['executedQuantity']+o['cancelledQuantity'],'Per-order conservation')
        require(self.accepted==sum(o['remainingQuantity'] for o in orders)+2*self.executed+self.cancelled,'Global conservation')
        require(not bids or not asks or bids[0]['priceTicks']<asks[0]['priceTicks'],'Uncrossed resting book')
        return dict(acceptedSequence=self.seq,acceptedQuantity=self.accepted,executedQuantity=self.executed,cancelledQuantity=self.cancelled,executedNotional=self.notional,orders=orders,bidPriority=[o['orderId'] for o in bids],askPriority=[o['orderId'] for o in asks])
    def apply(self,c):
        def reject(reason):return dict(status='REJECTED',reason=reason,acceptedSequence=self.seq,trades=[])
        identity=c['orderId'];kind=c['kind'];side=c.get('side');price=c.get('priceTicks');quantity=c.get('quantity')
        if not isinstance(identity,str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,31}',identity):return reject('INVALID_ID')
        if not ((kind=='limit' and side in ['buy','sell'] and type(price)==int and 1<=price<=1000000 and type(quantity)==int and 1<=quantity<=1000000) or (kind=='cancel' and side is None and price is None and quantity is None)):return reject('INVALID_COMMAND')
        if self.seq==MAX:return reject('SEQUENCE_EXHAUSTED')
        if kind=='cancel':
            if identity not in self.orders:return reject('UNKNOWN_ID')
            old=self.orders[identity]
            if not old['remainingQuantity']:return reject('NOT_RESTING')
            if self.cancelled+old['remainingQuantity']>MAX:return reject('ARITHMETIC_EXHAUSTED')
            self.cancelled+=old['remainingQuantity'];old['cancelledQuantity']+=old['remainingQuantity'];old['remainingQuantity']=0;self.seq+=1
            return dict(status='ACCEPTED',reason='CANCEL',acceptedSequence=self.seq,trades=[])
        if identity in self.orders:return reject('DUPLICATE_ID')
        if len(self.orders)==100000:return reject('LIFETIME_ID_CAPACITY')
        # Independent scan selects one best candidate repeatedly from a copied plain dictionary.
        import copy
        updated=copy.deepcopy(self.orders);remaining=quantity;trades=[];executed=self.executed;notional=self.notional
        while remaining:
            candidates=[o for o in updated.values() if o['remainingQuantity']>0 and o['side']!=side and (o['priceTicks']<=price if side=='buy' else o['priceTicks']>=price)]
            if not candidates:break
            best=min(candidates,key=lambda o:((o['priceTicks'] if side=='buy' else -o['priceTicks']),o['acceptedSequence']))
            amount=min(best['remainingQuantity'],remaining);best['remainingQuantity']-=amount;best['executedQuantity']+=amount;remaining-=amount;executed+=amount;notional+=amount*best['priceTicks']
            trades.append(dict(tradeId=str(self.seq+1)+':'+str(len(trades)+1),makerId=best['orderId'],takerId=identity,priceTicks=best['priceTicks'],quantity=amount))
        if max(self.accepted+quantity,executed,notional)>MAX:return reject('ARITHMETIC_EXHAUSTED')
        if sum(o['remainingQuantity']>0 for o in updated.values())+(remaining>0)>10000:return reject('RESTING_CAPACITY')
        updated[identity]=dict(orderId=identity,side=side,priceTicks=price,acceptedSequence=self.seq+1,acceptedQuantity=quantity,remainingQuantity=remaining,executedQuantity=quantity-remaining,cancelledQuantity=0)
        self.orders=updated;self.seq+=1;self.accepted+=quantity;self.executed=executed;self.notional=notional
        return dict(status='ACCEPTED',reason='LIMIT',acceptedSequence=self.seq,trades=trades)
def verify(input_path,output):
    require(input_path.stat().st_size<=8*1024*1024,'Input cap');commands=[json.loads(line) for line in input_path.read_text(encoding='utf-8').splitlines()]
    raw=output/'events.jsonl';require(raw.stat().st_size<=32*1024*1024,'Events cap');records=raw.read_text(encoding='utf-8').splitlines();require(len(records)==len(commands) and 1<=len(commands)<=20000,'Exact command partition')
    model=Model();accepted=rejected=trades=0
    for index,(command,line) in enumerate(zip(commands,records),1):
        record=json.loads(line);require(record['inputIndex']==index and record['command']==dict(kind=command['kind'],orderId=command['orderId'],side=command.get('side'),priceTicks=command.get('priceTicks'),quantity=command.get('quantity')),'Command framing/order')
        expected=model.apply(command);require(record['result']==expected,'Ordered result/trade mismatch at '+str(index));snapshot=model.snapshot();require(record['stateHash']==state_hash(snapshot),'Full ledger hash mismatch at '+str(index));accepted+=expected['status']=='ACCEPTED';rejected+=expected['status']=='REJECTED';trades+=len(expected['trades'])
    require(json.loads((output/'final.json').read_text())==model.snapshot(),'Final full ledger and priority queues')
    receipt=json.loads((output/'receipt.json').read_text());require(receipt['status']=='COMPLETE_NOT_INDEPENDENT_PROOF' and receipt['commands']==len(commands) and receipt['inputSha256']==hashlib.sha256(input_path.read_bytes()).hexdigest() and receipt['stateHash']==state_hash(model.snapshot()),'Run receipt identity')
    return dict(status='PASS_EVERY_COMMAND_INDEPENDENT_MODEL',commands=len(commands),accepted=accepted,rejected=rejected,trades=trades,stateHash=state_hash(model.snapshot()))
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);a=p.parse_args();result=verify(a.input,a.output);a.receipt.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
