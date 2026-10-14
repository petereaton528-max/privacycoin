"""Private, optional SIMULATION credits. No PC signing or network adapter.

Atomic whole-ledger transactions under the existing audited private file lock.
The OS account is trusted; operator and participant authority are distinct.
"""
import hashlib
import hmac
import secrets
import time
from pathlib import Path

UNIT = 'SIMULATION_CREDIT_ATOMIC_NOT_PC'
PC_MODE_ENABLED = False


def integer(value, low=0, high=10**15):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('INTEGER_BOUND')
    return value


def text(value, maximum=500):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(x)<32 for x in value):
        raise ValueError('TEXT_BOUND')
    return value


class Prediction:
    def __init__(self, home, clock=time.time):
        from src.phase6a import wallet as c
        self.c=c; self.home=Path(home); self.clock=clock
        c.harden(); self.home.mkdir(mode=0o700, exist_ok=True)
        with c.directory(self.home): pass
        self.path=self.home/'simulation.json'
        with c.lock(self.home/'simulation'):
            if not self.path.exists():
                c.write_private(self.path,c.f.canonical(dict(version=1,unit=UNIT,issued=0,participants={},events={},audit=[])))
            if not (self.home/'operator').exists():
                c.write_private(self.home/'operator',secrets.token_hex(32).encode())

    def _operator(self, token):
        if not isinstance(token,str) or not hmac.compare_digest(token.encode(),self.c.read_private(self.home/'operator')):
            raise ValueError('OPERATOR_AUTH_REQUIRED')

    def _transaction(self, fn):
        with self.c.lock(self.home/'simulation'):
            state=self.c.f.decode(self.c.read_private(self.path))
            if state['version']!=1 or state['unit']!=UNIT: raise ValueError('LEDGER_IDENTITY')
            result=fn(state)
            liabilities=sum(p['balance'] for p in state['participants'].values())
            liabilities+=sum(sum(b['amount'] for b in e['bets'].values()) for e in state['events'].values() if e['state']!='COMPLETED')
            if liabilities!=state['issued']: raise ValueError('CONSERVATION_FAILURE')
            if len(state['audit'])>2048: raise ValueError('AUDIT_BOUND_ARCHIVE_REQUIRED')
            self.c.write_private(self.path,self.c.f.canonical(state),replace=True)
            return result

    @staticmethod
    def _participant(state, credential):
        if not isinstance(credential,str) or len(credential)!=64: raise ValueError('PARTICIPANT_AUTH_REQUIRED')
        key=hashlib.sha256(credential.encode()).hexdigest()
        if key not in state['participants']: raise ValueError('PARTICIPANT_AUTH_REQUIRED')
        return key,state['participants'][key]

    def register(self, operator):
        self._operator(operator); credential=secrets.token_hex(32)
        def apply(s):
            if len(s['participants'])>=256: raise ValueError('PARTICIPANT_BOUND')
            s['participants'][hashlib.sha256(credential.encode()).hexdigest()]={'balance':100000}
            s['issued']+=100000
            return credential
        return self._transaction(apply)

    def create(self, operator, *, question, criteria, source, close, resolve, cancellation, authority):
        self._operator(operator)
        for x in (question,criteria,source,cancellation,authority): text(x)
        now=int(self.clock()); integer(close,now+1,now+86400*30); integer(resolve,close+1,close+86400*30)
        eid=secrets.token_hex(16)
        def apply(s):
            if len(s['events'])>=64: raise ValueError('EVENT_BOUND')
            s['events'][eid]=dict(id=eid,question=question,criteria=criteria,source=source,close=close,resolve=resolve,cancellation=cancellation,authority=authority,state='OPEN',bets={},outcome=None,evidence=None,payouts={},operations={})
            s['audit'].append(dict(event=eid,action='CREATE',time=now))
            return eid
        return self._transaction(apply)

    def participate(self, credential, event, side, amount, key):
        if side not in ('YES','NO'): raise ValueError('BINARY_SIDE')
        integer(amount,1,100000); text(key,64)
        def apply(s):
            pid,p=self._participant(s,credential); e=s['events'][event]; op=pid+':'+key
            terms=dict(participant=pid,side=side,amount=amount)
            if op in e['operations']:
                if e['operations'][op]!=terms: raise ValueError('IDEMPOTENCY_CONFLICT')
                return {'state':'ACCEPTED_SIMULATION','duplicate':True}
            if e['state']!='OPEN' or int(self.clock())>=e['close']: raise ValueError('PARTICIPATION_CLOSED')
            if pid in e['bets']: raise ValueError('ONE_PARTICIPATION_PER_EVENT')
            if p['balance']<amount: raise ValueError('INSUFFICIENT_CREDITS')
            p['balance']-=amount; e['bets'][pid]=terms; e['operations'][op]=terms
            return {'state':'ACCEPTED_SIMULATION','duplicate':False}
        return self._transaction(apply)

    def adjudicate(self, operator, event, action, *, outcome=None, evidence=None, consent=None):
        self._operator(operator)
        if action not in ('CLOSE','PROPOSE','DISPUTE','FINALIZE','VOID'): raise ValueError('ACTION')
        def apply(s):
            e=s['events'][event]; now=int(self.clock())
            if e['state']=='COMPLETED':
                if action in ('FINALIZE','VOID') and e['outcome']==('VOID' if action=='VOID' else outcome): return {'state':'COMPLETED','duplicate':True}
                raise ValueError('IMMUTABLE_COMPLETED_EVENT')
            if action=='CLOSE':
                if now<e['close'] or e['state']!='OPEN': raise ValueError('DEADLINE_OR_STATE')
                e['state']='PENDING_RESOLUTION'
            elif action=='PROPOSE':
                if now<e['close'] or now>e['resolve'] or e['state'] not in ('OPEN','PENDING_RESOLUTION','DISPUTED'): raise ValueError('DEADLINE_OR_STATE')
                if outcome not in ('YES','NO'): raise ValueError('BINARY_OUTCOME')
                text(evidence); e.update(state='FINAL_OUTCOME_PENDING_CONFIRMATION',outcome=outcome,evidence=evidence)
            elif action=='DISPUTE':
                if e['state']!='FINAL_OUTCOME_PENDING_CONFIRMATION': raise ValueError('STATE')
                text(evidence); e.update(state='DISPUTED',evidence=evidence)
            else:
                if consent!='CONFIRM SIMULATION SETTLEMENT': raise ValueError('EXPLICIT_CONSENT_REQUIRED')
                if action=='VOID':
                    text(evidence); e.update(outcome='VOID',evidence=evidence)
                elif now>e['resolve'] or e['state']!='FINAL_OUTCOME_PENDING_CONFIRMATION' or outcome!=e['outcome']:
                    raise ValueError('PROPOSED_RESULT_REQUIRED')
                e['state']='PAYOUT_RECONCILIATION'
                winners={p:b['amount'] for p,b in e['bets'].items() if b['side']==e['outcome']}
                if e['outcome']=='VOID' or not winners:
                    payouts={p:b['amount'] for p,b in e['bets'].items()}
                    if not winners: e['outcome']='VOID'
                else:
                    pool=sum(b['amount'] for b in e['bets'].values()); total=sum(winners.values())
                    payouts={p:pool*n//total for p,n in winners.items()}
                    # Integer remainder goes one unit at a time in scoped ID order.
                    remainder=pool-sum(payouts.values())
                    for p in sorted(payouts)[:remainder]: payouts[p]+=1
                e['payouts']=payouts
                for p,n in payouts.items(): s['participants'][p]['balance']+=n
                e['state']='COMPLETED'
            s['audit'].append(dict(event=event,action=action,time=now,outcome=e['outcome'],evidence=e['evidence']))
            return {'state':e['state'],'outcome':e['outcome'],'unit':UNIT}
        return self._transaction(apply)

    def view(self, credential):
        def apply(s):
            pid,p=self._participant(s,credential); events=[]
            for e in s['events'].values():
                item={k:e[k] for k in ('id','question','criteria','source','close','resolve','cancellation','authority','state','outcome','evidence')}
                if item['state']=='OPEN' and int(self.clock())>=e['close']: item['state']='CLOSED_PENDING_RESOLUTION'
                if item['state']!='COMPLETED' and int(self.clock())>e['resolve']: item['state']='RESOLUTION_OVERDUE_VOID_REQUIRED'
                item.update(my_participation=e['bets'].get(pid),my_payout=e['payouts'].get(pid,0),pooled_credits=sum(b['amount'] for b in e['bets'].values()))
                # Never return participant IDs or another person's side/stake.
                if item['my_participation']: item['my_participation']={k:v for k,v in item['my_participation'].items() if k!='participant'}
                events.append(item)
            return dict(unit=UNIT,balance=p['balance'],events=events,pc_mode_enabled=False,adjudication='LOCAL_AUTHENTICATED_OPERATOR_NOT_ORACLE',privacy='OPERATOR_SEES_CHOICES_AMOUNTS_AND_TIMING')
        return self._transaction(apply)
