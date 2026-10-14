"""Pinned local native-node adapter. No external socket or signing authority.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import json,socket,struct,time
from .candidate_profile import validate,identity
from .rpc import unique
class Node:
    def __init__(self,port,profile):
        if type(port) is not int or not 1024<=port<=65535:raise ValueError('LOCAL_NODE_PORT')
        self.port=port;self.profile=validate(profile);self.identity=identity(profile)
        self.rpc('status')
    def rpc(self,command,**fields):
        network,genesis,profile=self.identity
        raw=json.dumps(dict(network=network,genesis=genesis,profile=profile,command=command,**fields),separators=(',',':')).encode()
        if len(raw)>1048576:raise ValueError('RPC_REQUEST_BOUND')
        end=time.monotonic()+30
        def read(s,count):
            data=bytearray()
            while len(data)<count:
                remaining=end-time.monotonic()
                if remaining<=0:raise TimeoutError('CANDIDATE_RPC_DEADLINE')
                s.settimeout(remaining);chunk=s.recv(count-len(data))
                if not chunk:raise ValueError('RPC_EOF')
                data.extend(chunk)
            return bytes(data)
        magic=b'PrivacyCoinRPC04'
        with socket.create_connection(('127.0.0.1',self.port),timeout=3) as s:
            s.sendall(magic+struct.pack('>I',len(raw))+raw)
            header=read(s,20);size=int.from_bytes(header[16:],'big')
            if header[:16]!=magic or not 0<size<=1048576:raise ValueError('RPC_FRAME')
            result=json.loads(read(s,size),object_pairs_hook=unique)
        if not isinstance(result,dict) or tuple(result.get(k) for k in ('network','genesis','profile'))!=self.identity or 'error' in result:raise ValueError('CANDIDATE_RPC_REJECTED')
        return result
    def history(self):
        snapshot=self.rpc('snapshot_id');context={k:snapshot[k] for k in ('tip','revision','instance')}
        key=tuple(context.values())
        if getattr(self,'_history_key',None)==key:return self._history
        from src.phase4.wallet import ChainRecords
        state=dict(height=snapshot['height'],chain=ChainRecords(),pool=[],images=[],pool_images=[],orphan_images=[])
        offset=0
        while offset<=state['height']:
            page=self.rpc('history',offset=offset,count=32,metadata_only=1,**context)
            if page['next']<=offset:raise ValueError('HISTORY_CURSOR')
            for r in page['records']:
                state['chain'].extend([{k:r[k] for k in ('transaction','height','coinbase')}])
                state['images'].extend(r['images'])
            if offset==0:state['orphan_images']=page['orphan_images']
            offset=page['next']
        for offset in range(0,32,8):
            entries=self.rpc('pool_page',offset=offset,count=8,**context)['entries']
            state['pool'].extend({k:r[k] for k in ('transaction','height','coinbase')} for r in entries)
            state['pool_images'].extend(image for r in entries for image in r['images'])
            if len(entries)<8:break
        self._history_key=key;self._history=state
        return state
    def call(self,op,**q):
        if op=='policy':return dict(interval=65700,total=159627169409884823,liquid=15962716940988482,commitment=self.profile['commitment'])
        if op=='open':
            if q['block']!=self.profile['block'] or q['hash']!=self.profile['genesis']:raise ValueError('NODE_GENESIS_MISMATCH')
            return self.rpc('status')
        if op=='history':return self.history()
        if op=='pool':return dict(transactions=[r['transaction'] for r in self.history()['pool']])
        if op=='status':return self.rpc('status')
        if op=='payment':return self.rpc('submit_tx',transaction=q['transaction'])
        if op=='mine':return self.rpc('mine',reward_key=q['P'],R=q['R'],timestamp=q.get('timestamp',0))
        if op=='mine_async':
            if q.get('cancel') is not None and q['cancel'].is_set():return dict(stopped=True)
            initial=self.rpc('status');before=initial['mined'];began=time.monotonic();job=self.rpc('mine_private',reward_key=q['P'],R=q['R'])['job'];end=began+605
            try:
                while True:
                    if q.get('cancel') is not None and q['cancel'].is_set():
                        self.rpc('stop_mining',job=job);return dict(stopped=True)
                    state=self.rpc('status')
                    if state['mining_job']!=job:raise ValueError('MINING_JOB_CHANGED')
                    if q.get('progress'):q['progress'](dict(state,hashrate=(state['mining_hashes']-initial['mining_hashes'])/max(.001,time.monotonic()-began)))
                    if not state['mining']:
                        if state['mining_error']:raise ValueError('NATIVE_MINING_FAILED')
                        return dict(mined=state['mined']-before,height=state['height'],tip=state['tip'])
                    if time.monotonic()>=end:raise TimeoutError('BOUNDED_MINING_DEADLINE')
                    time.sleep(.1)
            finally:
                try:self.rpc('stop_mining',job=job)
                except (ValueError,OSError):pass # Never cancel a different job.
        raise ValueError('CANDIDATE_NODE_OPERATION_DENIED')
    def close(self):
        self._history_key=None;self._history=None # Never kills an independent node.
