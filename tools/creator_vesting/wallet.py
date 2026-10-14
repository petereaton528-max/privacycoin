"""Explicit offline draft wallet adapter; no production selector or RPC.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
from .policy import schedule
class CandidateWallet:
    def __init__(self,phase4,helper,binding,interval=65700):
        if interval not in (65700,80):raise ValueError('OFFLINE_POLICY_INTERVAL')
        self.phase4=phase4;self.helper=helper;self.binding=binding;self.interval=interval
    def scan(self,wallet,state):
        if not state['chain'] or state['chain'][0]['height']!=0 or not state['chain'][0]['coinbase']:raise ValueError('GENESIS_HISTORY_REQUIRED')
        # Reuse the native scanner in bounded batches. Genesis retains 17
        # outputs; all ordinary transactions retain the existing 16-output cap.
        result=dict(owned=[],eligible=[],record_outputs=[],scanned_outputs=0,scan_ms=0,undecodable_owned_outputs=0)
        spent=set(state['images']);reserved=set(state['pool_images']);batch=[];size=0;offset=0
        def consume():
            nonlocal offset
            local=dict(chain=batch,images=[],pool_images=[],height=state['height'])
            part=self.phase4.helper(dict(op='scan',draft_genesis=self.binding.genesis,**self.phase4.request(wallet,local)),self.helper)
            if len(part['record_outputs'])!=len(batch) or sum(part['record_outputs'])!=part['scanned_outputs']:raise ValueError('DRAFT_BATCH_COMPLETENESS')
            for item in part['owned']:
                item['global_index']+=offset
                if wallet['authority']=='full':item['spent']=item['image'] in spent;item['reserved']=item['image'] in reserved
            result['owned'].extend(part['owned']);result['eligible'].extend(i+offset for i in part['eligible']);result['record_outputs'].extend(part['record_outputs'])
            for key in ('scanned_outputs','scan_ms','undecodable_owned_outputs'):result[key]+=part[key]
            offset+=part['scanned_outputs']
        for record in state['chain']:
            if 'global_offset' in record:raise ValueError('UNEXPECTED_SCAN_OFFSET')
            n=len(self.phase4.foundation.canonical(record))
            if n>1024*1024:raise ValueError('DRAFT_RECORD_BOUND')
            if batch and (len(batch)>=256 or size+n>1024*1024):consume();batch=[];size=0
            batch.append(record);size+=n
        if batch:consume()
        counts=result['record_outputs']
        if len(counts)!=len(state['chain']) or counts[0]!=17 or sum(counts)!=result['scanned_outputs']:raise ValueError('DRAFT_INDEX_COMPLETENESS')
        if any(n>16 for n in counts[1:]):raise ValueError('ORDINARY_OUTPUT_LIMIT')
        expected={x['index']:x for x in schedule()}
        for x in result['owned']:
            if x['height']==0:
                tranche=expected[x['output_index']]
                if x['amount']!=tranche['atomic'] or x['unlock']!=x['output_index']*self.interval:raise ValueError('DRAFT_VESTING_SCAN')
        # Conservative displayed balance: next-block eligibility is separate.
        owned=[x for x in result['owned'] if not x['spent'] and not x['pending']]
        result['available']=sum(x['amount'] for x in owned if x['unlock']<=state['height'] and not x['reserved'])
        result['locked']=sum(x['amount'] for x in owned if x['unlock']>state['height'])
        return result
