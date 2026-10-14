"""Real valid future block timestamps cannot expire a wall-clock quotation."""
from common import *
from runtime import Runtime
from client import retrieve
import time
if __name__=='__main__':
    r=None;checks=[];out=ROOT/'docs/evidence/privacy-network-repair'/('clock-'+str(time.time_ns())+'.json')
    try:
        r=Runtime(NATIVE/'build/privacy-network-repair'/('clock-'+str(time.time_ns())));r.mine(80);a=r.client(0);q=a.quote(117);cipher,bundle=a.encrypt(q['id'],b't'*117);r.session.refresh();a.pay(q['id'],r.session,'CONFIRM')
        stamp=int(q['expires'])+120
        for _ in range(10):r.node.mine(r.address,stamp);stamp+=120
        state=a.status(q['id']);assert time.time()<q['expires'] and stamp-120>q['expires'];checks.append('real consensus-valid accelerated block times exceed quotation deadline while wall clock remains before it')
        assert state['state']=='CONFIRMED_LOCAL' and state['quote_state']=='OPEN';checks.append('future chain timestamps neither expire offer nor replace timely provider witness')
        a.upload(q['id']);assert retrieve(bundle)==b't'*117;checks.append('real future-timestamp paid entitlement stores and retrieves exact plaintext')
        report=dict(result='PASS_CLOCK_SEPARATION',passed=len(checks),checks=checks,quote_wall_deadline=q['expires'],last_block_timestamp=stamp-120,scope='Actual pinned Devnet transactions and ten valid future-dated blocks within unchanged 7200s consensus allowance. Only new isolated fixture. No consensus modification or wall-clock manipulation.')
    finally:
        if r:r.close()
    out.write_bytes(f.canonical(report)+b'\n');print(report['result'],len(checks),out.name)
