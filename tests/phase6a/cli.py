"""Exercise the actual CLI in fresh processes; never publish private streams."""
from pathlib import Path
import importlib.util,json,os,sys,subprocess,tempfile,shutil
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('six_gates',ROOT/'tests/phase6a/gates.py');g=importlib.util.module_from_spec(spec);sys.modules['six_gates']=g;spec.loader.exec_module(g)
c=g.c;f=g.f;w=g.w;h=g.h;RUN=g.RUN;OUT=g.OUT;checks=[];secret=[]
def check(name,condition):
    assert condition,name;checks.append(name);print('PASS',name,flush=True)
def call(command,wallet,password,expected=0,stdin='',**kw):
    argv=[sys.executable,str(ROOT/'scripts/phase6a/privacycoin-wallet'),command,'--wallet',str(wallet),'--password-file',str(password)]
    for key,value in kw.items():argv.extend(['--'+key.replace('_','-'),str(value)])
    p=subprocess.run(argv,input=stdin.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    check('CLI '+command+' exit '+str(expected),p.returncode==expected)
    for value in secret:assert value not in p.stdout+p.stderr and value.hex().encode() not in p.stdout+p.stderr,'secret in CLI stream'
    return p
def main():
    assert not (OUT/'cli.json').exists()
    with tempfile.TemporaryDirectory(prefix='privacycoin-6a-cli-') as d:
        base=Path(d);base.chmod(0o700);pw=f.read_private(RUN/'fixture.password');secret.append(pw);pf=base/'password';c.write_private(pf,pw)
        wallet=f.load(RUN/'A.wallet',pw)
        for key in ('seed','view'):secret.extend([wallet[key].encode(),bytes.fromhex(wallet[key])])
        for key in f.crypto('derive',wallet['seed'])[:2]:secret.extend([key.encode(),bytes.fromhex(key)])
        wf=base/'A.wallet';c.save(wf,wallet,pw)
        shutil.copytree(RUN/'node',base/'node');node=h.Node(base,'node');node.start()
        try:
            made=base/'new.wallet';call('create',made,pf)
            check('CLI creation entropy generates different identity',f.wallet_id(c.load(made,pw))!=f.wallet_id(wallet))
            opened=call('open',wf,pf);check('opening never presents cached balance',json.loads(opened.stdout)['balance'] is None)
            backup=base/'A.wallet-backup';call('backup',wf,pf,file=backup)
            call('backup',wf,pf,expected=1,file=backup)
            restored=base/'restored.wallet';call('restore',restored,pf,file=backup)
            call('restore',restored,pf,expected=1,file=backup)
            check('CLI restore same authority and key hierarchy',c.load(restored,pw)==wallet)
            report=call('restore-drill',wf,pf,file=backup,restore_wallet=base/'drill.wallet',rpc_port=node.rpc)
            check('CLI drill report has only declared public scope',set(json.loads(report.stdout))=={'result','height','tip','profile','scope','report_contains_secrets'})
            for cmd in ('sync','rescan','balance'):
                p=call(cmd,wf,pf,rpc_port=node.rpc);q=json.loads(p.stdout)
                check('CLI '+cmd+' qualified trust and mature/immature balances',q['global_freshness']=='UNKNOWN' and q['locked_coinbase']>0 and q['spendable']>0)
            # Cache authentication failure cannot quietly revert to a verified balance.
            cache=Path(str(wf)+'.phase6a-cache');original=cache.read_bytes();cache.write_bytes(original[:-12])
            bad=call('balance',wf,pf,expected=1,rpc_port=node.rpc)
            check('corrupt cache publishes no balance',not bad.stdout)
            cache.write_bytes(original)
            dest=f.address(f.load(RUN/'B.wallet',pw),0)
            before=node.call('pool')['transactions']
            call('send',wf,pf,expected=1,stdin='NO\n',rpc_port=node.rpc,destination=dest,amount=123456789,fee=1000000,max_fee=1000000)
            check('CLI rejected consent no pool mutation',node.call('pool')['transactions']==before)
            call('send',wf,pf,expected=1,stdin='CONFIRM\n',rpc_port=node.rpc,destination=dest,amount=1,fee=1000001,max_fee=1000000)
            check('CLI fee cap no pool mutation',node.call('pool')['transactions']==before)
            approved=call('send',wf,pf,stdin='CONFIRM\n',rpc_port=node.rpc,destination=dest,amount=123456789,fee=1000000,max_fee=1000000)
            check('CLI explicit consent submits one private transaction',len(node.call('pool')['transactions'])==len(before)+1 and b'"submitted": true' in approved.stdout)
            vp=os.urandom(32).hex().encode();secret.append(vp);vpf=base/'view-password';c.write_private(vpf,vp)
            cap=base/'incoming.capability';call('view-export',wf,pf,file=cap,export_password_file=vpf)
            vf=base/'incoming.wallet';call('view-import',vf,vpf,file=cap)
            vb=json.loads(call('balance',vf,vpf,rpc_port=node.rpc).stdout)
            check('CLI incoming view unknown spent and outgoing',vb['spendable'] is None and vb['spent_status']=='UNKNOWN' and vb['outgoing_status']=='UNKNOWN')
            call('send',vf,vpf,expected=1,stdin='CONFIRM\n',rpc_port=node.rpc,destination=dest,amount=1,fee=1000000,max_fee=1000000)
            wrong=base/'wrong-password';c.write_private(wrong,os.urandom(32));call('open',wf,wrong,expected=1)
            malformed=base/'malformed.wallet';c.write_private(malformed,b'{');call('open',malformed,pf,expected=1)
        finally:node.stop(crash=True)
    raw=f.canonical(dict(result='PASS',checks=checks,check_count=len(checks),secret_stream_audit='Actual generated seed/view/derived-spend/password raw and hex encodings absent in captured stdout/stderr',independent_drills=False))
    for value in secret:assert value not in raw and value.hex().encode() not in raw
    (OUT/'cli.json').write_bytes(raw+b'\n')
if __name__=='__main__':main()
