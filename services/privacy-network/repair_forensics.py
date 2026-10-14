"""Read-only original-store investigation; node opens ONLY a private chain copy."""
from common import *
from runtime import OwnedNode
import sqlite3,shutil,time,datetime
QID='2e6c5a37d014c23c079afb8d17ab89db7b7af6ff608899c3da4c2779854ea8c1'
OUT=ROOT/'docs/evidence/privacy-network-repair'
def inventory(home):
    return {str(p.relative_to(home)):digest(p.read_bytes()) for p in home.rglob('*') if p.is_file() and not p.is_symlink()}
def main():
    c.harden();OUT.mkdir(exist_ok=True);destination=OUT/('original-time-details.json' if '--details' in sys.argv else 'original-forensics.json');assert not destination.exists()
    original=Path.home()/'.local/share/privacycoin-network-v01';before=inventory(original)
    # Refuse a potentially changing live original rather than stop user processes.
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name)==os.getpid():continue
        try:args=(p/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if args and b'privacycoin-hardened-devnet' in args[0]:assert str(original/'node').encode() not in args,'Original node is running; read-only snapshot requires stable shutdown'
    base=private_dir(NATIVE/'build/privacy-network-repair'/('forensics-'+str(time.time_ns())));private_dir(base/'node');shutil.copyfile(original/'node/data.mdb',base/'node/data.mdb');os.chmod(base/'node/data.mdb',0o600)
    db=sqlite3.connect('file:'+str(original/'provider-0/state.sqlite')+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
    try:row=dict(db.execute('SELECT * FROM quotes WHERE id=?',(QID,)).fetchone())
    finally:db.close()
    record=load_json(original/'client-0'/(QID+'.intent'));config=load_json(original/'runtime-config');control=load_json(original/'provider-0/control')
    wallet=f.open_sealed(row['wallet'],control['password'].encode(),'resource-invoice-wallet')
    journal=f.open_sealed(c.read_private(original/'alice-wallets/DisposableAlice.wallet.gui-state'),config['password'].encode(),'gui-pilot-state')
    attempts=[a for a in journal['attempts'] if a['destination']==row['recipient'] and a['amount']==row['price']]
    node=OwnedNode(base,'node')
    try:
        node.start();state,scan,balance,work=c.observe(wallet,node.rpc)
        matching=[x for x in scan['owned'] if not x['coinbase'] and x['address_index']==0 and x['amount']==row['price']]
        chain=node.call('chain')['chain'];blocks=[]
        for blockid in chain:
            b=node.call('get_block',hash=blockid)
            if b['height']>=79:
                raw=bytes.fromhex(b['block']);offset=0;values=[]
                for _ in range(3):
                    value=0;shift=0
                    while True:
                        byte=raw[offset];offset+=1;value|=(byte&127)<<shift
                        if byte<128:break
                        shift+=7;assert shift<64
                    values.append(value)
                blocks.append(dict(height=b['height'],timestamp=values[2],hash=b['hash']))
        report=dict(result='READ_ONLY_FORENSICS',quote=QID,observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),quote_deadline_unix=row['expires'],quote_retention_seconds=row['retention'],quote_price_atomic=row['price'],quote_cipher_quota=row['quota'],provider_persisted_state=row['state'],provider_accepted_at=row['accepted'],provider_pinned_transaction=row['tx'],provider_has_object=row['blob'] is not None,provider_saved_tip=row['tip'],client_payment_state=record['payment'],client_intent_mtime_unix=(original/'client-0'/(QID+'.intent')).stat().st_mtime,original_matching_attempts=[{k:a[k] for k in ('created','status','transaction_id','amount','fee')} for a in attempts],snapshot_height=state['height'],snapshot_tip=state['tip'],snapshot_work=work,receiver_observed_outputs=[{k:x[k] for k in ('transaction','amount','height','unlock','pending','spent')}|dict(local_confirmations=0 if x['pending'] else state['height']-x['height']+1,unlocked=x['unlock']<=state['height']+1) for x in matching],receiver_balance_atomic=balance['balance'],recent_blocks=blocks,global_freshness='UNKNOWN',scope='Original files read only, secret values in memory only. Stable original chain copied privately; unchanged pinned node revalidated ONLY copy. No original payment, mining, wallet write, provider migration or entitlement mutation. Wallet ownership scan independently checks amount. Public whitelist excludes keys/passwords/capabilities.')
    finally:node.stop()
    assert inventory(original)==before,'Original files changed during forensics'
    report['node_data_mtime_unix']=(original/'node/data.mdb').stat().st_mtime
    report['provider_db_mtime_unix']=(original/'provider-0/state.sqlite').stat().st_mtime
    report['retained_plain_bytes']=load_json(original/'client-0'/(QID+'.upload'))['bundle']['plain_bytes']
    report['original_files_byte_unchanged']=len(before);report['original_store_fingerprint']=digest(f.canonical(before))
    raw=f.canonical(report)
    for secret in [config['password'],control['password'],control['admin'],record['quote']['owner'],record['quote']['retriever'],wallet['seed'],wallet['view']]:assert secret.encode() not in raw
    destination.write_bytes(raw+b'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
