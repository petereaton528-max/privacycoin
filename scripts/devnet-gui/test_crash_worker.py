"""TEST ONLY: fault injection into imported adapter, never a production command."""
from pathlib import Path
import os, signal, sys
from backend import Session,c,f,w,recovery_bundle

def kill():os.kill(os.getpid(),signal.SIGKILL)
home,port,stage,name,recipient=sys.argv[1:];home=Path(home);password=sys.stdin.buffer.readline().rstrip(b'\n')
if stage=='restore_before_publish':
    original=c.write_private
    def cut(*args,**kw):
        kw['fault']=lambda point:kill() if point=='before_publish' else None
        return original(*args,**kw)
    c.write_private=cut
    Session(home,int(port)).dispatch(dict(command='restore',name=name,backup='Fault-recovery',password=password.decode()))
else:
    wallet,_=recovery_bundle(home/'Fault-recovery.backup',password)
    c.save(home/(name+'.wallet'),wallet,password)
    s=Session(home,int(port));s.dispatch(dict(command='open',name=name,password=password.decode()));s.refresh()
    p=s.dispatch(dict(command='prepare',destination=recipient,amount=1000000,fee=188000,max_fee=500000))
    if stage=='unknown_before_sign':c.execute=lambda *args,**kw:kill()
    else:
        rpc=w.rpc
        def cut(port,cmd,**kw):
            if cmd=='submit_tx':
                if stage=='submitted_before_ack':rpc(port,cmd,**kw)
                kill()
            return rpc(port,cmd,**kw)
        w.rpc=cut
    s.dispatch(dict(command='confirm',token=p['token'],consent='CONFIRM'))
