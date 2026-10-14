"""Local role simulation: two separate provider/node stores, no real-host claim."""
from pathlib import Path
import json,os,signal,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
import role
role.bootstrap()
from common import *
from launcher_host import child_parent_guard

def main():
    c.harden();base=private_dir(NATIVE/'build/privacycoin-n2-preparation'/('roles-'+str(time.time_ns())));children=[];checks=[];metrics=[];result='FAIL';started=time.monotonic()
    def check(name,value=True):assert value,name;checks.append(name)
    def start(config):
        parent=os.getpid();p=subprocess.Popen([sys.executable,str(ROOT/'deploy/n2/common/role.py'),'provider','--config',str(config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent));children.append(p)
        import selectors
        sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ)
        t=time.monotonic()
        try:
            if not sel.select(110):raise ValueError('OWNED_ROLE_TIMEOUT')
            row=f.decode(p.stdout.readline());check('actual local provider readiness',row['state']=='LOCAL_PROVIDER_READY' and row['public_onion'] is False);metrics.append(dict(operation='role_start',ms=(time.monotonic()-t)*1000))
            descendants={p.pid};samples=[]
            for _ in range(3):
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit():continue
                    try:
                        raw=(proc/'stat').read_text().rsplit(')',1)[1].split()
                        if int(raw[1]) in descendants:descendants.add(int(proc.name))
                    except (OSError,ValueError):pass
            for pid in sorted(descendants):
                try:
                    raw=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split();samples.append(dict(pid=pid,rss_mib=int(raw[21])*os.sysconf('SC_PAGE_SIZE')/1024**2,cpu_seconds=(int(raw[11])+int(raw[12]))/os.sysconf('SC_CLK_TCK')))
                except (OSError,ValueError):pass
            metrics.append(dict(operation='owned_role_resource_snapshot',processes=samples));return p,row
        finally:sel.close()
    try:
        configs=[]
        for i in range(2):
            home=private_dir(base/('privacycoin-n2-provider-'+str(i)));ports=[role_port() for _ in range(5)]
            cfg=dict(version=1,devnet_only=True,role='provider',home=str(home),node_rpc=ports[0],node_p2p=ports[1],provider_port=ports[2],bridge_port=ports[3],socks_port=ports[4],peer_port=None)
            path=home/'provider.json';save_json(path,cfg);configs.append((path,cfg))
        A,a=start(configs[0][0]);B,b=start(configs[1][0]);check('independent identities',a['provider']!=b['provider'])
        check('separate node DBs',all((Path(cfg['home'])/'node').is_dir() for _,cfg in configs));check('no shared observation source configured',a['chain_information_sources']==b['chain_information_sources']=='NONE')
        duplicate=subprocess.run([sys.executable,str(ROOT/'deploy/n2/common/role.py'),'provider','--config',str(configs[0][0]),'--once'],capture_output=True,timeout=10);check('duplicate owned role rejected',duplicate.returncode!=0)
        before=call(configs[1][1]['provider_port'],'health')['provider']
        A.communicate(b'EXIT\n',timeout=20);check('owned role exits cleanly',A.returncode==0)
        check('provider B survives A shutdown',call(configs[1][1]['provider_port'],'health')['provider']==before)
        A,a2=start(configs[0][0]);check('restart identity persistence',a2['provider']==a['provider'])
        control=load_json(Path(configs[0][1]['home'])/'provider/control');q=call(configs[0][1]['provider_port'],'quote',control['admin'],quota=117)
        state=call(configs[0][1]['provider_port'],'status',q['owner'],quote=q['id']);check('unpaid quote never gets confirmed entitlement',state['state']!='CONFIRMED_LOCAL')
        A.communicate(b'EXIT\n',timeout=20);A,a3=start(configs[0][0]);control=load_json(Path(configs[0][1]['home'])/'provider/control')
        state=call(configs[0][1]['provider_port'],'status',q['owner'],quote=q['id']);check('unpaid quote survives restart without entitlement',state['state']!='CONFIRMED_LOCAL')
        check('private provider DB permissions',(Path(configs[0][1]['home'])/'provider/state.sqlite').stat().st_mode&0o077==0)
        result='PASS_LOCAL_ROLE_SIMULATION'
    finally:
        for p in reversed(children):
            if p.poll() is None:
                try:p.communicate(b'EXIT\n',timeout=20)
                except (subprocess.TimeoutExpired,BrokenPipeError):p.terminate();p.wait(timeout=15)
        report=dict(result=result,scope='LOCAL ROLE SIMULATION; no Tor activation, payment, mining or second physical host',checks=checks,metrics=metrics,seconds=time.monotonic()-started,private_fixture=str(base),owned_roles_remaining=sum(p.poll() is None for p in children))
        (ROOT/'docs/evidence/privacy-network-n2'/('roles-'+str(time.time_ns())+'.json')).write_text(json.dumps(report,indent=2))
    if result!='PASS_LOCAL_ROLE_SIMULATION':sys.exit(1)
def role_port():
    import socket
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
if __name__=='__main__':main()
