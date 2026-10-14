"""Opt-in operator lifecycle. Configuration is offline; activation requires typing consent."""
from pathlib import Path
import argparse,hashlib,json,os,signal,subprocess,sys,time
import role
if __name__=='__main__':role.bootstrap()
from common import c,f,w,load_json,save_json,private_dir,call
from tor_runtime import OwnedTor,write_config
from tor_transport import onion_address
from launcher_host import child_parent_guard
import n2_tls
ROOT=Path(__file__).resolve().parents[3]

def configure(provider_config,runtime,binary,resource=True):
    v=role.config(provider_config,'provider');home=role.checked_path(str(runtime))
    with c.directory(Path(v['home'])):pass
    # Existing provider/node/control files are read only; never prepare home again.
    control=load_json(Path(v['home'])/'provider/control')
    binary=role.tor_binary(binary);binary_hash=hashlib.sha256(binary.read_bytes()).hexdigest()
    wanted=dict(version=1,provider_config=str(provider_config),provider_id=control['id'],tor=str(binary),tor_sha256=binary_hash,resource=resource)
    if home.exists():
        if load_json(home/'plan.json')!=wanted:raise ValueError('EXISTING_PLAN_CONFLICT')
        OwnedTor(binary,home/'tor/torrc.DISABLED').verify();return home/'plan.json'
    # Reserve fixed separate ports; none overlaps existing role ports.
    if {19510,19520,19530,19550,19501,19560}&{v[x] for x in ('node_rpc','node_p2p','provider_port','bridge_port','socks_port')}:raise ValueError('PORT_COLLISION')
    private_dir(home);private_dir(home/'tor');private_dir(home/'tor/p2p-onion')
    lines=[f'DataDirectory {home}/tor','DisableNetwork 1','RunAsDaemon 0','SafeLogging 1','SocksPort 127.0.0.1:19550','ControlPort 127.0.0.1:19530','CookieAuthentication 1',f'HiddenServiceDir {home}/tor/p2p-onion','HiddenServiceVersion 3','HiddenServicePort 80 127.0.0.1:19510']
    if resource:
        private_dir(home/'tor/resource-onion');lines += [f'HiddenServiceDir {home}/tor/resource-onion','HiddenServiceVersion 3','HiddenServicePort 80 127.0.0.1:19520']
    write_config(home/'tor/torrc.DISABLED',lines);OwnedTor(binary,home/'tor/torrc.DISABLED').verify();save_json(home/'plan.json',wanted)
    return home/'plan.json'

def verify(plan):
    f.fields(plan,'version provider_config provider_id tor tor_sha256 resource')
    if type(plan['version']) is not int or plan['version']!=1 or type(plan['resource']) is not bool:raise ValueError('PLAN_SCHEMA')
    v=role.config(Path(plan['provider_config']),'provider');binary=role.tor_binary(Path(plan['tor']))
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=plan['tor_sha256']:raise ValueError('TOR_CHANGED')
    if load_json(Path(v['home'])/'provider/control')['id']!=plan['provider_id']:raise ValueError('PROVIDER_CHANGED')
    return v,binary

def run(plan_file):
    home=plan_file.parent;plan=load_json(plan_file);v,binary=verify(plan)
    with c.lock(home/'operator'):
        # No arbitrary torrc or forwarding targets: reconstruct and compare exact disabled template.
        expected=[f'DataDirectory {home}/tor','DisableNetwork 1','RunAsDaemon 0','SafeLogging 1','SocksPort 127.0.0.1:19550','ControlPort 127.0.0.1:19530','CookieAuthentication 1',f'HiddenServiceDir {home}/tor/p2p-onion','HiddenServiceVersion 3','HiddenServicePort 80 127.0.0.1:19510']
        if plan['resource']:expected += [f'HiddenServiceDir {home}/tor/resource-onion','HiddenServiceVersion 3','HiddenServicePort 80 127.0.0.1:19520']
        if c.read_private(home/'tor/torrc.DISABLED')!=('\n'.join(expected)+'\n').encode():raise ValueError('TOR_CONFIG_CHANGED')
        role.free_ports([19510,19520,19530,19550])
        health=call(v['provider_port'],'health')
        if health.get('provider')!=plan['provider_id'] or health.get('devnet_only') is not True:raise ValueError('LOCAL_PROVIDER_NOT_READY')
        if w.rpc(v['node_rpc'],'status')['genesis']!=w.GENESIS:raise ValueError('NODE_NETWORK')
        configs=[('p2p',n2_tls.channel(home/'tls-p2p','acceptor',19510,v['node_p2p'],purpose='p2p'))]
        if plan['resource']:configs.append(('resource',n2_tls.channel(home/'tls-resource','acceptor',19520,v['provider_port'],purpose='resource')))
        print('WARNING: public Tor may expose the configured onion endpoints. RPC/admin are not mapped. This does not authorize payments.')
        if input('Type ACTIVATE PUBLIC ONION to authorize this foreground session: ')!='ACTIVATE PUBLIC ONION':raise ValueError('NO_ACTIVATION_AUTHORIZATION')
        children=[];tor=None
        try:
            for purpose,config in configs:
                path=home/(purpose+'-server.json');save_json(path,config,replace=path.exists())
                args=[sys.executable,str(Path(__file__).with_name('p2p_channel.py')),'--config',str(path)] if purpose=='p2p' else [sys.executable,str(Path(__file__).with_name('n2_transport.py')),'resource-server','--config',str(path),'--hostname-file',str(home/'tor/resource-onion/hostname')]
                parent=os.getpid();children.append(subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent)))
            # Listener checks are local only, not remote readiness claims.
            end=time.monotonic()+10
            while True:
                if any(p.poll() is not None for p in children):raise ValueError('TLS_CHILD_FAILED')
                try:
                    import socket
                    for _,config in configs:
                        with socket.create_connection(('127.0.0.1',config['listen_port']),timeout=.2):pass
                    break
                except OSError:
                    if time.monotonic()>=end:raise ValueError('TLS_LISTENER_TIMEOUT')
                    time.sleep(.05)
            active=home/'tor/torrc.ACTIVE';write_config(active,[line if line!='DisableNetwork 1' else 'DisableNetwork 0' for line in expected])
            tor=OwnedTor(binary,active);tor.start();end=time.monotonic()+180
            while time.monotonic()<end:
                if any(p.poll() is not None for p in children) or tor.process.poll() is not None:raise ValueError('OWNED_SERVICE_EXITED')
                try:
                    if b'PROGRESS=100' in tor.control('GETINFO status/bootstrap-phase'):break
                except (OSError,ValueError):pass
                time.sleep(.3)
            else:raise ValueError('TOR_BOOTSTRAP_TIMEOUT')
            endpoint=dict(version=1,provider=plan['provider_id'],devnet_only=True,p2p_onion=onion_address(c.read_private(home/'tor/p2p-onion/hostname').decode().strip()))
            if plan['resource']:endpoint['resource_onion']=onion_address(c.read_private(home/'tor/resource-onion/hostname').decode().strip())
            save_json(home/'public-endpoints.json',endpoint,replace=(home/'public-endpoints.json').exists())
            print('TOR_BOOTSTRAPPED; public endpoint file written. Remote protocol/chain readiness remains unverified.')
            while input('EXIT stops only this owned Tor/TLS session: ')!='EXIT':
                if any(p.poll() is not None for p in children) or tor.process.poll() is not None:raise ValueError('OWNED_SERVICE_EXITED')
        finally:
            if tor:tor.close()
            for p in reversed(children):
                if p.poll() is None:
                    p.terminate()
                    try:p.wait(timeout=5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
            write_config(home/'tor/torrc.ACTIVE',[line for line in expected]) # leave disabled on disk

def links(plan_file,peer_public,p2p_cert_home,resource_cert_home=None):
    plan=load_json(plan_file);v,_=verify(plan);home=plan_file.parent;public=role.checked_path(str(peer_public))
    if not public.is_file() or public.stat().st_size>16384:raise ValueError('ENDPOINT_BOUND')
    endpoint=f.decode(public.read_bytes())
    if endpoint.get('devnet_only') is not True or endpoint.get('version')!=1:raise ValueError('ENDPOINT')
    p2p=onion_address(endpoint['p2p_onion'])
    outputs={'p2p-client.json':n2_tls.channel(p2p_cert_home,'connector',19501,80,p2p,19550,purpose='p2p')}
    # New alias configuration, same stores; never rewrite existing provider.json.
    outputs['provider-linked.json']=dict(v,peer_port=19501)
    if resource_cert_home:
        resource=onion_address(endpoint['resource_onion'])
        if resource==p2p:raise ValueError('SEPARATE_ENDPOINTS_REQUIRED')
        outputs['resource-client.json']=n2_tls.channel(resource_cert_home,'connector',19560,80,resource,19550,purpose='resource')
    # Validate all conflicts before writing. Repeated offline configuration is safe.
    for name,value in outputs.items():
        if (home/name).exists() and load_json(home/name)!=value:raise ValueError('EXISTING_LINK_CONFLICT')
    for name,value in outputs.items():
        if not (home/name).exists():save_json(home/name,value)
    print('New connector configs created. Existing node/provider config unchanged. No connection or spending started.')

def run_links(plan_file):
    home=plan_file.parent;plan=load_json(plan_file);_,binary=verify(plan);children=[]
    tor=OwnedTor(binary,home/'tor/torrc.ACTIVE')
    if b'PROGRESS=100' not in tor.control('GETINFO status/bootstrap-phase'):raise ValueError('TOR_NOT_READY')
    with c.lock(home/'links'):
        configs=[]
        import p2p_channel as pc
        for purpose in ('p2p','resource'):
            path=home/(purpose+'-client.json')
            if not path.exists():continue
            v=pc.validate(load_json(path));onion_address(v['endpoint'])
            if v['role']!='connector' or v['socks_port']!=19550 or v['target_port']!=80 or v['listen_port']!={'p2p':19501,'resource':19560}[purpose]:raise ValueError('TOR_ONLY_LINK')
            configs.append((purpose,path))
        if not configs:raise ValueError('NO_LINKS')
        if input('Type CONNECT VIA TOR to start these pinned links: ')!='CONNECT VIA TOR':raise ValueError('NO_CONSENT')
        try:
            for purpose,path in configs:
                args=[sys.executable,str(Path(__file__).with_name('p2p_channel.py')),'--config',str(path)] if purpose=='p2p' else [sys.executable,str(Path(__file__).with_name('n2_transport.py')),'resource-proxy','--config',str(path)]
                parent=os.getpid();children.append(subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent)))
            print('Owned link processes started; remote readiness must be verified separately. No payment created.')
            while input('EXIT stops only owned connectors: ')!='EXIT':
                if any(p.poll() is not None for p in children):raise ValueError('LINK_PROCESS_FAILED')
        finally:
            for p in children:
                if p.poll() is None:
                    p.terminate()
                    try:p.wait(timeout=5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['configure-existing','run','links','run-links']);p.add_argument('--provider-config',type=Path);p.add_argument('--runtime',type=Path);p.add_argument('--tor',type=Path);p.add_argument('--p2p-only',action='store_true');p.add_argument('--plan',type=Path);p.add_argument('--peer-public',type=Path);p.add_argument('--p2p-cert-home',type=Path);p.add_argument('--resource-cert-home',type=Path);a=p.parse_args();c.harden()
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    if a.action=='configure-existing':print('DISABLED_PLAN',configure(a.provider_config,a.runtime,a.tor,not a.p2p_only))
    elif a.action=='run':run(a.plan)
    elif a.action=='links':links(a.plan,a.peer_public,a.p2p_cert_home,a.resource_cert_home)
    else:run_links(a.plan)
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt,EOFError):raise SystemExit('N2 operator stopped/rejected; no automatic payment, refund or unrelated-process termination. Private details withheld.')
