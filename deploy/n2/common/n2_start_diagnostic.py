"""Additive diagnostic operator; old source/build manifests and stores untouched."""
from pathlib import Path
import argparse,signal,socket,subprocess,sys,time,select,os
import role
if __name__=='__main__':role.bootstrap()
import n2_operator as base
from common import c,w,load_json,save_json
from tor_runtime import write_config
from tor_transport import onion_address
from launcher_host import child_parent_guard
from n2_tor_diagnostics import Diagnostics,DiagnosticTor,Failure,children_alive,wait_bootstrap
from n2_upstream_socks5 import Policy,ProxyFailure,UpstreamTor

def template(home,resource):
    lines=[f'DataDirectory {home}/tor','DisableNetwork 1','RunAsDaemon 0','SafeLogging 1','SocksPort 127.0.0.1:19550','ControlPort 127.0.0.1:19530','CookieAuthentication 1',f'HiddenServiceDir {home}/tor/p2p-onion','HiddenServiceVersion 3','HiddenServicePort 80 127.0.0.1:19510']
    if resource:lines += [f'HiddenServiceDir {home}/tor/resource-onion','HiddenServiceVersion 3','HiddenServicePort 80 127.0.0.1:19520']
    return lines

def foreground(tor,children,diag,policy=None):
    print('EXIT stops only this owned Tor/TLS session.',flush=True)
    while True:
        if policy:policy.check()
        children_alive(children,diag)
        if tor.process.poll() is not None:
            diag.event('TOR_PROCESS_EXIT',exit_code=tor.process.poll());raise Failure('TOR_PROCESS_EXIT')
        if select.select([sys.stdin],[],[],.5)[0]:
            value=sys.stdin.readline()
            if not value or value.strip()=='EXIT':return

def run(plan_file,check_only=False,upstream_socks5=None):
    home=role.checked_path(str(plan_file.parent));diag=Diagnostics(home);children=[];tor=None;activated=False;result='PREFLIGHT_FAILED'
    try:
        with c.lock(home/'operator'):
            plan=load_json(plan_file);v,binary=base.verify(plan);expected=template(home,plan['resource'])
            if c.read_private(home/'tor/torrc.DISABLED')!=('\n'.join(expected)+'\n').encode():raise Failure('PREFLIGHT_FAILED')
            policy=None;active=home/'tor/torrc.ACTIVE';session_expected=expected
            if upstream_socks5 is not None:
                forbidden=[value for key,value in v.items() if key.endswith(('_port','_rpc','_p2p')) and type(value) is int]
                policy=Policy(upstream_socks5,diag,forbidden);policy.check(force=True)
                session_expected=policy.lines(expected)
                active=home/'tor'/('torrc.UPSTREAM.'+str(time.time_ns()))
                write_config(active,session_expected)
            role.free_ports([19510,19520,19530,19550])
            health=base.call(v['provider_port'],'health')
            if health.get('provider')!=plan['provider_id'] or health.get('devnet_only') is not True or w.rpc(v['node_rpc'],'status')['genesis']!=w.GENESIS:raise Failure('PREFLIGHT_FAILED')
            try:
                configs=[('p2p',base.n2_tls.channel(home/'tls-p2p','acceptor',19510,v['node_p2p'],purpose='p2p'))]
                if plan['resource']:configs.append(('resource',base.n2_tls.channel(home/'tls-resource','acceptor',19520,v['provider_port'],purpose='resource')))
                for purpose,_ in configs:base.n2_tls.verify_identity(home/('tls-'+purpose),purpose)
            except (ValueError,OSError,subprocess.SubprocessError):raise Failure('TLS_CONFIGURATION_FAILED') from None
            if check_only:
                DiagnosticTor(binary,active if policy else home/'tor/torrc.DISABLED',diag).verify()
                result='OFFLINE_CHECK_OK';diag.event(result);return result
            print('WARNING: activation can expose onion endpoints through PUBLIC Tor. No RPC/admin mapping; no payment authorization.',flush=True)
            if input('Type ACTIVATE PUBLIC ONION to authorize this foreground session: ')!='ACTIVATE PUBLIC ONION':raise Failure('NO_ACTIVATION_AUTHORIZATION')
            activated=True
            try:
                for purpose,config in configs:
                    path=home/(purpose+'-server.json');save_json(path,config,replace=path.exists())
                    module='p2p_channel.py' if purpose=='p2p' else 'n2_transport.py'
                    args=[sys.executable,str(Path(__file__).with_name(module))]
                    if purpose=='resource':args+=['resource-server']
                    args+=['--config',str(path)]
                    if purpose=='resource':args+=['--hostname-file',str(home/'tor/resource-onion/hostname')]
                    parent=os.getpid();process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent))
                    children.append((purpose,process));diag.event('TLS_'+purpose.upper()+'_STARTED')
                end=time.monotonic()+10
                while True:
                    children_alive(children,diag)
                    try:
                        for _,config in configs:
                            with socket.create_connection(('127.0.0.1',config['listen_port']),timeout=.2):pass
                        break
                    except OSError:
                        if time.monotonic()>=end:raise Failure('TLS_LISTENER_TIMEOUT')
                        time.sleep(.05)
                diag.event('TLS_LISTENERS_READY')
                write_config(active,[line if line!='DisableNetwork 1' else 'DisableNetwork 0' for line in session_expected])
                tor=UpstreamTor(binary,active,diag,policy) if policy else DiagnosticTor(binary,active,diag)
                tor.start();wait_bootstrap(tor,children,diag)
                try:
                    endpoint=dict(version=1,provider=plan['provider_id'],devnet_only=True,p2p_onion=onion_address(c.read_private(home/'tor/p2p-onion/hostname').decode().strip()))
                    if plan['resource']:endpoint['resource_onion']=onion_address(c.read_private(home/'tor/resource-onion/hostname').decode().strip())
                    save_json(home/'public-endpoints.json',endpoint,replace=(home/'public-endpoints.json').exists())
                except (ValueError,OSError):raise Failure('ENDPOINT_ERROR') from None
                diag.event('ENDPOINT_READY');print('TOR_BOOTSTRAPPED; remote reachability/chain freshness still UNVERIFIED.',flush=True)
                if policy:foreground(tor,children,diag,policy)
                else:foreground(tor,children,diag)
                result='TOR_READY'
            finally:
                # Attempt every owned cleanup even if one operation fails.
                failed=False
                if tor:
                    try:tor.close()
                    except Exception:failed=True
                for _,process in reversed(children):
                    try:
                        if process.poll() is None:
                            process.terminate()
                            try:process.wait(timeout=5)
                            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    except Exception:failed=True
                try:write_config(active,session_expected)
                except Exception:failed=True
                diag.event('CLEANUP_FAILED' if failed else 'OWNED_CLEANUP_COMPLETE')
                if failed:raise Failure('CLEANUP_FAILED')
    except (Failure,ProxyFailure) as error:result=error.code;diag.event(result)
    except (KeyboardInterrupt,EOFError):result='CANCELLED';diag.event(result)
    except Exception:result='INTERNAL_ERROR' if activated else 'PREFLIGHT_FAILED';diag.event(result)
    finally:diag.finish(result)
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--plan',type=Path,required=True);p.add_argument('--check-only',action='store_true')
    p.add_argument('--upstream-socks5',metavar='127.0.0.1:PORT',help='Explicit mandatory Tor upstream; no direct fallback; no credentials supported.')
    a=p.parse_args();c.harden()
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    result=run(a.plan,a.check_only,a.upstream_socks5);print('N2_RESULT',result,flush=True)
    if result not in ('TOR_READY','OFFLINE_CHECK_OK'):raise SystemExit(1)
if __name__=='__main__':main()
