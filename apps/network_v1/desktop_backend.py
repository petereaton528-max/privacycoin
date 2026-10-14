"""Single trusted private-pipe desktop backend; no privileged HTTP endpoint."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import shutil
import tempfile
import uuid
import hashlib

ROOT=Path(__file__).resolve().parents[2]
PUBLIC_HELPER=ROOT/('build/network-v1/pc-public-tools.exe' if os.name=='nt' else 'build/network-v1/pc-public-tools')
# Only nonsecret deployment paths. Never default to a developer's native tree.
os.environ['PC_DEVNET_NATIVE_ROOT']=str(ROOT)
os.environ['PC_DEVNET_BUILD_MANIFEST']=str(ROOT/'build/v1-native-manifest.json')
sys.path.insert(0,str(ROOT/'scripts/devnet-gui'))
from backend import Session,c,f
from launcher_host import requirements
from .rpc import rpc
from .prediction import Prediction


class Product:
    def __init__(self, home, rpc_port=29881, p2p=29882):
        if type(rpc_port) is not int or not 1024<=rpc_port<=65490 or type(p2p) is not int or not 1024<=p2p<=65535 or p2p in {rpc_port-1,rpc_port,*range(rpc_port+3,rpc_port+18)}:raise ValueError('PRODUCT_PORTS')
        self.home=Path(home)
        if not self.home.is_absolute() or any('privacycoin-n2' in x.lower() for x in self.home.parts) or os.name=='posix' and os.getuid()==0:raise ValueError('PRIVATE_V1_HOME_REQUIRED')
        if os.name=='nt':c.win.mkdir(self.home)
        else:self.home.mkdir(mode=0o700,exist_ok=True)
        with c.directory(self.home):pass
        self.guard=c.lock(self.home/'desktop');self.guard.__enter__()
        try:
            marker=self.home/'PRODUCT_V1.json'
            expected=dict(version=1,role='ISOLATED_V1_DESKTOP',rpc=rpc_port,p2p=p2p)
            from .rpc import NETWORK,PROFILE
            if NETWORK!='PrivacyCoinDev01':expected.update(network=NETWORK,profile=PROFILE)
            if marker.exists():
                if f.decode(c.read_private(marker))!=expected:raise ValueError('PRODUCT_IDENTITY_MISMATCH')
            else:
                if any(x.name!='desktop.lock' for x in self.home.iterdir()):raise ValueError('NEW_EMPTY_PRODUCT_HOME_REQUIRED')
                c.write_private(marker,f.canonical(expected))
            self.session=Session(self.home/'wallets',rpc_port);self.rpc=rpc_port;self.p2p=p2p
            self.node=None;self.index=None;self.miner=None;self.tor=None;self.prediction=None;self.participant=None;self.last_mining={'state':'DISABLED','worker_threads':1,'observed_hashrate':None}
            self.settings_file=self.home/'network.json'
            bundled_tor=ROOT/'runtime/bin'/('tor.exe' if os.name=='nt' else 'tor')
            default_tor=str(bundled_tor) if bundled_tor.is_file() else (None if os.name=='nt' else shutil.which('tor'))
            saved_settings=self.settings_file.exists()
            from .peers import initial_peers,read_catalog
            defaults=[] if saved_settings else initial_peers(ROOT/'apps/network_v1/bootstrap-catalogs.json',read_catalog,f.decode)
            self.settings=f.decode(c.read_private(self.settings_file)) if saved_settings else dict(tor_binary=default_tor,peers=defaults)
            # Explicit migration from the previous settings schema preserves peers.
            if set(self.settings)=={'tor_binary','peers'}:self.settings['upstream']=None
            f.fields(self.settings,'tor_binary peers upstream')
            if self.settings['upstream'] is not None:
                from .upstream import validate
                self.settings['upstream']=validate(self.settings['upstream'])
            from .peers import bootstrap
            from .rpc import NETWORK,GENESIS,PROFILE
            self.settings['peers']=bootstrap([dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,peers=self.settings['peers'])])
            binary=self.settings['tor_binary']
            self.tor_runtime_warning=None
            if binary is not None:
                if not isinstance(binary,str) or not Path(binary).is_absolute() or Path(binary).is_symlink():raise ValueError('TOR_BINARY')
                if not Path(binary).is_file():
                    # Removing an old application directory must not prevent
                    # opening/recovering its wallet. Preserve the saved config,
                    # disable Tor in memory and require an explicit new choice.
                    self.settings=dict(self.settings,tor_binary=None)
                    self.tor_runtime_warning='Configured Tor runtime is unavailable. Wallet access remains local; configure a reviewed runtime before connecting.'
            if not saved_settings and defaults:c.write_private(self.settings_file,f.canonical(self.settings))
            self.discovery_cursor=0
            self.network_enabled=False;self.tor_retry_at=0.;self.tor_retries=0
            self.storage=None;self.resource=None
        except BaseException:self.guard.__exit__(None,None,None);raise

    def spawn(self,args,**kw):
        if os.name=='nt':
            from .windows_owned import spawn
            return spawn(args,cwd=ROOT,stdin=kw.pop('stdin',subprocess.DEVNULL),stdout=kw.pop('stdout',subprocess.DEVNULL),stderr=subprocess.DEVNULL,**kw)
        return subprocess.Popen([sys.executable,str(ROOT/'apps/network_v1/owned_exec.py'),str(os.getpid()),*args],cwd=ROOT,stdin=kw.pop('stdin',subprocess.DEVNULL),stdout=kw.pop('stdout',subprocess.DEVNULL),stderr=subprocess.DEVNULL,start_new_session=True,**kw)

    @staticmethod
    def stop(child):
        if os.name=='nt':
            from .windows_owned import stop
            return stop(child)
        if child and child.poll() is None:
            # Each process starts its own session. Signal ONLY this owned group.
            os.killpg(child.pid,signal.SIGINT)
            try:child.wait(15)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGTERM)
                try:child.wait(5)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(3)

    @staticmethod
    def cleanup(actions):
        error=None
        for action in actions:
            try:action()
            except Exception as failure:
                if error is None:error=failure
        if error:raise error

    def stop_services(self):
        self.network_enabled=False
        self.cleanup([lambda:self.stop(self.miner),lambda:self.stop(self.index),
                      lambda:self.tor.close() if self.tor else None,lambda:self.stop(self.node)])
        if self.miner is not None:self.last_mining['state']='STOPPED'
        self.miner=None;self.index=None

    def start_node(self):
        if self.node and self.node.poll() is None:raise ValueError('NODE_ALREADY_OWNED')
        requirements(allow_native_linux=True)
        if self.index and self.index.poll() is not None:self.index=None
        args=[sys.executable,'-B','-m','apps.network_v1.run_node','--data',str(self.home/'chain'),'--rpc',str(self.rpc),'--p2p',str(self.p2p)]
        if (self.home/'chain').exists():args+=['--resume-v1-data']
        from .rpc import NETWORK
        for i in range(8 if NETWORK=='PrivacyCoinDev02' else len(self.settings['peers'])):args+=['--peer-loopback',str(self.rpc+10+i)]
        self.node=self.spawn(args)
        # Reload validates every persisted block/PoW. A large valid chain must
        # not be killed after an arbitrary 30 seconds. Status remains UNKNOWN
        # until the RPC actually responds; the UI itself stays usable.
        return self.status()

    def status(self):
        self.maintain_tor()
        node={'state':'STOPPED','global_freshness':'UNKNOWN'}
        if self.node and self.node.poll() is None:
            try:
                node=dict(state='LOCAL_VALIDATING_NODE',**rpc(self.rpc,'status'),global_freshness='UNKNOWN')
                if self.index is None:
                    self.index=self.spawn([sys.executable,'-B','-m','apps.network_v1','serve','--rpc',str(self.rpc),'--port',str(self.rpc-1),'--index',str(self.home/'public-index.sqlite'),'--helper',str(PUBLIC_HELPER)])
            except Exception:node={'state':'STARTING_OR_UNAVAILABLE','global_freshness':'UNKNOWN'}
        if self.miner and self.miner.poll() is not None:
            self.last_mining['state']='STOPPED' if self.miner.returncode==0 else 'STOPPED_OR_REJECTED'
        from .rpc import NETWORK,GENESIS
        if self.tor and hasattr(self.tor,'directory'):
            # Persist authenticated hints first; never persist an entire adversarial
            # candidate pool over independently configured bootstrap entries.
            candidates=self.settings['peers']+self.tor.directory.catalog()
            peers=list({p['onion']:p for p in candidates if p['certificate_sha256']!=self.tor.own_pin}.values())[:8]
            if peers!=self.settings['peers']:
                settings=dict(self.settings,peers=peers)
                c.write_private(self.settings_file,f.canonical(settings),replace=self.settings_file.exists());self.settings=settings
        return dict(node=node,network_identity=NETWORK,genesis=GENESIS,tor=self.tor.status() if self.tor else {'state':'DISABLED','route':'ONION_ONLY_NO_DIRECT_FALLBACK'},mining=dict(self.last_mining),index='PROCESS_RUNNING_UNVERIFIED' if self.index and self.index.poll() is None else 'STOPPED',testnet_only=True,pc_prediction_mode=False,configured_peers=len(getattr(self,'settings',{}).get('peers',[])),tor_runtime_configured=bool(getattr(self,'settings',{}).get('tor_binary')),tor_runtime_warning=getattr(self,'tor_runtime_warning',None))

    def wait_node(self):
        """Wallet creation cannot race asynchronous native validation startup."""
        end=time.monotonic()+180;delay=.05
        while time.monotonic()<end:
            if not self.node or self.node.poll() is not None:raise ValueError('OWNED_NODE_EXITED')
            try:return rpc(self.rpc,'status')
            except (OSError,ValueError):
                time.sleep(delay);delay=min(1,delay*1.5)
        raise ValueError('NODE_VALIDATION_NOT_READY_RETRY_WITHOUT_RECREATING_WALLET')

    def maintain_tor(self):
        # Consent is session-local: reboot/relaunch never activates networking.
        if not getattr(self,'network_enabled',False) or not self.tor or not self.node or self.node.poll() is not None:return
        process=self.tor.owned.process
        if process is not None and process.poll() is None:return
        if time.monotonic()<self.tor_retry_at:return
        try:self.tor.start('CONNECT VIA TOR');self.tor_retries=0
        except Exception:self.tor_retries=min(self.tor_retries+1,6)
        self.tor_retry_at=time.monotonic()+min(30,2**self.tor_retries)

    def prediction_enable(self,consent):
        if consent!='ENABLE SIMULATION ONLY':raise ValueError('SIMULATION_CONSENT')
        self.prediction=Prediction(self.home/'prediction');self.operator=c.read_private(self.home/'prediction/operator').decode()
        p=self.home/'prediction/participant'
        if not p.exists():c.write_private(p,self.prediction.register(self.operator).encode())
        self.participant=c.read_private(p).decode()
        return self.prediction.view(self.participant)

    def dispatch(self,r):
        if not isinstance(r,dict):raise ValueError('SCHEMA')
        if r.get('command')=='tor_provision':
            if set(r)!={'command','consent'} or r['consent']!='DOWNLOAD VERIFIED TOR':raise ValueError('EXPLICIT_TOR_DOWNLOAD_CONSENT_REQUIRED')
            if self.tor and self.tor.owned.process is not None and self.tor.owned.process.poll() is None:raise ValueError('DISCONNECT_TOR_BEFORE_RUNTIME_UPDATE')
            destination=self.home/('tor-runtime-'+str(uuid.uuid4()))
            # Owned, bounded helper; dependency downloads contain no wallet data.
            # Neither this helper nor publishing the setting activates Tor.
            child=self.spawn([sys.executable,'-B',str(ROOT/'services/privacy-network/provision_tor.py'),str(destination),'--source','torproject'])
            try:
                if child.wait(timeout=75):raise ValueError('TOR_PROVISIONING_FAILED')
            finally:self.stop(child)
            record=f.decode(c.read_private(destination/'provenance.json'))
            binary=destination/'root/usr/bin/tor'
            sys.path.insert(0,str(ROOT/'services/privacy-network'))
            from tor_policy import require_current
            version=require_current(binary)
            if record.get('archive')!='torproject' or record.get('binary_sha256')!=hashlib.sha256(binary.read_bytes()).hexdigest():raise ValueError('TOR_PROVENANCE_MISMATCH')
            settings=dict(self.settings,tor_binary=str(binary))
            c.write_private(self.settings_file,f.canonical(settings),replace=self.settings_file.exists());self.settings=settings
            self.tor_runtime_warning=None
            return dict(self.status(),tor_runtime=dict(version=version,source='OFFICIAL_TOR_PROJECT_SIGNED_ARCHIVE'),no_connection_started=True)
        cmd=r.get('command')
        if cmd=='peer_link_add':
            if set(r)!={'command','link'}:raise ValueError('SCHEMA')
            from .peer_uri import parse
            return self.dispatch(dict(command='peer_add',descriptor=parse(r['link'])))
        if cmd=='upgrade_check':
            if set(r)!={'command','old_root','data'}:raise ValueError('SCHEMA')
            from .upgrade import compatible
            return compatible(r['old_root'],ROOT,r['data'])
        if isinstance(cmd,str) and cmd.startswith('prediction_'):
            raise ValueError('PREDICTION_ARCHIVED_NOT_A_V1_SERVICE')
        if cmd=='wallet_export':
            if set(r)!={'command','destination'}:raise ValueError('SCHEMA')
            from .wallet_transfer import export
            return export(self.session,r['destination'])
        if cmd=='wallet_import':
            if set(r)!={'command','source','name','password','format','consent'}:raise ValueError('SCHEMA')
            from .wallet_transfer import import_wallet
            return import_wallet(self.session,r['source'],r['name'],r['password'],r['format'],r['consent'])
        cpu_preset=r.get('cpu_preset','balanced')
        if cmd=='mine_start' and 'cpu_preset' in r:r={k:v for k,v in r.items() if k!='cpu_preset'}
        if cmd=='verify_backup':
            if set(r)!={'command','name'} or not self.session.wallet:raise ValueError('OPEN_WALLET_REQUIRED')
            from backend import recovery_bundle
            recovered,bundle=recovery_bundle(self.session.path(r['name'],'.backup'),self.session.password)
            if f.wallet_id(recovered)!=f.wallet_id(self.session.wallet) or bundle['journal']!=self.session.journal:raise ValueError('CURRENT_WALLET_BACKUP_REQUIRED')
            # Exercise encrypted file publication/readback in a fresh private
            # directory. Never replace an existing wallet or submit a payment.
            with tempfile.TemporaryDirectory(prefix='verify-',dir=self.home) as directory:
                path=Path(directory)/'recovered.wallet';c.save(path,recovered,self.session.password)
                if f.wallet_id(c.load(path,self.session.password))!=f.wallet_id(self.session.wallet):raise ValueError('RESTORE_IDENTITY')
            return dict(verified=True,scope='encrypted backup decode + isolated wallet save/load; same funds, no payment',backup=r['name'])
        if cmd in ('prediction_disable','storage_detach'):
            if set(r)!={'command'}:raise ValueError('SCHEMA')
            if cmd=='prediction_disable':self.prediction=None;self.participant=None;self.operator=None
            else:
                if self.resource:self.resource.close()
                self.resource=None;self.storage=None
            return {'state':'DISABLED','private_data_preserved':True,'automatic_payment':False}
        if cmd=='discover_peers':
            if set(r)!={'command'} or not self.tor or self.tor.status()['state']!='TOR_READY':raise ValueError('READY_TOR_REQUIRED')
            if hasattr(self.tor,'directory'):
                return dict(candidates=self.tor.directory.candidates(),trust='BOUNDED_AUTOMATIC_HINTS; CONSENSUS_INDEPENDENT')
            from .onion import discover
            candidates={}
            # Bound total operation to one peer's ten-second request per click.
            if self.settings['peers']:
                peer=self.settings['peers'][self.discovery_cursor%len(self.settings['peers'])]
                self.discovery_cursor+=1
                for v in discover(peer,self.tor.socks):candidates[v['onion']]=v
            return {'candidates':list(candidates.values())[:8],'trust':'UNTRUSTED_TRANSPORT_HINTS; REVIEW_AND_ADD; CONSENSUS_INDEPENDENT'}
        if cmd=='upstream_configure':
            if set(r)!={'command','route'}:raise ValueError('SCHEMA')
            from .rpc import NETWORK
            if NETWORK!='PrivacyCoinDev02':raise ValueError('EXPLICIT_OPEN_DEVELOPMENT_NETWORK_REQUIRED')
            if self.tor and self.tor.owned.process is not None and self.tor.owned.process.poll() is None:raise ValueError('DISCONNECT_TOR_BEFORE_ROUTE_CHANGE')
            from .upstream import validate
            route=validate(r['route']) if r['route'] is not None else None
            settings=dict(self.settings,upstream=route)
            c.write_private(self.settings_file,f.canonical(settings),replace=self.settings_file.exists());self.settings=settings
            return dict(configured=True,explicit_proxy_required=route is not None,network_started=False)
        schemas={'product_status':'','explore':'kind day','node_start':'','node_stop':'','mine_start':'blocks consent password','mine_stop':'','tor_configure':'binary','peer_add':'descriptor','bootstrap_import':'path','tor_start':'consent','tor_stop':'','tor_descriptor':'','prediction_enable':'consent','prediction_view':'','prediction_create':'question criteria source close resolve cancellation authority','prediction_bet':'event side amount key','prediction_adjudicate':'event action outcome evidence consent','storage_attach':'profile','storage_request':'key bytes','storage_pay':'key consent','storage_observe':'key','storage_upload':'key source','storage_export':'key destination password','storage_restore':'source destination password'}
        if cmd not in schemas:
            if cmd=='connect' and r.get('port')!=self.rpc:raise ValueError('OWNED_NODE_ONLY')
            if cmd in ('create','open','restore') and not (self.node and self.node.poll() is None):self.start_node()
            if cmd in ('create','open','restore'):self.wait_node()
            return self.session.dispatch(r)
        if set(r)!={'command',*schemas[cmd].split()}:raise ValueError('SCHEMA')
        if cmd=='product_status':return self.status()
        if cmd=='explore':
            from .sdk import Client
            api=Client('http://127.0.0.1:'+str(self.rpc-1))
            if r['kind']=='network':return api.network()
            if r['kind']=='blocks':return api.blocks()
            if r['kind']=='rankings':return api.leaderboard(r['day'])
            raise ValueError('READ_QUERY')
        if cmd=='node_start':return self.start_node()
        if cmd=='node_stop':
            self.stop_services();return self.status()
        if cmd=='mine_stop':
            self.stop(self.miner);self.miner=None;self.last_mining['state']='STOPPED';return self.status()
        if cmd=='mine_start':
            if cpu_preset not in ('light','balanced','maximum'):raise ValueError('CPU_PRESET')
            if r['consent']!='START CPU MINING' or not self.session.wallet or self.session.wallet['authority']!='full' or not self.node or self.node.poll() is not None:raise ValueError('MINING_CONSENT_WALLET_NODE_REQUIRED')
            rpc(self.rpc,'status') # No mining against an unvalidated/reloading node.
            if self.miner and self.miner.poll() is None:raise ValueError('MINER_ALREADY_RUNNING')
            if type(r['blocks']) is not int or not 1<=r['blocks']<=100:raise ValueError('BLOCK_BOUND')
            # Verify password before handing it to an owned private-pipe worker.
            c.load(self.session.file,r['password'].encode())
            self.miner=self.spawn([sys.executable,'-B','-m','apps.network_v1','mine','--rpc',str(self.rpc),'--helper',str(PUBLIC_HELPER),'--wallet',str(self.session.file),'--blocks',str(r['blocks']),'--cpu-preset',cpu_preset,'--authorize-cpu-mining'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            self.miner.stdin.write(r['password'].encode()+b'\n');self.miner.stdin.close();self.last_mining={'state':'STARTING','worker_threads':1,'observed_hashrate':None}
            def consume(child):
                while True:
                    raw=child.stdout.readline(4097)
                    if not raw:break
                    try:
                        value=json.loads(raw)
                        if isinstance(value,dict):self.last_mining={k:v for k,v in value.items() if k in ('state','accepted','height','reward_atomic','worker_threads','observed_hashrate','hashes')}
                    except Exception:pass
            threading.Thread(target=consume,args=(self.miner,),daemon=True).start();return self.status()
        if cmd in ('tor_configure','peer_add','bootstrap_import'):
            from .rpc import NETWORK
            public_live=NETWORK=='PrivacyCoinDev02' and cmd in ('peer_add','bootstrap_import')
            if self.node and self.node.poll() is None and not public_live:raise ValueError('STOP_OWNED_NODE_BEFORE_NETWORK_CONFIG')
            from .onion import descriptor
            settings=dict(self.settings,peers=list(self.settings['peers']))
            if cmd=='tor_configure':
                binary=Path(r['binary'])
                if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():raise ValueError('TOR_BINARY')
                settings['tor_binary']=str(binary)
            elif cmd=='bootstrap_import':
                from .peers import bootstrap
                raw=c.read_private(Path(r['path']))
                if len(raw)>16384:raise ValueError('BOOTSTRAP_BOUND')
                settings['peers']=bootstrap(f.decode(raw),settings['peers'])
            else:
                v=descriptor(r['descriptor'])
                if v not in settings['peers']:
                    if len(settings['peers'])>=8:raise ValueError('PEER_BOUND')
                    if any(p['onion']==v['onion'] for p in settings['peers']):raise ValueError('PEER_PIN_CONFLICT')
                    settings['peers'].append(v)
            c.write_private(self.settings_file,f.canonical(settings),replace=self.settings_file.exists());self.settings=settings
            if public_live and self.tor:
                for value in settings['peers']:self.tor.directory.add(value)
            if cmd=='tor_configure':self.tor_runtime_warning=None
            return {'configured':True,'peer_count':len(self.settings['peers']),'no_connection_started':True}
        if cmd=='tor_start':
            from .onion import TorSession
            from .rpc import NETWORK
            if not self.node or self.node.poll() is not None or not self.settings['tor_binary']:raise ValueError('OWNED_NODE_AND_TOR_REQUIRED')
            if self.tor:self.tor.close()
            options={}
            if NETWORK=='PrivacyCoinDev02':
                from .public_network import PublicTorSession
                TorSession=PublicTorSession;options.update(connector_base=self.rpc+10,upstream=self.settings['upstream'])
            self.tor=TorSession(self.home/'tor',self.settings['tor_binary'],self.p2p,self.rpc+3,self.rpc+4,self.rpc+5,[(self.rpc+10+i,p) for i,p in enumerate(self.settings['peers'])],**options);self.tor.start(r['consent']);self.network_enabled=True;self.tor_retry_at=0.;self.tor_retries=0;return self.status()
        if cmd=='tor_stop':
            self.network_enabled=False
            if self.tor:self.tor.close()
            return self.status()
        if cmd=='tor_descriptor':return self.tor.public_descriptor()
        if cmd=='prediction_enable':return self.prediction_enable(r['consent'])
        if cmd.startswith('prediction_'):
            if not self.prediction:raise ValueError('OPTIONAL_MODULE_DISABLED')
            if cmd=='prediction_view':return self.prediction.view(self.participant)
            if cmd=='prediction_create':return {'event':self.prediction.create(self.operator,**{k:v for k,v in r.items() if k!='command'})}
            if cmd=='prediction_bet':return self.prediction.participate(self.participant,r['event'],r['side'],r['amount'],r['key'])
            if cmd=='prediction_adjudicate':return self.prediction.adjudicate(self.operator,r['event'],r['action'],outcome=r['outcome'],evidence=r['evidence'],consent=r['consent'])
        if cmd=='storage_attach':
            from .payments import Payments
            sys.path.insert(0,str(ROOT/'services/privacy-network'));from client import Client
            from tor_transport import OnionTransport
            from n2_transport import ResourceProxy
            v=f.decode(c.read_private(Path(r['profile'])))
            f.fields(v,'version scope provider admin onion channel');f.unhex(v['admin'],32);f.unhex(v['provider'],32)
            if v['version']!=1 or v['scope']!='V1_NEW_DEPLOYMENT_ONLY' or v['channel']['role']!='connector' or v['channel']['endpoint']!=v['onion']:raise ValueError('ONION_STORAGE_BINDING_REQUIRED')
            if self.resource:raise ValueError('STORAGE_ALREADY_ATTACHED')
            # Keep the original mutual TLS/pin gateway; never degrade storage to
            # unauthenticated HTTP or the open consensus admission policy.
            self.resource=ResourceProxy(v['channel']);threading.Thread(target=self.resource.run,daemon=True).start()
            transport=OnionTransport(v['onion'],v['provider'],v['channel']['listen_port'])
            client=Client(self.home/'storage-client',80,v['admin'],transport)
            self.storage=Payments(self.home/'storage-orders',client,c);return {'attached':True,'custody':'LOCAL_WALLET_ONLY','retention':'BOUNDED_PROVIDER_NOT_PERMANENT'}
        if cmd.startswith('storage_'):
            if not self.storage:raise ValueError('OPTIONAL_MODULE_DISABLED')
            if cmd=='storage_request':
                result=self.storage.request(r['key'],r['bytes']);q=self.storage.client.record(result['quote'])['quote']
                return dict(result,review={k:q[k] for k in ('amount_atomic','recipient','expires','payment_deadline','retention','confirmations')},fee_atomic='188000',max_fee_atomic='500000')
            if cmd=='storage_pay':return self.storage.authorize(r['key'],self.session,r['consent'])
            if cmd=='storage_observe':return self.storage.observe(r['key'])
            if cmd=='storage_upload':
                raw=c.read_private(Path(r['source']));return self.storage.deliver(r['key'],raw)
            if cmd=='storage_export':
                self.storage.export_recovery(r['key'],r['destination'],r['password'].encode());return {'encrypted_bundle_saved':True}
            if cmd=='storage_restore':
                from client import restore_bundle
                return restore_bundle(r['source'],r['password'].encode(),r['destination'],self.storage.client.transport)
        raise ValueError('COMMAND')

    def close(self):
        try:self.cleanup([self.session.close,lambda:self.resource.close() if self.resource else None,self.stop_services])
        finally:self.guard.__exit__(None,None,None)


def main():
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    default_home=Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'PrivacyCoinV1-testnet' if os.name=='nt' else Path.home()/'.local/share/privacycoin-v1-candidate3'
    from .rpc import NETWORK
    if NETWORK=='PrivacyCoinDev02':default_home=Path.home()/'.local/share/privacycoin-v1-open-dev02'
    c.harden();p=argparse.ArgumentParser();p.add_argument('--home',type=Path,default=default_home);p.add_argument('--port',type=int,default=29881);p.add_argument('--p2p',type=int,default=29882);a=p.parse_args()
    session=Product(a.home,a.port,a.p2p)
    try:
        while True:
            raw=sys.stdin.buffer.readline(16385)
            if not raw or len(raw)>16384 or not raw.endswith(b'\n'):break
            try:result=session.dispatch(f.decode(raw));response=dict(ok=True,result=result)
            except Exception:session.session.plan=None;response=dict(ok=False,error='Operation rejected; credentials, authority, network or state unavailable. Uncertain payment requires reconciliation; never repay automatically.')
            print(json.dumps(response,separators=(',',':')),flush=True)
    finally:session.close()


if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):sys.exit(1)
