"""Owned candidate full-node startup. Network activation stays explicit.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,os,subprocess,time
from pathlib import Path
from .candidate_profile import load
from .candidate_rpc import Node
class Runtime(Node):
    def __init__(self,home,build,profile_path,rpc_port=28281,p2p_port=28282,connector_base=28290):
        home=Path(home);build=Path(build);profile=load(profile_path)
        if not home.is_absolute() or '..' in home.parts or home.is_symlink() or any('privacycoin-n2' in p.lower() for p in home.parts) or not any(p.startswith('pc-candidate-profile-') or p in ('privacycoin-mainnet-candidate-offline','privacycoin-mainnet-v1') for p in home.parts):raise ValueError('ISOLATED_CANDIDATE_HOME')
        ports=[rpc_port,p2p_port,*range(connector_base,connector_base+8)]
        if any(type(p) is not int or not 1024<=p<=65535 for p in ports) or len(set(ports))!=10:raise ValueError('CANDIDATE_PORTS')
        if os.name!='posix' or os.getuid()==0:raise ValueError('SUPPORTED_UNPRIVILEGED_LINUX_REQUIRED')
        home.mkdir(mode=0o700,parents=True,exist_ok=True)
        from src.phase6a.wallet import directory
        with directory(home):pass
        binary=build/'draft-node';receipt=json.loads((build/'BUILD.json').read_text())
        from .candidate_profile import verify_build,identity
        verify_build(receipt)
        if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest()!=receipt['node']['binary_sha256']:raise ValueError('NODE_BINARY_INTEGRITY')
        self.process=None;self.tor=None
        self.log=(home/('owned-node-'+str(time.time_ns())+'.log')).open('xb');os.chmod(self.log.name,0o600)
        args=[str(binary),'--candidate-profile',str(Path(profile_path).resolve()),'--data-dir',str(home/'chain'),'--rpc-port',str(rpc_port),'--p2p-port',str(p2p_port)]
        for p in range(connector_base,connector_base+8):args+=['--peer-port',str(p)]
        try:
            self.process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log,start_new_session=True)
            end=time.monotonic()+15
            while True:
                if self.process.poll() is not None:raise ValueError('OWNED_NODE_START_FAILED')
                try:
                    if ('READY '+identity(profile)[0]+' ').encode() not in Path(self.log.name).read_bytes():raise ValueError('WAIT_FOR_OWNED_LISTENERS')
                    super().__init__(rpc_port,profile);break
                except (OSError,ValueError):
                    if time.monotonic()>=end:raise TimeoutError('OWNED_NODE_START_TIMEOUT')
                    time.sleep(.05)
            self.home=home;self.p2p=p2p_port;self.connector_base=connector_base
        except BaseException:self.close();raise
    def connect_tor(self,binary,peers,upstream,consent):
        if consent!='CONNECT VIA TOR':raise ValueError('EXPLICIT_TOR_CONSENT_REQUIRED')
        from src.network_identity import NETWORK,GENESIS,PROFILE
        if (NETWORK,GENESIS,PROFILE)!=self.identity:raise ValueError('TRANSPORT_CONTEXT_MISMATCH')
        from .onion import descriptor
        from .upstream import validate
        from .public_network import PublicTorSession
        if not isinstance(peers,list) or len(peers)>8:raise ValueError('PEER_BOUND')
        peers=[descriptor(peer) for peer in peers]
        upstream=validate(upstream) if upstream is not None else None
        ports=[self.port,self.p2p,self.p2p+1,self.p2p+2,self.p2p+3,*range(self.connector_base,self.connector_base+8)]
        if max(ports)>65535 or len(set(ports))!=len(ports):raise ValueError('TOR_PORT_COLLISION')
        if self.tor:self.tor.close();self.tor=None
        self.tor=PublicTorSession(self.home/'tor',Path(binary),self.p2p,self.p2p+1,self.p2p+2,self.p2p+3,[(self.connector_base+i,peer) for i,peer in enumerate(peers)],connector_base=self.connector_base,upstream=upstream)
        try:self.tor.start(consent)
        except BaseException:self.tor.close();self.tor=None;raise
        return self.tor.status()
    def close(self):
        if getattr(self,'tor',None):self.tor.close();self.tor=None
        if getattr(self,'process',None) and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(15)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(5)
        if getattr(self,'log',None):self.log.close()
