"""Owned official Tor processes; default config preparation cannot activate Tor.

PrivateNetwork is a loopback-only testing network, NOT the public Tor network.
It deliberately uses unsafe-for-public-network TestingTorNetwork options.
"""
from common import *
import subprocess,time,socket,signal,re,datetime,threading,sys
from launcher_host import child_parent_guard
from n1_diagnostics import emit

TOR=NATIVE/'build/privacy-network-n1/tor-runtime/root/usr/bin/tor'

def available(binary=TOR):
    if not Path(binary).is_file():raise ValueError('TOR_RUNTIME_MISSING: see provision_tor.py')
    return Path(binary)

def tor_path(path):
    path=Path(path)
    if os.name=='nt':
        if any(ch in str(path) for ch in ('"','\r','\n','\t','\0')):raise ValueError('TOR_PATH_UNSUPPORTED')
        return c.win.path(path)
    # Torrc interpolation is configuration code. Reject whitespace/control
    # characters rather than permitting path-based directive injection.
    if not path.is_absolute() or '..' in path.parts or not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(path)):raise ValueError('TOR_PATH_UNSUPPORTED')
    return path

def config_path(path):
    value=tor_path(path)
    if os.name!='nt':return str(value)
    # This reviewed MinGW Tor runtime uses legacy MSVCRT filesystem APIs. Torrc
    # unescapes C octal bytes, so preserve the Windows ANSI filename encoding
    # rather than passing UTF8 bytes to an ANSI fopen. Never change host locale.
    # Unrepresentable paths fail closed rather than creating a different folder.
    try:raw=value.as_posix().encode('mbcs',errors='strict')
    except UnicodeError as error:raise ValueError('TOR_PATH_SYSTEM_ENCODING_UNSUPPORTED') from error
    return '"'+''.join(chr(n) if 32<=n<127 and n not in (34,92) else '\\'+format(n,'03o') for n in raw)+'"'

def write_config(path,lines):
    c.write_private(Path(path),('\n'.join(lines)+'\n').encode(),replace=Path(path).exists())

class OwnedTor:
    def __init__(self,binary,config,diagnostics=None):
        self.binary=available(binary);self.config=Path(config);self.process=None;self.diagnostics=diagnostics
        self.owner=None;self.started_at=None
    def verify(self):
        result=subprocess.run([str(self.binary),'-f',str(self.config),'--verify-config'],capture_output=True,timeout=10)
        if result.returncode:raise ValueError('TOR_CONFIG_INVALID')
    def start(self):
        if self.process is not None and self.process.poll() is None:raise ValueError('TOR_ALREADY_OWNED')
        self.verify();parent=os.getpid()
        if os.name=='nt':
            from apps.network_v1.windows_owned import spawn
            self.process=spawn([str(self.binary),'-f',str(self.config)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        else:
            # Linux PDEATHSIG follows the creating THREAD. GUI request workers
            # return immediately, so keep a dedicated owner alive through wait().
            # Install the guard in a fresh single-threaded interpreter, not an
            # unsafe Python preexec_fn in the multithreaded GUI child.
            ready=threading.Event();errors=[]
            guard=('import ctypes,os,signal,sys; '
                   'r=ctypes.CDLL(None).prctl(1,signal.SIGTERM,0,0,0); '
                   'ok=r==0 and os.getppid()==int(sys.argv[1]); '
                   'ok or os._exit(125); os.execv(sys.argv[2],sys.argv[2:])')
            def own():
                try:
                    process=subprocess.Popen([sys.executable,'-c',guard,str(parent),str(self.binary),'-f',str(self.config)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    self.process=process
                except BaseException as error:errors.append(error)
                finally:ready.set()
                if not errors:process.wait()
            self.owner=threading.Thread(target=own,name='pc-owned-tor',daemon=True);self.owner.start();ready.wait()
            if errors:raise errors[0]
        self.started_at=time.monotonic()
        emit(self.diagnostics,'tor_process_started',role=self.config.parent.name,pid=self.process.pid)
    def close(self):
        if os.name=='nt' and self.process is not None:
            from apps.network_v1.windows_owned import stop
            stop(self.process);emit(self.diagnostics,'tor_process_stopped',role=self.config.parent.name,pid=self.process.pid)
            self.process=None;return
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
            emit(self.diagnostics,'tor_process_stopped',role=self.config.parent.name,pid=self.process.pid)
        if self.owner:self.owner.join(6)
    def control(self,command):
        if not isinstance(command,str) or '\r' in command or '\n' in command:raise ValueError('TOR_CONTROL_COMMAND')
        home=self.config.parent;cookie=c.read_private(home/'control_auth_cookie')
        if len(cookie)!=32:raise ValueError('TOR_CONTROL_COOKIE')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            port=int(next(line.rsplit(':',1)[1] for line in self.config.read_text().splitlines() if line.startswith('ControlPort ')))
            sock.settimeout(2);sock.connect(('127.0.0.1',port));end=time.monotonic()+2
            def response():
                # TCP recv boundaries are not Tor control-message boundaries.
                # Consume complete bounded lines through the terminal status.
                raw=b'';line=b'';data=False
                while True:
                    remaining=end-time.monotonic()
                    if remaining<=0:raise TimeoutError('TOR_CONTROL_DEADLINE')
                    sock.settimeout(remaining);part=sock.recv(1)
                    if not part:raise ValueError('TOR_CONTROL_EOF')
                    raw+=part;line+=part
                    if len(raw)>262144:raise ValueError('TOR_CONTROL_BOUND')
                    if not line.endswith(b'\r\n'):continue
                    if data:
                        if line==b'.\r\n':data=False
                    elif len(line)<6 or not line[:3].isdigit():raise ValueError('TOR_CONTROL_FRAME')
                    elif line[3:4]==b'+':data=True
                    elif line[3:4]==b' ':return raw
                    elif line[3:4]!=b'-':raise ValueError('TOR_CONTROL_FRAME')
                    line=b''
            sock.sendall(b'AUTHENTICATE '+cookie.hex().encode()+b'\r\n')
            if not response().startswith(b'250 '):raise ValueError('TOR_CONTROL_AUTH')
            sock.sendall(command.encode()+b'\r\n');reply=response()
            if command=='GETINFO status/bootstrap-phase':
                match=re.search(rb'PROGRESS=(\d+)',reply)
                if match:emit(self.diagnostics,'tor_bootstrap',role=self.config.parent.name,progress=int(match[1]),pid=self.process.pid if self.process else 0)
            return reply

class PrivateNetwork:
    def __init__(self,home,bridge_port,binary=TOR,experimental_upstream=False,diagnostics=None):
        self.home=private_dir(tor_path(home));self.binary=available(binary);self.nodes=[];self.bridge_port=f.integer(bridge_port,1024,65535)
        self.diagnostics=diagnostics
        self.experimental_upstream=experimental_upstream
        self.guard=c.lock(self.home/'network');self.guard.__enter__()
        try:self.prepare()
        except BaseException:self.guard.__exit__(None,None,None);raise
    def prepare(self):
        # OS-chosen loopback ports are persisted; collision fails closed at startup.
        path=self.home/'ports'
        if path.exists():self.ports=load_json(path)
        else:
            held=[];values=[];count=8 if self.experimental_upstream else 5
            try:
                while len(values)<3*count+3:
                    sock=socket.socket();sock.bind(('127.0.0.1',0));value=sock.getsockname()[1]
                    if value==self.bridge_port:sock.close();continue
                    held.append(sock);values.append(value)
                self.ports=dict(orports=values[:count],dirports=values[count:2*count],socks=values[2*count],control=values[2*count+1:])
                if self.experimental_upstream:self.ports.update(version=2,relays=8)
                save_json(path,self.ports)
            finally:
                for sock in held:sock.close()
        if 'version' in self.ports:
            if not self.experimental_upstream:raise ValueError('EXPERIMENTAL_TOR_PROFILE_REQUIRES_OPT_IN')
            f.fields(self.ports,'version relays orports dirports socks control')
            if type(self.ports['version']) is not int or self.ports['version'] not in (1,2) or type(self.ports['relays']) is not int or self.ports['relays']!=8:raise ValueError('PRIVATE_TOR_CONFIG_VERSION')
            self.relay_count=8;self.authority_count=3 if self.ports['version']==2 else 8
        else:
            f.fields(self.ports,'orports dirports socks control');self.relay_count=5;self.authority_count=5 # exact supported initial fixture; no migration
        count=self.relay_count
        if any(not isinstance(self.ports[k],list) or len(self.ports[k])!=n for k,n in [('orports',count),('dirports',count),('control',count+2)]):raise ValueError('PRIVATE_TOR_CONFIG_VERSION')
        values=self.ports['orports']+self.ports['dirports']+self.ports['control']+[self.ports['socks']]
        for value in values:f.integer(value,1024,65535)
        if len(set(values))!=3*count+3 or self.bridge_port in values:raise ValueError('PRIVATE_TOR_PORT_COLLISION')
        dns=self.home/'resolv.conf'
        if not dns.exists():c.write_private(dns,b'nameserver 127.0.0.1\n')
        authorities=[]
        for i in range(self.authority_count):
            home=private_dir(self.home/('auth'+str(i)));keys=private_dir(home/'keys')
            if not (keys/'authority_certificate').exists():
                subprocess.run([str(self.binary.with_name('tor-gencert')),'--create-identity-key','--passphrase-fd','0','-i',str(keys/'authority_identity_key'),'-s',str(keys/'authority_signing_key'),'-c',str(keys/'authority_certificate'),'-a','127.0.0.1:'+str(self.ports['dirports'][i]),'-m','1'],input=b'\n',capture_output=True,check=True,timeout=15)
            cert=(keys/'authority_certificate').read_text();v3=next(line.split()[1] for line in cert.splitlines() if line.startswith('fingerprint '))
            minimal=home/'identity.torrc';write_config(minimal,[f'DataDirectory {home}',f'Nickname auth{i}',f'ORPort 127.0.0.1:{self.ports["orports"][i]}','DisableNetwork 1','SocksPort 0','PublishServerDescriptor 0'])
            result=subprocess.run([str(self.binary),'-f',str(minimal),'--list-fingerprint'],capture_output=True,text=True,check=True,timeout=15)
            fingerprint=next(line for line in result.stdout.splitlines() if line.startswith('auth'+str(i)+' ')).split(' ',1)[1].replace(' ','')
            authorities.append(f'DirAuthority auth{i} orport={self.ports["orports"][i]} v3ident={v3} 127.0.0.1:{self.ports["dirports"][i]} {fingerprint}')
        # Upstream Chutney hs-v3 uses 3 authorities + 5 relays. The new profile
        # preserves that topology and phases; exits remain rejected here because
        # only onion services are tested, never clearnet destinations.
        for i in range(count+2):
            name='auth'+str(i) if i<self.authority_count else 'relay'+str(i) if i<count else 'client' if i==count else 'service';home=private_dir(self.home/name)
            lines=[f'DataDirectory {home}',f'Nickname {name}','TestingTorNetwork 1','RunAsDaemon 0','SafeLogging 1','Log notice file '+str(home/'notice.log'),'ControlPort 127.0.0.1:'+str(self.ports['control'][i]),'CookieAuthentication 1','SocksPort 0','Address 127.0.0.1','OutboundBindAddress 127.0.0.1','EnforceDistinctSubnets 0','DirAllowPrivateAddresses 1','ExtendAllowPrivateAddresses 1','ClientRejectInternalAddresses 0','UseEntryGuards 0','PathsNeededToBuildCircuits 0.67','TestingDirAuthVoteGuard *','TestingDirAuthVoteHSDir *','TestingDirAuthVoteExit *','TestingMinExitFlagThreshold 0','MaxMemInQueues 256 MB','NumCPUs 1','ServerDNSResolvConfFile '+str(dns),'ServerDNSDetectHijacking 0','ServerDNSAllowBrokenConfig 1']+authorities
            if i<count:lines += [f'ORPort 127.0.0.1:{self.ports["orports"][i]}',f'DirPort 127.0.0.1:{self.ports["dirports"][i]}','ExitPolicy reject *:*','ContactInfo isolated-test@example.invalid','AssumeReachable 1']
            if i<self.authority_count:lines += ['AuthoritativeDirectory 1','V3AuthoritativeDirectory 1','AuthDirMaxServersPerAddr 0','V3AuthNIntervalsValid 5','TestingV3AuthInitialVotingInterval 20','TestingV3AuthInitialVoteDelay 4','TestingV3AuthInitialDistDelay 4','V3AuthVotingInterval 300','V3AuthVoteDelay 20','V3AuthDistDelay 20']
            elif i==count:lines+=['ReachableAddresses accept 127.0.0.1:*, reject *:*','ClientOnly 1',f'SocksPort 127.0.0.1:{self.ports["socks"]}']
            elif i==count+1:
                self.onion_home=private_dir(home/'onion')
                lines+=['ReachableAddresses accept 127.0.0.1:*, reject *:*','ClientOnly 1','HiddenServiceDir '+str(self.onion_home),'HiddenServiceVersion 3',f'HiddenServicePort 80 127.0.0.1:{self.bridge_port}']
            lines=[line for line in lines if not (i==count and line=='SocksPort 0')]
            if self.authority_count==3:
                # Upstream Chutney exit-v4.i documents #11264: restrictive
                # private exit policies and optimistic Exit flags can disagree
                # with microdescriptor summaries. Its documented alternative is
                # regular descriptors. Never relax the no-exit policy to work
                # around a private-fixture bootstrap problem.
                lines+=['UseMicrodescriptors 0','ServerDNSTestAddresses']
            lines+=['ShutdownWaitLength 1']
            config=home/'torrc';write_config(config,lines);self.nodes.append(OwnedTor(self.binary,config,self.diagnostics))
    @property
    def hostname(self):
        from tor_transport import onion_address
        return onion_address((self.onion_home/'hostname').read_text().strip())
    @property
    def socks_port(self):return self.ports['socks']
    def start(self):
        try:
            end=time.monotonic()+180
            for node in self.nodes[:self.relay_count]:node.start()
            # Chutney launches clients/services in phase 2. Wait for all relay
            # descriptors in a current consensus, not just circuit bootstrap.
            if self.relay_count:
                while time.monotonic()<end:
                    try:
                        consensus=(self.nodes[0].config.parent/'cached-consensus').read_text()
                        until=next(x[12:] for x in consensus.splitlines() if x.startswith('valid-until '))
                        fresh=datetime.datetime.strptime(until,'%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp()>time.time()
                        if fresh and sum(x.startswith('r ') for x in consensus.splitlines())==self.relay_count:break
                    except (OSError,ValueError,StopIteration):pass
                    if any(n.process.poll() is not None for n in self.nodes[:self.relay_count]):raise ValueError('PRIVATE_TOR_RELAY_FAILED')
                    time.sleep(.2)
                else:raise ValueError('PRIVATE_TOR_CONSENSUS_TIMEOUT')
            for node in self.nodes[-2:]:node.start()
            while time.monotonic()<end:
                if any(n.process.poll() is not None for n in self.nodes):raise ValueError('PRIVATE_TOR_PROCESS_FAILED')
                try:
                    # Directory authorities do not report client bootstrap progress.
                    ready=all(b'PROGRESS=100' in n.control('GETINFO status/bootstrap-phase') for n in self.nodes[-2:])
                    if ready and (self.onion_home/'hostname').exists():return
                except (OSError,ValueError):pass
                time.sleep(.2)
            raise ValueError('PRIVATE_TOR_BOOTSTRAP_TIMEOUT')
        except BaseException:
            for n in self.nodes:n.close()
            raise
    def close(self):
        for n in reversed(self.nodes):n.close()
        self.guard.__exit__(None,None,None)

def prepare_public(home,bridge_port,socks_port=19050):
    """Disabled template only. Deliberately no public activation function here."""
    home=private_dir(tor_path(home));private_dir(home/'onion');f.integer(bridge_port,1024,65535);f.integer(socks_port,1024,65535)
    lines=[f'DataDirectory {home}','DisableNetwork 1','RunAsDaemon 0','SafeLogging 1','SocksPort 127.0.0.1:'+str(socks_port),'HiddenServiceDir '+str(home/'onion'),'HiddenServiceVersion 3',f'HiddenServicePort 80 127.0.0.1:{bridge_port}']
    write_config(home/'torrc.DISABLED',lines)
    return home/'torrc.DISABLED'
