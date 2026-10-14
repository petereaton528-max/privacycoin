"""Bounded allowlisted Tor observations. Never persist raw daemon/control output."""
from pathlib import Path
import datetime,json,os,re,subprocess,threading,time
import role
from common import c,private_dir,save_json
from tor_runtime import OwnedTor
from launcher_host import child_parent_guard

STAGES=set('starting conn conn_done conn_proxy conn_done_proxy conn_pt conn_done_pt handshake handshake_done onehop_create requesting_status loading_status loading_keys requesting_descriptors loading_descriptors enough_dirinfo ap_conn_pt ap_conn_done_pt ap_conn_proxy ap_conn_done_proxy ap_conn ap_conn_done ap_handshake ap_handshake_done circuit_create done'.split())
REASONS=set('MISC DONE CONNECTREFUSED IDENTITY CONNECTRESET TIMEOUT NOROUTE IOERROR RESOURCELIMIT PT_MISSING'.split())
CODES=set('SESSION_START CONFIG_VERIFIED TOR_CONFIG_INVALID TOR_VERIFY_TIMEOUT TOR_SPAWN_FAILED TOR_PROCESS_STARTED TOR_PROCESS_EXIT TOR_CONTROL_READY TOR_CONTROL_COOKIE_WAIT TOR_CONTROL_PERMISSION TOR_CONTROL_REFUSED TOR_CONTROL_TIMEOUT TOR_CONTROL_AUTH TOR_CONTROL_PROTOCOL TOR_CONTROL_UNAVAILABLE TOR_BOOTSTRAP TOR_LOG_BOOTSTRAP TOR_WAIT TOR_BOOTSTRAP_TIMEOUT TOR_READY TOR_CLOCK_SIGNAL TOR_CERTIFICATE_SIGNAL TOR_TLS_SIGNAL TOR_NETWORK_UNREACHABLE_SIGNAL TOR_CONNECTION_REFUSED_SIGNAL TOR_CONNECTION_TIMEOUT_SIGNAL TOR_WARNING_OTHER TLS_CONFIGURATION_FAILED TLS_P2P_STARTED TLS_RESOURCE_STARTED TLS_P2P_EXIT TLS_RESOURCE_EXIT TLS_LISTENERS_READY TLS_LISTENER_TIMEOUT PREFLIGHT_FAILED NO_ACTIVATION_AUTHORIZATION ENDPOINT_READY ENDPOINT_ERROR INTERNAL_ERROR CANCELLED OWNED_CLEANUP_COMPLETE CLEANUP_FAILED'.split())
CODES.add('OFFLINE_CHECK_OK')

class Failure(ValueError):
    def __init__(self,code):self.code=code;super().__init__(code)

class Diagnostics:
    def __init__(self,home):
        parent=private_dir(home/'diagnostics')
        self.home=parent/('run-'+str(time.time_ns()));self.home.mkdir(mode=0o700)
        self.path=self.home/'events.jsonl';c.write_private(self.path,b'')
        self.lock=threading.Lock();self.started=time.monotonic();self.last={};self.count=0;self.progress=None;self.stage='OTHER'
        print('PRIVATE_DIAGNOSTICS',self.home,flush=True);self.event('SESSION_START')
    def event(self,code,progress=None,stage=None,reason=None,exit_code=None):
        if code not in CODES:raise ValueError('DIAGNOSTIC_CODE')
        if progress is not None and (type(progress) is not int or not 0<=progress<=100):raise ValueError('DIAGNOSTIC_PROGRESS')
        if stage is not None and stage not in STAGES|{'OTHER'}:raise ValueError('DIAGNOSTIC_STAGE')
        if reason is not None and reason not in REASONS|{'OTHER'}:raise ValueError('DIAGNOSTIC_REASON')
        if exit_code is not None and (type(exit_code) is not int or not -255<=exit_code<=255):exit_code=None
        values=dict(code=code,progress=progress,stage=stage,reason=reason,exit_code=exit_code)
        with self.lock:
            if code!='TOR_WAIT' and values==self.last.get(code):return
            self.last[code]=values
            if code=='TOR_BOOTSTRAP':self.progress=progress;self.stage=stage
            raw=(json.dumps(dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_ms=round(1000*(time.monotonic()-self.started)),**values),sort_keys=True)+'\n').encode()
            if self.count>=512:return
            fd=os.open(self.path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
            try:
                stat=os.fstat(fd)
                if stat.st_uid!=os.getuid() or stat.st_mode&0o077 or stat.st_nlink!=1:raise ValueError('DIAGNOSTIC_PERMISSION')
                if stat.st_size+len(raw)>131072:return
                os.write(fd,raw);self.count+=1
            finally:os.close(fd)
            print('N2_DIAG',raw.decode().strip(),flush=True)
    def finish(self,code):
        if code not in CODES:raise ValueError('DIAGNOSTIC_CODE')
        save_json(self.home/'summary.json',dict(result=code,progress=self.progress,stage=self.stage,events=self.count,raw_output_saved=False))

def bootstrap(raw):
    match=re.search(rb'^250[- ]status/bootstrap-phase=(?:NOTICE|WARN) BOOTSTRAP PROGRESS=(\d{1,3}) TAG=([a-z0-9_]+)(?: |\r?$)',raw,re.M)
    if not raw.endswith(b'250 OK\r\n') or not match or not 0<=int(match[1])<=100:raise Failure('TOR_CONTROL_PROTOCOL')
    stage=match[2].decode();reason=re.search(rb'\bREASON=([A-Z_]+)\b',raw)
    return dict(progress=int(match[1]),stage=stage if stage in STAGES else 'OTHER',reason=reason[1].decode() if reason and reason[1].decode() in REASONS else 'OTHER')

def log_observation(raw,diag):
    # Treat arbitrary bytes as untrusted. Never forward SUMMARY, WARNING, peer IP,
    # paths, certificates, cookie, process arguments or arbitrary exception strings.
    match=re.search(rb'Bootstrapped (\d{1,3})% \(([a-z0-9_]+)\)',raw)
    if match and 0<=int(match[1])<=100:
        stage=match[2].decode();diag.event('TOR_LOG_BOOTSTRAP',progress=int(match[1]),stage=stage if stage in STAGES else 'OTHER')
    lower=raw.lower()
    for needles,code in ((('clock skew','clock is','clock jumped'),'TOR_CLOCK_SIGNAL'),(('certificate has expired','certificate is not yet valid','certificate validation'),'TOR_CERTIFICATE_SIGNAL'),(('tls error','tls handshake'),'TOR_TLS_SIGNAL'),(('network is unreachable','no route to host'),'TOR_NETWORK_UNREACHABLE_SIGNAL'),(('connection refused',),'TOR_CONNECTION_REFUSED_SIGNAL'),(('connection timed out',),'TOR_CONNECTION_TIMEOUT_SIGNAL')):
        if any(n.encode() in lower for n in needles):diag.event(code);return
    if b'[warn]' in lower or b'[err]' in lower:diag.event('TOR_WARNING_OTHER')

class DiagnosticTor(OwnedTor):
    def __init__(self,binary,config,diag):super().__init__(binary,config);self.diag=diag;self.reader=None
    def verify(self):
        try:result=subprocess.run([str(self.binary),'-f',str(self.config),'--verify-config'],capture_output=True,timeout=10)
        except subprocess.TimeoutExpired:raise Failure('TOR_VERIFY_TIMEOUT') from None
        if result.returncode:
            log_observation((result.stdout+result.stderr)[-16384:],self.diag);raise Failure('TOR_CONFIG_INVALID')
        self.diag.event('CONFIG_VERIFIED')
    def start(self):
        if self.process is not None and self.process.poll() is None:raise Failure('TOR_SPAWN_FAILED')
        self.verify();parent=os.getpid()
        try:self.process=subprocess.Popen([str(self.binary),'-f',str(self.config)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,preexec_fn=lambda:child_parent_guard(parent))
        except OSError:raise Failure('TOR_SPAWN_FAILED') from None
        self.diag.event('TOR_PROCESS_STARTED')
        def drain():
            pending=b''
            try:
                while True:
                    chunk=self.process.stdout.read1(1024)
                    if not chunk:break
                    for part in chunk.splitlines(keepends=True):
                        pending=(pending+part)[-4096:]
                        if pending.endswith(b'\n'):log_observation(pending,self.diag);pending=b''
                if pending:log_observation(pending,self.diag)
            except (OSError,ValueError):pass
        self.reader=threading.Thread(target=drain,daemon=True);self.reader.start()
    def close(self):
        super().close()
        if self.reader:self.reader.join(timeout=1)
        if self.process and self.process.stdout:self.process.stdout.close()

def children_alive(children,diag):
    for purpose,process in children:
        code=process.poll()
        if code is not None:
            label='TLS_'+purpose.upper()+'_EXIT';diag.event(label,exit_code=code);raise Failure(label)

def wait_bootstrap(tor,children,diag,seconds=180,clock=time.monotonic,sleep=time.sleep):
    if not 0<seconds<=180:raise ValueError('BOOTSTRAP_BOUND')
    end=clock()+seconds;last_valid=None;control_ok=False;heartbeat=clock()
    while clock()<end:
        children_alive(children,diag)
        code=tor.process.poll()
        if code is not None:diag.event('TOR_PROCESS_EXIT',exit_code=code);raise Failure('TOR_PROCESS_EXIT')
        try:
            observed=bootstrap(tor.control('GETINFO status/bootstrap-phase'));last_valid=clock();control_ok=True
            diag.event('TOR_CONTROL_READY');diag.event('TOR_BOOTSTRAP',**observed)
            if clock()>=end:break # a late reply must not extend acceptance
            if observed['progress']==100 and observed['stage']=='done':diag.event('TOR_READY');return
        except (OSError,ValueError) as error:
            control_ok=False
            if isinstance(error,FileNotFoundError):label='TOR_CONTROL_COOKIE_WAIT'
            elif isinstance(error,PermissionError):label='TOR_CONTROL_PERMISSION'
            elif isinstance(error,ConnectionRefusedError):label='TOR_CONTROL_REFUSED'
            elif isinstance(error,TimeoutError):label='TOR_CONTROL_TIMEOUT'
            elif str(error)=='TOR_CONTROL_AUTH':label='TOR_CONTROL_AUTH'
            else:label='TOR_CONTROL_PROTOCOL'
            diag.event(label)
            if label in ('TOR_CONTROL_PERMISSION','TOR_CONTROL_AUTH'):raise Failure(label) from None
        if clock()>=heartbeat+10:
            diag.event('TOR_WAIT',progress=diag.progress,stage=diag.stage);heartbeat=clock()
        sleep(min(.3,max(0,end-clock())))
    label='TOR_CONTROL_UNAVAILABLE' if last_valid is None or not control_ok else 'TOR_BOOTSTRAP_TIMEOUT'
    diag.event(label,progress=diag.progress,stage=diag.stage);raise Failure(label)
