"""One persistent child, anonymous pipes; no secrets in process arguments."""
from pathlib import Path
import io, json, os, queue, subprocess, threading, time

REJECTED='Backend unavailable or response rejected; submission may be UNKNOWN. Reopen and reconcile.'
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError(REJECTED)
        result[key]=value
    return result
def invalid_constant(_):raise ValueError(REJECTED)
class OperationRejected(ValueError):pass

class Bridge:
    def __init__(self, home=None, port=48081, timeout=120):
        if not 0<timeout<=120:raise ValueError('Invalid operation deadline')
        self.timeout=timeout
        script = Path(__file__).resolve().with_name('backend.py')
        if os.name == 'nt':
            mounted = '/mnt/'+script.drive[0].lower()+script.as_posix()[2:]
            command=['wsl.exe','-d','Ubuntu-24.04','-u','privacydev','--','python3',mounted]
        else: command=['python3',str(script)]
        if home: command += ['--home',str(home)]
        command += ['--port',str(port)]
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                      bufsize=0,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        self.process.stdout=io.BufferedReader(self.process.stdout)
        self.lock=threading.Lock(); self.closed=False
    def call(self, command, **fields):
        raw=json.dumps(dict(command=command,**fields),separators=(',',':')).encode()+b'\n'
        if len(raw)>16384: raise ValueError('Request too large')
        with self.lock:
            if self.closed: raise ValueError('Backend closed')
            replies=queue.Queue(maxsize=1);process=self.process
            def exchange():
                try:
                    remaining=memoryview(raw)
                    while remaining:
                        written=process.stdin.write(remaining)
                        if not written:raise OSError()
                        remaining=remaining[written:]
                    process.stdin.flush();replies.put(process.stdout.readline(1048577))
                except Exception:replies.put(None)
            threading.Thread(target=exchange,daemon=True).start();deadline=time.monotonic()+self.timeout
            while True:
                left=deadline-time.monotonic()
                if self.closed or left<=0:
                    self.close();raise ValueError(REJECTED)
                try:response=replies.get(timeout=min(.1,left));break
                except queue.Empty:pass
            try:
                if not response or len(response)>1048576 or not response.endswith(b'\n'):raise ValueError()
                result=json.loads(response,object_pairs_hook=unique,parse_constant=invalid_constant)
                if not isinstance(result,dict) or type(result.get('ok')) is not bool:raise ValueError()
                if not result['ok']:
                    if set(result)!={'ok','error'} or not isinstance(result['error'],str):raise ValueError()
                    raise OperationRejected()
                if set(result)!={'ok','result'} or not isinstance(result['result'],dict):raise ValueError()
                return result['result']
            except OperationRejected:raise ValueError(REJECTED) from None
            except Exception:
                self.close();raise ValueError(REJECTED) from None
    def close(self):
        self.closed=True
        try: self.process.stdin.close()
        except OSError: pass
        try: self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=2)
