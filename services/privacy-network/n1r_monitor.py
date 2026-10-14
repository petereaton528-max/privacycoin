"""Read-only bounded progress sampling of a known N1-R disposable fixture."""
from common import *
import argparse,time,datetime
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

def main():
    p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);a=p.parse_args()
    assert a.home.is_relative_to(NATIVE/'build/privacy-network-n1-repair')
    trace=sorted(a.home.glob('stress-trace-*'))[-1]
    events=[json.loads(line) for line in c.read_private(trace).splitlines()]
    codes={}
    for event in events:
        if event['event']=='request_error':codes[event['code']]=codes.get(event['code'],0)+1
    processes=[]
    for path in Path('/proc').iterdir():
        try:
            if not path.name.isdigit() or int(path.name)==os.getpid():continue
            args=(path/'cmdline').read_bytes().split(b'\0')
            if not any(x.startswith(str(a.home).encode()) for x in args):continue
            status=(path/'status').read_text();stat=(path/'stat').read_text().split()
            processes.append(dict(pid=int(path.name),rss_kib=next((int(x.split()[1]) for x in status.splitlines() if x.startswith('VmRSS:')),0),cpu_seconds=(int(stat[13])+int(stat[14]))/os.sysconf('SC_CLK_TCK'),fds=len(list((path/'fd').iterdir()))))
        except (OSError,ProcessLookupError):pass
    report=dict(at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),home_fixture=a.home.name,completed_http=sum(x['event']=='request_complete' for x in events),failed_attempt_codes=codes,connection_retries=sum(x['event']=='connection_retry' for x in events),owned_processes=len(processes),aggregate_rss_mib=sum(x['rss_kib'] for x in processes)/1024,fixture_bytes=sum(p.stat().st_size for p in a.home.rglob('*') if p.is_file() and not p.is_symlink()),processes=processes,scope='Known campaign fixture only, driver and idle provider B included; no payloads or authority')
    path=OUT/'progress.jsonl'
    if not path.exists() or path.stat().st_size<131072:
        with path.open('ab') as stream:stream.write(f.canonical(report)+b'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='processes'}))
if __name__=='__main__':main()
