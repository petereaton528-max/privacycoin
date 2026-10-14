"""Publish fixed-format Tor OOM evidence without identities or private logs."""
from common import *
import re,time
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'
def main():
    reports=[]
    for evidence in sorted((ROOT/'docs/evidence/privacy-network-n1').glob('integration-*.json')):
        value=json.loads(evidence.read_bytes());home=Path(value['private_fixture']);assert home.is_relative_to(NATIVE/'build/privacy-network-n1')
        events=[]
        for log in (home/'tor').glob('*/notice.log'):
            for line in log.read_text(errors='replace').splitlines():
                if "We're low on memory (cell queues total alloc:" in line:
                    match=re.search(r'cell queues total alloc: (\d+).*tor compress total alloc: (\d+).*lzma: (\d+)',line)
                    if match:events.append(dict(role=log.parent.name,timestamp=line[:22],cell_bytes=int(match[1]),compression_bytes=int(match[2]),lzma_bytes=int(match[3])))
        reports.append(dict(evidence=evidence.name,result=value['result'],oom_events=len(events),first_events=events[:10]))
    owned=[]
    for home in (NATIVE/'build/privacy-network-n1-repair').glob('test-*'):
        for log in (home/'tor').glob('*/debug-*.log'):
            for line in log.read_text(errors='replace').splitlines():
                if "We're low on memory (cell queues total alloc:" in line:
                    match=re.search(r'cell queues total alloc: (\d+).*tor compress total alloc: (\d+).*lzma: (\d+)',line)
                    if match:owned.append(dict(role=log.parent.name,timestamp=line[:22],cell_bytes=int(match[1]),compression_bytes=int(match[2]),lzma_bytes=int(match[3])))
    out=OUT/('oom-evidence-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(dict(historical=reports,new_reproduction=owned,scope='Whitelisted numeric Tor diagnostic fields only; no raw private logs or identities'))+b'\n');print(out.name,len(owned))
if __name__=='__main__':main()
