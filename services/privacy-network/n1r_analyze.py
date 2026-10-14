"""Redacted fixed-label analysis of NEW N1-R Tor fixture failures only."""
from common import *
import argparse,re,time
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

def main():
    p=argparse.ArgumentParser();p.add_argument('evidence',type=Path);a=p.parse_args()
    assert a.evidence.resolve().parent==OUT.resolve()
    report=json.loads(a.evidence.read_bytes());home=Path(report['private_fixture'])
    assert home.is_relative_to(NATIVE/'build/privacy-network-n1-repair')
    patterns={'oom':"We're low on memory",'late_vote':'cutoff for received votes','insufficient_signatures':'good signatures','missing_directory':'no suitable HSDirs','descriptor_missing':'descriptor.*(?:not found|unavailable|failed)', 'end_reason':'reason (?:5|8|512|517|520)\\b','expired':'consensus.*expired','no_path':'(?:not enough|no suitable).*nodes'}
    logs=[]
    for log in sorted((home/'tor').glob('*/*.log')):
        text=log.read_text(errors='replace');lines=text.splitlines();events={}
        for label,pattern in patterns.items():
            selected=[x for x in lines if re.search(pattern,x,re.I)]
            events[label]=dict(count=len(selected),last_timestamps=[x[:19] for x in selected[-5:]])
        logs.append(dict(role=log.parent.name,kind='debug' if log.name.startswith('debug') else 'notice',bytes=log.stat().st_size,events=events))
    raw=dict(source=a.evidence.name,result=report.get('result'),failures=[x for x in report.get('events',[]) if x['result']!='PASS'],logs=logs,scope='Numeric counts and timestamps only; no raw private Tor log lines, identities, keys, capabilities or payloads')
    out=OUT/('analysis-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(raw)+b'\n');print(out.name)
if __name__=='__main__':main()
