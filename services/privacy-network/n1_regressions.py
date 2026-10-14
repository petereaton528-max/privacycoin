"""Reuse existing tests without overwriting any frozen evidence."""
from common import *
import argparse,importlib,time,unittest
OUT=ROOT/'docs/evidence/privacy-network-n1'
def main():
    p=argparse.ArgumentParser();p.add_argument('suite',choices=['core','supplement','repair','wallet']);a=p.parse_args();OUT.mkdir(parents=True,exist_ok=True)
    modules=dict(core='tests',supplement='supplement',repair='repair_tests',wallet='test_backend')
    module=importlib.import_module(modules[a.suite]);start=time.monotonic()
    if a.suite in ('core','supplement','repair'):
        module.OUT=OUT;module.main()
    elif a.suite=='wallet':
        folder=OUT/('wallet-'+str(time.time_ns()));previous=sys.argv
        try:
            sys.argv=[str(module.__file__),'--out',str(folder)];module.main()
        finally:sys.argv=previous
        report=json.loads((folder/'backend.json').read_bytes())
        if not report['checks']:raise AssertionError('No wallet checks ran')
        (folder/'timing.json').write_bytes(f.canonical(dict(seconds=time.monotonic()-start,checks=len(module.checks)))+b'\n')
    else:module.main()
if __name__=='__main__':main()
