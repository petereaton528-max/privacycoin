"""Reuse frozen acceptance code with NEW evidence/fixtures, no historical writes."""
from pathlib import Path
import argparse,importlib,json,os,sys,time,unittest
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
OUT=ROOT/'docs/evidence/privacy-network-n2'
def main():
    p=argparse.ArgumentParser();p.add_argument('suite',choices=['unit','core','supplement','repair','wallet','integration']);p.add_argument('--native-root',type=Path);a=p.parse_args();OUT.mkdir(parents=True,exist_ok=True);start=time.monotonic()
    if a.native_root:
        os.environ['PC_DEVNET_NATIVE_ROOT']=str(a.native_root)
        os.environ['PC_DEVNET_BUILD_MANIFEST']=str(a.native_root/'build/n2-native-manifest.json')
    if a.suite=='unit':
        import n1r_unit as m
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in (m.Cases,m.BridgeCases,m.RepairCases))
        suite.addTest(m.AdditionalBridgeCases('test_partial_body_cannot_block_worker_indefinitely'))
        r=unittest.TextTestRunner(verbosity=2).run(suite)
        (OUT/('n1-units-'+str(time.time_ns())+'.json')).write_text(json.dumps(dict(result='PASS' if r.wasSuccessful() else 'FAIL',tests=r.testsRun,failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped),seconds=time.monotonic()-start),indent=2))
        if not r.wasSuccessful():raise SystemExit(1)
    elif a.suite=='wallet':
        import test_backend as m
        folder=OUT/('wallet-'+str(time.time_ns()));sys.argv=[m.__file__,'--out',str(folder)];m.main()
        (folder/'timing.json').write_text(json.dumps(dict(seconds=time.monotonic()-start)))
    elif a.suite=='integration':
        import n1_tests as m
        from common import NATIVE
        m.OUT=OUT;m.FIXTURE=NATIVE/'build/privacycoin-n2-preparation';m.STARTING_HEAD='db3f4e1e6bf9d25001859423365b508a9a814dda'
        sys.argv=[m.__file__];m.main()
    else:
        m=importlib.import_module({'core':'tests','supplement':'supplement','repair':'repair_tests'}[a.suite]);m.OUT=OUT;m.main()
if __name__=='__main__':main()
