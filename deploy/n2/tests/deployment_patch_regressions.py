"""Reuse existing suites without changing their frozen evidence destinations."""
from test_deployment_patch import *
import test_p2p_channel as p2p
import n1r_unit as n1

def main():
    c.harden();start=time.monotonic()
    suite=unittest.TestSuite()
    for cls in (p2p.Cases,n1.Cases,n1.BridgeCases,n1.RepairCases):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    suite.addTest(n1.AdditionalBridgeCases('test_partial_body_cannot_block_worker_indefinitely'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (OUT/('regressions-'+str(time.time_ns())+'.json')).write_text(json.dumps(dict(result='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),seconds=time.monotonic()-start),indent=2))
    if not result.wasSuccessful():sys.exit(1)
if __name__=='__main__':main()
