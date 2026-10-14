"""Existing frozen suites, fresh report destination only."""
from test_startup_diagnostics import *
import test_deployment_patch as deploy
import test_p2p_channel as p2p
import n1r_unit as n1

def main():
    begin=time.monotonic();suite=unittest.TestSuite()
    for cls in (deploy.Cases,p2p.Cases,n1.Cases,n1.BridgeCases,n1.RepairCases):suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    suite.addTest(n1.AdditionalBridgeCases('test_partial_body_cannot_block_worker_indefinitely'))
    with contextlib.redirect_stdout(io.StringIO()):result=unittest.TextTestRunner(verbosity=2).run(suite)
    (OUT/('neighbors-'+str(time.time_ns())+'.json')).write_bytes((json.dumps(dict(result='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,errors=len(result.errors),failures=len(result.failures),skipped=len(result.skipped),seconds=time.monotonic()-begin,public_tor=False),indent=2)+'\n').encode())
    if not result.wasSuccessful():raise SystemExit(1)
if __name__=='__main__':main()
