"""Frozen neighboring suites, NEW connectivity evidence and disposable fixtures."""
from pathlib import Path
import sys
import run_regressions as runner
runner.OUT=Path(__file__).resolve().parents[3]/'docs/evidence/privacy-network-n2-connectivity'
if __name__=='__main__':
    if sys.argv[1:]==['integration']:
        import n1_tests as m
        from common import NATIVE
        m.OUT=runner.OUT;m.FIXTURE=NATIVE/'build/privacycoin-n2-connectivity';m.STARTING_HEAD='ce12009574353a5df850e4576a0c852c240032d5'
        sys.argv=[m.__file__];m.main()
    else:runner.main()
