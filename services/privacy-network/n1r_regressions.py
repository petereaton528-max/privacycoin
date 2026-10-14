"""Run established suites into a new evidence directory, no frozen writes."""
from common import *
import n1_regressions
if __name__=='__main__':
    n1_regressions.OUT=ROOT/'docs/evidence/privacy-network-n1-repair'
    n1_regressions.main()
