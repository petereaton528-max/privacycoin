"""Run unchanged acceptance expectations with new evidence/fixture roots."""
from common import *
from n1_diagnostics import Diagnostics
from n1_runtime import N1Runtime
import n1_tests,sys

class TracedRuntime(N1Runtime):
    def __init__(self,home,experimental_upstream=False):
        home=private_dir(home)
        super().__init__(home,experimental_upstream,Diagnostics(home/'client-diagnostics'))

if __name__=='__main__':
    n1_tests.OUT=ROOT/'docs/evidence/privacy-network-n1-repair'
    n1_tests.FIXTURE=NATIVE/'build/privacy-network-n1-repair'
    n1_tests.STARTING_HEAD='7b23fe66139add6a375ad1ee25104faa3c7cb7e2'
    n1_tests.N1Runtime=TracedRuntime
    n1_tests.main()
