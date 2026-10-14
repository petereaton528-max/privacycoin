"""Run unchanged V0.1 test expectations with new evidence destinations."""
from common import *
import argparse,importlib.util
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('suite',choices=['core','supplement']);a=p.parse_args()
    path=Path(__file__).with_name('tests.py' if a.suite=='core' else 'supplement.py');spec=importlib.util.spec_from_file_location('repair_frozen_suite',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    m.OUT=ROOT/'docs/evidence/privacy-network-repair/regressions'/a.suite;m.OUT.mkdir(parents=True,exist_ok=True);m.main()
