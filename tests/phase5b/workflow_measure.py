"""Existing isolated measurement plus complete process CPU, no secret output."""
from pathlib import Path
import importlib.util,json
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('workflow_measured_client',ROOT/'tests/phase5b/measure.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def emit(payload):
    result=json.loads(payload);result['complete_process_cpu_ms']=m.usage()*1000
    result['cpu_scope']='Python process since launch plus reaped native children, including wallet/cache decrypt and encrypted publication; final JSON emission excluded.'
    print(json.dumps(result))
m.print=emit
if __name__=='__main__':m.main()
