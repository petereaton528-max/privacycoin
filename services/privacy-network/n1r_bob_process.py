"""Independent actual Bob CLI process using only encrypted retrieval authority."""
from common import *
from n1_runtime import N1Runtime
import argparse,subprocess,time
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

def main():
    c.harden();p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);a=p.parse_args()
    assert a.home.is_relative_to(NATIVE/'build/privacy-network-n1-repair')
    r=None;checks=[];report={};start=time.monotonic()
    try:
        r=N1Runtime(a.home);r.local.session.close()
        plain=b'N1 disposable private Tor resource trial\n'*100
        data=next(load_json(path) for path in r.client.home.glob('*.upload') if load_json(path)['bundle']['plain_hash']==digest(plain))
        password=token().encode();prefix=a.home/('bob-process-'+str(time.time_ns()))
        source=prefix.with_suffix('.bundle');destination=prefix.with_suffix('.output')
        r.client.export(data['bundle']['quote'],source,password)
        cmd=[sys.executable,str(Path(__file__).with_name('n1_retrieve.py')),'--socks-port',str(r.tor.socks_port)]
        def child(path,pw,dest):
            result=subprocess.run(cmd,input=str(path).encode()+b'\n'+pw+b'\n'+str(dest).encode()+b'\n',capture_output=True,timeout=120,start_new_session=True)
            assert password not in result.stdout+result.stderr
            return result
        result=child(source,password,destination)
        assert result.returncode==0 and digest(c.read_private(destination))==digest(plain)
        checks.append('actual separate Bob CLI process recovers exact original SHA256 through real Tor')
        assert r.local.session.wallet is None;checks.append('payer signer remains locked; Bob subprocess receives no wallet/password/key arguments')
        rejected=prefix.with_suffix('.wrong-output');result=child(source,b'invalid-disposable-password',rejected)
        assert result.returncode!=0 and not rejected.exists();checks.append('wrong password in separate Bob process creates no output')
        corrupted=prefix.with_suffix('.corrupt-bundle');raw=bytearray(c.read_private(source));raw[len(raw)//2]^=1;c.write_private(corrupted,bytes(raw))
        result=child(corrupted,password,rejected)
        assert result.returncode!=0 and not rejected.exists();checks.append('corrupted encrypted bundle in separate Bob process creates no output')
        result=child(source,password,destination)
        assert result.returncode!=0 and digest(c.read_private(destination))==digest(plain);checks.append('separate Bob process cannot overwrite an existing recovered file')
        report['result']='PASS'
    except Exception as error:report.update(result='FAIL',error_type=type(error).__name__)
    finally:
        if r:r.close()
        report.update(checks=checks,passed=len(checks),seconds=time.monotonic()-start,private_fixture=str(a.home),scope='Actual same-computer separate Bob CLI with private stdin, no new payment/mining, no physical-host or human acceptance')
        out=OUT/('bob-process-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print(report['result'],out.name)
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
