"""Explicit public-source allowlist; additive ZIP and reproducible hash manifest."""
from pathlib import Path
import hashlib,json,zipfile,importlib.util,tempfile
ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'build/n2-deployment'
FILES=['deploy/n2/common/'+name for name in ('n2_operator.py','n2_transport.py','n2_tls.py','n2_apply_patch.py','p2p_channel.py')]
FILES += ['docs/privacy-network/n2/'+name for name in ('DEPLOYMENT_PATCH_2026-10-10.md','DEPLOYMENT_PATCH_RESULTS.md')]

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    files={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in FILES}
    manifest=dict(version=1,source_base_commit='93f3e6f0a964f9d995d15c2e0346e5ec97801b5d',mode='ADDITIVE_ONLY_NO_OVERWRITE',files=files)
    archive=OUT/'PrivacyNetwork-N2-operator-patch-20261010.zip'
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name in sorted(FILES):
            raw=(ROOT/name).read_bytes()
            if b'-----BEGIN PRIVATE KEY-----' in raw or b'-----BEGIN RSA PRIVATE KEY-----' in raw:raise ValueError('SECRET_IN_PACKAGE')
            info=zipfile.ZipInfo(name,date_time=(2026,10,10,0,0,0));info.external_attr=0o100600<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,raw)
        info=zipfile.ZipInfo('N2_PATCH_MANIFEST.json',date_time=(2026,10,10,0,0,0));info.external_attr=0o100600<<16;info.compress_type=zipfile.ZIP_DEFLATED
        z.writestr(info,json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    sha=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(sha+'  '+archive.name+'\n')
    (OUT/'n2_apply_patch.py').write_bytes((ROOT/'deploy/n2/common/n2_apply_patch.py').read_bytes())
    spec=importlib.util.spec_from_file_location('installer',ROOT/'deploy/n2/common/n2_apply_patch.py');installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
    # Extraction is tested only in disposable SOURCE, never the authoritative tree.
    with tempfile.TemporaryDirectory(prefix='n2-patch-check-') as temporary:
        source=Path(temporary);sentinel=source/'N2_SOURCE_MANIFEST.json';sentinel.write_bytes(b'unchanged baseline manifest')
        assert installer.apply(archive,source,sha)==len(FILES)
        assert installer.apply(archive,source,sha)==0
        assert sentinel.read_bytes()==b'unchanged baseline manifest'
        assert all(hashlib.sha256((source/name).read_bytes()).hexdigest()==value for name,value in files.items())
    evidence=dict(archive=str(archive.relative_to(ROOT)),sha256=sha,bytes=archive.stat().st_size,files=len(files),installer_sha256=files['deploy/n2/common/n2_apply_patch.py'],extraction='PASS',second_application='NO_CHANGES',existing_manifest='UNCHANGED',contains_binaries=False,contains_private_state=False,manifest=manifest)
    (ROOT/'docs/evidence/privacy-network-n2-deployment-patch/package.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({k:v for k,v in evidence.items() if k!='manifest'},indent=2))
if __name__=='__main__':main()
