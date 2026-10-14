"""New local inspection artifacts, explicit reviewed source overlay and GNU pair.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02'
sys.path.insert(0,str(ROOT))
from apps.network_v1.release import archive,verify
from apps.network_v1.licensing import assessment,require_redistributable,inspect_set
from apps.network_v1.rpc import VERSION

p=argparse.ArgumentParser();p.add_argument('--product',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
os.umask(0o077);a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
sha=lambda raw:hashlib.sha256(raw).hexdigest()
git=['git','--git-dir=/mnt/d/grok Projects/Privacy_Coin/.phase0-git/worktrees/Privacy_Coin_V1_20261011','--work-tree='+str(ROOT)]
head=subprocess.check_output(git+['rev-parse','HEAD'],text=True).strip()
base=ROOT/'out/sphlib-integrated1/distributions3';baseline=json.loads((base/'RELEASE.json').read_text())
original=base/'privacycoin-rc5-sphlib-source.zip';gnu=base/'privacycoin-rc5-gnu-corresponding-source-inspection.zip'
for file in (original,gnu):
    if sha(file.read_bytes())!=baseline['artifacts'][file.name]:raise ValueError('SEALED_BASE_ARCHIVE_CHANGED')
with zipfile.ZipFile(original) as z:source={n:z.read(n) for n in z.namelist() if n not in ('V1_MANIFEST.json','SOURCE_REVISION.json','LICENSE_COMPLIANCE.json')}
product_manifest=json.loads((a.product/'V1_MANIFEST.json').read_text())
product={}
for name,digest in product_manifest['files'].items():
    raw=(a.product/name).read_bytes()
    if sha(raw)!=digest:raise ValueError('PRODUCT_HASH_CHANGED')
    product[name]=raw
    if name in source or name.startswith(('apps/network_v1/','src/','scripts/devnet-gui/','services/privacy-network/','docs/network-v1/')) and not name.startswith('runtime/'):
        source[name]=raw
# Build and test commands accompany the source, without historical dirty files.
names=subprocess.check_output(git+['ls-files','tools/open_client','tools/mainnet_prepare'],text=True).splitlines()
for name in names:
    blob=subprocess.check_output(git+['show',head+':'+name])
    if (ROOT/name).read_bytes()!=blob:raise ValueError('UNCOMMITTED_BUILD_TOOL')
    source[name]=blob
modified=json.loads(product['OPEN_CLIENT_BUILD.json'])['modified_source']
for name,digest in modified.items():
    blob=subprocess.check_output(git+['show',head+':'+name])
    if sha(blob)!=digest or source[name]!=blob:raise ValueError('SOURCE_COMMIT_CORRESPONDENCE')
source.pop('CORRESPONDING_SOURCE.json',None)
build=a.product/'OPEN_NATIVE_BUILD.json'
source['OPEN_NATIVE_BUILD.json']=build.read_bytes()
source['SOURCE_REVISION.json']=(json.dumps(dict(source_commit=head,product_base_commit='785ed1c0981bda4651d7044de29c076f0abe5910',source_sha256={n:sha(v) for n,v in sorted(source.items())},overlay='Reviewed current committed product files over the sealed licensed source snapshot; no historical dirty files',network='PrivacyCoinDev02'),indent=2)+'\n').encode()
stem='privacycoin-dev02-preview'+VERSION.rsplit('.',1)[1]
source_name=stem+'-source.zip'
source_sha=archive(a.out/source_name,source,'source',[])
require_redistributable(assessment(source,'source'))
shutil.copyfile(gnu,a.out/gnu.name)
refs=json.loads(product['CORRESPONDING_SOURCE.json']);refs['archives']={source_name:source_sha,gnu.name:baseline['artifacts'][gnu.name]};refs['source_commit']=head
product['CORRESPONDING_SOURCE.json']=(json.dumps(refs,indent=2)+'\n').encode()
product['SOURCE_REVISION.json']=source['SOURCE_REVISION.json']
product['OPEN_NATIVE_BUILD.json']=build.read_bytes()
report=dict(version=VERSION,source_commit=head,native_sha256=sha(product['build/monero-linux/phase4/privacycoin-hardened-devnet']),native_windows=False,published=False,public_release_ready=False,archives={source_name:source_sha,gnu.name:refs['archives'][gnu.name]},compliance={})
for kind in ('linux-x86_64','windows-wsl2-x86_64'):
    name=stem+'-'+kind+'.zip'
    report['archives'][name]=archive(a.out/name,product,kind,product_manifest['executable'])
    verify(a.out/name);report['compliance'][name]=inspect_set(a.out/name,a.out)
    require_redistributable(report['compliance'][name]['license_assessment'])
    # Deterministic same-input packaging, independently of native repeatability.
    repeated=a.out/(name+'.repeat')
    digest=archive(repeated,product,kind,product_manifest['executable'])
    if digest!=report['archives'][name]:raise ValueError('REPACK_MISMATCH')
    report.setdefault('deterministic_repack',{})[name]=True
# No private state is an inclusion source; inspect the final contents as well.
findings=[];counts={}
for name in report['archives']:
    if name==gnu.name:continue # unchanged sealed companion, exact-byte prior audit retained
    with zipfile.ZipFile(a.out/name) as z:
        counts[name]=len(z.namelist())
        for member in z.namelist():
            raw=z.read(member)
            if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{20}',raw):findings.append(member)
if findings:raise ValueError('PRIVATE_KEY_PATTERN_IN_FINAL_CONTENTS')
report['final_content_scan']=dict(private_key_findings=findings,archive_members=counts,scope='Generic private-key patterns plus release forbidden private-file paths; does not prove unknown-secret absence; GNU companion exact hash retained')
(a.out/'RELEASE.json').write_text(json.dumps(report,indent=2)+'\n')
(a.out/'SHA256SUMS').write_text(''.join(digest+'  '+name+'\n' for name,digest in sorted(report['archives'].items())))
print(json.dumps(dict(result='PASS_LOCAL_PACKAGE_CORRESPONDENCE_COMPLIANCE_AND_REPACK',out=str(a.out),archives=report['archives'])))
