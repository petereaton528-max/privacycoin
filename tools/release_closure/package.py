"""Local owner-review packaging; explicit committed overlays, no publication.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
ROOT=Path(__file__).resolve().parents[2];PRIMARY=Path('/mnt/d/grok Projects/Privacy_Coin_V1_20261011')
base=PRIMARY/'out/production-integration-lab-final4-20261013'
build=Path('/home/privacydev/pc-release-closure-native-final5-20261013')
sha=lambda b:hashlib.sha256(b).hexdigest()
gd=(ROOT/'.git').read_text().strip().removeprefix('gitdir: ');gd='/mnt/'+gd[0].lower()+'/'+gd[3:].replace('\\','/')
git=['git','--git-dir='+gd,'--work-tree='+str(ROOT)]
head=subprocess.check_output(git+['rev-parse','HEAD'],text=True).strip()
product=base/'privacycoin-production-integration-lab-linux-wsl2.zip';source=base/'privacycoin-production-integration-source.zip'
assert sha(product.read_bytes())=='819dc24da82f6137be2ed32990ed9e33c828278e30d7a9f36360c32b9c8f4447'
assert sha(source.read_bytes())=='31452e26bf11bec039352bb2a7d6dc4bca12699b88f7f129a6295981fd998ad2'
with zipfile.ZipFile(product) as z:files={n:z.read(n) for n in z.namelist()}
with zipfile.ZipFile(source) as z:sources={n:z.read(n) for n in z.namelist()}
manifest=json.loads(files.pop('V1_MANIFEST.json'));assert all(sha(files[n])==h for n,h in manifest['files'].items())
names=subprocess.check_output(git+['diff','--name-only','f0b3847',head],text=True).splitlines()
overlays={}
for name in names:
    if not name.startswith(('apps/','src/','tests/','tools/')):continue
    raw=subprocess.check_output(git+['show',head+':'+name]);assert raw==(ROOT/name).read_bytes()
    files[name]=raw;sources[name]=raw;overlays[name]=sha(raw)
receipt=json.loads((build/'BUILD.json').read_text())
for name in ('node','ledger','wallet'):
    raw=(build/('draft-'+name)).read_bytes();assert sha(raw)==receipt[name]['binary_sha256']
    assert all(sha((ROOT/n).read_bytes())==h for n,h in receipt[name]['source_sha256'].items())
    files['candidate-native/full/draft-'+name]=raw
files['candidate-native/full/BUILD.json']=(build/'BUILD.json').read_bytes()
metadata=dict(version='0.4.0-owner-review.1',source_commit=head,production=False,default_tor=False,publication_authorized=False,modified_source=overlays,peer_budget_header_sha256=sha((ROOT/'src/phase4/peer_budget.h').read_bytes()),native_binary_sha256={n:receipt[n]['binary_sha256'] for n in ('node','ledger','wallet')})
# The sealed integration baseline changed its legacy native binary but retained
# the earlier inventory binding. Reconcile ONLY that known original-code binary
# against the baseline's separate build manifest; third-party bytes unchanged.
inventory=json.loads(files['docs/network-v1/LICENSE_INVENTORY.json'])
legacy='build/monero-linux/phase4/privacycoin-hardened-devnet';legacy_hash=sha(files[legacy])
binding=json.loads(files['build/v1-native-manifest.json'])
assert legacy_hash in binding['binary_sha256'].values()
rebinding=[]
for kind in ('linux-x86_64','windows-wsl2-x86_64'):
    requirement=inventory['component_requirements_by_kind'][kind]['files']
    assert requirement[legacy]=='d096a9bc215d8206463340c4e3ba5f6d65681dc090617dd1c25a39b7d30347d9'
    rebinding.append(dict(kind=kind,path=legacy,previous=requirement[legacy],actual=legacy_hash))
    requirement[legacy]=legacy_hash
files['COMPONENT_REBINDING.json']=(json.dumps(dict(corrections=rebinding,evidence='Exact sealed final4 artifact, its native build manifest and preserved corresponding-source set; no third-party binary replacement',new_candidate_dependencies=receipt['node']['dependencies_sha256']),indent=2)+'\n').encode()
files['docs/network-v1/LICENSE_INVENTORY.json']=(json.dumps(inventory,indent=2)+'\n').encode()
sources['docs/network-v1/LICENSE_INVENTORY.json']=files['docs/network-v1/LICENSE_INVENTORY.json'];sources['COMPONENT_REBINDING.json']=files['COMPONENT_REBINDING.json']
os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02';sys.path.insert(0,str(ROOT))
from apps.network_v1.licensing import assessment
sources['LICENSE_COMPLIANCE.json']=(json.dumps(assessment(sources,'source'),indent=2)+'\n').encode()
files['RELEASE_CANDIDATE.json']=(json.dumps(metadata,indent=2)+'\n').encode()
sources['RELEASE_CANDIDATE.json']=files['RELEASE_CANDIDATE.json'];sources['candidate-native/full/BUILD.json']=files['candidate-native/full/BUILD.json']
files['Launch-PC.sh']=files['Launch-Candidate-Fullnode.sh'].replace(b'privacycoin-mainnet-candidate-offline',b'pc-candidate-profile-owner-review-040')
files['OWNER-START.txt']=b'Owner review only, NOT approved Mainnet. Linux x86_64 or existing Ubuntu WSL2/WSLg. Run ./Launch-PC.sh --profile /absolute/path/to/public-lab-profile.json. Select the SAME public non-production profile on A and B. No wallet, private identity or Genesis is bundled. Existing data directories are never migrated silently. See OWNER_HANDOFF.md.\n'
for name in ('OWNER_HANDOFF.md','SECURITY_REVIEW.md'):
    files[name]=(ROOT/'tools/release_closure'/name).read_bytes();sources[name]=files[name]
def pack(path,items,executables=()):
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,raw in sorted(items.items()):
            i=zipfile.ZipInfo(name,(1980,1,1,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;i.external_attr=(0o100700 if name in executables else 0o100600)<<16;z.writestr(i,raw)
os.umask(0o077);a.out.mkdir(parents=True,exist_ok=False)
source_manifest=json.loads(sources.pop('V1_MANIFEST.json')) if 'V1_MANIFEST.json' in sources else dict(manifest,kind='source',executable=[])
sources['SOURCE_REVISION.json']=(json.dumps(dict(source_commit=head,source_sha256={n:sha(v) for n,v in sources.items() if n!='SOURCE_REVISION.json'},base_sha256=sha(source.read_bytes())),indent=2)+'\n').encode()
source_manifest['files']={n:sha(raw) for n,raw in sorted(sources.items())};sources['V1_MANIFEST.json']=(json.dumps(source_manifest,indent=2)+'\n').encode()
srcname='privacycoin-owner-review-source.zip';pack(a.out/srcname,sources)
gnu=base/'privacycoin-rc5-gnu-corresponding-source-inspection.zip';assert sha(gnu.read_bytes())=='4723b07b7135d3966d6c9cd141bf47a1fca57ac03e9781c33d761c9ae4291c9d';shutil.copyfile(gnu,a.out/gnu.name)
refs=json.loads(files['CORRESPONDING_SOURCE.json']);refs['archives']={srcname:sha((a.out/srcname).read_bytes()),gnu.name:sha(gnu.read_bytes())};refs['source_commit']=head
files['CORRESPONDING_SOURCE.json']=(json.dumps(refs,indent=2)+'\n').encode();files['SOURCE_REVISION.json']=sources['SOURCE_REVISION.json']
files['LICENSE_COMPLIANCE.json']=(json.dumps(assessment(files,manifest['kind']),indent=2)+'\n').encode()
manifest['files']={n:sha(v) for n,v in sorted(files.items())};files['V1_MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
name='privacycoin-owner-review-0.4.0-linux-wsl2.zip';pack(a.out/name,files,manifest['executable']);pack(a.out/(name+'.repeat'),files,manifest['executable'])
assert sha((a.out/name).read_bytes())==sha((a.out/(name+'.repeat')).read_bytes())
for n,raw in files.items():
    if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{20}',raw):raise ValueError('PRIVATE_KEY_IN_PACKAGE')
metadata['archives']={n:sha((a.out/n).read_bytes()) for n in (name,srcname,gnu.name)}
os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02';sys.path.insert(0,str(ROOT))
from apps.network_v1.licensing import inspect_set,require_redistributable
metadata['compliance']=inspect_set(a.out/name,a.out);require_redistributable(metadata['compliance']['license_assessment'])
(a.out/'RELEASE.json').write_text(json.dumps(metadata,indent=2)+'\n')
(a.out/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in metadata['archives'].items()))
print(json.dumps(metadata['archives']))
