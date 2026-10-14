// Real LMDB map exhaustion/retry and independent ordered-container oracle.
#include "phase4/ledger.h"
#include <algorithm>
#include <iostream>
#include <random>
#include <sys/stat.h>
using namespace pcdev;
static void require(bool ok,const char* name){if(!ok)throw std::runtime_error(name);}
int main(int argc,char** argv){try{
  if(argc!=2)throw std::runtime_error("new private fixture required");
  std::string path=argv[1];
  require(path.find("/home/privacydev/pc-v1-fixtures-rc4-")==0&&!std::filesystem::exists(path),"new private isolated path");umask(0077);
  BranchSet<std::string> index;std::set<std::string> oracle;
  std::vector<BranchSet<std::string>> snapshots;std::vector<std::set<std::string>> expected;
  std::vector<uint64_t> values(10000);std::iota(values.begin(),values.end(),0);std::mt19937 rng(42791);std::shuffle(values.begin(),values.end(),rng);
  for(auto n:values){auto key=std::to_string(n);require(index.insert(key).second==oracle.insert(key).second,"insert oracle");require(!index.insert(key).second,"duplicate oracle");
    if(oracle.size()%1000==0){snapshots.push_back(index);expected.push_back(oracle);}}
  for(size_t i=0;i<snapshots.size();++i){auto copy=snapshots[i];copy.insert("fork-only");require(!snapshots[i].count("fork-only")&&!index.count("fork-only"),"snapshot branch independence");
    std::vector<std::string> actual;for(const auto& k:snapshots[i])actual.push_back(k);
    require(actual==std::vector<std::string>(expected[i].begin(),expected[i].end()),"ordered iteration oracle");
    for(auto n:values)require(snapshots[i].count(std::to_string(n))==expected[i].count(std::to_string(n)),"snapshot lookup oracle");}
  BranchVector<uint64_t> output;for(auto n:values)output.push_back(n);auto old=output;output.push_back(99999);
  for(size_t i=0;i<values.size();++i)require(old[i]==values[i],"stable output index oracle");require(old.size()==10000&&output.size()==10001,"append snapshot independence");
  std::cout<<"PASS immutable_AVL_random_order_duplicate_iteration_10000_and_forks"<<std::endl;
  std::string tip;{
    Ledger ledger(path,3600,65536);auto timestamp=wall_time()-200*120;
    for(uint64_t h=1;h<=200;++h){crypto::public_key P,R;crypto::secret_key p,r;crypto::generate_keys(P,p);crypto::generate_keys(R,r);auto t=ledger.mining_template(P,timestamp+h*120,R);
      for(uint64_t n=0;;++n){t.block.nonce=n;if(phase0::pow_valid(ledger.hash(t.block,t.seed),t.difficulty))break;}
      tip=ledger.submit(cryptonote::block_to_blob(t.block));}
    require(ledger.tip().height==200,"map retry height");
  }
  require(std::filesystem::file_size(std::filesystem::path(path)/"data.mdb")>65536,"actual initial map exhausted");
  {Ledger ledger(path);require(ledger.tip().id==tip&&ledger.tip().height==200,"expanded map reload");}
  std::cout<<"PASS actual_64KiB_LMDB_MAP_FULL_atomic_retry_and_restart_200_blocks"<<std::endl;
  return 0;
}catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<std::endl;return 1;}}
