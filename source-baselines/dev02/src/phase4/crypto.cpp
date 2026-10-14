// Private pipe adapter to unmodified pinned Monero construction/scanning routines.
// Input/output contain wallet metadata: never record these streams as evidence.
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_basic/tx_extra.h"
#include "device/device.hpp"
#include "ringct/rctSigs.h"
#include "ringct/bulletproofs_plus.h"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <sodium.h>
#include <iostream>
#include <chrono>
#include <set>
using namespace cryptonote;
using J=rapidjson::Value;
std::string hx(const void* v,size_t n){static const char d[]="0123456789abcdef";std::string s;auto p=(const unsigned char*)v;for(size_t i=0;i<n;++i){s+=d[p[i]>>4];s+=d[p[i]&15];}return s;}
template<class T>std::string hx(const T& v){return hx(&v,sizeof(v));}
std::string uh(std::string s){if(s.size()%2||s.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("hex");std::string b;for(size_t i=0;i<s.size();i+=2)b+=char(std::stoul(s.substr(i,2),nullptr,16));return b;}
template<class T>T read(const J& v){if(!v.IsString())throw std::runtime_error("type");auto b=uh(v.GetString());if(b.size()!=sizeof(T))throw std::runtime_error("length");T t;memcpy(&t,b.data(),sizeof(t));return t;}
void need(bool b){if(!b)throw std::runtime_error("request");}
void point(const crypto::public_key& p){need(crypto_core_ed25519_is_valid_point((const unsigned char*)&p)==1);}
auto started(){return std::chrono::steady_clock::now();}
double ms(std::chrono::steady_clock::time_point t){return std::chrono::duration<double,std::milli>(started()-t).count();}
struct Item{transaction tx;size_t index;uint64_t global_index,height,unlock;bool coinbase,pending=false;uint32_t address_index=0;crypto::public_key P; rct::key commitment;bool owned=false,spent=false,reserved=false;uint64_t amount=0; rct::key mask;crypto::key_image image{};};
int main(){
 try{
  need(sodium_init()>=0);std::string line;need(bool(std::getline(std::cin,line))&&line.size()<32*1024*1024);
  rapidjson::Document q; q.Parse(line.c_str());need(q.IsObject()&&q.HasMember("op")&&q["op"].IsString());
  auto op=std::string(q["op"].GetString());rapidjson::Document out;out.SetObject();auto& a=out.GetAllocator();
  auto str=[&](const char* name,const std::string& s){out.AddMember(J(name,a),J(s.c_str(),a),a);};
  if(op=="benchmark"){
   unsigned repeat=q.HasMember("repeat")?q["repeat"].GetUint():1;need(repeat>0&&repeat<=300);J proving(rapidjson::kArrayType),signing(rapidjson::kArrayType);
   for(unsigned trial=0;trial<repeat;++trial){
   // Controlled standalone primitive probes, not a decomposition of the
   // transaction constructor. Disposable native randomness never leaves here.
   auto mask=rct::skGen();auto t=started();auto proof=rct::bulletproof_plus_PROVE(std::vector<uint64_t>{123456789,987654321},rct::keyV{mask,rct::skGen()});
   auto proof_ms=ms(t);proving.PushBack(proof_ms,a);if(trial==0)out.AddMember("bulletproof_plus_two_outputs_ms",proof_ms,a);need(rct::bulletproof_plus_VERIFY(proof));
   rct::ctkeyV ring;auto p=rct::skGen();auto realmask=rct::skGen();auto offsetmask=rct::skGen();auto offset=rct::commit(1000000000,offsetmask);
   for(size_t n=0;n<16;++n)ring.push_back(rct::ctkey{rct::scalarmultBase(n==7?p:rct::skGen()),rct::commit(1000000000,n==7?realmask:rct::skGen())});
   auto message=rct::skGen();t=started();auto sig=rct::proveRctCLSAGSimple(message,ring,rct::ctkey{p,realmask},offsetmask,offset,7,hw::get_device("default"));
   auto sign_ms=ms(t);signing.PushBack(sign_ms,a);if(trial==0)out.AddMember("clsag_ring16_ms",sign_ms,a);need(rct::verRctCLSAGSimple(message,sig,ring,offset));
   }out.AddMember("proving_samples_ms",proving,a);out.AddMember("signing_samples_ms",signing,a);
  }else if(op=="block-reward"||op=="block-transaction"||op=="block-duplicate"){
   block b;auto raw=uh(q["block"].GetString());need(parse_and_validate_block_from_blob(raw,b)&&block_to_blob(b)==raw);
   if(op=="block-reward"){++b.miner_tx.vout.at(0).amount;b.miner_tx.invalidate_hashes();}
   else if(op=="block-duplicate"){need(b.tx_hashes.size()==1);b.tx_hashes.push_back(b.tx_hashes.front());}
   else{transaction tx;auto body=uh(q["transaction"].GetString());need(parse_and_validate_tx_from_blob(body,tx));b.tx_hashes={get_transaction_hash(tx)};}
   b.invalidate_hashes();auto blob=block_to_blob(b);str("block",hx(blob.data(),blob.size()));
  }else if(op=="mutate"||op=="inspect"){
   transaction tx;auto raw=uh(q["transaction"].GetString());need(parse_and_validate_tx_from_blob(raw,tx)&&tx_to_blob(tx)==raw);
   if(op=="mutate"){
    auto c=std::string(q["case"].GetString());auto& r=tx.rct_signatures;auto& in=boost::get<txin_to_key>(tx.vin[0]);
    if(c=="authorization")r.p.CLSAGs[0].s[0]=rct::identity();
    else if(c=="commitment")r.p.pseudoOuts[0]=rct::scalarmultBase(rct::skGen());
    else if(c=="range")r.p.bulletproofs_plus[0].A=rct::scalarmultBase(rct::skGen());
    else if(c=="ciphertext")r.ecdhInfo[0].amount.bytes[0]^=1;
    else if(c=="ring")in.key_offsets[1]=0;
    else if(c=="outside-ring")in.key_offsets[15]=UINT64_MAX;
    else if(c=="immature") {for(auto& k:in.key_offsets)k=1;in.key_offsets[0]=q["index"].GetUint64();}
    else if(c=="destination")boost::get<txout_to_key>(tx.vout[0].target).key=crypto::null_pkey;
    else if(c=="version")tx.version=3;
    else if(c=="fee")r.txnFee++;
    else if(c=="excess-fee")r.txnFee=1000000000001ULL;
    else if(c=="image")in.k_image=crypto::key_image{};
    else if(c=="duplicate-image"){need(tx.vin.size()>1);boost::get<txin_to_key>(tx.vin[1]).k_image=in.k_image;}
    else throw std::runtime_error("case");
    tx.invalidate_hashes();str("transaction",hx(tx_to_blob(tx).data(),tx_to_blob(tx).size()));
   }else{
    out.AddMember("version",tx.version,a);out.AddMember("scheme",tx.rct_signatures.type,a);out.AddMember("fee",tx.rct_signatures.txnFee,a);
    J amounts(rapidjson::kArrayType),keys(rapidjson::kArrayType);for(const auto& v:tx.vout){amounts.PushBack(v.amount,a);keys.PushBack(J(hx(boost::get<txout_to_key>(v.target).key).c_str(),a),a);}
    out.AddMember("public_amounts",amounts,a);out.AddMember("one_time_keys",keys,a);str("image",hx(boost::get<txin_to_key>(tx.vin[0]).k_image));
    out.AddMember("inputs",uint64_t(tx.vin.size()),a);out.AddMember("outputs",uint64_t(tx.vout.size()),a);
    J images(rapidjson::kArrayType);for(const auto& input:tx.vin)images.PushBack(J(hx(boost::get<txin_to_key>(input).k_image).c_str(),a),a);out.AddMember("images",images,a);
   }
  }else{
   account_keys keys{};keys.m_view_secret_key=read<crypto::secret_key>(q["view"]);keys.m_account_address.m_spend_public_key=read<crypto::public_key>(q["public"]);point(keys.m_account_address.m_spend_public_key);
   need(crypto::secret_key_to_public_key(keys.m_view_secret_key,keys.m_account_address.m_view_public_key));point(keys.m_account_address.m_view_public_key);
   bool full=q.HasMember("spend");if(full){keys.m_spend_secret_key=read<crypto::secret_key>(q["spend"]);crypto::public_key B;need(crypto::secret_key_to_public_key(keys.m_spend_secret_key,B)&&B==keys.m_account_address.m_spend_public_key);}
   auto& device=hw::get_device("default");std::unordered_map<crypto::public_key,subaddress_index> addresses;
   auto count=q["count"].GetUint();need(count>0&&count<=10000);for(uint32_t n=0;n<count;++n)addresses.emplace(device.get_subaddress_spend_public_key(keys,{0,n}),subaddress_index{0,n});
   std::set<std::string> spent;for(const auto& v:q["images"].GetArray())spent.insert(v.GetString());
   std::set<std::string> reserved;if(q.HasMember("pool_images"))for(const auto& v:q["pool_images"].GetArray())reserved.insert(v.GetString());
   std::vector<Item> items;std::unordered_map<uint64_t,size_t> positions;J output_counts(rapidjson::kArrayType);uint64_t undecodable=0,next_index=0;auto scan_start=started();
   for(const auto& record:q["chain"].GetArray()){
    transaction tx;auto raw=uh(record["transaction"].GetString());need(parse_and_validate_tx_from_blob(raw,tx)&&tx_to_blob(tx)==raw);auto height=record["height"].GetUint64();bool cb=record["coinbase"].GetBool();
    auto R=get_tx_pub_key_from_extra(tx);auto additional=get_additional_tx_pub_keys_from_extra(tx);point(R);
    // Sparse construction retains canonical global ring indices. Scan requests
    // cannot supply offsets; the Python pager assigns those after native parsing.
    uint64_t base=next_index;if(record.HasMember("global_offset")){need(op=="build"&&record["global_offset"].IsUint64());base=record["global_offset"].GetUint64();need(base>=next_index);}
    need(tx.vout.size()<=UINT64_MAX-base);next_index=base+tx.vout.size();output_counts.PushBack(uint64_t(tx.vout.size()),a);
    for(size_t i=0;i<tx.vout.size();++i){
     Item x;x.tx=tx;x.index=i;x.global_index=base+i;need(positions.emplace(x.global_index,items.size()).second);x.height=height;x.unlock=height+(cb?60:10);x.coinbase=cb;x.pending=record.HasMember("pending")&&record["pending"].GetBool();x.P=boost::get<txout_to_key>(tx.vout[i].target).key;
     x.commitment=cb?rct::zeroCommit(tx.vout[i].amount):tx.rct_signatures.outPk.at(i).mask;
     std::vector<crypto::public_key> candidates{R};if(!additional.empty()){need(additional.size()==tx.vout.size());candidates.push_back(additional[i]);}
     for(const auto& candidate:candidates){crypto::key_derivation d;need(crypto::generate_key_derivation(candidate,keys.m_view_secret_key,d));crypto::public_key D;need(crypto::derive_subaddress_public_key(x.P,d,i,D));
      if(!addresses.count(D))continue;x.owned=true;x.address_index=addresses.at(D).minor;
      if(cb){x.amount=tx.vout[i].amount;x.mask=rct::identity();}else{crypto::ec_scalar sk;crypto::derivation_to_scalar(d,i,sk);rct::key amountkey;memcpy(&amountkey,&sk,32);
       try{x.amount=rct::decodeRctSimple(tx.rct_signatures,amountkey,i,x.mask,device);}catch(...){x.owned=false;++undecodable;break;}}
      if(full){keypair ephemeral;need(generate_key_image_helper(keys,addresses,x.P,R,additional,i,ephemeral,x.image,device));x.spent=spent.count(hx(x.image));x.reserved=reserved.count(hx(x.image));}break;
     }items.push_back(x);
    }
   }
   out.AddMember("scan_ms",ms(scan_start),a);out.AddMember("scanned_outputs",uint64_t(items.size()),a);out.AddMember("undecodable_owned_outputs",undecodable,a);
   if(op=="scan"){
    J owned(rapidjson::kArrayType),eligible(rapidjson::kArrayType);auto height=q["height"].GetUint64();
    for(size_t i=0;i<items.size();++i){auto& x=items[i];if(!x.pending&&x.unlock<=height+1)eligible.PushBack(uint64_t(i),a);if(!x.owned)continue;
     J v(rapidjson::kObjectType);v.AddMember("global_index",uint64_t(i),a);v.AddMember("amount",x.amount,a);v.AddMember("height",x.height,a);v.AddMember("unlock",x.unlock,a);v.AddMember("spent",full?J(x.spent):J(rapidjson::kNullType),a);v.AddMember("reserved",full?J(x.reserved):J(rapidjson::kNullType),a);v.AddMember("pending",x.pending,a);v.AddMember("coinbase",x.coinbase,a);v.AddMember("address_index",x.address_index,a);if(full)v.AddMember("image",J(hx(x.image).c_str(),a),a);v.AddMember("output_index",uint64_t(x.index),a);v.AddMember("transaction",J(hx(get_transaction_hash(x.tx)).c_str(),a),a);owned.PushBack(v,a);}
    out.AddMember("owned",owned,a);out.AddMember("eligible",eligible,a);out.AddMember("record_outputs",output_counts,a);
   }else if(op=="build"){
    need(full&&q["sources"].IsArray()&&q["sources"].Size()>0&&q["sources"].Size()<=8&&q["destinations"].IsArray()&&q["destinations"].Size()>0&&q["destinations"].Size()<=15);
    auto fee=q["fee"].GetUint64();need(fee>0&&fee<=1000000000000ULL);uint64_t total=0,payments=0;std::set<uint64_t> selected;
    std::vector<tx_source_entry> sources;
    for(const auto& selection:q["sources"].GetArray()){
     auto source=selection["source"].GetUint64();need(positions.count(source)&&selected.insert(source).second);auto& real=items[positions.at(source)];
     need(real.owned&&!real.spent&&!real.reserved&&!real.pending&&real.unlock<=q["height"].GetUint64()+1&&total<=UINT64_MAX-real.amount);total+=real.amount;
     tx_source_entry s{};s.real_output_in_tx_index=real.index;s.real_out_tx_key=get_tx_pub_key_from_extra(real.tx);s.real_out_additional_tx_keys=get_additional_tx_pub_keys_from_extra(real.tx);s.amount=real.amount;s.rct=true;s.mask=real.mask;
     need(selection["ring"].Size()==16);size_t found=0;uint64_t previous=0;
     for(const auto& j:selection["ring"].GetArray()){auto n=j.GetUint64();need(positions.count(n)&&(s.outputs.empty()||n>previous));previous=n;auto& x=items[positions.at(n)];need(!x.pending&&x.unlock<=q["height"].GetUint64()+1);s.outputs.emplace_back(n,rct::ctkey{rct::pk2rct(x.P),x.commitment});if(n==source){s.real_output=s.outputs.size()-1;++found;}}need(found==1);sources.push_back(s);
    }
    std::vector<tx_destination_entry> dests;
    for(const auto& recipient:q["destinations"].GetArray()){
     auto amount=recipient["amount"].GetUint64();need(amount>0&&payments<=UINT64_MAX-amount);payments+=amount;
     account_public_address to{};to.m_spend_public_key=read<crypto::public_key>(recipient["D"]);to.m_view_public_key=read<crypto::public_key>(recipient["C"]);point(to.m_spend_public_key);point(to.m_view_public_key);dests.emplace_back(amount,to,recipient["sub"].GetBool());
    }
    need(payments<total&&fee<total-payments);
    bool dedicated=q.HasMember("dedicated_change")&&q["dedicated_change"].GetBool();
    auto change=dedicated?device.get_subaddress(keys,{0,1}):keys.m_account_address;
    dests.emplace_back("PrivacyCoin/change",total-payments-fee,change,dedicated);
    const std::string domain="PrivacyCoinDev01/private-spend-v1-hardening";auto domainhash=crypto::cn_fast_hash(domain.data(),domain.size());
    // A fixed public profile marker in the upstream long-nonce envelope also
    // suppresses automatic dummy payment-ID insertion without modifying upstream.
    std::vector<uint8_t> extra;need(add_extra_nonce_to_tx_extra(extra,std::string(1,'\0')+std::string(reinterpret_cast<const char*>(&domainhash),32)));transaction tx;crypto::secret_key txkey;std::vector<crypto::secret_key> more;
    auto t=started();need(construct_tx_and_get_tx_key(keys,addresses,sources,dests,change,extra,tx,txkey,more,true,{rct::RangeProofPaddedBulletproof,4},false));out.AddMember("construction_ms",ms(t),a);
    auto blob=tx_to_blob(tx);str("transaction",hx(blob.data(),blob.size()));str("id",hx(get_transaction_hash(tx)));out.AddMember("bytes",uint64_t(blob.size()),a);
    // Private construction receipts for independent disposable-workload ground
    // truth. Never publish these keys or amount mappings outside that harness.
    J receipts(rapidjson::kArrayType),selected_indices(rapidjson::kArrayType);
    for(size_t i=0;i<dests.size();++i){const auto& d=dests[i];J receipt(rapidjson::kObjectType);receipt.AddMember("index",uint64_t(i),a);receipt.AddMember("amount",d.amount,a);receipt.AddMember("D",J(hx(d.addr.m_spend_public_key).c_str(),a),a);receipt.AddMember("C",J(hx(d.addr.m_view_public_key).c_str(),a),a);receipt.AddMember("change",d.original=="PrivacyCoin/change",a);receipts.PushBack(receipt,a);}
    for(const auto& selection:q["sources"].GetArray())selected_indices.PushBack(selection["source"].GetUint64(),a);
    out.AddMember("receipts",receipts,a);out.AddMember("selected_sources",selected_indices,a);
   }else throw std::runtime_error("op");
   sodium_memzero(&keys.m_spend_secret_key,sizeof(keys.m_spend_secret_key));sodium_memzero(&keys.m_view_secret_key,sizeof(keys.m_view_secret_key));
  }
  rapidjson::StringBuffer buffer;rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);out.Accept(writer);std::cout<<buffer.GetString()<<'\n';sodium_memzero(line.data(),line.size());return 0;
 }catch(...){std::cerr<<"private transaction request rejected\n";return 1;}
}
