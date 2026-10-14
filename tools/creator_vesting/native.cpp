// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
// Offline pipe harness. No sockets, P2P, RPC server or production network selector.
#ifndef PC_OFFLINE_CREATOR_VESTING
#error Offline candidate build required
#endif
#include "phase4/ledger.h"
#include "consensus/creator_vesting_draft.h"
#include "consensus/rule_versions.h"
#include "cryptonote_basic/tx_extra.h"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <iostream>
#include <memory>
namespace pcdev {
struct DraftProbe {
  static uint64_t transaction(Ledger& l,const std::string& raw,uint64_t height){
    auto state=l.tip().state;return l.validate_transaction(raw,state,height);
  }
};
}
int main(){
 using namespace pcdev;using namespace cryptonote;
 std::unique_ptr<Ledger> ledger;
 std::string line;
 while(std::getline(std::cin,line))try{
  if(line.size()>1024*1024)throw std::runtime_error("bounded request");
  rapidjson::Document q;q.Parse(line.c_str());if(!q.IsObject()||!q.HasMember("op")||!q["op"].IsString())throw std::runtime_error("request");
  rapidjson::Document out;out.SetObject();auto& a=out.GetAllocator();
  auto str=[&](const char* k,const std::string& v){out.AddMember(rapidjson::Value(k,a),rapidjson::Value(v.c_str(),a),a);};
  const std::string op=q["op"].GetString();
  if(op=="policy"){
    out.AddMember("activation",pc_rules::activation,a);out.AddMember("interval",creator_draft::interval,a);out.AddMember("total",creator_draft::total,a);out.AddMember("liquid",creator_draft::liquid,a);str("commitment",creator_draft::genesis_extra());
  }else if(op=="genesis"){
#ifdef PC_FINAL_GENESIS_HASH
    throw std::runtime_error("final Genesis cannot be generated or replaced");
#endif
    auto D=public_key(q["D"].GetString()),C=public_key(q["C"].GetString());crypto::public_key R;crypto::secret_key r;crypto::generate_keys(R,r);crypto::key_derivation deriv;
    if(!crypto::generate_key_derivation(C,r,deriv))throw std::runtime_error("derivation");
    block b{};b.major_version=16;b.miner_tx.version=2;b.miner_tx.vin.push_back(txin_gen{0});
    for(size_t i=0;i<17;++i){crypto::public_key P;if(!crypto::derive_public_key(deriv,i,D,P))throw std::runtime_error("output");b.miner_tx.vout.push_back(tx_out{creator_draft::amount(i),txout_to_key{P}});}
    add_tx_pub_key_to_extra(b.miner_tx,R);add_extra_nonce_to_tx_extra(b.miner_tx.extra,creator_draft::genesis_extra());
    if(q.HasMember("mutation")){
      std::string m=q["mutation"].GetString();
      if(m=="amount")++b.miner_tx.vout[0].amount;
      else if(m=="duplicate")b.miner_tx.vout[1].target=b.miner_tx.vout[0].target;
      else if(m=="unlock")b.miner_tx.unlock_time=1;
      else if(m=="overflow")b.miner_tx.vout[0].amount=UINT64_MAX;
      else if(m=="header")b.timestamp=1;
      else if(m=="policy"){b.miner_tx.extra.clear();add_tx_pub_key_to_extra(b.miner_tx,R);add_extra_nonce_to_tx_extra(b.miner_tx.extra,creator_draft::domain);}
      else throw std::runtime_error("mutation");
    }
    str("block",hex(block_to_blob(b).data(),block_to_blob(b).size()));str("hash",hex(get_block_hash(b)));
  }else if(op=="verify_genesis"||op=="reconstruct_genesis"){
    // Public canonical reconstruction: use published one-time output points,
    // never a public derivation of recipient spending/view secrets. A separate
    // private wallet scan establishes recipient ownership before approval.
    block b{};
    if(op=="reconstruct_genesis"){
      if(!q.HasMember("commitment")||!q["commitment"].IsString()||q["commitment"].GetString()!=creator_draft::genesis_extra()||
         !q.HasMember("R")||!q["R"].IsString()||!q.HasMember("outputs")||!q["outputs"].IsArray()||q["outputs"].Size()!=17)throw std::runtime_error("public genesis plan");
      b.major_version=16;b.miner_tx.version=2;b.miner_tx.vin.push_back(txin_gen{0});
      for(size_t i=0;i<17;++i){const auto& x=q["outputs"][i];
        if(!x.IsObject()||x.MemberCount()!=3||!x.HasMember("key")||!x["key"].IsString()||!x.HasMember("atomic")||!x["atomic"].IsUint64()||x["atomic"].GetUint64()!=creator_draft::amount(i)||!x.HasMember("unlock")||!x["unlock"].IsUint64()||x["unlock"].GetUint64()!=creator_draft::unlock(i))throw std::runtime_error("public tranche plan");
        b.miner_tx.vout.push_back(tx_out{creator_draft::amount(i),txout_to_key{public_key(x["key"].GetString())}});
      }
      add_tx_pub_key_to_extra(b.miner_tx,public_key(q["R"].GetString()));add_extra_nonce_to_tx_extra(b.miner_tx.extra,creator_draft::genesis_extra());
    }else{
      if(!q.HasMember("block")||!q["block"].IsString()||!q.HasMember("hash")||!q["hash"].IsString())throw std::runtime_error("public genesis artifact");
      auto raw=unhex(q["block"].GetString());if(!parse_and_validate_block_from_blob(raw,b)||block_to_blob(b)!=raw||hex(get_block_hash(b))!=q["hash"].GetString())throw std::runtime_error("canonical genesis artifact");
    }
    const auto raw=block_to_blob(b);const auto id=hex(get_block_hash(b));
    Ledger verify("",3600,16*1024*1024,hex(raw.data(),raw.size()),id);
    auto state=verify.tip();if(state.creator_issued!=creator_draft::total||state.issued!=0)throw std::runtime_error("genesis supply invariant");
    str("block",hex(raw.data(),raw.size()));str("hash",id);str("commitment",creator_draft::genesis_extra());str("R",hex(get_tx_pub_key_from_extra(b.miner_tx)));
    out.AddMember("creator_atomic",creator_draft::total,a);out.AddMember("mining_atomic",uint64_t(0),a);out.AddMember("recipient_ownership_proven",false,a);
    rapidjson::Value outputs(rapidjson::kArrayType);
    for(size_t i=0;i<17;++i){rapidjson::Value x(rapidjson::kObjectType);auto key=hex(boost::get<txout_to_key>(b.miner_tx.vout[i].target).key);x.AddMember("key",rapidjson::Value(key.c_str(),a),a);x.AddMember("atomic",creator_draft::amount(i),a);x.AddMember("unlock",creator_draft::unlock(i),a);outputs.PushBack(x,a);}out.AddMember("outputs",outputs,a);
  }else if(op=="open"){
    ledger.reset();ledger=std::make_unique<Ledger>(q["path"].GetString(),3600,16*1024*1024,q["block"].GetString(),q["hash"].GetString());
  }else if(op=="close"){ledger.reset();}
  else{
    if(!ledger)throw std::runtime_error("no isolated ledger");
    if(op=="status"){
      auto t=ledger->tip();out.AddMember("height",t.height,a);str("tip",t.id);str("mining",t.issued.convert_to<std::string>());str("creator",t.creator_issued.convert_to<std::string>());str("total",t.total_issued().convert_to<std::string>());str("work",t.work.convert_to<std::string>());
    }else if(op=="mine"){
      auto t=ledger->mining_template(public_key(q["P"].GetString()),q["timestamp"].GetUint64(),public_key(q["R"].GetString()));
#ifdef PC_OFFLINE_MOCK_UPGRADE
      if(q.HasMember("forced_version")){if(!q.HasMember("candidate_only")||!q["candidate_only"].GetBool())throw std::runtime_error("negative fixture only");t.block.major_version=q["forced_version"].GetUint();t.block.invalidate_hashes();}
#endif
      if(q.HasMember("forced_transaction")){
        auto raw=unhex(q["forced_transaction"].GetString());transaction tx;
        if(!parse_and_validate_tx_from_blob(raw,tx)||!t.block.tx_hashes.empty())throw std::runtime_error("forced fixture transaction");
        ledger->import_transaction(raw);t.block.tx_hashes.push_back(get_transaction_hash(tx));
        if(t.block.miner_tx.vout[0].amount>UINT64_MAX-tx.rct_signatures.txnFee)throw std::runtime_error("fixture fee overflow");
        t.block.miner_tx.vout[0].amount+=tx.rct_signatures.txnFee;t.block.miner_tx.invalidate_hashes();t.block.invalidate_hashes();
      }
      for(size_t attempts=0;;++attempts){if(attempts>=10000)throw std::runtime_error("bounded PoW attempts");if(phase0::pow_valid(ledger->hash(t.block,t.seed),t.difficulty))break;++t.block.nonce;t.block.invalidate_hashes();}
      auto blob=block_to_blob(t.block);
      if(!q.HasMember("candidate_only")||!q["candidate_only"].GetBool())str("id",ledger->submit(blob));
      str("block",hex(blob.data(),blob.size()));
    }else if(op=="submit"){str("id",ledger->submit(unhex(q["block"].GetString())));}
    else if(op=="payment"){str("id",ledger->submit_transaction(unhex(q["transaction"].GetString())));}
    else if(op=="import"){ledger->import_transaction(unhex(q["transaction"].GetString()));}
    else if(op=="pool"){
      rapidjson::Value pool(rapidjson::kArrayType);for(const auto& item:ledger->pool_entries())pool.PushBack(rapidjson::Value(hex(item.second.data(),item.second.size()).c_str(),a),a);out.AddMember("transactions",pool,a);
    }
    else if(op=="probe"){
      out.AddMember("fee",DraftProbe::transaction(*ledger,unhex(q["transaction"].GetString()),q["height"].GetUint64()),a);
    }else if(op=="blocks"){
      rapidjson::Value values(rapidjson::kArrayType);for(const auto& id:ledger->active_chain()){auto entry=ledger->get(id);values.PushBack(rapidjson::Value(hex(entry.bytes.data(),entry.bytes.size()).c_str(),a),a);}out.AddMember("blocks",values,a);
    }else if(op=="history"){
      rapidjson::Value records(rapidjson::kArrayType),images(rapidjson::kArrayType);
      for(const auto& id:ledger->active_chain()){
        auto entry=ledger->get(id);auto add=[&](const transaction& tx,bool cb){rapidjson::Value record(rapidjson::kObjectType);auto blob=tx_to_blob(tx);record.AddMember("transaction",rapidjson::Value(hex(blob.data(),blob.size()).c_str(),a),a);record.AddMember("height",entry.height,a);record.AddMember("coinbase",cb,a);records.PushBack(record,a);};
        add(entry.block.miner_tx,true);
        for(const auto& tid:entry.block.tx_hashes){transaction tx;parse_and_validate_tx_from_blob(ledger->transaction(hex(tid)),tx);add(tx,false);}
      }
      for(const auto& image:ledger->tip().state.images)images.PushBack(rapidjson::Value(image.c_str(),a),a);
      rapidjson::Value pool_images(rapidjson::kArrayType);
      for(const auto& item:ledger->pool_entries()){transaction tx;if(!parse_and_validate_tx_from_blob(item.second,tx))throw std::runtime_error("pool parse");for(const auto& input:tx.vin)pool_images.PushBack(rapidjson::Value(hex(boost::get<txin_to_key>(input).k_image).c_str(),a),a);}
      out.AddMember("chain",records,a);out.AddMember("images",images,a);out.AddMember("pool_images",pool_images,a);out.AddMember("height",ledger->tip().height,a);
    }else throw std::runtime_error("offline operation");
  }
  out.AddMember("ok",true,a);rapidjson::StringBuffer buffer;rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);out.Accept(writer);std::cout<<buffer.GetString()<<std::endl;
 }catch(const std::exception& e){
   // Fixed native diagnostics only; never echo request/key material.
   rapidjson::Document out;out.SetObject();auto& a=out.GetAllocator();out.AddMember("error",rapidjson::Value(e.what(),a),a);rapidjson::StringBuffer b;rapidjson::Writer<rapidjson::StringBuffer> w(b);out.Accept(w);std::cout<<b.GetString()<<std::endl;
 }
}
