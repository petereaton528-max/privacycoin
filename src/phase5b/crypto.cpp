// Wallet/transport adapter only. Existing primitive/scanner implementations frozen.
#include "scan_reference.inc"

int main(){
 if(sodium_init()<0)return 1;std::string line;
 while(std::getline(std::cin,line))try{
  need(line.size()<32*1024*1024);rapidjson::Document q;q.Parse(line.c_str());need(q.IsObject()&&q.HasMember("op")&&q["op"].IsString());
  rapidjson::Document out;out.SetObject();auto& a=out.GetAllocator();auto op=std::string(q["op"].GetString());
  if(op=="manifest"){
   std::string previous=q["previous"].GetString();uint64_t height=q["start"].GetUint64();J records(rapidjson::kArrayType),blocks(rapidjson::kArrayType);
   for(const auto& r:q["blocks"].GetArray()){
    block b;auto raw=uh(r["block"].GetString());need(raw.size()<=300000&&parse_and_validate_block_from_blob(raw,b)&&block_to_blob(b)==raw);
    auto id=hx(get_block_hash(b));need(id==r["id"].GetString()&&hx(b.prev_id)==previous&&r["height"].GetUint64()==height);
    need(b.major_version==18&&b.tx_hashes.size()<=8&&b.miner_tx.version==2&&b.miner_tx.vin.size()==1&&boost::get<txin_gen>(b.miner_tx.vin[0]).height==height);
    auto record=[&](const crypto::hash& hash,bool cb){J v(rapidjson::kObjectType);v.AddMember("id",J(hx(hash).c_str(),a),a);v.AddMember("height",height,a);v.AddMember("coinbase",cb,a);records.PushBack(v,a);};
    record(get_transaction_hash(b.miner_tx),true);for(const auto& hash:b.tx_hashes)record(hash,false);
    J v(rapidjson::kObjectType);v.AddMember("id",J(id.c_str(),a),a);v.AddMember("height",height,a);v.AddMember("records",uint64_t(1+b.tx_hashes.size()),a);blocks.PushBack(v,a);previous=id;++height;
   }out.AddMember("records",records,a);out.AddMember("blocks",blocks,a);
  }else if(op=="metadata"){
   J records(rapidjson::kArrayType);uint64_t total=0;
   for(const auto& r:q["chain"].GetArray()){
    transaction tx;auto raw=uh(r["transaction"].GetString());need(raw.size()<=50000);crypto::hash id;
    if(r.HasMember("prunable_hash")){need(parse_and_validate_tx_base_from_blob(raw,tx,true,true)&&base_blob(tx)==raw);need(get_pruned_transaction_hash(tx,read<crypto::hash>(r["prunable_hash"]),id));}
    else{need(parse_and_validate_tx_from_blob(raw,tx)&&tx_to_blob(tx)==raw);id=get_transaction_hash(tx);}
    need(tx.version==2&&hx(id)==r["id"].GetString());bool cb=tx.vin.size()==1&&tx.vin[0].type()==typeid(txin_gen);auto height=r["height"].GetUint64();
    need(cb==r["coinbase"].GetBool()&&(cb?tx.rct_signatures.type==rct::RCTTypeNull:tx.rct_signatures.type==rct::RCTTypeBulletproofPlus));
    if(cb)need(boost::get<txin_gen>(tx.vin[0]).height==height);need(tx.vout.size()>0&&tx.vout.size()<=16);
    J v(rapidjson::kObjectType),images(rapidjson::kArrayType);v.AddMember("id",J(hx(id).c_str(),a),a);v.AddMember("height",height,a);v.AddMember("coinbase",cb,a);v.AddMember("outputs",uint64_t(tx.vout.size()),a);v.AddMember("fee",cb?uint64_t(0):tx.rct_signatures.txnFee,a);
    if(!cb)for(const auto& in:tx.vin)images.PushBack(J(hx(boost::get<txin_to_key>(in).k_image).c_str(),a),a);v.AddMember("images",images,a);records.PushBack(v,a);total+=tx.vout.size();
   }out.AddMember("records",records,a);out.AddMember("outputs",total,a);
  }else process(q,out);
  rapidjson::StringBuffer buffer;rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);out.Accept(writer);std::cout<<buffer.GetString()<<std::endl;sodium_memzero(line.data(),line.size());
 }catch(...){sodium_memzero(line.data(),line.size());std::cerr<<"sync cryptographic request rejected\n";return 1;}
 return 0;
}
