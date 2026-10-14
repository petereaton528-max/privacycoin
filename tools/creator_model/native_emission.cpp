// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
// Independent oracle: call the actual retained native subsidy implementation.
#include "consensus/development_profile.h"
#include <iostream>
#include <set>
int main(){
  phase0::wide issued=0;uint64_t first_tail=0;
  std::set<uint64_t> checkpoints{1,2,60,1051200,1051920};
  for(uint64_t year=1;year<=51;++year)checkpoints.insert(year*262800);
  for(uint64_t height=1;height<=51*262800ULL;++height){
    auto reward=phase0::subsidy(issued);if(reward==600000000000ULL&&!first_tail)first_tail=height;
    issued=phase0::add_issuance(issued,reward);
    if(checkpoints.count(height))std::cout<<height<<' '<<issued<<'\n';
  }
  std::cout<<"tail "<<first_tail<<'\n';
}
