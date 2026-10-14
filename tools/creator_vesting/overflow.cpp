// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
// Offline maximum-width supply guards; no ledger, key or network is opened.
#include "phase4/ledger.h"
#include "consensus/creator_vesting_draft.h"
#include <iostream>
int main(){
  auto need=[](bool ok){if(!ok)throw std::runtime_error("overflow regression");};
  pcdev::Entry e;auto max=std::numeric_limits<phase0::wide>::max();
  e.issued=max;e.creator_issued=0;need(e.total_issued()==max);
  e.creator_issued=1;bool rejected=false;try{(void)e.total_issued();}catch(const std::overflow_error&){rejected=true;}need(rejected);
  e.issued=max-creator_draft::total;e.creator_issued=creator_draft::total;need(e.total_issued()==max);
  need(phase0::add_issuance(max-1,1)==max);rejected=false;try{(void)phase0::add_issuance(max-1,2);}catch(const std::overflow_error&){rejected=true;}need(rejected);
  uint64_t sum=0;for(size_t i=0;i<17;++i)sum+=creator_draft::amount(i);need(sum==creator_draft::total);
  need(creator_draft::unlock(16)==1051200);
  rejected=false;try{(void)creator_draft::amount(17);}catch(const std::invalid_argument&){rejected=true;}need(rejected);
  std::cout<<"PASS 8 native supply boundary guards\n";
}
