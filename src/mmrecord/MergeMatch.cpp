/*
The Minnesota Intrusion Detection System or MINDS is a network intrusion detection software that uses data driven anomaly detection algorithms to identify attacks on cyber infrastructure.

The MINDS program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

MINDS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/
/*
# Copyright (c) 2018
#       The Regents of the University of Minnesota. All rights reserved.
*/


#include "MergeMatch.h"
#include <map>
#include "mindsconfig.h"

static inline bool lt_starttime(const mm_record& mm1, const mm_record& mm2){
  return mm1.sts<mm2.sts;
}

class fivetpl {
public:
  unsigned char protocol;
  unsigned long src_ip;
  unsigned short src_port;
  unsigned long dst_ip;
  unsigned short dst_port;
  
  fivetpl(mm_record &mmr, bool invert=false){
    if(!invert){
      protocol=mmr.protocol;
      src_ip=mmr.src_ip;
      src_port=mmr.src_port;
      dst_ip=mmr.dst_ip;
      dst_port=mmr.dst_port;
    } else {
      protocol=mmr.protocol;
      dst_ip=mmr.src_ip;
      dst_port=mmr.src_port;
      src_ip=mmr.dst_ip;
      src_port=mmr.dst_port;
    }      
  }

  fivetpl(){
    protocol=0;
    src_ip=0;
    src_port=0;
    dst_ip=0;
    dst_port=0;
  }
};

struct lt_fivetpl {
  bool operator()(const fivetpl& f1, const fivetpl& f2){
    if(f1.protocol<f2.protocol) return true;
    if(f1.protocol>f2.protocol) return false;
    if(f1.src_ip<f2.src_ip) return true;
    if(f1.src_ip>f2.src_ip) return false;
    if(f1.src_port<f2.src_port) return true;
    if(f1.src_port>f2.src_port) return false;
    if(f1.dst_ip<f2.dst_ip) return true;
    if(f1.dst_ip>f2.dst_ip) return false;
    if(f1.dst_port<f2.dst_port) return true;
    if(f1.dst_port>f2.dst_port) return false;
    return false;
  }
};

void MergeMatch::merge_match(std::vector<mm_record>& raw, std::vector<mm_record>& mmr){
  
  using namespace std;

  unsigned long beginTime; // the beginning of the time interval

  // (1) Sort raw 
  DEBUG("Sorting the flows on start time ... "); fflush(stderr);
  stable_sort(raw.begin(), raw.end(), lt_starttime);
  fprintf(stderr, "Done. Sorted size: %d\n", raw.size());

  // (2) Initialize port frquencies
  DEBUG("Calculating the port frequencies ... "); fflush(stderr);
  for(int i=0; i<NPORTS; i++) freqs[i]=0;
  for(unsigned int i=0; i<raw.size(); i++){
    freqs[raw[i].src_port]++;
    freqs[raw[i].dst_port]++;
  }
  fprintf(stderr, "Done.\n");

  // (3) Do the merge
  DEBUG("Merging ... "); fflush(stderr);
  // fivetuple -> index within raw 
  map<fivetpl, int, lt_fivetpl> idx;
  for(unsigned int i=0; i<raw.size(); i++){

    fivetpl straight(raw[i]);
    map<fivetpl, int, lt_fivetpl>::iterator idxit;
    idxit=idx.find(straight);
    if(idxit!=idx.end()){
      // potential merge
      mm_record& mmr_old = raw[idxit->second];
      mm_record& mmr_new = raw[i];
      if(mmr_new.sts < mmr_old.ets+MERGE_TIMEWINDOW){
	// actual merge
	// do not change mmr_old.sts
	mmr_old.ets = (mmr_old.ets<mmr_new.ets?mmr_new.ets:mmr_old.ets);
	mmr_old.cpackets += mmr_new.cpackets;
	mmr_old.spackets += mmr_new.spackets;
	mmr_old.cbytes += mmr_new.cbytes;
	mmr_old.sbytes += mmr_new.sbytes;
	mmr_old.flags |= mmr_new.flags;

	mmr_new.src_ip = 0;
      } else {
	// out of time window -> replace
	idxit->second=i;
      }
    } else {
      // never seen such a fivetuple before
      pair<fivetpl, int> pr;
      pr.first=straight;
      pr.second=i;
      idx.insert(pr);
    }
  }
  idx.clear();
  int nraw=0;
  for(unsigned int i=0; i<raw.size(); i++) if(raw[i].src_ip!=0) nraw++;
  fprintf(stderr, "Done [%d].\n", nraw);
  //
  // (4) Do the match
  //
  DEBUG("Matching ... "); fflush(stderr);
  for(unsigned int i=0; i<raw.size(); i++){
    if(raw[i].src_ip==0) {continue;}
    mm_record &mmr_new = raw[i];

    fivetpl reverse(raw[i], true);
    fivetpl straight(raw[i]);
    map<fivetpl, int, lt_fivetpl>::iterator idxit;
    idxit=idx.find(reverse);
    if(idxit!=idx.end()){
      // potential match
      mm_record &mmr_old = raw[idxit->second];
      if(mmr_new.sts < mmr_old.ets+MATCH_TIMEWINDOW){
	// actual match 
	// decide who is the client and who is the server
	bool old_is_client = false; 
	bool new_is_client = false;
	if(mmr_old.sts+50<mmr_new.sts) old_is_client=true;
	else if(mmr_new.sts+50<mmr_old.sts) new_is_client=true;
	else if(mmr_old.dst_port<1024 && mmr_new.dst_port>1024) old_is_client=true;
	else if(mmr_new.dst_port<1024 && mmr_old.dst_port>1024) new_is_client=true;
	else if(freqs[mmr_old.dst_port]>freqs[mmr_new.dst_port]) old_is_client=true;
	else new_is_client=true;
	// do not change mmr_old.sts
	mmr_old.ets = (mmr_old.ets<mmr_new.ets?mmr_new.ets:mmr_old.ets);
	mmr_old.cpackets += mmr_new.spackets;
	mmr_old.spackets += mmr_new.cpackets;
	mmr_old.cbytes += mmr_new.sbytes;
	mmr_old.sbytes += mmr_new.cbytes;
	mmr_old.flags |= mmr_new.flags;

	// the new flow was the client -> for the orig flow, exchange roles
	if(new_is_client){
	  mmr_old.src_ip = mmr_new.src_ip;
	  mmr_old.src_port = mmr_new.src_port;
	  mmr_old.dst_ip = mmr_new.dst_ip;
	  mmr_old.dst_port = mmr_new.dst_port;
	  mmr_old.src_mask = mmr_new.src_mask;
	  mmr_old.dst_mask = mmr_new.dst_mask;
	  mmr_old.src_as = mmr_new.src_as;
	  mmr_old.dst_as = mmr_new.dst_as;
	  unsigned long temp;
	  temp = mmr_old.spackets;
	  mmr_old.spackets = mmr_old.cpackets;
	  mmr_old.cpackets = temp;
	  temp = mmr_old.sbytes;
	  mmr_old.sbytes = mmr_old.cbytes;
	  mmr_old.cbytes = temp;
	}
	mmr_new.src_ip = 0;
      } 
    } else {
      // There is no matching (=reverse) fivetpl.  If there is identical, replace it,
      // if there is no identical fivetpl, insert it.
      //DEBUG("-- did not find reverse, ");
      idxit=idx.find(straight);
      if(idxit==idx.end()){
	// no identical (=straight) fivetpl -> insert it
	pair<fivetpl, int> pr;
	pr.first=straight;
	pr.second=i;
	idx.insert(pr);
      } else {
	// there is identical -> replace it with the newer
	idxit->second=i;
      }
    }
  }
  idx.clear();
  nraw=0;
  for(unsigned int i=0; i<raw.size(); i++) if(raw[i].src_ip!=0) nraw++;
  fprintf(stderr, "Done [%d].\n", nraw);

  //
  // (5) Remove early flows 
  //     -- scan detection starts 5 mins into the time period
  //
  // (5a) Find the end time of the earliest reply
  beginTime=raw[0].ets.secs;
  for(unsigned int i=0; i<raw.size(); i++){
    if(raw[i].src_ip==0)  {continue;}
    if(raw[i].spackets<1) {continue;}
    if(raw[i].ets.secs<beginTime) 
      beginTime=raw[i].ets.secs;
  }
  // (5b) Ignore all flows, that are unmatched and have a start time
  // that is earlier than beginTime+5mins
  for(unsigned int i=0; i<raw.size(); i++){
    if(raw[i].src_ip==0)         {continue;}
    if(raw[i].spackets>0)        {continue;} //matched
    if(raw[i].sts.secs<beginTime+300){raw[i].src_ip=0;} //early flow -- discard
  }

  //
  // (7) Copying the flows over
  //
  for(unsigned int i=0; i<raw.size(); i++){
    if(raw[i].src_ip==0) continue;
    mmr.push_back(raw[i]);
  }

  DEBUG("Size after merge-match: %d\n", mmr.size());
}
