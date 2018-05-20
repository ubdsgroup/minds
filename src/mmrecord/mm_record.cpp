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

#include <unistd.h>
#include <fstream>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>

#include "eee_flows.h"
#include "nf2mmrecord.h"
#include "mm_record.h"
#include "utilities.h"
#include "macros.h"

unsigned long get_ip(std::string &a){
    unsigned long ip=0;
    unsigned short block=0;
    for(std::string::iterator it=a.begin(); it!=a.end(); ++it){
        if(*it == '.'){
            ip += block;
            block = 0;
            ip <<= 8;
        }
        else
            block = block*10 + ((*it)-'0');
    }
    return ip+block;
}

unsigned long convert_mask(std::string &s){
    if(s.size()>2) return get_ip(s);
    int i = atoi(s.c_str());
    unsigned long mask = 0;
    for(int j=0; j<i; ++j){ mask <<= 1; mask |= 1;}
    return mask << (32-i);
}

std::ostream& operator<<(std::ostream& out, const flow_ts &ts){
  out<<ts.ts;
  return out;
}

bool operator<(const flow_ts &ts1, const flow_ts &ts2){
  if(ts1.ts>MAX_ULONG-(MAX_ULONG/4) && ts2.ts<MAX_ULONG/4) return true;
  return ts1.ts<ts2.ts;
}

flow_ts operator+(const flow_ts &ts, unsigned long inc){
  flow_ts r;
  if(MAX_ULONG-ts.ts<inc) r.ts=MAX_ULONG-ts.ts; // rollover
  else r.ts=ts.ts+inc;
  return r;
}

bool operator==(const flow_ts &ts1, const flow_ts &ts2){
  return ts1.ts == ts2.ts;
}

int operator% (const flow_ts &ts, int div){
  return ts.ts%div;
}

bool operator< (const mm_ts &ts1, const mm_ts &ts2){
  if(ts1.secs < ts2.secs) return true;
  if(ts1.secs > ts2.secs) return false;
  if(ts1.msecs < ts2.msecs) return true;
  return false;
}

bool operator<= (const mm_ts &ts1, const mm_ts &ts2){
  if(ts1.secs < ts2.secs) return true;
  if(ts1.secs > ts2.secs) return false;
  if(ts1.msecs <= ts2.msecs) return true;
  return false;
}

mm_ts operator+(const mm_ts &ts, unsigned long msecs){
  mm_ts result=ts;
  result.secs += (int)(msecs/1000);
  result.msecs += (msecs%1000);
  if(result.msecs>1000){ 
    result.msecs-=1000; 
    result.secs+=1;
  }
  return result;
}

void mm_super(mm_record& mmr, const mm_record& mma, const mm_record& mmb){
  
  using namespace std;

  mm_record result; // otherwise mma or mmb can be overwritten

  // The client is the flow
  // - that started at least 100 msec earlier than the other OR
  // - the other flow uses privileged port (port < 1024) OR
  // - the other flow has a larger port number
  // Conditions must be prioritized in this order.
  bool mma_is_client;
  if(mma.sts.secs + 1 < mmb.sts.secs) mma_is_client = true;
  else if(mmb.sts.secs + 1 < mma.sts.secs) mma_is_client = false;
  else if(mma.dst_port < 1024) mma_is_client = true;
  else if(mma.src_port < 1024) mma_is_client = false;
  else mma_is_client = (mma.src_port > mmb.src_port);

  mm_ts_min(result.sts, mma.sts, mmb.sts);
  mm_ts_max(result.ets, mma.ets, mmb.ets);

  if(mma_is_client){
    // mma is the client
    result.src_ip = mma.src_ip;
    result.src_port = mma.src_port;
    result.dst_ip = mma.dst_ip;
    result.dst_port = mma.dst_port;
    result.cbytes = mma.cbytes;
    result.cpackets = mma.cpackets;
    result.sbytes = mmb.cbytes;
    result.spackets = mmb.cpackets;
    result.protocol = mma.protocol;
    result.flags = mma.flags | mmb.flags;
    result.src_mask = mma.src_mask;
    result.dst_mask = mma.dst_mask;
    result.src_as = mma.src_as;
    result.dst_as = mma.dst_as;
    result.ts = (mma.ts<mmb.ts)?mmb.ts:mma.ts;
  } else {
    // mmb is the client
    result.src_ip = mmb.src_ip;
    result.src_port = mmb.src_port;
    result.dst_ip = mmb.dst_ip;
    result.dst_port = mmb.dst_port;
    result.cbytes = mmb.cbytes;
    result.cpackets = mmb.cpackets;
    result.sbytes = mma.cbytes;
    result.spackets = mma.cpackets;
    result.protocol = mmb.protocol;
    result.flags = mma.flags | mmb.flags;
    result.src_mask = mmb.src_mask;
    result.dst_mask = mmb.dst_mask;
    result.src_as = mmb.src_as;
    result.dst_as = mmb.dst_as;
    result.ts = (mma.ts<mmb.ts)?mmb.ts:mma.ts;
  }

  mmr = result;  

}

std::ostream& operator<< (std::ostream &out, const mm_ts& ts){
  print_time(ts.secs, ts.msecs, out);
  return out;
}

std::ostream& operator<< (std::ostream& out, const mm_record& mmr){
  print_ip(mmr.src_ip, out)<<"["<<mmr.src_port<<"] ";
  print_ip(mmr.dst_ip, out)<<"["<<mmr.dst_port<<"] ";
  out<<">"<<mmr.cbytes<<"("<<mmr.cpackets<<") ";
  out<<"<"<<mmr.sbytes<<"("<<mmr.spackets<<") ";
  out<<mmr.sts<<"-"<<mmr.ets;
  out<<" "<<mmr.is_inbound;
  out<<" "<<mmr.is_client;
  out<<" "<<(int)mmr.scan<<" "<<(int)mmr.p2p<<" "<<(int)mmr.hpdt;
  out<<" "<<mmr.lof_anomaly_score;
  return out;
}


bool operator< (const mm_record& mma, const mm_record& mmb){
  return mma.sts < mmb.sts;
}

