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
  # 
# Copyright (c) 2018
  #      The Regents of the University of Minnesota.  All rights reserved.
*/

#include <map>
#include <vector>
#include <netdb.h>
#include <stdio.h>
#include <iostream>
#include "scan_detector2.h"
#include "mm_record.h"
#include <math.h>


unsigned char IPSWEEP_TIME_WINDOW   = 0x1;
unsigned char IPSWEEP_CONN_WINDOW   = 0x2;
unsigned char PORTSWEEP_TIME_WINDOW = 0x4;
unsigned char PORTSWEEP_CONN_WINDOW = 0x8;
unsigned long TIMEOUT = 86400;      // one day
int high_bits = 10;
int low_bits = 4 ;
int port_res = 16;
unsigned char MASK_CAP = 24;

unsigned int calculate_mask(int h, int l){
  int i;
  unsigned int mask = 0;
  for(i = 0; i < h; ++i){
    mask <<= 1;
    mask |= 1;
  }
  mask <<= (32 - (h + l));
  for(i = 0; i < l; ++i){
    mask <<= 1;
    mask |= 1;
  }
  return mask;
}

unsigned int calculate_ip_index(unsigned long ip){
  unsigned int mask = 0;
  mask |= ip >> (32 - high_bits);
  mask <<= low_bits;
  mask |= ip & (0xFFFFFFFF >> (32 - low_bits));
  return mask;
}

inline unsigned short calculate_port_index(unsigned short p){
  if(p < 1024){
    return p;
  }
  else {
    return (p - 1024)/port_res;
  }
}

unsigned long convert_mask1(unsigned char i){
    unsigned long mask = 0;
    for(int j=0; j<i; ++j){ mask <<= 1; mask |= 1;}
    return mask << (32-i);
}

class sweep{
public:
  unsigned short dst_port;
  unsigned char protocol;
  unsigned long network;
  unsigned char mask;
 
  sweep(unsigned short s, unsigned char p, unsigned long l, unsigned char m):dst_port(s), protocol(p), network(l), mask(m){}
};
 
struct lt_sweep{ // comparison function for sweep class
  bool operator()(const sweep s1, const sweep s2) const{
    if     (s1.dst_port < s2.dst_port) return 1;
    else if(s1.dst_port > s2.dst_port) return 0;

    if     (s1.protocol < s2.protocol) return 1;
    else if(s1.protocol > s2.protocol) return 0;

    if     (s1.network < s2.network) return 1;
    else if(s1.network > s2.network) return 0;
 
    if     (s1.mask < s2.mask) return 1;
    return 0;
  }
};

void detect_scans2(std::vector<mm_record> &mmr_data,
		   unsigned int time_window,
		   unsigned int conn_window,
		   float t_score,
		   float c_score){
  using namespace std;
  unsigned int ip_mask = 0;
  vector<unsigned char> scans(mmr_data.size(), 0);
  char buf1[256], buf2[256];
  unsigned int i, j, p, q;

  cerr << "entered the scan detector" << endl;
  cerr << "time window : " << time_window << " milliseconds" << endl;
  cerr << "conn window : " << conn_window << " connections " << endl;
  cerr << "timeout     : " << TIMEOUT << " seconds" << endl;

  ip_mask = calculate_mask(high_bits, low_bits);

  // first index : ip-block
  // second index : port-block 
  vector< vector<float> > counts(1 << (high_bits + low_bits), vector<float>(1024 + (65536 - 1024) / port_res, 0));

  // by default, scan detection is performed on individual networks whose size is
  // specified by the mask.  In order to do scan detection at different levels of
  // granularity by specfying them in mask_level.
  // this is done for inbound flows only.
  vector<unsigned char> mask_level;
  //          src_ip         protocol
  map< pair<unsigned long, unsigned char>, map< sweep, vector<unsigned int>, lt_sweep > > ip_sweep;
  map< pair<unsigned long, unsigned char>, map< sweep, vector<unsigned int>, lt_sweep > >::iterator ip_it;
  map< sweep, vector<unsigned int> >::iterator sw_it;

  for(i = 0; i < mmr_data.size(); ++i){
    ++counts[calculate_ip_index(mmr_data[i].src_ip)][calculate_port_index(mmr_data[i].dst_port)];
    if(mmr_data[i].is_client != 2){  // not server
      pair<unsigned long, unsigned char> temp(mmr_data[i].src_ip, mmr_data[i].src_mask);
      unsigned char mask = mmr_data[i].dst_mask < MASK_CAP ? MASK_CAP : mmr_data[i].dst_mask;
      if(mmr_data[i].dst_mask == 0) mask = 0;   // not routed.  black holed
      ip_sweep[temp][sweep(mmr_data[i].dst_port, mmr_data[i].protocol, mmr_data[i].dst_ip & convert_mask1(mask), mask)].push_back(i);
    }
    else{  // anything to do with the replies?
    }
  }

  for(ip_it = ip_sweep.begin(); ip_it != ip_sweep.end(); ++ip_it){
    for(sw_it = ip_it->second.begin(); sw_it != ip_it->second.end(); ++sw_it){
      // flows from one source to a specific destination network
      // time window based detection
      map<unsigned long, int> targets;
      map<unsigned long, int>::iterator t_it;
      q = sw_it->second[0];
      float score = 0;
      int replies = 0;
      for(i = 0, j = 0; i < sw_it->second.size(); ++i){
	p = sw_it->second[i];
	if(mmr_data[p].cpackets < 4){
	  if((++(targets[mmr_data[p].dst_ip])) == 1){
	    score += 1.0 / (1 + log(counts[calculate_ip_index(mmr_data[p].src_ip)][calculate_port_index(mmr_data[p].dst_port)]));
	  }
	}
	while((mmr_data[p].sts.secs  - mmr_data[q].sts.secs) * 1000000 +
	      (mmr_data[p].sts.msecs - mmr_data[q].sts.msecs) > time_window){
	  if(mmr_data[q].cpackets >= 4){
	    q = sw_it->second[++j];
	    continue;
	  }
	  t_it = targets.find(mmr_data[q].dst_ip);
	  if(t_it == targets.end()){
	    cerr << "something is wrong in scan detector - time window" << endl;
	    continue;
	  }
	  if(t_it->second == 1){
	    targets.erase(t_it);
	    score -= 1.0 / (1 + log(counts[calculate_ip_index(mmr_data[p].src_ip)][calculate_port_index(mmr_data[p].dst_port)]));
	  }
	  else --(t_it->second);
	  q = sw_it->second[++j];
	}
	if(score > t_score){
	  score  = 0.0;
	  replies = 0;
	  targets.clear();
	  for(j = 0; j < sw_it->second.size(); ++j){
	    q = sw_it->second[j];
	    score += 1.0 / (1 + log(counts[calculate_ip_index(mmr_data[q].src_ip)][calculate_port_index(mmr_data[q].dst_port)]));
	    scans[q] |= IPSWEEP_TIME_WINDOW;
	    ++targets[mmr_data[q].dst_ip];
	  }
	  p = *sw_it->second.begin();
	  q = *sw_it->second.rbegin();
	  break;
	}
      }
      targets.clear();

      // connection window based signature
      q = sw_it->second[0];
      score = 0.0;
      replies=0;
      for(i = 0, j = 0; i < sw_it->second.size(); ++i){
	p = sw_it->second[i];
	if(scans[p] & IPSWEEP_TIME_WINDOW != 0) break;  // don't detect it again
	if(mmr_data[p].cpackets < 4){
	  if(++(targets[mmr_data[p].dst_ip]) == 1){
	    score += 1.0 / (1 + log(counts[calculate_ip_index(mmr_data[p].src_ip)][calculate_port_index(mmr_data[p].dst_port)]));
	  }
	}
	while((i - j > conn_window) || (mmr_data[p].sts.secs  - mmr_data[q].sts.secs > TIMEOUT)){
	  if(mmr_data[q].cpackets >= 4){
	    q = sw_it->second[++j];
	    continue;
	  }
	  t_it = targets.find(mmr_data[q].dst_ip);
	  if(t_it == targets.end()){
	    cerr << "something is wrong in scan detector - connection window" << endl;
	    continue;
	  }
	  if(t_it->second == 1){
	    targets.erase(t_it);
	    score -= 1.0 / (1 + log(counts[calculate_ip_index(mmr_data[p].src_ip)][calculate_port_index(mmr_data[p].dst_port)]));
	  }
	  else --(t_it->second);
	  q = sw_it->second[++j];
	}
	if(score > c_score){
	  score = 0.0;
	  replies = 0;
	  targets.clear();
	  for(j = 0; j < sw_it->second.size(); ++j){
	    q = sw_it->second[j];
	    score += 1.0 / (1 + log(counts[calculate_ip_index(mmr_data[q].src_ip)][calculate_port_index(mmr_data[q].dst_port)]));
	    scans[q] |= IPSWEEP_CONN_WINDOW;
	    ++targets[mmr_data[q].dst_ip];
	  }
	  p = *sw_it->second.begin();
	  q = *sw_it->second.rbegin();
	  break;
	}
      }
    }
  }
  //update the scan bits
  for(unsigned int i = 0; i < mmr_data.size(); i++)
    mmr_data[i].scan = scans[i];
}
