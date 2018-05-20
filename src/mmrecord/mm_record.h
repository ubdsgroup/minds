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

/*
 * Merge and match record
 *
 * A record structure used for merging and matching flows.
 *
 * mm_ts: abstraction of the begin and end time stamps <sec, msec>
 * mm_record: the actual record
 */
#ifndef __MM_RECORD_H__
#define __MM_RECORD_H__

#include <string>
#include "minds.h"
#include "macros.h"
#include "eee_flows.h"
#include "nf2mmrecord.h"

#define MAX_ULONG 0xFFFFFFFF

// scan flag in the mm_record
#define NOT_SCAN           0
#define SCAN_WITHOUT_REPLY 1
#define SCAN_WITH_REPLY    2

// p2p flag in the mm_record
#define NOT_P2P 0
#define P2P     1

// hpdt flags in the mm_record
#define NOT_HPDT 0
#define HPDT     1

// protocol flags
#define TCP 6
#define UDP 17
#define ICMP 1

unsigned long get_ip(std::string &a);
unsigned long convert_mask(std::string &s);
//
// flow_ts
//
// Time stamp that is capable of handling int (unsigned long) overflows.
// The operator < will give correct results as long as the difference
// between the two time stamps does not exceed 0xEFFFFFFF (MAX_ULONG/2).
//
class flow_ts{
 public:
  unsigned long ts;
  
  flow_ts(void) {ts=0L;}
  void operator++(int){ if(ts<MAX_ULONG) ts++; else ts=0L; }
  // default copy constructor
  
  friend std::ostream& operator<<(std::ostream&, const flow_ts&);
};

bool operator<(const flow_ts &ts1, const flow_ts &ts2);
flow_ts operator+(const flow_ts &ts, unsigned long inc);
bool operator==(const flow_ts &ts1, const flow_ts &ts2);
int  operator%(const flow_ts &, int);

//
// mm_ts
//
// Millisecond precision wallclock timestamps.
//
class mm_ts{
 public:
  unsigned long  secs;
  unsigned short msecs;

  mm_ts(){
    secs = 0L;
    msecs = 0;
  }

  mm_ts(unsigned long s, unsigned short ms){
    secs  = s;
    msecs = ms;
  }

  friend std::ostream& operator<< (std::ostream&, const mm_ts&);

};

bool operator< (const mm_ts &ts1, const mm_ts &ts2);
bool operator<= (const mm_ts &ts1, const mm_ts &ts2);
mm_ts operator+ (const mm_ts &ts, unsigned long msecs);

inline void mm_ts_min(mm_ts &result, const mm_ts &ts1, const mm_ts &ts2){
  mm_ts temp;
  temp = ts2;
  if(ts1<ts2) temp = ts1;
  result = temp;
}

inline void mm_ts_max(mm_ts &result, const mm_ts &ts1, const mm_ts &ts2){
  mm_ts temp;
  temp = ts2;
  if(ts2 < ts1) temp = ts1;
  result = temp;
}

class mm_record {
 public:
  mm_ts sts;  // start timestamp
  mm_ts ets;  // end timestamp
  flow_ts ts; // creation timestamp

  
  // DEFNITIONS of src, dst, server, client
  // 'src/dst' is from the initiator's prespective, that is
  // src = the source of the initiator flow, or equivalently, the destination
  // of the reply flow.  For the time being, client = src of initiator flow
  // and server = src of the reply flow [dst of initiator flow].
  unsigned long  src_ip;     
  unsigned short src_port;   
  unsigned long  dst_ip;
  unsigned short dst_port;
  
  unsigned long  cpackets;   
  unsigned long  spackets;   
  unsigned long  cbytes;
  unsigned long  sbytes;
  unsigned char  protocol;
  unsigned char  flags;

  unsigned char  src_mask;
  unsigned char  dst_mask;
  unsigned short src_as;
  unsigned short dst_as;

  // For scan detection
  unsigned char  scan;       // NOT_SCAN, SCAN_WITHOUT_REPLY, SCAN_WITH_REPLY

  unsigned char  p2p;        // NOT_P2P, P2P [defined above]
  unsigned char  hpdt;       // NOT_HPDT, HPDT [defined above]
  float          lof_anomaly_score;
  unsigned short is_inbound; //0 - No 1 - Yes
  unsigned short is_client;  //1 - source ip is client 2 - destination ip is client

  mm_record(){
    p2p = NOT_P2P;
    hpdt = NOT_HPDT;
    scan = NOT_SCAN;
    lof_anomaly_score = 0;
    cpackets = spackets = cbytes = sbytes = 0L;
    protocol = flags = 0;
    is_inbound = 0;
    is_client = 1;
  }

  friend std::ostream& operator<< (std::ostream&, const mm_record&);

};

bool operator< (const mm_record& mma, const mm_record& mmb);

// returns whether there is overlap between mma and mmb, each expanded
// by a window.
inline bool mm_overlap(const mm_record &mma, const mm_record &mmb, 
		 unsigned long window){
  if(mma.sts<mmb.sts){
    return mmb.sts.secs < mma.ets.secs + window;
  } else {
    return mma.sts.secs < mmb.ets.secs + window;
  }
}
#endif
