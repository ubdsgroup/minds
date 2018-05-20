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

#ifndef MINDS_MAIN
#define MINDS_MAIN

//#include "utilities.h"

#include <iostream>
std::ostream& print_ip(unsigned long, std::ostream&);

#define TCP 6
#define UDP 17
#define ICMP 1

// see merge.cpp for explanation
#define MERGE_TIMEOUT  10000
#define MERGE_TCP_TTL     20000  
#define MERGE_TCP_WINDOW     180  // 3 min
#define MERGE_UDP_TTL     20000  
#define MERGE_UDP_WINDOW     180  // 3 mins
#define MERGE_MISC_TTL     20000  
#define MERGE_MISC_WINDOW     180  // 3 mins

// see match.cpp for explanation
#define MATCH_TIMEOUT  10000
#define MATCH_TCP_TTL     20000  
#define MATCH_TCP_WINDOW     180  // 3 mins
#define MATCH_UDP_TTL     20000  
#define MATCH_UDP_WINDOW     180  // 3 mins
#define MATCH_MISC_TTL     20000  
#define MATCH_MISC_WINDOW     180  // 3 mins

// see ScanDetector.cpp for explanation
// For the University (amortize the count of a touch in two hours)
//#define SD_DECAY_FACTOR 0.997
//#define SD_TIMEOUT   100000      // roughly 30 secs
// For the Army Center (amortize the count of a touch in two hours)
//#define SD_DECAY_FACTOR 0.80
//#define SD_TIMEOUT   600           // 10 mins in the Army Center
// For fast testing at the Army Center -- approx results only
#define SD_TIMEOUT 3125
#define SD_DECAY_FACTOR 0.93
#define SD_SCANNERLIST_TTL 1000000 // 1M hosts -> 1 hr at the U
#define SD_CONNECTION_WINDOW 100
//#define SD_INDEX_SIZE 100000     // 100k flows -> 6 mins, 10MB, AHPCRC >1 day
//#define SD_INDEX_SIZE 10000      // AHPCRC 3 hrs
//#define SD_INDEX_SIZE 50000      // AHPCRC 15 hrs
#define SD_INDEX_SIZE 100000
#define SD_PS_SCORE_THRESHOLD 2.0
#define SD_IS_SCORE_THRESHOLD 1.0

//#define SD_COUNT_MASK 0xFF0000FF  // approx 1 GB
#define SD_COUNT_MASK 0xFE00007F  // approx 250 MB
#define SD_COUNT_PORTBLOCKS 5056  // resolution of 16


#define MINDS_SUCCESS 0
#define MINDS_EOF     -1
#define MINDS_ERROR   1

// the role of the flow: client/server/don't know/not applicable (i.e. ICMP)
#define MINDS_UNKNOWN 0
#define MINDS_CLIENT  1
#define MINDS_SERVER  2
#define MINDS_NA      3

class flow_record_b;

class flow_record_a{
public:
    // features used in distance calculation
    unsigned long srcip;
    unsigned long dstip;
    unsigned short srcport;
    unsigned short dstport;
    unsigned char protocol;
    float srcip_idf;            // log(N/srcip_count)... related to IDF concept
    float dstip_idf;
    float srcport_idf;
    float dstport_idf;
    float protocol_idf;

    unsigned char tcp_flags;

    float duration; // in seconds
    long octets;
    long packets;

    // time window based
    short unique_inside_src_count;
    short same_src_port_count;
    short unique_inside_dst_count;
    short same_dst_port_count;

    // connection window based
    short unique_inside_src_rate;
    short same_src_port_rate;
    short unique_inside_dst_rate;
    short same_dst_port_rate;
 
    flow_record_b *b;

    flow_record_a(){
        srcip = dstip = octets = packets = 0;
        srcport = dstport = 0;
        protocol = tcp_flags = 0;
        duration = 0;
        unique_inside_src_count = same_src_port_count = unique_inside_dst_count = same_dst_port_count = 0;
        unique_inside_src_rate = same_src_port_rate = unique_inside_dst_rate = same_dst_port_rate = 0;
    }
};

class flow_record_b{
public:
    // other features
    unsigned long  first_sec;
    unsigned short first_msec;
    unsigned long  last_sec;
    unsigned short last_msec; 
    unsigned short sif;         // source interface 
    unsigned short dif;         // destination interface
    unsigned short src_as;      // source autonomous system number
    unsigned short dst_as;      // destination autonomous system number
    unsigned char src_mask;     // network size of source
    unsigned char dst_mask;     // network size of destination
    bool is_inbound;            // is the destination ip inside the network
    unsigned char network_s;    // ID of the network source IP belongs to
    unsigned char network_d;    // ID of the network destination IP belongs to
    unsigned char is_client;    // did the source ip initiate the connection 
                                // only relevant for tcp
                                // 0-don't know 1-client 2-server 3-N/A

    long pairing_flow;           // id of the pairing tcp flow. -1 if not TCP or n/a

    flow_record_b(){
        first_sec = last_sec = 0;
        first_msec = last_msec = sif = dif = src_as = dst_as = 0;
        src_mask = dst_mask = network_s = network_d = is_client = 0;
        is_inbound = 0;
        pairing_flow = -1;
    }
};

class fivetuple{
 public:
  unsigned long  src_ip;
  unsigned long  dst_ip;
  unsigned short src_port;
  unsigned short dst_port;
  unsigned char  protocol;

  fivetuple(unsigned long sip, unsigned long dip, 
	    unsigned short sport, unsigned short dport, unsigned char proto){
    src_ip   = sip;
    dst_ip   = dip;
    src_port = sport;
    dst_port = dport;
    protocol = proto;
  }

  void reverse(){
    unsigned long tempulong = src_ip;
    src_ip = dst_ip;
    dst_ip = tempulong;
    unsigned short tempushort = src_port;
    src_port = dst_port;
    dst_port = tempushort;
  }

  friend std::ostream& operator<< (std::ostream& out, const fivetuple &ftpl){
    out<<"<";
    print_ip(ftpl.src_ip, out)<<", "<<ftpl.src_port<<", ";
    print_ip(ftpl.dst_ip, out)<<", "<<ftpl.dst_port<<", ";
    out<<((int)ftpl.protocol)<<">";
    return out;
  }
};

struct fivetuple_lt{
  bool operator()(const fivetuple &f1, const fivetuple &f2){
    if(f1.src_ip < f2.src_ip) return true;
    if(f1.src_ip > f2.src_ip) return false;
    if(f1.src_port < f2.src_port) return true;
    if(f1.src_port > f2.src_port) return false;
    if(f1.dst_ip < f2.dst_ip) return true;
    if(f1.dst_ip > f2.dst_ip) return false;
    if(f1.dst_port < f2.dst_port) return true;
    if(f1.dst_port > f2.dst_port) return false;
    return f1.protocol < f2.protocol;
  }
};

unsigned char is_inside(unsigned long ip, unsigned long pad1, unsigned long pad2);
#endif
