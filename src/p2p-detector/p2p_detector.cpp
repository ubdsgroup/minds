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
  # 	The Regents of the University of Minnesota. All rights reserved.
*/

#include <cmath>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <netdb.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include "utilities.h"
#include "mm_record.h"

extern unsigned int p2p_success_threshold;
extern unsigned int p2p_wellknown_threshold;
extern unsigned int p2p_minflow_threshold;
extern unsigned int p2p_min_connected_ips;
extern unsigned int p2p_minflow_threshold;

unsigned char KNOWN_P2P_PORT = 1;
unsigned char TCP_UDP = 2;
unsigned char IP_PORT_COUNT = 4;
unsigned char STAT_PROFILE = 16;
unsigned char SUCCESS_RATE = 32;
unsigned char SCAN_BEHAVIOR = 64;
unsigned char PAIRED_FLOW = 128; // this is max for unsigned char.

int UDP_FLOW = 2;
int TCP_FLOW = 4;
int GOOD_PORT = 8;

void detect_p2p(std::vector<mm_record> &data, // input part 
		std::set<unsigned short> &well_known_p2p_ports, // set of known p2p ports
		std::set<unsigned short> &well_known_malware_ports, // set of known malware ports
		std::set<unsigned short> &known_good_tcp_udp, // set of known ports that use both tcp and udp
		std::set<unsigned short> &known_good_ports){ // set of known good ports
  using namespace std;
  unsigned int i;
  cout << "entered the p2p detector" << endl;
  // for heuristic 1
  // we will store the inside IP first, then the outside one
  map<unsigned long, map<unsigned long, unsigned char> > flow_types;

  // for heuristic 2
  // for each ip, map port to distinct number of ips and ports.
  map<unsigned long, map<unsigned short, set<unsigned long> > > ipports_ip;
  map<unsigned long, map<unsigned short, set<unsigned short> > > ipports_port;
  map<unsigned long, map<unsigned short, set<unsigned short> > > ipports_good;
  map<unsigned long, map<unsigned short, unsigned int> > ipports_flows;
  map<unsigned long, map<unsigned short, set<long> > > ipports_bytes;
  map<unsigned long, map<unsigned short, set<long> > > ipports_packetsize;
  map<unsigned long, map<unsigned short, char> > ipports_p2p; // if 0, unknown; if 1, p2p; if 2, non-p2p

  // for heuristic 3
  map<unsigned long, vector<unsigned long> > intervals;

  // for heuristic 4
  // first set up the list of scanners, so that we can measure success rate of them
  //    ip of scanner       successful      failed
  map<unsigned long, pair<unsigned long, unsigned long> > scanners_success_rates;

  // for heuristic 5
  //  ip                 port                ip             flows
  map<unsigned long, map<unsigned short, map<unsigned long, unsigned long> > > perport;
  //  ip                 ip                 port            flows
  map<unsigned long, map<unsigned long, map<unsigned short, unsigned long> > > perip;

  ///////////////////////////////////////////////////////////////////
  // pre processing of data
  for(i = 0; i < data.size(); i++) {
    // we don't care for ICMP flow.
    if (data[i].protocol != 6 && data[i].protocol != 17){
      continue;
    }
    // for heuristic 1 and 2, it should be an unblocked flow.
    if (data[i].dst_mask) {

      // heuristic 1 - src/dst pairs of IP with TCP and UDP
      if (data[i].is_inbound){
	if (data[i].protocol == 17){
	  flow_types[data[i].dst_ip][data[i].src_ip] |= UDP_FLOW;
	}
	if (data[i].protocol == 6){
	  flow_types[data[i].dst_ip][data[i].src_ip] |= TCP_FLOW;
	}
      }
      else {
	if (data[i].protocol == 17){
	  flow_types[data[i].src_ip][data[i].dst_ip] |= UDP_FLOW;
	}
	if (data[i].protocol == 6){
	  flow_types[data[i].src_ip][data[i].dst_ip] |= TCP_FLOW;
	}
      }

      // flag this pair if they have used a well known tcp udp port
      if ( (known_good_tcp_udp.find(data[i].src_port) == known_good_tcp_udp.end()) &&
	   (known_good_tcp_udp.find(data[i].dst_port) == known_good_tcp_udp.end()) ) {
	if (data[i].is_inbound){
	  flow_types[data[i].dst_ip][data[i].src_ip] |= GOOD_PORT;
	}
	else {
	  flow_types[data[i].src_ip][data[i].dst_ip] |= GOOD_PORT;
	}
      }
      // end heuristic 1 pre processing

      // heuristic 2 pre processing

      // do for both src and dst -> this will be taken care of by the min_connected_ip_threshold

      // count distinct number of ips and ports
      ipports_ip[data[i].dst_ip][data[i].dst_port].insert(data[i].src_ip);
      ipports_ip[data[i].src_ip][data[i].src_port].insert(data[i].dst_ip);

      ipports_port[data[i].dst_ip][data[i].dst_port].insert(data[i].src_port);
      ipports_port[data[i].src_ip][data[i].src_port].insert(data[i].dst_port);

      // see if src_port is a well-known port; then dst ip-port pair will benefit
      if (known_good_ports.find(data[i].src_port) != known_good_ports.end()) {
	// dst communicates with a good src port
	ipports_good[data[i].dst_ip][data[i].dst_port].insert(data[i].src_port);
      }
      // see if dst_port is a well-known port; then src ip-port pair will benefit
      if (known_good_ports.find(data[i].dst_port) != known_good_ports.end()) {
	// src communicates with a good dst port
	ipports_good[data[i].src_ip][data[i].src_port].insert(data[i].dst_port);
      }

      // count the number of distinct bytes and average packet sizes
      ipports_bytes[data[i].dst_ip][data[i].dst_port].insert(data[i].cbytes);
      ipports_bytes[data[i].src_ip][data[i].src_port].insert(data[i].cbytes);

      ipports_packetsize[data[i].dst_ip][data[i].dst_port].insert(data[i].cbytes/data[i].cpackets);
      ipports_packetsize[data[i].src_ip][data[i].src_port].insert(data[i].cbytes/data[i].cpackets);

      // count the number of flows each appears in
      ipports_flows[data[i].dst_ip][data[i].dst_port]++;
      ipports_flows[data[i].src_ip][data[i].src_port]++;
			
      // DNS heuristic
      if ( (data[i].src_port == data[i].dst_port) && (data[i].src_port < 501) ) {
	ipports_p2p[data[i].src_ip][data[i].src_port] = 2;
	ipports_p2p[data[i].dst_ip][data[i].dst_port] = 2;
      }
      // end heuristic 2 pre processing
    }

    // for heuristic 3 to 5, blocked flows are also considered.

    // heuristic 3 pre processing
    // for now, only inbound traffic is considered.
    if (data[i].is_inbound == true) {
      // first_sec and first_msec is combined into one unsigned long
      intervals[data[i].src_ip].push_back(data[i].sts.secs);
    }
    // end of heuristic 3 pre processing

    // heuristic 4 pre processing
    if (data[i].spackets > 0) {
      // successful connection
      scanners_success_rates[data[i].src_ip].first++;
    }
    else if (data[i].protocol == 6) {
      // this is tcp but failed connection
      scanners_success_rates[data[i].src_ip].second++;
    }
    // end of heuristic 4 pre processing

    // heuristic 5 pre processing
    if (data[i].is_inbound == true) {
      perport[data[i].src_ip][data[i].dst_port][data[i].dst_ip]++;
      perip[data[i].src_ip][data[i].dst_ip][data[i].dst_port]++;
    }

    // end of heuristic 5 pre processing
  } // for(i = 0; i < data.size(); i++) {

  // heuristic 2 special processing
  // finding out ip-port pair which meets the heuristics 2
  map<unsigned long, map<unsigned short, set<unsigned long> > >::iterator ipports_it;
  map<unsigned short, set<unsigned long> >::iterator ports_it;
  for (ipports_it = ipports_ip.begin(); ipports_it != ipports_ip.end(); ipports_it++) {
    for (ports_it = ipports_it->second.begin(); ports_it != ipports_it->second.end(); ports_it++) {
      // skip if already non-p2p by DNS heuristic
      if (ipports_p2p[ipports_it->first][ports_it->first] == 2) {
	continue;
      }
      unsigned long distinct_ips = ports_it->second.size();
      unsigned long distinct_ports = ipports_port[ipports_it->first][ports_it->first].size();

      // initialize all ip/port pairs to 0 (unknown)
      ipports_p2p[ipports_it->first][ports_it->first] = 0;

      // only useful if enough ips are connected to it
      if (distinct_ips > p2p_min_connected_ips){
	int diff = abs((int)(distinct_ips - distinct_ports));
	if (well_known_p2p_ports.find(ports_it->first) != well_known_p2p_ports.end()) {
	  if (diff < 10) {
	    // mark as p2p
	    ipports_p2p[ipports_it->first][ports_it->first] = 1;
	  }
	  else if (diff > 20) {
	    // mark as non-p2p
	    ipports_p2p[ipports_it->first][ports_it->first] = 2;
	  }
	}
	else {
	  if (diff < 2 ) {
	    // mark as p2p
	    ipports_p2p[ipports_it->first][ports_it->first] = 1;
	  }
	  else if (diff > 10) {
	    // mark as non-p2p
	    ipports_p2p[ipports_it->first][ports_it->first] = 2;
	  }
	}
      }
    }
  }

  // false positive reducing heuristics
  // note that until now, all valid entries have 1
  // find pairs that match the false positive heuristic and make their entry 0
  map<unsigned long, map<unsigned short, char> >::iterator ipports_p2p_it;
  map<unsigned short, char>::iterator port_p2p_it;
  for (ipports_p2p_it = ipports_p2p.begin(); ipports_p2p_it != ipports_p2p.end(); ipports_p2p_it++) {
    for (port_p2p_it = ipports_p2p_it->second.begin(); port_p2p_it != ipports_p2p_it->second.end(); port_p2p_it++) {

      // gaming and malware heuristic
      if ( (well_known_p2p_ports.find(port_p2p_it->first) == well_known_p2p_ports.end()) &&
	   ( (ipports_bytes[ipports_p2p_it->first][port_p2p_it->first].size() == 1) || (ipports_packetsize[ipports_p2p_it->first][port_p2p_it->first].size() < 3) ) &&
	   ( (ipports_ip[ipports_p2p_it->first][port_p2p_it->first].size() > 5) || (well_known_malware_ports.find(port_p2p_it->first) != well_known_malware_ports.end()) || (port_p2p_it->first< 501) ) ) {
	// mark as non-p2p
	port_p2p_it->second = 2;
      }
      else {
	// port history heuristic
	unsigned int diff = ipports_port[ipports_p2p_it->first][port_p2p_it->first].size() - ipports_good[ipports_p2p_it->first][port_p2p_it->first].size();
	if ( (ipports_flows[ipports_p2p_it->first][port_p2p_it->first] >= p2p_minflow_threshold) && (diff < p2p_wellknown_threshold) ) {
	  // mark as non-p2p
	  port_p2p_it->second = 2;
	}
      }
    }
  }
  // end of heuristic 2 special processing

  ///////////////////////////////////////////////////////////////////
  // post processing - second pass through
  // OK. let's see how many are marked as p2p and/or scan. nine possibilities.
  unsigned long case111 = 0, case110 = 0, case101 = 0, case100 = 0;
  unsigned long case011 = 0, case010 = 0, case001 = 0, case000 = 0;
  unsigned long caseall = 0;
  for(i = 0; i < data.size(); i++) {
    // we only consider unblocked flows and TCP/UDP.
    if ((data[i].dst_mask == 0) || (data[i].protocol != 6 && data[i].protocol != 17)){
      continue;
    }
    caseall++;

    /////////////////////////////////
    // for heuristic 0 - if the flow is on a known p2p port flag it
    // this is mainly for testing/checking purposes...
    if ( well_known_p2p_ports.find(data[i].src_port) != well_known_p2p_ports.end() ||
	 well_known_p2p_ports.find(data[i].dst_port) != well_known_p2p_ports.end()){
      data[i].p2p |= KNOWN_P2P_PORT;
    }

    /////////////////////////////////
    // for heuristic 1 - if src or dst receives both TCP and UDP from the other guy, then this is TCP_UDP.
    if ( ( data[i].is_inbound == 1 &&
	   flow_types[data[i].dst_ip][data[i].src_ip] & TCP_FLOW &&
	   flow_types[data[i].dst_ip][data[i].src_ip] & UDP_FLOW &&
	   !flow_types[data[i].dst_ip][data[i].src_ip] & GOOD_PORT ) ||
	 ( data[i].is_inbound != 1 &&
	   flow_types[data[i].src_ip][data[i].dst_ip] & TCP_FLOW &&
	   flow_types[data[i].src_ip][data[i].dst_ip] & UDP_FLOW &&
	   !flow_types[data[i].src_ip][data[i].dst_ip] & GOOD_PORT ) ){
      // this flow is p2p as per heuristic 1
      data[i].p2p |= TCP_UDP;
    }

    /////////////////////////////////
    // for heuristic 2 - ip/port pair
    // check if srcpair OR dstpair are flagged as p2p pair
    if ( ipports_p2p[data[i].dst_ip][data[i].dst_port] != 2 &&  // dst ipport pair is not non-p2p
	 ipports_p2p[data[i].src_ip][data[i].src_port] != 2 &&  // src ipport pair is not non-p2p
	 (ipports_p2p[data[i].dst_ip][data[i].dst_port] == 1) || (ipports_p2p[data[i].src_ip][data[i].src_port] == 1) // at least one pair is p2p
	 ){
      data[i].p2p |= IP_PORT_COUNT;
    } // end of heuristic 2

    // count by cases.
    if (data[i].scan) {
      if (data[i].p2p & TCP_UDP) {
	if (data[i].p2p & IP_PORT_COUNT) case111++;
	else case110++;
      }
      else {
	if (data[i].p2p & IP_PORT_COUNT) case101++;
	else case100++;
      }
    }
    else {
      if (data[i].p2p & TCP_UDP) {
	if (data[i].p2p & IP_PORT_COUNT) case011++;
	else case010++;
      }
      else {
	if (data[i].p2p & IP_PORT_COUNT) case001++;
	else case000++;
      }
    }
  } // end of for loop.
}
