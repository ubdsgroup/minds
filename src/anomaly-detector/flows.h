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

#ifndef MINDS_MAIN
#define MINDS_MAIN

#include <string>

#define NUM_DIM 18
#define NUM_BASIC 10
// scan flag in the flow_record
#define NOT_SCAN           0
#define SCAN_WITHOUT_REPLY 1
#define SCAN_WITH_REPLY    2

// p2p flag in the flow_record
#define NOT_P2P 0
#define P2P     1

// hpdt flags in the mm_record
#define NOT_HPDT 0
#define HPDT     1

class record_stats{
public:
    std::vector<float> mean;
    std::vector<float> stdev;
    std::vector<float> stdev_inv;
    int num_features;

    record_stats(int n){
        num_features = n;
        for(int i=0;i<n;++i) {mean.push_back(0); stdev.push_back(0); stdev_inv.push_back(0);}
    }

    ~record_stats(){}

    void prepare(const std::vector<float> &weights){
        for(int i=0; i<num_features; ++i) {
	  if(stdev[i] == 0)
	    stdev_inv[i] = 0;
	  else
            stdev_inv[i] = weights[i]/stdev[i]/stdev[i];
        }
    }
};

class flow_record{
public:
    // extra features
    float duration;          // duration of the flow in seconds
    int network;             // network ID of the network that appears in the flow

    float i_cpackets;
    float i_spackets;

    // features used for distance computation
    float srcip_idf;
    float dstip_idf;
    float src_port_idf;
    float dst_port_idf;
    float protocol_idf;

    // connection window based
    unsigned short unique_inside_src_rate;
    unsigned short same_src_port_rate;
    unsigned short unique_inside_dst_rate;
    unsigned short same_dst_port_rate;

    // time window based
    unsigned short unique_inside_src_count;
    unsigned short same_src_port_count;
    unsigned short unique_inside_dst_count;
    unsigned short same_dst_port_count;

    flow_record(){
        network = 0;
        srcip_idf = dstip_idf = src_port_idf = dst_port_idf = protocol_idf = 0;
        i_cpackets=0;
	i_spackets = 0;
    }
};

int is_inside(unsigned long ip);
void lowercase(std::string &s);

#endif
