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

#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <time.h>
#include <stdio.h>
#include "io.h"
#include "flows.h"
#include "mm_record.h"
#include "mm_reader.h"
#include <string.h>
#include <netinet/in.h>
#include <ctime>
#include <map>
#include <netdb.h>
#include <strings.h>


using namespace std;

map<unsigned char, string> prot_map;
map<unsigned char, string>::iterator prot_map_it;

#define PBUFSIZE 20

#ifndef FLT_MAX
#define FLT_MAX 3.40282346E+38F
#endif

extern vector<mm_record> thevec;

// fills the buffer with the dotted notation
// assumes buf has enough space
void ip2str(unsigned long ip, unsigned char mask, char *buf){
    sprintf(buf,"%lu.%lu.%lu.%lu/%-d", ((ip & 0xFF000000) >> 24),
                                        ((ip & 0xFF0000  ) >> 16),
                                        ((ip & 0xFF00    ) >> 8 ),
                                        ((ip & 0xFF      )      ),
                                        24);
}

int MAX_IO_ERRORS = 1000; // io will fail after MAX_IO_ERRORS
int NUM_BUCKETS   = 1024; // bucket sort is used for time sorting the data

// used for sorting the flow records
bool compare_time_ptr2(mm_record *a, mm_record *b) {
    if(a->sts.secs < b->sts.secs) return 1;
    else if(a->sts.secs > b->sts.secs) return 0;
    else return a->sts.msecs < b->sts.msecs;
}

std::string flags2string(unsigned char flags){
    string s = "";
    if((flags & 0x80) == 0x80) s += "R";
    else s += "*";
    if((flags & 0x40) == 0x40) s += "R";
    else s += "*";
    if((flags & 0x20) == 0x20) s += "U";
    else s += "*";
    if((flags & 0x10) == 0x10) s += "A";
    else s += "*";
    if((flags & 0x08) == 0x08) s += "P";
    else s += "*";
    if((flags & 0x04) == 0x04) s += "R";
    else s += "*";
    if((flags & 0x02) == 0x02) s += "S";
    else s += "*";
    if((flags & 0x01) == 0x01) s += "F";
    else s += "*";
    return s;
}

int io(char *filename, std::vector<mm_record> &mmr_data,std::vector<flow_record> &flow_data){
    using namespace std;
    int size = 0;
    int j, k;
    //unsigned int i;
    time_t fs, ff;
    clock_t start, finish;

    size = 0;
    start=clock();

    mm_record mmr;
    start=clock();
    fs=time(NULL);
    mm_reader mmrr(filename);
    mmrr.read(mmr);
    while(mmrr.ok()){
      mmr_data.push_back(mmr);
      flow_data.push_back(flow_record());
      bzero((void*)(&flow_data[size]), sizeof(flow_record));
      if(mmr_data[size].cpackets != 0)
	flow_data[size].i_cpackets  = (float)1.0/mmr_data[size].cpackets;
      else
	flow_data[size].i_cpackets  = FLT_MAX;
	
      if(mmr_data[size].spackets != 0)
	flow_data[size].i_spackets  = (float)1.0/mmr_data[size].spackets;
      else
	flow_data[size].i_spackets  = FLT_MAX;

      flow_data[size].duration   = float(mmr_data[size].ets.secs  - mmr_data[size].sts.secs)*1000000 +
	float(mmr_data[size].ets.msecs - mmr_data[size].sts.msecs);
            
      j = is_inside(mmr_data[size].src_ip);
      k = is_inside(mmr_data[size].dst_ip);
      if(j) { // srcip is inside our network
	mmr_data[size].is_inbound = 1;
	flow_data[size].network = j-1;
      }
      else { // srcip is not inside our network
	mmr_data[size].is_inbound = 0;
	if(k != 0) flow_data[size].network = k-1;
      }
      size++;
      mmrr.read(mmr);
    }
    finish=clock();
    ff=time(NULL);
    cerr<<"copying to minds format took "<<ff-fs<<" wall clock seconds"<<endl;
    return 1;
}

void print_time(unsigned long seconds, unsigned long milliseconds, std::ostream &out){
    using namespace std;
    char buf[256];
    tm *tm;
    tm = localtime((time_t*)&seconds);
    sprintf(buf, "%-4.4d%-2.2d%-2.2d.%-2.2d:%-2.2d:%-2.2d.%-3.3lu ",   
           (int)tm->tm_year+1900, (int)tm->tm_mon+1, (int)tm->tm_mday, (int)tm->tm_hour,
           (int)tm->tm_min, (int)tm->tm_sec, (unsigned long)milliseconds);
    out << buf;
}

void print_duration(unsigned long ss, unsigned long es, std::ostream &out){
    using namespace std;
    char buf[256];
    unsigned long duration;
    duration=es-ss;
    tm *tm;
    tm = gmtime((time_t*)&duration);
    sprintf(buf, "%-2.2d:%-2.2d:%-2.2d ", (int)tm->tm_hour, (int)tm->tm_min, (int)tm->tm_sec);
    out << buf;
}

void fill_protocol_name(mm_record * a, char *buf, int bufsize)
{
    struct protoent *pro;
    if((prot_map_it=prot_map.find(a->protocol))!=prot_map.end()) {
        strcpy(buf, prot_map[a->protocol].c_str());
        return;
    }
    pro = getprotobynumber(a->protocol);
    if (pro) {
        strncpy(buf, pro->p_name, bufsize);
        prot_map[a->protocol]=buf;
    } else {
        snprintf(buf, bufsize, "%d", a->protocol);
        prot_map[a->protocol]=buf;
    }
}

void print_mmr_record(mm_record *m, std::ostream &out){
    using namespace std;
    char buf1[20], buf2[20], buf[256], protobuf[PBUFSIZE];
    unsigned int scanbit = 0,p2pbit = 0,hpdtbit = 0;
    if(m->p2p == NOT_P2P) p2pbit = 0;
    else p2pbit = 1;
    if(m->scan == NOT_SCAN) scanbit = 0;
    else if(m->scan == SCAN_WITHOUT_REPLY) scanbit = 1;
    else if(m->scan == SCAN_WITH_REPLY) scanbit = 2;
    if(m->hpdt == NOT_HPDT) hpdtbit = 0;
    else hpdtbit = 1;
    print_time((m->sts).secs, (m->sts).msecs, out);
    print_duration((m->sts).secs, (m->ets).secs, out);
    ip2str(m->src_ip, m->src_mask, buf1);
    ip2str(m->dst_ip, m->dst_mask, buf2);
    fill_protocol_name(m, protobuf, PBUFSIZE);
    if(m->protocol==6){//tcp flow
      sprintf(buf, "%-20s %-6u %-20s %-6u %-5s %u ", buf1, m->src_port, buf2, m->dst_port, protobuf, 0);
      out<<buf;
      sprintf(buf, "%-10s %u %-8lu %-10lu %-8lu %-10u %u %u %u %u %-4.2f %-4.2f", flags2string(m->flags).c_str(),0,m->cpackets, m->cbytes,m->spackets, m->sbytes,p2pbit, scanbit, hpdtbit, m->is_inbound, m->lof_anomaly_score);
      out << buf;
    }
    else if(m->protocol==17){//udp flow
      sprintf(buf,"%-20s %-6u %-20s %-6u %-5s %u " , buf1, m->src_port, buf2, m->dst_port, protobuf, 0);
      out<<buf;
      sprintf(buf,"%-10s %u %-8lu %-10lu %-8lu %-10u %u %u %u %u %-4.2f %-4.2f","********",0,m->cpackets, m->cbytes,m->spackets, m->sbytes,p2pbit, scanbit, hpdtbit, m->is_inbound, m->lof_anomaly_score);
      out << buf;
    }
    else if(m->protocol==1){//icmp flow
      sprintf(buf,"%-20s %-6d %-20s %-6d %-5s %u " , buf1, -1, buf2, -1, protobuf, 0);
      out<<buf;
      sprintf(buf,"%-10s %u %-8lu %-10lu %-8lu %-10u %u %u %u %u %-4.2f %-4.2f","********",0,m->cpackets, m->cbytes,m->spackets, m->sbytes,p2pbit, scanbit, hpdtbit, m->is_inbound, m->lof_anomaly_score);
      out << buf;
    }
    else{//other protocols
      sprintf(buf,"%-20s %-6u %-20s %-6u %-5s %u " , buf1, m->src_port, buf2, m->dst_port, protobuf, 0);
      out<<buf;
      sprintf(buf,"%-10s %u %-8lu %-10lu %-8lu %-10u %u %u %u %u %-4.2f %-4.2f","********", 0,m->cpackets, m->cbytes,m->spackets, m->sbytes,p2pbit, scanbit, hpdtbit, m->is_inbound, m->lof_anomaly_score);
      out << buf;
    }
    out <<" ";
}

void print_anomaly_scores(std::pair<float, mm_record*> &score, std::ostream &out){
    using namespace std;
    char buf[20];
    sprintf(buf, "%G ", score.first);
    out << buf;
    print_mmr_record(score.second, out);
}

void print_contributions(std::vector<float> &contrib, std::ostream &out){
    using namespace std;
    for(int i=0; i<NUM_DIM; ++i) {    char buf[100];sprintf(buf,"%4.2f ", contrib[i]);
    out << buf;}
}

void save_train(std::vector<pair<mm_record*,flow_record*> > &fr, std::ostream &out){
  for(unsigned int i=0;i<fr.size();++i)
    out.write((char *) fr[i].first, (int)sizeof(fr[i].first));
}

bool load_train(char *train_filename, std::vector<mm_record> &mmr_train_data,std::vector<flow_record> &flow_train_data){
  io(train_filename, mmr_train_data,flow_train_data);
  return 1;
}
