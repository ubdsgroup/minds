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

#include "nf2mmrecord.h"
#include "mm_record.h"
#include "macros.h"
#include <fstream>

unsigned long total;

struct l_root{
    struct l_record* first;
    struct l_record* last;
};

extern "C" void get_records(struct l_root *root, unsigned long *first, unsigned long *last);

void nf2mmrecord(struct l_record *nf, mm_record *mmr){
  mmr->sts.secs       = nf->first_sec;
  mmr->sts.msecs      = nf->first_msec;
  mmr->ets.secs       = nf->last_sec;
  mmr->ets.msecs      = nf->last_msec;
  
  mmr->src_ip         = nf->srcip;
  mmr->src_port       = nf->src_port;
  mmr->dst_ip         = nf->dstip;
  mmr->dst_port       = nf->dst_port;
  
  mmr->cbytes         = nf->octets;
  mmr->sbytes         = 0;
  mmr->cpackets       = nf->packets;
  mmr->spackets       = 0;
  
  mmr->src_mask       = nf->src_mask;
  mmr->dst_mask       = nf->dst_mask;
  mmr->src_as         = nf->src_as;
  mmr->dst_as         = nf->dst_as;
  
  mmr->flags          = nf->tcp_flags;
  
  mmr->protocol       = nf->protocol;
  
  mmr->p2p            = NOT_P2P;
  mmr->hpdt           = NOT_HPDT;
  mmr->scan           = NOT_SCAN;
  mmr->lof_anomaly_score   = 0;
}

// io function uses the flow-tools library to read data from stdin and sorts it
bool io(std::ofstream& out){
    using namespace std;
    struct l_root l_root;
    struct l_record* record;
    unsigned long first;
    unsigned long last;
    get_records(&l_root, &first, &last);
    record = l_root.first;
    while(record != NULL){
      mm_record mmr;
      nf2mmrecord(record,&mmr);
      total++;
      out.write((char*)&mmr, (int)sizeof(mmr));
      struct l_record* record2 = record->next;
      free(record);
      record = record2;
    }
    return 1;
}

int main(int argc, char** argv){
  using namespace std;
  if(argc!=2){
    cerr<<"Usage:\n\n"
	<<"cat <net-flow-file> | ./nf2mmrecord <mmr-file>\n\n";
    exit(1);
  }
  ofstream out(argv[1], ios::out | ios::binary);
  io(out);
  out.close();
  DEBUG("%ld records [of size %d] read\n", total, sizeof(mm_record));
}

