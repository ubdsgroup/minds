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

#include "eee_flows.h"
#include "mm_record.h"
#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void usage(const char* prgname){
  std::cerr<<"Usage:\n\n";
  std::cerr<<prgname<<" -i <flow-file> -o <mmr-file>\n\n";
  exit(1);
}

void e2mmrecord(eee_record *eee, mm_record *mmr){
  eee->ssecs = ntohl(eee->ssecs);
  eee->susecs = ntohl(eee->susecs);
  eee->esecs = ntohl(eee->esecs);
  eee->eusecs = ntohl(eee->eusecs);
  
  eee->sip = ntohl(eee->sip);
  eee->sport = ntohs(eee->sport);
  eee->dip = ntohl(eee->dip);
  eee->dport = ntohs(eee->dport);
  
  eee->cpackets = ntohl(eee->cpackets);
  eee->spackets = ntohl(eee->spackets);
  eee->cbytes = ntohl(eee->cbytes);
  eee->sbytes = ntohl(eee->sbytes);
  eee->cdbytes = ntohl(eee->cdbytes);
  eee->sdbytes = ntohl(eee->sdbytes);
  eee->window_size = ntohs(eee->window_size);
  
  //convert eee to mmr
  mmr->sts.secs = eee->ssecs;
  mmr->sts.msecs = eee->susecs/1000;
  mmr->ets.secs = eee->esecs;
  mmr->ets.msecs = eee->eusecs/1000;
  
  
  mmr->src_ip = eee->sip;
  mmr->src_port = eee->sport;
  mmr->dst_ip = eee->dip;
  mmr->dst_port = eee->dport;
  
  mmr->spackets = eee->spackets;
  mmr->cpackets = eee->cpackets;
  mmr->sbytes = eee->sbytes;
  mmr->cbytes = eee->cbytes;
  
  mmr->protocol = eee->protocol;
  mmr->flags = eee->flags;
  
  mmr->scan = NOT_SCAN;
  mmr->p2p  = NOT_P2P;
  mmr->hpdt  = NOT_P2P;
  mmr->lof_anomaly_score = 0.0;
}

int main(int argc, char** argv){
  using namespace std;
  char* infilename=NULL;
  char* outfilename=NULL;
  long  total=0;

  for(int i=1; i<argc; i++){
    if(strncmp(argv[i], "-i", 2)==0) infilename=strdup(argv[++i]);
    else if(strncmp(argv[i], "-o", 2)==0) outfilename=strdup(argv[++i]);
    else{
      cerr<<"Invalid argument "<<argv[i]<<endl;
      usage(argv[0]);
    }
  }
  if(!infilename || !outfilename) usage(argv[0]);
     
  int in;
  if((in=::open(infilename, O_RDONLY))<0)
     SYSERROR("Error opening file '%s'\n", infilename);

  ofstream out(outfilename, ios::out | ios::binary);
  if(!out.good()) SYSERROR("Error creating '%s'\n", outfilename);

  ssize_t len=1; // Anything but 0
  int version;
  len=::read(in, (char*)&version, 4);
  version=ntohl(version);
  if(len!=(ssize_t)4) 
    SYSERROR("Error reading '%s' at the version information\n", infilename);
  mm_record mmr;
  eee_record eee;
  while(len!=0){
    len = ::read(in, (char*)&eee, sizeof(eee_record));
    if(len<(size_t)sizeof(eee_record) && len!=(size_t)0)
      DEBUG("Error reading '%s': record %ld, pos %ld.\n", 
	    infilename, total, len);
    if(len==(size_t)0) break;
    e2mmrecord(&eee,&mmr);
    out.write((char*)&mmr, sizeof(mm_record));
    if(!out.good()) 
      DEBUG("Write error after %ld records\n", total);
    total++;
  }
  DEBUG("%ld records read\n", total);
  ::close(in);
  out.close();
}
