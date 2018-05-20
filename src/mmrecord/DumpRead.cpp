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


#include "DumpRead.h"
#include <iostream>
#include "macros.h"

void line2mmr(char* buffer, mm_record& mmr){

  //      st.s  st.ms et.s et.ms prt  sip   sprt  dip   dprt  flg  ToS   pckts
  sscanf(buffer,
	 "%lu%*c%u%*c%lu%*c%u%*c%u%*c%lu%*c%hu%*c%lu%*c%hu%*c%c%*c%*c%*c%lu%*c%lu", 
	 &mmr.sts.secs, &mmr.sts.msecs, &mmr.ets.secs, &mmr.ets.msecs, 
	 &mmr.protocol, 
	 &mmr.src_ip, &mmr.src_port, &mmr.dst_ip, &mmr.dst_port,
	 &mmr.flags, &mmr.cpackets, &mmr.cbytes);
}

//void DumpRead(vector<mm_record>& recs){
void dumpRead(long nFlows, std::vector<mm_record>& recs){
  
  DEBUG("Reading the nfdump ... "); fflush(stderr);
  char buffer[1000];
  mm_record mmr;
  long n;
  for(n=0; n<nFlows; n++){
    std::cin.getline(buffer, 1000);
    line2mmr(buffer, mmr);
    if(strlen(buffer)<1) {break;}
    recs.push_back(mmr);
  }
  fprintf(stderr, "Done [%ld flows read].\n", n);

}
