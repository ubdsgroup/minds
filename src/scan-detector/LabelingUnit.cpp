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


#include "LabelingUnit.h"
#include "utilities.h"
#include "mm_reader.h"
#include <map>
#include <fstream>
#include <string>

using namespace std;

LabelingUnit::LabelingUnit(char* mmr_filename, map<unsigned long, vector<Info> > &ipPortMap, char* output_filename){
  ofstream out(output_filename);
  map<unsigned long, vector<Info> >::iterator ipPortMapIt;
  //read the records from mmrecord file
  mm_record mmr;
  unsigned long total=0;

  mm_reader mmrr(mmr_filename);
  mmrr.read(mmr);
  while(mmrr.ok()){
    //set the scan,p2p and hpdt bits
    ipPortMapIt = ipPortMap.find(mmr.src_ip);
    if(ipPortMapIt != ipPortMap.end()){
      for(unsigned int i=0;i<(ipPortMapIt->second).size();i++){
	if(((ipPortMapIt->second)[i].sport == mmr.src_port) && ((ipPortMapIt->second)[i].dport == mmr.dst_port)){// && ((ipPortMapIt->second)[i].proto == mmr.protocol)){
	  char *labelChar = (char *)(ipPortMapIt->second)[i].label.c_str();
	  if((strcmp(labelChar,"norm_p2p") == 0) || (strcmp(labelChar,"norm_ignorep2p") == 0)){
	    mmr.p2p = 1;
	  }
	  if(strcmp(labelChar,"norm_hpdt") == 0){
	    mmr.hpdt = 1;
	  }
	  if((strcmp(labelChar,"hscr_blk") == 0)||(strcmp(labelChar,"hscr_dark") == 0)||(strcmp(labelChar,"hscr_nosrv") == 0)){
	    mmr.scan = 1;
	  }
	}
      }
    }
    out.write((char *) &mmr, (int)sizeof(mmr));
    mmrr.read(mmr);
    total++;
    if(total>=2*SWS) break;
  }
  out.close();
  if(!mmrr.eof() && total<2*SWS){ // DEBUG - DEBUG - DEBUG
    SYSERROR("Incorrect number of bytes read: %d\n", mmrr.len());
  }
}
