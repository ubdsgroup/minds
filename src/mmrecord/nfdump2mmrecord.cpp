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
 * mm -- code for merging and matching flows
 *
 * Input: unidirectional flows in nfdump in 'pipe' format
 * Output: merged matched flows in CFF
 *
 * Usage:
 * nfdump -R ~dokas/flows/nfsen/telecomb/xxx1:xxx2 -o pipe | nfdump2mmrecord <mmr-file>
 */

#include "mm_record.h"
#include "macros.h"
#include "DumpRead.h"
#include <fstream>
#include <iostream>
#include <vector>

int main(int argc, char** argv){

  using namespace std;

  if(argc!=2){
    cerr<<"Usage:\n\n"
	<<"nfdump -R <net-flow-file> -o pipe| nfdump2mmrecord <mmr-file>\n\n";
    exit(1);
  }
  char buffer[1000];
  int total = 0;
  int multiple = 1;
  ofstream out(argv[1], ios::out | ios::binary);

  while(true){
    std::cin.getline(buffer, 1000);
    if(strlen(buffer) < 1) break;
    mm_record mmr;
    line2mmr(buffer,mmr);
    out.write((char*)&mmr, (int)sizeof(mmr));
    total++;
    if(total == multiple*1000000){
      cerr<<multiple<<" million records read\n";
      multiple++;
    }
  }
  out.close();
  DEBUG("%d records [of size %d] read\n", total, sizeof(mm_record));
}
