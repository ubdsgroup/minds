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


#include "mm_reader.h"
#include <vector>
#include "mindsconfig.h"
#include "mm_record.h"

char *filename=0;

#define usage(msg, args...) \
{\
  fprintf(stderr, msg, ##args);\
  fprintf(stderr, \
"Usage:\n\n" \
"mm_cat -i MMR_filename  \n\n" \
"The program display MMR records in a human legible format.\n"\
"Options:\n"\
"   -i   MMR file name\n");\
  exit(1); \
}


void parseArgs(int argc, char** argv){
  int argi;
  for(argi=1; argi<argc; argi++){
    if(strcmp(argv[argi],"-i")==0){ 
      if(++argi<argc) filename=strdup(argv[argi]);
      else usage("-i requires file argument\n");
    } else if(strcmp(argv[argi], "-h")==0 || strcmp(argv[argi], "-?")==0){
      usage("");
    } 
    else 
      usage("Invalid switch '%s'\n", argv[argi]);
  }
  if(!filename)     usage("No MMR file specified\n");
}
int main(int argc, char **argv){
  using namespace std;
  parseArgs(argc, argv);
  vector<mm_record> buffer;
  mm_record mmr;
  unsigned long total=0;

  mm_reader mmrr(filename);
  mmrr.read(mmr);
  while(mmrr.ok()){
    buffer.push_back(mmr);
    total++;
    cout<<mmr<<"\n";
    if((total>SWS && total%SWS==0) || mmrr.eof()){
      // Sliding the window: delete the first SWS portion of 'buffer'
      vector<mm_record> copy;
      for(unsigned long i=SWS; i<buffer.size(); i++) copy.push_back(buffer[i]);
      buffer.clear();
      for(unsigned long i=0; i<copy.size(); i++) buffer.push_back(copy[i]);
      // Protecting 'total' against overflow 
      if(total>=1000*SWS) total=SWS;
    }
    mmrr.read(mmr);
    if(total>2*SWS) break; // DEBUG -- DEBUG -- DEBUG
  }
  if(!mmrr.eof() && total<2*SWS){ // DEBUG - DEBUG - DEBUG
    SYSERROR("Incorrect number of bytes read: %d\n", mmrr.len());
  }
}
