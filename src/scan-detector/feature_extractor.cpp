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
#include "FeatureExtractor.h"

char *filename=0;
char *darkIPsFile=0;
char *badPortsFile=0;
char *configFile=0;
char *outputFile=0;
#define usage(msg, args...) \
{\
  fprintf(stderr, msg, ##args);\
  fprintf(stderr, \
"Usage:\n\n" \
"./feature_extractor -i MMR_filename -b blkFilename -d darkIPsFile -c configFile -o outputFile\n\n" \
"The program extract feature of a network trace data set in MMR format\n"\
"and constructs a feature data set on stdout.\n\n"\
"Options:\n"\
"   -i   MMR file name\n"\
"   -d   the text file containing the dark IPs in unsigned long format\n"\
"   -b   the text file containing the bad ports (blk and kbp)\n"\
"   -c   the configuration file containing internal network information\n"\
"   -o   the output file where the extracted features are written out\n");\
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
    } else if(strcmp(argv[argi],"-d")==0){ 
      if(++argi<argc) darkIPsFile=strdup(argv[argi]);
      else usage("-d requires file argument\n");
    } else if(strcmp(argv[argi],"-b")==0){ 
      if(++argi<argc) badPortsFile=strdup(argv[argi]);
      else usage("-b requires file argument\n");
    } else if(strcmp(argv[argi],"-c")==0){ 
      if(++argi<argc) configFile=strdup(argv[argi]);
      else usage("-c requires file argument\n");
    } else if(strcmp(argv[argi],"-o")==0){ 
      if(++argi<argc) outputFile=strdup(argv[argi]);
      else usage("-o requires file argument\n");
    } else 
      usage("Invalid switch '%s'\n", argv[argi]);
  }
  if(!filename)     usage("No MMR file specified\n");
  if(!darkIPsFile)  usage("No dark IPs file specified\n");
  if(!badPortsFile) usage("No bad ports file specified\n");
  if(!configFile)   usage("No config file specified\n");
  if(!outputFile)   usage("No output file specified\n");
}
      

int main(int argc, char **argv){
  using namespace std;
  parseArgs(argc, argv);
  vector<mm_record> buffer;
  mm_record mmr;
  unsigned long total=0;
  FeatureExtractor fe(badPortsFile, darkIPsFile, configFile);
  mm_reader mmrr(filename);
  while(mmrr.ok()){
    mmrr.read(mmr);
    buffer.push_back(mmr);
    total++;
    if((total>SWS && total%SWS==0) || mmrr.eof()){
      //
      // A window is full
      //
      fprintf(stderr, "Processing flows between %ll and %ll\n", 
	      (total%SWS==0?total-2*SWS:total-SWS-total%SWS), total);
      // process a window -- ADD THE JUICE IN HERE
      fe.featureExtract(buffer,outputFile);
      // Sliding the window: delete the first SWS portion of 'buffer'
      vector<mm_record> copy;
      for(unsigned long i=SWS; i<buffer.size(); i++) copy.push_back(buffer[i]);
      buffer.clear();
      for(unsigned long i=0; i<copy.size(); i++) buffer.push_back(copy[i]);
      // Protecting 'total' against overflow 
      if(total>=1000*SWS) total=SWS;
    }
  if(total>2*SWS) break; // DEBUG -- DEBUG -- DEBUG
  }
  if(!mmrr.eof() && total<2*SWS){ // DEBUG - DEBUG - DEBUG
    SYSERROR("Incorrect number of bytes read: %d\n", mmrr.len());
  }

}
