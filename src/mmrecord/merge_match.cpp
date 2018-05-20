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
  #     The Regents of the University of Minnesota. All rights reserved.
*/

#include <vector>
#include <fstream>
#include "xml.h"
#include "mm_reader.h"
#include "MergeMatch.h"
#include "mindsconfig.h"

using namespace std;

vector<unsigned long> insidenws;
vector<unsigned long> insidemasks;
char* input_filename=0;
char* output_filename=0;
char* config_filename=0;

#define usage(msg, args...) \
{\
  fprintf(stderr, msg, ##args);\
  fprintf(stderr, \
"Usage:\n\n" \
"./merge-match -i input_filename -o output_filename -c config_filename\n\n"); \
  exit(1); \
}

void parseArgs(int argc, char** argv){
  int argi;
  for(argi=1; argi<argc; argi++){
    if(strcmp(argv[argi],"-i")==0){ 
      if(++argi<argc) input_filename=strdup(argv[argi]);
      else usage("-i requires input mmr file argument\n");
    } else if(strcmp(argv[argi],"-o")==0){
      if(++argi<argc) output_filename=strdup(argv[argi]);
      else usage("-o requires output mmr file argument\n");
    } else if(strcmp(argv[argi],"-c")==0){ 
      if(++argi<argc) config_filename=strdup(argv[argi]);
      else usage("-c requires configuration file argument\n");
    } else if(strcmp(argv[argi], "-h")==0 || strcmp(argv[argi], "-?")==0){
      usage("");
    } 
    else 
      usage("Invalid switch '%s'\n", argv[argi]);
  }
  if(!input_filename)     usage("No MMR file specified\n");
  if(!output_filename)    usage("No output file specified\n");
  if(!config_filename)    usage("No config file specified\n");
}
      
bool insideip(unsigned long ip){
  for(unsigned int i=0; i<insidenws.size(); i++)
    if((ip & insidemasks[i])==insidenws[i]) return true;
  return false;
}

int main(int argc, char **argv){
  parseArgs(argc, argv);
  // Read config parameters
  DEBUG("Reading configuration file '%s' ...", config_filename); fflush(stderr);
  TiXmlDocument doc;
  if(!doc.LoadFile(config_filename)) SYSERROR("Error opening the config file '%s'\n", config_filename);
  TiXmlNode* nodeRoot = doc.RootElement();
  if(strcmp(nodeRoot->Value(),"mindsconfig")) SYSERROR("Incorrect root node. Mu\
st be mindsconfig.\n");
  for(TiXmlNode* child = nodeRoot->FirstChild(); child; child = child->NextSibling() ){
    if(!strcmp(child->Value(),"internal")){
      string mask = "0";
      if(((TiXmlElement*) child)->Attribute("mask"))
        mask = ((TiXmlElement*) child)->Attribute("mask");
      string ipstr = ((TiXmlElement*) child)->GetText();
      insidenws.push_back(get_ip(ipstr));
      insidemasks.push_back(convert_mask(mask));
    }
  }

  vector<mm_record> buffer;
  mm_record mmr;
  unsigned long total=0;
  unsigned int i;
  mm_reader mmrr(input_filename);
  mmrr.read(mmr);
  while(mmrr.ok()){
    buffer.push_back(mmr);
    mmrr.read(mmr);
    total++;
    if(total>=2*SWS) break;
  }
  if(!mmrr.eof() && total<2*SWS){ // DEBUG - DEBUG - DEBUG
    SYSERROR("Incorrect number of bytes read: %d\n", mmrr.len());
  }
  MergeMatch mm;
  vector<mm_record> mmbuffer; // buffer for merge-matched flows
  mm.merge_match(buffer, mmbuffer);
  //write out mmbuffer to output file
  ofstream out;
  out.open(output_filename,ios::out | ios::binary);
  for(i=0;i<mmbuffer.size();i++){
    //check the direction of the flow
    if(insideip(mmbuffer[i].dst_ip) && !(insideip(mmbuffer[i].src_ip))) mmbuffer[i].is_inbound = 1;
    out.write((char*)&mmbuffer[i], (int)sizeof(mmr));
  }
  out.close();
}
