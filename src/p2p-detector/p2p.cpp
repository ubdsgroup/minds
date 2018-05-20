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

#include <vector>
#include <map>
#include <set>
#include <iostream>
#include <fstream>
#include <ctime>
#include <cmath>
#include <algorithm>
#include <time.h>
#include "p2p_detector.h"
#include "mm_record.h"
#include "mm_reader.h"
#include "mindsconfig.h"
#include "xml.h"

using namespace std;


// p2p detection
int print_p2p_details = 1;
unsigned int p2p_success_threshold = 20;
unsigned int p2p_wellknown_threshold = 1;
unsigned int p2p_minflow_threshold = 10;
unsigned int p2p_min_connected_ips = 20;
std::set<unsigned short> well_known_p2p_ports;
std::set<unsigned short> well_known_malware_ports;
std::set<unsigned short> known_good_tcp_udp;
std::set<unsigned short> known_good_ports;

char* mmr_filename=0;
char* output_filename=0;
char* config_filename=0;

#define usage(msg, args...) \
{\
  fprintf(stderr, msg, ##args);\
  fprintf(stderr, \
"Usage:\n\n" \
"./p2p-detector -i mmr_filename -o output_filename -c config_filename\n\n"); \
  exit(1); \
}

void parseArgs(int argc, char** argv){
  int argi;
  for(argi=1; argi<argc; argi++){
    if(strcmp(argv[argi],"-i")==0){
      if(++argi<argc) mmr_filename=strdup(argv[argi]);
      else usage("-i requires mmr file argument\n");
    } else if(strcmp(argv[argi],"-o")==0){
      if(++argi<argc) output_filename=strdup(argv[argi]);
      else usage("-o requires output file argument\n");
    } else if(strcmp(argv[argi],"-c")==0){
      if(++argi<argc) config_filename=strdup(argv[argi]);
      else usage("-c requires config file argument\n");
    } else if(strcmp(argv[argi], "-h")==0 || strcmp(argv[argi], "-?")==0){
      usage("");
    }
    else
      usage("Invalid switch '%s'\n", argv[argi]);
  }
  if(!mmr_filename)     usage("No MMR file specified\n");
  if(!output_filename)  usage("No output file specified\n");
  if(!config_filename)  usage("No config file specified\n");
}

void parse_p2p_config(){
  TiXmlDocument doc;
  if(!doc.LoadFile(config_filename)) SYSERROR("Error opening the config file '%s'\n", config_filename);
  TiXmlNode* nodeRoot = doc.RootElement();
  if(strcmp(nodeRoot->Value(),"mindsconfig")) SYSERROR("Incorrect root node. Must be mindsconfig.\n");
  for(TiXmlNode* child = nodeRoot->FirstChild(); child; child = child->NextSibling() ){
    if(!strcmp(child->Value(),"print_p2p_details"))
      print_p2p_details = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"p2p_success_threshold"))
      p2p_success_threshold = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"p2p_wellknown_threshold"))
      p2p_wellknown_threshold = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"p2p_minflow_threshold"))
      p2p_minflow_threshold = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"p2p_minflow_threshold"))
      p2p_minflow_threshold = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"p2p_min_connected_ips"))
      p2p_min_connected_ips = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"ports")){
      const char * type = ((TiXmlElement*) child)->Attribute("type");
      if(!strcmp(type,"p2p_port"))
 	well_known_p2p_ports.insert(atoi(((TiXmlElement*) child)->GetText()));
      if(!strcmp(type,"malware_port"))
 	well_known_malware_ports.insert(atoi(((TiXmlElement*) child)->GetText()));
      if(!strcmp(type,"good_tcp_udp"))
 	known_good_tcp_udp.insert(atoi(((TiXmlElement*) child)->GetText()));
      if(!strcmp(type,"good_port"))
 	known_good_ports.insert(atoi(((TiXmlElement*) child)->GetText()));
    }
  }
}

int main(int argc, char **argv){
    using namespace std;
    clock_t start, finish;
    double duration;
    vector<mm_record> data;
    ifstream in;
    ofstream out;

    parseArgs(argc,argv);

    // parse p2p_config file
    parse_p2p_config();
    cerr << "config file loaded" << endl;

    start = clock();
    mm_record mmr;
    mm_reader mmrr(mmr_filename);
    mmrr.read(mmr);
    while(mmrr.ok()){
      data.push_back(mmr);
      mmrr.read(mmr);
    }
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    if(!mmrr.eof()) SYSERROR("Incorrect number of bytes read: %d\n", mmrr.len());
    cerr << "Finished reading data (" << data.size() << ") in " << duration << " seconds" << endl;
    //detect p2ps
    cerr <<"Starting the p2p detection module\n";
    start = clock();
    detect_p2p(data,well_known_p2p_ports,well_known_malware_ports,known_good_tcp_udp,known_good_ports);
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    cerr << "Finished detecting p2p in " << duration << " seconds" << endl;
    //write out the data
    out.open(output_filename);    
    for(unsigned int i=0;i<data.size();i++)
      out.write((char *) &mmr, (int)sizeof(mmr));
    out.close();
    out.clear();
    return 1;
}
