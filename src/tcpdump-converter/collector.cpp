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

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include "pcap.h"
#include "io.h"
#include "read_tcpdump.h"
#include "flowrecord.h"
#include <time.h>
#include <netinet/in.h>

using namespace std;

char datafile[200];		//needs to be global since this is used in the logging
char *df;
void config(std::ifstream & in);

unsigned long file_start_time;
unsigned long num_packets_cleanup = 100000;
int file_close_time = HOUR;
int version=1;

std::ofstream flowfile;
std::ofstream logfile;
pcap_t *descr;

char* tcpdump_filename=0;
char* interface_name=0;
char* output_filename=0;

#define usage(msg, args...) \
{\
  fprintf(stderr, msg, ##args);\
  fprintf(stderr, \
"Usage:\n\n" \
"collector [-i input_tcpdump_filename|-e interface_name] -o output_filename\n\n"); \
  exit(1); \
}

void parseArgs(int argc, char** argv){
  int argi;
  for(argi=1; argi<argc; argi++){
    if(strcmp(argv[argi],"-i")==0){ 
      if(++argi<argc) tcpdump_filename=strdup(argv[argi]);
      else usage("-i requires tcpdump file argument\n");
    } else if(strcmp(argv[argi],"-e")==0){
      if(++argi<argc) interface_name=strdup(argv[argi]);
      else usage("-e requires interface argument\n");
    } else if(strcmp(argv[argi],"-o")==0){
      if(++argi<argc) output_filename=strdup(argv[argi]);
      else usage("-o requires output file argument\n");
    } 
    else 
      usage("Invalid switch '%s'\n", argv[argi]);
  }
  if((!tcpdump_filename)&&(!interface_name))  usage("No input source specified\n");
  if((tcpdump_filename)&&(interface_name))  usage("Only one input source can be specified\n");
  if(!output_filename)  usage("No output file specified\n");
}

int main(int argc, char **argv)
{
  parseArgs(argc,argv);
  char errbuf[PCAP_ERRBUF_SIZE];
  int snaplen = 100;
  ifstream in;
    
  struct bpf_program filter;
  char filter_app[] = "";
  bpf_u_int32 net, mask;
  version=htonl(version);


  logfile.open("errors.log", ios::app);
  struct tm *cur_time;
  time_t cur_sec = time(NULL);
  file_start_time = (unsigned long) cur_sec;
  if (file_close_time == MINUTE) {
    file_start_time = file_start_time - (file_start_time % 60);
  } else if (file_close_time == TEN_MINUTE) {
    file_start_time = file_start_time - (file_start_time % (60 * 10));
  } else if (file_close_time == HALF_HOUR) {
    file_start_time = file_start_time - (file_start_time % (60 * 30));
  } else if (file_close_time == HOUR) {
    file_start_time = file_start_time - (file_start_time % (60 * 60));
  } else if (file_close_time == DAY) {
    file_start_time = file_start_time - (file_start_time % (60 * 60 * 24));
  } else if (file_close_time == WEEK) {
    file_start_time = file_start_time - (file_start_time % (60 * 60 * 24 * 7));
  } else {
    cout << "Unexpected value!!" << endl;
    return 0;
  }
  cur_sec = (time_t) file_start_time;
  cur_time = gmtime(&cur_sec);
  flowfile.open(output_filename, ios::binary);
  flowfile.write((char *) &version, sizeof(int));


  df = datafile;
  if (interface_name){
    strncpy(datafile, interface_name, 200);
    descr = pcap_open_live(datafile, snaplen, 1, 1, errbuf);
    pcap_lookupnet(datafile, &net, &mask, errbuf);
    if (pcap_compile(descr, &filter, filter_app, 0, net) == -1) {
      cout << "error compiling filter" << endl;
    }
    pcap_setfilter(descr, &filter);
  } else if (tcpdump_filename) {
    strncpy(datafile, tcpdump_filename, 200);
    descr = pcap_open_offline(datafile, errbuf);
  }

  log_error("Begining Flow Collection", logfile);

  if (descr == NULL) {
    printf("pcap_open_: %s\n", errbuf);
    exit(1);
  }

  pcap_loop(descr, -1, my_callback, NULL);
  write_open_flows();
  flowfile.close();
  logfile.close();
  return 1;
}

