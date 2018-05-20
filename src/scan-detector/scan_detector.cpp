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
#include <iomanip>
#include <vector>
#include <map>
#include <string>
#include "mm_record.h"
#include "mm_reader.h"
#include "utilities.h"
#include "LabelingUnit.h"
#include "scan_detector2.h"
#include "xml.h"

using namespace std;
map<int,int> httpPorts;
map<int,int> ftpPorts;
map<int,int> p2pPorts;
map<unsigned long,int> p2pHosts;
map<unsigned long,int> hpdtHosts;
map<pair<unsigned long, unsigned long>,int> hpdtHostsPairs;

char *filename=0;
char *p2pFilename=0;
char *p2pHostsFilename=0;
char *mmrFilename=0;
char *configFilename=0;
char *outputFilename=0;

int vertPortsPerHost=10;
int vertMinPorts=100;
int drkMinHosts=2;
int drkMinPercent=2;
int blkMinHosts=2;
int srvMinHosts=2;
int srvMinPercent=90;
int nrmMinHosts=2;
int nrmMinPercent=2;
int bckMinHosts=20;
int bckMinPorts=20;
int ignoreP2P=0;
int p2pMinPercent=99;

// required for 2nd level scan detector
unsigned int time_window = 10000000;   // microseconds
unsigned int conn_window = 256;     // connections
float t_score = 1.0;
float c_score = 1.0;

const char *help = " Labels the following types of traffic (in this order of precedence, with no \n" \
" re-labeling allowed): \n" \
" (1) 'norm_bck' backscatter:  \n" \
"     srcip touching at least 'min_hosts' distinct dst ips and 'min_ports' \n" \
"     distinct dst ports from the same source port. \n" \
" (2) 'vscanner' vertical scanner \n" \
"     srcip touching at least 'min_ports' distinct destination ports, \n" \
"     at least 'min_ports_per_host' ports in each dst IP, and is not backscatter. \n" \
" (3) 'norm_p2p' and 'norm_ignorep2p' P2P \n" \
"     (a) the dst port of the flow is a known P2P port. \n" \
"     (b) more than 'min_p2phost_percent' of the destination IPs is p2p host \n" \
"         This requires that the ip2p (ignore P2P hosts) switch is used. \n" \
" (4) 'norm_hpdt' High-port data transfer for FTP, HTTP, and P2P \n" \
"     (a) If the dst ip 'dip' has successfully offered service on at least one \n" \
"         of the FPT (20,21), HTTP (80, 8080) or P2P (ports in p2p_file) to  \n" \
"         'sip', then any traffic between 'sip' and 'dip' on high ports is  \n" \
"         considered high-port data transfer. \n" \
"     (b) If *all* the dst ips of a src ip are p2p hosts and all data transfers \n" \
"         on the given high dst port are successful, than all successful data  \n" \
"         transfers between that pair of hosts on high ports is considered \n" \
"         high-port P2P data transfer. \n" \
" (5) 'norm_trc' and 'norm_ident' -- traceroute and ident by destination port \n" \
" (6) 'norm_srv' -- service-based normal traffic \n" \
"     The srcip touched 'min_norm_ip' distinct dst ips that offered the service \n" \
"     and at least 'min_norm_percent' of the distinct dst ips offered the \n" \
"     service. \n" \
" (7) 'hscnr' Horizontal (aka IP-) scanners. \n" \
"     (3a) 'hscnr_drk' -- scanner who touches too many dark IPs \n" \
"          srcip touched 'min_drk_ip' dark IPs, and at least 'min_fail_percent' \n" \
"          of the dst ip did not offer the requested service. \n" \
"     (3b) 'hscnr_blk' -- scanning on blocked or bad(!) ports \n" \
"          srcip touched 'min_blocked_hosts' dst ips on a blocked port. \n" \
"          [All connections on a blocked port are assumed to fail.] \n" \
"     (3c) 'hscnr_nosrv' -- scanner based on (lack of) service \n" \
"          the srcip must initiate connections to at least 'min_nosrv_hosts' \n" \
"          dstips that do not offer the requested service and at least  \n" \
"          'min_nosrv_percent' percent of the all the dst ips the src ip talked  \n" \
"          to must not offer the requested service. \n" \
" (8) 'dnknw' -- none of the above \n" \
"  \n" \
" Options: \n" \
" -f    name of the unlabeled file as output by 'fe' \n" \
" -pp   list of P2P ports \n" \
" -ph   list of P2P hosts \n" \
" -ip2p for horizontal scan detection, ignore sources for which the percentage \n" \
"       of distinct p2p hosts among all disctinct destination ips exceeds  \n" \
"       min_p2phost_percent and the destination port is a non-priviledged port. \n" \
"     \n" \
" Backscatter:  \n" \
" -bh  minimum number of distinct dst ips [20] and  \n" \
" -bp  minimum number of disticnt dst ports [20] to become source of backscatter \n" \
"  \n" \
" Vertical scanners: \n" \
" -vph minimum number of distinct ports *on each host a src ip* [10] and \n" \
" -vp  minimum number of distinct ports *an any host* [100] to be vscanner \n" \
"  \n" \
" Dark horizontal scanners: \n" \
" -dn  minimum number of distinct dark dst ips [2] \n" \
" -dp  minimum percentage of distinct ips not offering the requested service [90] \n" \
"      \n" \
" Blocked horizontal scanners: \n" \
" -bn  minimum number of distinct dst ips [2] on blocked ports to be vscanner \n" \
"  \n" \
" Service-based horizontal scanners: \n" \
" -sn  minimum number of distinct dst ips [4] that do not offer requested service \n" \
" -sp  minimum percentage of distinct dst ips [90] that to not offer requested \n" \
"      service. \n" \
"  \n" \
" Normal sources: \n" \
" -nn  minimum number of distinct dst ips [2] offering the service \n" \
" -np  minimum percentage of distinct dst ips offereing the service [90] \n" \
"  \n" \
" P2P: \n" \
" -ip  minimum percentage of the distinct dst ips that need to P2P hosts [99] \n";

#define usage(msg, args...) \
{\
  fprintf(stderr, msg, ##args);\
  fprintf(stderr, \
"Usage:\n\n" \
"./scan_detector -i mmr_filename -f unlabeled -o output_mmr_filename \n"\
"         -c config_filename -pp p2p_port_file [-ph p2p_host] \n" \
" Type ./scan_detector -h for a complete help.\n"); \
  exit(1); \
}

void parseArgs(int argc, char** argv){
  int argi;
  for(argi=1; argi<argc; argi++){
    if(strcmp(argv[argi],"-f")==0){ 
      if(++argi<argc) filename=strdup(argv[argi]);
      else usage("-f requires filename argument\n");
    } else if(strcmp(argv[argi], "-h")==0 || strcmp(argv[argi], "-?")==0){
      fprintf(stderr,help);
      usage("");
    } else if(strcmp(argv[argi],"-i")==0){ 
      if(++argi<argc) mmrFilename=strdup(argv[argi]);
      else usage("-i requires mmrFilename argument\n");
    } else if(strcmp(argv[argi],"-c")==0){ 
      if(++argi<argc) configFilename=strdup(argv[argi]);
      else usage("-i requires mmrFilename argument\n");
    } else if(strcmp(argv[argi],"-o")==0){ 
      if(++argi<argc) outputFilename=strdup(argv[argi]);
      else usage("-o requires outputFilename argument\n");
    } else if(strcmp(argv[argi],"-pp")==0){ 
      if(++argi<argc) p2pFilename=strdup(argv[argi]);
      else usage("-pp requires p2pFilename argument\n");
    } else if(strcmp(argv[argi],"-ph")==0){ 
      if(++argi<argc) p2pHostsFilename=strdup(argv[argi]);
      else usage("-ph requires p2pHostsFilename argument\n");
    } else 
      usage("Invalid switch '%s'\n", argv[argi]);
  }
  if(!filename)     usage("No extracted features file specified\n");
  if(!mmrFilename)     usage("No input mmr file specified\n");
  if(!outputFilename)     usage("No output mmr file specified\n");
  if(!configFilename)     usage("No configuration file specified\n");
  if(!p2pFilename)  usage("No P2P port list specified\n");
  if(!p2pHostsFilename)  usage("No P2P hosts list specified\n");

  // Read config parameters
  DEBUG("Reading configuration file '%s' ...", configFilename); fflush(stderr);
  TiXmlDocument doc;
  if(!doc.LoadFile(configFilename)) SYSERROR("Error opening the config file '%s'\n", configFilename);
  TiXmlNode* nodeRoot = doc.RootElement();
  if(strcmp(nodeRoot->Value(),"mindsconfig")) SYSERROR("Incorrect root node. Must be mindsconfig.\n");
  for(TiXmlNode* child = nodeRoot->FirstChild(); child; child = child->NextSibling() ){
    if(!strcmp(child->Value(),"vertPortsPerHost"))
      vertPortsPerHost = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"vertMinPorts"))
      vertMinPorts = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"drkMinHosts"))
      drkMinHosts = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"drkMinPercent"))
      drkMinPercent = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"blkMinHosts"))
      blkMinHosts = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"srvMinHosts"))
      srvMinHosts = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"srvMinPercent"))
      srvMinPercent = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"nrmMinHosts"))
      nrmMinHosts = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"nrmMinPercent"))
      nrmMinPercent = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"bckMinHosts"))
      bckMinHosts = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"bckMinPorts"))
      bckMinPorts = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"ignoreP2P"))
      ignoreP2P = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"p2pMinPercent"))
      p2pMinPercent = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"conn_window"))
      conn_window = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"time_window"))
      time_window = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"t_score"))
      t_score = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"c_score"))
      c_score = atof(((TiXmlElement*) child)->GetText());
  }

}


//--------------------------------------------------------------- 
// Processing the P2P files
//--------------------------------------------------------------- 

void readP2Pports(){
  DEBUG("Reading p2p ports file '%s' ... ", p2pFilename); fflush(stderr);
  int port;
  char proto[10];
  FILE *file=fopen(p2pFilename, "r");
  if(!file) SYSERROR("Error opening p2p ports file '%s'\n", p2pFilename);
  while(fscanf(file, "%s %d", proto, &port)==2){
    if((strcmp(proto, "TCP")==0) || (strcmp(proto, "UDP")==0)){
      p2pPorts[port] = 1;
    }else{
      WARNING("Unexpected protocol '%s'\n", proto);
    }
  }
  fprintf(stderr, "Done. [%d ports read.]\n", p2pPorts.size());
}

void readP2Phosts(){
  DEBUG("Readin p2p hosts file '%s' ... ", p2pHostsFilename); fflush(stderr);
  FILE *file=fopen(p2pHostsFilename, "r");
  if(!file) SYSERROR("Error opening p2p hosts file '%s'\n", p2pHostsFilename);
  char buf[256];
  unsigned long ip;
  while(fscanf(file, "%s", buf)==1){
    string ipstr(buf);
    ip = get_ip(ipstr);
    p2pHosts[ip] = 1;
  }
  fclose(file);
  fprintf(stderr, "Done. [%d IPs read.]\n", p2pHosts.size());
}

void Tokenize(const string& str, vector<string>& tokens,const string& delimiters){
  string::size_type lastPos = str.find_first_not_of(delimiters, 0);
  string::size_type pos     = str.find_first_of(delimiters, lastPos);
  while (string::npos != pos || string::npos != lastPos){
    tokens.push_back(str.substr(lastPos, pos - lastPos));
    lastPos = str.find_first_not_of(delimiters, pos);
    pos = str.find_first_of(delimiters, lastPos);
  }
}

int main(int argc, char *argv[]){
  parseArgs(argc,argv);
  //initialize the http ports and ftp ports
  httpPorts[80] = 1;httpPorts[8080] = 1;
  ftpPorts[21] = 1;
  //read the p2p ports and hosts
  readP2Phosts();readP2Pports();

  map<unsigned long, vector<Info> > ipPortMap;
  map<unsigned long, vector<Info> >::iterator ipPortMapIt;

  //first pass -- find pairs of hosts that have FTP, HTTP or P2P going on
  ifstream f(filename);
  string bufstr;
  if(f.fail()) SYSERROR("Error opening extracted features file '%s'\n", filename);
  while(!f.fail()){
    getline(f,bufstr);
    if(bufstr.length() == 0) continue;
    vector<string> fields(0);
    Tokenize(bufstr,fields," ");
    unsigned long srcip = atol(fields[1].c_str());
    unsigned int dstport = (int) atol(fields[3].c_str());
    unsigned int ndstips = (unsigned int) atol(fields[8].c_str());
    unsigned int nservice = (unsigned int) atol(fields[10].c_str());
    string blocked = fields[14];
    if(fields[14] == "Y") continue;
    /* For dst ips, that the given src ip talked to successfully(!) either
     on an FTP, HTTP or P2P ports, any high-port data transfer will be 
     allowed [even if there is no reply -- for UDP] */
    if((p2pPorts.find(dstport) != p2pPorts.end()) || (httpPorts.find(dstport) != httpPorts.end()) || (ftpPorts.find(dstport) != ftpPorts.end())){
      for(unsigned int i = 15; i < fields.size(); i+=2){
	if(fields[i+1] == "S"){
	  hpdtHosts[srcip] = 1;
	  hpdtHostsPairs[pair<unsigned int, unsigned int>(srcip,atol(fields[i].c_str()))] = 1;
	}
      }
    }
    /* If all destinations are p2p hosts and the transfer succeeds,
       it can be high data transfer.*/
    int allDstsP2PHosts = 1;
    for(unsigned int i = 15; i < fields.size(); i += 2){
      if(p2pHosts.find(atol(fields[i].c_str())) != p2pHosts.end()){
	allDstsP2PHosts = 0;
	break;
      }
    }
    if(allDstsP2PHosts){
      hpdtHosts[srcip] = 1;
      for(unsigned int i = 15; i < fields.size(); i += 2)
	hpdtHostsPairs[pair<unsigned int, unsigned int>(srcip,atol(fields[i].c_str()))] = 1;
    }
  }
  f.close();

  //second pass
  f.open(filename);
  if(f.fail()) SYSERROR("Error opening extracted features file '%s'\n", filename);
  while(!f.fail()){
    getline(f,bufstr);
    if(bufstr.length() == 0) continue;
    vector<string> fields(0);
    Tokenize(bufstr,fields," ");
    unsigned int proto;string proto_str = fields[1];
    if(proto_str == "TCP") proto = TCP;
    if(proto_str == "UDP") proto = UDP;
    if(proto_str == "ICMP") proto = ICMP;
    unsigned long srcip = atol(fields[1].c_str());
    unsigned int srcport = (unsigned int) atol(fields[2].c_str());
    unsigned int dstport = (unsigned int) atol(fields[3].c_str());
    int dpPsi = (int) atol(fields[4].c_str()); //DstPrts Per SrcIP
    double dpPdiPsi = atof(fields[5].c_str()); //ratio of dstIPs/ dstPrts touched by srcIP
    int dpPsisp = (int) atol(fields[6].c_str()); // Dst Ports Per Src IP, Src Port
    double dpPdiPsisp = atof(fields[7].c_str()); //Dst ports Per dst IPs for Src IP, Src Port
    unsigned int ndstips = (unsigned int) atol(fields[8].c_str());//
    unsigned int ndark   = (unsigned int) atol(fields[9].c_str());//number of dark dst IPs per SrcIP, Src Port
    unsigned int nservice = (unsigned int) atol(fields[10].c_str());//number of dst IPs offering service
    double rservice = atof(fields[11].c_str());//ratio of dst IPs offering service among the dstIPs this SrcIP,SrcPrt touched
    double avgbytes = atof(fields[12].c_str());//avg number of bytes over the dst ips
    double avgpckets = atof(fields[13].c_str());//avg number of pckts over the dst ips
    string blocked = fields[14];
    unsigned int nfailure = ndstips - nservice;
    string label = "dnknw";

    // Is it backscatter?
    if( (dpPsisp >= bckMinPorts) && (dpPsisp*100/dpPdiPsisp >= bckMinHosts)){
      if(label == "dnknw") label="norm_bck";
    }

    // Is it vertical scanner?
    if((dpPsi>=vertMinPorts) && (dpPdiPsi>=vertPortsPerHost) && (nservice*100/ndstips<nrmMinPercent)){
      if(label == "dnknw") label="vscanner";
    }

    // Is it p2p?
    if(p2pPorts.find(dstport) != p2pPorts.end()){
      if(label == "dnknw") label="norm_p2p";
    }

    // It is traceroute?
    if((dstport>=33434) && (dstport<33499) ){
      if(label == "dnknw") label="norm_trc";
    }

    // Is it ident?
    if((proto == TCP) && (dstport==113)){
      if(label == "dnknw") label="norm_ident";
    }

    // High-port data transfer
    if((dstport>1024) && ((srcport==0) || (srcport>1024))){
       int hpdt=1;
       for(unsigned int i=15;  i < fields.size();  i+=2){
	 unsigned long dstip = atol(fields[i].c_str());
	 if(fields[i+1] != "S") hpdt=0;
	 if((hpdtHosts.find(srcip) == hpdtHosts.end()) || (hpdtHostsPairs.find(pair<unsigned long, unsigned long>(srcip,dstip)) == hpdtHostsPairs.end())){ 
	   hpdt=0;
	   break;
	 }
       }
       if( hpdt &&  (label  ==  "dnknw")) label="norm_hpdt";
    }

    // Plain normal
    if((nservice>= nrmMinHosts) && (nservice*100/ ndstips>= nrmMinPercent)){
      if( label  ==  "dnknw") label="norm_srv";
    }

    // Blocked
    if( (blocked  ==  "Y") && (ndstips>= blkMinHosts)){
      if( label  ==  "dnknw") label="hscr_blk";
      }

    // Dark
    if((ndark>= drkMinHosts) && (nfailure*100/ ndstips>= drkMinPercent)){
      if( label  ==  "dnknw") label="hscr_dark";
    }

    // Ignore p2p hosts
    if(ignoreP2P && (dstport>1024)){
      int nP2PHosts=0;
      for(unsigned int i=15; i<fields.size(); i+=2){
	if(p2pHosts.find(atol(fields[i].c_str())) != p2pHosts.end())
	  nP2PHosts++;
      }
      if( nP2PHosts*100/ndstips >= p2pMinPercent) {
	if(label == "dnknw") label="norm_ignorep2p";
      }
    }
    // Service-based
    if((nfailure >= srvMinHosts) && (nfailure*100/ndstips >= srvMinPercent)){
      if(label == "dnknw")  label="hscr_nosrv";
    }
    //add to the map
    Info tmpInfo;
    tmpInfo.proto = proto;
    tmpInfo.label = label;
    tmpInfo.sport = srcport;
    tmpInfo.dport = dstport;

    //check if there is already an entry in the map for ip
    ipPortMapIt = ipPortMap.find(srcip);
    if(ipPortMapIt == ipPortMap.end()){
      //create a new entry
      vector<Info> tmpInfoVec;
      tmpInfoVec.push_back(tmpInfo);
      ipPortMap[srcip] = tmpInfoVec;
    } else {
      //insert new structure in that location
      ipPortMap[srcip].push_back(tmpInfo);
    }
  }
  f.close();
  //call the labeling unit here
  LabelingUnit lu(mmrFilename, ipPortMap, outputFilename);

  //call the 2nd scan detector here
  vector<mm_record> mmr_data(0);
  mm_record mmr;
  mm_reader mmrr(outputFilename);
  mmrr.read(mmr);
  while(mmrr.ok()){
    mmr_data.push_back(mmr);
    mmrr.read(mmr);
  }
  detect_scans2(mmr_data, time_window, conn_window, t_score, c_score);
  ofstream out(outputFilename);
  for(unsigned int i = 0; i < mmr_data.size(); i++)
    out.write((char *) &mmr_data[i], (int)sizeof(mmr_data[i]));
  out.close();
}
