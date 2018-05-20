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


#include <iomanip>
#include <string>
#include <vector>
#include <fstream>
#include "FeatureExtractor.h"
#include "mindsconfig.h"
#include "MergeMatch.h"
#include "Count2.h"
#include "utilities.h"
#include "mm_record.h"
#include "xml.h"

std::vector<unsigned long> insidenws;
std::vector<unsigned long> insidemasks;
#define SERVICE   10
#define NOSERVICE 11
#define DARK      12

bool insideip(unsigned long ip){
  for(unsigned int i=0; i<insidenws.size(); i++)
    if((ip & insidemasks[i])==insidenws[i]) return true;
  return false;
}

void lowercase(std::string &s){
    for(std::string::iterator it=s.begin(); it!=s.end(); ++it)
        if(*it>='A' && *it<='Z') *it += 'a' - 'A';
}

struct SISPKey {  // Key for the SrcIP SrcPort index
  unsigned char  proto;
  unsigned long  srcip;
  unsigned short srcport;
  SISPKey(mm_record& mmr): proto(mmr.protocol), srcip(mmr.src_ip), srcport(mmr.src_port) {};
  SISPKey(unsigned char pr=0, unsigned long si=0, unsigned short sp=0){ 
    proto=pr; srcip=si, srcport=sp;
  }
};

struct lt_SISPKey { // Comparison function of SISPKey
  bool operator() (const SISPKey& k1, const SISPKey& k2){
    if(k1.proto<k2.proto) return true;
    if(k1.proto>k2.proto) return false;
    if(k1.srcip<k2.srcip) return true;
    if(k1.srcip>k2.srcip) return false;
    return (k1.srcport<k2.srcport);
  }
};

struct SIDPKey { // Key for the SrcIP DstPort index
  unsigned char  proto;
  unsigned long  srcip;
  unsigned short dstport;
  SIDPKey(mm_record& mmr): proto(mmr.protocol), srcip(mmr.src_ip), dstport(mmr.dst_port) {};
  SIDPKey(unsigned char pr=0, unsigned long si=0, unsigned short dp=0){ 
    proto=pr; srcip=si, dstport=dp;
  }
};

struct lt_SIDPKey { // Comparison function of SIDPKey
  bool operator() (const SIDPKey& k1, const SIDPKey& k2){
    if(k1.proto<k2.proto) return true;
    if(k1.proto>k2.proto) return false;
    if(k1.srcip<k2.srcip) return true;
    if(k1.srcip>k2.srcip) return false;
    return (k1.dstport<k2.dstport);
  }
};

struct SIKey { 
  unsigned char proto;
  unsigned long srcip;
  SIKey(mm_record& mmr): proto(mmr.protocol), srcip(mmr.src_ip) {};
  SIKey(unsigned char pr=0, unsigned long si=0): proto(pr),srcip(si) {};
};

struct lt_SIKey {
  bool operator() (const SIKey &k1, const SIKey &k2){
    if(k1.proto<k2.proto) return true;
    if(k1.proto>k2.proto) return false;
    return (k1.srcip<k2.srcip);
  }
};

// Statistics for each source IP
struct SIStats {
  int ndstports;  // number of distinct dst ports touched
  int ndstips;    // number of distinct dst ips touched
  SIStats(int ndp=0, int ndi=0): ndstports(ndp), ndstips(ndi) {};
};

// Statistics for each srcIP,srcPort pair
struct SISPStats {
  int ndstports;  // number of distinct dst ports
  int ndstips;    // number of distinct dst ips
  SISPStats(int ndp=0, int ndi=0):ndstports(ndp), ndstips(ndi) {};
};

// Statistics for each srcIP, dstPport pair
struct SIDPStats {
  int            ndstips;    // number of distinct dst IPs touched
  int            ndarkips;   // how many of those were dark 
  int            nservice;   // how many offered service
  int            dstportfreq;// freq. of the dst port
  double         adstfreq;   // average freq of the destinations
  double         avgbytes;   // avg # of octets to these dst IPs
  double         avgpackets; // avg # of packets to these dst IPs
  bool           blocked;    // is the dstPort blocked or known bad?
  unsigned short srcport;    // all touches came from this srcport or 0
  SIDPStats(int ndi=0, int ndark=0, int nserv=0, int dpf=0, 
	    double adf=0, double avgb=0.0, double avgp=0.0, 
	    bool blk=false, unsigned short sp=0):
    ndstips(ndi), ndarkips(ndark), nservice(nserv), dstportfreq(dpf),
    adstfreq(adf), avgbytes(avgb), avgpackets(avgp), 
    blocked(blk), srcport(sp) {};
};

FeatureExtractor::FeatureExtractor(const char *blkFile, const char *darkFile, const char *configFile){
  using namespace std;

  // Read config parameters
  DEBUG("Reading configuration file '%s' ...", configFile); fflush(stderr);
  TiXmlDocument doc;
  if(!doc.LoadFile(configFile)) SYSERROR("Error opening the config file '%s'\n", configFile);
  TiXmlNode* nodeRoot = doc.RootElement();
  if(strcmp(nodeRoot->Value(),"mindsconfig")) SYSERROR("Incorrect root node. Must be mindsconfig.\n");
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
  //
  // Read bad ports
  //
  DEBUG("Reading bad ports file '%s' ... ", blkFile); fflush(stderr);
  int port;  
  int tcpcnt=0, udpcnt=0;
  char proto[10];
  for(int i=0; i<(1<<16); i++){ 
    tcpPorts[(unsigned short)i]=false;
    udpPorts[(unsigned short)i]=false;
  }
  FILE *file=fopen(blkFile, "r");
  if(!file) SYSERROR("Error opening bad ports file '%s'\n", blkFile);
  while(fscanf(file, "%s %d", proto, &port)==2){
    if(strcmp(proto, "TCP")==0){
      tcpPorts[(unsigned short)port]=true;
    } else if(strcmp(proto, "UDP")==0){
      udpPorts[(unsigned short)port]=true;
    } else {
      WARNING("Unexpected protocol '%s'\n", proto);
    }
  }
  fclose(file);
  for(int i=0; i<(1<<16); i++) {
    if(tcpPorts[(unsigned short)i]) tcpcnt++;
    if(udpPorts[(unsigned short)i]) udpcnt++;
  }
  fprintf(stderr, "Done. [%d TCP %d UDP ports read.]\n", tcpcnt, udpcnt);

  //
  // Read dark IPs
  //
  DEBUG("Readin dark IPs file '%s' ... ", darkFile); fflush(stderr);
  file=fopen(darkFile, "r");
  if(!file) SYSERROR("Error opening dark IPs file '%s'\n", darkFile);
  char buf[256];
  unsigned long ip;
  while(fscanf(file, "%s", buf)==1){
    pair<unsigned long, bool> pr;
    string ipstr(buf);
    ip = get_ip(ipstr);
    pr.first=ip;
    pr.second=true;
    darkIPs.insert(pr);
  }
  fclose(file);
  fprintf(stderr, "Done. [%ld IPs read.]\n", darkIPs.size());
}

void FeatureExtractor::featureExtract(std::vector<mm_record>& buffer,char *outputFile){
  using namespace std;
  ofstream out(outputFile);
  MergeMatch mm;
  vector<mm_record> mmbuffer = buffer;
  DEBUG("Building the port frequency table ... "); fflush(stderr);
  unsigned int tcppf[1<<16];
  unsigned int udppf[1<<16];
  for(int i=0; i<(1<<16); i++){
    tcppf[i]=0;
    udppf[i]=0;
  }
  for(unsigned long i=0; i<mmbuffer.size(); i++){
    if(mmbuffer[i].src_port==0 || mmbuffer[i].dst_port==0) continue;
    if(mmbuffer[i].protocol==TCP){
      tcppf[mmbuffer[i].src_port]++;
      tcppf[mmbuffer[i].dst_port]++;
    } else if(mmbuffer[i].protocol==UDP){
      udppf[mmbuffer[i].src_port]++;
      udppf[mmbuffer[i].dst_port]++;
    }
  }
  fprintf(stderr, "Done.\n");

  //
  // (3) Build the usage matrix
  //
  DEBUG("Building the usage matrix... "); fflush(stderr);
  Count tcpscnt;   // count of successful TCP flows into that destination
  Count udpscnt;
  Count tcpqcnt;
  Count udpqcnt;
  Count tcpfcnt;
  Count udpfcnt;
  for(unsigned long i=0; i<mmbuffer.size(); i++){
    mm_record& mmr = mmbuffer[i];

    if(!insideip(mmr.dst_ip)) {continue;} // only inside dsts.

    if(succeeded(mmr)){
      if(mmr.protocol==TCP) tcpscnt.incr(mmr.dst_ip, mmr.dst_port);
      else if(mmr.protocol==UDP) udpscnt.incr(mmr.dst_ip, mmr.dst_port);
    } else if(! failed(mmr)){
      if(mmr.protocol==TCP) tcpqcnt.incr(mmr.dst_ip, mmr.dst_port);
      else if(mmr.protocol==UDP) udpqcnt.incr(mmr.dst_ip, mmr.dst_port);
    } else {
      if(mmr.protocol==TCP) tcpfcnt.incr(mmr.dst_ip, mmr.dst_port);
      else if(mmr.protocol==UDP) udpfcnt.incr(mmr.dst_ip, mmr.dst_port);
    }
  }
  fprintf(stderr, "Done.\n");

  //
  // (4) Build the scan detection index
  //
  DEBUG("Building the scan detection index... "); fflush(stderr);
  map<SISPKey, vector<int>, lt_SISPKey> sispIdx;
  map<SIDPKey, vector<int>, lt_SIDPKey> sidpIdx;
  map<SIKey, vector<int>, lt_SIKey> siIdx;

  for(unsigned long i=0; i<mmbuffer.size(); i++){
    
    mm_record &mmr = mmbuffer[i];

    if(mmr.protocol!=TCP && mmr.protocol!=UDP) {continue;}
    if(insideip(mmr.src_ip)) {continue;}

    map<SIKey, vector<int>, lt_SIKey>::iterator siIdxIt;
    SIKey siKey(mmr);
    siIdxIt=siIdx.find(siKey);
    if(siIdxIt==siIdx.end()){
      pair<SIKey, vector<int> > siPair;
      siPair.first = siKey;
      siPair.second.push_back(i);
      siIdx.insert(siPair);
    } else {
      siIdxIt->second.push_back(i);
    }
    map<SISPKey, vector<int>, lt_SISPKey>::iterator sispIdxIt;
    SISPKey sispKey(mmr);
    sispIdxIt=sispIdx.find(sispKey);
    if(sispIdxIt==sispIdx.end()){
      pair<SISPKey, vector<int> > sispPair;
      sispPair.first = sispKey;
      sispPair.second.push_back(i);
      sispIdx.insert(sispPair);
    } else {
      sispIdxIt->second.push_back(i);
    }
    map<SIDPKey, vector<int>, lt_SIDPKey>::iterator sidpIdxIt;
    SIDPKey sidpKey(mmr);
    sidpIdxIt=sidpIdx.find(sidpKey);
    if(sidpIdxIt==sidpIdx.end()){
      pair<SIDPKey, vector<int> > sidpPair;
      sidpPair.first = sidpKey;
      sidpPair.second.push_back(i);
      sidpIdx.insert(sidpPair);
    } else {
      sidpIdxIt->second.push_back(i);
    }
  }
  fprintf(stderr, "Done.\n");

  //
  // (4) Extracting the features
  //
  // SI Stats
  DEBUG("Extracting the SI <SrcIP> features ... "); fflush(stderr);
  map<SIKey, SIStats, lt_SIKey> siStats;
  map<SIKey, vector<int>, lt_SIKey>::iterator siIdxIt;
  for(siIdxIt=siIdx.begin(); siIdxIt!=siIdx.end(); siIdxIt++){
    vector<int>& flows=siIdxIt->second;
    map<unsigned short, int> dstportMap; // dst port -> count
    map<unsigned long, int> dstipMap;    // dst ip -> count
    for(unsigned int i=0; i<flows.size(); i++){
      dstportMap[mmbuffer[flows[i]].dst_port]++;
      dstipMap[mmbuffer[flows[i]].dst_ip]++;
      if(mmbuffer[flows[i]].src_ip != siIdxIt->first.srcip){
	DEBUG("Inconsistency: mmbuffer[flows[%d]=%d].srcip=", i, flows[i]);
	print_ip(mmbuffer[flows[i]].src_ip, cerr)<<" != ";
	print_ip(siIdxIt->first.srcip, cerr)<<endl;
      }
    }
    pair<SIKey, SIStats> siPair;
    siPair.first=siIdxIt->first;
    siPair.second=SIStats((int)dstportMap.size(), (int)dstipMap.size());
    siStats.insert(siPair);
  }
  fprintf(stderr, "Done.\n");
  // SISP Stats
  DEBUG("Extracting the SISP <SrcIP, SrcPort> features ... "); fflush(stderr);
  map<SISPKey, SISPStats, lt_SISPKey> sispStats;
  map<SISPKey, vector<int>, lt_SISPKey>::iterator sispIdxIt;
  for(sispIdxIt=sispIdx.begin(); sispIdxIt!=sispIdx.end(); sispIdxIt++){
    vector<int>& flows=sispIdxIt->second;
    map<unsigned short, int> dstportMap; // dst Port -> count
    map<unsigned long,  int> dstipMap;
    for(unsigned int i=0; i<flows.size(); i++){
      dstportMap[mmbuffer[flows[i]].dst_port]++;
      dstipMap[mmbuffer[flows[i]].dst_ip]++;
    }
    pair<SISPKey, SISPStats> sispPair;
    sispPair.first=sispIdxIt->first;
    sispPair.second=SISPStats((int)dstportMap.size(), (int)dstipMap.size());
    sispStats.insert(sispPair);
  }
  fprintf(stderr, "Done.\n");
  // SIDP Stats
  DEBUG("Extracting the SIDP <SrcIP, DstPort> features ... "); fflush(stderr);
  map<SIDPKey, SIDPStats, lt_SIDPKey> sidpStats;
  map<SIDPKey, vector<int>, lt_SIDPKey>::iterator sidpIdxIt;
  for(sidpIdxIt=sidpIdx.begin(); sidpIdxIt!=sidpIdx.end(); sidpIdxIt++){
    unsigned char  proto    = sidpIdxIt->first.proto;
    //    unsigned long  srcip    = sidpIdxIt->first.srcip;
    unsigned short dstport  = sidpIdxIt->first.dstport;
    int            nbytes      = 0;
    int            npackets    = 0;
    int            ndark       = 0;
    int            nservice    = 0;
    int            ndstips     = 0;
    int            dstportfreq = (proto==TCP?tcppf[dstport]:udppf[dstport]);
    bool           blocked     = (proto==TCP?tcpPorts[dstport]:udpPorts[dstport]);
    unsigned short srcport     = 0;
    double         adstfreq    = 0;
    vector<int>&   flows       = sidpIdxIt->second;
    // src port
    for(unsigned int i=0; i<flows.size(); i++){
      if(srcport != 0 && srcport != mmbuffer[flows[i]].src_port){
	srcport=0; break;
      }
      srcport = mmbuffer[flows[i]].src_port;
    }
    // number of bytes, packets, targets
    map<unsigned long, int> targets; // dst_ip -> count
    for(unsigned int i=0; i<flows.size(); i++){
      mm_record &mmr = mmbuffer[flows[i]];
      targets[mmr.dst_ip]++;
      nbytes += (mmr.cbytes+mmr.sbytes);
      npackets += (mmr.cpackets+mmr.spackets);
    }
    // look at the destinations: ndark, nservice, avg dst freq
    ndstips=(int)targets.size();
    map<unsigned long, int>::iterator targetsIt;
    for(targetsIt=targets.begin(); targetsIt!=targets.end(); targetsIt++){
      // Dark IP?
      map<unsigned long, bool>::iterator darkIPsIt;
      darkIPsIt=darkIPs.find(targetsIt->first);
      if(darkIPsIt!=darkIPs.end()) ndark++;
      // Service offered?
      switch(proto){
      case TCP:
	if(tcpscnt(targetsIt->first, dstport)>0) nservice++;
	break;
      case UDP:
	if(udpscnt(targetsIt->first, dstport)>0) nservice++;
	break;
      }    
      // Average dst frequency
      double dstfreq=0;
      switch(proto){
      case TCP:
	dstfreq=tcpscnt(targetsIt->first, dstport)
	  +tcpqcnt(targetsIt->first, dstport)
	  +tcpfcnt(targetsIt->first, dstport);
	break;
      case UDP:
	dstfreq=udpscnt(targetsIt->first, dstport)
	  +udpqcnt(targetsIt->first, dstport)
	  +udpfcnt(targetsIt->first, dstport);
	break;
      }    
      adstfreq+=dstfreq/(double)ndstips;
      
    }
    // Inserting
    pair<SIDPKey, SIDPStats> sidpPair;
    sidpPair.first = sidpIdxIt->first;;
    sidpPair.second = SIDPStats(ndstips, ndark, nservice, dstportfreq,
				adstfreq,
				(double)nbytes/(double)ndstips, 
				(double)npackets/(double)ndstips,
				blocked, srcport);
    sidpStats.insert(sidpPair);
  }
  fprintf(stderr, "Done.\n");

  //
  // (5) Creating the feature data set
  //
  DEBUG("Writing the feature data set ... "); fflush(stderr);
  map<SIDPKey, SIDPStats, lt_SIDPKey>::iterator sidpStatsIt;
  map<SIDPKey, vector<int>, lt_SIDPKey>::iterator dispIdxIt;
  for(sidpStatsIt=sidpStats.begin(); sidpStatsIt!=sidpStats.end(); sidpStatsIt++){
    unsigned char      proto    = sidpStatsIt->first.proto;
    unsigned long      srcip    = sidpStatsIt->first.srcip;
    unsigned short     srcport  = sidpStatsIt->second.srcport;
    unsigned short     dstport  = sidpStatsIt->first.dstport;
    SIKey              siKey(proto, srcip);

    sidpIdxIt=sidpIdx.find(sidpStatsIt->first);
    if(sidpIdxIt==sidpIdx.end()){
      DEBUG("Can not located record for <%3s, %10ul, %5d>\n",
	    proto, srcip, dstport);  
      continue;
    }

    map<SIKey, SIStats, lt_SIKey>::iterator siStatsIt;
    siStatsIt=siStats.find(siKey);
    
    print_proto(proto, out)<<" ";
    print_ip(srcip, out)<<" "<<setw(5)<<srcport<<" "<<setw(5)<<dstport<<" ";
    // STATISTICS BY SRC IP (only)
    // - number of distinct dst ports
    // - and ratio of distinct dst ports to distinct dst ips
    char buf1[256];
    sprintf(buf1,"%5d %9.4f ", siStatsIt->second.ndstports,
	    (double)siStatsIt->second.ndstports
	    /(double)siStatsIt->second.ndstips);
    out << buf1;
    // STATISTICS BY SRC IP, SRC PORT
    // - number of distinct dst ports
    // - and ratio of distinct dst ports to distinct dst ips
    char buf2[256];
    if(srcport>0){
      SISPKey sispKey(proto, srcip, srcport);
      map<SISPKey, SISPStats, lt_SISPKey>::iterator sispStatsIt;
      sispStatsIt=sispStats.find(sispKey);
      if(sispStatsIt==sispStats.end())
	DEBUG("INCONSISTENCY: No SISP stats record found for %20s %5d\n",
	      srcip, srcport);
      sprintf(buf2,"%5d %9.4f ", sispStatsIt->second.ndstports,
	     (double)sispStatsIt->second.ndstports
	     /(double)sispStatsIt->second.ndstips);
    } else sprintf(buf2,"%5d %9.4f ", 0, 0.0);
    out<<buf2;
    // STATISTICS BY SRC IP, DST PORT
    // - number of distinct dst ips [ndstips]
    // - number of distinct dark dst ips [ndark]
    // - number of distinct dst ips with service [nservice]
    // - ratio of service to non-service
    //// - dst port frequency
    //// - avg dst frequency
    // - avg bytes per destination
    // - avg packets per destination
    char buf3[256];
    sprintf(buf3,"%7d %7d %7d %7.5f %12.2f %10.2f %c ", 
	   sidpStatsIt->second.ndstips,
	   sidpStatsIt->second.ndarkips, sidpStatsIt->second.nservice,
	   (double)(sidpStatsIt->second.nservice)
	   /(double)(sidpStatsIt->second.ndstips),
	   //	   sidpStatsIt->second.dstportfreq,
	   //	   sidpStatsIt->second.adstfreq,
	   sidpStatsIt->second.avgbytes, sidpStatsIt->second.avgpackets,
	   (sidpStatsIt->second.blocked?'Y':'N'));
    out<<buf3;
    // printing out the destination IPs
    vector<int>& flows = sidpIdxIt->second;
    map<unsigned long, int> targets;
    for(unsigned long f=0; f<flows.size() && f<50; f++){
      mm_record& mmr=mmbuffer[flows[f]];
      
      unsigned long dstip = mmr.dst_ip;

      bool dark=false;
      bool service=false;

      // Dark IP?
      map<unsigned long, bool>::iterator darkIPsIt;
      darkIPsIt=darkIPs.find(dstip);
      if(darkIPsIt!=darkIPs.end()) dark=true;

      // Service offered?
      switch(proto){
      case TCP:
	if(tcpscnt(dstip, dstport)>0) service=true;
	break;
      case UDP:
	if(udpscnt(dstip, dstport)>0) service=true;
	break;
      }

      if(dark){
	if(targets[mmr.dst_ip]!=DARK) targets[mmr.dst_ip]=DARK;
      } else if(service){
	if(targets[mmr.dst_ip]!=SERVICE) targets[mmr.dst_ip]=SERVICE;
      } else {
	if(targets[mmr.dst_ip]!=DARK && targets[mmr.dst_ip]!=SERVICE) targets[mmr.dst_ip]=NOSERVICE;
      }
      
    }
    for(map<unsigned long, int>::iterator tit=targets.begin(); tit!=targets.end(); tit++){
      char buf5[128];
      sprintf(buf5," %10lu %s", tit->first, (tit->second==DARK?"D":(tit->second==SERVICE?"S":"N")));
      out<<buf5;
    }
    out<<endl;
  }
  out.close();
  fprintf(stderr, "Done.\n");
}

bool FeatureExtractor::failed(mm_record& mmr){
  // if blocked, certainly a failure
  //if(mmr.dst_mask==0) return true;
  // if there is no reply, it is a failure
  if(mmr.protocol==TCP){
    //if((mmr.flags&4)==4) return true;  // RST flag set
    if(mmr.spackets<1) return true;
    if(mmr.cpackets<2) return true;
  }
  // for UDP
  if(mmr.protocol==UDP){
    //    if((mmr.dst_port==53 || mmr.dst_port==123) && mmr.spackets<1) return true;
    if(failure_npckts==0 && mmr.cbytes<50) return true;
    if(mmr.cpackets+mmr.spackets<=(unsigned long)failure_npckts) return true;
  }
  return false;
}


bool FeatureExtractor::succeeded(mm_record& mmr){
  using namespace std;
  // if blocked, certainly a failure -> can not have succeded
  if(mmr.dst_mask==0) return false;
  // if there are two server packets, and 2 client packets, probably 
  // successful
  if(mmr.spackets>=2 && mmr.cpackets>=2 && (mmr.protocol!=TCP || (mmr.flags&4)!=4)) return true;
  if(mmr.spackets>5 && mmr.cpackets>5) return true;

  if(mmr.protocol==UDP){
    if(mmr.spackets>=1) return true;
    if(mmr.cpackets>=(unsigned long)success_npckts) return true;
  }
  return false;
}
