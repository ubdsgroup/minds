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
#include <sys/stat.h>
#include "flows.h"
#include "mm_record.h"
#include "io.h"
#include "anomaly_detector.h"
#include "generate_itemsets.h"
#include "input_filter.h"
#include "xml.h"
namespace main_space{
#include "minds_constants"
}

using namespace std;

extern vector< int > ruleset_sizes;
unsigned int train_size = 1000; // default value for training set size
unsigned int test_size = 0;     // default value for test set size
float tail_cutoff = 0.1;
int max_top   = 1000;

unsigned int time_window = 10000000;   // microseconds
unsigned int conn_window = 256;     // connections
unsigned long TIMEOUT = 86400;      // one day
float server_threshold = 5;

unsigned int session = 1;
unsigned int nn = 15;
int method = 1; // 0:lof_simplified - 1:lof
float eps = 0.0;

int num_num_features = 13;
int num_cat_features = 5;
std::vector<float> num_weights(num_num_features,0);  // weights for numerical   attributes
std::vector<float> cat_weights(num_cat_features,0);  // weights for categorical attributes
std::vector< std::pair<unsigned long, unsigned long> > INSIDE; // network list

record_stats s(num_num_features);

vector<pair<mm_record*,flow_record*> > train;
vector<pair<mm_record*,flow_record*> > test;
vector<mm_record> mmr_data;
vector<flow_record> flow_data;
vector< pair<float, mm_record* > > score;
vector< vector<float> > contrib;

char* mmr_filename=0;
char* rules_filename=0;
char* config_filename=0;
char *summarization_config_filename=0;
char* output_filename=0;
unsigned int num_threads=1;
int scheme = 4; //1-0/1, 2-weighted 0/1, 3-iof, 4 - of

bool compare_index(std::pair<unsigned short, int> a, std::pair<unsigned short,int> b){return a.second > b.second;}
bool compare_score_ptr(std::pair<int, float> a, std::pair<int, float> b){return a.second > b.second;}
class compare_score {
public: 
  bool operator() (std::pair<float,mm_record*> a, std::pair<float,mm_record*> b) {return a.first > b.first;}
};

bool inVector(unsigned short key,vector<unsigned short> vec){
  if(vec.size() == 0) return false;
  for(unsigned int i = 0; i < vec.size(); i++)
    if(key == vec[i]) return true;
  return false;
}

int is_inside(unsigned long ip){
  for(unsigned int i=0; i<INSIDE.size(); ++i){
    if( (ip & INSIDE[i].second) == INSIDE[i].first) return i+1;
  }
  return 0;
}

void lowercase(std::string &s){
  for(std::string::iterator it=s.begin(); it!=s.end(); ++it)
    if(*it>='A' && *it<='Z') *it += 'a' - 'A';
}

void unifrnd(int N, unsigned int k, std::set<unsigned int> &s){
  // generated k random numbers in the interval [0,N-1)
  unsigned long r;
  unsigned int i;
  srand( (unsigned)time( NULL ) );
  while(s.size()!=k){
    r = rand(); r <<= 15; r += rand();
    i = r%N;
    s.insert(i);
  }
}

//  get_stats will ignore x fraction from each end of the distribution when calculation stdev (0 < x <1)
void get_stats(std::vector<pair<mm_record *,flow_record*> > &mask, record_stats &s, float x){
  std::vector< std::vector<float> > a(num_num_features);
  std::vector<pair<mm_record*,flow_record*> >::iterator it;
  std::vector<float>::iterator fit;
  int i=0;
  float INF=float(1e20);
  for(it = mask.begin(); it!= mask.end(); ++it, ++i){
    a[0].push_back((it->second)->duration);
    if((it->first)->cpackets != 0)
      a[1].push_back(float((it->first)->cbytes)*float((it->second)->i_cpackets));
    a[2].push_back((it->first)->cpackets);
    if((it->first)->spackets != 0)
       a[3].push_back(float((it->first)->sbytes)*float((it->second)->i_spackets));
    
    a[4].push_back((it->first)->spackets);
    a[5].push_back((it->second)->unique_inside_dst_count);
    a[6].push_back((it->second)->unique_inside_dst_rate);
    a[7].push_back((it->second)->same_dst_port_count);
    a[8].push_back((it->second)->same_dst_port_rate);
    a[9].push_back((it->second)->unique_inside_src_count);
    a[10].push_back((it->second)->unique_inside_src_rate);
    a[11].push_back((it->second)->same_src_port_count);
    a[12].push_back((it->second)->same_src_port_rate);
  }
  for(i=0; i<num_num_features; ++i) sort(a[i].begin(), a[i].end());
  for(i=0; i<num_num_features; ++i){
    if(a[i].size() <= 1){s.stdev[i] = 0;break;}
    for(fit=a[i].begin() + int(a[i].size()*x); fit + int(a[i].size()*x)!=a[i].end(); ++fit) s.mean[i] += *fit;
    s.mean[i] /= a[i].size();
    for(fit=a[i].begin() + int(a[i].size()*x); fit + int(a[i].size()*x)!=a[i].end(); ++fit) s.stdev[i] += (*fit - s.mean[i])*(*fit - s.mean[i]);
    s.stdev[i] = sqrt(s.stdev[i] / (a[i].size()-1));
  }
}

  void build_index(std::vector<pair<mm_record*,flow_record*> >&data,
		   std::map<unsigned long , std::vector<pair<mm_record*,flow_record*> > > &i_srcIP,   
		   std::map<unsigned long , std::vector<pair<mm_record*,flow_record*> > > &i_dstIP,                
		   std::map<unsigned short, std::vector<pair<mm_record*,flow_record*> > > &i_srcPort, 
		   std::map<unsigned short, std::vector<pair<mm_record*,flow_record*> > > &i_dstPort, 
		   std::map<unsigned short, std::vector<pair<mm_record*,flow_record*> > > &i_proto){
    for(unsigned int i=0;i<data.size();++i){
      i_srcIP[(data[i].first)->src_ip].push_back(data[i]);
      i_dstIP[(data[i].first)->dst_ip].push_back(data[i]);
      i_srcPort[(data[i].first)->src_port].push_back(data[i]);
      i_dstPort[(data[i].first)->dst_port].push_back(data[i]);
      i_proto[(data[i].first)->protocol].push_back(data[i]);
    }
  }           

  void extract_features(std::vector<pair<mm_record*,flow_record*> > &data,
			std::map<unsigned long , std::vector<pair<mm_record*,flow_record*> > > &i_srcIP,
			std::map<unsigned long , std::vector<pair<mm_record*,flow_record*> > > &i_dstIP,
			std::map<unsigned short, std::vector<pair<mm_record*,flow_record*> > > &i_srcPort, 
			std::map<unsigned short, std::vector<pair<mm_record*,flow_record*> > > &i_dstPort){ 
    std::map<unsigned long, std::vector<pair<mm_record*,flow_record*> > >::iterator ip_it;  
    std::vector<pair<mm_record*,flow_record*> >::reverse_iterator it1, it2;
    unsigned short count;
    // initialize derived features to be 0
    for(unsigned int i=0; i<data.size(); ++i){
      (data[i].second)->unique_inside_src_rate = (data[i].second)->unique_inside_src_count = (data[i].second)->same_src_port_rate = (data[i].second)->same_src_port_count = 0;
      (data[i].second)->unique_inside_dst_rate = (data[i].second)->unique_inside_dst_count = (data[i].second)->same_dst_port_rate = (data[i].second)->same_dst_port_count = 0;
    }
    // connection window based features
    for(ip_it = i_srcIP.begin(); ip_it != i_srcIP.end(); ++ip_it){
      for(it1 = ((*ip_it).second).rbegin(); (it1 != ((*ip_it).second).rend()); ++it1){
	count = 0;
	std::map<unsigned short, int> unique_dst;
	for(it2 = it1+1; (it2 != ((*ip_it).second).rend()) && (count < conn_window); ++it2, ++count){
	  if((((it1->first)->sts).secs - ((it2->first)->sts).secs) > main_space::TIMEOUT) break;
	  if((it1->first)->is_inbound) ++unique_dst[(it2->first)->dst_ip];
	  if((it2->first)->dst_port == (it1->first)->dst_port) ++((it1->second)->same_dst_port_rate);
	  if(+unique_dst[(it2->first)->dst_ip] > 500) { break; }
	  if(((it1->second)->same_dst_port_rate) > 500) { break; }
	}
	(it1->second)->unique_inside_dst_rate = unique_dst.size();
      }
    }
    for(ip_it = i_dstIP.begin(); ip_it != i_dstIP.end(); ++ip_it){
      for(it1 = ((*ip_it).second).rbegin(); (it1 != ((*ip_it).second).rend()); ++it1){
	count = 0;
	std::map<unsigned short, int> unique_src;  
	for(it2 = it1+1; (it2 != ((*ip_it).second).rend()) && (count < conn_window); ++it2, ++count){
	  if((((it1->first)->sts).secs - ((it2->first)->sts).secs) > main_space::TIMEOUT) break;
	  if(!(it1->first)->is_inbound) ++unique_src[(it2->first)->src_ip];
	  if ((it2->first)->src_port == (it1->first)->src_port) ++((it1->second)->same_src_port_rate);
	      if(unique_src[(it2->first)->src_ip] > 500) { break; }
	      if(((it1->second)->same_src_port_rate) > 500) { break; }
	      }
	  (it1->second)->unique_inside_src_rate = unique_src.size();
	}
      }
      // time window based features
      for(ip_it = i_srcIP.begin(); ip_it != i_srcIP.end(); ++ip_it){
	for(it1 = ((*ip_it).second).rbegin(); (it1 != ((*ip_it).second).rend()); ++it1){
	  std::map<unsigned short, int> unique_dst;
	  for(it2 = it1+1; (it2 != ((*ip_it).second).rend()) && ((((it1->first)->sts).secs - ((it2->first)->sts).secs) < time_window); ++it2){
	    if((it1->first)->is_inbound) ++unique_dst[(it2->first)->dst_ip];
	    if ((it2->first)->dst_port == (it1->first)->dst_port) ++((it1->second)->same_dst_port_count);

	    if(unique_dst[(it2->first)->dst_ip] > 500) { break; } //put in to try and speed the loop up
	    if((it1->second)->same_dst_port_count > 500) { break; }

	  }
	  (it1->second)->unique_inside_dst_count = unique_dst.size();
	}
      }
      for(ip_it = i_dstIP.begin(); ip_it != i_dstIP.end(); ++ip_it){
	for(it1 = ((*ip_it).second).rbegin(); (it1 != ((*ip_it).second).rend()); ++it1){
	  std::map<unsigned short, int> unique_src;
	  for(it2 = it1+1; (it2 != ((*ip_it).second).rend()) && ((((it1->first)->sts).secs - ((it2->first)->sts).secs) < time_window); ++it2){
	    if(!(it1->first)->is_inbound) ++unique_src[(it2->first)->src_ip];
	    if ((it2->first)->src_port == (it1->first)->src_port) ++((it1->second)->same_src_port_count);
	    if((it1->second)->same_src_port_count > 500) { break; }
	    if(unique_src[(it2->first)->src_ip] > 500) { break; }

	  }
	  (it1->second)->unique_inside_src_count = unique_src.size();
	}
      }
    }

    void parse_config(char *config_filename){
      using namespace std;
      TiXmlDocument doc;
      if(!doc.LoadFile(config_filename)) SYSERROR("Error opening the config file '%s'\n", config_filename);
      TiXmlNode* nodeRoot = doc.RootElement();
      if(strcmp(nodeRoot->Value(),"mindsconfig")) SYSERROR("Incorrect root node. Must be mindsconfig.\n");
      for(TiXmlNode* child = nodeRoot->FirstChild(); child; child = child->NextSibling() ){
	if(!strcmp(child->Value(),"internal")){
	  string mask = "0";
	  if(((TiXmlElement*) child)->Attribute("mask"))
	    mask = ((TiXmlElement*) child)->Attribute("mask");
	  string ipstr = ((TiXmlElement*) child)->GetText();
	  INSIDE.push_back(pair<unsigned long, unsigned long>(get_ip(ipstr),convert_mask(mask)));
	}
	if(!strcmp(child->Value(),"session")) session = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"train_size")) train_size = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"test_size")) test_size = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"method")) method = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"nn")) nn = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"tail_cutoff")) tail_cutoff = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"time_window")) time_window = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"conn_window")) conn_window = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"max_top")) max_top = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"num_threads")) num_threads = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"scheme")) scheme = atoi(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"eps")) eps = atof(((TiXmlElement*) child)->GetText());
	if(!strcmp(child->Value(),"weights")){
	  for(TiXmlNode* wchild = child->FirstChild(); wchild; wchild = wchild->NextSibling()){
	    if(!strcmp(wchild->Value(),"srcIP")) cat_weights[0] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"dstIP")) cat_weights[1] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"srcPort")) cat_weights[2] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"dstPort")) cat_weights[3] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"proto")) cat_weights[4] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"duration")) num_weights[0] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"bytesperpacket")) num_weights[1] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"packets")) num_weights[2] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"serverbytesperpacket")) num_weights[3] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"serverpackets")) num_weights[4] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"unique_inside_dst_count")) num_weights[5] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"unique_inside_dst_rate")) num_weights[6] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"same_inside_dst_count")) num_weights[7] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"same_inside_dst_rate")) num_weights[8] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"unique_inside_src_count")) num_weights[9] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"unique_inside_src_rate")) num_weights[10] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"same_inside_src_count")) num_weights[11] = atof(((TiXmlElement*) wchild)->GetText());
	    if(!strcmp(wchild->Value(),"same_inside_src_rate")) num_weights[12] = atof(((TiXmlElement*) wchild)->GetText());
	  }
	}
      }
    }

#define usage(msg, args...) \
{\
  fprintf(stderr, msg, ##args);\
  fprintf(stderr, \
"Usage:\n\n" \
"./anomaly_detector -i input_MMR_filename -c config_filename -r rules_filename -o output_filename -s summarization_config_filename\n\n"); \
  exit(1); \
}
  
    void parseArgs(int argc, char** argv){
      int argi;
      for(argi=1; argi<argc; argi++){
	if(strcmp(argv[argi],"-i")==0){ 
	  if(++argi<argc) mmr_filename=strdup(argv[argi]);
	  else usage("-i requires mmr file argument\n");
	} else if(strcmp(argv[argi],"-c")==0){
	  if(++argi<argc) config_filename=strdup(argv[argi]);
	  else usage("-c requires config file argument\n");
	} else if(strcmp(argv[argi],"-s")==0){
	  if(++argi<argc) summarization_config_filename=strdup(argv[argi]);
	  else usage("-s requires summarization config file argument\n");
	} else if(strcmp(argv[argi],"-r")==0){
	  if(++argi<argc) rules_filename=strdup(argv[argi]);
	  else usage("-r requires rules file argument\n");
	}else if(strcmp(argv[argi],"-o")==0){
	  if(++argi<argc) output_filename=strdup(argv[argi]);
	  else usage("-o requires output file argument\n");
	} else if(strcmp(argv[argi], "-h")==0 || strcmp(argv[argi], "-?")==0){
	  usage("");
	} 
	else 
	  usage("Invalid switch '%s'\n", argv[argi]);
      }
      if(!mmr_filename)     usage("No MMR file specified\n");
      if(!config_filename)  usage("No config file specified\n");
      if(!summarization_config_filename)  usage("No summarization config file specified\n");
      if(!rules_filename)   usage("No rule file specified\n");
      if(!output_filename)  usage("No output file specified\n");
    }
    
    int main(int argc, char **argv){
      using namespace std;
      clock_t start, finish;
      double duration;
      int ret;
      unsigned int i, j, k;
      ifstream in;
      time_t fs, ff, sum_time=0;
      string file_name;
      ofstream out;
      parseArgs(argc,argv);
      cerr<<"Using "<<num_threads<<" threads"<<endl;
      // read config file
      parse_config(config_filename);
      // read rule file
      in.open(rules_filename);
      if(in.fail()) {cerr << "rule file not found\n"; exit(0);}
      vector<rule> ruleset;
      read_ruleset(in, ruleset);

      // read data file
      start = clock();
      ret = io(mmr_filename, mmr_data, flow_data);
      finish = clock();
      if(ret == 0) {
	cerr << "Error in reading the data... Aborting" << endl;
	return 0;
      }
      duration = (double)(finish - start) / CLOCKS_PER_SEC;
      cerr << "Finished reading data (" << mmr_data.size() << ") in " << duration << " seconds" << endl;
  
      //split into flows if required
      unsigned int numSessions =  mmr_data.size();
      if(session == 0){//split the sessions into two
	cerr<<"Splitting the sessions into flows\n";
	for(k = 0;k < numSessions;++k){
	  if(mmr_data[k].sbytes != 0){//this session has a reply
	    mm_record oneMmr; flow_record oneFlow;
	    oneMmr.sts = mmr_data[k].sts;
	    oneMmr.ets = mmr_data[k].ets;

	    oneMmr.cbytes = mmr_data[k].sbytes;
	    oneMmr.cpackets = mmr_data[k].spackets;
	    oneFlow.i_cpackets = flow_data[k].i_spackets;
	    oneMmr.sbytes = mmr_data[k].cbytes;
	    oneMmr.spackets = mmr_data[k].cpackets;
	    oneFlow.i_spackets = flow_data[k].i_cpackets;

	    oneMmr.src_ip = mmr_data[k].dst_ip;
	    oneMmr.dst_ip = mmr_data[k].src_ip;
	    oneMmr.src_port = mmr_data[k].dst_port;
	    oneMmr.dst_port = mmr_data[k].src_port;
	    oneMmr.src_mask = mmr_data[k].dst_mask;
	    oneMmr.dst_mask = mmr_data[k].src_mask;

	    oneMmr.protocol = mmr_data[k].protocol;
	    oneMmr.flags = mmr_data[k].flags;
	    oneFlow.duration = flow_data[k].duration;
	    oneMmr.p2p = mmr_data[k].p2p;
	    oneMmr.scan = mmr_data[k].scan;
	    oneMmr.hpdt = mmr_data[k].hpdt;
	    oneMmr.lof_anomaly_score = mmr_data[k].lof_anomaly_score;
	    if(mmr_data[k].is_client == 1)  oneMmr.is_client = 2;
	    else oneMmr.is_client = 1;
	    oneMmr.is_inbound  = !mmr_data[k].is_inbound;
	    oneFlow.network = flow_data[k].network;
	    mmr_data.push_back(oneMmr);
	    flow_data.push_back(oneFlow);
	  }
	}
	cerr<<"Obtained "<<mmr_data.size()<<" flows from "<<numSessions<<" sessions\n"; 
      }
      if(session != 1){//need to consider only initiating flows. Make weights of the response flow features to be zero
	num_weights[3] = 0;
	num_weights[4] = 0;
      }
      // apply rules
      vector<pair<mm_record*,flow_record*> > subset;
      for(k=0; k<mmr_data.size(); ++k){
	bool select = 0;
	for(j=0; j<ruleset.size(); ++j){
	  if(ruleset[j].type) { // ignore rule
	    if(ruleset[j].apply(&mmr_data[k])){select=0; break;}
	  }
	  else { //select rule
	    if(ruleset[j].apply(&mmr_data[k])){select=1; break;}
	  }    
	}     
	if(select)
	  subset.push_back(pair<mm_record*, flow_record*>(&mmr_data[k],&flow_data[k]));
      }  
      // index the data
      map<unsigned long , vector<pair<mm_record*,flow_record*> > > i_srcIP;
      map<unsigned long , vector<pair<mm_record*,flow_record*> > > i_dstIP;
      map<unsigned short, vector<pair<mm_record*,flow_record*> > > i_srcPort;
      map<unsigned short, vector<pair<mm_record*,flow_record*> > > i_dstPort;
      map<unsigned short, vector<pair<mm_record*,flow_record*> > > i_proto;
    
      start = clock();
      build_index(subset, i_srcIP, i_dstIP, i_srcPort, i_dstPort, i_proto);
      finish = clock();
      duration = (double)(finish - start) / CLOCKS_PER_SEC;
      cerr << "Building the index on 6 fields for " << subset.size() << " flows took " << duration << " seconds\n";
      cerr << "Protocol Based Statistics:\n";
      cerr << "tcp: " << i_proto[6].size() << " udp: " << i_proto[17].size() << " icmp: " << i_proto[1].size() << " ipsec: " << i_proto[50].size() + i_proto[51].size() << endl;
    
      // extract features
      start = clock();
      extract_features(subset, i_srcIP, i_dstIP, i_srcPort, i_dstPort);
      finish = clock();
      duration = (double)(finish - start) / CLOCKS_PER_SEC;
      cerr << "Extracting connection based features (" << conn_window << " conn, " << time_window/1000000 << " sec) ";
      cerr << "took " << duration << " seconds\n";
    
      // calculate stats
      record_stats s(num_num_features);
      get_stats(subset, s, eps); // chop off the distribution from both ends
      // if train_size, test_size is too large
      unsigned int train_size_ruleset = train_size;
    
      train.resize(0);
      set<unsigned int> train_set;
      set<unsigned int>::iterator set_it;
      if(train_size_ruleset-train.size() > subset.size() ){
	train_size_ruleset=subset.size() + train.size();
      }
      unifrnd(subset.size(), train_size_ruleset-train.size(), train_set);
      for(set_it=train_set.begin(); set_it!=train_set.end() && train.size() < train_size_ruleset; ++set_it)
	train.push_back(subset[*set_it]);

      test.clear();
      unsigned int test_size_ruleset  = test_size;
      if(test_size_ruleset > subset.size() || test_size_ruleset == 0) test_size_ruleset  = subset.size();
      for(i=0; i<test_size_ruleset; ++i) test.push_back(subset[i]);

      s.prepare(num_weights);  // multiplication is faster than division

      if(scheme == 1){
	cerr<<"Using the 0/1 weighting scheme\n";
	for(i=0; i<subset.size(); ++i){
	  (subset[i].second)->srcip_idf    = 1;
	  (subset[i].second)->dstip_idf    = 1;
	  (subset[i].second)->src_port_idf = 1;
	  (subset[i].second)->dst_port_idf = 1;
	  (subset[i].second)->protocol_idf = 1;
	}
      }else if(scheme == 2){
	cerr<<"Using the columbia weighting scheme\n";
	for(i=0; i<subset.size(); ++i){
	  (subset[i].second)->srcip_idf    = 1/sqrt(float(i_srcIP.size()));
	  (subset[i].second)->dstip_idf    = 1/sqrt(float(i_dstIP.size()));
	  (subset[i].second)->src_port_idf = 1/sqrt(float(i_srcPort.size()));
	  (subset[i].second)->dst_port_idf = 1/sqrt(float(i_dstPort.size()));
	  (subset[i].second)->protocol_idf = 1/sqrt(float(i_proto.size()));
	}
      }else if(scheme == 3){
	cerr<<"Using the df weighting scheme\n";
	for(i=0; i<subset.size(); ++i){
	  (subset[i].second)->srcip_idf    = log(float(i_srcIP[(subset[i].first)->src_ip].size()) + 1);
	  (subset[i].second)->dstip_idf    = log(float(i_dstIP[(subset[i].first)->dst_ip].size()) + 1);
	  (subset[i].second)->src_port_idf = log(float(i_srcPort[(subset[i].first)->src_port].size()) + 1);
	  (subset[i].second)->dst_port_idf = log(float(i_dstPort[(subset[i].first)->dst_port].size()) + 1);
	  (subset[i].second)->protocol_idf = log(float(i_proto[(subset[i].first)->protocol].size()) + 1);
	}
      }else if(scheme == 4){
	cerr<<"Using the idf weighting scheme\n";
	for(i=0; i<subset.size(); ++i){
	  (subset[i].second)->srcip_idf    = log(float(subset.size())/float(i_srcIP[(subset[i].first)->src_ip].size()));
	  (subset[i].second)->dstip_idf    = log(float(subset.size())/float(i_dstIP[(subset[i].first)->dst_ip].size()));
	  (subset[i].second)->src_port_idf = log(float(subset.size())/float(i_srcPort[(subset[i].first)->src_port].size()));
	  (subset[i].second)->dst_port_idf = log(float(subset.size())/float(i_dstPort[(subset[i].first)->dst_port].size()));
	  (subset[i].second)->protocol_idf = log(float(subset.size())/float(i_proto[(subset[i].first)->protocol].size()));
	}
      }

      // free up some memory
      i_srcIP.clear(); i_dstIP.clear(); i_srcPort.clear(); i_dstPort.clear(); i_proto.clear();
      // call the anomaly detection algorithm
      unsigned int nn_ruleset = nn;
      if(nn >= train.size()) nn_ruleset = train.size()-1;
     
      contrib.resize(test.size(), vector<float>(NUM_DIM,0));
      score.resize(test.size());

      fs=time(NULL);
      switch(method){
      case 1: lof(train, test, score, nn_ruleset, s.stdev_inv, cat_weights, contrib,max_top); break;
      default: cerr<<"Error: Method "<<method<<" not supported. Exiting .. \n";exit(0);break;
      }
      ff=time(NULL);
      sum_time+=(ff-fs);
      cerr << "anomaly scores calculated in " << ff-fs << " seconds"<<endl;

      // save the mmr records. The anomaly scores for test are already updated.
      out.open(output_filename);
      for(unsigned int i = 0; i < mmr_data.size(); i++)
 	out.write((char *) &mmr_data[i], (int)sizeof(mmr_data[i]));
      out.close();
      // ptr sort the scores first. (keep track of sorted scores. re-order contributions)
      vector< pair<int, float> > score_ptr(test.size());
      for(i=0; i<test.size(); ++i) score_ptr[i] = pair<int, float>(i, score[i].first);
      stable_sort(score_ptr.begin(), score_ptr.end(), compare_score_ptr);
      // re-order contributions
        vector< vector<float> > contrib2;
       for(i=0; i<test.size(); ++i){
	 contrib2.push_back(contrib[score_ptr[i].first]);
	 contrib[score_ptr[i].first].clear();
       }
       contrib.clear();
       stable_sort(score.begin(), score.end(), compare_score());
       ofstream anomaly_file;
       char fname[128];
       strcpy(fname, output_filename);
       strcat(fname, "_annotated");
       anomaly_file.open(fname);
       for(int i=0; i<max_top ; ++i){
 	if(i >= score.size()) break;
  	print_anomaly_scores(score[score_ptr[i].first], anomaly_file);
  	print_contributions(contrib2[i], anomaly_file);
  	anomaly_file << endl;
       }
       anomaly_file.close();
       //perform summarization on the top scores
       char fname2[128];
       strcpy(fname2, output_filename);
       strcat(fname2, "_itemsets");
       ofstream itemset_file(fname2);
       generate_itemsets(score, contrib2, itemset_file, summarization_config_filename);
       itemset_file.close();
       
       cerr<<"Core time took "<<sum_time<<" seconds"<<endl;
       return 1;
    }
