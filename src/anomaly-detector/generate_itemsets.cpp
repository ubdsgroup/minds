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
  #
  # Levent Ertoz
  # ertoz@cs.umn.edu
  #
  # Eric Eilertson
  # eric@cs.umn.edu
*/

#include <vector>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cmath>
#include <netdb.h>
#include <stdio.h>
#include "mm_record.h"
#include "generate_itemsets.h"
#include "discriminating_itemsets.h"
#include "xml.h"

#define NUM_DIM 18
#define NUM_BASIC 10

using namespace std;

std::string ip2string(unsigned long ip){
  std::string s;
  std::stringstream str;
  str << ((ip & 0xFF000000)>>24) << "." << ((ip & 0xFF0000)>>16) << "." << ((ip & 0xFF00)>>8) << "." << (ip & 0xFF);
  str >> s;
  return s;
}

std::string flags2string1(unsigned char flags){
    string s = "";
    if((flags & 0x80) == 0x80) s += "R";
    else s += "*";
    if((flags & 0x40) == 0x40) s += "R";
    else s += "*";
    if((flags & 0x20) == 0x20) s += "U";
    else s += "*";
    if((flags & 0x10) == 0x10) s += "A";
    else s += "*";
    if((flags & 0x08) == 0x08) s += "P";
    else s += "*";
    if((flags & 0x04) == 0x04) s += "R";
    else s += "*";
    if((flags & 0x02) == 0x02) s += "S";
    else s += "*";
    if((flags & 0x01) == 0x01) s += "F";
    else s += "*";
    return s;
}

void generate_itemsets(std::vector< std::pair<float, mm_record *> > &score,
                       std::vector< std::vector<float> > &contrib,
                       std::ostream &out,
		       char *summarization_config_filename){
  using namespace std;
  float top     = 0.05;
  float bot     = 0.30;
  float top_sup = 0.01;
  float bot_sup = 0.10;
  float eps     = 0.05;
  float alpha   = 0.50;
  float cap     = 0.15;

  unsigned int num_cpackets_bins = 75;
  unsigned int num_cbytes_bins  = 75;
  unsigned int num_spackets_bins = 75;
  unsigned int num_sbytes_bins    = 75;
  //parse configuration file
  TiXmlDocument doc;
  if(!doc.LoadFile(summarization_config_filename)) SYSERROR("Error opening the summarization_config file '\
%s'\n", summarization_config_filename);
  TiXmlNode* nodeRoot = doc.RootElement();
  if(strcmp(nodeRoot->Value(),"mindsconfig")) SYSERROR("Incorrect root node. Must be mindsconfig.\n");
  for(TiXmlNode* child = nodeRoot->FirstChild(); child; child = child->NextSibling() ){
    if(!strcmp(child->Value(),"top")) top = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"bot")) bot = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"top_sup")) top_sup = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"bot_sup")) bot_sup = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"eps")) eps = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"alpha")) alpha = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"cap")) cap = atof(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"num_cpackets_bins")) num_cpackets_bins = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"num_cbytes_bins")) num_cbytes_bins = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"num_spackets_bins")) num_spackets_bins = atoi(((TiXmlElement*) child)->GetText());
    if(!strcmp(child->Value(),"num_sbytes_bins")) num_sbytes_bins = atoi(((TiXmlElement*) child)->GetText());
  }  
  unsigned int i, j, k;
  // only using the top and bottom portions
  vector< vector<unsigned int> > data((unsigned int)(ceil(top * score.size()) + ceil(bot * score.size())), vector<unsigned int>(NUM_BASIC,0));
  vector< int > item_category; // srcip, srcport, dstip, dstport, protocol, tcp_flags, cpackets, cbytes, spackets, sbytes
  vector<string> names; // values corresponding to binarized attributes

  map<unsigned long,  int> srcip, dstip;
  map<unsigned long,  int>::iterator ip_it;
  map<pair<unsigned short, unsigned short>, int> srcport, dstport; // port, protocol pair... 53/UDP is different than 53/TCP
  map<pair<unsigned short, unsigned short>, int>::iterator port_it;
  map<unsigned char, int> protocol;
  map<unsigned char, int> tcp_flags;
  map<unsigned char, int>::iterator flag_it;
  // prepare the data in transaction form
  for(i = 0; i < score.size(); ++i){
    // ignore the middle part
    if(i >= (unsigned int)(score.size() * top) && i < (unsigned int)(score.size() * (1 - bot))) continue;
    
    if(srcip.find(score[i].second->src_ip) == srcip.end())
      srcip[score[i].second->src_ip] = srcip.size() - 1;

    if(srcport.find(pair<unsigned short, unsigned short>(score[i].second->src_port, score[i].second->protocol)) == srcport.end())
      srcport[pair<unsigned short, unsigned short>(score[i].second->src_port, score[i].second->protocol)] = srcport.size() - 1;

    if(dstip.find(score[i].second->dst_ip) == dstip.end())
      dstip[score[i].second->dst_ip] = dstip.size() - 1;

    if(dstport.find(pair<unsigned short, unsigned short>(score[i].second->dst_port, score[i].second->protocol)) == dstport.end())
      dstport[pair<unsigned short, unsigned short>(score[i].second->dst_port, score[i].second->protocol)] = dstport.size() - 1;

    if(protocol.find(score[i].second->protocol) == protocol.end())
      protocol[score[i].second->protocol] = protocol.size() - 1;

    if(tcp_flags.find(score[i].second->flags) == tcp_flags.end())
      tcp_flags[score[i].second->flags] = tcp_flags.size() - 1;
  }

  vector<unsigned int> offsets(NUM_BASIC+1);
  offsets[0] = 0;
  offsets[1] = srcip.size();
  offsets[2] = srcport.size();
  offsets[3] = dstip.size();
  offsets[4] = dstport.size();
  offsets[5] = protocol.size();
  offsets[6] = tcp_flags.size();
  for(i = 1; i < NUM_BASIC-1; ++i){
    item_category.insert(item_category.end(), offsets[i], i - 1);
    offsets[i] += offsets[i-1];
  }
  names.resize(offsets[6]);
    
  for(ip_it = srcip.begin(); ip_it != srcip.end(); ++ip_it) names[offsets[0] + ip_it->second] = ip2string(ip_it->first);
  for(port_it = srcport.begin(); port_it != srcport.end(); ++port_it){
    stringstream s;
    string str;
    s << port_it->first.first;
    s >> str;
    names[offsets[1] + port_it->second] = str;
  }
  for(ip_it = dstip.begin(); ip_it != dstip.end(); ++ip_it) names[offsets[2] + ip_it->second] = ip2string(ip_it->first);
  for(port_it = dstport.begin(); port_it != dstport.end(); ++port_it){
    stringstream s;
    string str;
    s << port_it->first.first;
    s >> str;
    names[offsets[3] + port_it->second] = str;
  }
  for(flag_it = protocol.begin(); flag_it != protocol.end(); ++flag_it){
    stringstream s;
    string str;
    s << (unsigned int)(flag_it->first);
    s >> str;
    names[offsets[4] + flag_it->second] = str;
  }
  for(flag_it = tcp_flags.begin(); flag_it != tcp_flags.end(); ++flag_it){
    stringstream s;
    string str;
    s << (unsigned int)(flag_it->first);
    s >> str;
    names[offsets[5] + flag_it->second] = str;
  }

  // discretize the number of packets and octets
  map<unsigned int, unsigned int> p_dist, o_dist, w_dist, t_dist;  // value , count ... later becomes value, index into names
  map<unsigned int, unsigned int>::iterator it;
    
  for(i = 0; i < score.size() * top; ++i){
    ++p_dist[score[i].second->cpackets];
    ++o_dist[score[i].second->cbytes];
    ++w_dist[score[i].second->spackets];
    ++t_dist[score[i].second->sbytes];
  }
  for(i = (unsigned int)(score.size() * (1. - bot)); i < score.size(); ++i){
    ++p_dist[score[i].second->cpackets];
    ++o_dist[score[i].second->cbytes];
    ++w_dist[score[i].second->spackets];
    ++t_dist[score[i].second->sbytes];
  }

  { // create equal width bins for number of packets
    vector<unsigned int> counts(p_dist.size(), 1); // number of distinct (consecutive) values in the current bin
    vector<unsigned int> sizes(p_dist.size());     // total number of instances covered by the bin
    for(i = 0, it = p_dist.begin(); it != p_dist.end(); ++it){
      sizes[i] = it->second;
      ++i;
    }
    k = p_dist.size();
    while(k > num_cpackets_bins){
      j = 0;
      unsigned int min_loc = 0;
      unsigned int min_size = score.size();
      while(j + counts[j] < counts.size()){
	if(sizes[j] + sizes[j + counts[j]] < min_size){
	  min_size = sizes[j] + sizes[j + counts[j]];
	  min_loc = j;
	}
	j += counts[j];
      }
      sizes[min_loc] += sizes[min_loc + counts[min_loc]]; // update the total size of both merging bin
      counts[min_loc] += counts[min_loc + counts[min_loc]];
      --k;
    }
        
    num_cpackets_bins = k;
    for(i = 0, j = 0, it = p_dist.begin(); i < num_cpackets_bins; ++i){
      names.push_back(string());

      string bin_name;
      stringstream s;
      s << "[";
      if(it->first < 1024) s << it->first << ",";
      else{
	if(it->first > (1 << 20)) s << (it->first >> 20) << "M,";
	else                      s << (it->first >> 10) << "k,";
      }
      for(k = 0; k < counts[j]; ++k){
	it->second = i;
	++it;
      }
      --it;
      if(it->first < 1024) s << it->first << "]";
      else{
	if(it->first > (1 << 20)) s << (it->first >> 20) << "M]";
	else                      s << (it->first >> 10) << "k]";
      }
      s >> bin_name;
      ++it;
      names.back() = bin_name;
      // cout << bin_name << " " << counts[j] << " " << sizes[j] << endl;
      j += counts[j];
    }
  }
  { // create equal width bins for number of bytes
    vector<unsigned int> counts(o_dist.size(), 1); // number of distinct (consequtive) values in the current bin
    vector<unsigned int> sizes(o_dist.size());     // total number of instances covered by the bin
    for(i = 0, it = o_dist.begin(); it != o_dist.end(); ++it){
      sizes[i] = it->second;
      ++i;
    }
    k = o_dist.size();
    while(k > num_cbytes_bins){
      j = 0;
      unsigned int min_loc = 0;
      unsigned int min_size = score.size();
      while(j + counts[j] < counts.size()){
	if(sizes[j] + sizes[j + counts[j]] < min_size){
	  min_size = sizes[j] + sizes[j + counts[j]];
	  min_loc = j;
	}
	j += counts[j];
      }
      sizes[min_loc] += sizes[min_loc + counts[min_loc]]; // update the total size of both merging bin
      counts[min_loc] += counts[min_loc + counts[min_loc]];
      --k;
    }
        
    num_cbytes_bins = k;
    for(i = 0, j = 0, it = o_dist.begin(); i < num_cbytes_bins; ++i){
      names.push_back(string());

      string bin_name;
      stringstream s;
      s << "[";
      if(it->first < 1024) s << it->first << ",";
      else{
	if(it->first > (1 << 20)) s << (it->first >> 20) << "M,";
	else                      s << (it->first >> 10) << "k,";
      }
      for(k = 0; k < counts[j]; ++k){
	it->second = i;
	++it;
      }
      --it;
      if(it->first < 1024) s << it->first << "]";
      else{
	if(it->first > (1 << 20)) s << (it->first >> 20) << "M]";
	else                      s << (it->first >> 10) << "k]";
      }
      s >> bin_name;
      ++it;
      names.back() = bin_name;
      // cout << bin_name << " " << counts[j] << " " << sizes[j] << endl;
      j += counts[j];
    }
  }


  { // create equal width bins for spackets
    vector<unsigned int> counts(w_dist.size(), 1); // number of distinct (consequtive) values in the current bin
    vector<unsigned int> sizes(w_dist.size());     // total number of instances covered by the bin
    for(i = 0, it = w_dist.begin(); it != w_dist.end(); ++it){
      sizes[i] = it->second;
      ++i;
    }
    k = w_dist.size();
    while(k > num_spackets_bins){
      j = 0;
      unsigned int min_loc = 0;
      unsigned int min_size = score.size();
      while(j + counts[j] < counts.size()){
	if(sizes[j] + sizes[j + counts[j]] < min_size){
	  min_size = sizes[j] + sizes[j + counts[j]];
	  min_loc = j;
	}
	j += counts[j];
      }
      sizes[min_loc] += sizes[min_loc + counts[min_loc]]; // update the total size of both merging bin
      counts[min_loc] += counts[min_loc + counts[min_loc]];
      --k;
    }
        
    num_spackets_bins = k;
    for(i = 0, j = 0, it = w_dist.begin(); i < num_spackets_bins; ++i){
      names.push_back(string());

      string bin_name;
      stringstream s;
      s << "[";
      s << it->first << ",";

      for(k = 0; k < counts[j]; ++k){
	it->second = i;
	++it;
      }
      --it;
      s << it->first << "]";

      s >> bin_name;
      ++it;
      names.back() = bin_name;
      j += counts[j];
    }
  }

  { // create equal width bins for sbytes
    vector<unsigned int> counts(t_dist.size(), 1); // number of distinct (consequtive) values in the current bin
    vector<unsigned int> sizes(t_dist.size());     // total number of instances covered by the bin
    for(i = 0, it = t_dist.begin(); it != t_dist.end(); ++it){
      sizes[i] = it->second;
      ++i;
    }
    k = t_dist.size();
    while(k > num_sbytes_bins){
      j = 0;
      unsigned int min_loc = 0;
      unsigned int min_size = score.size();
      while(j + counts[j] < counts.size()){
	if(sizes[j] + sizes[j + counts[j]] < min_size){
	  min_size = sizes[j] + sizes[j + counts[j]];
	  min_loc = j;
	}
	j += counts[j];
      }
      sizes[min_loc] += sizes[min_loc + counts[min_loc]]; // update the total size of both merging bin
      counts[min_loc] += counts[min_loc + counts[min_loc]];
      --k;
    }

    num_sbytes_bins = k;
    for(i = 0, j = 0, it = t_dist.begin(); i < num_sbytes_bins; ++i){
      names.push_back(string());

      string bin_name;
      stringstream s;
      s << "[";
      s << it->first << ",";

      for(k = 0; k < counts[j]; ++k){
	it->second = i;
	++it;
      }
      --it;
      s << it->first << "]";

      s >> bin_name;
      ++it;
      names.back() = bin_name;
      j += counts[j];
    }
  }
  offsets[7] = offsets[6] + num_cpackets_bins;
  offsets[8] = offsets[7] + num_cbytes_bins;
  offsets[9] = offsets[8] + num_spackets_bins;
  offsets[10] = offsets[9] + num_sbytes_bins;
  item_category.insert(item_category.end(), num_cpackets_bins, 6);
  item_category.insert(item_category.end(), num_cbytes_bins, 7);
  item_category.insert(item_category.end(), num_spackets_bins, 8);
  item_category.insert(item_category.end(), num_sbytes_bins, 9);
  unsigned int num_items = offsets[NUM_BASIC];
  unsigned int topitems = (unsigned int) ceil(score.size()*top);
  unsigned int botitems = (unsigned int) ceil(score.size()*bot);
  for(i = 0; i < topitems; i++){
    data[i][0] = srcip     [score[i].second->src_ip];
    data[i][1] = srcport   [pair<unsigned short, unsigned short>(score[i].second->src_port, score[i].second->protocol)] + offsets[1];
    data[i][2] = dstip     [score[i].second->dst_ip]     + offsets[2];
    data[i][3] = dstport   [pair<unsigned short, unsigned short>(score[i].second->dst_port, score[i].second->protocol)] + offsets[3];
    data[i][4] = protocol  [score[i].second->protocol]  + offsets[4];
    data[i][5] = tcp_flags [score[i].second->flags] + offsets[5];
    data[i][6] = p_dist    [score[i].second->cpackets]   + offsets[6];
    data[i][7] = o_dist    [score[i].second->cbytes]    + offsets[7];
    data[i][8] = w_dist    [score[i].second->spackets] + offsets[8];
    data[i][9] = t_dist    [score[i].second->sbytes] + offsets[9];
  }
  // data converted to bit-vector
  
  for(j = score.size()-botitems; j < score.size(); ++j,++i){
    data[i][0] = srcip     [score[j].second->src_ip];
    data[i][1] = srcport   [pair<unsigned short, unsigned short>(score[j].second->src_port, score[j].second->protocol)] + offsets[1];
    data[i][2] = dstip     [score[j].second->dst_ip]     + offsets[2];
    data[i][3] = dstport   [pair<unsigned short, unsigned short>(score[j].second->dst_port, score[j].second->protocol)] + offsets[3];
    data[i][4] = protocol  [score[j].second->protocol]  + offsets[4];
    data[i][5] = tcp_flags [score[j].second->flags] + offsets[5];
    data[i][6] = p_dist    [score[j].second->cpackets]   + offsets[6];
    data[i][7] = o_dist    [score[j].second->cbytes]    + offsets[7];
    data[i][8] = w_dist    [score[j].second->spackets] + offsets[8];
    data[i][9] = t_dist    [score[j].second->cbytes] + offsets[9];
  }
  // data converted to bit-vector

  vector<itemset_record> rules;
  discriminating_itemsets(rules, data, num_items, (unsigned int)(ceil(top * score.size())), top_sup, bot_sup, eps, item_category); 
  // calculate the centroid of contributions for itemsets
  vector< vector<float> > itemset_contrib(rules.size(), vector<float>(NUM_DIM,0));
  for(i = 0; i < rules.size(); ++i){
    for(j = 0; j < rules[i].records.size(); ++j)
      for(k = 0; k < NUM_DIM; ++k) itemset_contrib[i][k] += contrib[rules[i].records[j]][k];
    for(k = 0; k < NUM_DIM; ++k) itemset_contrib[i][k] /= float(rules[i].records.size());
  }

  vector<bool> selected(rules.size(), 0);
  vector<int> record2rule(data.size(), -1);
  vector<float> record2rule_match(data.size(), -1);
  // select the best rule (match + min(cap, alpha * support) for every record
  for(i = 0; i < rules.size(); ++i){
    for(j = 0; j < rules[i].records.size(); ++j){
      if(rules[i].records[j] > top * score.size()) break; // only selecting rules for anomalous connections
      float f = min(alpha * float(rules[i].c1) / float(data.size() * top), cap);
      for(k = 0; k < NUM_DIM; ++k) f += itemset_contrib[i][k] * contrib[rules[i].records[j]][k]; // dot product
      if(f >= record2rule_match[rules[i].records[j]] * .999999) {
	record2rule_match[rules[i].records[j]] = f;
	record2rule[rules[i].records[j]] = i;
      }
    }
  }
  char buf[256];
  sprintf(buf, "%-6s %4s %4s %-16s%-6s%-16s%-6s%-5s%-9s%-12s%-12s%-12s%-12s%s\n",
	  "score", "c1", "c2", "srcIP", "sPort", "dstIP", "dPort", "pro", "flags", "cpackets", "cbytes","spackets","sbytes",
	  "  1    2    3    4    5    6    7    8    9    10   11   12   13   14   15   16   17");
  out << buf;
  for(i = 0; i < data.size() * top; ++i){
    protoent *pro;
    pro = getprotobynumber(score[i].second->protocol);
    if(record2rule[i] == -1){ // no rule matched the record
      sprintf(buf, "%G %4s %4s ", score[i].first, "-", "-");
      out << buf;
      if(pro != NULL){
	sprintf(buf, "%-16s%5s %-16s%5s %3s %5s %-12s%-12s%-12s%-12s ",
		names[data[i][0]].c_str(), names[data[i][1]].c_str(), names[data[i][2]].c_str(), names[data[i][3]].c_str(),
		pro->p_name, flags2string1(score[i].second->flags).c_str(), names[data[i][6]].c_str(), names[data[i][7]].c_str(),names[data[i][8]].c_str(),names[data[i][9]].c_str());
      }
      else
	sprintf(buf, "%-16s%5s %-16s%5s %3s %5s %-12s%-12s%-12s%-12s ",
		names[data[i][0]].c_str(), names[data[i][1]].c_str(), names[data[i][2]].c_str(), names[data[i][3]].c_str(),
		names[data[i][4]].c_str(), flags2string1(score[i].second->flags).c_str(), names[data[i][6]].c_str(), names[data[i][7]].c_str(),names[data[i][8]].c_str(),names[data[i][9]].c_str());
      out << buf;
      for(j = 0; j < NUM_DIM; ++j){
	sprintf(buf, "%4.2f ", contrib[i][j]);
	out << buf;
      }
      out << endl;
    }
    else{ // print out the best rule that matched the record
      j = record2rule[i];
      if(selected[j]) continue;  // rule already displayed
      vector<string> a(NUM_BASIC, "");
      a[0] = a[2] = "xxx.xxx.xxx.xxx";
      a[1] = a[3] = "-----";
      a[4] = "xxx";
      a[5]="  ----  ";
      a[6] = a[7] = a[8] = a[9] = "---------";
      selected[j] = 1;
      float f = 0;
      for(k = 0; k < rules[j].records.size(); ++k) f += score[rules[j].records[k]].first;
      f /= float(rules[j].records.size());  // average score for the rule

      for(k = 0; k < rules[j].itemset.size(); ++k){
	stringstream s;
	if(item_category[rules[j].itemset[k]] == 4){
	  if(pro != NULL){
	    s << pro->p_name;
	    s >> a[4];
	  }
	  else{
	    s << int(score[rules[j].records[0]].second->protocol);
	    s >> a[4];
	  }
	  continue;
	}
	if(item_category[rules[j].itemset[k]] == 5)
	  a[5] = flags2string1(score[rules[j].records[0]].second->flags);
	else a[item_category[rules[j].itemset[k]]] = names[rules[j].itemset[k]];
      }

      sprintf(buf, "%6.1f %4d %4d ", f, rules[j].c1, rules[j].c2);
      out << buf;
      sprintf(buf,  "%-16s%5s %-16s%5s %4s %3s %-12s%-12s%-12s%-12s ",
	      a[0].c_str(), a[1].c_str(), a[2].c_str(), a[3].c_str(), a[4].c_str(),a[5].c_str(), a[6].c_str(), a[7].c_str(), a[8].c_str(), a[9].c_str());
      out << buf;
      for(k=0; k<NUM_DIM; ++k){
	sprintf(buf, "%4.2f ", itemset_contrib[j][k]);
	out << buf;
      }
      out << endl;
    }
  }
}
