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

#include "input_filter.h"
#include "flows.h"
#include "mm_record.h"
#include <iostream>
#include <map>
#include <netdb.h>
#include <vector>

using namespace std;

bool ge(unsigned long a, unsigned long b, unsigned long c){return a>=b;}
bool gr(unsigned long a, unsigned long b, unsigned long c){return a> b;}
bool le(unsigned long a, unsigned long b, unsigned long c){return a<=b;}
bool ls(unsigned long a, unsigned long b, unsigned long c){return a< b;}
bool eq(unsigned long a, unsigned long b, unsigned long c){return a==b;}
bool ne(unsigned long a, unsigned long b, unsigned long c){return a!=b;}
bool net_equal(unsigned long a, unsigned long b, unsigned long c)    {return (a&c) == b;}  // ip value mask
bool net_not_equal(unsigned long a, unsigned long b, unsigned long c){return (a&c) != b;}  // ip value mask
bool inside (unsigned long a, unsigned long b, unsigned long c)      {return is_inside(a)>0;}
bool outside(unsigned long a, unsigned long b, unsigned long c)      {return is_inside(a)==0;}

void read_ruleset(std::ifstream &in, std::vector<rule> &ruleset){
  int last_set, last_rule;
  unsigned long value;
  std::string s, op, val, name;
  std::map<std::string, bool(*)(unsigned long, unsigned long, unsigned long)> operation;
  operation[">="] = ge;
  operation[">"]  = gr;
  operation["<="] = le;
  operation["<"]  = ls;
  operation["=="] = eq;
  operation["!="] = ne;
  operation["inside"] = inside;
  operation["outside"] = outside;
  operation["net_equal"] = net_equal;
  operation["net_not_equal"] = net_not_equal;

  last_rule = -1;
  last_set  = -1;
  while(1){
    in >> s;
    lowercase(s);
    if(in.fail()) break;
    if(s == "ruleset") {
      if(last_set != -1){
	cerr<<"Only one ruleset allowed. Skipping additional rulesets.\n";
	break;
      }
      in >> name;
      ruleset = std::vector<rule>(); 
      ++last_set; 
      last_rule=-1;
    }
    else if(s == "ignore")  {ruleset.push_back(rule(1, name)); ++last_rule;}
    else if(s == "select")  {ruleset.push_back(rule(0, name)); ++last_rule;}

    else if(s == "srcip"){
      in >> op;
      lowercase(op);
      if(op == "inside" || op == "outside") {ruleset[last_rule].add(1, operation[op],0,0);}
      else {
	in >> val;
	value = get_ip(val);
	if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
	if(op == "net_equal" || op == "net_not_equal") {
	  in >> s;
	  ruleset[last_rule].add(1, operation[op], value, convert_mask(s));
	}
	else ruleset[last_rule].add(1, operation[op], value, 0);
      }
    }
    else if(s == "dstip"){
      in >> op;
      lowercase(op);
      if(op == "inside" || op == "outside") {ruleset[last_rule].add(2, operation[op],0,0);}
      else {
	in >> val;
	value = get_ip(val);
	if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
	if(op == "net_equal" || op == "net_not_equal") {
	  in >> s;
	  ruleset[last_rule].add(2, operation[op], value, convert_mask(s));
	}
	else ruleset[last_rule].add(2, operation[op], value, 0);
      }
    }
    else if(s == "srcport"){
      in >> op >> value;
      lowercase(op);
      if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
      ruleset[last_rule].add(3, operation[op], value, 0);
    }
    else if(s == "dstport"){
      in >> op >> value;
      lowercase(op);
      if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
      ruleset[last_rule].add(4, operation[op], value, 0);
    }
    else if(s == "protocol"){
      in >> op >> name;
      struct protoent *p;
      if((p=getprotobyname(name.c_str())) != NULL){
	value = p->p_proto;
      } else {
	value = atoi(name.c_str());
      }

      lowercase(op);
      if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
      ruleset[last_rule].add(5, operation[op], value, 0);
    }
    else if(s == "packets"){
      in >> op >> value;
      lowercase(op);
      if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
      ruleset[last_rule].add(6, operation[op], value, 0);
    }
    else if(s == "bytesperpacket"){
      in >> op >> value;
      lowercase(op);
      if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
      ruleset[last_rule].add(7, operation[op], value, 0);
    }
    else if(s == "ip"){
      in >> op;
      lowercase(op);
      if(op == "inside" || op == "outside") {ruleset[last_rule].add(8, operation[op],0,0);}
      else {
	in >> val;
	value = get_ip(val);
	if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
	if(op == "net_equal" || op == "net_not_equal") {
	  in >> s;
	  ruleset[last_rule].add(8, operation[op], value, convert_mask(s));
	}
	else {
	  ruleset[last_rule].add(8, operation[op], value, 0);
	}
      }
    }
    else if(s == "port"){
      in >> op >> value;
      lowercase(op);
      if(operation.find(op) == operation.end()) {std::cerr << "unrecognized operation: " << op << "\n"; exit(0);}
      ruleset[last_rule].add(9, operation[op], value, 0);
    }
    else if(s == "scans"){
      ruleset[last_rule].add(10,NULL, 0, 0);
    }
    else if(s == "p2p"){
      ruleset[last_rule].add(11,NULL, 0, 0);
    }
    else if(s == "hpdt"){
      ruleset[last_rule].add(12,NULL, 0, 0);
    }
    else if(s == "all"){
      ruleset[last_rule].add(0, ne, 0, 0);
    }
    else {std::cerr << "rule keyword: '" << s << "' not recognized\n"; exit(0);}
  }
}

