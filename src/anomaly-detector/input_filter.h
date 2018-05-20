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

#ifndef MINDS_FILTER
#define MINDS_FILTER

#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include "flows.h"
#include "mm_record.h"
class list{
public:
    int field;
    bool (*comp) (unsigned long, unsigned long, unsigned long);
    unsigned long value;
    unsigned long mask;
    list *next;

    list(int i, bool (*comp) (unsigned long, unsigned long, unsigned long), unsigned long val, unsigned long mask, 
        list *next):field(i), comp(comp), value(val), mask(mask), next(next) {}
};

class rule{
public:
    bool type;
    char name[64];
    list *first, *last;

    rule(bool p, std::string s):type(p) {first = NULL; last = NULL; strcpy(name, s.c_str());}

    void add(int i, bool (*op)(unsigned long, unsigned long, unsigned long), unsigned long val, unsigned long mask){
        if(first == NULL) {
            first = new list(i, op, val, mask, NULL);
            last  = first;
        }
        else {
            last->next = new list(i, op, val, mask, NULL);
            last       = last->next;
        }
    }

    bool apply(mm_record* f){
        list *p;
        p = first;
        do{
	  switch(p->field){
	  case 1: // srcip
	    if(!p->comp(f->src_ip,   p->value, p->mask)) return 0;
	    break;
	  case 2: // dstIP
	    if(!p->comp(f->dst_ip,   p->value, p->mask)) return 0;
	    break;
	  case 3: // srcPort
	    if(!p->comp(f->src_port, p->value, 0)) return 0;
	    break;
	  case 4: // dstPort
	    if(!p->comp(f->dst_port, p->value, 0)) return 0;
	    break;
	  case 5: // protocol
	    if(!p->comp(f->protocol,   p->value, 0)) return 0;
	    break;
	  case 6: // packets
	    if(!p->comp(f->cpackets, p->value, 0)) return 0;
	    break;
	  case 7: // octets
	    if(!p->comp(f->cbytes,  p->value, 0)) return 0;
	    break;
	  case 8: // ip
	    if(!p->comp(f->src_ip,  p->value, p->mask) && !p->comp(f->dst_ip,  p->value, p->mask)) return 0;
	    break;
	  case 9: // ip
	    if(!p->comp(f->src_port,  p->value, 0) && !p->comp(f->dst_port,  p->value, 0)) return 0;
	    break;
	  case 10: //scan
	    if(f->scan == NOT_SCAN) return 0;
	    break;
	  case 11: //p2p
	    if(f->p2p == NOT_P2P) return 0;
	    break;
	  case 12: //hpdt
	    if(f->hpdt == NOT_HPDT) return 0;
	    break;
	  case 0: // true
	    return 1;
	    break;
	  }
        } while((p = p->next) != NULL);
        return 1;
    }
};

//void read_rules(std::ifstream &in, std::vector< std::vector<rule> > &ruleset);
void read_ruleset(std::ifstream &in, std::vector<rule> &ruleset);

#endif
