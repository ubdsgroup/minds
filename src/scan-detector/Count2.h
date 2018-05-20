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


#ifndef __COUNT2_H__
#define __COUNT2_H__

#include "macros.h"
#include <map>
#include <iostream>

class Count {
 protected:
  // dst_ip -> (dst_port -> frequency)
  std::map<unsigned long, std::map<unsigned short, double> > cnts;
  int           total; // total number of flows seen by Count
  double      maxfrq; // maximal frequency

 public:  
  Count(){maxfrq=0;}
  //~Count(){ delete[] cnts; }
  double operator() (unsigned long ip, unsigned short port);
  void incr(unsigned long ip, unsigned short port);
  double prob(unsigned long ip, unsigned short port);
  double minprob(){ return (double)1/(double)total; }
  double maxfreq(){ return maxfrq;}
/*   void incr(unsigned long ip, unsigned short port){ */
/*     DEBUG("ip: %d->%d, port: %d->%d => pos=%d\n", */
/* 	  ip, ipblock(ip), port, portblock(port), */
/* 	  pos(ipblock(ip), portblock(port))); */
/*     cnts[pos(ipblock(ip), portblock(port))]++; */
/*   } */
  void decay(float factor);
  void setmask(unsigned long msk){
    //init(msk);
  }
};

#endif
