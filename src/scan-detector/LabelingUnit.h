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


#ifndef __LABELING_UNIT_H__
#define __LABELING_UNIT_H__

#include "mm_record.h"
#include "mindsconfig.h"
#include <vector>
#include <map>
#include <string>

using namespace std;
struct Info {
  unsigned short sport;
  unsigned short dport;
  unsigned char  proto;
  string label;
};

class LabelingUnit {
 public:
  LabelingUnit(char* mmr_filename, map<unsigned long, vector<Info> > &ipPortMap, char* output_filename);
};
#endif
