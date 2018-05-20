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


#ifndef __FEATURE_EXTRACTOR_H__
#define __FEATURE_EXTRACTOR_H__

#include <vector>
#include <map>
#include "mm_record.h"

class FeatureExtractor {
 private:
  bool tcpPorts[1<<16];
  bool udpPorts[1<<16];
  std::map<unsigned long, bool> darkIPs; 
 public:
  unsigned long success_npckts;
  unsigned long failure_npckts;

  FeatureExtractor(const char* blkFile, const char* drkFile, const char* configFile);

  void featureExtract(std::vector<mm_record>&, char *outputFile);
  bool failed(mm_record&);
  bool succeeded(mm_record&);
};

#endif
