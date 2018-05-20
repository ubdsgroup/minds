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


/*
 * MergeMatch
 *
 * A module for merging and matching flows in a quasi-batch mode.
 */
#ifndef __MERGE_MATCH_H__
#define __MERGE_MATCH_H__

#include "mm_record.h"
#include <vector>

class MergeMatch{

 private:  

  static const int NPORTS=(1<<16);

  int freqs[1<<16]; // the frequencies of the ports

 public:

  MergeMatch(){};

  // raw -> the un-merged, unmatched flows, mmr -> merged and matched flows
  // mmr should be initially empty.
  void merge_match(std::vector<mm_record> &raw, std::vector<mm_record> &mmr);

};


#endif
