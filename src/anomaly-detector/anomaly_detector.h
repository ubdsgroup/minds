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

#ifndef OUTLIER
#define OUTLIER

#include <vector>
#include "flows.h"
#include "mm_record.h"

void lof             (std::vector<std::pair<mm_record*,flow_record*> > &train,
                      std::vector<std::pair<mm_record*,flow_record*> > &test,
                      std::vector< std::pair<float, mm_record*> > &score,
                      unsigned int k,
                      std::vector<float> &num_weights,
                      std::vector<float> &cat_weights,
                      std::vector< std::vector<float> > &contrib,
		      int max_top);
void *thread_function_lof( void *arg);
#endif
