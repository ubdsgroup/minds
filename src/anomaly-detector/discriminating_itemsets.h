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
# Levent Ertos
# ertoz@cs.umn.edu
#
# Eric Eilertson
# eric@cs.umn.edu
*/


#ifndef MINDS_DISC_ITEMSET
#define MINDS_DISC_ITEMSET

#include <vector>

class itemset_record{
public:
    std::vector<unsigned int> itemset;    // items in the itemset
    std::vector<unsigned int> records;    // list of records the itemset covers
    unsigned int c1;                      // coverage in most  anomalous section
    unsigned int c2;                      // coverage in least anomalous section

    itemset_record(){
        c1 = c2 = 0;
    }

    ~itemset_record(){
        itemset.clear();
        records.clear();
    }
};

void discriminating_itemsets(std::vector<itemset_record> &rules,
                             std::vector< std::vector<unsigned int> > &data,
                             unsigned int num_items,
                             unsigned int top,     // this is different than original top
                             float top_sup,
                             float bot_sup,
                             float epsi,
                             std::vector<int> &item_category);
                                 

#endif
