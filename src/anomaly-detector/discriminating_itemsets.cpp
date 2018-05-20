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
#include <iostream>
#include "discriminating_itemsets.h"

unsigned int MAX_SIZE = 10;

void get_counts(std::vector<unsigned int> &list, unsigned int &count_top, unsigned int &count_bot, unsigned int top){
    count_bot = count_top = 0;
    std::vector<unsigned int>::iterator it;
    for(it = list.begin(); it != list.end(); ++it){
        if(*it < top) ++count_top;
        else ++count_bot;
    }
}

void intersection(const std::pair<std::vector<unsigned int>, std::vector<unsigned int> > &a,
                  const std::pair<std::vector<unsigned int>, std::vector<unsigned int> > &b,
                        std::pair<std::vector<unsigned int>, std::vector<unsigned int> > &can,
                  const std::vector< std::map< std::vector<unsigned int>, std::pair<unsigned int, unsigned int> > > &lookup){
    // from ABCd and ABCe, get ABCDE
    can.first = a.first;
    can.first.push_back(b.first.back());

    for(unsigned int i = 0; i < can.first.size(); ++i){
        std::vector<unsigned int> check;
        for(unsigned int j = 0; j < can.first.size(); ++j)
            if(i != j) check.push_back(b.first[j]);
        if(lookup[can.first.size() - 2].find(check) == lookup[b.first.size() - 2].end()) return; // subset infrequent
    }

    std::vector<unsigned int>::const_iterator q, w;
    q = a.second.begin();
    w = b.second.begin();
    while(q != a.second.end() && w != b.second.end()){
        if(*q == *w){
            can.second.push_back(*q);
            ++q;
            ++w;
        }
        else {
            if(*q < *w) ++q;
            else ++w;
        }
    }
}

void discriminating_itemsets(std::vector<itemset_record> &rules,
                             std::vector< std::vector<unsigned int> > &data,
                             unsigned int num_items,
                             unsigned int top,     // number of rows in data that are anomalous
                             float top_sup,
                             float bot_sup,
                             float eps,
                             std::vector<int> &item_category){
    using namespace std;
    vector< map< vector<unsigned int>, pair<unsigned int, unsigned int> > > lookup(1);  // itemset, <c1, c2>
    vector<vector<pair<vector<unsigned int>, vector<unsigned int> > > > itemsets(1); // <itemset, list>
    vector<vector<pair<vector<unsigned int>, vector<unsigned int> > > > itemsets2(1);

    vector<pair<vector<unsigned int>, vector<unsigned int> > >::iterator itemset_it;
    map<vector<unsigned  int>, pair<unsigned int, unsigned int> >::iterator lookup_it;

    unsigned int i, j, k, q;

    map<unsigned int, unsigned int> temp;
    itemsets[0].resize(num_items);
    for(i = 0; i < data.size(); ++i){
        for(j = 0; j < data[i].size(); ++j){
            if(itemsets[0][data[i][j]].first.empty()){
                itemsets[0][data[i][j]].first.push_back(data[i][j]);
            }
            itemsets[0][data[i][j]].second.push_back(i);
        }
    }

    float thresh_top = top_sup * top;
    float thresh_bot = bot_sup * (data.size() - top);
    unsigned int count_top = 0 , count_bot = 0;

    for(itemset_it = itemsets[0].begin(); itemset_it != itemsets[0].end(); ++itemset_it){
        get_counts(itemset_it->second, count_top, count_bot, top);
        if(count_top > thresh_top || count_bot > thresh_bot){
            itemsets2[0].push_back(*itemset_it);
            lookup[0][itemset_it->first] = pair<unsigned int, unsigned int>(count_top, count_bot);
        }
    }
    itemsets.clear();

    for(i = 2; i <= MAX_SIZE; ++i){  // starting from generating pairs (i == 2)
        if(i == 3) itemsets2[0].clear(); // free up some memory
        itemsets2.push_back(vector<pair<vector<unsigned int>, vector<unsigned int> > >());
        lookup.push_back(map<vector<unsigned int>, pair<unsigned int, unsigned int> >());
        for(j = 0; j + 1 < itemsets2[i - 2].size(); ++j){
            for(k = j + 1; k < itemsets2[i - 2].size(); ++k){
                bool compatible = 1;
                for(q = 0; q + 1 < itemsets2[i - 2][j].first.size(); ++q){ // only consider intersections of form ABCd ABCe
                    if(itemsets2[i - 2][j].first[q] != itemsets2[i - 2][k].first[q]){
                       compatible = 0;
                       break;
                    }
                }
                if(!compatible) continue;

                pair< vector<unsigned int>, vector<unsigned int> > candidate;
                intersection(itemsets2[i - 2][j], itemsets2[i - 2][k], candidate, lookup);
                get_counts(candidate.second, count_top, count_bot, top);
                if(count_top > thresh_top || count_bot > thresh_bot){ // could generate rules for normal too
                    itemsets2[i - 1].push_back(candidate);
                    lookup[i - 1][candidate.first] = pair<unsigned int, unsigned int>(count_top, count_bot);
                    // pruning
                    vector<unsigned int> check;
                    for(unsigned int ii = 0; ii < candidate.first.size(); ++ii){
                        for(unsigned int jj = 0; jj < candidate.first.size(); ++jj)
                            if(ii != jj) check.push_back(candidate.first[jj]);
                        lookup_it  = lookup[candidate.first.size() - 2].find(check);
                        if(lookup_it != lookup[candidate.first.size() - 2].end()){
                            if(lookup_it->second.first == 0){
                                check.clear();
                                continue;
                            }
                            if(float(count_top) / float(lookup_it->second.first) >= (1. - eps)){
                                lookup_it->second.first  = 0;
                                lookup_it->second.second = 0;
                            }
                        }
                        check.clear();
                    }
                }
                candidate = pair< vector<unsigned int>, vector<unsigned int> >();
            }
        }
        if(itemsets2.back().size() <= 1) break; // cannot generate itemsets that are longer
    }

    unsigned int num_pruned = 0, num_pruned2 = 0, num_pruned3 = 0;
    k = 0;
    for(i = 2; i <= itemsets2.size(); ++i){ // start from pairs
        for(j = 0; j < itemsets2[i - 1].size(); ++j){
            lookup_it = lookup[i - 1].find(itemsets2[i - 1][j].first);

            if(lookup_it->second.first == 0 && lookup_it->second.second == 0) ++num_pruned;
            if(lookup_it->second.first == 0) continue;
            // eliminate rules that appear more in the normal
            if(float(lookup_it->second.second) / float(data.size() - top) > float(lookup_it->second.first) / float(top)){
                ++num_pruned2;
                continue;
            }

            // force either source or destination ip be in the rule
            bool check = 0;
            for(q = 0; q < itemsets2[i - 1][j].first.size(); ++q){
                if(item_category[itemsets2[i - 1][j].first[q]] == 0 || item_category[itemsets2[i - 1][j].first[q]] == 2){
                    check = 1;
                    break;
                }
            }
            if(!check){
                ++num_pruned3;
                continue;
            }

            rules.push_back(itemset_record());

            rules[k].itemset = itemsets2[i - 1][j].first;
            rules[k].records = itemsets2[i - 1][j].second;
            rules[k].c1      = lookup_it->second.first;
            rules[k].c2      = lookup_it->second.second;
            ++k;
        }
    }
    cout << "  " << num_pruned   << " rules pruned... more specific rule had almost exact coverage (" << 1. - eps << "%)" << endl;
    cout << "  " << num_pruned2  << " rules pruned... rules' support were more in normal" << endl;
    cout << "  " << num_pruned3  << " rules pruned... rules did not contain an ip" << endl;
    cout << "  " << rules.size() << " rules generated" << endl;
    return;

}

