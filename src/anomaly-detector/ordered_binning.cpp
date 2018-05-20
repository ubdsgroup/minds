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

#include "ordered_binning.h"
#include <iostream>
#include <queue>
#include <algorithm>

class bin{
public:
    float gini;
    unsigned int start;
    unsigned int end; // not included

    bin(float g, int s, int e):gini(g), start(s), end(e){}
};

class compare{public:bool operator()(bin a, bin b){return a.gini < b.gini;}};
bool compare_value(node a, node b){return a.value < b.value;}

std::pair<int, std::pair<float,float> > find_best_split(std::vector<node> &d, std::vector< std::pair<int,int> > &counts, int start, int end){
    using namespace std;
    int i;
    float p=0, n=0, gini_l, gini_r, gini, l, r, best_gini;
    float tp = counts[end].first  - counts[start].first;
    float tn = counts[end].second - counts[start].second;

    pair<int, pair<float, float> > best_split;
    best_gini = 10000;
    for(i=start; i<end-1; ++i){
        p += d[i].pos;
        n += d[i].neg;
        l = p+n;
        r = tp + tn - p - n;
        gini_l = 1 - (p/l)*(p/l) - (n/l)*(n/l);
        gini_r = 1 - (tp-p)/r*(tp-p)/r - (tn-n)/r*(tn-n)/r;
        gini = (gini_l * l + gini_r * r) / (l+r);
        if(gini < best_gini) {
            best_split = pair<int, pair<float,float> > (i+1, pair<float,float>(gini_l, gini_r));
            best_gini = gini;
        }
    }
    return best_split;
}

std::vector<int> create_bins(std::vector<node> &data, unsigned int nbins){
    using namespace std;
    unsigned int i;
    if(nbins > data.size()) {
//        cerr << "too many bins\n";
        nbins = data.size();
    }

    sort(data.begin(), data.end(), compare_value);
    vector< pair<int,int> > counts(data.size()+1, pair<int,int>(0,0));
    for(i=0; i<data.size(); ++i){
        counts[i+1].first  = counts[i].first  + data[i].pos;
        counts[i+1].second = counts[i].second + data[i].neg;
    }

    priority_queue<bin, vector<bin>, compare> q;
    float p = counts.end()->first;
    float n = counts.end()->second;
    float gini = 1 - p/(p+n)*p/(p+n) - n/(p+n)*n/(p+n);

    bin a = bin(gini, 0, data.size());
    q.push(a);
    pair<unsigned int, pair<float,float> > split;
    vector<int> bins;
    while(q.size() != nbins){
        a = q.top();
        q.pop();
        split = find_best_split(data, counts, a.start, a.end);
        if((split.first <= a.start) || (split.first >= a.end)) {cout << a.start << " " << split.first << " " << a.end << endl;}
        if(split.first - a.start == 1){
            bins.push_back(data[split.first].value);
            --nbins;
        }
        else q.push(bin(split.second.first,  a.start, split.first));

        if(a.end - split.first == 1){
            if(a.end != data.size()) bins.push_back(data[a.end].value);
            --nbins;
        }
        else q.push(bin(split.second.second, split.first, a.end));
    }
    
    while(!q.empty()){
        a = q.top();
        q.pop();
        if(a.end != data.size()) bins.push_back(data[a.end].value);
    }
    
    sort(bins.begin(), bins.end());
    return bins;
}
