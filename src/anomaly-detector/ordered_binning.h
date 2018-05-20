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

#ifndef MINDS_BIN
#define MINDS_BIN

#include <vector>

class node{
public:
    int value;
    int pos;
    int neg;

    node(int v, int p, int n):value(v), pos(p), neg(n){}
};

std::vector<int> create_bins(std::vector<node> &data, unsigned int nbins);

#endif
