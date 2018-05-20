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
# 	The Regents of the University of Minnesota. All rights reserved.
*/

#ifndef MINDS_P2P_DETECTOR
#define MINDS_P2P_DETECTOR
 
#include <fstream>
#include <vector>
#include "mm_record.h"
 
void detect_p2p(std::vector<mm_record> &data,
                std::set<unsigned short> &well_known_p2p_ports,
                std::set<unsigned short> &well_known_malware_ports,
                std::set<unsigned short> &known_good_tcp_udp,
                std::set<unsigned short> &known_good_ports);
#endif
