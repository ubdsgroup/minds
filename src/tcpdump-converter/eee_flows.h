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

#ifndef MINDS_MAIN
#define MINDS_MAIN

#include <string>

//this is the record stored in the binary .flow file
class eee_record{
public:
        unsigned long ssecs;
        unsigned long susecs;
        unsigned long esecs;
        unsigned long eusecs;

        unsigned long sip;
        unsigned short sport;
        unsigned long dip;
        unsigned short dport;

        unsigned long cpackets;
        unsigned long spackets;
        unsigned long cbytes;
	unsigned long cdbytes;
        unsigned long sbytes;
	unsigned long sdbytes;

        unsigned char protocol;
        unsigned char flags;
        unsigned short window_size;
        unsigned char window_changed;
	unsigned char ttl;
	unsigned char session_closed;
   
    eee_record(){
        cpackets = spackets = cbytes = cdbytes = sbytes = sdbytes = 0;
        protocol = flags = window_changed = ttl = 0;
        window_size=0;
	session_closed=0;
    }

};

#endif
