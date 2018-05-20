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

#ifndef __nf2mmrecord_H__
#define __nf2mmrecord_H__

struct l_record{
    unsigned long first_sec;
    unsigned long first_msec;
    unsigned long last_sec;
    unsigned long last_msec;
    unsigned long octets;
    unsigned long packets;
    unsigned long srcip;
    unsigned long dstip;
 
    unsigned short sif;
    unsigned short dif;
    unsigned short src_as;
    unsigned short dst_as;
    unsigned short src_port;
    unsigned short dst_port;
 
    unsigned char src_mask;
    unsigned char dst_mask;
    unsigned char protocol;
    unsigned char tcp_flags;
 
    struct l_record * next;
};

#endif /* nf2mmrecord */
