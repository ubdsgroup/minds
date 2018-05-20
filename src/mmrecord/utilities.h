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

#ifndef __UTILITIES_H__
#define __UTILITIES_H__

#include <iostream>
#include "minds.h"

#define exchange(a, b, type){ \
 type temp = (a); \
 (a) = (b);       \
 (b) = temp;      \
}

#define MAX_STRING_LENGTH 2<<20

std::ostream& print_type(int type, std::ostream &out);
std::ostream& print_ip(unsigned long ip, std::ostream &out);
std::ostream& print_time(unsigned long sec, 
			 unsigned short msec, 
			 std::ostream &out);
std::ostream& format(std::ostream& out, const char* fmt, ...);
std::ostream& print_proto(unsigned char proto, std::ostream& out);
#endif
