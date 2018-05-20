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


#include "utilities.h"
#include <stdarg.h>
#include <iomanip>
#include "mm_record.h"

#define MINDS_UNKNOWN 0
#define MINDS_CLIENT  1
#define MINDS_SERVER  2
#define MINDS_NA      3

std::ostream& print_type(int type, std::ostream &out){
  switch(type){
  case MINDS_SERVER:  out <<'S' ; break;
  case MINDS_CLIENT:  out <<'C' ; break;
  case MINDS_UNKNOWN: out <<'?' ; break;
  case MINDS_NA:      out <<'N' ; break;
  default:            out <<'X' ;
  }
  return out;
}

std::ostream& print_proto(unsigned char proto, std::ostream& out){
  switch(proto){
  case TCP: out<<"TCP "; break;
  case UDP: out<<"UDP "; break;
  case ICMP:out<<"ICMP"; break;
  default:  out<<"??? "; 
  }
  return out;
}

std::ostream& print_ip(unsigned long ip, std::ostream &out){
  char str[20];
  sprintf(str, "%lu.%lu.%lu.%lu", 
	  ((ip & 0xFF000000) >> 24),
	  ((ip & 0xFF0000  ) >> 16),
	  ((ip & 0xFF00    ) >> 8 ),
	  ((ip & 0xFF      )      ));
  out<<std::setw(18)<<str;
  return out;
}

std::ostream& print_time(unsigned long sec, unsigned short msec, 
			 std::ostream &out){
  struct tm *tm;
  tm = localtime((time_t*)&sec);
  format(out, "%-4.4d%-2.2d%-2.2d.%-2.2d:%-2.2d:%-2.2d.%03lu ",
	    (int) tm->tm_year + 1900, (int) tm->tm_mon + 1, (int) tm->tm_mday,
	    (int) tm->tm_hour, (int) tm->tm_min, (int) tm->tm_sec,
	    (unsigned long) msec);
  return out;
}
  
std::ostream& format(std::ostream& out, const char* fmt, ...){
  va_list args;
  char str[MAX_STRING_LENGTH];
  va_start(args, fmt);
  vsnprintf(str, MAX_STRING_LENGTH-1, fmt, args);
  va_end(args);
  out<<str;
  return out;
}
