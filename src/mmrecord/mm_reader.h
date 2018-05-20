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


#ifndef __mm_reader_H__
#define __mm_reader_H__

#include "mm_record.h"
#include <sys/types.h>

class mm_reader {
 protected:
  int     _fd;      // file descriptor
  ssize_t _len; // Number of bytes read last

 public:
  mm_reader(const char* filename);
  void read(mm_record &);
  int  len() {return (int)_len;}
  bool ok()  {return (_len==sizeof(mm_record));}
  bool eof() {return (_len==(size_t)0);}
  
};

#endif /* mm_reader */
