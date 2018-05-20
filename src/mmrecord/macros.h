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

#ifndef __MACROS_H__
#define __MACROS_H__

#include <string.h>
#include <errno.h>
#include <stdio.h>

#define SYSERROR(format, args...) \
{\
   fprintf(stderr, "ERROR: %s: %s: %d:\n   ", __FILE__, __PRETTY_FUNCTION__,\
	   __LINE__);\
   fprintf(stderr, format, ##args);\
   fprintf(stderr, "   %s\n", strerror(errno));\
   exit(1); \
}

#define SYSERRORF(format, args...) \
{\
   fprintf(stderr, "ERROR: %s: %s: %d:\n   ", __FILE__, __PRETTY_FUNCTION__,\
	   __LINE__);\
   fprintf(stderr, format, ##args);\
   fprintf(stderr, "   %s\n", strerror(errno));\
}


#define ERROR(format, args...) \
{\
   fprintf(stderr, "ERROR: %s: %s: %d:\n   ", __FILE__, __PRETTY_FUNCTION__,\
	   __LINE__);\
   fprintf(stderr, format, ##args);\
   exit(1); \
}

#define ERRORF(format, args...) \
{\
   fprintf(stderr, "ERROR: %s: %s: %d:\n   ", __FILE__, __PRETTY_FUNCTION__,\
	   __LINE__);\
   fprintf(stderr, format, ##args);\
}

/* #define DEBUG(format, args...) \ */
/* {\ */
/*    fprintf(stderr, "DEBUG: %s: %s: %d:    ", __FILE__, __PRETTY_FUNCTION__, \ */
/* 	   __LINE__);\ */
/*    fprintf(stderr, format, ##args);\ */
/* } */

#define DEBUG(format, args...) \
{\
   fprintf(stderr, "DEBUG: %s: %d:    ", __FILE__, \
	   __LINE__);\
   fprintf(stderr, format, ##args);\
}

#define WARNING(format, args...) \
{\
   fprintf(stderr, "WARNING: %s: %s: %d:\n   ", __FILE__, __PRETTY_FUNCTION__,\
	   __LINE__);\
   fprintf(stderr, format, ##args);\
}



#endif
