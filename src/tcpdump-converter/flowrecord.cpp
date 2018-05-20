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

#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include "flowrecord.h"
#include "eee_flows.h"
#include "io.h"
#include "read_tcpdump.h"

using namespace std;

extern std::ofstream logfile;
extern std::ofstream flowfile;
extern char* output_filename;
extern unsigned long file_start_time;
extern int file_close_time;
extern int version;


void reopen(unsigned long secs)
{
    write_open_flows();
    flowfile.close();
    flowfile.clear();
    log_stats();
    flowfile.open(output_filename);
    flowfile.write((char *) &version, sizeof(int));
    log_error("Reopening flowfile", logfile);
    return;
}


void check_time(unsigned long secs)
{
    string filename;
    if (file_close_time == MINUTE) {
	if (file_start_time + 60 < secs) {
	    file_start_time = secs - (secs % 60);
	    reopen(secs);
	}
    }
    if (file_close_time == TEN_MINUTE) {
	if (file_start_time + (60 * 10) < secs) {
	    file_start_time = secs - (secs % (60 * 10));
	    reopen(secs);
	}
    }
    if (file_close_time == HALF_HOUR) {
	if (file_start_time + (60 * 30) < secs) {
	    file_start_time = secs - (secs % (60 * 30));
	    reopen(secs);
	}
    }
    if (file_close_time == HOUR) {
	if (file_start_time + (60 * 60) < secs) {
	    file_start_time = secs - (secs % (60 * 60));
	    reopen(secs);
	}
    }
    if (file_close_time == DAY) {
	if (file_start_time + (60 * 60 * 24) < secs) {
	    file_start_time = secs - (secs % (60 * 60 * 24));
	    reopen(secs);
	}
    }
    if (file_close_time == WEEK) {
	if (file_start_time + (60 * 60 * 24 * 7) < secs) {
	    file_start_time = secs - (secs % (60 * 60 * 24 * 7));
	    reopen(secs);
	}
    }
}

