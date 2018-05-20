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

#include <iostream>
#include <fstream>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <pcap.h>

#include "eee_flows.h"
#include "flowrecord.h"

using namespace std;

extern char *df;
extern std::ofstream flowfile;
extern std::ofstream logfile;
extern pcap_t *descr;

void log_error(char *message, std::ostream & out)
{
    char buf[100];
    time_t ti = time(NULL);
    bzero(buf, 100);
    strncpy(buf, ctime(&ti), 100);
    buf[strlen(buf) - 1] = ' ';
    out << buf << df << " " << message << endl;
    return;
}

void print_flow_record_bin(eee_record *a, int closed)
{
    check_time(a->esecs);
    eee_record rec;

    rec.ssecs = htonl(a->ssecs);
    rec.susecs = htonl(a->susecs);
    rec.esecs = htonl(a->esecs);
    rec.eusecs = htonl(a->eusecs);
                                                                              
    rec.sip = htonl(a->sip);
    rec.sport = htons(a->sport);
    rec.dip = htonl(a->dip);
    rec.dport = htons(a->dport);
                                                                              
    rec.cpackets = htonl(a->cpackets);
    rec.spackets = htonl(a->spackets);
    rec.cbytes = htonl(a->cbytes);
    rec.cdbytes = htonl(a->cdbytes);
    rec.sbytes = htonl(a->sbytes);
    rec.sdbytes = htonl(a->sdbytes);
    rec.protocol = a->protocol;
    rec.flags = a->flags;
    rec.window_size = htons(a->window_size);
    rec.window_changed = a->window_changed;
    rec.ttl = a->ttl;
    rec.session_closed = closed;
    flowfile.write((char *) &rec, sizeof(struct eee_record));

    return;
}

int log_stats(){
    struct pcap_stat ps;
    char buf[200];
    pcap_stats(descr, &ps);
    sprintf(buf, "Captured: %d Dropped: %d", ps.ps_recv, ps.ps_drop);
    log_error(buf, logfile);
}
