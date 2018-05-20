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
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      $Id: flow-print.c,v 1.1.1.1 2009-03-03 19:21:49 chandola Exp $
 */
 
/*
 * This is a modified version of flow-print.c
 * I made it a function that is linked to a c++ program.  Instead of
 * printing the flows, it collects the data and passes it back to the calling program
 *
 * last updated : april 11, 2003
 * Levent Ertoz
 */
 
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <ftlib.h>
#include <limits.h>
 
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
 
#if HAVE_STRING_H
  #include <string.h>
#endif
 
//#include "ftbuild.h"

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
 
struct l_root{
    struct l_record* first;
    struct l_record* last;
};

struct jump {
    int (*where)(struct ftio *ftio, int options, struct l_root* l_root, unsigned long *first, unsigned long *last);
};
int format0(struct ftio *ftio, int options, struct l_root* l_root, unsigned long *first, unsigned long *last);
struct jump format[] = {{format0}};
#define NFORMATS 1

void get_records(struct l_root *root, unsigned long *first, unsigned long *last)
{
    struct ftio ftio;
    int ret;
    root->first = NULL;
    root->last  = NULL;
 
    /* init fterr */
    fterr_setid("");
 
    /* read from stdin */
    if (ftio_init(&ftio, 0, FT_IO_FLAG_READ) < 0)
        fterr_errx(1, "ftio_init(): failed");
 
    ret = format[0].where(&ftio, 0, root, first, last);
} /* main */

int format0(struct ftio *ftio, int options, struct l_root* l_root, unsigned long *first, unsigned long *last)
{
    struct tm *tm;
    struct fttime ftt;
    struct fts3rec_all cur;
    struct fts3rec_offsets fo;
    struct ftver ftv;
    struct ftsym *sym_prot, *sym_asn;
    char *rec;
 
    if (ftio_check_xfield(ftio, FT_XFIELD_DPKTS |
        FT_XFIELD_DOCTETS | FT_XFIELD_FIRST | FT_XFIELD_LAST | FT_XFIELD_INPUT |
        FT_XFIELD_OUTPUT | FT_XFIELD_SRCADDR | FT_XFIELD_DSTADDR |
        FT_XFIELD_SRC_MASK | FT_XFIELD_DST_MASK |
        FT_XFIELD_SRC_AS | FT_XFIELD_DST_AS |
        FT_XFIELD_SRCPORT | FT_XFIELD_DSTPORT | FT_XFIELD_UNIX_SECS |
        FT_XFIELD_UNIX_NSECS | FT_XFIELD_SYSUPTIME | FT_XFIELD_TCP_FLAGS |
        FT_XFIELD_PROT)) {
        fterr_warnx("Flow record missing required field for format.");
        return -1;
    }
 
    ftio_get_ver(ftio, &ftv);
    fts3rec_compute_offsets(&fo, &ftv);
    sym_prot = sym_asn = (struct ftsym*)0L;
    while ((rec = (char*)ftio_read(ftio))) {
        cur.unix_secs = ((u_int32*)(rec+fo.unix_secs));
        cur.unix_nsecs = ((u_int32*)(rec+fo.unix_nsecs));
        cur.sysUpTime = ((u_int32*)(rec+fo.sysUpTime));
        cur.dOctets = ((u_int32*)(rec+fo.dOctets));
        cur.dPkts = ((u_int32*)(rec+fo.dPkts));
        cur.First = ((u_int32*)(rec+fo.First));
        cur.Last = ((u_int32*)(rec+fo.Last));
        cur.input = ((u_int16*)(rec+fo.input));
        cur.output = ((u_int16*)(rec+fo.output));
        cur.srcaddr = ((u_int32*)(rec+fo.srcaddr));
        cur.dstaddr = ((u_int32*)(rec+fo.dstaddr));
        cur.src_as = ((u_int16*)(rec+fo.src_as));
        cur.dst_as = ((u_int16*)(rec+fo.dst_as));
        cur.src_mask = ((u_int8*)(rec+fo.src_mask));
        cur.dst_mask = ((u_int8*)(rec+fo.dst_mask));
        cur.srcport = ((u_int16*)(rec+fo.srcport));
        cur.dstport = ((u_int16*)(rec+fo.dstport));
        cur.prot = ((u_int8*)(rec+fo.prot));
        cur.tcp_flags = ((u_int8*)(rec+fo.tcp_flags));
 
        ftt = ftltime(*cur.sysUpTime, *cur.unix_secs, *cur.unix_nsecs, *cur.First);
        tm = localtime((time_t*)&ftt.secs);

        if(l_root->first == NULL){
            l_root->first = (struct l_record *)malloc(sizeof(struct l_record));
            l_root->last = l_root->first;
            *first = ftt.secs;
            *last =  ftt.secs;
        }
        else{
            l_root->last->next = (struct l_record *)malloc(sizeof(struct l_record));
            l_root->last = l_root->last->next;
            if(ftt.secs < *first) *first = ftt.secs;
            if(ftt.secs > *last)  *last  = ftt.secs;
        }
        l_root->last->octets        = *cur.dOctets;
        l_root->last->packets       = *cur.dPkts;
        l_root->last->srcip         = *cur.srcaddr;
        l_root->last->dstip         = *cur.dstaddr;
 
        l_root->last->sif           = *cur.input;
        l_root->last->dif           = *cur.output;
        l_root->last->src_as        = *cur.src_as;
        l_root->last->dst_as        = *cur.dst_as;
        l_root->last->src_port      = *cur.srcport;
        l_root->last->dst_port      = *cur.dstport;
 
        l_root->last->src_mask      = *cur.src_mask;
        l_root->last->dst_mask      = *cur.dst_mask;
        l_root->last->protocol      = *cur.prot;
        l_root->last->tcp_flags     = *cur.tcp_flags;
 
        l_root->last->first_sec  = ftt.secs;
        l_root->last->first_msec = ftt.msecs;
        l_root->last->next = NULL;

        ftt = ftltime(*cur.sysUpTime, *cur.unix_secs, *cur.unix_nsecs, *cur.Last);
        tm = localtime((time_t*)&ftt.secs);
        l_root->last->last_sec  = ftt.secs;
        l_root->last->last_msec = ftt.msecs;
    } /* while */
    return 0;
} /* format 0 */
