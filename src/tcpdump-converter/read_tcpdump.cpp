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

#include "pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>

#ifdef SOLARIS
#include <sys/ethernet.h>
#include <netinet/arp.h>
#include <netinet/in_systm.h>

/* if we have u_int8_t */
#define u_int8_t u_char

/* if we have u_int16_t */
#define u_int16_t u_short

/* if we have u_int32_t */ 
#define u_int32_t u_int

#define __FAVOR_BSD

#else
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#endif

/*
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
*/

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>


#include <iostream>
#include <string>
#include <map>
#include <vector>

#include "io.h"
#include "eee_flows.h"
#include "read_tcpdump.h"
#include "flowrecord.h"

using namespace std;

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

#define L_DEVICE 0
#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)&x))

#define TCPTIMEOUT 120
#define UDPTIMEOUT 10
#define IPSECTIMEOUT 10

extern unsigned long num_packets_cleanup;
extern std::ofstream flowfile;

const struct pcap_pkthdr *eee_hdr;
const u_char *eee_linkdata;
const u_char *eee_data;

bool operator<(struct tuple4 a, struct tuple4 b)
{
    if (a.saddr < b.saddr)
	return true;
    if (a.saddr > b.saddr)
	return false;
    if (a.daddr < b.daddr)
	return true;
    if (a.daddr > b.daddr)
	return false;
    if (a.source < b.source)
	return true;
    if (a.source > b.source)
	return false;
    if (a.dest < b.dest)
	return true;
    return false;
}



map < struct tuple4, eee_record > tcp_map;
map < struct tuple4, eee_record >::iterator tcp_temp_it;
map < struct tuple4, eee_record >::iterator my_iterator;


map < struct tuple4, eee_record > udp_map;
map < struct tuple4, eee_record > ipsec_map;
map < struct tuple4, eee_record >::iterator udp_it;
map < struct tuple4, eee_record >::iterator ipsec_it;


unsigned int latest_time = 0;
unsigned long num_tcp = 0;
unsigned long num_tcp_temp = 0;
unsigned long num_udp = 0;
unsigned long num_ipsec = 0;

u_int16_t handle_ethernet(u_char * args, const struct pcap_pkthdr *pkthdr,
			  const u_char * packet);
u_char *handle_IP(u_char * args, const struct pcap_pkthdr *pkthdr,
		  const u_char * packet);
u_char *process_TCP(u_char * args, const struct pcap_pkthdr *pkthdr,
		    const u_char * packet);

void lookup_tcp(const struct pcap_pkthdr *eee_hdr, const u_char * packet);

void ip2buf(unsigned long ip, char *buf)
{
    sprintf(buf, "%lu.%lu.%lu.%lu", ((ip & 0xFF000000) >> 24),
	    ((ip & 0xFF0000) >> 16), ((ip & 0xFF00) >> 8), ((ip & 0xFF)));
}

void print_ip(unsigned long ip, std::ostream & out)
{
    char buf1[20];

    ip2buf(ip, buf1);
    out << buf1;
    return;
}

struct my_ip {
    u_int8_t ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos;		/* type of service */
    u_int16_t ip_len;		/* total length */
    u_int16_t ip_id;		/* identification */
    u_int16_t ip_off;		/* fragment offset field */
#define	IP_DF 0x4000		/* dont fragment flag */
#define	IP_MF 0x2000		/* more fragments flag */
#define	IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_int8_t ip_ttl;		/* time to live */
    u_int8_t ip_p;		/* protocol */
    u_int16_t ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};
/* looking at ethernet headers */
void my_callback(u_char * args, const struct pcap_pkthdr *pkthdr,
		 const u_char * packet)
{
    u_int16_t type = handle_ethernet(args, pkthdr, packet);
    eee_hdr = pkthdr;
    eee_linkdata = packet;
    eee_data = packet + sizeof(struct ether_header);

    if (type == ETHERTYPE_IP) {	/* handle IP packet */
	handle_IP(args, pkthdr, packet);
    } else if (type == ETHERTYPE_ARP) {	/* handle arp packet */
    } else if (type == ETHERTYPE_REVARP) {	/* handle reverse arp packet */
    }
}

u_char *handle_IP(u_char * args, const struct pcap_pkthdr * pkthdr,
		  const u_char * packet)
{
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int off;

    /* jump pass the ethernet header */
    ip = (struct my_ip *) (packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip)) {
	printf("truncated ip %d", length);
	return NULL;
    }

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0) {
	if (ip->ip_p == 6) {
            lookup_tcp(pkthdr, packet);
	    return NULL;
	} else if (ip->ip_p == 17) {
	    udp_callback(eee_data, (struct ip *) eee_data);
	} else {
	    ip_callback((struct ip *) eee_data);
	}
    }

    return NULL;
}

u_int16_t handle_ethernet(u_char * args, const struct pcap_pkthdr * pkthdr,
			  const u_char * packet)
{
    u_int caplen = pkthdr->caplen;
    struct ether_header *eptr;	/* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN) {
	fprintf(stdout, "Packet length less than ethernet header length\n");
	return 0;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    return ether_type;
}

void lookup_tcp(const struct pcap_pkthdr *eee_hdr, const u_char * packet)
{
    struct tuple4 addr, raddr;
    const u_char *eee_data = packet + sizeof(struct ether_header);
    struct ip *this_iphdr = (struct ip *) eee_data;
    struct tcphdr *this_tcphdr =
	(struct tcphdr *) (eee_data + 4 * this_iphdr->ip_hl);
    unsigned char *payload;

#ifdef __FAVOR_BSD
    addr.source = ntohs(this_tcphdr->th_sport);
    addr.dest = ntohs(this_tcphdr->th_dport);
    raddr.source = ntohs(this_tcphdr->th_dport);
    raddr.dest = ntohs(this_tcphdr->th_sport);
#else
    addr.source = ntohs(this_tcphdr->source);
    addr.dest = ntohs(this_tcphdr->dest);
    raddr.source = ntohs(this_tcphdr->dest);
    raddr.dest = ntohs(this_tcphdr->source);

#endif

#ifdef __FAVOR_BSD
    payload = (unsigned char *)(this_tcphdr) + (this_tcphdr->th_off * 4);
#else
    payload = (unsigned char *)(this_tcphdr) + this_tcphdr->doff * 4;
#endif

    int hs = (char *)payload - (char *)this_iphdr;

    addr.saddr = this_iphdr->ip_src.s_addr;
    addr.daddr = this_iphdr->ip_dst.s_addr;
    raddr.saddr = this_iphdr->ip_dst.s_addr;
    raddr.daddr = this_iphdr->ip_src.s_addr;

    num_tcp_temp++;
    if (num_tcp_temp == num_packets_cleanup) {
	num_tcp_temp = 0;
	for (tcp_temp_it = tcp_map.begin();
	     tcp_temp_it != tcp_map.end(); tcp_temp_it++) {
	    if (tcp_temp_it->second.esecs + TCPTIMEOUT + 1 < latest_time) {	//this is old
		num_tcp++;
//                              cout<<"This next one is a non established one"<<endl;
//		toflows(&(tcp_temp_it->second));
                print_flow_record_bin(&(tcp_temp_it->second), 1);

	    }
	}
	tcp_temp_it = tcp_map.begin();

	while (tcp_temp_it != tcp_map.end()) {
	    if (tcp_temp_it->second.esecs + TCPTIMEOUT + 1 < latest_time) {	//this is old
		tcp_map.erase(tcp_temp_it);
		tcp_temp_it = tcp_map.begin();
	    } else {
		tcp_temp_it++;
	    }
	}
    }
//if this packet has ONLY the syn flag set
//check if we already have a session established
//if so clear that one and process normally
//i.e. this is a new session now
    if (((eee_data + 4 * this_iphdr->ip_hl)[13]) & 0x3f == 0x02) {	//syn only
	int found = 0;
	if (tcp_map.find(addr) != tcp_map.end()) {
	    my_iterator = tcp_map.find(addr);
	    found = 1;
	} else if (tcp_map.find(raddr) != tcp_map.end()) {
	    my_iterator = tcp_map.find(raddr);
	    found = 1;
	}
	if (found == 1) {
//	    toflows(&(my_iterator->second));
             print_flow_record_bin(&(my_iterator->second), 1);
	    tcp_map.erase(my_iterator);
	    cout << "flushed one early" << endl;
	}
    }
    //this is new
    if ((tcp_map.find(addr) == tcp_map.end())
	&& (tcp_map.find(raddr) == tcp_map.end())) {

	eee_record blah;
	blah.ssecs = eee_hdr->ts.tv_sec;
	blah.susecs = eee_hdr->ts.tv_usec;
	blah.esecs = eee_hdr->ts.tv_sec;
	blah.eusecs = eee_hdr->ts.tv_usec;
	blah.sip = ntohl(addr.saddr);
	blah.dip = ntohl(addr.daddr);
	blah.sport = addr.source;
	blah.dport = addr.dest;
	blah.cpackets = 1;
	blah.spackets = 0;
	blah.cbytes = ntohs(this_iphdr->ip_len);
	blah.cdbytes = ntohs(this_iphdr->ip_len) - hs; 
	blah.sbytes = 0;
	blah.ttl = this_iphdr->ip_ttl;
	blah.protocol = this_iphdr->ip_p;
	blah.flags = (eee_data + 4 * this_iphdr->ip_hl)[13];

#ifdef SOLARIS
        blah.window_size = ntohs(this_tcphdr->th_win);
#else

//this is all coming about because solaris is insane!
#ifdef __FAVOR_BSD
	blah.window_size = ntohs(this_tcphdr->th_window);
#else
	blah.window_size = ntohs(this_tcphdr->window);
#endif
#endif
	blah.window_changed = 0;
	tcp_map[addr] = blah;
	return;
    }
    if (tcp_map.find(addr) != tcp_map.end()) {
	my_iterator = tcp_map.find(addr);
	my_iterator->second.cpackets += 1;
	my_iterator->second.cbytes += ntohs(this_iphdr->ip_len);
	my_iterator->second.cdbytes += ntohs(this_iphdr->ip_len) - hs;
	my_iterator->second.esecs = eee_hdr->ts.tv_sec;
	my_iterator->second.eusecs = eee_hdr->ts.tv_usec;
	my_iterator->second.flags |= (eee_data + 4 * this_iphdr->ip_hl)[13];

	return;
    }
    if (tcp_map.find(raddr) != tcp_map.end()) {
	my_iterator = tcp_map.find(raddr);
	my_iterator->second.spackets += 1;
	my_iterator->second.sbytes += ntohs(this_iphdr->ip_len);
	my_iterator->second.sdbytes += ntohs(this_iphdr->ip_len) - hs;
	my_iterator->second.esecs = eee_hdr->ts.tv_sec;
	my_iterator->second.eusecs = eee_hdr->ts.tv_usec;
	my_iterator->second.flags |= (eee_data + 4 * this_iphdr->ip_hl)[13];
	return;
    }

}


int icmp_handler(struct ip *pkt)
{
    eee_record blah;
    struct icmp6_hdr *icmp_hdr =
	(struct icmp6_hdr *) (eee_data + 4 * pkt->ip_hl);
    struct ip *new_ip_hdr = (struct ip *) (eee_data + (4 * pkt->ip_hl) + 8);
    struct tuple4 addr, raddr;

    blah.ssecs = eee_hdr->ts.tv_sec;
    blah.susecs = eee_hdr->ts.tv_usec;
    blah.esecs = eee_hdr->ts.tv_sec;
    blah.eusecs = eee_hdr->ts.tv_usec;
    blah.sip = ntohl(pkt->ip_src.s_addr);
    blah.dip = ntohl(pkt->ip_dst.s_addr);
    blah.ttl = pkt->ip_ttl;
    blah.protocol = pkt->ip_p;
    blah.cpackets = 1;
    blah.cbytes = ntohs(pkt->ip_len);
    blah.cdbytes = ntohs(pkt->ip_len) - 4;
    blah.flags = 0;

    blah.sport = icmp_hdr->icmp6_type;
    blah.dport = icmp_hdr->icmp6_code;

    if (blah.sport != 3) {	//3 is destination unreachable
//	toflows(&blah);
         print_flow_record_bin(&blah, 1);
	return 0;
    }
    if (blah.sport == 3) {	//3 is dest. unrearchable
//can probably get rid of raddr stuff

	addr.saddr = new_ip_hdr->ip_src.s_addr;
	addr.daddr = new_ip_hdr->ip_dst.s_addr;
	raddr.saddr = new_ip_hdr->ip_dst.s_addr;
	raddr.daddr = new_ip_hdr->ip_src.s_addr;

	if (new_ip_hdr->ip_p == 6) {	//tcp
	    struct tcphdr *this_tcphdr =
		(struct tcphdr *) ((eee_data + (4 * pkt->ip_hl) + 8) +
				   (4 * new_ip_hdr->ip_hl));
#ifdef __FAVOR_BSD
	    addr.source = ntohs(this_tcphdr->th_sport);
	    addr.dest = ntohs(this_tcphdr->th_dport);
	    raddr.source = ntohs(this_tcphdr->th_dport);
	    raddr.dest = ntohs(this_tcphdr->th_sport);
#else
	    addr.source = ntohs(this_tcphdr->source);
	    addr.dest = ntohs(this_tcphdr->dest);
	    raddr.source = ntohs(this_tcphdr->dest);
	    raddr.dest = ntohs(this_tcphdr->source);
#endif
	    if (tcp_map.find(addr) != tcp_map.end()) {
//		toflows(&(tcp_map[addr]));
                print_flow_record_bin(&(tcp_map[addr]), 1);
		tcp_map.erase(addr);
//		toflows(&blah);
                print_flow_record_bin(&blah, 1);
	    }

	}
	if (new_ip_hdr->ip_p == 17) {	//udp
	    struct udphdr *this_udphdr =
		(struct udphdr *) ((eee_data + (4 * pkt->ip_hl) + 8) +
				   (4 * new_ip_hdr->ip_hl));
#ifdef __FAVOR_BSD
	    addr.source = ntohs(this_udphdr->uh_sport);
	    addr.dest = ntohs(this_udphdr->uh_dport);
	    raddr.source = ntohs(this_udphdr->uh_dport);
	    raddr.dest = ntohs(this_udphdr->uh_sport);
#else
	    addr.source = ntohs(this_udphdr->source);
	    addr.dest = ntohs(this_udphdr->dest);
	    raddr.source = ntohs(this_udphdr->dest);
	    raddr.dest = ntohs(this_udphdr->source);
#endif
	    if ((udp_it = udp_map.find(addr)) != udp_map.end()) {
//		toflows(&(udp_map[addr]));
                print_flow_record_bin(&(udp_map[addr]), 1);
		udp_map.erase(addr);
//		toflows(&blah);
                print_flow_record_bin(&blah, 1);
	    }
	}

    }
    return 1;

}

void ip_callback(struct ip *pkt)
{
    struct tuple4 addr;

//if its udp or tcp return
    if ((pkt->ip_p == 6) || (pkt->ip_p == 17)) {
	return;
    }

    if (pkt->ip_p == 1) {	//icmp
	if (icmp_handler(pkt) == 1) {
//	    cout << "removed something" << endl;
	} else {
//      cout<<"did not remove something"<<endl;
	}
	return;
    }

    if ((pkt->ip_p == 50) || (pkt->ip_p == 51))	//build up sessions for ipsec
    {
	latest_time = eee_hdr->ts.tv_sec;
	num_ipsec++;

	addr.source = 0;
	addr.dest = 0;
	addr.saddr = pkt->ip_src.s_addr;
	addr.daddr = pkt->ip_dst.s_addr;

	if (num_ipsec == num_packets_cleanup) {
	    num_ipsec = 0;
	    for (ipsec_it = ipsec_map.begin(); ipsec_it != ipsec_map.end();
		 ipsec_it++) {
		if (ipsec_it->second.esecs + IPSECTIMEOUT + 1 < latest_time) {	//this is old
//		    toflows(&(ipsec_it->second));
                    print_flow_record_bin(&(ipsec_it->second), 1);
		}
	    }
	    ipsec_it = ipsec_map.begin();

	    while (ipsec_it != ipsec_map.end()) {
		if (ipsec_it->second.esecs + IPSECTIMEOUT + 1 < latest_time) {	//this is old
		    ipsec_map.erase(ipsec_it);
		    ipsec_it = ipsec_map.begin();
		} else {
		    ipsec_it++;
		}
	    }
	}

	if ((ipsec_it = ipsec_map.find(addr)) != ipsec_map.end()) {
	    if (ipsec_it->second.esecs + IPSECTIMEOUT > eee_hdr->ts.tv_sec) {	//if its within 5 second
		ipsec_it->second.esecs = eee_hdr->ts.tv_sec;
		ipsec_it->second.eusecs = eee_hdr->ts.tv_usec;
		ipsec_it->second.cpackets += 1;
		ipsec_it->second.cbytes += ntohs(pkt->ip_len);
		ipsec_it->second.cdbytes += ntohs(pkt->ip_len) - (4 * pkt->ip_hl);
		return;
	    }
//	    toflows(&(ipsec_map[addr]));
            print_flow_record_bin(&(ipsec_map[addr]), 1);
	    ipsec_map.erase(addr);	//notice we don't return. this is because if it is a new session we need to insert it
	}
    }



    eee_record blah;
    blah.ssecs = eee_hdr->ts.tv_sec;
    blah.susecs = eee_hdr->ts.tv_usec;
    blah.esecs = eee_hdr->ts.tv_sec;
    blah.eusecs = eee_hdr->ts.tv_usec;
    blah.sip = ntohl(pkt->ip_src.s_addr);
    blah.dip = ntohl(pkt->ip_dst.s_addr);
    blah.sport = 0;
    blah.dport = 0;
    blah.ttl = pkt->ip_ttl;
    blah.protocol = pkt->ip_p;

    blah.cpackets = 1;

    blah.cbytes = ntohs(pkt->ip_len);
    blah.cdbytes = ntohs(pkt->ip_len) - (4 * pkt->ip_hl);
    blah.flags = 0;

    if ((pkt->ip_p == 50) || (pkt->ip_p == 51)) {
	ipsec_map[addr] = blah;
	return;
    }
//    toflows(&blah);
    print_flow_record_bin(&blah, 1);

    return;
}


void udp_callback(const u_char * data, struct ip *pkt)
{
    struct tuple4 addr;

    struct udphdr *this_udphdr =
	(struct udphdr *) (eee_data + 4 * pkt->ip_hl);


#ifdef __FAVOR_BSD
    addr.source = ntohs(this_udphdr->uh_sport);
    addr.dest = ntohs(this_udphdr->uh_dport);
#else
    addr.source = ntohs(this_udphdr->source);
    addr.dest = ntohs(this_udphdr->dest);
#endif
    addr.saddr = pkt->ip_src.s_addr;
    addr.daddr = pkt->ip_dst.s_addr;


    //used to know when to scan the tree for stuff to prune, and how long ago is old
    latest_time = eee_hdr->ts.tv_sec;
    num_udp++;

    if (num_udp == num_packets_cleanup) {
	num_udp = 0;
	for (udp_it = udp_map.begin(); udp_it != udp_map.end(); udp_it++) {
	    if (udp_it->second.esecs + UDPTIMEOUT < latest_time) {	//this is old
//		toflows(&(udp_it->second));
                print_flow_record_bin(&(udp_it->second), 1);
	    }
	}
	udp_it = udp_map.begin();

	while (udp_it != udp_map.end()) {
	    if (udp_it->second.esecs + UDPTIMEOUT < latest_time) {	//this is old
		udp_map.erase(udp_it);
		udp_it = udp_map.begin();
	    } else {
		udp_it++;
	    }
	}
    }


    if ((udp_it = udp_map.find(addr)) != udp_map.end()) {
	if (udp_it->second.esecs + UDPTIMEOUT + 1 > eee_hdr->ts.tv_sec) {	//if its within 5 second
	    udp_it->second.esecs = eee_hdr->ts.tv_sec;
	    udp_it->second.eusecs = eee_hdr->ts.tv_usec;
	    udp_it->second.cpackets += 1;
	    udp_it->second.cbytes += ntohs(pkt->ip_len);
	    udp_it->second.cdbytes += ntohs(pkt->ip_len) - (4 * pkt->ip_hl);
	    return;
	}
//	toflows(&(udp_map[addr]));
        print_flow_record_bin(&(udp_map[addr]), 1);
	udp_map.erase(addr);	//notice we don't return. this is because if it is a new session we need to insert it
    }

    eee_record blah;
    blah.ssecs = eee_hdr->ts.tv_sec;
    blah.susecs = eee_hdr->ts.tv_usec;
    blah.esecs = eee_hdr->ts.tv_sec;
    blah.eusecs = eee_hdr->ts.tv_usec;
    blah.sip = ntohl(pkt->ip_src.s_addr);
    blah.dip = ntohl(pkt->ip_dst.s_addr);
    blah.sport = addr.source;
    blah.dport = addr.dest;
    blah.ttl = pkt->ip_ttl;
    blah.protocol = pkt->ip_p;

    blah.cpackets = 1;

    blah.cbytes = ntohs(pkt->ip_len);
    blah.cdbytes = ntohs(pkt->ip_len) - (4 * pkt->ip_hl);
    blah.flags = 0;

    udp_map[addr] = blah;

    return;
}


void write_open_flows() {

        for (tcp_temp_it = tcp_map.begin(); tcp_temp_it != tcp_map.end(); tcp_temp_it++) {
            if (tcp_temp_it->second.esecs + TCPTIMEOUT + 1 < latest_time) {     //this is old
                print_flow_record_bin(&(tcp_temp_it->second), 1);
            } else {
		print_flow_record_bin(&(tcp_temp_it->second), 0);
	    }
        }
        tcp_temp_it = tcp_map.begin();

        while (tcp_temp_it != tcp_map.end()) {
            if (tcp_temp_it->second.esecs + TCPTIMEOUT + 1 < latest_time) {     //this is old
                tcp_map.erase(tcp_temp_it);
                tcp_temp_it = tcp_map.begin();
            } else {
                tcp_temp_it++;
            }
        }
	
        for (ipsec_it = ipsec_map.begin(); ipsec_it != ipsec_map.end(); ipsec_it++) {
            if (ipsec_it->second.esecs + IPSECTIMEOUT + 1 < latest_time) {  //this is old
               print_flow_record_bin(&(ipsec_it->second), 1);
            } else {
	       print_flow_record_bin(&(ipsec_it->second), 0);
	    }
        }
        ipsec_it = ipsec_map.begin();

        while (ipsec_it != ipsec_map.end()) {
            if (ipsec_it->second.esecs + IPSECTIMEOUT + 1 < latest_time) {  //this is old
                ipsec_map.erase(ipsec_it);
                ipsec_it = ipsec_map.begin();
            } else {
                ipsec_it++;
            }
        }


        for (udp_it = udp_map.begin(); udp_it != udp_map.end(); udp_it++) {
            if (udp_it->second.esecs + UDPTIMEOUT < latest_time) {      //this is old
                print_flow_record_bin(&(udp_it->second), 1);
            } else {
                print_flow_record_bin(&(udp_it->second), 0);
            }
        }
        udp_it = udp_map.begin();

        while (udp_it != udp_map.end()) {
            if (udp_it->second.esecs + UDPTIMEOUT < latest_time) {      //this is old
                udp_map.erase(udp_it);
                udp_it = udp_map.begin();
            } else {
                udp_it++;
            }
        }


}


