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
# 	The Regents of the University of Minnesota. All rights reserved.
*/

#ifndef MINDS_IO
#define MINDS_IO

#include <fstream>
#include <iostream>
#include <vector>
#include "flows.h"
#include "mm_record.h"

std::string flags2string(unsigned char flags);
int io(char *filename, std::vector<mm_record> &mmr_data,std::vector<flow_record> &flow_data);
void ip2str(unsigned long ip, unsigned char mask, char *buf);
void print_time(unsigned long seconds, unsigned long milliseconds, std::ostream &out);
void print_duration(unsigned long ss, unsigned long es, std::ostream &out);
void print_mmr_record(mm_record *m, std::ostream &out);
void print_anomaly_scores(std::pair<float, mm_record* >&score, std::ostream &out);
void print_contributions(std::vector<float> &contrib, std::ostream &out);
void save_train(std::vector<std::pair<mm_record*,flow_record*> > &fr, std::ostream &out);
bool load_train(char *train_filename, std::vector<mm_record> &mmr_train_data,std::vector<flow_record> &flow_train_data);
void log_error(char *message, std::ostream &out);
#endif
