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
  #
# Copyright (c) 2018
  #      The Regents of the University of Minnesota.  All rights reserved.
*/

#include <vector>
#include <queue>
#include <algorithm>
#include <cmath>
#include "limits.h"
#include "flows.h"
#include "io.h"
#include "anomaly_detector.h"
#include "mm_record.h"

#include <pthread.h>

#include <ctime>
#include <iostream>
using namespace std;

#ifndef FLT_MAX
#define FLT_MAX 3.40282346E+38F
#endif

#ifndef EPS
#define EPS 1E-10
#endif


inline float max(float a, float b){return a>b ? a : b;}

extern unsigned int num_threads;
extern int max_top;
extern vector<pair<mm_record*,flow_record*> > train;
extern vector<pair<mm_record*,flow_record*> > test;
extern vector< pair<float, mm_record*> > score;
extern vector< vector<float> > contrib;
unsigned int nearest_neighbors;

vector<float> my_num_weights;
vector<float> my_cat_weights;

vector< pair<float, int> > ordering;
vector<float> lrd_test;
vector<float> lof_test;
vector<float> lrd;
vector< vector< pair<float,int> > > d;

bool compare_lrd(const pair<float, int> &a, const pair<float, int> &b){
  return a.first > b.first;
}

// used as the comparison funtion in the priority queue
class compare_lof{
public: 
  bool operator() (std::pair<float,int> a, std::pair<float,int> b) {
    return a.first < b.first;
  }
};

//used for keeping the top X anomaly scores
class compare_Q{
public:
  bool operator() (float a, float b) {
    return a > b;
  }
};
priority_queue<float, vector<float>, compare_Q> top_scores;

typedef struct thread_stuff {
  unsigned int thread_id;
  unsigned int offset;
  unsigned int worksize;
} thread_stuff_t;

float dist_categorical(pair<mm_record*,flow_record*> &a, pair<mm_record*,flow_record*> &b, std::vector<float> &cat_weights){
  float sum = 0;
  if((a.first)->src_ip != (b.first)->src_ip)        
    sum+= cat_weights[0]*((a.second)->srcip_idf * (b.second)->srcip_idf);
  if((a.first)->dst_ip != (b.first)->dst_ip)        
    sum+= cat_weights[1]*((a.second)->dstip_idf * (b.second)->dstip_idf);
  if((a.first)->src_port != (b.first)->src_port)  sum+= cat_weights[2]*((a.second)->src_port_idf * (b.second)->src_port_idf);
  if((a.first)->dst_port != (b.first)->dst_port)  sum+= cat_weights[3]*((a.second)->dst_port_idf * (b.second)->dst_port_idf);
  if((a.first)->protocol!= (b.first)->protocol)   sum+= cat_weights[4]*((a.second)->protocol_idf * (b.second)->protocol_idf);
  return sum;
}

float dist_euclidean(pair<mm_record*,flow_record*> &a, pair<mm_record*,flow_record*> &b, std::vector<float> &num_weights){
  float sum = 0.0;
  sum += num_weights[0]*(((a.second)->duration - (b.second)->duration) * ((a.second)->duration - (b.second)->duration));
  if(((a.first)->cpackets > 0) && ((b.first)->cpackets > 0)){
    sum += (num_weights[1]*(float((a.first)->cbytes)*(a.second)->i_cpackets - float((b.first)->cbytes)*(b.second)->i_cpackets)) * (float((a.first)->cbytes)*(a.second)->i_cpackets - float((b.first)->cbytes)*(b.second)->i_cpackets);
    sum += (num_weights[2]*((a.first)->cpackets - (b.first)->cpackets) * ((a.first)->cpackets - (b.first)->cpackets));
  }
  if(((a.first)->spackets > 0) && ((b.first)->spackets > 0)){
    sum +=  (num_weights[3]*(float((a.first)->sbytes)*(a.second)->i_spackets - float((b.first)->sbytes)*(b.second)->i_spackets)) * (float((a.first)->sbytes)*(a.second)->i_spackets - float((b.first)->sbytes)*(b.second)->i_spackets);
    sum += (num_weights[4]*((a.first)->spackets - (b.first)->spackets) * ((a.first)->spackets - (b.first)->spackets));
  }
  sum +=  (num_weights[5]*((a.second)->unique_inside_dst_count-(b.second)->unique_inside_dst_count) * ((a.second)->unique_inside_dst_count-(b.second)->unique_inside_dst_count));
  sum +=  (num_weights[6]*((a.second)->unique_inside_dst_rate-(b.second)->unique_inside_dst_rate) * ((a.second)->unique_inside_dst_rate-(b.second)->unique_inside_dst_rate));
  sum +=  (num_weights[7]*((a.second)->same_dst_port_count-(b.second)->same_dst_port_count) * ((a.second)->same_dst_port_count-(b.second)->same_dst_port_count));
  sum +=  (num_weights[8]*((a.second)->same_dst_port_rate-(b.second)->same_dst_port_rate) * ((a.second)->same_dst_port_rate-(b.second)->same_dst_port_rate));
  sum +=  (num_weights[9]*((a.second)->unique_inside_src_count-(b.second)->unique_inside_src_count) * ((a.second)->unique_inside_src_count-(b.second)->unique_inside_src_count));
  sum +=  (num_weights[10]*((a.second)->unique_inside_src_rate-(b.second)->unique_inside_src_rate) * ((a.second)->unique_inside_src_rate-(b.second)->unique_inside_src_rate));
  sum +=  (num_weights[11]*((a.second)->same_src_port_count-(b.second)->same_src_port_count) * ((a.second)->same_src_port_count-(b.second)->same_src_port_count));
  sum +=  (num_weights[12]*((a.second)->same_src_port_rate-(b.second)->same_src_port_rate) * ((a.second)->same_src_port_rate-(b.second)->same_src_port_rate));
  return sum;
}

void print_record(pair<mm_record*,flow_record*> &a){
  cerr<<(a.second)->duration<<" "<<(a.first)->cbytes<<" "<<(a.second)->i_cpackets<<" "<<(a.first)->cpackets<<" "<<(a.first)->sbytes<<" "<<(a.second)->i_spackets<<" "<<(a.first)->spackets<<"\n";
}

void calculate_contrib(std::pair<mm_record*,flow_record*> a, std::pair<mm_record*,flow_record*>b, int i,
                       std::vector< std::vector<float> > &contrib,
                       std::vector<float> &num_weights, 
                       std::vector<float> &cat_weights){
  contrib[i][0] += cat_weights[0]*((a.second)->srcip_idf * (b.second)->srcip_idf);
  contrib[i][1] += cat_weights[1]*((a.second)->dstip_idf * (b.second)->dstip_idf);
  contrib[i][2] += cat_weights[2]*((a.second)->src_port_idf * (b.second)->src_port_idf);
  contrib[i][3] += cat_weights[3]*((a.second)->dst_port_idf * (b.second)->dst_port_idf);
  contrib[i][4] += cat_weights[4]*((a.second)->protocol_idf * (b.second)->protocol_idf);

   contrib[i][5] += num_weights[0]*((a.second)->duration-(b.second)->duration)*((a.second)->duration-(b.second)->duration);
   contrib[i][6] += num_weights[1]*((float)(a.first)->cbytes*(a.second)->i_cpackets-(float)(b.first)->cbytes*(b.second)->i_cpackets)
     * ((float)(a.first)->cbytes*(a.second)->i_cpackets-(float)(b.first)->cbytes*(b.second)->i_cpackets);
   contrib[i][7] += num_weights[2]*((a.first)->cpackets-(b.first)->cpackets) * ((a.first)->cpackets-(b.first)->cpackets);
   contrib[i][8] += num_weights[3]*((float)(a.first)->sbytes*(a.second)->i_spackets-(float)(b.first)->sbytes*(b.second)->i_spackets)
     * ((float)(a.first)->sbytes*(a.second)->i_spackets-(float)(b.first)->sbytes*(b.second)->i_spackets);
   contrib[i][9] += num_weights[4]*((a.first)->spackets-(b.first)->spackets) * ((a.first)->spackets-(b.first)->spackets);
   contrib[i][10] += num_weights[5]*((a.second)->unique_inside_dst_count-(b.second)->unique_inside_dst_count)
     *((a.second)->unique_inside_dst_count-(b.second)->unique_inside_dst_count);
   contrib[i][11] += num_weights[6]*((a.second)->unique_inside_dst_rate-(b.second)->unique_inside_dst_rate)
     *((a.second)->unique_inside_dst_rate-(b.second)->unique_inside_dst_rate);
   contrib[i][12] += num_weights[7]*((a.second)->same_dst_port_count-(b.second)->same_dst_port_count)
     *((a.second)->same_dst_port_count-(b.second)->same_dst_port_count);
   contrib[i][13] += num_weights[8]*((a.second)->same_dst_port_rate-(b.second)->same_dst_port_rate)
     *((a.second)->same_dst_port_rate-(b.second)->same_dst_port_rate);
   contrib[i][14] += num_weights[9]*((a.second)->unique_inside_src_count-(b.second)->unique_inside_src_count)
     *((a.second)->unique_inside_src_count-(b.second)->unique_inside_src_count);
   contrib[i][15] += num_weights[10]*((a.second)->unique_inside_src_rate-(b.second)->unique_inside_src_rate)
     *((a.second)->unique_inside_src_rate-(b.second)->unique_inside_src_rate);
   contrib[i][16] += num_weights[11]*((a.second)->same_src_port_count-(b.second)->same_src_port_count)
     *((a.second)->same_src_port_count-(b.second)->same_src_port_count);
   contrib[i][17] += num_weights[12]*((a.second)->same_src_port_rate-(b.second)->same_src_port_rate)
     *((a.second)->same_src_port_rate-(b.second)->same_src_port_rate);
}

// LOF: Local Outlier Factor
// the method is modified to train on a training set and be applied on a test set
void lof(std::vector<pair<mm_record*,flow_record*> > &train,
         std::vector<pair<mm_record*,flow_record*> > &test,
         std::vector< std::pair<float, mm_record*> > &score,
         unsigned int k,
         std::vector<float> &num_weights,  
         std::vector<float> &cat_weights,
         std::vector< std::vector<float> > &contrib,
	 int max_top){

  using namespace std;
  unsigned int i, j, n, m;
  float sum;
  clock_t start, finish;
  float duration;
  nearest_neighbors = k;
  //////////////// calculate distance matrix for training set ////////////////
  vector< priority_queue< pair<float, int> , vector< pair<float, int> > , compare_lof> > Q(train.size());
  pair<float,int> temp(FLT_MAX,-1);
  
  // initialize Q to have k elements inside
  for(i=0; i<train.size(); ++i){
    for(j=0; j<k; ++j) Q[i].push(temp);
  }

  start = clock();
  for(i=0; i<train.size(); ++i){
    for(j=i+1; j<train.size(); ++j){
      float sum1 = dist_euclidean(train[i],train[j],num_weights);
      float sum2 = dist_categorical(train[i],train[j],cat_weights);
      sum = dist_euclidean  (train[i], train[j], num_weights) +
	dist_categorical(train[i], train[j], cat_weights);
      
      temp = pair<float,int> (sum, j);
      Q[i].push(temp);
      Q[i].pop();
      // extend the neighborhood size (k), if the distance to k-th element is 0
      // or equal to the distance to k+1-st element
      if((Q[i].top().first == 0) || (Q[i].top().first == temp.first)) Q[i].push(temp);
      temp = pair<float,int> (sum, i);
      Q[j].push(temp);
      Q[j].pop();
      if((Q[j].top().first == 0) || (Q[j].top().first == temp.first)) Q[j].push(temp);
    }
  }

  // store the distances
  d.resize(train.size());
  for(i=0; i<train.size(); ++i){
    n = Q[i].size();
    vector< pair<float,int> > temp2(n, pair<float,int>());
    // reverse the order of elements in the queue and put them in a vector
    for(j=0; j<n; ++j){
      temp2[n-1-j] = Q[i].top();
      Q[i].pop();
    }
            
    // remove the extra elements that might have been inserted
    for(j=k; j<n; ++j){
      if(temp2[j].first == 0) continue;
      if(temp2[j].first != temp2[j+1].first){
	temp2.resize(j+1);
	break;
      }
    }
    d[i] = temp2;
  }
  Q.clear();
  finish = clock();
  duration = (double)(finish - start) / CLOCKS_PER_SEC;

  // calculate local reachability distance for training set 
  lrd.resize(train.size(),0);
    
  for(i=0; i<train.size(); ++i){
    n = d[i].size();
    for(j=0; j<n; ++j) {
      m = d[d[i][j].second].size();
      lrd[i] += max(d[d[i][j].second][m-1].first, d[i][j].first);
    }
    if(lrd[i] > 0) lrd[i] = float(n)/lrd[i];
    else {
      lrd[i]=FLT_MAX; 
    }
  }
  cerr <<   "lrd calculated" << endl;


  ///////////// optimizations
  ordering.resize(train.size());
  for(i=0; i<train.size(); ++i) ordering[i] = pair<float, int>(lrd[i], i);
  sort(ordering.begin(), ordering.end(), compare_lrd);
  //////////////// calculate distance matrix for test set ////////////////
  lrd_test.resize(test.size(), 0);
  lof_test.resize(test.size(),0);

  my_num_weights.clear();
  my_num_weights=num_weights;
  my_cat_weights.clear();
  my_cat_weights=cat_weights;
  //clear out the top scores queue
  while(!top_scores.empty()) {
    top_scores.pop();
  }

  //fill the queue back up with 1.0
  for(int i=0;i<max_top;++i){
    top_scores.push(1.0);
  }

  vector<pthread_t> threads(num_threads);
  vector<thread_stuff_t> tsv(num_threads);
  //    vector<pthread_attr_t> pat(num_threads);
  unsigned int worksize=test.size()/num_threads;
  for(unsigned int i=0;i<threads.size();++i){
    tsv[i].thread_id=i;
    tsv[i].offset=i*worksize;
    tsv[i].worksize=worksize;
    if(i==threads.size()-1){ //last thread, it better go to the end
      tsv[i].worksize=test.size()-i*worksize;
    }
    pthread_create(&(threads[i]), NULL, thread_function_lof, (void *) &(tsv[i]));
  }
  for(unsigned int i=0;i<threads.size();++i){
    pthread_join(threads[i], NULL);
  }
}       


void *thread_function_lof( void *arg){

  thread_stuff_t *ts=(thread_stuff_t *)(arg);

  pair<float,int> temp(FLT_MAX,-1);
  unsigned int i, j, n, m, k; 
  unsigned long int num_ops1 = 0;
  unsigned long int num_ops2 = 0;
  float sum;
  k=nearest_neighbors;
  clock_t start, current;

  vector<pair<mm_record*,flow_record*> > my_train=train;
  vector<mm_record> my_actual_mmr_train(my_train.size());
  vector<flow_record> my_actual_flow_train(my_train.size());

  //make a local copy of the training data
  for(unsigned int i=0;i<my_train.size();++i){
    my_actual_mmr_train[i]=*(my_train[i].first);
    my_actual_flow_train[i]=*(my_train[i].second);
    my_train[i].first=&(my_actual_mmr_train[i]);
    my_train[i].second=&(my_actual_flow_train[i]);
  }
  cerr<<"Keeping top "<<top_scores.size()<<" scores"<<endl;
  cerr<<"thread "<< ts->thread_id<< " k is "<<k<<" offset is "<< ts->offset<<" worksize is "<<ts->worksize<<endl;

  start = clock();
  unsigned int ct=0;
  for(i=ts->offset ; ct < ts->worksize && i < test.size();++i){
    ct++;
    if(i>10 && (i%(test.size()/10)==0)){
      current = clock();
      cerr << i/(test.size()/10)*10 << "% done... ETA: " << int(double(current-start)/CLOCKS_PER_SEC * double((test.size()-i))/double(i)) << " seconds threshold is " << top_scores.top() << endl;
    }
    bool check = 0;
    priority_queue< pair<float,int> , vector< pair<float,int> > , compare_lof> Q2;
    temp = pair<float,int>(FLT_MAX,-1);
    for(j=0; j<k; ++j) Q2.push(temp);
    for(j=0; j<my_train.size(); ++j){
      sum = dist_euclidean  (test[i], my_train[ordering[j].second], my_num_weights) + dist_categorical(test[i], my_train[ordering[j].second], my_cat_weights);
      temp = pair<float,int> (sum, ordering[j].second);
      Q2.push(temp);
      Q2.pop();
      if((Q2.top().first == 0) || (Q2.top().first == temp.first)) Q2.push(temp);

      if(j%30 == 29 && j>=k){
	int jj;
	int nn = Q2.size();
	vector< pair<float, int> > d2(nn, pair<float,int>());
	for(jj=0; jj<nn; ++jj) {
	  d2[nn-1-jj] = Q2.top();
	  Q2.pop();
	}
	for(jj=k; jj<nn; ++jj){
	  if(d2[jj].first == 0) continue;
	  if(d2[jj].first != d2[jj+1].first){
	    d2.resize(jj+1);
	    break;
	  }
	}
	nn = d2.size();
	lrd_test[i] = 0;
	for(jj=0; jj<nn; ++jj){
	  m = d[d2[jj].second].size();
	  lrd_test[i] += max(d[d2[jj].second][m-1].first, d2[jj].first);
	}
	if(lrd_test[i] != 0) { lrd_test[i] = float(nn)/lrd_test[i]; }
	else {lrd_test[i]=FLT_MAX; cerr << "error in approximation\n";}
	// calculate the outlier scores
	lof_test[i] = 0;
	for(jj=0; jj<nn; ++jj) lof_test[i] += lrd[d2[jj].second];
	lof_test[i] /= (lrd_test[i]*nn);
	if(lof_test[i] < top_scores.top()){
	  score[i] = pair<float, mm_record*>(lof_test[i], test[i].first);
	  num_ops1 += j + 1;
	  ++num_ops2;
	  check = 1;
	  while(!Q2.empty()) Q2.pop();
	  break;
	}else{
	  score[i] = pair<float, mm_record*>(0.00, test[i].first);
	}
	for(jj=0; jj<nn; ++jj) Q2.push(d2[jj]);
      }
    }
    if(check) continue;
    n = Q2.size();
    vector< pair<float, int> > d2(n, pair<float,int>());

    for(j=0; j<n; ++j) {
      d2[n-1-j] = Q2.top();
      Q2.pop(); 
    }
        
    for(j=k; j<n; ++j){
      if(d2[j].first == 0) continue;
      if(d2[j].first != d2[j+1].first){
	d2.resize(j+1);
	break;
      }
    }

    // calculate the contributions
      for(j=0; j<d2.size(); ++j)
        calculate_contrib(test[i], my_train[d2[j].second], i, contrib, my_num_weights, my_cat_weights);
    sum = 0;
    for(j=0; j<NUM_DIM; ++j) sum += contrib[i][j] * contrib[i][j];
    //divisions bad!
    sum = 1.0/sqrt(sum);
    for(j=0; j<NUM_DIM; ++j) contrib[i][j] *= sum;
    // calculate lrd for test set
    n = d2.size();
    for(j=0; j<n; ++j){
      m = d[d2[j].second].size();
      lrd_test[i] += max(d[d2[j].second][m-1].first, d2[j].first);
    }
    if(lrd_test[i] != 0) lrd_test[i] = float(n)/lrd_test[i];
    else {lrd_test[i]=FLT_MAX;}

    // calculate the outlier scores
    lof_test[i] = 0;
    for(j=0; j<n; ++j) lof_test[i] += lrd[d2[j].second];
    lof_test[i] /= (lrd_test[i]*n);
    //used for optimization
    top_scores.push(lof_test[i]);
    top_scores.pop();
    score[i] = pair<float, mm_record*>(lof_test[i], test[i].first);
    (test[i].first)->lof_anomaly_score = lof_test[i];
  }       
  cerr << "average number of comparisons : " << float(num_ops1)/ts->worksize << endl;
  cerr << "number of points for which comparisons are stopped early : " << num_ops2 << endl;
  cerr << "Lower threshold was finally "<<top_scores.top()<<endl;
  cerr << "Thread "<< ts->thread_id << " is returning"<<endl;
  return 0;
}       
