#include "xt_alivefunc.h"
#include "xt_avalanche.h"
#include "xt_file.h"
#include "xt_detector.h"
#include "xt_log.h"
#include "xt_liveness.h"
#include "xt_preprocess.h"
#include "xt_propagate.h"

#include <iostream>

using namespace std;

Detector::Detector(string fn, bool dump) {
  fn_   = fn;
  dump_ = dump;
}

void Detector::detect() {
  string curr_time = get_time();
  curr_time        = '-' + curr_time;

  vector<string> s_log;
  xt_file::File file(fn_);
  file.read(s_log);
  cout << "init log entries: " << s_log.size() << endl;

  s_log = preprcss::preprocess(s_log);
  if(dump_) {
    string path = xt_file::res_path \
                  + fn_ + xt_file::preprocess \
                  + curr_time + xt_file::ext;
    file.write_str_log(path, s_log);
  }

  Log log(s_log);
  // log.print_log();
  if(dump_) {
    string m_path = xt_file::res_path \
                  + fn_ + xt_file::add_mem_sz \
                  + curr_time + xt_file::ext;
    file.write_log_mem(m_path, log);

    string i_path = xt_file::res_path \
                + fn_ + xt_file::add_index \
                + curr_time + xt_file::ext;
    file.write_log_idx(i_path, log);
  }

  vector<AliveFunction> v_liveness;
  vector< vector<Record> > r_alive_func;

  Liveness live;
  live.analyze_liveness(log, r_alive_func, v_liveness);
  if(dump_) {
    file.write_alive_func(curr_time, r_alive_func);
    file.write_cont_buf(curr_time, v_liveness);
    // propagate alive buffer?
  }

  Propagate prpgt(log);
  Avalanche aval(log, prpgt);
  aval.detect(v_liveness);
}

string Detector::get_time() {
  time_t t = time(0);   // get time now
  struct tm * now = localtime( & t );

  string c_time = to_string( (now->tm_year + 1900) ) + '-'
                  + to_string( (now->tm_mon + 1) ) + '-'
                  + to_string(  now->tm_mday) + '-'
                  + to_string(  now->tm_hour) + '-'
                  + to_string(  now->tm_min);
  return c_time;
}
