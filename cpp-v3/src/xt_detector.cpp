#include "xt_file.h"
#include "xt_detector.h"
#include "xt_log.h"
#include "xt_preprocess.h"

#include <iostream>

using namespace std;

Detector::Detector(string fn, bool dump) {
  fn_   = fn;
  dump_ = dump;
}

void Detector::detect() {
  string curr_time = get_time();
  curr_time        = '-' + curr_time;

  xt_file::File file(fn_);
  vector<string> v_s_log = file.read();
  cout << "init log entries: " << v_s_log.size() << endl;

  PreProcess pre_pro;
  v_s_log = pre_pro.clean_unuse_insn_mark(v_s_log);
  cout << "log entries after cleaning insn mark: " << v_s_log.size() << endl;

  v_s_log = pre_pro.clean_empty_func_mark(v_s_log);
  cout << "log entries after cleaning empty function mark: " << v_s_log.size()
       << endl;

  v_s_log = pre_pro.clean_invalid_func_mark(v_s_log);
  cout << "log entries after cleaning invalid function mark: " << v_s_log.size()
       << endl;

  if(dump_) {
    string path = xt_file::res_path + fn_ + xt_file::preprocess + curr_time +
        xt_file::ext;
    file.write_str_log(path, v_s_log);
  }

  Log log(v_s_log);
  // log.print_log();
  log.analyze_mem_record();
}

string Detector::get_time() {
  time_t t = time(0);   // get time now
  struct tm * now = localtime( & t );

  string c_time = to_string( (now->tm_year + 1900) ) + '-' +
      to_string( (now->tm_mon + 1) ) + '-' +
      to_string(  now->tm_mday) + '-' +
      to_string(  now->tm_hour) + '-' +
      to_string(  now->tm_min);
  return c_time;
}