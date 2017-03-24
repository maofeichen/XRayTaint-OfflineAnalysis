#include "xt_file.h"
#include "xt_log.h"

#include <iostream>

using namespace std;

Log::Log(vector<string> &v_s_log) {
  init_log(v_s_log);
}

void Log::print_log() {
  if(v_rec_.empty() ) {
    cout << "log is empty" << endl;
    return;
  }

  for(auto it = v_rec_.begin(); it != v_rec_.end(); ++it) {
    it->print_record();
  }
}

void Log::init_log(vector<string> &v_s_log) {
  cout << "init log..." << endl;

  if(v_s_log.empty() ) {
    cout << "init log: given vector of string log is empty..." << endl;
    return;
  }

  uint32_t index = 0;
  for(auto it = v_s_log.begin(); it != v_s_log.end(); ++it) {
    Record rec(index);
    if(rec.init_record(*it) ) {
      v_rec_.push_back(rec);
      index++;
    }
  }
}

