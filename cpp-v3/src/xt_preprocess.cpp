#include "xt_flag.h"
#include "xt_util.h"
#include "xt_preprocess.h"

#include <cassert>
#include <iostream>

using namespace std;

PreProcess::PreProcess() {}

vector<string> PreProcess::clean_unuse_insn_mark(vector<string> &v_s_log) {
  cout << "cleaning unuse insn mark..." << endl;
  vector<string> v;

  for(auto it = v_s_log.begin(); it != v_s_log.end() - 1; ++it) {
    auto  it_next = it + 1;
    string flag = it->substr(0,2);
    string flag_next = it_next->substr(0,2);

    if(XT_Util::equal_mark(flag, xt_flag::XT_INSN_ADDR) &&
        XT_Util::equal_mark(flag_next, xt_flag::XT_INSN_ADDR) ) {
      continue;
    }

    v.push_back(*it);
  }

  return v;
}

vector<string> PreProcess::clean_empty_func_mark(vector<string> &v_s_log) {
  cout << "cleaning empty funcion mark..." << endl;
  vector<string> v;

  for(auto it = v_s_log.begin(); it != v_s_log.end(); ++it) {
    string flag = it->substr(0,2);
    if(XT_Util::equal_mark(flag, xt_flag::XT_RET_INSN_SEC) ) {
      string ret = v.back();

      if(v.size() < 3) {
        continue;
      }

      // if empty function mark, then last third record should be call mark
      string call = v[v.size() - 3];
      string call_flag = call.substr(0,2);
      if(XT_Util::equal_mark(call_flag, xt_flag::XT_CALL_INSN) ||
          XT_Util::equal_mark(call_flag, xt_flag::XT_CALL_INSN_FF2) ) {

        // if call and ret esp values are same
        vector<string> v_call = XT_Util::split(call.c_str(), '\t');
        vector<string> v_ret  = XT_Util::split(ret.c_str(), '\t');

        assert(v_call.size() == v_ret.size() );
        string c_esp = v_call[1];
        string r_esp = v_ret[1];

        if(c_esp.compare(r_esp) == 0) {
          // del empty function marks and skip push the last empty function mark
          v.erase(v.end()-3, v.end() );
          continue;
        }
      }
    }
    v.push_back(*it);
  }
  return  v;
}

vector<string> PreProcess::clean_invalid_func_mark(vector<string> &v_s_log) {
  cout << "cleaning invalid funcion mark..." << endl;
  vector<string> v;

  return v;
}
