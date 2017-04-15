#include "xt_flag.h"
#include "xt_util.h"
#include "xt_preprocess.h"

#include <cassert>
#include <iostream>

using namespace std;

namespace preprcss
{
vector<string> preprocess(vector<string> &s_log)
{
  vector<string> v;
  v = clean_unuse_insn_mark(s_log);
  cout << "log entries after cleaning insn mark: " << v.size() << endl;

  v = clean_empty_func_mark(v);
  cout << "log entries after cleaning empty function mark: " << v.size()
       << endl;

  v = clean_invalid_func_mark(v);
  cout << "log entries after cleaning invalid function mark: " << v.size()
       << endl;

//  for(auto it = s_log.begin(); it != v.end(); ++it) {
//    cout << "rec: " << *it << endl;
//  }

  return v;
}

vector<string> clean_unuse_insn_mark(vector<string> &v_s_log) {
  cout << "cleaning unuse insn mark..." << endl;
  vector<string> v;

  for(auto it = v_s_log.begin(); it != v_s_log.end() - 1; ++it) {
    auto  it_next = it + 1;
    string flag = it->substr(0,2);
    string flag_next = it_next->substr(0,2);

    if(util::equal_mark(flag, flag::XT_INSN_ADDR) &&
        util::equal_mark(flag_next, flag::XT_INSN_ADDR) ) {
      continue;
    }

    v.push_back(*it);
  }

  return v;
}

vector<string> clean_empty_func_mark(std::vector<std::string> &v_s_log) {
  cout << "cleaning empty funcion mark..." << endl;
  vector<string> v;

  for(auto it = v_s_log.begin(); it != v_s_log.end(); ++it) {
    string flag = it->substr(0,2);
    if(util::equal_mark(flag, flag::XT_RET_INSN_SEC) ) {
      string ret = v.back();

      if(v.size() < 3) {
        continue;
      }

      // if empty function mark, then last third record should be call mark
      string call = v[v.size() - 3];
      string call_flag = call.substr(0,2);
      if(util::equal_mark(call_flag, flag::XT_CALL_INSN) ||
          util::equal_mark(call_flag, flag::XT_CALL_INSN_FF2) ) {

        // if call and ret esp values are same
        vector<string> v_call = util::split(call.c_str(), '\t');
        vector<string> v_ret  = util::split(ret.c_str(), '\t');

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

vector<string> clean_invalid_func_mark(std::vector<std::string> &v_s_log) {
  cout << "cleaning invalid funcion mark..." << endl;
  vector<string> v;

  vector<string> call_stack;
  vector<string>::iterator it_curr_ret;

  bool has_valid_rec = false;

  for(auto it = v_s_log.begin(); it != v_s_log.end(); ++it) {
    bool is_del = false;

    string flag = it->substr(0,2);
    bool is_mark = util::is_mark(flag);

    if(is_mark) {
      if(util::equal_mark(flag, flag::XT_CALL_INSN) ||
          util::equal_mark(flag, flag::XT_CALL_INSN_FF2) ) {

        call_stack.push_back(*it);
        has_valid_rec = false;
      } else if(util::equal_mark(flag, flag::XT_RET_INSN_SEC) &&
          !call_stack.empty() ) {
        string last_call = call_stack.back();
        it_curr_ret  = it - 1;

        vector<string> v_call = util::split(last_call.c_str(), '\t');
        vector<string> v_ret  = util::split(it_curr_ret->c_str(), '\t');

        assert(v_call.size() == v_ret.size() );
        string c_esp = v_call[1];
        string r_esp = v_ret[1];

        if(c_esp.compare(r_esp) == 0 && !has_valid_rec) {
          call_stack.pop_back();

          string last_rec = v.back();
          while (last_rec.compare(last_call) ) {
            v.pop_back();
            last_rec = v.back();
          }
          v.pop_back(); // pop the last call mark
          // cout << v.back() << endl;

          is_del = true;
        }
      }
    } else {
      has_valid_rec = true;
    }

    if(!is_del) {
      v.push_back(*it);
      // cout << v.size() << endl;
    }
  }

  return v;
}

}
