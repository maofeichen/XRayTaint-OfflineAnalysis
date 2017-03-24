#include "xt_flag.h"
#include "xt_util.h"

using namespace std;

bool XT_Util::equal_mark(std::string flag, std::string mark) {
  if(!flag.empty() && !mark.empty() ) {
    if(flag.compare(mark) == 0) {
      return true;
    }
  }
  return false;
}

bool XT_Util::is_mark(std::string flag) {
  if(equal_mark(flag, xt_flag::XT_INSN_ADDR) ||
      equal_mark(flag, xt_flag::XT_CALL_INSN) ||
      equal_mark(flag, xt_flag::XT_CALL_INSN_SEC) ||
      equal_mark(flag, xt_flag::XT_CALL_INSN_FF2) ||
      equal_mark(flag, xt_flag::XT_CALL_INSN_FF2_SEC) ||
      equal_mark(flag, xt_flag::XT_RET_INSN) ||
      equal_mark(flag, xt_flag::XT_RET_INSN_SEC) ) {
    return true;
  } else {
    return false;
  }
}

vector<string> XT_Util::split(const char *s, char c){
  vector<string> v;

  do {
    const char *b = s;
    while(*s != c && *s)
      s++;

    v.push_back(string(b, s) );
  } while (*s++ != 0);

  return v;
}
