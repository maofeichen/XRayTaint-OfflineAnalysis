#include "xt_flag.h"
#include "xt_util.h"

using namespace std;

namespace util
{
bool equal_mark(const std::string &flag, const std::string &mark)
{
  if (!flag.empty() && !mark.empty()) {
    if (flag.compare(mark) == 0) {
      return true;
    }
  }
  return false;
}

bool is_mark(const std::string &flag)
{
  if (equal_mark(flag, flag::XT_INSN_ADDR)
      || equal_mark(flag, flag::XT_CALL_INSN)
      || equal_mark(flag, flag::XT_CALL_INSN_SEC)
      || equal_mark(flag, flag::XT_CALL_INSN_FF2)
      || equal_mark(flag, flag::XT_CALL_INSN_FF2_SEC)
      || equal_mark(flag, flag::XT_RET_INSN)
      || equal_mark(flag, flag::XT_RET_INSN_SEC)) {
    return true;
  }
  else {
    return false;
  }
}

bool is_pair_func(const Node& call, const Node& ret)
{
  // for call and ret mark, second field is esp value
  string esp_c = call.get_addr();
  string esp_r = ret.get_addr();
  if(esp_c.compare(esp_r) == 0) { return true; }
  else { return false; }
}

std::vector<std::string> split(const char *s, const char c)
{
  vector<string> v;

  do {
    const char *b = s;
    while (*s != c && *s)
      s++;

    v.push_back(string(b, s));
  }
  while (*s++ != 0);

  return v;
}
}
