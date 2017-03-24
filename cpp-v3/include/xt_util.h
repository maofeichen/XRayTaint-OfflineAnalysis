#ifndef XT_UTIL_H
#define XT_UTIL_H

#include <vector>
#include <string>

class XT_Util{
 public:
  static bool equal_mark(std::string flag, std::string mark);
  static bool is_mark(std::string flag);
  static std::vector<std::string> split(const char *s, char c);
};

#endif //XT_UTIL_H
