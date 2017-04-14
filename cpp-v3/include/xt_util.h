#ifndef XT_UTIL_H
#define XT_UTIL_H

#include <vector>
#include <string>

namespace util
{
bool equal_mark(const std::string &flag, const std::string &mark);
bool is_mark(const std::string &flag);
std::vector<std::string> split(const char *s, const char c);
}

#endif //XT_UTIL_H
