#ifndef XT_PREPROCESS_H
#define XT_PREPROCESS_H

#include <string>
#include <vector>

namespace preprcss
{

std::vector<std::string> preprocess(std::vector<std::string> &s_log);
std::vector<std::string> clean_unuse_insn_mark(std::vector<std::string> &v_s_log);
std::vector<std::string> clean_empty_func_mark(std::vector<std::string> &v_s_log);
std::vector<std::string> clean_invalid_func_mark(std::vector<std::string> &v_s_log);

}

#endif //XT_PREPROCESS_H
