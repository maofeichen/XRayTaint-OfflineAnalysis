#ifndef XT_PREPROCESS_H
#define XT_PREPROCESS_H

#include "xt_data.h"
#include <vector>
#include <string>

using namespace std;

class XT_PreProcess {
 public:
  XT_PreProcess();

  std::vector<string> clean_size_mark(vector<string> &);

  std::vector<std::string> clean_function_call_mark(std::vector<std::string>
                                                    &v_s_log);

  std::vector<std::string> clean_empty_instruction_mark(std::vector<std::string> &s_vXTLog);

  std::vector<Record> convertToRec(std::vector<std::string> &log);
  std::vector<string> parseMemSizeInfo(std::vector<std::string> &v);
  std::vector<string> addRecordIndex(std::vector<std::string> &s_vXTLog);
 private:
  inline bool is_invalid_record(string &);
  inline bool isValidRecord(string &s);
  inline RegularRecord initMarkRecord(std::vector<std::string> &singleRec);
  inline RegularRecord initRegularRecord(std::vector<std::string> &singleRec);
  inline std::string getBufSize(int iRecFlag, int &TCGEncode);
  inline std::string addBufSize(std::string &s,
                                std::string size,
                                int TCGEncode);

  std::vector<std::string> clean_nonempyt_func_mark_fast(
      std::vector<std::string> &v_s_log);
  std::vector<string> clean_empty_function_mark(vector<string> &);
  std::vector<string> clean_nonempty_function_mark(vector<string> &);
};
#endif
