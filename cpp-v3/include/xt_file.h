#ifndef XT_FILE_H
#define XT_FILE_H

#include <string>
#include <vector>

namespace xt_file {
  const std::string ext       = ".txt";
  const std::string log_path  =
      "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/test_file/";
  const std::string res_path  =
      "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/test_result/";

  const std::string preprocess    = "-preprocess";
  const std::string add_mem_sz    = "-add_mem_sz";
  const std::string add_index     = "-add_index";
  const std::string alive_buf     = "-alive_buf";
  const std::string continue_buf  = "-continue_buf";

  class File;
}

class xt_file::File{
 public:
  File(std::string fn);
  std::vector<std::string> read();
  void read(std::vector<std::string>& v_s_log);

  void write_str_log(std::string path, std::vector<std::string> &v_s_log);
 private:
  std::string fn_;
};

#endif //XT_FILE_H
