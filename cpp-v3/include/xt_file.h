#ifndef XT_FILE_H
#define XT_FILE_H

#include "xt_alivefunc.h"
#include "xt_log.h"
#include <string>
#include <vector>

namespace xt_file {
  const std::string ext       = ".txt";
  const std::string log_path  =
      "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/test_file/";
  const std::string res_path  =
      "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/test_result/";

  const std::string preprocess    = "-preprcss";
  const std::string add_mem_sz    = "-add_mem_sz";
  const std::string add_index     = "-add_index";
  const std::string alive_buf     = "-alive_buf";
  const std::string continue_buf  = "-continue_buf";

  class File;
}

class xt_file::File{
 public:
  File(std::string fn);
  void read(std::vector<std::string> &s_log);

  void write_str_log(const std::string path,
                     const std::vector<std::string> &v_s_log);
  void write_log_mem(const std::string path,
                     const Log &log);
  void write_log_idx(const std::string path,
                     const Log &log);
  void write_alive_func(const std::string& curr_t,
                        const std::vector< std::vector<Record> >& alive_func) const;
  void write_cont_buf(const std::string& curr_t,
                      const std::vector<AliveFunction>& v_liveness_res);

 private:
  std::string fn_;
};

#endif //XT_FILE_H
