#ifndef XT_LIVENESS
#define XT_LIVENESS

#include <string>
#include <vector>

#include "xt_data.h"
#include "xt_log.h"
#include "xt_functioncall.h"

using namespace std;

class XT_Liveness {
 public:
  XT_Liveness();
  XT_Liveness(std::vector<std::string> &s_vAliveBuffer);

  static std::vector<std::string> analyze_alive_buffer(std::vector<std::string> &xtLog);
  static std::vector<t_AliveFunctionCall> merge_continue_buffer(std::vector<std::string> &);
  static std::vector<t_AliveFunctionCall> filter_continue_buffer(std::vector<
      t_AliveFunctionCall> &);
  void forceAddTaintBuffer(std::vector<t_AliveFunctionCall> &vFCallContBuf,
                           std::string funcCallMark,
                           unsigned long beginAddr,
                           unsigned long size);

  std::vector<string> insert_load_buffer(std::vector<string> &alive_buffer,
                                         std::vector<string> &xtLog);

  std::vector<XT_FunctionCall> getAliveFunctionCall();
  vector<t_AliveFunctionCall> create_function_call_buffer(XTLog &xtLog);
  void filter_small_continuous_buffer();
  std::vector<t_AliveFunctionCall> filter_kernel_buffer(std::vector<
      t_AliveFunctionCall> &vAliveFunction);
  void clean_empty_function(std::vector<t_AliveFunctionCall> &vAliveFunction);
  void propagate_alive_buffer(vector<t_AliveFunctionCall> &vAliveFunction);

  std::vector<t_AliveFunctionCall> convert_alive_function_call();
 private:
  static const unsigned long STACK_BEGIN_ADDR = 0xb0000000;

  std::vector<std::string> m_s_vAliveBuffer;
  std::vector<XT_FunctionCall> m_vAliveFunctionCall;

  static inline bool is_mem_alive(unsigned long &, unsigned long &);
  static inline bool is_heap_mem_alive();
  static inline bool is_stack_mem_alive(unsigned long &, unsigned long &);

  inline bool isHasAliveBuffer(t_AliveFunctionCall &aliveFunction,
                               t_AliveContinueBuffer &aliveBuffer);

  static vector<string> analyze_function_alive_buffer(vector<string> &); // IGNORE
  static vector<string> analyze_alive_buffer_per_function(vector<string> &);

  static inline Buf_Rec_t analyze_load_buf(string &);
  static inline Buf_Rec_t analyze_store_buf(string &);
  static bool compare_buf_rec(Buf_Rec_t &, Buf_Rec_t &);

  static vector<t_AliveContinueBuffer> create_continue_buffer(vector<Buf_Rec_t> &);
  static t_AliveFunctionCall analyze_continue_buffer_per_function(vector<string> &);
};
#endif