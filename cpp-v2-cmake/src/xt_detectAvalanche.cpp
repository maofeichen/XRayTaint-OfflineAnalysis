#include <algorithm>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include "xt_constant.h"
#include "xt_data.h"
#include "xt_detectAvalanche.h"
#include "xt_detect.h"
#include "xt_file.h"
#include "xt_liveness.h"
#include "xt_log.h"
#include "xt_preprocess.h"
#include "xt_propagate.h"
#include "xt_searchavalanche.h"
#include "xt_util.h"

using namespace std;

XT_DetectAvalanche::XT_DetectAvalanche() {}

XT_DetectAvalanche::XT_DetectAvalanche(bool isAddInputBuffer,
                                       string funcCallMark,
                                       unsigned int beginAddress,
                                       unsigned int size) {
  m_isAddInputBuffer = isAddInputBuffer;
  string m_funcCallMark = funcCallMark;
  m_beginAddress = beginAddress;
  m_size = size;
}

void XT_DetectAvalanche::detect_avalanche(string logPath, bool is_dump) {
  string c_time = get_time();
  c_time = '-' + c_time;

  vector<string> v_s_log;
  // Read file
  XT_File xt_file = (XT_FILE_PATH + logPath + XT_FILE_EXT);
//  v_s_log = xt_file.read();
  xt_file.read(v_s_log);

  // Preprocess
  XT_PreProcess preproc;
  v_s_log = preproc.clean_empty_instruction_mark(v_s_log);
  cout << "num of entries after clean insn mark: " << v_s_log.size() << endl;

  v_s_log = preproc.clean_function_call_mark(v_s_log);
  // v_s_log = preproc.clean_empty_function_mark(v_s_log);
  // v_s_log = preproc.clean_nonempty_function_mark(v_s_log);
  if (is_dump) {
    xt_file.write(
        XT_RESULT_PATH + logPath + XT_PREPROCESS + c_time + XT_FILE_EXT,
        v_s_log);
  }

  // Add memory size infomation
  v_s_log = preproc.parseMemSizeInfo(v_s_log);
  if (is_dump) {
    xt_file.write(
        XT_RESULT_PATH + logPath + XT_ADD_SIZE_INFO + c_time + XT_FILE_EXT,
        v_s_log);
  }

  // Add index for each record
  v_s_log = preproc.addRecordIndex(v_s_log);
  if (is_dump) {
    xt_file.write(
        XT_RESULT_PATH + logPath + XT_ADD_INDEX + c_time + XT_FILE_EXT,
        v_s_log);
  }

  // Initialize XTLog object after adding memory size
  XTLog o_log(v_s_log);

  // Buffer liveness analysis
  XT_Liveness xt_liveness;
  vector<string> v_s_alive_buf;

  v_s_alive_buf = XT_Liveness::analyze_alive_buffer(v_s_log);
  // v_s_alive_buf =  xt_liveness.insert_load_buffer(v_s_alive_buf, v_s_log);
  if (is_dump) {
    xt_file.write(
        XT_RESULT_PATH + logPath + XT_ALIVE_BUF + c_time + XT_FILE_EXT,
        v_s_alive_buf);
  }

  // Create continuous buffers in each function call
  vector<t_AliveFunctionCall> v_alive_func;
  XT_Liveness func_live(v_s_alive_buf);
  v_alive_func = func_live.create_function_call_buffer(o_log);

  func_live.propagate_alive_buffer(v_alive_func);
//  v_alive_func = func_live.filter_kernel_buffer(v_alive_func);
  if (is_dump) {
    xt_file.write_continue_buffer(
        XT_RESULT_PATH + logPath + CONT_BUF + c_time + XT_FILE_EXT,
    v_alive_func);
  }

  // Converts string format to Record format
  vector<Record> log_rec;
  log_rec = preproc.convertToRec(v_s_log);

  // Searches avalanche effect

  // vector<AvalResBetweenInOut> vAvalResult;
  //vector<XT_FunctionCall> v_xtFunctionCall = func_live.getAliveFunctionCall();
  // SearchAvalanche sa(v_xtFunctionCall, vAliveFunctionCall, log_rec, o_log);


  // SearchAvalanche sa(v_alive_func, log_rec, o_log);
  // vAvalResult = sa.detect_avalanche();
  //    if(is_dump){
  //        xt_file.writeAvalResult(XT_RESULT_PATH + logPath + AVAL_RES + c_time + XT_FILE_EXT, vAvalResult);
  //    }

  // Detects after liveness analysis
  Detect det(v_alive_func, o_log, log_rec);
  det.detect_cipher();

}

string XT_DetectAvalanche::get_time() {
  time_t t = time(0);   // get time now
  struct tm *now = localtime(&t);

  string c_time = to_string((now->tm_year + 1900)) + '-' +
      to_string((now->tm_mon + 1)) + '-' +
      to_string(now->tm_mday) + '-' +
      to_string(now->tm_hour) + '-' +
      to_string(now->tm_min);
  return c_time;
}
