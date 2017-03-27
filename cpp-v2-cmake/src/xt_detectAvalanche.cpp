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

XT_DetectAvalanche::XT_DetectAvalanche(bool isAddInputBuffer,
                                       string funcCallMark,
                                       unsigned int beginAddress,
                                       unsigned int size) {
  m_isAddInputBuffer = isAddInputBuffer;
  string m_funcCallMark = funcCallMark;
  m_beginAddress = beginAddress;
  m_size = size;
}

void XT_DetectAvalanche::detect_avalanche(string logPath, bool isWriteFile) {
  string c_time = get_time();
  c_time = '-' + c_time;

  vector<string> v_s_log;
  // Read file
  XT_File xtFile = (XT_FILE_PATH + logPath + XT_FILE_EXT);
  v_s_log = xtFile.read();

  // Preprocess
  XT_PreProcess xtPreProc;
  v_s_log = xtPreProc.clean_empty_instruction_mark(v_s_log);
  cout << "num of entries after clean insn mark: " << v_s_log.size() << endl;
  v_s_log = xtPreProc.clean_empty_function_mark(v_s_log);
  cout << "num of entries after clean empyt func mark: " << v_s_log.size()
       << endl;
  // v_s_log = xtPreProc.clean_nonempty_function_mark(v_s_log);
  v_s_log = xtPreProc.clean_function_call_mark(v_s_log);
  cout << "num of entries after clean func mark: " << v_s_log.size() << endl;
  if (isWriteFile)
    xtFile.write(
        XT_RESULT_PATH + logPath + XT_PREPROCESS + c_time + XT_FILE_EXT, v_s_log);


  // Add memory size infomation
  v_s_log = xtPreProc.parseMemSizeInfo(v_s_log);
  if (isWriteFile)
    xtFile.write(
        XT_RESULT_PATH + logPath + XT_ADD_SIZE_INFO + c_time + XT_FILE_EXT,
        v_s_log);

  // Add index for each record
  v_s_log = xtPreProc.addRecordIndex(v_s_log);
  if (isWriteFile)
    xtFile.write(XT_RESULT_PATH + logPath + XT_ADD_INDEX + c_time + XT_FILE_EXT,
                 v_s_log);

  // Initialize XTLog object after adding memory size
  XTLog o_xtLog(v_s_log);


  // Buffer liveness analysis
  XT_Liveness xtLiveness;
  vector<string> aliveBuf;
  aliveBuf = XT_Liveness::analyze_alive_buffer(v_s_log);
  // aliveBuf =  xtLiveness.insert_load_buffer(aliveBuf, v_s_log);
  if (isWriteFile)
    xtFile.write(XT_RESULT_PATH + logPath + XT_ALIVE_BUF + c_time + XT_FILE_EXT,
                 aliveBuf);

  // Create continuous buffers in each function call
  vector<t_AliveFunctionCall> vAliveFunction;
  XT_Liveness functionLiveness(aliveBuf);
  vAliveFunction = functionLiveness.create_function_call_buffer(o_xtLog);
  functionLiveness.propagate_alive_buffer(vAliveFunction);
  vAliveFunction = functionLiveness.filter_kernel_buffer(vAliveFunction);
  if (isWriteFile)
    xtFile.write_continue_buffer(
        XT_RESULT_PATH + logPath + CONT_BUF + c_time + XT_FILE_EXT,
        vAliveFunction);

  // Converts string format to Record format
  vector<Record> xtLogRec;
  xtLogRec = xtPreProc.convertToRec(v_s_log);

  // Searches avalanche effect
  vector<AvalResBetweenInOut> vAvalResult;
  /*
  vector<XT_FunctionCall> v_xtFunctionCall = functionLiveness.getAliveFunctionCall();
  SearchAvalanche sa(v_xtFunctionCall, vAliveFunctionCall, xtLogRec, o_xtLog);
  */
  // SearchAvalanche sa(vAliveFunction, xtLogRec, o_xtLog);
  // vAvalResult = sa.detect_avalanche();
  //    if(isWriteFile){
  //        xtFile.writeAvalResult(XT_RESULT_PATH + logPath + AVAL_RES + c_time + XT_FILE_EXT, vAvalResult);
  //    }

  // Detects after liveness analysis
  Detect det(vAliveFunction, o_xtLog, xtLogRec);
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
