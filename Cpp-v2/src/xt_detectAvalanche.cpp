#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "xt_constant.h"
#include "xt_data.h"
#include "xt_detectAvalanche.h"
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
									   unsigned int size)
{
	m_isAddInputBuffer = isAddInputBuffer;
	string m_funcCallMark = funcCallMark;
	m_beginAddress = beginAddress;
	m_size = size;
}

void XT_DetectAvalanche::detect_avalanche(string logPath, bool isWriteFile)
{
	vector<string> xtLog;

    // Read file
    XT_File xtFile =(XT_FILE_PATH + logPath + XT_FILE_EXT);
    xtLog = xtFile.read();

	// Preprocess
    XT_PreProcess xtPreProc;
    xtLog = xtPreProc.clean_empty_function_mark(xtLog);
    xtLog = xtPreProc.clean_nonempty_function_mark(xtLog);
    if(isWriteFile)
        xtFile.write(XT_RESULT_PATH + logPath + XT_PREPROCESS + XT_FILE_EXT, xtLog);

    // Add memory size infomation
    xtLog = xtPreProc.parseMemSizeInfo(xtLog);
    if(isWriteFile)
        xtFile.write(XT_RESULT_PATH + logPath + XT_ADD_SIZE_INFO + XT_FILE_EXT, xtLog);

    // Initialize XTLog object after adding memory size
    XTLog o_xtLog(xtLog);

    // Buffer liveness analysis
    XT_Liveness xtLiveness;
    vector<string> aliveBuf;
    aliveBuf = XT_Liveness::analyze_alive_buffer(xtLog);
    aliveBuf =  xtLiveness.insert_load_buffer(aliveBuf, xtLog);
    if(isWriteFile)
        xtFile.write(XT_RESULT_PATH + logPath + XT_ALIVE_BUF + XT_FILE_EXT, aliveBuf);

    // Create continuous buffers in each function call
    XT_Liveness functionCallLiveness(aliveBuf);
    functionCallLiveness.create_function_call_buffer(o_xtLog);
    // Todo: filter out size < 8 bytes
    // Todo: filter out kernel address
    functionCallLiveness.propagate_alive_buffer();
    if(isWriteFile)
        xtFile.write_continuous_buffer(XT_RESULT_PATH + logPath + CONT_BUF + XT_FILE_EXT, 
                                       functionCallLiveness);

    // Merges continuous buffers
    vector<t_AliveFunctionCall> vAliveFunctionCall;
    vAliveFunctionCall = functionCallLiveness.convert_alive_function_call();

    // vAliveFunctionCall = XT_Liveness::merge_continue_buffer(aliveBuf);
    // vAliveFunctionCall = XT_Liveness::filter_continue_buffer(vAliveFunctionCall);
    // if(m_isAddInputBuffer)
    //     xtLiveness.forceAddTaintBuffer(vAliveFunctionCall,
    //                                    TAINT_FUNC_CALL_MARK, 
    //     							   TAINT_BUF_BEGIN_ADDR, 
    //                                    TAINT_BUF_SIZE);
    // if(isWriteFile)
    //     xtFile.write_continue_buffer(XT_RESULT_PATH + logPath + CONT_BUF + XT_FILE_EXT, 
    //                                  vAliveFunctionCall);

    // Converts string format to Record format
    vector<Record> xtLogRec;
    xtLogRec = xtPreProc.convertToRec(xtLog);

    // Searches avalanche effect
    vector<AvalResBetweenInOut> vAvalResult;
    SearchAvalanche sa(vAliveFunctionCall, xtLogRec, o_xtLog);
    // vAvalResult = sa.searchAvalanche();
    // if(isWriteFile){
    //     xtFile.writeAvalResult(XT_RESULT_PATH + logPath + AVAL_RES + XT_FILE_EXT, vAvalResult);
    // }
}	