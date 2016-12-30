#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "xt_constant.h"
#include "xt_data.h"
#include "xt_detectAvalanche.h"
#include "xt_file.h"
#include "xt_liveness.h"
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
	vector<string> xtLog, aliveBuf;
    vector<Record> xtLogRec;
    vector<Func_Call_Cont_Buf_t> vFuncCallContBuf;
    vector<AvalResBetweenInOut> vAvalResult;

    XT_File xtFile =(XT_FILE_PATH + logPath + XT_FILE_EXT);
    xtLog = xtFile.read();

	// preprocess
    XT_PreProcess xtPreProc;
    xtLog = xtPreProc.clean_empty_function_mark(xtLog);
    xtLog = xtPreProc.clean_nonempty_function_mark(xtLog);
    if(isWriteFile)
        xtFile.write(XT_RESULT_PATH + logPath + XT_PREPROCESS + XT_FILE_EXT, xtLog);

    // add memory size infomation
    xtLog = xtPreProc.parseMemSizeInfo(xtLog);
    if(isWriteFile)
        xtFile.write(XT_RESULT_PATH + logPath + XT_ADD_SIZE_INFO + XT_FILE_EXT, xtLog);

    // buffer liveness analysis
    aliveBuf = XT_Liveness::analyze_alive_buffer(xtLog);
    if(isWriteFile)
        xtFile.write(XT_RESULT_PATH + logPath + XT_ALIVE_BUF + XT_FILE_EXT, aliveBuf);

    // Merges continuous buffers
    XT_Liveness xtLiveness;
    vFuncCallContBuf = XT_Liveness::merge_continue_buffer(aliveBuf);
    vFuncCallContBuf = XT_Liveness::filter_continue_buffer(vFuncCallContBuf);
    if(m_isAddInputBuffer)
        xtLiveness.forceAddTaintBuffer(vFuncCallContBuf,TAINT_FUNC_CALL_MARK, 
        								TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE);
    if(isWriteFile)
        xtFile.write_continue_buffer(XT_RESULT_PATH + logPath + CONT_BUF + XT_FILE_EXT, vFuncCallContBuf);

    // Converts string format to Record format
    xtLogRec = xtPreProc.convertToRec(xtLog);

    // Searches avalanche effect
    SearchAvalanche sa(vFuncCallContBuf, xtLogRec);
    vAvalResult = sa.searchAvalanche();
    if(isWriteFile){
        xtFile.writeAvalResult(XT_RESULT_PATH + logPath + AVAL_RES + XT_FILE_EXT, vAvalResult);
    }
}	