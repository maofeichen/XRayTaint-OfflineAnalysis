#include "boost/program_options.hpp" 

using namespace boost;
namespace po = boost::program_options;

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "xt_constant.h"
#include "xt_data.h"
#include "xt_file.h"
#include "xt_liveness.h"
#include "xt_preprocess.h"
#include "xt_propagate.h"
#include "xt_searchavalanche.h"

using namespace std;

bool compare_res_node(const Node &a, const Node &b){
    return a.i_addr < b.i_addr;
}

void testCase(string logPath, bool isForceAdd);

int main(int argc, char const *argv[])
{
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "produce help message")
        ("input-file,i", po::value< string >(), "input file");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);    

    if (vm.count("help")) {
        cout << desc << endl;
        return 1;
    }

    if(vm.count("input-file") ){
        cout << "input file: " << vm["input-file"].as< string >() << endl;
    } 

    // testCase(AES_1B_ENC_LCOMP_TAINT_MEM_IN_FIX_ADD, false);
    return 0;
}

// Duplicate testCase() for latest test
void testCase(string logPath, bool isForceAdd)
{
    vector<string> xtLog;
    vector<string> aliveBuf;
    vector<Rec> xtLogRec;
    vector<Func_Call_Cont_Buf_t> vFuncCallContBuf;
    vector<AvalancheResBetweenInAndOut> vAvalResult;

    XT_File xtFile =(XT_FILE_PATH + logPath + XT_FILE_EXT);
    xtLog = xtFile.read();

    // preprocess
    XT_PreProcess xtPreProc;
    // xtLog = xtPreProc.clean_size_mark(xtLog); Not needed any more

    // There is a bug
    // xtLog = xtPreProc.clean_empty_function_mark(xtLog);
    xtLog = xtPreProc.clean_nonempty_function_mark(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_PREPROCESS + XT_FILE_EXT, xtLog);

    // add memory size infomation
    // xtLog = XT_PreProcess::add_mem_size_info(xtLog); Not needed
    xtLog = xtPreProc.parseMemSizeInfo(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_ADD_SIZE_INFO + XT_FILE_EXT, xtLog);

    // buffer liveness analysis
    aliveBuf = XT_Liveness::analyze_alive_buffer(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_ALIVE_BUF + XT_FILE_EXT, aliveBuf);

    // Merges continuous buffers
    XT_Liveness xtLiveness;
    vFuncCallContBuf = XT_Liveness::merge_continue_buffer(aliveBuf);
    vFuncCallContBuf = XT_Liveness::filter_continue_buffer(vFuncCallContBuf);
    if(isForceAdd)
        xtLiveness.forceAddTaintBuffer(vFuncCallContBuf, TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE);
    // xtFile.write_continue_buffer(XT_RESULT_PATH + logPath + CONT_BUF + XT_FILE_EXT, vFuncCallContBuf);

    // Converts string format to Rec format
    xtLogRec = xtPreProc.convertToRec(xtLog);

    // Searches avalanche effect
    SearchAvalanche sa(vFuncCallContBuf, xtLogRec);
    vAvalResult = sa.searchAvalanche();
    xtFile.writeAvalancheResult(XT_RESULT_PATH + logPath + AVAL_RES + XT_FILE_EXT, vAvalResult);
}
