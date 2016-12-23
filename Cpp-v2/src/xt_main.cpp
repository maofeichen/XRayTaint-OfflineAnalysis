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
#include "xt_util.h"
using namespace std;

bool compare_res_node(const Node &a, const Node &b){
    return a.i_addr < b.i_addr;
}

void detect_avalanche(string logPath, bool isForceAddInput, bool isWriteFile);

int main(int argc, char const *argv[])
{
    string fn;

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
        cout << "input log: " << vm["input-file"].as< string >() << endl;

        vector<string> v_fp = XT_Util::split( vm["input-file"].as< string >().c_str(), '/' );
        fn = v_fp.back().substr(0, v_fp.back().size() - 4); // also remove ".txt"

        detect_avalanche(fn, false, true);
    } 
    
    return 0;
}

// Duplicate detect_avalanche() for latest test
void detect_avalanche(string logPath, bool isForceAddInput, bool isWriteFile)
{
    vector<string> xtLog, aliveBuf;
    vector<Rec> xtLogRec;
    vector<Func_Call_Cont_Buf_t> vFuncCallContBuf;
    vector<AvalancheResBetweenInAndOut> vAvalResult;

    XT_File xtFile =(XT_FILE_PATH + logPath + XT_FILE_EXT);
    xtLog = xtFile.read();

    // preprocess
    XT_PreProcess xtPreProc;
    // xtLog = xtPreProc.clean_size_mark(xtLog); Not needed any more
    xtLog = xtPreProc.clean_empty_function_mark(xtLog);
    xtLog = xtPreProc.clean_nonempty_function_mark(xtLog);
    if(isWriteFile)
        xtFile.write(XT_RESULT_PATH + logPath + XT_PREPROCESS + XT_FILE_EXT, xtLog);

    // add memory size infomation
    // xtLog = XT_PreProcess::add_mem_size_info(xtLog); Not needed
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
    if(isForceAddInput)
        xtLiveness.forceAddTaintBuffer(vFuncCallContBuf, TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE);
    if(isWriteFile)
        xtFile.write_continue_buffer(XT_RESULT_PATH + logPath + CONT_BUF + XT_FILE_EXT, vFuncCallContBuf);

    // Converts string format to Rec format
    xtLogRec = xtPreProc.convertToRec(xtLog);

    // Searches avalanche effect
    SearchAvalanche sa(vFuncCallContBuf, xtLogRec);
    vAvalResult = sa.searchAvalanche();
    if(isWriteFile)
        xtFile.writeAvalancheResult(XT_RESULT_PATH + logPath + AVAL_RES + XT_FILE_EXT, vAvalResult);
}
