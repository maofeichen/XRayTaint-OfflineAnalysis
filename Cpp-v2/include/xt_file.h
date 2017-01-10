#ifndef XT_FILE_H
#define XT_FILE_H

#include <string>
#include <vector>

#include "xt_data.h"
#include "xt_liveness.h"
#include "xt_searchavalanche.h"

using namespace std;

const string XT_FILE_EXT    = ".txt";
const string XT_FILE_PATH	= "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/Cpp-v2/test-file/";
const string XT_RESULT_PATH = "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/Cpp-v2/test-result/";

const string XT_FILE_FAKE_DATA  = "test-aes-128-1B-all-identify-in-out-buffer-fake-data";
const string XT_FILE_AES        = "test-aes-128-1B-all-marks";
const string FILE_REFINE        = "test-aes-128-oneblock-sizemark-refine";
const string FILE_AES_KEYSTOKE  = "test-aes-128-1B-taint-keystroke-input";
const string AES_128_CBC_1B_TAINT_INPUT_MEMORY = "aes-128-cbc-1B-taint-input-memory-all-mark";
const string AES_128_CBC_1B_Taint_INPUT_KEYSTROKE = "aes-128-cbc-1B-taint-input-keystroke-all-mark";

const string AES_128_1B_LC_TAINT_INPUT = "aes-128-one-block-enc-local_compile-taint_input";
const string AES_128_1B_LC_TAINT_INPUT_FIX = "aes-128-one-block-enc-local_compile-taint_input-fix_ld_st_size_mark";
const string AES_1B_ENC_LCOMP_TAINT_MEM_IN_FIX_ADD = "aes-1B-enc-LComp-taint_mem_in-fix-add_i32-error";


const string XT_PREPROCESS      = "-preprocess";
const string XT_ADD_SIZE_INFO   = "-add-size-info";
const string XT_ADD_INDEX       = "-add_index";
const string XT_ALIVE_BUF       = "-alive-buf";
const string CONT_BUF           = "-cont-buf";
const string ALL_PROPAGATE_RES  = "-all-propagate-res";
const string AVAL_RES           = "-avalanche-result";

class XT_File
{
private:
    std::string path_r;
public:
    XT_File(std::string);

    std::vector<std::string> read();
    void write(std::string, std::vector<std::string> &);
    void write_continue_buffer(string, vector<t_AliveFunctionCall> &);
    void write_continuous_buffer(std::string path, 
    							 XT_Liveness &function_call_liveness);
    void write_all_propagate_result(string path, vector<NodePropagate> &allPropagateRes);
    void writeAvalancheResult(std::string p, std::vector<AvalancheResBetweenInAndOut> &vAvalRes);
    void writeAvalResult(std::string p, std::vector<AvalResBetweenInOut> &vAvalRes);
}; 
#endif
