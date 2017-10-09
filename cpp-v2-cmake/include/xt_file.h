#ifndef XT_FILE_H
#define XT_FILE_H

#include <string>
#include <vector>

#include "xt_data.h"
#include "xt_liveness.h"
#include "xt_searchavalanche.h"

using namespace std;

const string XT_FILE_EXT    = ".txt";
//const string XT_FILE_PATH	= "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/test_file/";
//const string XT_RESULT_PATH = "/home/xtaint/Workplace/XRayTaint-OfflineAnalysis/test_result/";
const std::string XT_FILE_PATH  = "/home/xtaint/Workplace/XRayTaint/TestResult/";
const std::string XT_RESULT_PATH  = "/home/xtaint/Workplace/XT_Test_Result/";


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
  	void read(std::vector<std::string>& log);
    void write(std::string, std::vector<std::string> &);
    void write_continue_buffer(string, vector<t_AliveFunctionCall> &);
    void write_continuous_buffer(std::string path, 
    							 XT_Liveness &function_call_liveness);
    void write_all_propagate_result(string path, vector<NodePropagate> &allPropagateRes);
    void writeAvalancheResult(std::string p, std::vector<AvalancheResBetweenInAndOut> &vAvalRes);
    void writeAvalResult(std::string p, std::vector<AvalResBetweenInOut> &vAvalRes);
}; 
#endif
