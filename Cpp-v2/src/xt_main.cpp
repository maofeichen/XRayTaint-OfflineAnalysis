#include "boost/program_options.hpp" 

using namespace boost;
namespace po = boost::program_options;

// #include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "xt_constant.h"
#include "xt_data.h"
#include "xt_detectAvalanche.h"
#include "xt_util.h"

using namespace std;

bool compare_res_node(const Node &a, const Node &b){
    return a.i_addr < b.i_addr;
}

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
        // also remove ".txt"
        fn = v_fp.back().substr(0, v_fp.back().size() - 4); 

        XT_DetectAvalanche da(false, 
                              TAINT_FUNC_CALL_MARK, 
                              TAINT_BUF_BEGIN_ADDR, 
                              TAINT_BUF_SIZE);
        da.detect_avalanche(fn, true);
    } 
    
    return 0;
}

