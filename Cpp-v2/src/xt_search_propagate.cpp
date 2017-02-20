// xt_search_propagate.cpp
// The program is used to given a xray taint log, and any nodes in the log,
// as taint source, returns (prints) the search propagation result.

#include "boost/program_options.hpp"

using namespace boost;
namespace po = boost::program_options;

#include "xt_data.h"
#include "xt_flag.h"
#include "xt_file.h"
#include "xt_log.h"
#include "xt_node.h"
#include "xt_preprocess.h"
#include "xt_propagate.h"
#include "xt_util.h"

using namespace std;

NodePropagate init_taint_source(XTNode &node)
{
	NodePropagate source;
	unsigned int recordIndex = node.getIndex();

	string sflag = node.getFlag();
	if(XT_Util::equal_mark(sflag, flag::TCG_QEMU_LD) ){
		source.isSrc 	= true;
		source.id 		= node.getIndex() * 2;
	}else if(XT_Util::equal_mark(sflag, flag::TCG_QEMU_ST) ){
		source.isSrc 	= false;
		source.id 		= node.getIndex() * 2 + 1;
	}

	source.parentId 	= 0;
	source.layer 		= 0;
	source.pos 			= recordIndex;
	source.insnAddr 	= "";
	source.n.flag 		= node.getFlag();
	source.n.addr 		= node.getAddr();
	source.n.val 		= node.getVal();
	source.n.i_addr 	= node.getIntAddr();
	source.n.sz 		= node.getBitSize();

	return source;
}


void search_taint_propagate(string log_path)
{
	vector<string> v_log;

    // Read file
    XT_File xt_file =(log_path);
    v_log = xt_file.read();

    // Preprocess
    XT_PreProcess xt_preproc;
    v_log = xt_preproc.clean_empty_function_mark(v_log);
    v_log = xt_preproc.clean_nonempty_function_mark(v_log);
    v_log = xt_preproc.clean_empty_instruction_mark(v_log);

    // Add memory size infomation
    v_log = xt_preproc.parseMemSizeInfo(v_log);

    // Add index for each record
    v_log = xt_preproc.addRecordIndex(v_log);

    // Initialize XTLog object after adding memory size
    XTLog xt_log(v_log);

    Propagate propagate(xt_log);
    vector<Record> v_record;
    NodePropagate taint_src;
    XTNode node;

    // taint source: index 107992
    node = xt_log.getRecord(107992).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 107992 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);

    // taint source: index 115470
    node = xt_log.getRecord(115470).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 115470 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);

    /*
    // taint source: index 327121
    node = xt_log.getRecord(327121).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 327121 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);

    // taint source: index 330887
    node = xt_log.getRecord(330887).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 330887 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);

    // taint source: index 338587
    node = xt_log.getRecord(338587).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 338587 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);
	*/

    /*
    // taint source: index 1
    node = xt_log.getRecord(1).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 1  addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);

    // taint source: index 127565
    node = xt_log.getRecord(127565).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 127565 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);

    // taint source: index 127571
    node = xt_log.getRecord(127571).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 127571 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);

    // taint source: index 127577
    node = xt_log.getRecord(127577).getSourceNode();
    taint_src = init_taint_source(node);
    cout << "search propagation, taint source: index: 127577 addr: " << hex << node.getIntAddr() << endl;
    propagate.getPropagateResult(taint_src, v_record, 0);
    */
}

int main(int argc, char const *argv[] )
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
    	string log_path = vm["input-file"].as< string >();
        cout << "input log: " << vm["input-file"].as< string >() << endl;
        // vector<string> v_fp = XT_Util::split( vm["input-file"].as< string >().c_str(), '/' );

        search_taint_propagate(log_path);
    }

	return 0;
}

