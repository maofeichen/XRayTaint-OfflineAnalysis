#include <string>
#include "xt_flag.h"
#include "xt_log.h"
#include "xt_util.h"

using namespace std;

XTLog::XTLog(vector<string> &vXTLog)
{
	m_vXTLog = vXTLog;
}

Node XTLog::convertToNode(vector<string> &recordField, bool isSource)
{
	Node node;

	if(!recordField.empty() ){
		if(isSource){
			node.flag = recordField[0];
			node.addr = recordField[1];
			node.val  = recordField[2];
		} else{
			if(!XT_Util::isMarkRecord(recordField[0]) ){
				node.flag = recordField[3];
				node.addr = recordField[4];
				node.val  = recordField[5];
			}
		}

		if(XT_Util::equal_mark(recordField[0], flag::TCG_QEMU_LD) ){
			node.i_addr = stoul(recordField[1], nullptr, 16);
			node.sz 	= stoul(recordField[6], nullptr, 10);
		}else if(XT_Util::equal_mark(recordField[0], flag::TCG_QEMU_ST) ){
			node.i_addr = stoul(recordField[4], nullptr, 16);
			node.sz 	= stoul(recordField[6], nullptr, 10);
		}
	}
	// try error...
	return node;
}

Node XTLog::getSourceNode(std::size_t index)
{
	Node source;
	vector<string> recordField;
	bool isSource = true;

	recordField = XT_Util::split(m_vXTLog[index].c_str(), '\t');
	source = convertToNode(recordField, isSource);

	return source;	
}

Node XTLog::getDestinateNode(std::size_t index)
{
	Node destination;
	vector<string> recordField;
	bool isSource = false;

	recordField = XT_Util::split(m_vXTLog[index].c_str(), '\t');
	destination = convertToNode(recordField, isSource);

	return destination;
}

Record XTLog::getRecord(std::size_t index)
{

}