#include <string>
#include "xt_flag.h"
#include "xt_log.h"
#include "xt_node.h"
#include "xt_util.h"

using namespace std;

XTLog::XTLog() {}

XTLog::XTLog(vector<string> &vXTLog)
{
	unsigned int index = 0;
	vector<string>::iterator it = vXTLog.begin();
	for(; it != vXTLog.end(); ++it){
		XTRecord xtRecord(*it, index);
		m_vXTRecord.push_back(xtRecord);
		index++;	
	}
}

XTRecord XTLog::getRecord(std::size_t index)
{
	return m_vXTRecord[index];
}


unsigned int XTLog::findRecord(std::string &s_record)
{
	unsigned int recordIndex = 0;
	vector<string> s_vRecord;

	s_vRecord = XT_Util::split(s_record.c_str(), '\t');

	vector<XTRecord>::iterator it = m_vXTRecord.begin();
	for(; it != m_vXTRecord.end(); ++it){
		XTNode source = (*it).getSourceNode();
		XTNode destination = (*it).getDestinationNode();

		if(s_vRecord[0] == source.getFlag() && 
		   s_vRecord[1] == source.getAddr() && 
		   s_vRecord[2] == source.getVal() && 
		   s_vRecord[3] == destination.getFlag() &&
		   s_vRecord[4] == destination.getAddr() &&
		   s_vRecord[5] == destination.getVal() ){

			recordIndex = it - m_vXTRecord.begin();
			break;
		}
	}

	return recordIndex;
}

unsigned int XTLog::getRecordSize()
{
	return m_vXTRecord.size();
}