#include "xt_flag.h"
#include "xt_record.h"
#include "xt_util.h"

using namespace std;

// XTRecord::XTRecord(){}
XTRecord::XTRecord(std::string &record, unsigned int index)
{
	m_index = index;
	vector<string> v_record = XT_Util::split(record.c_str(), '\t');

	string flag = v_record[0];
	m_isMark = XT_Util::isMarkRecord(flag );

	if(isMark() ){
		m_sourceNode = XTNode(v_record, true, m_index);
		// m_sourceNode = XTNode(v_record, true);
	} else{
		vector<string>::iterator first;
		vector<string>::iterator last;

		first = v_record.begin();
		last  = v_record.begin() + 3;
		vector<string> v_source(first, last);

		first = v_record.begin() + 3;
		last  = v_record.end() - 1;
		vector<string> v_destination(first, last);

		string size;
		if(XT_Util::equal_mark(flag, flag::TCG_QEMU_LD) ){
			size = v_record[6];
			v_source.push_back(size);
		}else if(XT_Util::equal_mark(flag, flag::TCG_QEMU_ST) ){
			size = v_record[6];
			v_destination.push_back(size);
		}

		m_sourceNode 		= XTNode(v_source, true, m_index);
		m_destinationNode 	= XTNode(v_destination, false, m_index);

		// m_sourceNode = XTNode(v_source, true);
		// m_destinationNode = XTNode(v_destination, false);
	}
}

bool XTRecord::isMark() {return m_isMark; }

unsigned int XTRecord::XTRecord::getIndex() {return m_index; }

XTNode XTRecord::getSourceNode() {return m_sourceNode; }

XTNode XTRecord::getDestinationNode() {return m_destinationNode; }
