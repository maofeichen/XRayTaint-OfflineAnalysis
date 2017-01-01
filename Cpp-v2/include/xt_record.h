#ifndef XT_RECORD_H
#define XT_RECORD_H

#include "xt_node.h"

class XTRecord
{
public:
	// XTRecord();
	XTRecord(std::string &record);

	bool isMark();
	XTNode getSourceNode();
	XTNode getDestinationNode();

private:
	bool m_isMark;
	XTNode m_sourceNode;
	XTNode m_destinationNode;
};

#endif