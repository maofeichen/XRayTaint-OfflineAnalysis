#ifndef TAINT_PROPAGATE_H
#define TAINT_PROPAGATE_H

#include "xt_node.h"

class TaintPropagate
{
public:
	TaintPropagate();

	bool isValidPropagate(XTNode &prevDestination, XTNode &nextSource);
private:
	enum e_MemorySize
	{
		XT_BYTE		= 1,
		XT_WORD 	= 2,
		XT_DWORD 	= 4
	};

	bool isStoreMemoryFlag(std::string &flag);
	bool isRegisterTemporary(std::string &addr);

	bool compareMemoryValue(XTNode &nodeFirst, XTNode &nodeSecond);
	bool isValueMatch(XTNode &nodeSmallSize, XTNode &nodeLargeSize);

	bool compareMemoryValueSameSize(XTNode &nfirst, XTNode &nSecond);
};

#endif