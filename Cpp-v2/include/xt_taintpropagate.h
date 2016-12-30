#ifndef TAINT_PROPAGATE_H
#define TAINT_PROPAGATE_H

#include "xt_node.h"

class TaintPropagate
{
private:
	bool isStoreMemoryFlag(std::string &flag);
	bool isRegisterTemporary(std::string &addr);
public:
	TaintPropagate();

	bool isValidPropagate(XTNode &prevDestination, XTNode &nextSource);
	
};

#endif