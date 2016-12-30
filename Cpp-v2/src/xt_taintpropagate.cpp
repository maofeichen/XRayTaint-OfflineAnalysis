#include "xt_flag.h"
#include "xt_taintpropagate.h"
#include "xt_util.h"

using namespace std;

bool TaintPropagate::isStoreMemoryFlag(string &flag)
{
	return XT_Util::equal_mark(flag, flag::TCG_QEMU_ST);
}

bool TaintPropagate::isRegisterTemporary(std::string &addr)
{
	return false;
}

TaintPropagate::TaintPropagate(){}

// Determines if a previous destination node can propagate to next source node
// Retrun true if valid, false otherwise 
bool TaintPropagate::isValidPropagate(XTNode &prevDestination, 
									  XTNode &nextSource)
{
	bool isValid = false;

	string prevDestinateFlag = prevDestination.getFlag();
	string prevDestinateAddr = prevDestination.getAddr();

	if(isStoreMemoryFlag(prevDestinateFlag) ){

	}else{
		if(isRegisterTemporary(prevDestinateAddr) ){

		}else{	// local tempory otherwise

		}
	} 

	return isValid;
}