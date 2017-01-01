#include "xt_constant.h"
#include "xt_flag.h"
#include "xt_taintpropagate.h"
#include "xt_util.h"

using namespace std;

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
		if(prevDestinateAddr == nextSource.getAddr() ){
			// Todo: add error prevent: nextSource bitSize should not be empty
			if(prevDestination.getBitSize() == nextSource.getBitSize() ){
				if(prevDestination.getVal() == nextSource.getVal() )
					isValid = true;
			}else{ // value analysis when sizes are different
				isValid = compareMemoryValue(prevDestination, nextSource);
			}
		}
	}else{
		// It seems we don't need to distinguish register or 
		// local temporary here
		// if(isRegisterTemporary(prevDestinateAddr) ){

		// }else{	// local tempory otherwise

		// }

		if(prevDestinateAddr == nextSource.getAddr() && 
		   prevDestination.getVal() == nextSource.getVal() )
			isValid = true;
	} 

	return isValid;
}

bool TaintPropagate::isStoreMemoryFlag(string &flag)
{
	return XT_Util::equal_mark(flag, flag::TCG_QEMU_ST);
}

// Not uses currently
bool TaintPropagate::isRegisterTemporary(std::string &addr)
{
	return false;
}

bool TaintPropagate::compareMemoryValue(XTNode &nodeFirst, 
										XTNode &nodeSecond)
{
	bool isMatch = false;

	unsigned int ByteNodeFirst 	= nodeFirst.getBitSize() / BIT_TO_BYTE;
	unsigned int ByteNodeSecond = nodeSecond.getBitSize() / BIT_TO_BYTE;

	size_t lenNodeFirst 	= nodeFirst.getVal().length();
	size_t lenNodeSecond 	= nodeSecond.getVal().length();

	unsigned int smallSize = ((ByteNodeFirst < ByteNodeSecond) ? ByteNodeFirst : ByteNodeSecond);
	switch(smallSize){
		case XT_BYTE:
			if(nodeFirst.getVal().substr(lenNodeFirst - 2, 2) == 
			   nodeSecond.getVal().substr(lenNodeSecond - 2, 2) )
				isMatch = true;
			break;
		case XT_WORD:
			if(nodeFirst.getVal().substr(lenNodeFirst - 4, 4) == 
				   nodeSecond.getVal().substr(lenNodeSecond - 4, 4) )
					isMatch = true;
			break;
		default:
			// other cases should not be possible
			break;
	}

	return isMatch;
}