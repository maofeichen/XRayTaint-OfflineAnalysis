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
				if(prevDestination.getVal() == nextSource.getVal() ){
					isValid = true;
				}else{
					// Analyze values even their direct values are different, e.g.
					// 	pre dst: bffff73c 138 1B; next src: bffff73c 38 1B
					// There byte values are same, should consider valid
					isValid = compareMemoryValueSameSize(prevDestination, nextSource);
				}
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

	unsigned int byteNodeFirst 	= nodeFirst.getBitSize() / BIT_TO_BYTE;
	unsigned int byteNodeSecond = nodeSecond.getBitSize() / BIT_TO_BYTE;

	if(byteNodeFirst < byteNodeSecond)
		isMatch = isValueMatch(nodeFirst, nodeSecond);
	else
		isMatch = isValueMatch(nodeSecond, nodeFirst);

	return isMatch;
}

bool TaintPropagate::isValueMatch(XTNode &nodeSmallSize, XTNode &nodeLargeSize)
{
	bool isMatch = false;

	unsigned int byteSizeNodeSmall = nodeSmallSize.getByteSize();

	unsigned int valLenNodeSmallSize = nodeSmallSize.getVal().length();
	unsigned int valLenNodeLargeSize = nodeLargeSize.getVal().length();

	string valNodeSmall = "";
	string valNodeLarge = "";

	unsigned int iValNodeSmall = 0;
	unsigned int iValNodeLarge = 0;

	switch(byteSizeNodeSmall){
		case XT_BYTE:
		{
			if(valLenNodeSmallSize > 1)
				valNodeSmall = nodeSmallSize.getVal().substr(valLenNodeSmallSize - 2, 2);
			else
				valNodeSmall = nodeSmallSize.getVal();
			valNodeLarge = nodeLargeSize.getVal().substr(valLenNodeLargeSize - 2, 2);
		}
			break;
		case XT_WORD:
		{
			if(valLenNodeSmallSize > 3)
				valNodeSmall = nodeSmallSize.getVal().substr(valLenNodeSmallSize - 4, 4);
			else
				valNodeSmall = nodeSmallSize.getVal().substr(valLenNodeSmallSize - 3, 3);
			valNodeLarge = nodeLargeSize.getVal().substr(valLenNodeLargeSize - 4, 4);
		}
			break;
		default:
			break;
	}

	iValNodeSmall = stoul(valNodeSmall, nullptr, 16);
	iValNodeLarge = stoul(valNodeLarge, nullptr, 16);

	if(iValNodeSmall == iValNodeLarge)
		isMatch = true;

	return isMatch;
}

bool TaintPropagate::compareMemoryValueSameSize(XTNode &nFirst, XTNode &nSecond)
{
	unsigned int byteSize = nFirst.getByteSize();

	unsigned int valLenFirst = nFirst.getVal().length();
	unsigned int valLenSecond = nSecond.getVal().length();

	string valFirst = "";
	string valSecond = "";

	unsigned int iValFirst = 0;
	unsigned int iValSecond = 0;

	switch(byteSize){
		case XT_BYTE:
		{
			if(valLenFirst > 1)
				valFirst = nFirst.getVal().substr(valLenFirst - 2, 2);
			else
				valFirst = nFirst.getVal();

			if(valLenSecond > 1)
				valSecond = nSecond.getVal().substr(valLenSecond - 2, 2);
			else
				valSecond = nSecond.getVal();
		}
			break;
		case XT_WORD:
		{
			if(valLenFirst > 3)
				valFirst = nFirst.getVal().substr(valLenFirst - 4, 4);
			else
				valFirst = nFirst.getVal();

			if(valLenSecond > 3)
				valSecond = nSecond.getVal().substr(valLenSecond - 4, 4);
			else
				valSecond = nSecond.getVal();
		}
			break;
		case XT_DWORD:
			valFirst = nFirst.getVal();
			valSecond = nSecond.getVal();
			break;
		default:
			break;
	}

	iValFirst = stoul(valFirst, nullptr, 16);
	iValSecond = stoul(valSecond, nullptr, 16);

	if(iValFirst == iValSecond)
		return true;
	else
		return false;

}