#ifndef XT_ALIVEBUFFER_H
#define XT_ALIVEBUFFER_H

#include <vector>
#include "xt_node.h"

// Why can't declare in private?
struct t_AliveNode
{
	unsigned int index 	= 0;		// index in class XTLog
	bool isSource		= false;	// is source or destination
};

class XT_AliveBuffer
{
private:
	unsigned int m_beginAddr 	= 0;
	unsigned int m_bitSize 		= 0;

	std::vector<XTNode> m_vNode;
	std::vector<unsigned long> m_vIndex;

public:
	XT_AliveBuffer();

	void clearAliveBuffer();
	void setBeginAddr(unsigned int beginAddr);
	void setBitSize(unsigned int bitSize);
	void increaseBitSize(unsigned int bitSize);
	void addNode(XTNode &node);
	void addIndex(unsigned long index);

	unsigned int getBeginAddr();
	unsigned int getBufferBitSize();
	unsigned int getBufferByteSize();
	std::vector<XTNode> getVecAliveNode();
}; 
#endif