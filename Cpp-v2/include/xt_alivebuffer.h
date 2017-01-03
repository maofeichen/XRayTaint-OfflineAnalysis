#ifndef XT_ALIVEBUFFER_H
#define XT_ALIVEBUFFER_H

#include <vector>

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

	std::vector<t_AliveNode> m_vAliveNode;

public:
	XT_AliveBuffer();

	unsigned int getBeginAddr();
	unsigned int getBufferBitSize();
	std::vector<t_AliveNode> getVecAliveNode();
}; 
#endif