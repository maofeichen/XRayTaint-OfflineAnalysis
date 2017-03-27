#include "xt_alivebuffer.h"
#include "xt_constant.h"

using namespace std;

XT_AliveBuffer::XT_AliveBuffer() {};

void XT_AliveBuffer::clearAliveBuffer()
{
	m_beginAddr = 0;
	m_bitSize = 0;
	m_vNode.clear();
	m_vIndex.clear();
}

void XT_AliveBuffer::setBeginAddr(unsigned int beginAddr) { m_beginAddr = beginAddr; }

void XT_AliveBuffer::setBitSize(unsigned int bitSize) { m_bitSize = bitSize; }

void XT_AliveBuffer::increaseBitSize(unsigned int bitSize) { m_bitSize += bitSize; }

void XT_AliveBuffer::addNode(XTNode &node) { m_vNode.push_back(node); }

void XT_AliveBuffer::addIndex(unsigned long index) { m_vIndex.push_back(index); }

unsigned int XT_AliveBuffer::getBeginAddr(){return m_beginAddr; }

unsigned int XT_AliveBuffer::getBufferBitSize() {return m_bitSize; }

unsigned int XT_AliveBuffer::getBufferByteSize() { return m_bitSize / BIT_TO_BYTE ; }

vector<XTNode> XT_AliveBuffer::getVecAliveNode() {return m_vNode; }
