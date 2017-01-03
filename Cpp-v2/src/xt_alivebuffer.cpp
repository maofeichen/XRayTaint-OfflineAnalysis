#include "xt_alivebuffer.h"

using namespace std;

XT_AliveBuffer::XT_AliveBuffer() {};

unsigned int XT_AliveBuffer::getBeginAddr(){return m_beginAddr; }

unsigned int XT_AliveBuffer::getBufferBitSize() {return m_bitSize; }

vector<t_AliveNode> XT_AliveBuffer::getVecAliveNode() {return m_vAliveNode; }
