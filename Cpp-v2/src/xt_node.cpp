#include "xt_node.h"

using namespace std;

XTNode::XTNode(){}

bool XTNode::isMark(){return m_isMark; }	
string XTNode::getFlag(){return m_flag; }
string XTNode::getAddr(){return m_addr; }
string XTNode::getVal(){return m_val; }
unsigned int XTNode::getIntAddr(){return m_intAddr; }
unsigned int XTNode::getBitSize(){return m_bitSize; }
