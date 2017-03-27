#include "xt_flag.h"
#include "xt_constant.h"
#include "xt_node.h"
#include "xt_util.h"

using namespace std;

XTNode::XTNode() {}

XTNode::XTNode(std::vector<std::string> &str_vNode, bool isSrc)
{
	m_flag = str_vNode[0];
	m_addr = str_vNode[1];
	m_val  = str_vNode[2];

	m_isMark = XT_Util::isMarkRecord(m_flag);

	if( (XT_Util::equal_mark(m_flag, flag::TCG_QEMU_LD) && isSrc) || 
	    (XT_Util::equal_mark(m_flag, flag::TCG_QEMU_ST) && !isSrc) ){
		m_intAddr = stoul(m_addr, nullptr, 16);
		m_bitSize = stoul(str_vNode[3], nullptr, 10);
	}
}

// If Qemu_ld/st, it must be the case that node[3] indicating the size
XTNode::XTNode(vector<string> &node, bool isSrc, unsigned int index)
{
	// TODO: add try error
	m_flag 	= node[0];
	m_addr 	= node[1];
	m_val	= node[2];

	m_isMark = XT_Util::isMarkRecord(m_flag);
	m_index = index;

	if( (XT_Util::equal_mark(m_flag, flag::TCG_QEMU_LD) && isSrc) || 
	    (XT_Util::equal_mark(m_flag, flag::TCG_QEMU_ST) && !isSrc) ){
		m_intAddr = stoul(m_addr, nullptr, 16);
		m_bitSize = stoul(node[3], nullptr, 10);
	}
}

bool XTNode::isMark(){return m_isMark; }	

unsigned int XTNode::getIndex() { return m_index; }	

string XTNode::getFlag(){return m_flag; }

string XTNode::getAddr(){return m_addr; }

string XTNode::getVal(){return m_val; }

unsigned int XTNode::getIntAddr(){return m_intAddr; }

unsigned int XTNode::getBitSize(){return m_bitSize; }

unsigned int XTNode::getByteSize(){return getBitSize() / BIT_TO_BYTE; }	
