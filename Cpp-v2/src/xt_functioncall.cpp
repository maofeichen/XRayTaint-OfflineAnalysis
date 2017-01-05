#include <algorithm>
#include "xt_functioncall.h"
#include "xt_flag.h"
#include "xt_util.h"

using namespace std;

XT_FunctionCall::XT_FunctionCall() {}

XT_FunctionCall::XT_FunctionCall(vector<string> &s_vAliveBuffer,
								 XTLog &xtLog)
{
	m_str_vAliveBuffer = s_vAliveBuffer;
	m_xtLog = xtLog;

	size_t len = m_str_vAliveBuffer.size();
	m_callMarkFirst		= m_str_vAliveBuffer[0];
	m_callMarkSecond 	= m_str_vAliveBuffer[1];
	m_retMarkFirst 		= m_str_vAliveBuffer[len - 2];
	m_retMarkSecond 	= m_str_vAliveBuffer[len - 1];

	merge_continuous_buffer();
}

string XT_FunctionCall::getFirstCallMark() {return m_callMarkFirst; }

string XT_FunctionCall::getSecondCallMark() {return m_callMarkSecond; }

string XT_FunctionCall::getFirstRetMark() {return m_retMarkFirst; }

string XT_FunctionCall::getSecondRetMark() {return m_retMarkSecond; }

unsigned int XT_FunctionCall::getFunctionCAllEsp()
{
	string funcESP = "";
	vector<string> vFirstCallMark;
	unsigned int i_funcESP = 0;

	vFirstCallMark = XT_Util::split(m_callMarkFirst.c_str(), '\t');
	funcESP = vFirstCallMark[1];
	i_funcESP = stoul(funcESP, nullptr, 16);

	return i_funcESP;	
}

bool XT_FunctionCall::isHasAliveBuffer(XT_AliveBuffer &aAliveBuffer)
{
	bool isHas = false;

	vector<XT_AliveBuffer>::iterator it = m_vAliveBuffer.begin();
	for(; it != m_vAliveBuffer.end(); ++it){
		if( (*it).getBeginAddr() == aAliveBuffer.getBeginAddr() && 
			(*it).getBufferBitSize() == aAliveBuffer.getBufferBitSize() ){
			isHas = true;
			break;
		}
	}

	return isHas;
}

void XT_FunctionCall::addAliveBuffer(XT_AliveBuffer &aAliveBuffer)
{
	m_vAliveBuffer.push_back(aAliveBuffer);	
}

vector<XT_AliveBuffer> XT_FunctionCall::getAliveBuffers() {return m_vAliveBuffer; }


// Merge all continuous buffers if any for the particular function call
void XT_FunctionCall::merge_continuous_buffer()
{
	vector<XTNode> vNode;

	vector<string>::iterator it = m_str_vAliveBuffer.begin() + 2;
	for(; it != m_str_vAliveBuffer.end() - 2; ++it){
		XTNode node;
		unsigned int index = m_xtLog.findRecord(*it);

		if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) ){
			node = m_xtLog.getRecord(index).getSourceNode();
		}else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_ST) ){
			node = m_xtLog.getRecord(index).getDestinationNode();
		}

		vNode.push_back(node);
	}

	sort(vNode.begin(), vNode.end(), compare_node);

	create_continuous_buffer(vNode);
}

void XT_FunctionCall::create_continuous_buffer(vector<XTNode> &vNode)
{
	XT_AliveBuffer aAliveBuffer;

	// Initialize first node
	aAliveBuffer.setBeginAddr(vNode[0].getIntAddr() );
	aAliveBuffer.setBitSize(vNode[0].getBitSize() );
	aAliveBuffer.addNode(vNode[0]);

	vector<XTNode>::iterator it = vNode.begin();
	for(; it != vNode.end(); ++it){
		unsigned int current_addr = aAliveBuffer.getBeginAddr() + aAliveBuffer.getBufferByteSize();

		// If contains
		if( current_addr > (*it).getIntAddr() )
			continue;
		// If continue
		else if( current_addr == (*it).getIntAddr() ){
			aAliveBuffer.increaseBitSize( (*it).getBitSize() );
			aAliveBuffer.addNode(*it);
		}
		// If discontinue
		else if(current_addr < (*it).getIntAddr() ){
			m_vAliveBuffer.push_back(aAliveBuffer);
			aAliveBuffer.clearAliveBuffer();

			aAliveBuffer.setBeginAddr((*it).getIntAddr() );
			aAliveBuffer.setBitSize((*it).getBitSize() );
			aAliveBuffer.addNode(*it);
		}
	}

	// Do we need this? Is it correct?
	m_vAliveBuffer.push_back(aAliveBuffer);
}

bool XT_FunctionCall::compare_node(XTNode &firstNode, XTNode &secondNode)
{
	return firstNode.getIntAddr() < secondNode.getIntAddr();
}