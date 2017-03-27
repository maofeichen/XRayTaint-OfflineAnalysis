#include <algorithm>

#include "xt_constant.h"
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

void XT_FunctionCall::removeAliveBuffer(XT_AliveBuffer &aAliveBuffer)
{
	vector<XT_AliveBuffer>::iterator itAliveBuf = m_vAliveBuffer.begin();
	for(; itAliveBuf != m_vAliveBuffer.end(); ++itAliveBuf){
		if(aAliveBuffer.getBeginAddr() == (*itAliveBuf).getBeginAddr() && 
		   aAliveBuffer.getBufferBitSize() == (*itAliveBuf).getBufferBitSize() ){
			m_vAliveBuffer.erase(itAliveBuf);
			break;
		}
	}
}	

vector<XT_AliveBuffer> XT_FunctionCall::getAliveBuffers() {return m_vAliveBuffer; }


// Merge all continuous buffers if any for the particular function call
t_AliveFunctionCall XT_FunctionCall::merge_continuous_buffer()
{
	t_AliveFunctionCall aliveFunction;

	vector<XTNode> vNode;
	vector<string> vRecord;

	size_t len = m_str_vAliveBuffer.size();
	aliveFunction.call_mark 		= m_str_vAliveBuffer[0];
	aliveFunction.sec_call_mark 	= m_str_vAliveBuffer[1];
	aliveFunction.ret_mark 			= m_str_vAliveBuffer[len - 2];
	aliveFunction.sec_ret_mark		= m_str_vAliveBuffer[len - 1];

	vector<string>::iterator it = m_str_vAliveBuffer.begin() + 2;
	for(; it != m_str_vAliveBuffer.end() - 2; ++it){
		vRecord = XT_Util::split((*it).c_str(), '\t');
		string sIndex = vRecord.back();
		unsigned long index = stoul(sIndex, nullptr, 10);

		XTNode node;
		// unsigned int index = m_xtLog.findRecord(*it);

		if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) ){
			node = m_xtLog.getRecord(index).getSourceNode();
		}else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_ST) ){
			node = m_xtLog.getRecord(index).getDestinationNode();
		}

		vNode.push_back(node);
	}

	sort(vNode.begin(), vNode.end(), compare_node);

	create_continuous_buffer(vNode, aliveFunction);

	return aliveFunction;
}

void XT_FunctionCall::create_continuous_buffer(
	vector<XTNode> &vNode,
	t_AliveFunctionCall &aliveFunction)
{
	// XT_AliveBuffer aAliveBuffer;
	t_AliveContinueBuffer aliveBuffer;

	unsigned long accumulateBitSize = 0;
	unsigned long nodeIndex = vNode[0].getIndex();


	// Initialize first node
	vector<XTNode>::iterator it = vNode.begin();

	// aAliveBuffer.setBeginAddr(vNode[0].getIntAddr() );
	// aAliveBuffer.setBitSize(vNode[0].getBitSize() );
	// aAliveBuffer.addNode(vNode[0]);
	// aAliveBuffer.addIndex(nodeIndex);

	aliveBuffer.beginAddress 	= (*it).getIntAddr();
	aliveBuffer.size 			= (*it).getBitSize();
	aliveBuffer.vNodeIndex.push_back(nodeIndex);

	accumulateBitSize += (*it).getBitSize();

	for(++it; it != vNode.end(); ++it){
		// unsigned int current_addr = aAliveBuffer.getBeginAddr() + aAliveBuffer.getBufferByteSize();
		unsigned int current_addr = aliveBuffer.beginAddress + (aliveBuffer.size / BIT_TO_BYTE);

		// If contains
		if( current_addr > (*it).getIntAddr() ){
		    // Debug: uses only 1 source instead of multiple
			// continue;

		    nodeIndex = (*it).getIndex();
			aliveBuffer.vNodeIndex.push_back(nodeIndex);
		}
		// If continue
		else if( current_addr == (*it).getIntAddr() ){
			accumulateBitSize += (*it).getBitSize();
			nodeIndex = (*it).getIndex();
			// aAliveBuffer.increaseBitSize( (*it).getBitSize() );
			// aAliveBuffer.addIndex(nodeIndex);
			// aAliveBuffer.addNode(*it);

			aliveBuffer.size += (*it).getBitSize();
			aliveBuffer.vNodeIndex.push_back(nodeIndex);
		}
		// If discontinue
		else if(current_addr < (*it).getIntAddr() ){
			// Need to modify here also
			// Only for test
			// aliveFunction.vAliveContinueBuffer.push_back(aliveBuffer);
			
			if(accumulateBitSize / BIT_TO_BYTE > VALID_BYTE_SIZE){
				// m_vAliveBuffer.push_back(aAliveBuffer);
				aliveFunction.vAliveContinueBuffer.push_back(aliveBuffer);
			}

			// aAliveBuffer.clearAliveBuffer();
			// aAliveBuffer.setBeginAddr((*it).getIntAddr() );
			// aAliveBuffer.setBitSize((*it).getBitSize() );

			nodeIndex = (*it).getIndex();

			aliveBuffer.vNodeIndex.clear();
			aliveBuffer.beginAddress 	= (*it).getIntAddr();
			aliveBuffer.size 			= (*it).getBitSize();
			aliveBuffer.vNodeIndex.push_back(nodeIndex);

			// aAliveBuffer.addNode(*it);
			// aAliveBuffer.addIndex(nodeIndex);
			
			accumulateBitSize = (*it).getBitSize();
		}
	}
	// Modify here to test byte taint propagate!!!
	// Only for test 
	// aliveFunction.vAliveContinueBuffer.push_back(aliveBuffer);
	
	if(accumulateBitSize / BIT_TO_BYTE > VALID_BYTE_SIZE){
		// Only >= 8 bytes consider a valid buffer
		// m_vAliveBuffer.push_back(aAliveBuffer);
		aliveFunction.vAliveContinueBuffer.push_back(aliveBuffer);
	}
}

bool XT_FunctionCall::compare_node(XTNode &firstNode, XTNode &secondNode)
{
	return firstNode.getIntAddr() < secondNode.getIntAddr();
}
