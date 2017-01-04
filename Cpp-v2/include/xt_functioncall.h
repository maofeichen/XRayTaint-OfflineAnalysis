#ifndef XT_FUNCTIONCALL_H
#define XT_FUNCTIONCALL_H 

#include <string>
#include <vector>

#include "xt_alivebuffer.h"
#include "xt_log.h"

class XT_FunctionCall
{
private:
	std::string m_callMarkFirst;
	std::string m_callMarkSecond;
	std::string m_retMarkFirst;
	std::string m_retMarkSecond;

	std::vector<std::string> m_str_vAliveBuffer;
	std::vector<XT_AliveBuffer> m_vAliveBuffer;

	XTLog m_xtLog;

	void merge_continuous_buffer();
	void create_continuous_buffer(std::vector<XTNode> &vNode);
	static bool compare_node(XTNode &firstNode, XTNode &secondNode);
	
public:
	XT_FunctionCall();
	XT_FunctionCall(std::vector<std::string> &s_vAliveBuffer,
					XTLog &xtLog);

	std::string getFirstCallMark();
	std::string getSecondCallMark();
	std::string getFirstRetMark();
	std::string getSecondRetMark();

	std::vector<XT_AliveBuffer> getAliveBuffers();	
};

#endif