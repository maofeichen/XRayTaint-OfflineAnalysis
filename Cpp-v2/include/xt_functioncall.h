#ifndef XT_FUNCTIONCALL_H
#define XT_FUNCTIONCALL_H 

#include <string>
#include <vector>

#include "xt_alivebuffer.h"

class XT_FunctionCall
{
private:
	std::string m_callMarkFirst;
	std::string m_callMarkSecond;
	std::string m_retMarkFirst;
	std::string m_retMarkSecond;

	std::vector<XT_AliveBuffer> m_vAliveBuffer;
public:
	XT_FunctionCall();

	std::string getFirstCallMark();
	std::string getSecondCallMark();
	std::string getFirstRetMark();
	std::string getSecondRetMark();

	std::vector<XT_AliveBuffer> getAliveBuffers();	
};

#endif