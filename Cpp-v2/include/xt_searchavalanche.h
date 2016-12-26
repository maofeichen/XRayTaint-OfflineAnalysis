#ifndef XT_SEARCHAVALANCHE_H
#define XT_SEARCHAVALANCHE_H

#include "xt_data.h"
#include "xt_propagate.h"
#include <string>
#include <vector>
#include <unordered_set>

struct Buffer
{
	unsigned long beginAddr;
	unsigned int size;
};

struct BufferInOut
{
	Buffer in;
	Buffer out;
};

struct FunctionCallBuffer
{
	std::string callMark;
	std::string callSecMark;
	std::string retMark;
	std::string retSecMark;

	Buffer buffer;	
};

struct AvalancheRes{
	Buffer avalIn;
	std::vector<Buffer> vAvalOut;
};


// new struct to represent avalanche
// Uses Buffer directly instead of vector
struct AvalRes
{
	Buffer avalIn;
	Buffer avalOut;	
};

// Avalanche effect result
// All bytes of buffer in can propagate to all bytes of buffer out
struct AvalancheResBetweenInAndOut
{
	FunctionCallBuffer in;
	FunctionCallBuffer out;
	std::vector<AvalancheRes> vAvalacheRes;
};

// New representation of avalanche result
struct AvalResBetweenInOut
{
	FunctionCallBuffer in;
	FunctionCallBuffer out;
	std::vector<AvalRes> vAvalRes;
};

class SearchAvalanche
{
public:
	SearchAvalanche();
	// ~SearchAvalanche();
	SearchAvalanche(std::vector<Func_Call_Cont_Buf_t> v_funcCallContBuf, 
					std::vector<Rec> logAesRec);
	// std::vector<AvalancheResBetweenInAndOut> searchAvalanche();
	std::vector<AvalResBetweenInOut> searchAvalanche();

	void searchAvalancheDebug();
	void printAvalResBetweenInAndOut(AvalancheResBetweenInAndOut &avalResInOut);
	void printAvalResBetweenInAndOutNew(AvalResBetweenInOut &avalResInOut);
	void printAvalancheRes(AvalancheRes &avalRes);
	void printAvalancheResNew(AvalRes &avalRes);
	void printFunctionCallBuffer(FunctionCallBuffer &a);
	void printFuncCallContBuf(std::vector<Func_Call_Cont_Buf_t> &vFuncCallContBuf);
	void printBuffer(Buffer &a);

private:
	const unsigned int 	BIT_TO_BYTE			= 8;
	const unsigned int 	BUFFER_LEN			= 64;
	const unsigned long KERNEL_ADDR			= 0xC0000000;
	const unsigned int 	VALID_AVALANCHE_LEN	= 8;

	inline BufferInOut assignBufInOut(FunctionCallBuffer &in, FunctionCallBuffer &out);
	inline void clearAvalacheResult(AvalancheRes &avalRes, Buffer &avalIn, std::vector<Buffer> &vAvalOut);
	inline bool isDuplBufInOut(BufferInOut &bufInOut, std::vector<BufferInOut> &vBufInOut);
	inline std::string getInsnAddr(unsigned int &idx, std::vector<Rec> &vRec);
	inline bool isKernelAddress(unsigned int addr);
	inline bool isMarkMatch(std::string &mark, Rec &r);
	inline bool isInRange(unsigned long &addr, Node &node);
	inline bool isSameBuffer(FunctionCallBuffer &a, FunctionCallBuffer &b);
	inline bool isSameFunctionCall(FunctionCallBuffer &a, FunctionCallBuffer &b);
	inline bool isSameNode(NodePropagate &a, NodePropagate &b);

	inline void saveAvalancheResult(AvalancheRes &avalRes, Buffer &avalIn, std::vector<Buffer> &vAvalOut);
	inline void saveAvalResult(AvalResBetweenInOut &avalResInOut, Buffer &avalIn, std::vector<Buffer> &vAvalOut);


	void assignFunctionCallBuffer(FunctionCallBuffer &a, FunctionCallBuffer &b);
	std::vector<FunctionCallBuffer> getAvalancheInNewSearch(std::unordered_set<Node, NodeHash> &propagateResult, 
													   		FunctionCallBuffer &out);
	std::vector<Buffer> getAvalancheInFirstByte(std::unordered_set<Node, NodeHash> &propagateRes, 
												FunctionCallBuffer &out);
	std::vector<Buffer> getAvalancheInRestByte(Buffer &avalIn,
											   std::unordered_set<Node, NodeHash> &propagateRes, 
											   std::vector<Buffer> &vAvalOut);

	std::vector<Buffer> getAvalInRestByte(AvalResBetweenInOut &avalResInOut,
										  Buffer &avalIn,
										  std::unordered_set<Node, NodeHash> &propagateRes, 
										  std::vector<Buffer> &vAvalOut);

	Buffer getAvalancheInRestByteOneBuffer(std::unordered_set<Node, NodeHash> &propagateRes, Buffer &avalOut);
	std::vector<FunctionCallBuffer> getFunctionCallBuffer(std::vector<Func_Call_Cont_Buf_t> &v);	
	NodePropagate initialBeginNode(FunctionCallBuffer &buf, unsigned long &addr, std::vector<Rec> &logRec);

	AvalancheResBetweenInAndOut old_searchAvalancheBetweenInAndOut(FunctionCallBuffer &in, 
															   	   FunctionCallBuffer &out,
															       Propagate &propagate);
	AvalResBetweenInOut searchAvalancheBetweenInAndOut(FunctionCallBuffer &in, 
															   FunctionCallBuffer &out,
															   Propagate &propagate);
	void searchAvalancheBetweenInAndOut_IGNORE(FunctionCallBuffer &in, FunctionCallBuffer &out);
	void searchAvalancheBetweenInAndOutDebug(FunctionCallBuffer &in, FunctionCallBuffer &out);

	std::vector<Func_Call_Cont_Buf_t> m_vFuncCallContBuf;
	std::vector<Rec> m_logAesRec;
};
#endif