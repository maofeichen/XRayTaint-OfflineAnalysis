#ifndef XT_SEARCHAVALANCHE_H
#define XT_SEARCHAVALANCHE_H

#include "xt_alivebuffer.h"
#include "xt_data.h"
#include "xt_functioncall.h"
#include "xt_log.h"
#include "xt_propagate.h"
#include <string>
#include <vector>
#include <unordered_set>

struct Buffer
{
	unsigned long beginAddr;
	unsigned int size;

	// std::vector<XTNode> vNode;
	std::vector<unsigned long> vNodeIndex;
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
	SearchAvalanche(std::vector<t_AliveFunctionCall> v_funcCallContBuf, 
					std::vector<Record> logAesRec);
	SearchAvalanche(std::vector<t_AliveFunctionCall> v_funcCallContBuf, 
					std::vector<Record> logAesRec,
					XTLog &xtLog);
	SearchAvalanche(std::vector<XT_FunctionCall> vAliveFunctionCall, 
					std::vector<t_AliveFunctionCall> v_funcCallContBuf, 
					std::vector<Record> logAesRec,
					XTLog &xtLog);

	// std::vector<AvalancheResBetweenInAndOut> searchAvalanche();
	std::vector<AvalResBetweenInOut> searchAvalanche();
	std::vector<AvalResBetweenInOut> detect_avalanche();

	void printAvalResBetweenInAndOut(AvalancheResBetweenInAndOut &avalResInOut);
	void printAvalResBetweenInAndOutNew(AvalResBetweenInOut &avalResInOut);
	void printAvalancheRes(AvalancheRes &avalRes);
	void printAvalancheResNew(AvalRes &avalRes);
	void printFunctionCallBuffer(FunctionCallBuffer &a);
	void printFuncCallContBuf(std::vector<t_AliveFunctionCall> &vFuncCallContBuf);
	void printBuffer(Buffer &a);

private:
	const unsigned int 	BIT_TO_BYTE			= 8;
	const unsigned int 	BUFFER_LEN			= 64;
	const unsigned long KERNEL_ADDR			= 0xC0000000;
	const unsigned int 	VALID_AVALANCHE_LEN	= 8;

	XTLog m_xtLog;

	std::vector<t_AliveFunctionCall> m_vFuncCallContBuf;
	std::vector<Record> m_logAesRec;
	std::vector<XT_FunctionCall> m_vAliveFunctionCall; 

	inline BufferInOut assignBufInOut(FunctionCallBuffer &in, FunctionCallBuffer &out);
	inline void clearAvalacheResult(AvalancheRes &avalRes, Buffer &avalIn, std::vector<Buffer> &vAvalOut);
	inline bool isDuplBufInOut(BufferInOut &bufInOut, std::vector<BufferInOut> &vBufInOut);
	inline std::string getInsnAddr(unsigned int &idx, std::vector<Record> &vRec);
	inline bool isKernelAddress(unsigned int addr);
	inline bool isMarkMatch(std::string &mark, Record &r);
	inline bool isInRange(unsigned long &addr, Node &node);
	inline bool isSameBuffer(FunctionCallBuffer &a, FunctionCallBuffer &b);
	inline bool isSameFunctionCall(FunctionCallBuffer &a, FunctionCallBuffer &b);
	inline bool isSameNode(NodePropagate &a, NodePropagate &b);

	inline void saveAvalancheResult(AvalancheRes &avalRes, Buffer &avalIn, std::vector<Buffer> &vAvalOut);
	inline void saveAvalResult(AvalResBetweenInOut &avalResInOut, Buffer &avalIn, std::vector<Buffer> &vAvalOut);

	// Computes the inteval to next different taint source
	inline unsigned long compu_multi_source_interval(std::vector<unsigned long> &v_node_idx, 
													 std::vector<unsigned long>::iterator it_node_idx);

	// Merge propagate result for multiple identical taint source
	inline void merge_propagate_res(std::unordered_set<Node, NodeHash> &propagateRes,
									std::unordered_set<Node, NodeHash> &propagate_res_merge);

	std::unordered_set<Node, NodeHash> compu_multi_propagate_res(unsigned int src_interval,
																 std::vector<unsigned long>::iterator it_idx_interval,
																 unsigned int byte_pos,
																 XTNode &node,
																 Propagate &propagate);


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
	std::vector<FunctionCallBuffer> getFunctionCallBuffer(std::vector<t_AliveFunctionCall> &v);

	XTNode getMemoryNode(unsigned long index);

	NodePropagate initialBeginNode(FunctionCallBuffer &buf, unsigned long &addr, std::vector<Record> &logRec);
	NodePropagate initPropagateSourceNode(XTNode &node, vector<Record> &logRecord);

	AvalResBetweenInOut searchAvalancheBetweenInAndOut(FunctionCallBuffer &in, 
													   FunctionCallBuffer &out,
													   Propagate &propagate);
};
#endif
