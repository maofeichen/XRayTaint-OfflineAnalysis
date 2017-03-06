#include "xt_alivebuffer.h"
#include "xt_data.h"
#include "xt_flag.h"
#include "xt_searchavalanche.h"
#include "xt_util.h"

#include <cassert>
#include <iostream>

#define DEBUG 1

using namespace std;

SearchAvalanche::SearchAvalanche(){}

SearchAvalanche::SearchAvalanche(vector<t_AliveFunctionCall> v_funcCallContBuf,
								 vector<Record> logAesRec)
{
	m_vFuncCallContBuf = v_funcCallContBuf;
	m_logAesRec = logAesRec;
}

SearchAvalanche::SearchAvalanche(std::vector<t_AliveFunctionCall> v_funcCallContBuf, 
								 std::vector<Record> logAesRec,
								 XTLog &xtLog)
{
	m_vFuncCallContBuf = v_funcCallContBuf;
	m_logAesRec = logAesRec;
	m_xtLog = xtLog;
}

SearchAvalanche::SearchAvalanche(
	vector<XT_FunctionCall> vAliveFunctionCall, 
	vector<t_AliveFunctionCall> v_funcCallContBuf, 
	vector<Record> logAesRec,
	XTLog &xtLog)
{
	m_vAliveFunctionCall = vAliveFunctionCall;
	m_vFuncCallContBuf = v_funcCallContBuf;
	m_logAesRec = logAesRec;
	m_xtLog = xtLog;
}

// vector<AvalancheResBetweenInAndOut> 
vector<AvalResBetweenInOut> SearchAvalanche::searchAvalanche()
{
	vector<FunctionCallBuffer> v_functionCallBuffer;

	AvalResBetweenInOut avalResInOut_new;
	vector<AvalResBetweenInOut> vAvalRes_new;

    Propagate propagate(m_xtLog);

	BufferInOut bufInOut;
	vector<BufferInOut> vBufInOut;	// Duplicate In Out buffers check

	int numSearch;
	v_functionCallBuffer = getFunctionCallBuffer(m_vFuncCallContBuf);

	// print all continue buffers
	// printFuncCallContBuf(m_vFuncCallContBuf);

	cout << "Searching avalanche between buffers..." << endl;

	numSearch = 0;
	vector<FunctionCallBuffer>::iterator in = v_functionCallBuffer.begin();
	for(; in != v_functionCallBuffer.end() - 1; ++in){
		// if NOT kernel address and larger than 8 bytes
		if(in->buffer.size >= BUFFER_LEN && 
		   !isKernelAddress(in->buffer.beginAddr) ){

			vector<FunctionCallBuffer>::iterator out = in + 1;
			for(; out != v_functionCallBuffer.end(); ++out){

				if(!isSameFunctionCall(*in, *out) && 
				   out->buffer.size >= BUFFER_LEN && 
				   !isKernelAddress(out->buffer.beginAddr) && 
				   in->buffer.beginAddr != out->buffer.beginAddr){

				   	bufInOut = assignBufInOut(*in, *out);


				   	if(!isDuplBufInOut(bufInOut, vBufInOut) ){
				   		vBufInOut.push_back(bufInOut);

				   		cout << "----------------------------------------" << endl;
				   		cout << numSearch << " times search avalanche..." << endl;
						// Print in & out 
						cout << "Input buffer:" << endl;
					   	printFunctionCallBuffer(*in);
					   	cout << "----------" << endl;
					   	cout << "Output buffer: " << endl;
					   	printFunctionCallBuffer(*out);


					   	if(in->callMark == "14\tbffff4dc\t804a059\t" && \
					   	   in->buffer.beginAddr == 0xbffff764)
					   		cout << "Debug: in: 0xbffff764" << endl;

					   	// Uses new search instead
					   	// should pass hashmap of proproagate directly instead of propagate obj
					   	avalResInOut_new = searchAvalancheBetweenInAndOut(*in, *out, propagate);
					   	vAvalRes_new.push_back(avalResInOut_new);

					   	numSearch++;
				   	}
				}
			} // end inner for
		}
	} // end outter for
LABEL_OUTTER_LOOP:
	cout << "Total numbfer of seaching: " << numSearch << endl;
	cout << "search finish" << endl;

	return vAvalRes_new;
}

std::vector<AvalResBetweenInOut> 
SearchAvalanche::detect_avalanche()
{
	cout << "Detecting avalanche between alive function calls..." << endl;

	AvalResBetweenInOut avalResInOut;
	vector<AvalResBetweenInOut> vAvalRes;

	Propagate pg(m_xtLog);

	// Store which IN and OUT buffer had been searched already
	vector<BufferInOut> vBufferInOut;

	unsigned int numSearch = 1;

	// size_t numFunction = m_vFuncCallContBuf.size();
	vector<t_AliveFunctionCall>::iterator itInFunction = m_vFuncCallContBuf.end() - 2;

	// vector<t_AliveFunctionCall>::iterator itInFunction = m_vFuncCallContBuf.begin();
	for(; itInFunction != m_vFuncCallContBuf.end() - 1; ++itInFunction){

		vector<t_AliveFunctionCall>::iterator itOutFunction = itInFunction + 1;
		for(; itOutFunction != m_vFuncCallContBuf.end(); ++itOutFunction){

			// iterate each alive buffer in in function call
			vector<t_AliveContinueBuffer> vCurrentINBuf = (*itInFunction).vAliveContinueBuffer;
			vector<t_AliveContinueBuffer>::iterator itInBuf = vCurrentINBuf.begin();
			for(; itInBuf != vCurrentINBuf.end(); ++itInBuf){

				// iterate each alive buffer in out function call
				vector<t_AliveContinueBuffer> v_current_out_buf = (*itOutFunction).vAliveContinueBuffer;
				vector<t_AliveContinueBuffer>::iterator itOutBuf = v_current_out_buf.begin();
				for(; itOutBuf != v_current_out_buf.end(); ++itOutBuf){

					if(	(*itInBuf).beginAddress  != (*itOutBuf).beginAddress  ){
						FunctionCallBuffer in;
						FunctionCallBuffer out;

						in.callMark 	= (*itInFunction).call_mark;
						in.callSecMark 	= (*itInFunction).sec_call_mark;
						in.retMark 		= (*itInFunction).ret_mark;
						in.retSecMark 	= (*itInFunction).sec_ret_mark;
						in.buffer.beginAddr 	= (*itInBuf).beginAddress ;
						in.buffer.size 			= (*itInBuf).size;
						in.buffer.vNodeIndex 	= (*itInBuf).vNodeIndex;

						out.callMark 	= (*itOutFunction).call_mark;
						out.callSecMark = (*itOutFunction).sec_call_mark;
						out.retMark 	= (*itOutFunction).ret_mark;
						out.retSecMark 	= (*itOutFunction).sec_ret_mark;
						out.buffer.beginAddr 	= (*itOutBuf).beginAddress ;
						out.buffer.size 	 	= (*itOutBuf).size;
						out.buffer.vNodeIndex 	= (*itOutBuf).vNodeIndex;

						BufferInOut bufInOut;
						bufInOut.in.beginAddr 	= in.buffer.beginAddr;
						bufInOut.in.size 		= in.buffer.size;
						bufInOut.out.beginAddr 	= out.buffer.beginAddr;
						bufInOut.out.size 		= out.buffer.size;


						if(isDuplBufInOut(bufInOut, vBufferInOut) ){
							cout << "In and Out buffers had been searched, skip..." << endl;
						}else{
							cout << "IN buffer: " << endl;
							printFunctionCallBuffer(in);
						   	cout << "----------" << endl;
						   	cout << "Output buffer: " << endl;
						   	printFunctionCallBuffer(out);

							cout << "----------------------------------------" << endl;
							cout << "Searching IN and Out: " << numSearch << endl;

							vBufferInOut.push_back(bufInOut);

							avalResInOut = searchAvalancheBetweenInAndOut(in, out, pg);
							vAvalRes.push_back(avalResInOut);

							// if(in.buffer.beginAddr == 0xbffff70c /* && 
							// 	out.buffer.beginAddr == 0xbffff6fc */ ){
							// 	avalResInOut = searchAvalancheBetweenInAndOut(in, out, pg);
							// 	vAvalRes.push_back(avalResInOut);
							// }

							numSearch++;
						}
					}
				}	
			}
		}
	}

	cout << "Total numbfer of search: " << numSearch << endl;

	return vAvalRes;
}

// Given function call buffer in and out, assigns them to a struct <in, out>
// for duplicate in and out buffer checking
inline BufferInOut SearchAvalanche::assignBufInOut(FunctionCallBuffer &in, FunctionCallBuffer &out)
{
	BufferInOut bufInOut;

	bufInOut.in.beginAddr = in.buffer.beginAddr;
	bufInOut.in.size = in.buffer.size;

	bufInOut.out.beginAddr = out.buffer.beginAddr;
	bufInOut.out.size = out.buffer.size;

	return bufInOut;
}

inline void SearchAvalanche::clearAvalacheResult(AvalancheRes &avalRes, 
												 Buffer &avalIn, std::vector<Buffer> &vAvalOut)
{
	avalRes.avalIn.beginAddr = 0;
	avalRes.avalIn.size = 0;
	avalRes.vAvalOut.clear();

	avalIn.beginAddr = 0;
	avalIn.size = 0;
	
	vAvalOut.clear();
}

inline bool SearchAvalanche::isDuplBufInOut(BufferInOut &bufInOut, vector<BufferInOut> &vBufInOut)
{
	if(vBufInOut.empty())
		return false;

	for(vector<BufferInOut>::iterator it = vBufInOut.begin(); it != vBufInOut.end(); ++it){
		if(it->in.beginAddr == bufInOut.in.beginAddr && 
		   it->in.size == bufInOut.in.size && 
		   it->out.beginAddr == bufInOut.out.beginAddr &&
		   it->out.size == bufInOut.out.size)
			return true;
	}

	return false;
}

inline string SearchAvalanche::getInsnAddr(unsigned int &idx, vector<Record> &vRec)
{
	unsigned int i = idx;
	while(i > 0){
		if(vRec[i].isMark &&
           XT_Util::equal_mark(vRec[i].regular.src.flag, flag::XT_INSN_ADDR) )
			return vRec[i].regular.src.addr;
		i--;
   }
   return "";
}

// Is the hardcode correct?
inline bool SearchAvalanche::isKernelAddress(unsigned int addr)
{
	if(addr > KERNEL_ADDR)
		return true;
	else
		return false;
}

inline bool SearchAvalanche::isMarkMatch(string &mark, Record &r)
{
	vector<string> vMark;

	vMark = XT_Util::split(mark.c_str(), '\t');
	if(vMark[0] == r.regular.src.flag && 
	   vMark[1] == r.regular.src.addr && 
	   vMark[2] == r.regular.src.val)
		return true;
	else return false;
}

// Determines if the given address is in the range of given node
// !!! Notice it MUST be < (NOT <= ) 
inline bool SearchAvalanche::isInRange(unsigned long &addr, Node &node)
{
	if(addr >= node.i_addr && addr < node.i_addr + node.sz / BIT_TO_BYTE)
		return true;
	else return false;
}

inline bool SearchAvalanche::isSameBuffer(FunctionCallBuffer &a, FunctionCallBuffer &b)
{
	if(a.buffer.beginAddr == b.buffer.beginAddr &&
		a.buffer.size == b.buffer.size)
		return true;
	else
		return false;
}

inline bool SearchAvalanche::isSameFunctionCall(FunctionCallBuffer &a, FunctionCallBuffer &b)
{
	if(a.callMark == b.callMark && 
	   a.callSecMark == b.callSecMark && 
	   a.retMark == b.retMark && 
	   a.retSecMark == b.retSecMark)
		return true;
	else return false;
}

inline bool SearchAvalanche::isSameNode(NodePropagate &a, NodePropagate &b)
{
	if(a.isSrc 		== b.isSrc && 
	   a.id 		== b.id && 
	   a.parentId 	== b.parentId && 
	   a.layer		== b.layer && 
	   a.pos 		== b.pos && 
	   a.insnAddr 	== b.insnAddr && 
	   a.n.flag 	== b.n.flag && 
	   a.n.addr 	== b.n.addr && 
	   a.n.val 		== b.n.val && 
	   a.n.i_addr 	== b.n.i_addr && 
	   a.n.sz 		== b.n.sz)
		return true;
	else return false;
}

inline void SearchAvalanche::saveAvalancheResult(AvalancheRes &avalRes, Buffer &avalIn, std::vector<Buffer> &vAvalOut)
{
	avalRes.avalIn.beginAddr = avalIn.beginAddr;
	avalRes.avalIn.size = avalIn.size;

	for(auto s : vAvalOut){
		avalRes.vAvalOut.push_back(s);
	}
}

inline void SearchAvalanche::saveAvalResult(AvalResBetweenInOut &avalResInOut, Buffer &avalIn, std::vector<Buffer> &vAvalOut)
{
	AvalRes avalRes;

	avalRes.avalIn = avalIn;

	for(auto s : vAvalOut){
		avalRes.avalOut.beginAddr = s.beginAddr;
		avalRes.avalOut.size = s.size;
		avalResInOut.vAvalRes.push_back(avalRes);
	}
}

inline unsigned long SearchAvalanche::compu_multi_source_interval(vector<unsigned long> &v_node_idx, 
													 			  vector<unsigned long>::iterator it_node_idx)
{
	unsigned long count = 0;

	XTNode node = getMemoryNode(*it_node_idx);
	unsigned long begin_addr = node.getIntAddr();

	for(; it_node_idx != v_node_idx.end(); ++it_node_idx){
		node = getMemoryNode(*it_node_idx);
		count++;

		if(begin_addr != node.getIntAddr() )
			break;
	}	

	return count;
}

inline void SearchAvalanche::merge_propagate_res(unordered_set<Node, NodeHash> &propagateRes,
												 unordered_set<Node, NodeHash> &propagate_res_merge) 
{
	unordered_set<Node,NodeHash>::iterator it = propagateRes.begin();
	for(; it != propagateRes.end(); ++it){
		propagate_res_merge.insert(*it);
	}	
}

unordered_set<Node, NodeHash> 
SearchAvalanche::compu_multi_propagate_res(unsigned int src_interval,
										   vector<unsigned long>::iterator it_idx_interval,
										   unsigned int byte_pos,
										   XTNode &node,
										   Propagate &propagate)
{
	unordered_set<Node, NodeHash> propagateRes;
	unordered_set<Node, NodeHash> propagate_res_merge;

	NodePropagate s;

	for(int idx = 0; idx < src_interval - 1; idx++){
		node = getMemoryNode(*it_idx_interval);
		s = initPropagateSourceNode(node, m_logAesRec);

		propagateRes = propagate.getPropagateResult(s, m_logAesRec, byte_pos);
		merge_propagate_res(propagateRes, propagate_res_merge);

		it_idx_interval++;
	}

	return propagate_res_merge;
}

void SearchAvalanche::assignFunctionCallBuffer(FunctionCallBuffer &a, FunctionCallBuffer &b)
{
	a.callMark = b.callMark;
	a.callSecMark = b.callSecMark;
	a.retMark = b.retMark;
	a.retSecMark = b.retSecMark;
	a.buffer.beginAddr = b.buffer.beginAddr;
	a.buffer.size = b.buffer.size;
}

NodePropagate SearchAvalanche::initialBeginNode(FunctionCallBuffer &buf, 
												unsigned long &addr,
												vector<Record> &logRec)
{
	NodePropagate s;
	Node node;
	bool isFound;
	int functionCallIdx = 0;
	unsigned int recordIdx = 0;

	// locate the function call position
	vector<Record>::iterator it = logRec.begin();
	for(; it != logRec.end(); ++it){
		if(it->isMark){
			if(isMarkMatch(buf.callMark, *it) && 
			   isMarkMatch(buf.callSecMark, *(it + 1) ) ){
				functionCallIdx = it - logRec.begin();
				break;
			}
		}
	}

#ifdef DEBUG
	// functionCallIdx is the index of callMark in logRec vector
	// if(functionCallIdx != 0)
	// 	cout << "Function Call Idx: " << functionCallIdx << endl;
#endif

	if(functionCallIdx != 0){
		vector<Record>::iterator it = logRec.begin() + functionCallIdx;
		for(; it != logRec.end(); ++it){
			if(!it->isMark){
				if(XT_Util::equal_mark(it->regular.src.flag, flag::TCG_QEMU_LD) ){
					if(isInRange(addr, it->regular.src) ){
						isFound = true;
						recordIdx = it - logRec.begin();
						break;
					}
				} else if(XT_Util::equal_mark(it->regular.src.flag, flag::TCG_QEMU_ST) ){
					if(isInRange(addr, it->regular.dst) ){
						isFound = true;
						recordIdx = it - logRec.begin();
						break;
					}
				}
			} // end if !it->isMark
		}
	}

	assert(isFound == true);
	if(isFound){
		if(XT_Util::equal_mark(logRec[recordIdx].regular.src.flag, flag::TCG_QEMU_LD) ){
			node = logRec[recordIdx].regular.src;
			s.isSrc = true;
			s.id = recordIdx * 2;
		} else if(XT_Util::equal_mark(logRec[recordIdx].regular.src.flag, flag::TCG_QEMU_ST) ){
			node = logRec[recordIdx].regular.dst;
			s.isSrc = false;
			s.id = recordIdx * 2 + 1;
		}
		s.parentId	= 0;
		s.layer		= 0;
		s.pos 		= recordIdx;
		s.insnAddr 	= getInsnAddr(recordIdx, logRec);
		s.n.flag 	= node.flag;
		s.n.addr 	= node.addr;
		s.n.val 	= node.val;
		s.n.i_addr 	= node.i_addr;
		s.n.sz 		= node.sz;
	}

	return s;
}

NodePropagate 
SearchAvalanche::initPropagateSourceNode(
	XTNode &node,
	vector<Record> &logRecord)
{
	NodePropagate source;
	unsigned int recordIndex = node.getIndex();

	string sflag = node.getFlag();
	if(XT_Util::equal_mark(sflag, flag::TCG_QEMU_LD) ){
		source.isSrc 	= true;
		source.id 		= node.getIndex() * 2;
	}else if(XT_Util::equal_mark(sflag, flag::TCG_QEMU_ST) ){
		source.isSrc 	= false;
		source.id 		= node.getIndex() * 2 + 1;
	}

	source.parentId 	= 0;
	source.layer 		= 0;
	source.pos 			= recordIndex;
	source.insnAddr 	= getInsnAddr(recordIndex, logRecord);
	source.n.flag 		= node.getFlag();
	source.n.addr 		= node.getAddr();
	source.n.val 		= node.getVal();
	source.n.i_addr 	= node.getIntAddr();
	source.n.sz 		= node.getBitSize();

	return source;
}

// Given the propagate result of in, and continuous out buffer,
// returns the intersection of the two (essentially the avalanche effect)
vector<FunctionCallBuffer> SearchAvalanche::getAvalancheInNewSearch(unordered_set<Node, NodeHash> &propagateResult, 
											  				   	    FunctionCallBuffer &out)
{
	vector<FunctionCallBuffer> vFuncCallBuffer;
	FunctionCallBuffer funcCallBuffer;
	unsigned long addr;
	unsigned int size, numPropagateByte;
	bool isHit;

	funcCallBuffer.callMark 	= out.callMark;
	funcCallBuffer.callSecMark 	= out.callSecMark;
	funcCallBuffer.retMark 		= out.retMark;
	funcCallBuffer.retSecMark 	= out.retSecMark;	
	// funcCallBuffer.buffer.beginAddr = out.buffer.beginAddr;
	funcCallBuffer.buffer.size 	= 0;

	addr = out.buffer.beginAddr;
	size = out.buffer.size / BIT_TO_BYTE;
	numPropagateByte = 0;

	for(int byteIdx = 0; byteIdx < size; byteIdx++){
		isHit = false;
		for(auto s : propagateResult){
			if(addr >= s.i_addr && addr < s.i_addr + s.sz / BIT_TO_BYTE){
				isHit = true;
				numPropagateByte++;
				break;
			}
		}
		if(isHit){
			if(numPropagateByte == 1)
				funcCallBuffer.buffer.beginAddr = addr;
			funcCallBuffer.buffer.size += 1 * BIT_TO_BYTE;
		} else{
			if(numPropagateByte >= VALID_AVALANCHE_LEN)
				vFuncCallBuffer.push_back(funcCallBuffer);
			else{
				numPropagateByte = 0;
			}
		}
		addr++;
	}

	// push the last avalache buffer if it is valid
	if(funcCallBuffer.buffer.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN)
		vFuncCallBuffer.push_back(funcCallBuffer);

	return vFuncCallBuffer;
}

vector<Buffer> SearchAvalanche::getAvalancheInFirstByte(std::unordered_set<Node, NodeHash> &propagateRes, 
														FunctionCallBuffer &out)
{

}

vector<Buffer> SearchAvalanche::getAvalancheInRestByte(Buffer &avalIn,
													   unordered_set<Node, NodeHash> &propagateRes, 
									  				   vector<Buffer> &vAvalOut)
{
	Buffer buf;
	vector<Buffer> vAvalOutNew;

	for(vector<Buffer>::iterator it = vAvalOut.begin(); it != vAvalOut.end(); ++it){
		buf = getAvalancheInRestByteOneBuffer(propagateRes, *it);
		if(buf.beginAddr != 0 && 
		   buf.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN)
			vAvalOutNew.push_back(buf);
	}

	return vAvalOutNew; 
}

vector<Buffer> SearchAvalanche::getAvalInRestByte(AvalResBetweenInOut &avalResInOut,
												  Buffer &avalIn,
												  std::unordered_set<Node, NodeHash> &propagateRes, 
												  std::vector<Buffer> &vAvalOut)
{
	Buffer buf;
	vector<Buffer> vAvalOutNew;

	AvalRes avalRes;

	for(vector<Buffer>::iterator it = vAvalOut.begin(); it != vAvalOut.end(); ++it){
		buf = getAvalancheInRestByteOneBuffer(propagateRes, *it);

		if(buf.beginAddr != 0 && 
		   buf.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN)
			vAvalOutNew.push_back(buf);
		else{	// if intersect result <= VALIND_AVALANCHE_LEN
			// is in and out size > VALIND_AVALANCHE_LEN 
			if(avalIn.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN && 
				(*it).size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN){
				avalRes.avalIn = avalIn;
				avalRes.avalOut = *it;
				avalResInOut.vAvalRes.push_back(avalRes);
			} 

		}
	}

	return vAvalOutNew;
}

Buffer SearchAvalanche::getAvalancheInRestByteOneBuffer(unordered_set<Node, NodeHash> &propagateRes, 
														Buffer &avalOut)
{
	Buffer buf;

	unsigned int byteIndex, numPropagateByte;
	unsigned long addr;
	bool isHit;

	buf.beginAddr = 0;
	buf.size = 0;

	numPropagateByte = 0;
	addr = avalOut.beginAddr;
	
	for(byteIndex = 0; byteIndex < (avalOut.size / BIT_TO_BYTE); byteIndex++){
		isHit = false;
		for(auto s : propagateRes){
			if(addr >= s.i_addr && addr < s.i_addr + s.sz / BIT_TO_BYTE){
				isHit = true;
				numPropagateByte++;
				break;
			}
		}
		if(isHit){
			if(numPropagateByte == 1)
				buf.beginAddr = addr;
			buf.size += 1 * BIT_TO_BYTE;
		} else{
			if(numPropagateByte >= VALID_AVALANCHE_LEN)
				break;
			else{
				// No valid propagate result
				buf.beginAddr = 0;
				buf.size = 0;
				break;
			}
		}
		addr++;
	}
	return buf;
}

// Transfers t_AliveFunctionCall to FunctionCallBuffer.
// In t_AliveFunctionCall, each pair of call and ret mark may have multiple
// continuous buffers.
// But in FunctionCallBuffer, each pair of call and ret mark only have one
// continous buffer, even there might be repeated marks in the results.
vector<FunctionCallBuffer> SearchAvalanche::getFunctionCallBuffer(vector<t_AliveFunctionCall> &v)
{
	vector<FunctionCallBuffer> v_new;
	FunctionCallBuffer f;

	for(auto s : v){
		for(auto t : s.vAliveContinueBuffer){
			f.callMark = s.call_mark;
			f.callSecMark = s.sec_call_mark;
			f.retMark = s.ret_mark;
			f.retSecMark = s.sec_ret_mark;
			f.buffer.beginAddr = t.beginAddress;
			f.buffer.size = t.size;

			v_new.push_back(f);
		}
	}
	return v_new;
}

XTNode SearchAvalanche::getMemoryNode(unsigned long index)
{
	XTNode node;
	XTRecord record = m_xtLog.getRecord(index);
	XTNode srcNode = record.getSourceNode();
	string srcFlag = srcNode.getFlag();
	if(XT_Util::equal_mark(srcFlag, flag::TCG_QEMU_LD) )
		node = srcNode;
	else if(XT_Util::equal_mark(srcFlag, flag::TCG_QEMU_ST) )
		node = record.getDestinationNode();
	else
		cout << "Record index: " << index << " neither load or store node, error..." << endl;

	return node;
}

AvalResBetweenInOut 
SearchAvalanche::searchAvalancheBetweenInAndOut(
	FunctionCallBuffer &in, 
    FunctionCallBuffer &out,
    Propagate &propagate)
{
	NodePropagate s;
	NodePropagate curr_s;
	NodePropagate prev_s;
	unordered_set<Node, NodeHash> propagateRes;
	unordered_set<Node, NodeHash> propagate_res_merge;

	unsigned long inBeginAddr;
	unsigned int numInByteAccumulate; 
	unsigned int byteIndex;
	unsigned int byte_pos;
	unsigned int src_interval = 0;

	Buffer avalIn;
	vector<Buffer> vAvalOut;
	vector<FunctionCallBuffer> vFuncAvalOut;

	AvalancheRes avalRes;
	AvalancheResBetweenInAndOut avalResInOut;

	AvalRes avalRes_new;
	AvalResBetweenInOut avalResInOut_new;

	avalIn.beginAddr = 0;
	avalIn.size = 0;
	vAvalOut.clear();

	avalRes.avalIn.beginAddr = 0;
	avalRes.avalIn.size = 0;
	avalRes.vAvalOut.clear();

	assignFunctionCallBuffer(avalResInOut_new.in, in);
	assignFunctionCallBuffer(avalResInOut_new.out, out);

	// assignFunctionCallBuffer(avalResInOut.in, in);
	// assignFunctionCallBuffer(avalResInOut.out, out);
	avalResInOut.vAvalacheRes.clear();

	byteIndex 			= 0;
	numInByteAccumulate = 0;
	inBeginAddr 		= in.buffer.beginAddr;
	byte_pos 			= 0;

	// vector<XTNode>::iterator itNode = in.buffer.vNode.begin();
	vector<unsigned long>::iterator itNodeIndex = in.buffer.vNodeIndex.begin();

// Process first stage
LABEL_S_ONE:
	// XTNode inNode = in.buffer.vNode[0];
	// while(byteIndex < in.buffer.size / BIT_TO_BYTE){
	while(itNodeIndex != in.buffer.vNodeIndex.end() ){
		// s = initialBeginNode(in, inBeginAddr, m_logAesRec);
		XTNode node;
		src_interval = compu_multi_source_interval(in.buffer.vNodeIndex, itNodeIndex);
		vector<unsigned long>::iterator it_idx_interval = itNodeIndex;
		// for(int idx = 0; idx < src_interval - 1; idx++){
		// 	node = getMemoryNode(*it_idx_interval);
		// 	s = initPropagateSourceNode(node, m_logAesRec);
		// 	cout << "search propagation, taint source: " << hex << inBeginAddr << endl; 

		// 	propagateRes = propagate.getPropagateResult(s, m_logAesRec, byte_pos);
		// 	merge_propagate_res(propagateRes, propagate_res_merge);

		// 	it_idx_interval++;
		// }
		propagate_res_merge = compu_multi_propagate_res(src_interval, it_idx_interval, byte_pos,
														node, propagate);

		// XTNode node = getMemoryNode(*itNodeIndex);
		// s = initPropagateSourceNode(node, m_logAesRec);

		cout << "search propagation, taint source: " << hex << inBeginAddr << endl; 

		// propagateRes = propagate.getPropagateResult(s, m_logAesRec, byte_pos);
		// vFuncAvalOut = getAvalancheInNewSearch(propagateRes, out);

		vFuncAvalOut = getAvalancheInNewSearch(propagate_res_merge, out);

		// if 1st byte can propagate to any valid subset of out?
		if(!vFuncAvalOut.empty() ){
			// we don't need vFuncAvalOut, only need vAvalOut
			// need to transfer
			for(vector<FunctionCallBuffer>::iterator it = vFuncAvalOut.begin(); 
				it != vFuncAvalOut.end(); ++it){
				Buffer buf;
				buf.beginAddr = it->buffer.beginAddr;
				buf.size = it->buffer.size;
				vAvalOut.push_back(buf);
			}
			// 1st byte has propagate result, init avalIn
			avalIn.beginAddr = inBeginAddr;
			// avalIn.size = 1 * BIT_TO_BYTE;
			// avalIn.size = node.getBitSize();
			// only has 1 byte currently
			avalIn.size = node.getBitSize() / BIT_TO_BYTE;

			byteIndex++;
			numInByteAccumulate++;
			inBeginAddr++;
			byte_pos++;

			// byteIndex += node.getByteSize();
			// numInByteAccumulate += node.getByteSize();
			// inBeginAddr += node.getByteSize();

			curr_s = s;
			// Not go to next node yet
			// ++itNodeIndex;
			goto LABEL_S_TWO;		
		} else{
			byteIndex++;
			inBeginAddr++;
			byte_pos++;

			// if cross 4 bytes, reset and goto next node
			if(byte_pos > 3){
				byte_pos = 0;
				// ++itNodeIndex;
				// instead of plus 1, plus the interval
				itNodeIndex += src_interval;
			}

			// byteIndex += node.getByteSize();
			// inBeginAddr += node.getByteSize();
			// ++itNodeIndex;
		}
	}

LABEL_S_TWO:
	// while(byteIndex < in.buffer.size / BIT_TO_BYTE){
	while( itNodeIndex != in.buffer.vNodeIndex.end() ){
		prev_s = curr_s;
		// curr_s = initialBeginNode(in, inBeginAddr, m_logAesRec);

		cout << "search propagation, taint source: " << hex << inBeginAddr << endl; 
	
		XTNode node;
		src_interval = compu_multi_source_interval(in.buffer.vNodeIndex, itNodeIndex);
		vector<unsigned long>::iterator it_idx_interval = itNodeIndex;
		propagate_res_merge = compu_multi_propagate_res(src_interval, it_idx_interval, byte_pos,
														node, propagate);
		
		// XTNode node = getMemoryNode(*itNodeIndex);
		// curr_s = initPropagateSourceNode(node, m_logAesRec);
		// cout << "search propagation, taint source: " << hex << inBeginAddr << endl; 
		// propagateRes = propagate.getPropagateResult(curr_s, m_logAesRec, byte_pos);
		// vAvalOut = getAvalInRestByte(avalResInOut_new, avalIn, propagateRes, vAvalOut);
		vAvalOut = getAvalInRestByte(avalResInOut_new, avalIn, propagate_res_merge, vAvalOut);

		// No need this optimize now, because we use byte to byte search
		// if(!isSameNode(prev_s, curr_s)){
		// 	// propagateRes = propagate.getPropagateResult(s, m_logAesRec);
  //           // should be curr_s?
  //           propagateRes = propagate.getPropagateResult(curr_s, m_logAesRec);
		// 	vAvalOut = getAvalInRestByte(avalResInOut_new, avalIn, propagateRes, vAvalOut);
		// }

		if(!vAvalOut.empty() ){
			// can propagate, accumulate size
			avalIn.size += 1 * BIT_TO_BYTE;
			byteIndex++;
			numInByteAccumulate++;
			inBeginAddr++;
			byte_pos++;

			// avalIn.size += node.getBitSize();
			// byteIndex += node.getByteSize();
			// numInByteAccumulate += node.getByteSize();
			// inBeginAddr += node.getByteSize();

			// ++itNodeIndex;
		} else{
			// no need?
			// clear avalIn, vAvalOut
			if(numInByteAccumulate >= VALID_AVALANCHE_LEN){
				// save avalIn, vAvalOut to AvalancheRes
				saveAvalancheResult(avalRes, avalIn, vAvalOut);
				avalResInOut.vAvalacheRes.push_back(avalRes);
			}
			clearAvalacheResult(avalRes, avalIn, vAvalOut);

			numInByteAccumulate = 0;
			// byteIndex++;
			// inBeginAddr++;

			// Should not incremental the byte
			// numInByteAccumulate += node.getByteSize();
			// inBeginAddr += node.getByteSize();
			// ++itNodeIndex;
			goto LABEL_S_ONE;
		}

		if(byte_pos > 3){
			byte_pos = 0;
			// ++itNodeIndex;
			// instead of plus 1, plus the interval
			itNodeIndex += src_interval;
		}
	}

	// if all bytes of in can propagate to all of out
	if(avalIn.beginAddr != 0 && 
	   avalIn.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN && 
	   // avalIn.size >= VALID_AVALANCHE_LEN && 
	   !vAvalOut.empty() ){
	   	saveAvalResult(avalResInOut_new, avalIn, vAvalOut);
		// saveAvalancheResult(avalRes, avalIn, vAvalOut);
		// avalResInOut.vAvalacheRes.push_back(avalRes);
	}

	return avalResInOut_new;
}

void SearchAvalanche::printAvalResBetweenInAndOut(AvalancheResBetweenInAndOut &avalResInOut)
{
	cout << "Search Avalache Input Buffer: " << endl;
	printFunctionCallBuffer(avalResInOut.in);
	cout << "----------" << endl;
	cout << "Search Avalache Output Buffer: " << endl;
	printFunctionCallBuffer(avalResInOut.out);
	cout << "----------" << endl;
	if(!avalResInOut.vAvalacheRes.empty() ){
		for(auto s : avalResInOut.vAvalacheRes){
			printAvalancheRes(s);
		}
	} else
		cout << "no avalanche found between the input and output buffer" << endl;
}

void SearchAvalanche::printAvalResBetweenInAndOutNew(AvalResBetweenInOut &avalResInOut)
{
	cout << "Search Avalache Input Buffer: " << endl;
	printFunctionCallBuffer(avalResInOut.in);
	cout << "----------" << endl;
	cout << "Search Avalache Output Buffer: " << endl;
	printFunctionCallBuffer(avalResInOut.out);
	cout << "----------" << endl;

	if(!avalResInOut.vAvalRes.empty() ){
		for(auto s : avalResInOut.vAvalRes ){
			printAvalancheResNew(s);
		}
	}else
		cout << "no avalanche found between the input and output buffer" << endl;
}

void SearchAvalanche::printFunctionCallBuffer(FunctionCallBuffer &a)
{
	cout << "Call Mark: " << a.callMark << endl;
	cout << "Sec Call Mark: " << a.callSecMark << endl;
	cout << "Ret Mark: " << a.retMark << endl;
	cout << "Sec Ret Mark: " << a.retSecMark << endl;
	cout << "----------" << endl;
	cout << "Buffer Begin Addr: " << hex << a.buffer.beginAddr << endl;
	cout << "Buffer Size: " << dec << a.buffer.size / BIT_TO_BYTE << endl; 
}

void SearchAvalanche::printAvalancheRes(AvalancheRes &avalRes)
{
	cout << "avalache effect from buffer: " << endl;
	cout << "Buffer begin addr: " << hex << avalRes.avalIn.beginAddr << endl;
	cout << "Buffer size: " << dec << avalRes.avalIn.size / BIT_TO_BYTE << endl;

	cout << "avalache effect to buffers: " << endl;
	for(auto s : avalRes.vAvalOut)
		printBuffer(s);

}

void SearchAvalanche::printAvalancheResNew(AvalRes &avalRes)
{
	cout << "avalache effect from buffer: " << endl;
	printBuffer(avalRes.avalIn);
	cout << "avalache effect to buffers: " << endl;
	printBuffer(avalRes.avalOut);
	cout << "-----" << endl;
}

void SearchAvalanche::printFuncCallContBuf(std::vector<t_AliveFunctionCall> &vFuncCallContBuf)
{
	int funcCallIndex;
	int contBufIndex;
	int numTotalContBuf;

	cout << "Number of funcation calls: " << vFuncCallContBuf.size() << endl;

	funcCallIndex = 0;
	numTotalContBuf = 0;
	for (auto s : vFuncCallContBuf){
		cout << "Function Call Index: " << funcCallIndex << endl;
		cout << "Call Mark: " << s.call_mark << endl;
		cout << "Sec Call Mark: " << s.sec_call_mark << endl;
		cout << "Ret Mark: " << s.ret_mark << endl;
		cout << "Sec Ret Mark: " << s.sec_ret_mark << endl;

		cout << "continuous buffers in this function call: " << endl;
		contBufIndex = 0;
		for(auto t : s.vAliveContinueBuffer){
			if(t.size / BIT_TO_BYTE > VALID_AVALANCHE_LEN && 
			   !isKernelAddress(t.beginAddress)){
				cout << "Begin Addr: " << hex << t.beginAddress << endl;
				cout << "Size: " << dec << t.size / BIT_TO_BYTE << endl;
				cout << "----------" << endl;
				contBufIndex++;
				numTotalContBuf++;
			}
		}
		cout << "number of valid continuous buffers: " << contBufIndex << endl;
		cout << "--------------------" << endl;
		funcCallIndex++;
	}
	cout << "number of total continuout buffers: " << numTotalContBuf << endl;
}

void SearchAvalanche::printBuffer(Buffer &a)
{
	if(!a.vNodeIndex.empty() )
		cout << "Buffer Begin Address: " << hex << a.beginAddr << " index: " << a.vNodeIndex.front() << endl;
	else
		cout << "Buffer Begin Addr: " << hex << a.beginAddr << endl;
	cout << "Buffer Size: " << dec << a.size / BIT_TO_BYTE << endl;
}
