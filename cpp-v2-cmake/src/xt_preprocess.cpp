#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "xt_flag.h"
#include "xt_preprocess.h"
#include "xt_util.h"

using namespace std;

XT_PreProcess::XT_PreProcess(){}

// filter out mark records
inline bool XT_PreProcess::isValidRecord(string &s)
{
    if(s.compare(flag::XT_INSN_ADDR) != 0 && \
       s.compare(flag::XT_TCG_DEPOSIT) != 0 && \
       s.compare(flag::XT_SIZE_BEGIN) != 0 && \
       s.compare(flag::XT_SIZE_END) != 0 && \
	   s.compare(flag::XT_CALL_INSN) != 0 && \
       s.compare(flag::XT_CALL_INSN_SEC) != 0 && \
	   s.compare(flag::XT_CALL_INSN_FF2) != 0 && \
	   s.compare(flag::XT_CALL_INSN_FF2_SEC) != 0 && \
       s.compare(flag::XT_RET_INSN) != 0 && \
	   s.compare(flag::XT_RET_INSN_SEC) != 0)
       return true;
   else
       return false;
}

// Given the record flag, determine its size
inline std::string XT_PreProcess::getBufSize(int iRecFlag, int &TCGEncode)
{
	int size = 0;
	if(iRecFlag > flag::NUM_TCG_ST_POINTER){
		size = iRecFlag - flag::NUM_TCG_ST_POINTER;
		TCGEncode = flag::NUM_TCG_ST_POINTER;
	}
	else if(iRecFlag > flag::NUM_TCG_ST){
		size = iRecFlag - flag::NUM_TCG_ST;
		TCGEncode = flag::NUM_TCG_ST;
	}
	else if(iRecFlag > flag::NUM_TCG_LD_POINTER){
		size = iRecFlag - flag::NUM_TCG_LD_POINTER;
		TCGEncode = flag::NUM_TCG_LD_POINTER;
	}
	else if(iRecFlag > flag::NUM_TCG_LD){
		size = iRecFlag - flag::NUM_TCG_LD;
		TCGEncode = flag::NUM_TCG_LD;
	}
	else
		std::cout << "getBufSize(): unknown iRecFlag" << endl;

	switch(size){
		case 1:
			return "8";
		case 2:
			return "16";
		case 3:
			return "32";
		default:
			std::cout << "getBufSize(): unknown size" << endl;
	}
}

// Replace original flag with TCGEncode, add the size info at the end
inline std::string XT_PreProcess::addBufSize(std::string &s, std::string size, int TCGEncode)
{
	std::string s_new, sTCGEncode;
	std::vector<std::string> v_s;
	std::ostringstream oTCGEncode;

	oTCGEncode << std::hex << TCGEncode;
	sTCGEncode = oTCGEncode.str();
	v_s = XT_Util::split(s.c_str(), '\t');

	// reform src of record
	s_new = sTCGEncode + '\t';
	s_new += v_s[1] + '\t';
	s_new += v_s[2] + '\t';

	// reform dst of record
	s_new += sTCGEncode + '\t';
	s_new += v_s[4] + '\t';
	s_new += v_s[5] + '\t';
	s_new += size;

	return s_new;
}

// Not need
vector<string> XT_PreProcess::clean_size_mark(vector<string> &v)
{
    vector<string> v_new;
    string begin, end;
    
    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // if a size end mark
        if( (*it).substr(0,2).compare(flag::XT_SIZE_END) == 0){
            end = *it;
            begin = v_new.back();
            // if a begin mark
            if(begin.substr(0,2).compare(flag::XT_SIZE_BEGIN) == 0)
                // if match size
                if(begin.substr(3, string::npos).compare(end.substr(3,string::npos) ) == 0 ){
                    v_new.pop_back();
                    continue;
                }
        }
        v_new.push_back(*it);
    }
    // std::cout << "after clean size mark: " << std::endl;
    // for(vector<string>::iterator it = v_new.begin(); it != v_new.end(); ++it)
    //     std::cout << *it << std::endl; 
    return v_new;
}

vector<string> XT_PreProcess::clean_function_call_mark(vector<string> &v_s_log) {
  vector<string> v;
  v = clean_empty_function_mark(v_s_log);
  cout << "num of entries after clean empyt func mark: " << v.size()
       << endl;
  v = clean_nonempyt_func_mark_fast(v);
  cout << "num of entries after clean func mark: " << v.size() << endl;
  return v;
}

// v - contain xtaint record line by line
// if a pair of function call mark, there is no records between, delete it
// for example,
//      14   c0795f08    c015baa5    
//      4b  c01ace50    0   
//      18  c0795f04    c015baa5    
//      4c  c01ace80    0  
// first two lines indicate a CALL instruction:
// - 14 is CALL mark
// - come with esp value, top of stack value,
// - 4b is 2nd mark of CALL
// - comes with callee addr
//
// last two lines indicate RET insn
// - 18 is RET mark
// - comes with esp value, top of stack
// - 4c is 2nd mark of RET
// - comes with function end addr
//
// they are match due to the top of stack values are same, and
// since no valid records between, delete them 
// return - new vector
vector<string> XT_PreProcess::clean_empty_function_mark(vector<string> &v)
{
    vector<string> vNew, vCall, vRet;
    string call, ret;
    vector<string>::size_type sz;

    cout << "Cleanning empty function call mark..." << endl;

    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // if a 2nd ret insn mark
        if( (*it).substr(0,2).compare(flag::XT_RET_INSN_SEC) == 0){
            ret = vNew.back();
            // !!!it assums the call must before ret, but this does NOT hold
            if(vNew.size() < 3)
                continue;

            // if empty function, then -3 is call
            call = vNew[vNew.size() - 3]; 
            // if an CALL insn mark
            if(call.substr(0,2).compare(flag::XT_CALL_INSN) == 0 || \
                call.substr(0,2).compare(flag::XT_CALL_INSN_FF2) == 0 ){
                // if matches
                vCall = XT_Util::split(call.c_str(), '\t');
                vRet = XT_Util::split(ret.c_str(), '\t');
                // assert(vCall.size() == vRet.size() );
                sz = vCall.size();
                // If top of stack are same
                if(vCall.at(sz - 2).compare(vRet.at(sz - 2) ) == 0){
                    vNew.erase(vNew.end()-3, vNew.end() );
                    continue;
                }
            }
        }
        vNew.push_back(*it);
    }
    return vNew;
}

inline bool XT_PreProcess::is_invalid_record(string &s)
{
     if(s.substr(0,2).compare(flag::XT_INSN_ADDR) != 0 && \
        s.substr(0,2).compare(flag::XT_TCG_DEPOSIT) != 0 && \
        s.substr(0,2).compare(flag::XT_SIZE_BEGIN) != 0 && \
        s.substr(0,2).compare(flag::XT_SIZE_END) != 0 && \
        s.substr(0,2).compare(flag::XT_CALL_INSN_SEC) != 0 && \
        s.substr(0,2).compare(flag::XT_RET_INSN) != 0)
        return true;
    else
        return false;   
}
// clear pair function call marks that contain no valid records between
vector<string> XT_PreProcess::clean_nonempty_function_mark(vector<string> &v)
{
    vector<string> v_new, v_call, v_ret;
    string call, ret;
    int sz, num_item;
    bool is_invalid_rec, is_del_marks;

    cout << "Cleanning non-empty function call mark..." << endl;
    
    for(std::vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // if a 2nd RET insn mark
        if( (*it).substr(0,2).compare(flag::XT_RET_INSN_SEC) == 0){
            is_del_marks = false; // alway assume do not del the pair marks 
            is_invalid_rec = true; // always assume no valid records between 
            num_item = 1;
            ret = v_new.back();

            // !!!it assums the call must before ret, but this does NOT hold
            if(v_new.size() < 3)
                continue;

            // scan reverse to find most recent CALL mark
            // ??? why begins from rbegin() ???
            vector<string>::reverse_iterator rit = v_new.rbegin();
            for(; rit != v_new.rend(); ++rit){
                call = *rit;
                // found a CALL mark
                if(call.substr(0,2).compare(flag::XT_CALL_INSN) == 0 || \
                    call.substr(0,2).compare(flag::XT_CALL_INSN_FF2) == 0){
                    v_call = XT_Util::split(call.c_str(), '\t');
                    v_ret = XT_Util::split(ret.c_str(), '\t');
                    assert(v_call.size() == v_ret.size() );
                    sz = v_call.size();

                    // is CALL & RET marks matched & no valid records between
                    if(v_call.at(sz - 2).compare(v_ret.at(sz - 2) ) == 0 && is_invalid_rec){
                        // del the pair markds and records between
                        v_new.resize(v_new.size() - num_item);
                        is_del_marks = true;
                    } 

                    break; // break inner for loop if a CALL found
                }
                // else if a valid record, set the valid flag to false
                if(is_invalid_record(call) && is_invalid_rec)
                    is_invalid_rec = false;

                num_item++;
            }
            if(!is_del_marks)
                v_new.push_back(*it); // if not del, push the RET mark as well
        }
        else
            v_new.push_back(*it);  // push non RET mark records
    }

    return v_new;
}

vector<string> XT_PreProcess::clean_nonempyt_func_mark_fast(
    vector<string> &v_s_log) {
  cout << "cleaning invalid funcion mark..." << endl;
  vector<string> v;

  vector<string> call_stack;
  vector<string>::iterator it_curr_ret;

  bool has_valid_rec = false;

  for(auto it = v_s_log.begin(); it != v_s_log.end(); ++it) {
    bool is_del = false;

    string flag = it->substr(0,2);
    bool is_mark = XT_Util::is_mark(flag);

    if(is_mark) {
      if(XT_Util::equal_mark(flag, flag::XT_CALL_INSN) ||
          XT_Util::equal_mark(flag, flag::XT_CALL_INSN_FF2) ) {

        call_stack.push_back(*it);
        has_valid_rec = false;
      } else if(XT_Util::equal_mark(flag, flag::XT_RET_INSN_SEC) &&
          !call_stack.empty() ) {
        string last_call = call_stack.back();
        it_curr_ret  = it - 1;

        vector<string> v_call = XT_Util::split(last_call.c_str(), '\t');
        vector<string> v_ret  = XT_Util::split(it_curr_ret->c_str(), '\t');

        assert(v_call.size() == v_ret.size() );
        string c_esp = v_call[1];
        string r_esp = v_ret[1];

        if(c_esp.compare(r_esp) == 0 && !has_valid_rec) {
          call_stack.pop_back();

          string last_rec = v.back();
          while (last_rec.compare(last_call) ) {
            v.pop_back();
            last_rec = v.back();
          }
          v.pop_back(); // pop the last call mark
          // cout << v.back() << endl;

          is_del = true;
        }
      }
    } else {
      has_valid_rec = true;
    }

    if(!is_del) {
      v.push_back(*it);
      // cout << v.size() << endl;
    }
  }

  return v;
}

// Clean empty instruction mark: if a instruction mark follows right
// instruction makr, then it can be removed
vector<string> XT_PreProcess::clean_empty_instruction_mark(vector<string> &s_vXTLog)
{
    cout << "Cleanning empty instruction mark..." << endl;

    vector<string> s_vXTLogNew;

    vector<string>::iterator it = s_vXTLog.begin(); 
    for(; it != s_vXTLog.end() - 1; ++it){
        if(XT_Util::equal_mark(*it, flag::XT_INSN_ADDR) ){
            vector<string>::iterator itNext = it+1;
            if(XT_Util::equal_mark(*itNext, flag::XT_INSN_ADDR) ){
                continue;
            }
        }
        s_vXTLogNew.push_back(*it);
    }

    return s_vXTLogNew;
}

// Convert string xt log format to Record format
std::vector<Record> XT_PreProcess::convertToRec(std::vector<std::string> &log)
{
    vector<Record> v_rec;
    vector<string> v_log, v_single_rec;

    Record rec;
    Node src, dst;
    int i;

    std::cout << "Converting string xray taint log to Record format..." << endl;

    for(vector<string>::iterator it = log.begin(); it != log.end(); ++it){
        v_single_rec = XT_Util::split( (*it).c_str(), '\t');
        if(XT_Util::isMarkRecord(v_single_rec[0]) ){
            rec.isMark = true;
            rec.regular = initMarkRecord(v_single_rec);
        }else{
            rec.isMark = false;
            rec.regular = initRegularRecord(v_single_rec);
        }
        v_rec.push_back(rec);
        i++;
    }

    return v_rec;
} 

// Parse size info for qemu_ld/st record
std::vector<string> XT_PreProcess::parseMemSizeInfo(std::vector<std::string> &v)
{
	string recFlag, size;
	string rec;
	int iRecFlag, TCGEncode;
	std::vector<std::string> v_new;

    std::cout << "Parsing memory size info..." << endl;

	for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
		recFlag = (*it).substr(0,2);
		rec = *it;
		if(isValidRecord(recFlag) ){
			iRecFlag = std::stoi(recFlag, nullptr, 16);
			// if qemu_ld or qemu_st
			if(iRecFlag >= flag::NUM_TCG_LD_MIN && iRecFlag <= flag::NUM_TCG_ST_MAX){
				size = getBufSize(iRecFlag, TCGEncode);
				rec = addBufSize(rec, size, TCGEncode);
				v_new.push_back(rec);
				continue;
			}
		}
		v_new.push_back(*it);
	}

	return v_new;
}

// Add index to each record
vector<string> XT_PreProcess::addRecordIndex(vector<string> &s_vXTLog)
{
    cout << "Adding index to each record..." << endl;

    vector<string> s_vXTLogNew;
    unsigned long index = 0;
    string s_index = "";

    vector<string>::iterator it = s_vXTLog.begin();
    for(; it != s_vXTLog.end(); ++it){
        s_index = to_string(index);

        if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) || 
           XT_Util::equal_mark(*it, flag::TCG_QEMU_ST) ){
            // cout << "load or store..." << endl;
            (*it) += '\t';
            (*it) += s_index;
        }else{
            (*it) += s_index;
        }

        s_vXTLogNew.push_back(*it);
        index++;
    }

    return s_vXTLogNew;
}

inline RegularRecord XT_PreProcess::initMarkRecord(vector<string> &singleRec)
{
    RegularRecord mark;

    mark.src.flag = singleRec[0];
    mark.src.addr = singleRec[1];
    mark. src.val = singleRec[2];
    mark.src.i_addr = 0;
    mark.src.sz = 0;

    return mark;
}

inline RegularRecord XT_PreProcess::initRegularRecord(vector<string> &singleRec)
{
    RegularRecord reg;

    reg.src.flag = singleRec[0];
    reg.src.addr = singleRec[1];
    reg.src.val = singleRec[2];
    reg.src.i_addr = 0;
    reg.src.sz = 0;

    reg.dst.flag = singleRec[3];
    reg.dst.addr = singleRec[4];
    reg.dst.val = singleRec[5];
    reg.dst.i_addr = 0;
    reg.dst.sz = 0;

    if(XT_Util::equal_mark(singleRec[0], flag::TCG_QEMU_LD) ){
        reg.src.i_addr = std::stoul(singleRec[1], nullptr, 16);
        reg.src.sz = std::stoul(singleRec[6], nullptr, 10);
    } else if(XT_Util::equal_mark(singleRec[0], flag::TCG_QEMU_ST) ) {
        reg.dst.i_addr = std::stoul(singleRec[4], nullptr, 16);
        reg.dst.sz = std::stoul(singleRec[6], nullptr, 10);
    }

    return reg;
}
