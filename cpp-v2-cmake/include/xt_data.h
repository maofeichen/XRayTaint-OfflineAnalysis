#ifndef XT_DATA_H
#define XT_DATA_H

#include <string>
#include <vector>

// Buffer Record
struct Buf_Rec_t{
    std::string src_flag;
    std::string src_addr;
    std::string src_val;

    std::string dst_flag;
    std::string dst_addr;
    std::string dst_val;

    std::string s_size;
    std::string this_rec;

    unsigned long addr;
    unsigned int size;
};

// Continue Buffer
struct t_AliveContinueBuffer
{
    unsigned long beginAddress;
    unsigned long size;
    std::vector<unsigned long> vNodeIndex;
};

// Continues Buffers per function call
struct t_AliveFunctionCall
{
    std::string call_mark;
    std::string sec_call_mark;
    std::string ret_mark;
    std::string sec_ret_mark;
    std::vector<t_AliveContinueBuffer> vAliveContinueBuffer;
};

struct Node{
    std::string flag;
    std::string addr;
    std::string val;

    unsigned long i_addr;
    unsigned int sz;
};

struct RegularRecord
{
    struct Node src;
    struct Node dst;
};

// if a mark, then src becomes the mark
struct Record
{
    bool isMark;
    struct RegularRecord regular;
};

struct NodePropagate
{
    unsigned long id;
    unsigned long parentId;
    unsigned long layer;
    std::string insnAddr;
    bool isSrc;
    unsigned int pos;
    struct Node n; 
};

inline bool operator==(Node a, Node b)
{
    return a.flag == b.flag &&
               a.addr == b.addr &&
               a.val == b.val &&
               a.sz == b.sz;
}

struct NodeHash
{
    std::size_t operator()(const Node &a) const {
        size_t h1 ( std::hash<int>()(a.i_addr) );
        size_t h2 ( std::hash<int>()(a.sz) );
        return h1 ^ (h2 << 1);    
    }
};
#endif
