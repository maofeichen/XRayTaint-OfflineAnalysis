/*
 * TaintBitmap.h
 *
 *  Created on: May 13, 2011
 *      Author: xin
 */

#ifndef TAINTBITMAP_H_
#define TAINTBITMAP_H_
// The class is implemented by Xin Li for
// CiperXray project. 
//
// The class is used to store the taint information
// during the taint source propagation search. 
//
// During the search, if any memory can be propagated from the taint
// source, the address and taint info will be store.
//
// The <addr, info> will be stored in a bitmap structure, each bit
// represents one byte. If the bit is set to 1, indicating the 
// corresponding memory byte is tainted.
//
// Consider a 32 bit address space, to cover the whole address space
// we need 2^32 / 8 entries, each entry is 1 byte.
//
// However in practice, the memory that the taint source can proagate
// to is relatively small, the number of entries will be small. 
// We will allocate memory for these entries dynamically when needed.
//
// To save memory, the bitmap is structured like a two level page table:
// Consider a 32 bit address, we divide it to:
//  | 20 bit | 9 bit | 3 bit|

#include <list>

class TaintBitMap {
    static const int size = 0x100000; // 2^32 / 4096
    static const int nslots = 8;
    static const int entrysize = 4096 / nslots; // 4k, every byte represents 8 bytes taintness info
    static bool valinitdone;
    static char value[8][8];
    static char rvalue[8][8];

    char **bitmap;
    std::list<char *> usedentry;
    std::list<char *> freeentry;

    inline int getindex(unsigned int address);
    inline int getoffset(unsigned int address);
    inline char *getentry(int index);
    inline char getval(int offset, int length);
    inline char getrval(int offset, int length);
    void initvalue();
    bool oldIsTainted(unsigned int address, int length = 1);

    public:
    TaintBitMap();
    ~TaintBitMap();
    bool isTainted(unsigned int address);
    void mark(unsigned int address, int length);
    void unmark(unsigned int address, int length);
    void reset();
};

#endif /* TAINTBITMAP_H_ */
