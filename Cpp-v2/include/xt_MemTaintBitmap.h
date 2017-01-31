#ifndef XT_MemTaintBitmap_H_
#define XT_MemTaintBitmap_H_ 

// !!!The class is not used currently. Use XinLi's implement
// code instead.
// 
// The implementation references XinLi's CipherXray code:
//		TaintBitMap.h
//		TaintBitMap.cpp
//
// The class MemTaintBitmap is used to store the taint information
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
//	| 20 bit | 9 bit | 3 bit|
//	1. 20 bit (2^20) as index of each slot, the size is 2^20 * 1 byte = 1MB
//	2. each slot has 2^9 entries
//	3. each entry is 1 byte, and has taint info to 8 bytes memory
//
// Give an address addr1:
// 1. locate the slot: use index: addr1 >> 12
// 2. locate the entry: use index: (addr1 >> 3) & mask
// 3. In the encry, to locate the corresponding bit, we use mask: & 7

class MemTaintBitMap
{
public:
	MemTaintBitMap();
	~MemTaintBitMap();
private:
	static const ENTRY_BIT	= 3;
	static const SLOT_BIT	= 9;
	static const MEM_TAINT_BITMAP_ROOT_SIZE	= 0x100000;	// 2^20

	// root of memory taint bitmap
	char **mem_taint_bitmap;
	
};

#endif