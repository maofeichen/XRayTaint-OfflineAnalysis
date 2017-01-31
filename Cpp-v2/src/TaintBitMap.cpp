/*
 * TaintBitMap.cpp
 *
 *  Created on: May 13, 2011
 *      Author: xin
 */
#include <iostream>
#include <algorithm>
#include <list>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "TaintBitMap.h"

bool TaintBitMap::valinitdone = false;
char TaintBitMap::value[][8] = {0};
char TaintBitMap::rvalue[][8] = {0};

TaintBitMap::TaintBitMap() {
    bitmap = (char **)malloc(size * sizeof(char *));
    memset(bitmap, 0, size * sizeof(char *));

    for(int i = 0; i < 16; i++) {
        char *entry = (char *)malloc(entrysize);
        memset(entry, 0, entrysize);
        freeentry.push_back(entry);
    }

    initvalue();
}

void TaintBitMap::initvalue() {
    if(valinitdone) {
        return;
    }

    for(int pos = 0; pos < 8; pos++) {
        for(int length = 1; length <= 8 - pos; length++) {
            value[pos][length] = (1 << pos) * ((1 << length) - 1);
            rvalue[pos][length] = ~(value[pos][length]);
        }
    }

    valinitdone = true;
}

TaintBitMap::~TaintBitMap() {
    char *entry;

    std::list<char *>::iterator it;
    for(it = usedentry.begin(); it != usedentry.end(); it++) {
        free((*it));
    }
    usedentry.clear();

    for(it = freeentry.begin(); it != freeentry.end(); it++) {
        free((*it));
    }
    freeentry.clear();

    free(bitmap);
}

int TaintBitMap::getindex(unsigned int address) {
    return (address >> 12);
}

int TaintBitMap::getoffset(unsigned int address) {
    return ((address >> 3) & (entrysize - 1));
}

char TaintBitMap::getval(int offset, int length) {
    return value[offset][length];
}

char TaintBitMap::getrval(int offset, int length) {
    return rvalue[offset][length];
}

char *TaintBitMap::getentry(int index) {
    char *entry;

    if(freeentry.empty()) {
        entry = (char *)malloc(entrysize);
        memset(entry, 0, entrysize);
    } else {
        entry = freeentry.front();
        freeentry.pop_front();
    }

    bitmap[index] = entry;
    usedentry.push_back(entry);

    return entry;
}

bool TaintBitMap::oldIsTainted(unsigned int address, int length) {
    int index  = getindex(address);
    int offset = getoffset(address);
    char *entry = bitmap[index];

    if(entry == NULL) {
		int size = entrysize * nslots - address & (entrysize * nslots - 1);
		length -= size;
		address += size;

		index++;
		offset = 0;
		entry = bitmap[index];
    } else if(address & 0x7) {
    	// in case address is not at the 8-byte boundary, align it. since
    	// in the bitmap, every byte represents 8 byte's taintness
    	char val = *(entry + offset);
        int gap = 8 - (address & 7) - length;
        gap = gap < 0 ? 0 : gap;
    	if((val & (0xff << (address & 0x7))) & (0xff >> gap)){
    		return true;
    	}

    	length -= 8 - (address & 7);
    	address = (address + 7) & 7;

    	offset++;
    	if(offset == entrysize) {
    		offset = 0;
    		index++;
    		entry = bitmap[index];
    	}
    }

    // address is 8-byte aligned
    while(length >= 8) {
    	if(entry == NULL) {
    		length -= entrysize * nslots;

    		index++;
    		offset = 0;
    		entry = bitmap[index];
    	} else {
    		char val = *(entry + offset);
    		if(val) {
    			return true;
    		}

    		length -= 8;

    		offset++;
    		if(offset == entrysize) {
    			offset = 0;
    			index++;
    			entry = bitmap[index];
    		}
    	}
    }

    // check the remaining bytes
    if(length > 0) {
    	if(entry != NULL) {
    		char val = *(entry + offset);
    		if(val & (0xff >> (8 - length))) {
    			return true;
    		}
    	}
    }

    return false;
}

bool TaintBitMap::isTainted(unsigned int address) {
    int index = getindex(address);
    int offset = getoffset(address);

    char *entry = bitmap[index];
    if(entry == NULL) {
        return false;
    } else {
        entry += offset;
        char val = *entry;
        if((val & (1 << (address & 7))) != 0) {
            return true;
        } else {
            return false;
        }
    }
}

void TaintBitMap::mark(unsigned int address, int length) {
    int index = getindex(address);
    int offset = getoffset(address);
    char *entry = bitmap[index];
    if(entry == NULL) {
        entry = getentry(index);
    }

    entry += offset;
    while(true) {
        int size = 8 - (address & 7);
        size = size > length ? length : size;
        *entry |= getval(address & 7, size);
        length -= size;
        if(length == 0) {
            break;
        }

        address += size;
        offset++;
        if(offset == entrysize) {
            offset = 0;
            index++;
            entry = bitmap[index];
            if(entry == NULL) {
                entry = getentry(index);
            }
        } else {
            entry++;
        }
    }
}

void TaintBitMap::unmark(unsigned int address, int length) {
    int index = getindex(address);
    int offset = getoffset(address);
    char *entry = bitmap[index];

    while(true) {
        if(entry == NULL) {
            index++;
            int next = (index << 12) - 1;
            length -= next - address;
            address = next;
            offset = 0;
        } else {
            int size = 8 - (address & 7);
            size = size > length ? length : size;
            char val = getrval(address & 7, size);
            *(entry + offset) &= val;

            length -= size;
            address += size;
            offset++;
            if(offset == entrysize) {
                offset = 0;
                index++;
                entry = bitmap[index];
            }
        }

        if(length <= 0) {
            break;
        }
    }
}

void TaintBitMap::reset() {
    memset(bitmap, 0, size * sizeof(char *));

    std::list<char *>::iterator it;
    for(it = usedentry.begin(); it != usedentry.end(); it++) {
        char *entry = *it;
        memset(entry, 0 ,entrysize * sizeof(char));
        freeentry.push_back(entry);
    }

    usedentry.clear();
}
