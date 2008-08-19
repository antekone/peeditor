/*
 * FlatAlloc.cc
 *
 *  Created on: 2008-08-14
 *      Author: antek
 */

#include "ped.hpp"
#include "FlatAlloc.hpp"

FlatAlloc::FlatAlloc(int max) {
	memory = Alloc<byte>::anew(max);
	size = max;
	ptr = 0;
}

FlatAlloc::~FlatAlloc() {
	// Alloc<byte>::adelete(memory);
}

byte *FlatAlloc::alloc(int size, int *lastptr) {
	assert(memory != NULL);
	assert(size > 0);

	byte *mem_ptr = &memory[ptr];
	if(lastptr)
		*lastptr = ptr;

	ptr += size;
	return mem_ptr;
}

byte *FlatAlloc::get_base() {
	assert(memory != NULL);
	return memory;
}

uint FlatAlloc::get_size() {
	return size;
}
