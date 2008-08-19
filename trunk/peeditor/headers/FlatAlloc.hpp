/*
 * FlatAlloc.hpp
 *
 *  Created on: 2008-08-14
 *      Author: antek
 */

#ifndef FLATALLOC_HPP_
#define FLATALLOC_HPP_

class FlatAlloc {
private:
	byte *memory;
	uint size, ptr;

public:
	FlatAlloc(int max);
	virtual ~FlatAlloc();

	byte *alloc(int size, int *lastptr = NULL);
	byte *get_base();
	uint get_size();
};

#endif /* FLATALLOC_HPP_ */
