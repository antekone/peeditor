/*
 * Section.hpp
 *
 *  Created on: 2008-08-08
 *      Author: antek
 */

#ifndef SECTION_HPP_
#define SECTION_HPP_

#include "TraceCtx.hpp"

class Section {
private:
	TraceCtx *trace_ctx;
	bool tracing;

public:
	Section();
	virtual ~Section();

	string name;
	ulong virtual_size;
	ulong virtual_address;
	ulong physical_address;
	ulong size_of_raw_data;
	ulong pointer_to_raw_data;
	ulong pointer_to_relocations;
	ulong pointer_to_linenumbers;
	ushort number_of_relocations;
	ushort number_of_linenumbers;
	ulong characteristics;

	IMAGE_SECTION_HEADER *orig;
	byte *data;

	void init(istream*, IMAGE_SECTION_HEADER *, TraceCtx *);
};

#endif /* SECTION_HPP_ */
