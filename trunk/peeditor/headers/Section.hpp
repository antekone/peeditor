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
	ulong vsz; // VirtualSize
	ulong va; // VirtualAddress
	ulong physa; // PhysicalAddress, TODO only in object files?
	ulong rsz; // SizeOfRawData
	ulong raw; // PointerToRawData
	ulong reloc_ptr; // PointerToRelocations
	ulong lineno_ptr; // PointerToLinenumbers
	ushort reloc_n; // NumberOfRelocations
	ushort lineno_n; // NumberOfLinenumbers
	ulong traits; // Characteristics
	uptr file_ptr;

	bool abstract;

	IMAGE_SECTION_HEADER *orig;
	byte *data;

	void init(istream *stream, IMAGE_SECTION_HEADER *ish, TraceCtx *trace_ctx, uptr file_pos);
};

#endif /* SECTION_HPP_ */
