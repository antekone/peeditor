/*
 * File:   RVAConverter.hpp
 * Author: antek
 *
 * Created on 30 lipiec 2008, 12:14
 */

#ifndef _RVACONVERTER_HPP
#define	_RVACONVERTER_HPP

class RVAConverter {
private:
	// these structures hold the same pointers, but sorted in a different
	// way.

	// sections sorted via PointerToRawData;
	IMAGE_SECTION_HEADER **sections_ptr;

	// sections sorted via VirtualAddress.
	IMAGE_SECTION_HEADER **sections_va;

	// sections unsorted (as in file).
	IMAGE_SECTION_HEADER **sections;

	// number of sections in file.
	int n;

	// sorting code.
	void init();

public:
	RVAConverter(IMAGE_SECTION_HEADER **, int);
	~RVAConverter();

	ulong ptr_from_rva(ulong rva);
	ulong rva_from_ptr(ulong ptr);
	bool check_overlaps(int&, int&);
	bool same_section(uptr rva1, uptr rva2);
	bool valid_rva(uptr rva);
	bool valid_ptr(uptr ptr);
	IMAGE_SECTION_HEADER *get_section_for_rva(uptr rva);
	IMAGE_SECTION_HEADER *get_section_for_ptr(uptr ptr);

	// header pointers detected. file may be packed.
	bool hdr_ptrs;
};

#endif	/* _RVACONVERTER_HPP */
