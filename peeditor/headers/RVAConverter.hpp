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
	IMAGE_SECTION_HEADER **sections_ptr;
	IMAGE_SECTION_HEADER **sections_va;
	IMAGE_SECTION_HEADER **sections;
	int n;
	
	void init();
	
public:
	RVAConverter(IMAGE_SECTION_HEADER **, int);
	~RVAConverter();
	
	ulong ptr_from_rva(ulong rva);
	ulong rva_from_ptr(ulong ptr);
	bool check_overlaps(int&, int&);
	bool same_section(uptr rva1, uptr rva2);
	IMAGE_SECTION_HEADER *get_section_for_rva(uptr rva);
	IMAGE_SECTION_HEADER *get_section_for_ptr(uptr ptr);
};

#endif	/* _RVACONVERTER_HPP */
