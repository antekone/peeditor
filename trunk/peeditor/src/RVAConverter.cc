#include "ped.hpp"

RVAConverter::RVAConverter(IMAGE_SECTION_HEADER **sections, int n) {
	assert(sections != NULL);
	assert(sections[0] != NULL);
	assert(n > 0);
	
	this->sections = sections;
	this->sections_ptr = NULL;
	this->n = n;
	
	init();
}

RVAConverter::~RVAConverter() {
	assert(sections != NULL);
	this->sections = NULL;
	
	assert(sections_ptr != NULL);
	assert(sections_va != NULL);
	Alloc<IMAGE_SECTION_HEADER*>::adelete(sections_ptr);
	Alloc<IMAGE_SECTION_HEADER*>::adelete(sections_va);
}

void RVAConverter::init() {
	sections_ptr = Alloc<IMAGE_SECTION_HEADER*>::anew(n);
	sections_va = Alloc<IMAGE_SECTION_HEADER*>::anew(n);
	
	for(int i = 0; i < n; i++) {
		sections_ptr[i] = sections[i];
		sections_va[i] = sections[i];
	}
	
	IMAGE_SECTION_HEADER *value;
	for(int j = 0, i = 1; i < n; i++) {
		j = i - 1;
		
		value = sections_ptr[i];
		while(j >= 0 && sections_ptr[j]->PointerToRawData > value->PointerToRawData) {
			sections_ptr[j + 1] = sections_ptr[j];
			j--;
		}
		
		sections_ptr[j + 1] = value;
	}
	
	for(int j = 0, i = 1; i < n; i++) {
		j = i - 1;
		
		value = sections_va[i];
		while(j >= 0 && sections_va[j]->VirtualAddress > value->VirtualAddress) {
			sections_va[j + 1] = sections_va[j];
			j--;
		}
		
		sections_va[j + 1] = value;
	}
}

IMAGE_SECTION_HEADER *RVAConverter::get_section_for_rva(uptr rva) {
	assert(sections_ptr != NULL);
	assert(sections != NULL);
	assert(sections[0] != NULL);
	assert(sections_va != NULL);
	assert(n > 0);
	assert(rva != 0);
	
	IMAGE_SECTION_HEADER *s = NULL;
	for(int i = 0; i < n; i++) {
		if(sections_va[i]->VirtualAddress > rva) {
			if(i == 0)
				return NULL;
			
			s = sections_va[i - 1];
			break;
		}
	}
	
	return s;
}

IMAGE_SECTION_HEADER *RVAConverter::get_section_for_ptr(uptr ptr) {
	assert(sections_ptr != NULL);
	assert(sections != NULL);
	assert(sections[0] != NULL);
	assert(sections_ptr != NULL);
	assert(n > 0);
	assert(ptr != 0);
	
	IMAGE_SECTION_HEADER *s = NULL;
	for(int i = 0; i < n; i++) {
		if(sections_va[i]->PointerToRawData > ptr) {
			if(i == 0) 
				return NULL;
			
			s = sections_ptr[i - 1];
			break;
		}
	}
	
	return s;
}

ulong RVAConverter::ptr_from_rva(ulong rva) {
	assert(rva != 0);
	
	IMAGE_SECTION_HEADER *s = get_section_for_rva(rva);
	assert(s != NULL);
	
	ulong ofs = rva - s->VirtualAddress + s->PointerToRawData;
	return ofs;
}

ulong RVAConverter::rva_from_ptr(ulong ptr) {
	assert(ptr != 0);

	IMAGE_SECTION_HEADER *s = get_section_for_ptr(ptr);
	assert(s != NULL);
	
	ulong ofs = ptr - s->PointerToRawData + s->VirtualAddress;
	return ofs;
}

bool RVAConverter::check_overlaps(int& s1, int& s2) {
	// check vas.
	for(int i = 0; i < n - 1; i++) {
		if(sections_va[i]->VirtualAddress + sections_va[i]->Misc.VirtualSize > sections_va[i+1]->VirtualAddress) {
			s1 = i;
			s2 = i+1;
			return false;
		}
	}
	
	// check ptrs.
	for(int i = 0; i < n - 1; i++) {
		if(sections_va[i]->PointerToRawData + sections_va[i]->SizeOfRawData > sections_va[i+1]->PointerToRawData) {
			s1 = i;
			s2 = i+1;
			return false;
		}
	}
	
	
	return true;
}

bool RVAConverter::same_section(uptr rva1, uptr rva2) {
	assert(rva1 != 0);
	assert(rva2 != 0);
	
	IMAGE_SECTION_HEADER *s1 = get_section_for_rva(rva1), *s2 = get_section_for_rva(rva2);
	
	assert(s1 != NULL);
	assert(s2 != NULL);
	
	return s1 == s2;
}
