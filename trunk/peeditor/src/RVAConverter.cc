#include "ped.hpp"

RVAConverter::RVAConverter(IMAGE_SECTION_HEADER **sections, int n) {
	assert(sections != NULL);
	assert(sections[0] != NULL);
	assert(n > 0);

	hdr_ptrs = false;

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
		IMAGE_SECTION_HEADER *cs = sections_va[i];
		int size = cs->Misc.VirtualSize;

		if(size > 0)
			size--;

		if(rva >= cs->VirtualAddress && rva <= (cs->VirtualAddress + size)) {
			s = sections_va[i];
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
		IMAGE_SECTION_HEADER *cs = sections_ptr[i];
		if(ptr >= cs->PointerToRawData && ptr < (cs->PointerToRawData + cs->SizeOfRawData)) {
			s = sections_ptr[i];
			break;
		}
	}

	return s;
}

ulong RVAConverter::ptr_from_rva(ulong rva) {
	assert(rva != 0);

	if(is_header_rva(rva)) {
		hdr_ptrs = true;
		return rva;
	}

	IMAGE_SECTION_HEADER *s = get_section_for_rva(rva);
	assert(s != NULL);
	ulong ofs = rva - s->VirtualAddress + s->PointerToRawData;

	return ofs;
}

IMAGE_SECTION_HEADER *RVAConverter::get_smallest_va_section() {
	assert(n > 0);

	int help = 0;
	IMAGE_SECTION_HEADER *d = NULL;
	for(d = sections_va[0]; !d->VirtualAddress; d = sections_va[++help])
		assert(help < n);

	assert(d != NULL);
	return d;
}

IMAGE_SECTION_HEADER *RVAConverter::get_biggest_va_section() {
	assert(n > 0);
	return sections_va[n - 1];
}

IMAGE_SECTION_HEADER *RVAConverter::get_biggest_ptr_section() {
	assert(n > 0);
	return sections_ptr[n - 1];
}

IMAGE_SECTION_HEADER *RVAConverter::get_smallest_ptr_section() {
	int help = 0;
	IMAGE_SECTION_HEADER *d = NULL;
	for(d = sections_ptr[0]; !d->PointerToRawData; d = sections_ptr[++help])
		assert(help < n);
	assert(d != NULL);
	return d;
}

uptr RVAConverter::get_biggest_va() {
	return get_biggest_va_section()->VirtualAddress;
}

uptr RVAConverter::get_biggest_ptr() {
	return get_biggest_ptr_section()->PointerToRawData;
}

uptr RVAConverter::get_smallest_va() {
	return get_smallest_va_section()->VirtualAddress;
}

uptr RVAConverter::get_smallest_ptr() {
	return get_smallest_ptr_section()->PointerToRawData;
}

bool RVAConverter::is_rva_mappable_to_ptr(ulong rva) {
	// check for header:
	// if the pointer is smaller than smallest section's VA and RAW, it's mappable to header -- return true.
	// if the pointer is smaller than smallest section's VA but bigger than RAW, it's unmappable -- return false.
	IMAGE_SECTION_HEADER *d = get_smallest_va_section();
	if(rva < d->VirtualAddress) {
		if(rva < d->PointerToRawData) {
			// pointer to header.
			hdr_ptrs = true;
			return true;
		} else {
			// pointer to first section -- impossible to convert.
			return false;
		}
	} else {
		// check for sections:
		// get_section_for_rva should handle this case.
		return get_section_for_rva(rva) != NULL;
	}
}

bool RVAConverter::is_ptr_mappable_to_rva(ulong ptr) {
	// check for header:
	// if the ptr is smaller than smallest section's PTR, it's mappable to header -- return true.
	IMAGE_SECTION_HEADER *d = get_smallest_ptr_section();
	if(ptr < d->PointerToRawData) {
		hdr_ptrs = true;
		return true;
	} else
	// check for sections:
	// get_section_for_ptr should do the trick.
		return get_section_for_ptr(ptr) != NULL;
}

bool RVAConverter::is_header_rva(ulong rva) {
	IMAGE_SECTION_HEADER *d = get_smallest_va_section();
	// got a section with non zero VA.

	// a good pointer should be smaller than Virtual Address, and smaller than SizeOfRawData. Then
	// it's possible to map it to header: just return the rva - returns true.

	// a good pointer is also when it's smaller than Virtual Address, and bigger than SizeOfRawData, but
	// in this case it's impossible to convert it to file offset - returns true.

	// when the pointer is bigger than this Virtual Address, then it's a part of this Section,
	// so is_header_rva() returns false.
	if(rva < d->VirtualAddress) {
		hdr_ptrs = true;
		return true;
	} else
		return false;
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

bool RVAConverter::valid_rva(uptr rva) {
	return is_rva_mappable_to_ptr(rva);
}

bool RVAConverter::valid_ptr(uptr ptr) {
	return is_ptr_mappable_to_rva(ptr);
}
