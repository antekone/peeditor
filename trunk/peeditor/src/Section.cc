/*
 * Section.cpp
 *
 *  Created on: 2008-08-08
 *      Author: antek
 */

#include "ped.hpp"
#include "Section.hpp"

Section::Section() {
	data = NULL;
}

Section::~Section() {

}

void Section::init(istream *input, IMAGE_SECTION_HEADER *sec, TraceCtx *trace) {
	trace_ctx = trace;
	tracing = trace_ctx != NULL;

	orig = sec;

	ostringstream os;
	os << sec->Name;

	this->characteristics = sec->Characteristics.dword;
	this->name = os.str();
	this->number_of_linenumbers = sec->NumberOfLinenumbers;
	this->number_of_relocations = sec->NumberOfRelocations;
	this->pointer_to_linenumbers = sec->PointerToLinenumbers;
	this->pointer_to_raw_data = sec->PointerToRawData;
	this->pointer_to_relocations = sec->PointerToRelocations;
	this->size_of_raw_data = sec->SizeOfRawData;
	this->virtual_address = sec->VirtualAddress;
	this->virtual_size = sec->Misc.VirtualSize;
	this->physical_address = sec->Misc.PhysicalAddress;
	data = NULL;

	if(pointer_to_raw_data != 0) {
		TRACE_CTX(_("Physical section detected, seeking to its raw base (PointerToRawData) at 0x%08X.", pointer_to_raw_data));
		input->seekg(pointer_to_raw_data, ios_base::beg);

		data = Alloc<byte>::anew(size_of_raw_data);
		TRACE_CTX(_("Reading section data at 0x%08X (size: %d bytes - according to SizeOfRawData).", (uint) input->tellg(), size_of_raw_data));
		RANGE_CHECK(input, size_of_raw_data);
		input->read((char *) data, size_of_raw_data);
	} else {
		TRACE_CTX("Abstract section detected, not reading data since it's not even there.");
	}

	if(name.length() == 0) {
		os.clear();
		os << "(ptr: " << hex << pointer_to_raw_data << ")";
		name = os.str();
		TRACE_CTX(_("Empty section name detected, changing it to '%s'.", name.c_str()));
	}
}
