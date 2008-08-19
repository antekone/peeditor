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
	abstract = true;
	file_ptr = 0;
	lineno_n = 0;
	lineno_ptr = 0;
	name = ".new";
	orig = NULL;
	physa = 0;
	raw = 0;
	reloc_n = 0;
	reloc_ptr = 0;
	rsz = 0;
	trace_ctx = NULL;
	tracing = false;
	traits = 0;
	va = 0;
	vsz = 0;
}

Section::~Section() {
	// helps to control synchronization of `abstract' field.
	if(abstract)
		assert(abstract && data == NULL);
	else
		assert(!abstract && data != NULL);

	/*
	if(!abstract && data) {
		Alloc<byte>::adelete(data);
		data = NULL;
	}
	*/
}

void Section::init(istream *input, IMAGE_SECTION_HEADER *sec, TraceCtx *trace, uptr filepos) {
	trace_ctx = trace;
	tracing = trace_ctx != NULL;

	orig = sec;

	ostringstream os;
	os << sec->Name;

	this->traits = sec->Characteristics.dword;
	this->name = os.str();
	this->lineno_n = sec->NumberOfLinenumbers;
	this->reloc_n = sec->NumberOfRelocations;
	this->lineno_ptr = sec->PointerToLinenumbers;
	this->raw = sec->PointerToRawData;
	this->reloc_ptr = sec->PointerToRelocations;
	this->rsz = sec->SizeOfRawData;
	this->va = sec->VirtualAddress;
	this->vsz = sec->Misc.VirtualSize;
	this->physa = sec->Misc.PhysicalAddress;
	this->file_ptr = filepos;

	if(input) {
		if(raw > 0 && rsz > 0) {
			TRACE_CTX(_("Physical section detected, seeking to its raw base (PointerToRawData) at 0x%08X.", raw));
			input->seekg(raw, ios_base::beg);

			// rsz sometimes can be 0. If that is the case, use vsz instead of rsz.
			int size = rsz == 0? vsz: rsz;
			if(size == 0) {
				// if the size is still 0, then something strange is going on.
				cout << WARNING << "Section at " << hex << setw(8) << setfill(' ') << " has a size of 0, marking as abstract." << endl;
				data = NULL;
				abstract = true;
			} else {
				data = Alloc<byte>::anew(size);
				abstract = false;
			}

			TRACE_CTX(_("Reading section data at 0x%08X (size: %d bytes - according to SizeOfRawData or VirtualSize if the first on is 0).", (uint) input->tellg(), size));
			RANGE_CHECK(input, rsz);
			input->read((char *) data, rsz);
		} else {
			TRACE_CTX("Abstract section detected, not reading data since it's not even there.");
			abstract = true;
		}

		if(name.length() == 0) {
			os.clear();
			os << hex << raw << "?";
			name = os.str();
			TRACE_CTX(_("Empty section name detected, changing it to '%s'.", name.c_str()));
		}
	}
}
