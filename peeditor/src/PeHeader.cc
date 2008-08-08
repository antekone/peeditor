#include "ped.hpp"
#include "RVAConverter.hpp"
#include "PeHeader.hpp"
#include "ImportDirectory.hpp"

PeHeader::PeHeader(istream *input, bool use_first_thunk) {
	ok = false;

	export_dir = 0;
	imports = 0;
	exports = 0;
	this->use_first_thunk = use_first_thunk;

	input->read(reinterpret_cast<char*>(&this->signature), 4);

	if(signature != 0x4550) {
		cout << FATAL << "invalid PE signature: " << hex << setw(8) << uppercase << setfill(' ') << signature << endl;
		return;
	}

	// Read File Header.
	ifh = Alloc<IMAGE_FILE_HEADER>::anew();
	input->read(reinterpret_cast<char*>(ifh), sizeof(IMAGE_FILE_HEADER));

	if(!validate_machine()) {
		cout << FATAL << "invalid Machine: " << hex << setw(4) << uppercase << setfill(' ') << ifh->Machine << endl;
		return;
	}

	// TODO validate_characteristics();

	// Read Optional Header.
	ioh = Alloc<IMAGE_OPTIONAL_HEADER>::anew();
	input->read(reinterpret_cast<char*>(ioh), sizeof(IMAGE_OPTIONAL_HEADER));

	if(ioh->Magic != 0x10b) {
		cout << FATAL << "invalid PE Magic: " << hex << setw(4) << uppercase << setfill(' ') << ioh->Magic << endl;
		cout << FATAL << "(PE+ files are not supported)" << endl;
		return;
	}

	if(ioh->ImageBase % (64 * 1024)) {
		cout << WARNING << "ImageBase not multiple of 64kb" << endl;
	}

	if(!validate_subsystem()) {
		cout << FATAL << "invalid Subsystem: " << hex << setw(4) << uppercase << setfill(' ') << ioh->Subsystem << endl;
		return;
	}

	// TODO: SizeOfStackReserve/Commit, SizeOfHeapReserve/Commit - doesn't exist in DLLs.

	if(!sec_build(input)) {
		cout << FATAL << "section info corrupted." << endl;
		return;
	}

	// TODO: Validate sections & alignments.
	// TODO: Validate if there's code between sections.

	// Before dd_build.
	rvac = new RVAConverter(sections, ifh->NumberOfSections);

	int s1 = 0, s2 = 0;
	if(!rvac->check_overlaps(s1, s2)) {
		cout << FATAL << "section table is invalid: overlap at " << s1 << " and " << s2 << endl;
		return;
	}

	dd_build(input);

	ok = true;
}

PeHeader::~PeHeader() {
	if(imports)
		delete imports;

	if(exports)
		delete exports;

	if(rvac)
		delete rvac;

	if(sections) {
		for(int i = 0; i < ifh->NumberOfSections; i++)
			Alloc<IMAGE_SECTION_HEADER>::adelete(sections[i]);
		Alloc<IMAGE_SECTION_HEADER*>::adelete(sections);
	}

	Alloc<IMAGE_FILE_HEADER>::adelete(ifh);
	Alloc<IMAGE_OPTIONAL_HEADER>::adelete(ioh);

	if(export_dir)
		Alloc<IMAGE_EXPORT_DIRECTORY>::adelete(export_dir);
}

bool PeHeader::is_dll() {
	return ifh->Characteristics.dll;
}

bool PeHeader::sec_build(istream *input) {
	uint nos;

	if((nos = ifh->NumberOfSections) > 100)
		return false;

	sections = Alloc<IMAGE_SECTION_HEADER*>::anew(nos);

	for(uint i = 0; i < nos; i++) {
		sections[i] = Alloc<IMAGE_SECTION_HEADER>::anew();
		input->read(reinterpret_cast<char*>(sections[i]), sizeof(IMAGE_SECTION_HEADER));

		// cout << hex << setw(8) << setfill(' ');

		//cout << sections[i]->Name << ", RVA: " << sections[i]->VirtualAddress << ", PTR: " << sections[i]->PointerToRawData << endl;
		//cout << "VSIZE: " << sections[i]->Misc.VirtualSize << endl;
		/*
		cout << sections[i]->Name << ": ";
		if(sections[i]->Characteristics.code)
			cout << "code ";
		if(sections[i]->Characteristics.comdat)
			cout << "comdat ";
		if(sections[i]->Characteristics.discardable)
			cout << "discardable ";
		if(sections[i]->Characteristics.executable)
			cout << "executable ";
		if(sections[i]->Characteristics.extended_relocations)
			cout << "extrelocs ";
		if(sections[i]->Characteristics.fardata)
			cout << "fardata ";
		if(sections[i]->Characteristics.initialized_data)
			cout << "idata ";
		if(sections[i]->Characteristics.linker_info)
			cout << "linker info ";
		if(sections[i]->Characteristics.linker_info2)
			cout << "linker info 2 ";
		if(sections[i]->Characteristics.locked)
			cout << "locked ";
		if(sections[i]->Characteristics.not_cacheable)
			cout << "not cacheable ";
		if(sections[i]->Characteristics.not_pageable)
			cout << "not pageable ";
		if(sections[i]->Characteristics.readable)
			cout << "readable ";
		if(sections[i]->Characteristics.shared)
			cout << "shared ";
		if(sections[i]->Characteristics.uninitialized_data)
			cout << "udata ";
		if(sections[i]->Characteristics.writable)
			cout << "writable ";
		cout << endl;
		 **/
	}

	return true;
}

void PeHeader::dd_exports(istream *input) {
	assert(rvac != NULL);

	ulong size = ioh->DataDirectory[0].size, rva = ioh->DataDirectory[0].rva;
	if(rva == 0 || size == 0)
		return;

	uptr export_ptr = rvac->ptr_from_rva(rva);

	IMAGE_SECTION_HEADER *section = rvac->get_section_for_rva(rva);
	if(!section->Characteristics.initialized_data || !section->Characteristics.readable) {
		cout << WARNING << "export section (" << section->Name << ") has wrong "
				"characteristics: should be initialized_data and readable" << endl;
	}

	if(section->Characteristics.discardable) {
		cout << WARNING << "export section (" << section->Name << " has discardable "
				"flag." << endl;
	}

	export_dir = Alloc<IMAGE_EXPORT_DIRECTORY>::anew();
	input->seekg(export_ptr, ios_base::beg);
	input->read((char *) export_dir, sizeof(IMAGE_EXPORT_DIRECTORY));

	exports = new ExportDirectory(rvac, sections, ifh->NumberOfSections, export_dir, input, rva);
}

void PeHeader::dd_imports(istream *input) {
	assert(rvac != NULL);

	ulong size = ioh->DataDirectory[1].size, rva = ioh->DataDirectory[1].rva;
	if(rva == 0 || size == 0)
		return;

	uptr import_ptr = rvac->ptr_from_rva(rva);

	IMAGE_SECTION_HEADER *section = rvac->get_section_for_rva(rva);
	if(!section->Characteristics.initialized_data || !section->Characteristics.readable) {
		cout << WARNING << "import section (" << section->Name << ") has wrong "
				"characteristics: should be initialized_data and readable" << endl;
	}

	struct IMAGE_IMPORT_DESCRIPTOR import_d;
	input->seekg(import_ptr, ios_base::beg);

	imports = new ImportDirectory();

	// odczyt ciagly
	while(true) {
		input->read((char *) &import_d, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if(import_d.OriginalFirstThunk == 0 && import_d.FirstThunk == 0 && import_d.Name == 0)
			break;

		DLLImport *dlli = new DLLImport();
		dlli->first_thunk = import_d.FirstThunk;
		dlli->forwarder_chain = import_d.ForwarderChain;
		dlli->original_first_thunk = import_d.OriginalFirstThunk;
		dlli->time_date_stamp = import_d.TimeDateStamp;
		dlli->name_rva = import_d.Name;

		//if(dlli->original_first_thunk == 0)
		//	dlli->original_first_thunk = dlli->first_thunk;

		//assert(dlli->original_first_thunk != 0);
		assert(dlli->first_thunk != 0);
		assert(dlli->name_rva != 0);

		if(dlli->original_first_thunk)
			dlli->original_first_thunk_ptr = rvac->ptr_from_rva(dlli->original_first_thunk);

		if(dlli->first_thunk)
			dlli->first_thunk_ptr = rvac->ptr_from_rva(dlli->first_thunk);

		if(dlli->name_rva)
			dlli->name_ptr = rvac->ptr_from_rva(dlli->name_rva);

		imports->dlls->push_back(dlli);

		if(!input->good()) {
			cout << FATAL << "structure error when reading import table." << endl;
			return;
		}
	}

	IMAGE_THUNK_DATA thunk_data;

	// na wyrywki
	for(vector<DLLImport*>::iterator i = imports->dlls->begin(); i != imports->dlls->end(); ++i) {
		DLLImport *im = *i;
		assert(im->name_ptr != 0);
		input->seekg(im->name_ptr, ios_base::beg);

		char ch;
		while(input->good()) {
			input->get(ch);
			if(ch == 0)
				break;
			else
				im->name += ch;
		}

		if(use_first_thunk) {
			assert(im->first_thunk_ptr != 0);
			input->seekg(im->first_thunk_ptr, ios_base::beg);
		} else {
			if(im->original_first_thunk_ptr)
				input->seekg(im->original_first_thunk_ptr, ios_base::beg);
			else if(im->first_thunk_ptr)
				input->seekg(im->first_thunk_ptr, ios_base::beg);
			else {
				assert(im->original_first_thunk_ptr != 0 && im->first_thunk_ptr != 0);
			}
		}

		while(true) {
			uptr prev_offset = input->tellg();
			input->read((char *) &thunk_data, sizeof(IMAGE_THUNK_DATA));
			if(thunk_data.Function == 0)
				break;

			ImportFunction *func = new ImportFunction();

			func->thunk_offset = prev_offset;

			assert(func->thunk_offset != 0);
			func->thunk_rva = rvac->rva_from_ptr(func->thunk_offset);

			if(thunk_data.Function & 0x80000000) {
				func->ordinal = true;
				func->thunk_value = thunk_data.Function ^ 0x80000000;
				func->inited = true;
				func->thunk_ptr = 0;
			} else {
				func->thunk_value = thunk_data.Function;
				func->inited = false;
				assert(thunk_data.Function != 0);

				if(rvac->get_section_for_rva(thunk_data.Function) == NULL) {
					// bound import
					ostringstream oss(ostringstream::out);

					func->thunk_ptr = 0;
					oss << "Memory location: " << hex << setw(8) << setfill('0') << thunk_data.Function;
					func->api_name = oss.str();

					func->bound = true;
					func->inited = true;
				} else {
					func->thunk_ptr = rvac->ptr_from_rva(thunk_data.Function);
				}
			}

			im->functions->push_back(func);

			if(!input->good() || thunk_data.Function == 0)
				break;
		}

		for(vector<ImportFunction*>::iterator k = im->functions->begin(); k != im->functions->end(); ++k) {
			ImportFunction *func = *k;

			if(func->inited && !func->ordinal)
				continue;

			input->seekg(func->thunk_ptr, ios_base::beg);

			ushort hint;
			input->read((char *) &hint, 2);
			func->hint = hint;

			while(input->good()) {
				input->get(ch);
				if(ch == 0) break;

				func->api_name += ch;
			}

			func->inited = true;
		}
	}
}

void PeHeader::dd_build(istream *input) {
	dd_exports(input);
	dd_imports(input);

	/*
	dd_resoures();
	dd_exceptions();
	dd_security();
	dd_basereloc();
	dd_debug();
	dd_copyright();
	dd_machineval();
	dd_loadconfig();
	dd_boundimport();
	dd_iat();
	dd_delayimport();
	dd_complus();
	dd_reserved();
	*/
}

bool PeHeader::validate_subsystem() {
	ushort subsystem = ioh->Subsystem;

	ushort values[] = {
		IMAGE_SUBSYSTEM_NATIVE,
		IMAGE_SUBSYSTEM_WINDOWS_GUI,
		IMAGE_SUBSYSTEM_WINDOWS_CUI,
		IMAGE_SUBSYSTEM_OS2_CUI,
		IMAGE_SUBSYSTEM_POSIX_CUI,
		IMAGE_SUBSYSTEM_WINCE_GUI,
		IMAGE_SUBSYSTEM_EFI,
		IMAGE_SUBSYSTEM_EFI_BOOT,
		IMAGE_SUBSYSTEM_EFI_RUNTIME
	};

	for(int i = 0, len = sizeof(values); i < len; i++)
		if(subsystem == values[i])
			return true;

	return false;
}

bool PeHeader::validate_machine() {
	ushort machine = ifh->Machine;

	uint values[] = {
		IMAGE_FILE_MACHINE_I386,
		IMAGE_FILE_MACHINE_I486,
		IMAGE_FILE_MACHINE_PENTIUM,
		IMAGE_FILE_MACHINE_R3000_BE,
		IMAGE_FILE_MACHINE_R3000_LE,
		IMAGE_FILE_MACHINE_R4000_BE,
		IMAGE_FILE_MACHINE_R10000_LE,
		IMAGE_FILE_MACHINE_ALPHA,
		IMAGE_FILE_MACHINE_PPC
	};

	for(int i = 0, len = sizeof(values); i < len; i++)
		if(machine == values[i])
			return true;

	return false;
}

