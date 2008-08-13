#include "ped.hpp"
#include "RVAConverter.hpp"
#include "PeHeader.hpp"
#include "ImportDirectory.hpp"

PeHeader::PeHeader(istream *input, bool use_first_thunk, TraceCtx *trace) {
	ok = false;

	export_dir = 0;
	imports_first_thunk = NULL;
	imports_original_first_thunk = NULL;
	exports = 0;
	this->use_first_thunk = use_first_thunk;

	trace_ctx = trace;
	tracing = trace_ctx != NULL;

	TRACE_CTX(_("Reading NT signature ('PE') at 0x%08X.", (uint) input->tellg()));
	RANGE_CHECK(input, 4);
	input->read((char*) &this->signature, 4);

	if(signature != 0x4550) {
		cout << FATAL << "invalid PE signature: " << hex << setw(8) << uppercase << setfill(' ') << signature << endl;
		return;
	}

	// Read File Header.
	ifh = Alloc<IMAGE_FILE_HEADER>::anew();

	TRACE_CTX(_("Reading IMAGE_FILE_HEADER (%d bytes) at 0x%08X.",
			sizeof(IMAGE_FILE_HEADER), (uint) input->tellg()));
	RANGE_CHECK(input, sizeof(IMAGE_FILE_HEADER));
	input->read((char *) ifh, sizeof(IMAGE_FILE_HEADER));

	if(!validate_machine()) {
		cout << FATAL << "invalid Machine: " << hex << setw(4) << uppercase << setfill(' ') << ifh->Machine << endl;
		return;
	}

	// TODO validate_characteristics();

	// Read Optional Header.
	ioh = Alloc<IMAGE_OPTIONAL_HEADER>::anew();
	TRACE_CTX(_("Reading IMAGE_OPTIONAL_HEADER (%d bytes) at 0x%08X.",
			sizeof(IMAGE_OPTIONAL_HEADER), (uint) input->tellg()));
	RANGE_CHECK(input, sizeof(IMAGE_OPTIONAL_HEADER));
	input->read((char*) ioh, sizeof(IMAGE_OPTIONAL_HEADER));

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

	TRACE_CTX(_("Preparing to interpret section headers."));
	if(!sec_build(input)) {
		cout << FATAL << "section info corrupted." << endl;
		return;
	}
	TRACE_CTX(_("Interpretation of section headers completed."));

	// TODO: Validate sections & alignments.
	// TODO: Validate if there's code between sections.

	// Before dd_build.
	rvac = new RVAConverter(sections, ifh->NumberOfSections);

	TRACE_CTX(_("Checking section overlaps."));
	int s1 = 0, s2 = 0;
	if(!rvac->check_overlaps(s1, s2)) {
		cout << FATAL << "section table is invalid: overlap at " << s1 << " and " << s2 << endl;
		return;
	}

	TRACE_CTX(_("Preparing to interpret data directories."));
	dd_build(input);
	TRACE_CTX(_("Interpretation of data directories completed."));

	// TODO: Check if entrypoint is in some section. If not, maybe it's
	// a SpaceFiller virus? (idea taken from Wine).

	TRACE_CTX(_("Making bonus checks."));
	TRACE_CTX(_("Bonus checks completed."));
	ok = true;
}

PeHeader::~PeHeader() {
	if(imports_first_thunk)
		delete imports_first_thunk;

	if(imports_original_first_thunk)
		delete imports_original_first_thunk;

	if(exports)
		delete exports;

	if(rvac)
		delete rvac;

	if(sections) {
		for(int i = 0; i < ifh->NumberOfSections; i++)
			Alloc<IMAGE_SECTION_HEADER>::adelete(sections[i]);
		Alloc<IMAGE_SECTION_HEADER*>::adelete(sections);
	}

	if(sections_data) {
		Alloc<Section>::adeletearray(sections_data, ifh->NumberOfSections);
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

	if((nos = ifh->NumberOfSections) > 100) {
		TRACE_CTX(_("Too many sections - %d - bailing out.", nos));
		return false;
	}

	TRACE_CTX(_("Reading %d sections (according to file_header->NumberOfSections", nos));
	sections = Alloc<IMAGE_SECTION_HEADER*>::anew(nos);
	sections_data = Alloc<Section>::anewarray(nos);

	for(uint i = 0; i < nos; i++) {
		sections[i] = Alloc<IMAGE_SECTION_HEADER>::anew();

		TRACE_CTX(_("Reading section's %d header (%d bytes) at 0x%08X.", i,
				sizeof(IMAGE_SECTION_HEADER), (uint) input->tellg()));
		RANGE_CHECK(input, sizeof(IMAGE_SECTION_HEADER));
		input->read((char *) sections[i], sizeof(IMAGE_SECTION_HEADER));
	}

	for(uint i = 0; i < nos; i++) {
		TRACE_CTX(_("Interpretation of section %d follows:", i));
		sections_data[i]->init(input, sections[i], trace_ctx);
		TRACE_CTX(_("Interpretation of section %d complete.", i));
	}

	return true;
}

void PeHeader::dd_exports(istream *input) {
	assert(rvac != NULL);

	ulong size = ioh->DataDirectory[0].size, rva = ioh->DataDirectory[0].rva;
	if(rva == 0 || size == 0) {
		TRACE_CTX("Skipping Export Directory because it's not there.");
		return;
	}

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

	TRACE_CTX(_("Seeking to IMAGE_EXPORT_DIRECTORY struct at 0x%08X (ptr taken from DataDirectory[0].rva).", export_ptr));
	input->seekg(export_ptr, ios_base::beg);

	TRACE_CTX(_("Reading IMAGE_EXPORT_DIRECTORY (size: %d) struct at 0x%08X.", sizeof(IMAGE_EXPORT_DIRECTORY), (uint) input->tellg()));
	input->read((char *) export_dir, sizeof(IMAGE_EXPORT_DIRECTORY));

	exports = new ExportDirectory(rvac, sections, ifh->NumberOfSections, export_dir, input, rva, trace_ctx);
	exports->directory_ptr = export_ptr;
	exports->directory_rva = rva;
	exports->directory_size = size;
}

void PeHeader::dd_imports(istream *input) {
	assert(rvac != NULL);

	ulong size = ioh->DataDirectory[1].size, rva = ioh->DataDirectory[1].rva;
	if(rva == 0 || size == 0) {
		TRACE_CTX("Skipping Import Directory because it's not there.");
		return;
	}

	IMAGE_SECTION_HEADER *section = rvac->get_section_for_rva(rva);
	if(!section->Characteristics.initialized_data || !section->Characteristics.readable) {
		cout << WARNING << "import section (" << section->Name << ") has wrong "
				"characteristics: should be initialized_data and readable" << endl;
	}

	TRACE_CTX("Reading Import Table using FirstThunk chain.");
	imports_first_thunk = new ImportDirectory(rvac, sections, ifh->NumberOfSections, input, rva, true, trace_ctx);
	TRACE_CTX("Reading Import Table using OriginalFirstThunk chain.");
	imports_original_first_thunk = new ImportDirectory(rvac, sections, ifh->NumberOfSections, input, rva, false, trace_ctx);

	Section *s = get_csection_for_section(section);
	imports_first_thunk->section_name = s->name;
	imports_original_first_thunk->section_name = s->name;
}

void PeHeader::dd_build(istream *input) {

	TRACE_CTX("Interpratation of Export Directory follows:");
	dd_exports(input); // 0
	TRACE_CTX("Interpretation of Export Directory complete.");

	TRACE_CTX("Interpratation of Import Directory follows:");
	dd_imports(input); // 1
	TRACE_CTX("Interpratation of Import Directory follows:");

	/*
	dd_resoures();     // 2
	dd_exceptions();   // 3
	dd_security();     // 4
	dd_basereloc();    // 5
	dd_debug();        // 6
	dd_copyright();    // 7
	dd_machineval();   // 8
	dd_loadconfig();   // 9
	dd_boundimport();  // 10
	dd_iat();          // 11
	dd_delayimport();  // 12
	dd_complus();      // 13
	dd_reserved();     // 14
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

Section *PeHeader::get_csection_for_section(IMAGE_SECTION_HEADER *section) {
	int nos = ifh->NumberOfSections;
	for(int i = 0; i < nos; i++) {
		// compare pointers.
		if(sections_data[i]->orig == section) {
			return sections_data[i];
		}
	}

	return NULL;
}

void PeHeader::dump_trace_result(ostringstream &os) {
	if(tracing)
		trace_ctx->dump(os);
	else
		os << "Tracing not enabled." << endl;
}
