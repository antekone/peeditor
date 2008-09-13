#include "ped.hpp"
#include "RVAConverter.hpp"
#include "PeHeader.hpp"
#include "ImportDirectory.hpp"
#include "Utils.hpp"

PeHeader::PeHeader(istream *input, bool use_first_thunk, TraceCtx *trace) {
	ok = false;

	export_dir = 0;
	imp_ft = NULL;
	imp_oft = NULL;
	exports = 0;
	this->use_first_thunk = use_first_thunk;
	hdata = NULL;
	hdata_sz = 0;

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
	// TODO: Validate if there's code between sections. (wine idea)

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

	TRACE_CTX(_("Checking for data/code in the header."));
	read_code_in_header(input);

	TRACE_CTX(_("Making bonus checks."));
	TRACE_CTX(_("Bonus checks completed."));

	ok = true;
}

PeHeader::~PeHeader() {
	if(imp_ft)
		delete imp_ft;

	if(imp_oft)
		delete imp_oft;

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

void PeHeader::read_code_in_header(istream *input) {
	// Do it only when header pointers were detected.
	if(rvac->hdr_ptrs) {
		input->seekg(lastsec_ptr);
		uptr fraw = rvac->get_smallest_ptr(),
			size = fraw - lastsec_ptr;

		if(size > 0) {
			hdata = Alloc<byte>::anew(size);
			input->read((char *) hdata, size);
			hdata_sz = size;
		}
	}
}

bool PeHeader::is_dll() {
	return ifh->Characteristics.dll;
}

bool PeHeader::sec_build(istream *input) {
	uint nos; // initialied below.
	uptr *ptrs = NULL;

	if((nos = ifh->NumberOfSections) > 100) {
		TRACE_CTX(_("Too many sections - %d - bailing out.", nos));
		return false;
	}

	ptrs = Alloc<uptr>::anew(nos);

	TRACE_CTX(_("Reading %d sections (according to file_header->NumberOfSections", nos));
	sections = Alloc<IMAGE_SECTION_HEADER*>::anew(nos);
	sections_data = Alloc<Section>::anewarray(nos);

	for(uint i = 0; i < nos; i++) {
		sections[i] = Alloc<IMAGE_SECTION_HEADER>::anew();

		uint last_pos = input->tellg();
		ptrs[i] = (uptr) last_pos;

		TRACE_CTX(_("Reading section's %d header (%d bytes) at 0x%08X.", i,
				sizeof(IMAGE_SECTION_HEADER), last_pos));
		RANGE_CHECK(input, sizeof(IMAGE_SECTION_HEADER));
		input->read((char *) sections[i], sizeof(IMAGE_SECTION_HEADER));
	}

	lastsec_ptr = (uptr) input->tellg();

	sync_csections_with_sections(nos, input, ptrs);
	return true;
}

void PeHeader::sync_csections_with_sections(int nos, istream *input, uptr *ptrs) {
	int falign = ioh->FileAlignment;//, salign = ioh->SectionAlignment;

	for(int i = 0; i < nos; i++) {
		TRACE_CTX(_("Interpretation of section %d follows:", i));

		Section *sect = sections_data[i];

		if(ptrs)
			sect->init(input, sections[i], trace_ctx, ptrs[i]);
		else
			sect->init(input, sections[i], trace_ctx, 0);

		if(sect->rsz % falign) {
			int new_align = sect->rsz + falign - (sect->rsz % falign);
			cout << WARNING << _("Section %d - size of raw (0x%X) data isn't properly aligned to 0x%X (should be 0x%X?)", i, sect->rsz, falign, new_align) << endl;
		}

		TRACE_CTX(_("Interpretation of section %d complete.", i));
	}
}

void PeHeader::grow_and_remap_csections(Section *nsect) {
	// This array will hold pointers to section datas. We don't want to
	// reallocate them, but we do want to reallocate the Section objects.
	// That's why we have to remember data pointers, recreate new
	// Section objects, and bind the data pointers to the new Section
	// objects - because Section object after creation has data pointer
	// fixed to NULL.
	vector<uptr> *datas = new vector<uptr>();

	int old_nos = ifh->NumberOfSections;
	int new_nos = ifh->NumberOfSections + 1;

	// Remember the data pointers.
	for(int i = 0; i < old_nos; i++) {
		uptr data = (uptr) sections_data[i]->data;
		datas->push_back(data);
	}

	// Deallocate the whole Section objects array.
	if(sections_data)
		Alloc<Section>::adeletearray(sections_data, old_nos);

	// Create a brand, new, shiny, and empty Section objects array that is
	// one item bigger than the old array.
	sections_data = Alloc<Section>::anewarray(new_nos);

	// Inject the new Section object into this array: first release the
	// last item (created by Alloc<Section>::anewarray()), and bind the
	// new Section object to the last place of the array.
	delete sections_data[old_nos];
	sections_data[old_nos] = nsect;

	// Synchronize Section objects with section structures in the `sections'
	// array.
	sync_csections_with_sections(new_nos);

	// Now, the Section objects are initialized. The only thing that needs
	// to be done is to recall the data pointers to these sections, because
	// right now they're all marked as abstract.
	for(int i = 0; i < old_nos; i++) {
		uptr data = datas->at(i);
		sections_data[i]->data = (byte *) data;
		sections_data[i]->abstract = (data == 0); // clear the abstract flag.
	}

	// Clear the junk.
	delete datas;
}

void PeHeader::grow_and_remap_sections(IMAGE_SECTION_HEADER *usect) {
	int o_slen, n_slen;
	assert(usect != NULL);

	o_slen = ifh->NumberOfSections;
	n_slen = ifh->NumberOfSections + 1;

	// Allocate memory for the new section header table.
	IMAGE_SECTION_HEADER **table = Alloc<IMAGE_SECTION_HEADER*>::anew(n_slen);

	// Copy the previous table to the new table.
	for(int i = 0; i < o_slen; i++) {
		// Create a new table item.
		table[i] = Alloc<IMAGE_SECTION_HEADER>::anew();

		// Do some sanity assertions.
		assert(sections[i]);

		// Copy the section header.
		memcpy((void *) table[i], (void *) sections[i], sizeof(IMAGE_SECTION_HEADER));
	}

	// The last item is reserved for the new section. First, create the item.
	table[n_slen - 1] = Alloc<IMAGE_SECTION_HEADER>::anew();

	// Then copy the new sections header.
	memcpy((void *) table[n_slen - 1], (void *) usect, sizeof(IMAGE_SECTION_HEADER));

	// Deallocate the old table.
	Alloc<IMAGE_SECTION_HEADER>::adeletearray(sections, o_slen);

	// As from now, the program will use new table.
	sections = table;
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
	imp_ft = new ImportDirectory(rvac, sections, ifh->NumberOfSections, input, rva, true, trace_ctx);
	TRACE_CTX("Reading Import Table using OriginalFirstThunk chain.");
	imp_oft = new ImportDirectory(rvac, sections, ifh->NumberOfSections, input, rva, false, trace_ctx);

	imports = use_first_thunk? imp_ft : imp_oft;

	Section *s = get_csection_for_section(section);
	imp_ft->section_name = s->name;
	imp_oft->section_name = s->name;
}

void PeHeader::dd_build(istream *input) {

	TRACE_CTX("Interpratation of Export Directory follows:");
	dd_exports(input); // 0
	TRACE_CTX("Interpretation of Export Directory complete.");

	TRACE_CTX("Interpratation of Import Directory follows:");
	dd_imports(input); // 1
	TRACE_CTX("Interpratation of Import Directory follows:");

	// TODO add more.

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

Section *PeHeader::get_csection_for_rva(uptr rva) {
	IMAGE_SECTION_HEADER *usect = rvac->get_section_for_rva(rva);
	assert(usect != NULL);
	return get_csection_for_section(usect);
}

Section *PeHeader::get_csection_for_ptr(uptr ptr) {
	IMAGE_SECTION_HEADER *usect = rvac->get_section_for_ptr(ptr);
	assert(usect != NULL);
	return get_csection_for_section(usect);
}

void PeHeader::dump_trace_result(ostringstream &os) {
	if(tracing)
		trace_ctx->dump(os);
	else
		os << "Tracing not enabled." << endl;
}

void PeHeader::csection_to_section(Section *sect, IMAGE_SECTION_HEADER *usect) {
	usect->Characteristics.dword = sect->traits;
	usect->Misc.VirtualSize = sect->vsz;
	Utils::string_to_bytearray(usect->Name, sect->name, sect->name.size());
	usect->NumberOfLinenumbers = sect->lineno_n;
	usect->NumberOfRelocations = sect->reloc_n;
	usect->PointerToLinenumbers = sect->lineno_ptr;
	usect->PointerToRawData = sect->raw;
	usect->PointerToRelocations = sect->reloc_ptr;
	usect->SizeOfRawData = sect->rsz;
	usect->VirtualAddress = sect->va;
}

void PeHeader::section_to_csection(IMAGE_SECTION_HEADER *s, Section *cs) {
	cs->init(NULL, s, NULL, 0);
}

Section *PeHeader::add_section(string name, int size) {
	assert(rvac != NULL);

	struct IMAGE_SECTION_HEADER *usect = Alloc<IMAGE_SECTION_HEADER>::anew();
	Section *nsect = new Section();

	Section *biggest_ptr, *biggest_va;

	biggest_ptr = get_csection_for_section(rvac->get_biggest_ptr_section());
	biggest_va = get_csection_for_section(rvac->get_biggest_va_section());

	assert(biggest_ptr);
	assert(biggest_va);

	uptr raw, va, rsz;

	// Calculate new raw and va values. There are two options to do that.
	// The first option is to search for an empty, unmapped spot in the executable.
	// If `size' is smaller or equal to the size of that empty spot, make a new
	// section there and map it. Searching for empty spots should be done using
	// section headers only. The same thing should be used when searching for
	// empty virtual spots. The good thing using this approach is that the size
	// of executable will not change. The main drawback is that it can be
	// complicated to write, and is bug-prone.
	// TODO this is not ready yet.

	// Second option, when the first one fails, is to append the new section
	// at the end of the image. Good thing is that it's easy to do, bad thing
	// is that the file size will be larger.

	// Calculate the next valid file pointer.
	raw = Utils::align(biggest_ptr->raw + biggest_ptr->rsz, ioh->FileAlignment);

	// Calculate the size or our new section (just align it).
	rsz = Utils::align(size, ioh->FileAlignment);

	// Calculate the next valid virtual address.
	va = Utils::align(biggest_va->va + 1 + biggest_va->vsz, ioh->SectionAlignment);

	// Use a failry standard section traits. They can be changed later, before
	// writing to the file, so they're not that important.
	usect->Characteristics.readable = true;
	usect->Characteristics.writable = true;
	usect->Characteristics.code = true;

	// Set the section values.
	usect->Misc.VirtualSize = size; // not aligned
	usect->PointerToRawData = raw; // aligned
	usect->SizeOfRawData = rsz; // aligned
	usect->VirtualAddress = va; // aligned

	// Clear unused values. TODO this values can only be seen in object files?
	usect->NumberOfLinenumbers = 0;
	usect->NumberOfRelocations = 0;
	usect->PointerToLinenumbers = 0;
	usect->PointerToRelocations = 0;

	// Set the name of the section.
	memcpy(usect->Name, name.c_str(), min(name.size(), sizeof(usect->Name)));

	// Create z Section object from the `usect' structure. This will allow
	// us to bind the section data to this section. Later the PE builder will
	// operate on Section objects and write this data to the file under
	// our offset (usect->PointerToRawData).
	section_to_csection(usect, nsect);

	// Allocate memory for the section data.
	nsect->data = Alloc<byte>::anew(rsz);

	// Since the section will have data, it has to have `abstract' field cleared.
	nsect->abstract = false;

	// Recreate structures that hold information about section headers
	// and section data. This will also fix NT headers.
	add_section(usect, nsect);

	// We don't need the structure anymore, since we have Section object.
	Alloc<IMAGE_SECTION_HEADER>::adelete(usect);

	return nsect;
}

void PeHeader::flush_sectn_in_header(Section *nsect) {
	ifh->NumberOfSections++;
	ioh->SizeOfImage = nsect->va + nsect->vsz;
}

void PeHeader::add_section(IMAGE_SECTION_HEADER *usect, Section *nsect) {
	// Add a new section to the `sections' array.
	grow_and_remap_sections(usect);

	// Add a new section to the `csections' array.
	grow_and_remap_csections(nsect);

	// Alter NT header to be able to "see" the new section.
	flush_sectn_in_header(nsect);

	// Reinitialize the RVA Converter to see the new section.
	if(rvac)
		delete rvac;

	rvac = new RVAConverter(sections, ifh->NumberOfSections);

	// Done.
}

bool PeHeader::remove_section(Section *sect) {
	throw 0;
}
