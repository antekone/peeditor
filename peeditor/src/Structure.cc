#include "ped.hpp"

#include "Structure.hpp"
#include "Utils.hpp"

Structure::Structure(istream *input, bool use_ft, uint addr_trace) {
	this->input = input;
	use_first_thunk = use_ft;
	trace_ctx = NULL;
	ok = false;

	if(addr_trace != UINT_NOVALUE)
		trace_ctx = new TraceCtx(addr_trace);

	tracing = trace_ctx != NULL;
	parse();
}

Structure::~Structure() {
	delete mz;
	delete pe;

	if(trace_ctx)
		delete trace_ctx;
}

void Structure::parse() {
	// Read MZ header.
	if(!(mz = new MzHeader(input, trace_ctx))->ok)
		// If it fails, bail out.
		return;

	// Calculate the offset to PE header.
	uint pos = input->tellg(), npe = mz->get_e_lfanew();
	if(npe <= pos) {
		cout << WARNING << "Abnormal PE header offset - no DOS stub found." << endl;

		// Invalidate the MZ header and seek for correct PE header.
		mz->invalidate();
		input->seekg(npe, ios_base::beg);
	} else {
		// Allocate memory for storing the DOS stub program.
		int dos_stub_size = npe - pos;
		byte *mem = Alloc<byte>::anew(dos_stub_size);

		// Store the DOS stub program.
		TRACE_CTX(_("Reading DOS stub program at 0x%08X", (uint) input->tellg()));
		RANGE_CHECK(input, dos_stub_size);
		input->read(reinterpret_cast<char*>(mem), dos_stub_size);
		mz->set_dos_stub(mem, dos_stub_size);

		Alloc<byte>::adelete(mem);
	}

	// Should be OK when istream is ifstream's parent.
	ulong cur_ptr = input->tellg();
	assert(cur_ptr == mz->get_e_lfanew());

	// Check PE header start offset alignment -- not mandatory.
	if(cur_ptr % 8 > 0)
		cout << WARNING << "PE file header is not aligned to 8: start offset is " << hex << uppercase << setw(8) << setfill('0') << cur_ptr << endl;

	// Read PE header.
	if(!(pe = new PeHeader(input, use_first_thunk, trace_ctx))->ok)
		return;

	if(hdr_ptrs()) {
		cout << INFO << "Header pointers detected. File may be packed." << endl;
	}

	ok = true;
}

void Structure::parse_mz() {

}

bool Structure::is_dll() {
	return pe->is_dll();
}

bool Structure::hdr_ptrs() {
	return pe->rvac->hdr_ptrs;
}

// It's NOT for comparing with file's size. This proc doesn't take into consideration for example
// the space after section headers and the first section.
uint Structure::get_image_size() {
	uint raw_size = sizeof(MZ_HEADER);

	if(mz->has_stub())
		raw_size += mz->dos_stub_size;

	raw_size += 4; // IMAGE_NT_SIGNATURE
	raw_size += sizeof(IMAGE_FILE_HEADER);
	raw_size += sizeof(IMAGE_OPTIONAL_HEADER);
	raw_size += Utils::align(sizeof(IMAGE_SECTION_HEADER) * pe->ifh->NumberOfSections, pe->ioh->FileAlignment);

	for(int i = 0, size = pe->ifh->NumberOfSections; i < size; ++i) {
		Section *sect = pe->sections_data[i];
		raw_size += Utils::align(sect->rsz, pe->ioh->FileAlignment);
	}

	return raw_size;
}
