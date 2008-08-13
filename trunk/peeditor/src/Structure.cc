#include "ped.hpp"

#include "Structure.hpp"

Structure::Structure(istream *input, bool use_ft, uint addr_trace) {
	this->input = input;
	use_first_thunk = use_ft;
	trace_ctx = NULL;

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
}

void Structure::parse_mz() {

}

bool Structure::is_dll() {
	return pe->is_dll();
}

bool Structure::hdr_ptrs() {
	return pe->rvac->hdr_ptrs;
}
