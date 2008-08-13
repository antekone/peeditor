#include "ped.hpp"

#include "MzHeader.hpp"

MzHeader::MzHeader(istream *in, TraceCtx *trace) {
	ok = false;
	trace_ctx = trace;
	tracing = trace_ctx != NULL;

	hdr = Alloc<struct MZ_HEADER>::anew();

	TRACE_CTX(_("Reading MZ header at 0x%08X.", (uint) in->tellg()));
	RANGE_CHECK(in, sizeof(MZ_HEADER));
	in->read(reinterpret_cast<char*>(hdr), sizeof(MZ_HEADER));

	ushort magic;
	if((magic = get_e_magic()) != 0x5a4d && magic != 0x4d5a) {
		cout << FATAL << "invalid MZ magic: " << uppercase << setw(4) << setfill('0') << hex << magic << endl;
		return;
	}

	TRACE_CTX(_("Got PE header offset from e_lfanew: 0x%08X.", get_e_lfanew()));

	dos_stub_size = -1;
	dos_stub = NULL;

	ok = true;
	valid = true;
}

MzHeader::~MzHeader() {
	if(hdr) Alloc<struct MZ_HEADER>::adelete(hdr);
	if(dos_stub) Alloc<byte>::adelete(dos_stub);
}

uptr MzHeader::get_e_lfanew() {
	assert(hdr);
	return hdr->e_lfanew;
}

ushort MzHeader::get_e_magic() {
	assert(hdr);
	return hdr->e_magic;
}

void MzHeader::set_dos_stub(byte *mem, uint len) {
	assert(mem != NULL);

	dos_stub = Alloc<byte>::anew(len);
	memcpy(dos_stub, mem, len);
	dos_stub_size = len;
}

byte *MzHeader::get_dos_stub() {
	return dos_stub;
}

uint MzHeader::get_dos_stub_size() {
	return dos_stub_size;
}

void MzHeader::invalidate() {
	valid = false;
}

bool MzHeader::is_valid() {
	return valid;
}

bool MzHeader::has_dos_stub() {
	return dos_stub_size != UINT_NOVALUE;
}
