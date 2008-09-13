/*
 * PeBuilder.cc
 *
 *  Created on: 2008-08-08
 *      Author: antek
 */

#include "ped.hpp"
#include "Utils.hpp"
#include "Structure.hpp"
#include "PeBuilder.hpp"
#include "FlatAlloc.hpp"

PeBuilder::PeBuilder(Structure *s) {
	this->s = s;
	pe_start_delta = 0;
}

PeBuilder::~PeBuilder() {

}

byte *PeBuilder::build_pe() {
	new_mz();

	MzHeader *mzs = s->mz;
	int fill, ofs = sizeof(MZ_HEADER);

	FILE *fp = fopen("test.bin", "w");
	fwrite(mzh, sizeof(MZ_HEADER), 1, fp);

	if(s->mz->has_stub()) {
		fwrite(mzs->dos_stub, mzs->dos_stub_size, 1, fp);
		ofs += mzs->dos_stub_size;
	}

	fill = get_pe_start_aligned(mzs) - ofs;
	char ch = 0;
	for(int i = 0; i < fill; i++)
		fwrite((char *) &ch, 1, 1, fp);

	uptr new_pe_start = get_pe_start_aligned(mzs),
		old_pe_start = mzs->get_e_lfanew();

	pe_start_delta = new_pe_start - old_pe_start;

	new_pe();

	fwrite(filehdr, sizeof(IMAGE_FILE_HEADER) + 4, 1, fp);
	fwrite(opthdr, sizeof(IMAGE_OPTIONAL_HEADER), 1, fp);
	fwrite(secthdrs, secthdrs_sz, 1, fp);
	fwrite(sectdata, sectdata_sz, 1, fp);
	fclose(fp);

	/*
	new_imptbl();

	fp = fopen("impdir.bin", "w");
	fwrite(imptbl, imptbl_sz, 1, fp);
	fclose(fp);

	Alloc<byte>::adelete(imptbl);
	*/

	return NULL;
}

void PeBuilder::new_mz() {
	assert(s->mz != NULL);

	mzh = Alloc<byte>::anew(sizeof(MZ_HEADER));

	MzHeader *cmz = s->mz;
	MZ_HEADER *mz = reinterpret_cast<MZ_HEADER *>(mzh);

	if(cmz->has_stub()) {
		mz->e_cblp = cmz->hdr->e_cblp;
		mz->e_cp = cmz->hdr->e_cp;
		mz->e_cparhdr = cmz->hdr->e_cparhdr;
		mz->e_crlc = cmz->hdr->e_crlc;
		mz->e_cs = cmz->hdr->e_cs;
		mz->e_csum = cmz->hdr->e_csum;
		mz->e_ip = cmz->hdr->e_ip;
		mz->e_lfanew = get_pe_start_aligned(cmz);
		mz->e_lsarlc = cmz->hdr->e_lsarlc;
		mz->e_magic = 'ZM';
		mz->e_maxalloc = cmz->hdr->e_maxalloc;
		mz->e_minalloc = cmz->hdr->e_minalloc;
		mz->e_oemid = cmz->hdr->e_oemid;
		mz->e_oeminfo = cmz->hdr->e_oeminfo;
		mz->e_ovno = cmz->hdr->e_ovno;
		memcpy(mz->e_res, cmz->hdr->e_res, sizeof(mz->e_res));
		memcpy(mz->e_res2, cmz->hdr->e_res2, sizeof(mz->e_res2));
		mz->e_sp = cmz->hdr->e_sp;
		mz->e_ss = cmz->hdr->e_ss;
	} else {
		// complete rebuild of tampered pe header.
		byte *dos_stub = Alloc<byte>::anew(0x21);
		char *banner_text = (char*) "http://anadoxin.org/blog";
		strcpy((char*) dos_stub, banner_text);

		cmz->set_dos_stub(dos_stub, strlen(banner_text) + 1);
		Alloc<byte>::adelete(dos_stub);

		mz->e_magic = 'ZM';
		mz->e_cparhdr = (sizeof(mz) + 0x0f) / 0x10;
		mz->e_lfanew = get_pe_start_aligned(cmz);
		mz->e_lsarlc = get_pe_start_aligned(cmz);
		mz->e_maxalloc = 0xffff;
		mz->e_minalloc = 0;
		mz->e_oemid = 0xa1;     // ;)
		mz->e_oeminfo = 0xbabe; // ;)
		mz->e_sp = 0xb8;
		mz->e_ss = 0;
	}
}

uptr PeBuilder::get_pe_start_unaligned(MzHeader *mzs) {
	uptr ptr = sizeof(MZ_HEADER);

	if(mzs->has_stub())
		ptr += mzs->dos_stub_size;

	return ptr;
}

uptr PeBuilder::get_pe_start_aligned(MzHeader *mzs) {
	uptr ptr = get_pe_start_unaligned(mzs);

	// Make sure the PE starts at offset that is aligned to 8.
	return Utils::align(ptr, 8);
}

void PeBuilder::new_pe() {
	PeHeader *pe = s->pe;

	filehdr = Alloc<byte>::anew(sizeof(IMAGE_FILE_HEADER) + 4); // + signature
	opthdr = Alloc<byte>::anew(sizeof(IMAGE_OPTIONAL_HEADER));

	IMAGE_FILE_HEADER *fh = (IMAGE_FILE_HEADER *) &filehdr[4];
	IMAGE_OPTIONAL_HEADER *oh = (IMAGE_OPTIONAL_HEADER *) opthdr;
	ushort *signature_lo = (ushort *) filehdr;
	ushort *signature_hi = (ushort *) &filehdr[2];

	// file header
	*signature_lo = 0x4550;
	*signature_hi = 0;
	fh->Characteristics = pe->ifh->Characteristics;
	fh->Machine = pe->ifh->Machine;
	fh->NumberOfSections = pe->ifh->NumberOfSections;
	fh->NumberOfSymbols = pe->ifh->NumberOfSymbols;
	fh->SizeOfOptionalHeader = pe->ifh->SizeOfOptionalHeader;
	fh->TimeDateStamp = time(NULL);

	// optional header
	oh->Magic = pe->ioh->Magic;
	oh->AddressOfEntryPoint = pe->ioh->AddressOfEntryPoint;
	oh->BaseOfCode = pe->ioh->BaseOfCode;
	oh->BaseOfData = pe->ioh->BaseOfData;
	oh->CheckSum = pe->ioh->CheckSum; // TODO calculate valid checksum
	oh->DllCharacteristics = pe->ioh->DllCharacteristics;
	oh->FileAlignment = pe->ioh->FileAlignment;
	oh->ImageBase = pe->ioh->ImageBase;
	oh->LoaderFlags = pe->ioh->LoaderFlags;
	oh->MajorImageVersion = pe->ioh->MajorImageVersion;
	oh->MajorLinkerVersion = pe->ioh->MajorLinkerVersion;
	oh->MajorOperatingSystemVersion = pe->ioh->MajorOperatingSystemVersion;
	oh->MajorSubsystemVersion = pe->ioh->MajorSubsystemVersion;
	oh->MinorImageVersion = pe->ioh->MinorImageVersion;
	oh->MinorLinkerVersion = pe->ioh->MinorLinkerVersion;
	oh->MinorOperatingSystemVersion = pe->ioh->MinorOperatingSystemVersion;
	oh->MinorSubsystemVersion = pe->ioh->MinorSubsystemVersion;
	oh->NumberOfRvaAndSizes = pe->ioh->NumberOfRvaAndSizes;
	oh->Reserved1 = pe->ioh->Reserved1;
	oh->SectionAlignment = pe->ioh->SectionAlignment;
	oh->SizeOfCode = pe->ioh->SizeOfCode;
	oh->SizeOfHeaders = pe->ioh->SizeOfHeaders;
	oh->SizeOfHeapCommit = pe->ioh->SizeOfHeapCommit;
	oh->SizeOfHeapReserve = pe->ioh->SizeOfHeapReserve;
	oh->SizeOfImage = pe->ioh->SizeOfImage;
	oh->SizeOfInitializedData = pe->ioh->SizeOfInitializedData;
	oh->SizeOfStackCommit = pe->ioh->SizeOfStackCommit;
	oh->SizeOfStackReserve = pe->ioh->SizeOfStackReserve;
	oh->SizeOfUninitializedData = pe->ioh->SizeOfUninitializedData;
	oh->Subsystem = pe->ioh->Subsystem;

	// export table, placeholder.

	oh->DataDirectory[0].rva = pe->ioh->DataDirectory[0].rva;
	oh->DataDirectory[1].rva = pe->ioh->DataDirectory[1].rva;

	oh->DataDirectory[0].size = pe->ioh->DataDirectory[0].size;
	oh->DataDirectory[1].size = pe->ioh->DataDirectory[1].size;

	// section info
	uint nos = fh->NumberOfSections;
	uint align_fill;

	secthdrs_sz = nos * sizeof(IMAGE_SECTION_HEADER);
	uint header_size = sizeof(IMAGE_FILE_HEADER) +
		sizeof(IMAGE_OPTIONAL_HEADER) +
		sizeof(MZ_HEADER) +
		(s->mz->has_stub()? s->mz->stub_size(): 0) +
		4; // sygnatura PE

	align_fill = oh->FileAlignment - (secthdrs_sz + header_size) % oh->FileAlignment;

	secthdrs_sz += align_fill;
	secthdrs = Alloc<byte>::anew(secthdrs_sz);

	// q: czy miejsce na deskryptory sekcji jest stale? ile moze byc max sekcji?
	// sizeofheaders to jest wlasnie ta wartosc?
	for(uint i = 0; i < nos; i++) {
		Section *src = pe->sections_data[i];
		IMAGE_SECTION_HEADER *dst = (IMAGE_SECTION_HEADER *) &secthdrs[i * sizeof(IMAGE_SECTION_HEADER)];

		dst->NumberOfLinenumbers = src->lineno_n;
		dst->NumberOfRelocations = src->reloc_n;
		dst->PointerToLinenumbers = src->lineno_ptr; // TODO fix pointer
		dst->PointerToRelocations = src->reloc_ptr; // TODO fix pointer
		dst->Characteristics.dword = src->traits;
		dst->SizeOfRawData = src->rsz;
		dst->VirtualAddress = src->va;
		dst->Misc.VirtualSize = src->vsz;
		dst->PointerToRawData = src->raw; // TODO fix pointer

		Utils::string_to_bytearray(dst->Name, src->name, sizeof(dst->Name));
	}

	byte *bonus_space = (byte *) &secthdrs[nos * sizeof(IMAGE_SECTION_HEADER)];
	uint bonus_space_size = align_fill;
	if(bonus_space_size >= 3) {
		// embed editor signature (if enough room).
		byte mark[3] = { 0xA1, 0xBA, 0xBE };
		memcpy(bonus_space, mark, 3);
	}

	// store section datas.
	uptr cptr = header_size + secthdrs_sz;
	sectdata_sz = 0;
	RVAConverter *c = s->pe->rvac;
	for(uint i = 0; i < nos; i++) {
		IMAGE_SECTION_HEADER *usect = c->get_section_for_ptr(cptr);
		if(usect == NULL)
			continue;

		cptr += usect->SizeOfRawData;
		sectdata_sz += usect->SizeOfRawData;
	}

	uint cptrd = 0;
	byte *mem = NULL;
	Section *csect = NULL;
	IMAGE_SECTION_HEADER *usect = NULL;

	sectdata = Alloc<byte>::anew(sectdata_sz);
	mem = (byte *) sectdata;
	cptr = header_size + secthdrs_sz;
	cptrd = cptr;

	for(uint i = 0; i < nos; i++) {
		usect = c->get_section_for_ptr(cptr);
		if(!usect)
			continue;

		csect = pe->get_csection_for_section(usect);
		assert(csect != NULL);

		//printf("storing to %X (from %p), size=%d\n", usect->PointerToRawData - cptrd, csect->data, usect->SizeOfRawData);
		memcpy(&mem[usect->PointerToRawData - cptrd], csect->data, usect->SizeOfRawData);
		cptr += usect->SizeOfRawData;
	}
}

uint PeBuilder::get_dll_names_sz() {
	ImportDirectory *im = s->pe->imports;
	uint size = 0;

	for(vector<DLLImport*>::iterator it = im->dlls->begin(); it != im->dlls->end(); ++it) {
		DLLImport *dlli = (*it);

		size += dlli->name.size() + 1;
	}

	return size;
}

uint PeBuilder::get_all_names_sz() {
	ImportDirectory *im = s->pe->imports;
	uint size = 0;

	for(vector<DLLImport*>::iterator it = im->dlls->begin(); it != im->dlls->end(); ++it) {
		DLLImport *dlli = (*it);

		for(vector<ImportFunction*>::iterator itl = dlli->functions->begin(); itl != dlli->functions->end(); ++itl) {
			ImportFunction* fi = (*itl);

			size += fi->api_name.size() + 3; // + hint (ushort), + 1 trailing zero byte.
		}
	}

	return size;
}

void PeBuilder::new_imptbl() {
	// Table contains pointers to library names, relative to the base of the memory.
	uptr *dll_names_va = NULL, *mem = NULL;
	uint dll_cnt;
	int membase = NULL;

	int dll_names_sz = get_dll_names_sz(), all_names_sz = get_all_names_sz();
	FlatAlloc fa(dll_names_sz + all_names_sz);

	imptbl = fa.get_base();
	imptbl_sz = fa.get_size();

	ImportDirectory *im = s->pe->imports;
	dll_cnt = im->dlls->size();

	// create array of dll names.
	dll_names_va = Alloc<uptr>::anew(dll_cnt);

	// store names in this array.
	for(uint i = 0; i < dll_cnt; i++) {
		string& str = im->dlls->at(i)->name;
		int str_n = str.size();
		const char *name = str.c_str();

		mem = (uptr*) fa.alloc(str_n + 1, &membase); // + zero byte
		strncpy((char*) mem, name, str_n); // store name

		dll_names_va[i] = (uptr) membase;
	}

	// build IMAGE_IMPORT_BY_NAMEs.
	for(uint i = 0; i < dll_cnt; i++) {
		DLLImport *dlli = im->dlls->at(i);
		vector<ImportFunction*> *ifuncs = dlli->functions;
		uint func_cnt = ifuncs->size();

		if(dlli->names) {
			Alloc<uptr>::adelete(dlli->names);
			dlli->names = NULL;
		} else {
			dlli->names = Alloc<uptr>::anew(func_cnt);
		}

		for(uint k = 0; k < func_cnt; k++) {
			ImportFunction *func = ifuncs->at(k);

			string& str = func->api_name;
			int str_n = str.size();
			const char *name = str.c_str();

			mem = (uptr*) fa.alloc(str_n + 3, &membase); // + hint (ushort) + zero byte
			dlli->names[k] = membase;

			memcpy((void *) mem, &func->hint, 2);
			strncpy((char*) mem + 2, name, str_n);
		}
	}

	for(uint i = 0; i < dll_cnt; i++) {
		printf("Name: %s, addr: %08X\n", (const char *) im->dlls->at(i)->name.c_str(), (unsigned int) dll_names_va[i]);
	}
	// build original first thunk chain.

	// build first thunk chain.

	// build IMAGE_IMPORT_DESCRIPTORS array.

}
