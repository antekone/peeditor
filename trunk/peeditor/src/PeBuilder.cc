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

PeBuilder::PeBuilder(Structure *s) {
	this->s = s;
}

PeBuilder::~PeBuilder() {

}

byte *PeBuilder::build_pe() {
	create_mz_header();
	create_pe_header();

	MzHeader *mzs = s->mz;

	FILE *fp = fopen("test.bin", "w");
	fwrite(mz_header, sizeof(MZ_HEADER), 1, fp);
	if(s->mz->has_dos_stub())
		fwrite(mzs->dos_stub, mzs->dos_stub_size, 1, fp);

	fwrite(file_header, sizeof(IMAGE_FILE_HEADER) + 4, 1, fp);
	fwrite(optional_header, sizeof(IMAGE_OPTIONAL_HEADER), 1, fp);
	fwrite(section_descriptors, section_descriptors_len, 1, fp);
	fwrite(section_data, section_data_len, 1, fp);
	fclose(fp);

	build_import_table();

	fp = fopen("impdir.bin", "w");
	fwrite(imptbl, imptblsz, 1, fp);
	fclose(fp);

	return NULL;
}

void PeBuilder::create_mz_header() {
	assert(s->mz != NULL);

	mz_header = Alloc<byte>::anew(sizeof(MZ_HEADER));

	MzHeader *mzs = s->mz;
	MZ_HEADER *mz = reinterpret_cast<MZ_HEADER *>(mz_header);

	if(mzs->has_dos_stub()) {
		mz->e_cblp = mzs->hdr->e_cblp;
		mz->e_cp = mzs->hdr->e_cp;
		mz->e_cparhdr = mzs->hdr->e_cparhdr;
		mz->e_crlc = mzs->hdr->e_crlc;
		mz->e_cs = mzs->hdr->e_cs;
		mz->e_csum = mzs->hdr->e_csum;
		mz->e_ip = mzs->hdr->e_ip;
		mz->e_lfanew = calc_e_lfanew(mzs);
		mz->e_lsarlc = mzs->hdr->e_lsarlc;
		mz->e_magic = 'ZM';
		mz->e_maxalloc = mzs->hdr->e_maxalloc;
		mz->e_minalloc = mzs->hdr->e_minalloc;
		mz->e_oemid = mzs->hdr->e_oemid;
		mz->e_oeminfo = mzs->hdr->e_oeminfo;
		mz->e_ovno = mzs->hdr->e_ovno;
		memcpy(mz->e_res, mzs->hdr->e_res, sizeof(mz->e_res));
		memcpy(mz->e_res2, mzs->hdr->e_res2, sizeof(mz->e_res2));
		mz->e_sp = mzs->hdr->e_sp;
		mz->e_ss = mzs->hdr->e_ss;
	} else {
		// complete rebuild of tampered pe header.
		byte *dos_stub = Alloc<byte>::anew(0x21);
		char *banner_text = (char*) "http://anadoxin.org/blog";
		strcpy((char*) dos_stub, banner_text);

		mzs->set_dos_stub(dos_stub, strlen(banner_text) + 1);
		Alloc<byte>::adelete(dos_stub);

		mz->e_magic = 'ZM';
		mz->e_cparhdr = (sizeof(mz) + 0x0f) / 0x10;
		mz->e_lfanew = calc_e_lfanew(mzs);
		mz->e_lsarlc = calc_e_lfanew(mzs);
		mz->e_maxalloc = 0xffff;
		mz->e_minalloc = 0;
		mz->e_oemid = 0xa1;
		mz->e_oeminfo = 0xbabe;
		mz->e_sp = 0xb8;
		mz->e_ss = 0;
	}
}

uptr PeBuilder::calc_e_lfanew(MzHeader *mzs) {
	uptr ptr = sizeof(MZ_HEADER);

	if(mzs->has_dos_stub())
		ptr += mzs->dos_stub_size;

	return ptr;
}

void PeBuilder::create_pe_header() {
	PeHeader *pe = s->pe;

	file_header = Alloc<byte>::anew(sizeof(IMAGE_FILE_HEADER) + 4); // + signature
	optional_header = Alloc<byte>::anew(sizeof(IMAGE_OPTIONAL_HEADER));

	IMAGE_FILE_HEADER *fh = (IMAGE_FILE_HEADER *) &file_header[4];
	IMAGE_OPTIONAL_HEADER *oh = (IMAGE_OPTIONAL_HEADER *) optional_header;
	ushort *signature_lo = (ushort *) file_header;
	ushort *signature_hi = (ushort *) &file_header[2];

	// file header
	*signature_lo = 0x4550;
	*signature_hi = 0;
	fh->Characteristics = pe->ifh->Characteristics;
	fh->Machine = pe->ifh->Machine;
	fh->NumberOfSections = pe->ifh->NumberOfSections;
	fh->NumberOfSymbols = pe->ifh->NumberOfSymbols;
	fh->SizeOfOptionalHeader = pe->ifh->SizeOfOptionalHeader;
	//fh->TimeDateStamp = pe->ifh->TimeDateStamp;
	fh->TimeDateStamp = time(NULL);

	// optional header
	oh->AddressOfEntryPoint = pe->ioh->AddressOfEntryPoint;
	oh->BaseOfCode = pe->ioh->BaseOfCode;
	oh->BaseOfData = pe->ioh->BaseOfData;
	oh->CheckSum = pe->ioh->CheckSum; // TODO calculate valid checksum
	oh->DllCharacteristics = pe->ioh->DllCharacteristics;
	oh->FileAlignment = pe->ioh->FileAlignment;
	oh->ImageBase = pe->ioh->ImageBase;
	oh->LoaderFlags = pe->ioh->LoaderFlags;
	oh->Magic = pe->ioh->Magic;
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

	oh->DataDirectory[0].rva = pe->ioh->DataDirectory[0].rva;
	oh->DataDirectory[1].rva = pe->ioh->DataDirectory[1].rva;

	oh->DataDirectory[0].size = pe->ioh->DataDirectory[0].size;
	oh->DataDirectory[1].size = pe->ioh->DataDirectory[1].size;

	// section info
	uint nos = fh->NumberOfSections;
	uint align_fill;

	section_descriptors_len = nos * sizeof(IMAGE_SECTION_HEADER);
	uint header_size = sizeof(IMAGE_FILE_HEADER) +
		sizeof(IMAGE_OPTIONAL_HEADER) +
		sizeof(MZ_HEADER) +
		(s->mz->has_dos_stub()? s->mz->get_dos_stub_size(): 0) +
		4; // sygnatura PE

	align_fill = oh->FileAlignment - (section_descriptors_len + header_size) % oh->FileAlignment;

	section_descriptors_len += align_fill;
	section_descriptors = Alloc<byte>::anew(section_descriptors_len);

	// q: czy miejsce na deskryptory sekcji jest stale? ile moze byc max sekcji?
	// sizeofheaders to jest wlasnie ta wartosc?
	for(uint i = 0; i < nos; i++) {
		Section *src = pe->sections_data[i];
		IMAGE_SECTION_HEADER *dst = (IMAGE_SECTION_HEADER *) &section_descriptors[i * sizeof(IMAGE_SECTION_HEADER)];

		dst->NumberOfLinenumbers = src->number_of_linenumbers;
		dst->NumberOfRelocations = src->number_of_relocations;
		dst->PointerToLinenumbers = src->pointer_to_linenumbers; // TODO fix pointer
		dst->PointerToRelocations = src->pointer_to_relocations; // TODO fix pointer
		dst->Characteristics.dword = src->characteristics;
		dst->SizeOfRawData = src->size_of_raw_data;
		dst->VirtualAddress = src->virtual_address;
		dst->Misc.VirtualSize = src->virtual_size;
		dst->PointerToRawData = src->pointer_to_raw_data; // TODO fix pointer

		Utils::string_to_bytearray(dst->Name, src->name, sizeof(dst->Name));
	}

	byte *bonus_space = (byte *) &section_descriptors[nos * sizeof(IMAGE_SECTION_HEADER)];
	uint bonus_space_size = align_fill;

	if(bonus_space_size >= 3) {
		// embed editor signature (if enough room).
		byte mark[3] = { 0xA1, 0xBA, 0xBE };
		memcpy(bonus_space, mark, 3);
	}

	// store section datas
	uptr cptr = header_size + section_descriptors_len;
	section_data_len = 0;
	RVAConverter *c = s->pe->rvac;
	for(uint i = 0; i < nos; i++) {
		IMAGE_SECTION_HEADER *usect = c->get_section_for_ptr(cptr);
		if(usect == NULL)
			continue;

		cptr += usect->SizeOfRawData;
		section_data_len += usect->SizeOfRawData;
	}

	section_data = Alloc<byte>::anew(section_data_len);
	byte *mem = section_data;
	cptr = header_size + section_descriptors_len;
	uint cptrd = cptr;

	for(uint i = 0; i < nos; i++) {
		IMAGE_SECTION_HEADER *usect = c->get_section_for_ptr(cptr);
		if(!usect) continue;
		Section *csect = pe->get_csection_for_section(usect);
		assert(csect != NULL);

		memcpy(&mem[usect->PointerToRawData - cptrd], csect->data, usect->SizeOfRawData);
		cptr += usect->SizeOfRawData;
	}
}

uint PeBuilder::get_it_size() {
	uint impdir_size = 0;
	ImportDirectory *impdir = s->pe->imports_original_first_thunk;

	printf("walking import table\n");
	for(vector<DLLImport*>::iterator i = impdir->dlls->begin(); i != impdir->dlls->end(); ++i) {
		DLLImport *dll = (*i);

		impdir_size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		printf("sizeof(IID)=%08X\n", impdir_size);
		//impdir_size += dll->name.size() + 1; // +1 = trailing zero.
		printf("dll->name.size()=%08X\n", impdir_size);
		impdir_size += dll->functions->size() * 4; // pointer_to_functions chain.
		printf("dll->functions_size()*4=%08X\n", impdir_size);

		printf("walking functions\n");
		for(vector<ImportFunction*>::iterator k = dll->functions->begin(); k != dll->functions->end(); ++k) {
			ImportFunction* fi = (*k);

			//impdir_size += fi->api_name.size() + 1; // +1 = trailing zero.
			printf("after api_name(%s)=%08X\n", fi->api_name.c_str(), impdir_size);
			impdir_size += 8; // two dwords in `names' and `name ordinals' chains.
			printf("after +8=%08X\n", impdir_size);
		}
		printf("done walking functions\n");
	}

	impdir_size += sizeof(IMAGE_IMPORT_DESCRIPTOR); // empty structure which marks the end of array.
	return impdir_size;
}

void PeBuilder::build_import_table() {
	uint impdir_size = 0;

	// count size.
	impdir_size = get_it_size();
	cout << "impdir size: " << dec << impdir_size << hex << ", hex: " << impdir_size << endl;
	cout << "predicted ending: " << hex << 0x42f4 + impdir_size << endl;
}
