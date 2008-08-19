#include <sys/types.h>
#include <sys/stat.h>

#include "ped.hpp"

#include "Instance.hpp"
#include "Structure.hpp"
#include "Utils.hpp"

void parse_cmdline(int, char**, Instance*);
int tests(Instance*); // tests.cc

char *FATAL = (char *) "[!] ";
char *WARNING = (char *) "[?] ";
char *INFO = (char *) "[i] ";

bool check_file(const char *fname) {
	struct stat st;

	if(!stat(fname, &st)) {
		if(S_ISREG(st.st_mode))
			return true;
		else if(S_ISDIR(st.st_mode)) {
			// TODO maybe support it?
			cout << FATAL << "Directory parsing is not supported." << endl;
			return false;
		} else {
			cout << FATAL << "I can work only on regular files (that will allow seek operations)." << endl;
			return false;
		}
	} else {
		cout << FATAL << "Error when running stat on specified file." << endl;
		return false;
	}
}

int file_size(const char *fname) {
	struct stat st;

	if(!stat(fname, &st)) {
		if(S_ISREG(st.st_mode)) {
			return st.st_size;
		} else
			return -1;
	} else {
		cout << FATAL << "Error when running stat on specified file." << endl;
		return -1;
	}
}

void dumping(Instance *inst) {
	string filename = inst->input_file();
	uint fsize = 0;

	if(!check_file(filename.c_str())) {
		return;
	}

	fsize = file_size(filename.c_str());
	if(fsize == UINT_NOVALUE) {
		return;
	}

	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);
	if(!((ifstream*) file_stream)->is_open()) {
		cout << FATAL << "Can't open specified file: " << filename << endl;
		return;
	}

	auto_ptr<istream> aptr_file_stream(file_stream);
	auto_ptr<Structure> aptr_structure(new Structure(file_stream, inst->first_thunk()));

	Structure *s = aptr_structure.get();
	PeHeader *pe = s->pe;

	if(!pe->ok)
		return;

	vector<string> messages;

	string args = inst->dump_args();

	time_t t = time(NULL);
	cout << "Session time: " << ctime(&t) << "\n";

	// dump section table
	if(args.find('0') != string::npos) {
		cout << INFO << "==============" << endl;
		cout << INFO << "Section table." << endl;
		cout << INFO << "==============" << endl;
		cout << endl;

		int secn = pe->ifh->NumberOfSections, salign = pe->ioh->SectionAlignment, falign = pe->ioh->FileAlignment;
		uptr ep_rva = pe->ioh->AddressOfEntryPoint;

		printf("Number of sections:           %d\n", secn);
		printf("Section alignment:            0x%08X, %dd\n", salign, salign);
		printf("File alignment:               0x%08X, %dd\n", falign, falign);

		Section *isec = NULL, *esec = NULL, *entrysec = NULL;

		// Check the location of import table.
		if(pe->imports) {
			if(pe->rvac->is_header_rva(pe->imports->directory_rva)) {
				printf("Import table in header:       File offset: 0x%X\n", (unsigned int) pe->imports->directory_rva);
				isec = NULL;
			} else
				isec = pe->get_csection_for_rva(pe->imports->directory_rva);
		}

		// Check the location of export table.
		if(pe->exports) {
			if(pe->rvac->is_header_rva(pe->exports->directory_rva)) {
				printf("Export table in header:       File offset: 0x%X\n", (unsigned int) pe->exports->directory_rva);
				esec = NULL;
			} else
				esec = pe->get_csection_for_rva(pe->exports->directory_rva);
		}

		// TODO Check the location of relocation data.

		// TODO Check the location of the rest of data directory entries...

		// Check the location of entry point.
		if(pe->rvac->is_header_rva(ep_rva)) {
			printf("Entrypoint in header:         File offset: 0x%X\n", (unsigned int) ep_rva);
			entrysec = NULL;
		} else
			entrysec = pe->get_csection_for_rva(ep_rva);

		string rwars, vwars;
		bool imports, exports, ep;
		uint largest_raw = 0, largest_rsz = 0;

		printf("\n");
		for(int i = 0; i < secn; i++) {
			Section *sect = pe->sections_data[i];
			IMAGE_SECTION_HEADER *usect = sect->orig;

			printf("%3d. %-8s  (ptr: 0x%X, size: %d b) ", i, (const char *) sect->name.c_str(), (unsigned int) sect->file_ptr, sizeof(IMAGE_SECTION_HEADER));

			imports = isec == sect;
			exports = esec == sect;
			ep = entrysec == sect;

			if(sect->raw > largest_raw) {
				largest_raw = sect->raw;
				largest_rsz = sect->rsz;
			}

			if(sect->abstract)
				printf("(abstract)");

			printf("\n");

			rwars.clear();
			vwars.clear();
			if(sect->va % salign)
				vwars.append("!");
			printf("     Offset   - raw: %3s 0x%-11X virtual: %3s 0x%-11X\n", vwars.c_str(), (unsigned int) sect->raw, vwars.c_str(), (unsigned int) sect->va);

			int rsum = sect->raw + sect->rsz - 1, vsum = sect->va + sect->vsz - 1;
			printf("     Last ofs - raw:     0x%-11X virtual:     0x%-11X\n", rsum >= 0? rsum: 0, vsum >= 0? vsum: 0);

			rwars.clear();
			vwars.clear();
			if(sect->rsz % falign) {
				rwars.append("!");
			}

			printf("     Size hex - raw: %3s 0x%-11X virtual: %3s 0x%-11X\n", rwars.c_str(), (unsigned int) sect->rsz, vwars.c_str(), (unsigned int) sect->vsz);
			printf("     Size dec - raw: %3s %-11d   virtual: %3s %-11d\n", rwars.c_str(), (unsigned int) sect->rsz, vwars.c_str(), (unsigned int) sect->vsz);

			if(inst->verbose()) {
				printf("     Relocs   - raw:     0x%-11X size:        0x%X (%d)\n", (unsigned int) sect->reloc_ptr, (unsigned int) sect->reloc_n, (unsigned int) sect->reloc_n);
			}

			ostringstream os;
			if(usect->Characteristics.executable)
				os << "exec ";
			if(usect->Characteristics.readable)
				os << "read ";
			if(usect->Characteristics.writable)
				os << "write ";
			if(usect->Characteristics.code)
				os << "code ";
			if(usect->Characteristics.initialized_data)
				os << "idata ";
			if(usect->Characteristics.uninitialized_data)
				os << "udata ";
			if(usect->Characteristics.extended_relocations)
				os << "relocs ";
			if(usect->Characteristics.discardable)
				os << "discardable ";
			if(usect->Characteristics.comdat)
				os << "comdat ";
			if(usect->Characteristics.fardata)
				os << "fardata ";
			if(usect->Characteristics.purgable)
				os << "purgable ";
			if(usect->Characteristics.locked)
				os << "locked ";
			if(usect->Characteristics.preload)
				os << "preload ";
			if(usect->Characteristics.not_cacheable)
				os << "uncacheable ";
			if(usect->Characteristics.not_pageable)
				os << "unpagable ";
			if(usect->Characteristics.shared)
				os << "shared ";

			string os_str = os.str();
			os_str.erase(os_str.end() - 1);

			printf("\n");
			printf("     Charact  - 0x%08X (%s)\n", (unsigned int) sect->traits, os_str.c_str());

			if(imports)
				printf("     Imports  - raw: 0x%X, virtual: 0x%X\n", (unsigned int) pe->imports->directory_ptr, (unsigned int) pe->imports->directory_rva);

			if(exports)
				printf("     Exports  - raw: 0x%X, virtual: 0x%X\n", (unsigned int) pe->exports->directory_ptr, (unsigned int) pe->exports->directory_rva);

			if(ep) {
				uptr ep_ptr = pe->rvac->ptr_from_rva(pe->ioh->AddressOfEntryPoint);
				printf("     EntryPt  - raw: 0x%X, virtual: 0x%X\n", (unsigned int) ep_ptr, (unsigned int) pe->ioh->AddressOfEntryPoint);
			}

			printf("\n");

		}

		if(inst->verbose()) {
			uint raw_size = s->get_image_size();
			printf("Simulated image size:         %d bytes (%d kb, %d mb)\n", raw_size, raw_size / 1024, raw_size / 1024 / 1024);
		}

		printf("Last file offset:             0x%X", (unsigned int) (largest_rsz + largest_raw - 1));

		if(largest_rsz + largest_raw != fsize) {
			printf(", *NOT* equal to file size: %d bytes (delta: %d)\n", fsize, (unsigned int) (fsize - (largest_rsz + largest_raw)));
		} else {
			printf(", equals with file size.\n");
		}

		if(messages.size() > 0) {
			for(int i = 0, size = messages.size(); i < size; ++i) {
				cout << WARNING << messages.at(i) << endl;
			}
		}

		printf("\n");
	}

	// dump exports
	if(args.find('1') != string::npos) {
		cout << INFO << "=============" << endl;
		cout << INFO << "Export table." << endl;
		cout << INFO << "=============" << endl;
		cout << endl;

		ExportDirectory *ex = pe->exports;
		if(!ex) {
			cout << FATAL << "No export table in this file." << endl;
		} else {
			int delta = ex->funcs_sz - ex->names_sz;

			printf("Characteristics:              0x%08X, %d\n", (unsigned int) ex->traits, (unsigned int) ex->traits);
			printf("Number of exported functions: 0x%08X, %d\n", (unsigned int) ex->funcs_sz, (unsigned int) ex->funcs_sz);
			printf("Number of named functions:    0x%08X, %d\n", (unsigned int) ex->names_sz, (unsigned int) ex->names_sz);
			printf("Number of unnamed functions:  0x%08X, %d\n", delta, delta);
			printf("Ordinal base:                 0x%08X, %d\n", (unsigned int) ex->nbase, (unsigned int) ex->nbase);
			printf("\n");

			printf("Registered module name:       File offset: 0x%08X, RVA: 0x%08X, '%s'\n",
					(unsigned int) ex->name_ptr, (unsigned int) ex->name_rva, (const char *) ex->nname.c_str());

			printf("Export directory address:     File offset: 0x%08X, RVA: 0x%08X, size: %d (0x%08X) bytes\n",
					(unsigned int) ex->directory_ptr, (unsigned int) ex->directory_rva, (unsigned int) ex->directory_size, (unsigned int) ex->directory_size);

			printf("Function table:               File offset: 0x%08X, RVA: 0x%08X\n",
					(unsigned int) ex->funcs_ptr, (unsigned int) ex->funcs_rva);

			printf("Table of function names:      File offset: 0x%08X, RVA: 0x%08X\n",
					(unsigned int) ex->names_ptr, (unsigned int) ex->names_rv);

			printf("Table of function indexes:    File offset: 0x%08X, RVA: 0x%08X\n",
					(unsigned int) ex->ordinals_ptr, (unsigned int) ex->ordinals_rva);

			printf("\n");

			char *hdr = (char *) "         Ord    Func PTR   Func RVA   Name PTR   Name\n";
			printf("%s", hdr);

			// function dump
			for(vector<FunctionInfo*>::iterator i = ex->functions.begin(); i != ex->functions.end(); ++i) {
				FunctionInfo *fi = *i;

				char *name;
				if(fi->name.length() > 0)
					name = const_cast<char*>(fi->name.c_str());
				else
					name = (char*) "(ordinal)";

				if(fi->ptr == 0 && fi->ptr_rva == 0 && !inst->verbose())
					continue;

				char *fmt;
				if(fi->name_ptr == 0) {
					// ordinal?
					fmt = (char*) "O %5d  0x%04X 0x%08X 0x%08X            %s\n";
					printf(fmt, fi->export_idx, fi->ord, fi->ptr, fi->ptr_rva, name);
				} else {
					// normalny eksport.
					fmt = (char *) "O %5d  0x%04X 0x%08X 0x%08X 0x%08X %s\n";
					printf(fmt, fi->export_idx, fi->ord, fi->ptr, fi->ptr_rva, fi->name_ptr, name);
				}
			}

			printf("%s", hdr);
		}

		cout << endl;
	}

	if(args.find('2') != string::npos) {
		cout << INFO << "=============" << endl;
		cout << INFO << "Import table." << endl;
		cout << INFO << "=============" << endl;
		cout << endl;

		ImportDirectory *im = pe->imports;

		if(!im) {
			cout << FATAL << "No import table in this file." << endl << endl;
		} else {
			Section *sect = pe->get_csection_for_rva(im->directory_rva);
			printf("Data resides in section:      %s\n", im->section_name.c_str());
			printf("This section's base RVA addr: 0x%X\n", (unsigned int) sect->va);
			printf("First import descriptor:      File offset: 0x%X, RVA: 0x%X\n", (unsigned int) im->directory_ptr, (unsigned int) im->directory_rva);
			printf("Number of libraries:          %d\n", im->dlls->size());

			cout << endl;

			char *hdr = (char*) ("         OFT PTR    OFT RVA    FT PTR     FT RVA     TimeDate   FwdChain   Name PTR   Name RVA   Length   Module\n");
			int pos = 0;
			printf("%s", hdr);

			for(vector<DLLImport*>::iterator i = im->dlls->begin(); i != im->dlls->end(); ++i) {
				DLLImport *dll = *i;

				printf("I %5d  0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X %-8d %s %c\n",
						pos++,
						(unsigned int) dll->oft_ptr,
						(unsigned int) dll->oft_rva,
						(unsigned int) dll->ft_ptr,
						(unsigned int) dll->ft_rva,
						(unsigned int) dll->tstamp,
						(unsigned int) dll->fwd_chain,
						(unsigned int) dll->name_ptr,
						(unsigned int) dll->name_rva,
						(unsigned int) dll->functions->size(),
						(const char *) dll->name.c_str(),
						(char) ((dll->tstamp != ((ulong) -1))? ' ': ' ')
						);
			}

			if(pos > 10)
				printf("%s", hdr);

			cout << endl;
			char *hdrl = (char*) "         Hint RVA        Offset     Value      Pointer    Api        ";
			char api_name_buffer[80], *api_name_ptr;

			for(vector<DLLImport*>::iterator i = im->dlls->begin(); i != im->dlls->end(); ++i) {
				DLLImport *dll = *i;

				pos = 0;
				printf("\n  --- %s ---\n", dll->name.c_str());
				printf("%s\n", hdrl);
				for(vector<ImportFunction*>::iterator k = dll->functions->begin(); k != dll->functions->end(); ++k) {
					ImportFunction *func = *k;

					if(func->ord) {
						 sprintf(api_name_buffer, "Import by ordinal: 0x%04X, %d", (unsigned int) func->thunk_value, (int) func->thunk_value);
						 api_name_ptr = api_name_buffer;
					} else
						api_name_ptr = (char*) func->api_name.c_str();

					//      lp   hint rva    offset value  api
					printf("I %5d  %04X 0x%08X 0x%08X 0x%08X 0x%08X %s\n",
							pos++,
							(unsigned int) func->hint,
							(unsigned int) func->thunk_rva,
							(unsigned int) func->thunk_offset,
							(unsigned int) func->thunk_value,
							(unsigned int) func->thunk_ptr,
							(const char *) api_name_ptr);
				}

				if(pos > 10)
					printf("%s\n", hdrl);
			}
		}

		cout << endl;
	}

	if(args.find('D') != string::npos) {
		cout << INFO << "=================" << endl;
		cout << INFO << "Data directories." << endl;
		cout << INFO << "=================" << endl;
		cout << endl;

		PeHeader *pe = s->pe;
		IMAGE_DATA_DIRECTORY *dd = pe->ioh->DataDirectory;

		string desc;
		bool flag;
		for(int i = 0; i < 16; i++) {
			flag = false;

			switch(i) {
			case 0: desc = "export"; break;
			case 1: desc = "import"; break;
			case 2: desc = "resource"; break;
			case 3: desc = "exception"; break;
			case 4: desc = "security"; flag = true; break;
			case 5: desc = "relocations"; break;
			case 6: desc = "debug"; break;
			case 7: desc = "architecture"; break;
			case 8: desc = "globalptr"; break;
			case 9: desc = "tls"; break;
			case 10: desc = "loadconfig"; break;
			case 11: desc = "bound iat"; break;
			case 12: desc = "iat"; break;
			case 13: desc = "delay iat"; break;
			case 14: desc = "clr header"; break;
			case 15: desc = "?"; break;
			default: desc = "n/a"; break;
			}

			if(dd[i].rva == 0 && dd[i].size == 0) {
				printf("%3d. %15s: -\n", i, desc.c_str());
			} else {
				if(!flag) {
					uptr raw;
					if(pe->rvac->valid_rva(dd[i].rva)) {
						raw = pe->rvac->ptr_from_rva(dd[i].rva);
					} else {
						raw = UINT_NOVALUE;
					}

					printf("%3d. %15s: Virtual address: 0x%-8X Size: %d\n", i, desc.c_str(), (unsigned int) dd[i].rva, (unsigned int) dd[i].size);
					printf("                      File offset: 0x%X\n", (unsigned int) raw);
				} else {
					printf("%3d. %15s: File offset: 0x%-8X Size: %d\n", i, desc.c_str(), (unsigned int) dd[i].rva, (unsigned int) dd[i].size);
					printf("                      -\n");
				}
			}
		}

		printf("\n");
	}
}

void addr_trace(Instance *inst) {
	string filename = inst->input_file();
	if(filename.size() == 0) {
		cout << "no input file specified." << endl;
		return;
	}

	bool use_ft = inst->first_thunk();
	uint addr_trace = Utils::string_to_uint(inst->traced_address());

	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);
	auto_ptr<istream> ifs(file_stream);

	Structure *s = new Structure(file_stream, use_ft, addr_trace);
	auto_ptr<Structure> pe_file(s);

	PeHeader *pe = pe_file.get()->pe;
	if(!pe->ok)
		return;

	cout << "Trace result:" << endl;

	ostringstream os;
	pe->dump_trace_result(os);
	cout << os.str() << endl;
}

uint calc(Instance *inst, bool rva, uint address) {
	string filename = inst->input_file();
	if(filename.size() == 0) {
		cout << "no input file specified." << endl;
		return -1;
	}

	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);

	auto_ptr<istream> aptr_file_stream(file_stream);
	auto_ptr<Structure> aptr_structure(new Structure(file_stream, inst->first_thunk()));

	Structure *s = aptr_structure.get();
	PeHeader *pe = s->pe;

	if(!pe->ok)
		return -1;

	uint saddr = Utils::string_to_uint(inst->calc_addr()), daddr;

	if(rva) {
		if(pe->rvac->valid_rva(saddr))
			daddr = pe->rvac->ptr_from_rva(saddr);
		else {
			cout << FATAL << "Invalid RVA entered." << endl;
			daddr = UINT_NOVALUE;
		}
	} else {
		if(pe->rvac->valid_ptr(saddr))
			daddr = pe->rvac->rva_from_ptr(saddr);
		else {
			cout << FATAL << "Invalid pointer entered." << endl;
			daddr = UINT_NOVALUE;
		}
	}

	return daddr;
}

void calc_rva(Instance *inst) {
	uint saddr = Utils::string_to_uint(inst->calc_addr()), daddr = calc(inst, true, saddr);
	if(daddr == UINT_NOVALUE)
		return;

	cout << "rva hex: " << hex << saddr << endl;
	cout << "raw hex: " << hex << daddr << endl;
}

void calc_raw(Instance *inst) {
	uint saddr = Utils::string_to_uint(inst->calc_addr()), daddr = calc(inst, false, saddr);
	if(daddr == UINT_NOVALUE)
		return;

	cout << "rva hex: " << hex << daddr << endl;
	cout << "raw hex: " << hex << saddr << endl;
}

int main(int argc, char **argv) {
	Instance inst;

	parse_cmdline(argc, argv, &inst);

	switch(inst.mode()) {
		case USAGE:
			cout << " -D x		dump pe info" << endl;
			cout << "    x=D		dump data directories" << endl;
			cout << "    x=0		dump section table" << endl;
			cout << "    x=1		dump export table" << endl;
			cout << "    x=2		dump import table" << endl;
			cout << " -F		walk FirstThunk instead of OriginalFirstThunk when reading import table" << endl;
			cout << " -f <file>	the file to parse" << endl;
			cout << " -h		display this help" << endl;
			cout << " -r <addr>	rva to raw pointer calculator" << endl;
			cout << " -p <addr>	raw pointer to rva calculator" << endl;
			cout << " -t <addr> run address trace" << endl;
			//cout << " -X		run tests (self-diagnostics mode)" << endl;
			break;
		case DUMPING:
			dumping(&inst);
			break;
		case QUIT:
			break;
		case SELFDIAG:
			if(tests(&inst) != 0)
				cout << "FAIL." << endl;
			break;
		case CALC_RVA:
			calc_rva(&inst);
			break;
		case CALC_RAW:
			calc_raw(&inst);
			break;
		case ADDR_TRACE:
			addr_trace(&inst);
			break;
	}

	return 0;
}

void parse_cmdline(int argc, char **argv, Instance *inst) {
	int opt;
	inst->mode(USAGE);

	while((opt = getopt(argc, argv, "t:r:p:FvhD:f:X")) != -1) {
		switch(opt) {
			case 'X':
				inst->mode(SELFDIAG);
				break;
			case 'h':
				break;
			case 'D':
				inst->mode(DUMPING);
				inst->dump_args(optarg);
				break;
			case 'f':
				inst->input_file(optarg);
				if(inst->input_file() == emptystr) {
					cout << "Can't open specified file: " << optarg << endl;
					inst->mode(QUIT);
					return;
				}

				break;
			case 'F':
				inst->first_thunk(true);
				break;
			case 'v':
				inst->verbose(true);
				break;
			case 'r':
				inst->mode(CALC_RVA);
				inst->calc_addr(optarg);
				break;
			case 'p':
				inst->mode(CALC_RAW);
				inst->calc_addr(optarg);
				break;
			case 't':
				inst->mode(ADDR_TRACE);
				inst->traced_address(optarg);
			default:
				break;
		}
	}

	if(inst->mode() == DUMPING && inst->input_file() == emptystr)
		inst->mode(USAGE);
}
