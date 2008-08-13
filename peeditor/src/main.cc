#include "ped.hpp"

#include "Instance.hpp"
#include "Structure.hpp"
#include "Utils.hpp"

void parse_cmdline(int, char**, Instance*);
int tests(Instance*); // tests.cc

char *FATAL = (char *) "[!] ";
char *WARNING = (char *) "[?] ";
char *INFO = (char *) "[i] ";

void dumping(Instance *inst) {
	string filename = inst->get_input_file();
	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);

	auto_ptr<istream> ifs(file_stream);
	auto_ptr<Structure> pe_file(new Structure(file_stream, inst->is_first_thunk()));
	PeHeader *pe = pe_file.get()->pe;
	if(!pe->ok)
		return;

	string args = inst->get_dump_args();

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
			printf("Characteristics:              0x%08X, %d\n", ex->characteristics, ex->characteristics);
			printf("Number of exported functions: 0x%08X, %d\n", ex->number_of_functions, ex->number_of_functions);
			printf("Number of named functions:    0x%08X, %d\n", ex->number_of_names, ex->number_of_names);
			printf("Number of unnamed functions:  0x%08X, %d\n", ex->number_of_functions-ex->number_of_names, ex->number_of_functions-ex->number_of_names);
			printf("Ordinal base:                 0x%08X, %d\n", ex->nbase, ex->nbase);
			printf("\n");
			printf("Registered module name:       File offset: 0x%08X, RVA: 0x%08X, '%s'\n",
					ex->ptr_to_name, ex->rva_to_name, ex->nname.c_str());
			printf("Export directory address:     File offset: 0x%08X, RVA: 0x%08X, size: %d (0x%08X) bytes\n", ex->directory_ptr, ex->directory_rva, ex->directory_size, ex->directory_size);
			printf("Function table:               File offset: 0x%08X, RVA: 0x%08X\n", ex->ptr_to_functions, ex->rva_to_functions);
			printf("Table of function names:      File offset: 0x%08X, RVA: 0x%08X\n", ex->ptr_to_names, ex->rva_to_names);
			printf("Table of function indexes:    File offset: 0x%08X, RVA: 0x%08X\n", ex->ptr_to_ordinals, ex->rva_to_ordinals);
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

				if(fi->ptr == 0 && fi->ptr_rva == 0 && !inst->is_verbose())
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

		ImportDirectory *im;
		if(inst->is_first_thunk())
			im = pe->imports_first_thunk;
		else
			im = pe->imports_original_first_thunk;

		if(!im) {
			cout << FATAL << "No import table in this file." << endl << endl;
		} else {
			printf("Data resides in section: %s\n", im->section_name.c_str());

			cout << endl;

			char *hdr = (char*) ("         OFT PTR    OFT RVA    FT PTR     FT RVA     TimeDate   FwdChain   Name PTR   Name RVA   Length   Module\n");
			int pos = 0;
			printf("%s", hdr);

			for(vector<DLLImport*>::iterator i = im->dlls->begin(); i != im->dlls->end(); ++i) {
				DLLImport *dll = *i;

				printf("I %5d  0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X %-8d %s %c\n",
						pos++,
						dll->original_first_thunk_ptr,
						dll->original_first_thunk,
						dll->first_thunk_ptr,
						dll->first_thunk,
						dll->time_date_stamp,
						dll->forwarder_chain,
						dll->name_ptr,
						dll->name_rva,
						dll->functions->size(),
						dll->name.c_str(),
						(dll->time_date_stamp != ((ulong) -1))? ' ': ' '
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

					if(func->ordinal) {
						 sprintf(api_name_buffer, "Import by ordinal: 0x%04X, %d", func->thunk_value, func->thunk_value);
						 api_name_ptr = api_name_buffer;
					} else
						api_name_ptr = (char*) func->api_name.c_str();

					//      lp   hint rva    offset value  api
					printf("I %5d  %04X 0x%08X 0x%08X 0x%08X 0x%08X %s\n",
							pos++,
							func->hint,
							func->thunk_rva,
							func->thunk_offset,
							func->thunk_value,
							func->thunk_ptr,
							api_name_ptr);
				}

				if(pos > 10)
					printf("%s\n", hdrl);
			}
		}

		cout << endl;
	}
}

void addr_trace(Instance *inst) {
	string filename = inst->get_input_file();
	if(filename.size() == 0) {
		cout << "no input file specified." << endl;
		return;
	}

	bool use_ft = inst->is_first_thunk();
	uint addr_trace = Utils::string_to_uint(inst->get_traced_address());

	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);
	auto_ptr<istream> ifs(file_stream);

	Structure *s = new Structure(file_stream, inst->is_first_thunk(), addr_trace);
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
	string filename = inst->get_input_file();
	if(filename.size() == 0) {
		cout << "no input file specified." << endl;
		return -1;
	}

	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);

	auto_ptr<istream> ifs(file_stream);
	auto_ptr<Structure> pe_file(new Structure(file_stream, inst->is_first_thunk()));
	PeHeader *pe = pe_file.get()->pe;
	if(!pe->ok)
		return -1;

	uint saddr = Utils::string_to_uint(inst->get_calc_addr()), daddr;

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
	uint saddr = Utils::string_to_uint(inst->get_calc_addr()), daddr = calc(inst, true, saddr);
	if(daddr == UINT_NOVALUE)
		return;

	cout << "rva hex: " << hex << saddr << endl;
	cout << "raw hex: " << hex << daddr << endl;
}

void calc_raw(Instance *inst) {
	uint saddr = Utils::string_to_uint(inst->get_calc_addr()), daddr = calc(inst, false, saddr);
	if(daddr == UINT_NOVALUE)
		return;

	cout << "rva hex: " << hex << daddr << endl;
	cout << "raw hex: " << hex << saddr << endl;
}

int main(int argc, char **argv) {
	Instance inst;

	parse_cmdline(argc, argv, &inst);

	switch(inst.get_mode()) {
		case USAGE:
			cout << " -D x		dump pe info" << endl;
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
	inst->set_mode(USAGE);

	while((opt = getopt(argc, argv, "t:r:p:FvhD:f:X")) != -1) {
		switch(opt) {
			case 'X':
				inst->set_mode(SELFDIAG);
				break;
			case 'h':
				break;
			case 'D':
				inst->set_mode(DUMPING);
				inst->set_dump_args(optarg);
				break;
			case 'f':
				inst->set_input_file(optarg);
				if(inst->get_input_file() == emptystr) {
					cout << "Can't open specified file: " << optarg << endl;
					inst->set_mode(QUIT);
					return;
				}

				break;
			case 'F':
				inst->set_first_thunk(true);
				break;
			case 'v':
				inst->set_verbose(true);
				break;
			case 'r':
				inst->set_mode(CALC_RVA);
				inst->set_calc_addr(optarg);
				break;
			case 'p':
				inst->set_mode(CALC_RAW);
				inst->set_calc_addr(optarg);
				break;
			case 't':
				inst->set_mode(ADDR_TRACE);
				inst->set_traced_address(optarg);
			default:
				break;
		}
	}

	if(inst->get_mode() == DUMPING && inst->get_input_file() == emptystr)
		inst->set_mode(USAGE);
}
