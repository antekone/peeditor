#include "ped.hpp"

#include "Instance.hpp"
#include "Structure.hpp"

void parse_cmdline(int, char**, Instance*);
int tests(); // tests.cc

char *FATAL = (char *) "[!] ";
char *WARNING = (char *) "[?] ";
char *INFO = (char *) "[i] ";

void dumping(Instance *inst) {
	string filename = inst->get_input_file();
	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);

	auto_ptr<istream> ifs(file_stream);
	auto_ptr<Structure> pe_file(new Structure(file_stream, inst->is_first_thunk()));
	PeHeader *pe = pe_file.get()->pe;

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

		ImportDirectory *im = pe->imports;
		if(!im) {
			cout << FATAL << "No import table in this file." << endl << endl;
		} else {
			int pos = 0;
			char *hdr = (char*) ("         OFT PTR    OFT RVA    FT PTR     FT RVA     TimeDate   FwdChain   Name PTR   Name RVA   Length   Module\n");
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
						dll->time_date_stamp != -1? '*': ' '
						);
			}

			if(pos > 10)
				printf("%s", hdr);

			cout << endl;

			for(vector<DLLImport*>::iterator i = im->dlls->begin(); i != im->dlls->end(); ++i) {
				DLLImport *dll = *i;

				pos = 0;
				printf("\n  --- %s ---\n", dll->name.c_str());
				char *hdrl = (char*) "         Hint RVA        Offset     Value      Pointer    Api        ";
				printf("%s\n", hdrl);
				for(vector<ImportFunction*>::iterator k = dll->functions->begin(); k != dll->functions->end(); ++k) {
					ImportFunction *func = *k;

					//      lp   hint rva    offset value  api
					printf("I %5d  %04X 0x%08X 0x%08X 0x%08X 0x%08X %s\n",
							pos++,
							func->hint,
							func->thunk_rva,
							func->thunk_offset,
							func->thunk_value,
							func->thunk_ptr,
							func->api_name.c_str());
				}

				if(pos > 10)
					printf("%s\n", hdrl);
			}
		}

		cout << endl;
	}
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
			//cout << " -X		run tests (self-diagnostics mode)" << endl;
			break;
		case DUMPING:
			dumping(&inst);
			break;
		case QUIT:
			break;
		case SELFDIAG:
			if(tests() != 0)
				cout << "FAIL." << endl;
			break;
	}

	return 0;
}

void parse_cmdline(int argc, char **argv, Instance *inst) {
	int opt;
	inst->set_mode(USAGE);

	while((opt = getopt(argc, argv, "FvhD:f:X")) != -1) {
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
			default:
				break;
		}
	}

	if(inst->get_mode() == DUMPING && inst->get_input_file() == emptystr)
		inst->set_mode(USAGE);
}
