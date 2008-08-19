#include "ped.hpp"
#include "ExportDirectory.hpp"

ExportDirectory::ExportDirectory(RVAConverter *c, IMAGE_SECTION_HEADER **sec,
		int n, IMAGE_EXPORT_DIRECTORY *ed, istream *input, uptr export_rva,
		TraceCtx *trace):
			traits(ed->Characteristics),
			nbase(ed->nBase),
			funcs_sz(ed->NumberOfFunctions),
			names_sz(ed->NumberOfNames)
{
	assert(input != NULL);

	trace_ctx = trace;
	tracing = trace_ctx != NULL;

	uptr lname_ptr = c->ptr_from_rva(ed->nName),
			functions_ptr = c->ptr_from_rva(ed->AddressOfFunctions),
			lnames_ptr = c->ptr_from_rva(ed->AddressOfNames),
			ords_ptr = c->ptr_from_rva(ed->AddressOfNameOrdinals);

	funcs_ptr = functions_ptr;
	names_ptr = lnames_ptr;
	ordinals_ptr = ords_ptr;
	name_ptr = lname_ptr;
	funcs_rva = ed->AddressOfFunctions;
	names_rv = ed->AddressOfNames;
	ordinals_rva = ed->AddressOfNameOrdinals;
	name_rva = ed->nName;

	// read name.
	char *module_name = Alloc<char>::anew(33);

	TRACE_CTX(_("Seeking to 0x%08X to read the module name (ptr taken from IMAGE_EXPORT_DIRECTORY).", lname_ptr));
	input->seekg(lname_ptr, ios_base::beg);

	TRACE_CTX(_("Reading 32 bytes of module name at 0x%08X.", (uint) input->tellg()));
	RANGE_CHECK(input, 32);
	input->read(module_name, 32);

	this->nname = module_name;
	Alloc<char>::adelete(module_name);

	string name;
	functions.clear();

	TRACE_CTX(_("Seeking to 0x%08X to begin reading functions.", functions_ptr));
	input->seekg(functions_ptr, ios_base::beg);

	for(int i = 0, len = ed->NumberOfFunctions; i < len; i++) {
		uptr ptr_rva = 0, ptr = 0;
		TRACE_CTX(_("Reading DWORD (RVA address) of exported function number %d RVA at 0x%08X.", i, (uint) input->tellg()));
		RANGE_CHECK(input, 4);
		input->read((char *) &ptr_rva, 4);

		// quirk one: rva is 0, so it's unused.
		if(ptr_rva > 0) {
			ptr = c->ptr_from_rva(ptr_rva);
		}

		// TODO: quirk two: if rva points to this section, it's a forwarded export.

		FunctionInfo *fi = new FunctionInfo();
		fi->export_idx = i;
		fi->ptr = ptr;
		fi->ptr_rva = ptr_rva;
		fi->ord = ed->nBase + i;

		TRACE_CTX(_("Export seems OK, rva=0x%08X, raw=0x%08X, ord=0x%X/%dd, adding to Structure", ptr_rva, ptr, fi->ord, fi->ord));
		functions.push_back(fi);
	}

	TRACE_CTX(_("Going thorough assertions."));

	assert(functions.size() == ed->NumberOfFunctions);

	TRACE_CTX(_("Seeking to AddressOfNameOrdinals: 0x%08X and reading data needed to attach names to every export.", ords_ptr));
	TRACE_CTX(_("NumberOfNames structure has %d entries.", ed->NumberOfNames));
	input->seekg(ords_ptr, ios_base::beg);
	for(int i = 0, len = ed->NumberOfNames; i < len; i++) {
		ushort idx = 0;

		TRACE_CTX(_("Reading WORD for function number %d at 0x%08X.", i, (uint) input->tellg()));
		input->read((char *) &idx, 2);

		FunctionInfo *fi = get_functioninfo_by_index(idx);

		if(fi) {
			TRACE_CTX(_("Attaching name index %d (the WORD that has just been read) to function number %d/raw=0x%08X/rva=0x%08X.", i, fi->export_idx, fi->ptr, fi->ptr_rva));
			fi->name_idx = i;
		}
	}

	// resolve names
	TRACE_CTX(_("Seeking to AddressOfNames structure at 0x%08X.", lnames_ptr));
	TRACE_CTX(_("Resolving function names for %d functions.", ed->NumberOfNames));
	input->seekg(lnames_ptr, ios_base::beg);
	for(int i = 0, len = ed->NumberOfNames; i < len; i++) {
		ulong name_rva, name_ptr;

		TRACE_CTX(_("Reading DWORD (RVA) for name of function %d at 0x%08X", i, (uint) input->tellg()));
		RANGE_CHECK(input, 4);
		input->read((char *) &name_rva, 4);

		FunctionInfo *fi = get_functioninfo_by_name_idx(i);

		if(fi) {
			name_ptr = c->ptr_from_rva(name_rva);
			fi->name_rva = name_rva;
			fi->name_ptr = name_ptr;

			TRACE_CTX(_("Attaching name address=0x%08X for function number %d/rva=0x%08X/raw=0x%08X.", name_ptr, fi->export_idx, fi->ptr_rva, fi->ptr));
		}
	}

	TRACE_CTX(_("Reading names."));
	// read names
	vector<FunctionInfo*>::iterator i;
	for(i = functions.begin(); i != functions.end(); ++i) {
		FunctionInfo *fi = *i;

		if(fi->name_ptr == 0) {
			TRACE_CTX(_("Function number %d has no name (export by ord), skipping.", fi->export_idx));
			continue;
		}

		TRACE_CTX(_("Seeking to address containing name for function %d: 0x%08X", fi->export_idx, fi->name_ptr));
		input->seekg(fi->name_ptr, ios_base::beg);

		char ch = 0;
		while(true) {
			RANGE_CHECK(input, 1);
			input->get(ch);

			if(ch == 0 || input->bad() || !input->good())
				break;

			fi->name += ch;
		}

		TRACE_CTX(_("Got name: '%s'.", fi->name.c_str()));
	}
}

FunctionInfo *ExportDirectory::get_functioninfo_by_ord(int idx) {
	assert(functions.size() > 0);

	vector<FunctionInfo*>::iterator i;
	for(i = functions.begin(); i != functions.end(); ++i) {
		FunctionInfo *fi = *i;
		if(fi->ord == idx)
			return fi;
	}

	return NULL;
}

FunctionInfo *ExportDirectory::get_functioninfo_by_index(int idx) {
	assert(functions.size() > 0);

	vector<FunctionInfo*>::iterator i;
	for(i = functions.begin(); i != functions.end(); ++i) {
		FunctionInfo *fi = *i;
		if(fi->export_idx == idx)
			return fi;
	}

	return NULL;
}

FunctionInfo *ExportDirectory::get_functioninfo_by_name_idx(int idx) {
	assert(functions.size() > 0);

	vector<FunctionInfo*>::iterator i;
	for(i = functions.begin(); i != functions.end(); ++i) {
		FunctionInfo *fi = *i;
		if(fi->name_idx == idx)
			return fi;
	}

	return NULL;
}

ExportDirectory::~ExportDirectory() {
	vector<FunctionInfo*>::iterator i;
	for(i = functions.begin(); i != functions.end(); ++i) {
		FunctionInfo *fi = *i;
		delete fi;
	}
	functions.clear();
}
