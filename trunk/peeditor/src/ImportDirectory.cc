/**
 * ImportDirectory.cc
 *
 * This file holds the logic needed for interpretation of Import Directory in PE files.
 * AUthor: antek
 */

#include "ped.hpp"

#include "ImportDirectory.hpp"
#include "Utils.hpp"

ImportFunction::ImportFunction() {
	inited = false;
	ord = false;
	hint = 0;
	bound = false;
	thunk_offset = 0;
	thunk_ptr = 0;
	thunk_rva = 0;
	thunk_value = 0;
}

ImportFunction::~ImportFunction() {

}

DLLImport::DLLImport() {
	functions = new vector<ImportFunction*>();
	names = NULL;
	name = emptystr;
	oft_rva = 0;
	oft_ptr = 0;
	ft_rva = 0;
	ft_ptr = 0;
	tstamp = 0;
	fwd_chain = 0;
	name_rva = 0;
	name_ptr = 0;
}

DLLImport::~DLLImport() {
	assert(functions != NULL);

	for(vector<ImportFunction*>::iterator i = functions->begin(); i != functions->end(); ++i) {
		ImportFunction *func = *i;
		if(func)
			delete func;
	}

	delete functions;
}

void ImportDirectory::ctor(RVAConverter *c, IMAGE_SECTION_HEADER **sc, int n,
		istream *input, uptr rva, bool use_first_thunk) {

	struct IMAGE_IMPORT_DESCRIPTOR idesc;

	dlls = new vector<DLLImport *>();
	directory_ptr = c->ptr_from_rva(rva);
	directory_rva = rva;

	TRACE_CTX(_("Seeking to the first IMAGE_IMPORT_DESCRIPTOR at 0x%08X (according to DataDirectory[1].rva)", directory_ptr));
	input->seekg(directory_ptr, ios_base::beg);
	DLLImport *dlli;

	// odczyt ciagly
	while(true) {
		TRACE_CTX(_("Reading IMAGE_IMPORT_DESCRIPTOR (%d bytes) at 0x%08X", sizeof(IMAGE_IMPORT_DESCRIPTOR), (uint) input->tellg()));

		RANGE_CHECK(input, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		input->read((char *) &idesc, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if(idesc.OriginalFirstThunk == 0 && idesc.FirstThunk == 0 && idesc.Name == 0) {
			TRACE_CTX(_("End of array mark encountered."));
			break;
		}

		dlli = new DLLImport();
		dlli->ft_rva = idesc.FirstThunk;
		dlli->fwd_chain = idesc.ForwarderChain;
		dlli->oft_rva = idesc.OriginalFirstThunk;
		dlli->tstamp = idesc.TimeDateStamp;
		dlli->name_rva = idesc.Name;

		assert(dlli->name_rva != 0);

		if(dlli->oft_rva)
			dlli->oft_ptr = c->ptr_from_rva(dlli->oft_rva);

		if(dlli->ft_rva)
			dlli->ft_ptr = c->ptr_from_rva(dlli->ft_rva);

		if(dlli->name_rva) {
			dlli->name_ptr = c->ptr_from_rva(dlli->name_rva);
		}

		dlls->push_back(dlli);

		if(!input->good()) {
			cout << FATAL << "structure error when reading import table." << endl;
			return;
		}
	}

	IMAGE_THUNK_DATA thunk;

	TRACE_CTX(_("Reading import names."));

	// na wyrywki
	for(vector<DLLImport*>::iterator i = dlls->begin(); i != dlls->end(); ++i) {
		DLLImport *im = *i;
		assert(im->name_ptr != 0);

		TRACE_CTX(_("Reading ASCIIZ from 0x%08X, this address should have import library's name", im->name_ptr));
		input->seekg(im->name_ptr, ios_base::beg);

		char ch;
		while(input->good()) {
			RANGE_CHECK(input, 1);
			input->get(ch);
			if(ch == 0)
				break;
			else
				im->name += ch;
		}

		// Set chain: first thunk or original first thunk.
		if(use_first_thunk) {
			assert(im->ft_ptr != 0);
			TRACE_CTX(_("Seek to 0x%08X (forced first thunk).", im->ft_ptr));
			input->seekg(im->ft_ptr, ios_base::beg);
		} else {
			if(im->oft_ptr) {
				TRACE_CTX(_("Seek to 0x%08X (auto original_first_thunk).", (uint) input->tellg()));
				input->seekg(im->oft_ptr, ios_base::beg);
			} else if(im->ft_ptr) {
				TRACE_CTX(_("Seek to 0x%08X (auto first_thunk).", (uint) input->tellg()));
				input->seekg(im->ft_ptr, ios_base::beg);
			} else {
				assert(im->oft_ptr != 0 && im->ft_ptr != 0);
			}
		}

		TRACE_CTX(_("Reading library (%s) imports.", im->name.c_str()));
		while(true) {
			uptr prev_offset = input->tellg();

			TRACE_CTX(_("Reading thunk data (%d bytes) at 0x%08X.", sizeof(IMAGE_THUNK_DATA), (uint) input->tellg()));
			RANGE_CHECK(input, sizeof(IMAGE_THUNK_DATA));
			input->read((char *) &thunk, sizeof(IMAGE_THUNK_DATA));
			if(thunk.Function == 0)
				break;

			ImportFunction *func = new ImportFunction();

			func->thunk_offset = prev_offset;

			assert(func->thunk_offset != 0);
			func->thunk_rva = c->rva_from_ptr(func->thunk_offset);

			if(thunk.Function & 0x80000000) {
				func->ord = true;
				func->thunk_value = thunk.Function ^ 0x80000000;
				func->inited = true;
				func->thunk_ptr = 0;
			} else {
				func->thunk_value = thunk.Function;
				func->inited = false;
				assert(thunk.Function != 0);

				if(c->get_section_for_rva(thunk.Function) == NULL) {
					// bound import
					ostringstream oss(ostringstream::out);

					func->thunk_ptr = 0;
					oss << "Memory location: " << hex << setw(8) << setfill('0') << thunk.Function;
					func->api_name = oss.str();

					func->bound = true;
					func->inited = true;
				} else {
					// AddressOfData is the same as Function - they're in one union.
					func->thunk_ptr = c->ptr_from_rva(thunk.AddressOfData);
				}
			}

			im->functions->push_back(func);

			if(!input->good() || thunk.Function == 0)
				break;
		}

		for(vector<ImportFunction*>::iterator k = im->functions->begin(); k != im->functions->end(); ++k) {
			ImportFunction *func = *k;

			if(func->inited && !func->ord)
				continue;

			input->seekg(func->thunk_ptr, ios_base::beg);

			TRACE_CTX(_("Reading function (ord=%d) hint at 0x%08X", func->ord, (uint) input->tellg()));
			RANGE_CHECK(input, 2);

			ushort hint;
			input->read((char *) &hint, 2);
			func->hint = hint;

			TRACE_CTX(_("Reading function (ord=%d) name at 0x%08X", func->ord, (uint) input->tellg()));
			while(input->good()) {
				RANGE_CHECK(input, 1);
				input->get(ch);
				if(ch == 0) break;

				func->api_name += ch;
			}
			TRACE_CTX(_("Function (ord=%d) name is '%s'.", func->ord, func->api_name.c_str()));
			func->inited = true;
		}
	}
}

ImportDirectory::ImportDirectory(RVAConverter *c, IMAGE_SECTION_HEADER **sec, int n, istream *input, uptr rva, bool use_first_thunk, TraceCtx *trace) {
	assert(c != NULL);
	assert(sec != NULL);
	assert(n > 0);
	assert(input != NULL);
	assert(input->good());

	trace_ctx = trace;
	tracing = trace_ctx != NULL;

	// Gdb gets lost when inspecting locals in constructors. I wonder why?
	// Solution to this problem is either NOT use pure constructor method
	// as a main logic, OR (a better way) is to use -gstabs+ in gcc's command
	// line.
	ctor(c, sec, n, input, rva, use_first_thunk);
}

ImportDirectory::~ImportDirectory() {
	assert(dlls != NULL);

	vector<DLLImport*>::iterator i;
	for(i = dlls->begin(); i != dlls->end(); ++i) {
		DLLImport *dlli = *i;
		if(dlli)
			delete dlli;
	}

	delete dlls;
}
