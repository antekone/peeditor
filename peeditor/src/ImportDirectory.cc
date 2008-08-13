#include "ped.hpp"
#include "ImportDirectory.hpp"
#include "Utils.hpp"

ImportFunction::ImportFunction() {
	inited = false;
	ordinal = false;
	this->hint = 0;
	this->bound = false;
	this->thunk_offset = 0;
	this->thunk_ptr = 0;
	this->thunk_rva = 0;
	this->thunk_value = 0;
}

ImportFunction::~ImportFunction() {

}

DLLImport::DLLImport() {
	functions = new vector<ImportFunction*>();
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

	struct IMAGE_IMPORT_DESCRIPTOR import_d;

	dlls = new vector<DLLImport *>();
	import_ptr = c->ptr_from_rva(rva);
	//IMAGE_SECTION_HEADER *hdr = c->get_section_for_ptr(import_ptr);

	TRACE_CTX(_("Seeking to the first IMAGE_IMPORT_DESCRIPTOR at 0x%08X (according to DataDirectory[1].rva)", import_ptr));
	input->seekg(import_ptr, ios_base::beg);
	DLLImport *dlli;

	// odczyt ciagly
	while(true) {
		TRACE_CTX(_("Reading IMAGE_IMPORT_DESCRIPTOR (%d bytes) at 0x%08X", sizeof(IMAGE_IMPORT_DESCRIPTOR), (uint) input->tellg()));
		RANGE_CHECK(input, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		input->read((char *) &import_d, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if(import_d.OriginalFirstThunk == 0 && import_d.FirstThunk == 0 && import_d.Name == 0) {
			TRACE_CTX(_("End of array mark encountered."));
			break;
		}

		dlli = new DLLImport();
		dlli->first_thunk = import_d.FirstThunk;
		dlli->forwarder_chain = import_d.ForwarderChain;
		dlli->original_first_thunk = import_d.OriginalFirstThunk;
		dlli->time_date_stamp = import_d.TimeDateStamp;
		dlli->name_rva = import_d.Name;

		//if(dlli->original_first_thunk == 0)
		//	dlli->original_first_thunk = dlli->first_thunk;

		//assert(dlli->original_first_thunk != 0);
		//assert(dlli->first_thunk != 0);
		assert(dlli->name_rva != 0);

		if(dlli->original_first_thunk)
			dlli->original_first_thunk_ptr = c->ptr_from_rva(dlli->original_first_thunk);

		if(dlli->first_thunk)
			dlli->first_thunk_ptr = c->ptr_from_rva(dlli->first_thunk);

		if(dlli->name_rva) {
			dlli->name_ptr = c->ptr_from_rva(dlli->name_rva);
		}

		dlls->push_back(dlli);

		if(!input->good()) {
			cout << FATAL << "structure error when reading import table." << endl;
			return;
		}
	}

	IMAGE_THUNK_DATA thunk_data;

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

		if(use_first_thunk) {
			assert(im->first_thunk_ptr != 0);
			TRACE_CTX(_("Seek to 0x%08X (forced first thunk).", im->first_thunk_ptr));
			input->seekg(im->first_thunk_ptr, ios_base::beg);
		} else {
			if(im->original_first_thunk_ptr) {
				TRACE_CTX(_("Seek to 0x%08X (auto original_first_thunk).", (uint) input->tellg()));
				input->seekg(im->original_first_thunk_ptr, ios_base::beg);
			} else if(im->first_thunk_ptr) {
				TRACE_CTX(_("Seek to 0x%08X (auto first_thunk).", (uint) input->tellg()));
				input->seekg(im->first_thunk_ptr, ios_base::beg);
			} else {
				assert(im->original_first_thunk_ptr != 0 && im->first_thunk_ptr != 0);
			}
		}

		TRACE_CTX(_("Reading library (%s) imports.", im->name.c_str()));
		while(true) {
			uptr prev_offset = input->tellg();

			TRACE_CTX(_("Reading thunk data (%d bytes) at 0x%08X.", sizeof(IMAGE_THUNK_DATA), (uint) input->tellg()));
			RANGE_CHECK(input, sizeof(IMAGE_THUNK_DATA));
			input->read((char *) &thunk_data, sizeof(IMAGE_THUNK_DATA));
			if(thunk_data.Function == 0)
				break;

			ImportFunction *func = new ImportFunction();

			func->thunk_offset = prev_offset;

			assert(func->thunk_offset != 0);
			func->thunk_rva = c->rva_from_ptr(func->thunk_offset);

			if(thunk_data.Function & 0x80000000) {
				func->ordinal = true;
				func->thunk_value = thunk_data.Function ^ 0x80000000;
				func->inited = true;
				func->thunk_ptr = 0;
			} else {
				func->thunk_value = thunk_data.Function;
				func->inited = false;
				assert(thunk_data.Function != 0);

				if(c->get_section_for_rva(thunk_data.Function) == NULL) {
					// bound import
					ostringstream oss(ostringstream::out);

					func->thunk_ptr = 0;
					oss << "Memory location: " << hex << setw(8) << setfill('0') << thunk_data.Function;
					func->api_name = oss.str();

					func->bound = true;
					func->inited = true;
				} else {
					func->thunk_ptr = c->ptr_from_rva(thunk_data.Function);
				}
			}

			im->functions->push_back(func);

			if(!input->good() || thunk_data.Function == 0)
				break;
		}

		for(vector<ImportFunction*>::iterator k = im->functions->begin(); k != im->functions->end(); ++k) {
			ImportFunction *func = *k;

			if(func->inited && !func->ordinal)
				continue;

			input->seekg(func->thunk_ptr, ios_base::beg);

			TRACE_CTX(_("Reading function (ord=%d) hint at 0x%08X", func->ordinal, (uint) input->tellg()));
			RANGE_CHECK(input, 2);

			ushort hint;
			input->read((char *) &hint, 2);
			func->hint = hint;

			TRACE_CTX(_("Reading function (ord=%d) name at 0x%08X", func->ordinal, (uint) input->tellg()));
			while(input->good()) {
				RANGE_CHECK(input, 1);
				input->get(ch);
				if(ch == 0) break;

				func->api_name += ch;
			}
			TRACE_CTX(_("Function (ord=%d) name is '%s'.", func->ordinal, func->api_name.c_str()));
			func->inited = true;
		}
	}
}

ImportDirectory::ImportDirectory(RVAConverter *c, IMAGE_SECTION_HEADER **sec,
		int n, istream *input, uptr rva, bool use_first_thunk, TraceCtx *trace) {
	assert(c != NULL);
	assert(sec != NULL);
	assert(n > 0);
	assert(input != NULL);
	assert(input->good());

	trace_ctx = trace;
	tracing = trace_ctx != NULL;

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

void ImportDirectory::generate() {

}
