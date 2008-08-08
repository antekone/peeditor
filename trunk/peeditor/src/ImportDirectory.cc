#include "ped.hpp"
#include "ImportDirectory.hpp"

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

ImportDirectory::ImportDirectory() {
	dlls = new vector<DLLImport *>();
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
