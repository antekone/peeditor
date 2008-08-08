#include "ped.hpp"
#include "ExportDirectory.hpp"

ExportDirectory::ExportDirectory(RVAConverter *c, IMAGE_SECTION_HEADER **sec, 
		int n, IMAGE_EXPORT_DIRECTORY *ed, istream *input, uptr export_rva):
			characteristics(ed->Characteristics),
			nbase(ed->nBase),
			number_of_functions(ed->NumberOfFunctions),
			number_of_names(ed->NumberOfNames)
{
	assert(input != NULL);
	
	uptr name_ptr = c->ptr_from_rva(ed->nName),
			functions_ptr = c->ptr_from_rva(ed->AddressOfFunctions),
			names_ptr = c->ptr_from_rva(ed->AddressOfNames),
			ordinals_ptr = c->ptr_from_rva(ed->AddressOfNameOrdinals);
	
	ptr_to_functions = functions_ptr;
	ptr_to_names = names_ptr;
	ptr_to_ordinals = ordinals_ptr;
	ptr_to_name = name_ptr;
	rva_to_functions = ed->AddressOfFunctions;
	rva_to_names = ed->AddressOfNames;
	rva_to_ordinals = ed->AddressOfNameOrdinals;
	rva_to_name = ed->nName;
			
	// read name.
	char *module_name = Alloc<char>::anew(33);
	input->seekg(name_ptr, ios_base::beg);
	input->read(module_name, 32);
	this->nname = module_name;
	Alloc<char>::adelete(module_name);

	string name;
	functions.clear();
	input->seekg(functions_ptr, ios_base::beg);
	
	for(int i = 0, len = ed->NumberOfFunctions; i < len; i++) {
		uptr ptr_rva = 0, ptr = 0;
		input->read((char *) &ptr_rva, 4);

		// quirk one: rva is 0, so it's unused.
		if(ptr_rva > 0)
			ptr = c->ptr_from_rva(ptr_rva);

		// TODO: quirk two: if rva points to this section, it's a forwarded export.
		
		FunctionInfo *fi = new FunctionInfo();
		fi->export_idx = i;
		fi->ptr = ptr;
		fi->ptr_rva = ptr_rva;
		fi->ord = ed->nBase + i;
		
		functions.push_back(fi);
	}
	
	assert(functions.size() == ed->NumberOfFunctions);
	
	input->seekg(ordinals_ptr, ios_base::beg);
	for(int i = 0, len = ed->NumberOfNames; i < len; i++) {
		ushort idx = 0;
		input->read((char *) &idx, 2);
		
		FunctionInfo *fi = get_functioninfo_by_index(idx);
		
		if(fi) {
			fi->name_idx = i;
		}
	}
	
	// resolve names
	input->seekg(names_ptr, ios_base::beg);
	for(int i = 0, len = ed->NumberOfNames; i < len; i++) {
		ulong name_rva, name_ptr;
		input->read((char *) &name_rva, 4);
		
		FunctionInfo *fi = get_functioninfo_by_name_idx(i);
		
		if(fi) {
			name_ptr = c->ptr_from_rva(name_rva);
			fi->name_rva = name_rva;
			fi->name_ptr = name_ptr;
		}
	}
	
	// read names
	vector<FunctionInfo*>::iterator i;
	for(i = functions.begin(); i != functions.end(); ++i) {
		FunctionInfo *fi = *i;
		
		if(fi->name_ptr == 0) 
			continue;
		
		input->seekg(fi->name_ptr, ios_base::beg);
		
		char ch = 0;
		while(true) {
			input->get(ch);
			
			if(ch == 0 || input->bad() || !input->good())
				break;
			
			fi->name += ch;
		}
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
