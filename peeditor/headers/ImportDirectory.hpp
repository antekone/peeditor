/*
 * File:   ImportDirectory.hpp
 * Author: antek
 *
 * Created on 6 sierpie� 2008, 12:43
 */

#ifndef _IMPORTDIRECTORY_HPP
#define	_IMPORTDIRECTORY_HPP

class ImportFunction {
public:
	uptr thunk_rva, thunk_offset, thunk_ptr;
	ulong thunk_value;
	ushort hint;
	string api_name;
	bool inited, ordinal, bound;

	ImportFunction();
	~ImportFunction();
};

class DLLImport {
public:
	string name;

	ulong original_first_thunk, original_first_thunk_ptr;
	ulong time_date_stamp;
	ulong forwarder_chain;
	ulong first_thunk, first_thunk_ptr;
	ulong name_rva, name_ptr;

	vector<ImportFunction*> *functions;

	DLLImport();
	~DLLImport();
};

class ImportDirectory {
public:
	vector<DLLImport *> *dlls;

	ImportDirectory();
	~ImportDirectory();
};

#endif	/* _IMPORTDIRECTORY_HPP */

