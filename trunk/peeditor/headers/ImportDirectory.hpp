/*
 * File:   ImportDirectory.hpp
 * Author: antek
 *
 * Created on 6 sierpieñ 2008, 12:43
 */

#ifndef _IMPORTDIRECTORY_HPP
#define	_IMPORTDIRECTORY_HPP

#include "TraceCtx.hpp"

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
private:
	void ctor(RVAConverter *c, IMAGE_SECTION_HEADER **sc, int n,
			istream *input, uptr rva, bool use_first_thunk);

	TraceCtx *trace_ctx;
	bool tracing;
public:
	vector<DLLImport *> *dlls;

	uptr import_ptr;

	// setup in PeHeader->dd_imports
	string section_name;

	ImportDirectory(RVAConverter *c, IMAGE_SECTION_HEADER **sec,
			int n, istream *input, uptr rva, bool use_first_thunk,
			TraceCtx *trace);
	~ImportDirectory();

	void generate();
};

#endif	/* _IMPORTDIRECTORY_HPP */

