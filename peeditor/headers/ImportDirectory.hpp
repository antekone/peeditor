/*
 * File:   ImportDirectory.hpp
 * Author: antek
 *
 * Created on 6 sierpien 2008, 12:43
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
	bool inited, ord, bound;

	ImportFunction();
	~ImportFunction();
};

class DLLImport {
public:
	string name;

	ulong oft_rva, oft_ptr;
	ulong ft_rva, ft_ptr;
	ulong tstamp;
	ulong fwd_chain;
	ulong name_rva, name_ptr;

	uptr *names; // will help in PeBuilder::pe_build().

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
	vector<DLLImport*> *dlls;

	uptr directory_ptr, directory_rva;

	// setup in PeHeader->dd_imports
	string section_name;

	ImportDirectory(RVAConverter *c, IMAGE_SECTION_HEADER **sec,
			int n, istream *input, uptr rva, bool use_first_thunk,
			TraceCtx *trace);
	~ImportDirectory();

	void generate();
};

#endif	/* _IMPORTDIRECTORY_HPP */

