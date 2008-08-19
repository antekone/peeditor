/*
 * File:   ExportDirectory.hpp
 * Author: antek
 *
 * Created on 30 lipiec 2008, 18:05
 */

#ifndef _EXPORTDIRECTORY_HPP
#define	_EXPORTDIRECTORY_HPP

#include "TraceCtx.hpp"

class FunctionInfo {
public:
	uptr ptr, ptr_rva, name_ptr, name_rva;
	int export_idx, ord;
	string name;
	int name_idx;

	FunctionInfo() {
		name_ptr = 0;
		name_rva = 0;
		export_idx = 0;
		ord = 0;
		name_idx = -1;
		name = "";
		ptr = 0;
		ptr_rva = 0;
	}
};

class ExportDirectory {
private:
	TraceCtx *trace_ctx;
	bool tracing;

public:
	ulong traits;
	string nname;
	ulong nbase;
	ulong funcs_sz;
	ulong names_sz;

	uptr funcs_ptr, funcs_rva;
	uptr names_ptr, names_rv;
	uptr ordinals_ptr, ordinals_rva;
	uptr name_ptr, name_rva;
	uptr directory_ptr, directory_rva;
	ulong directory_size;

	vector<FunctionInfo *> functions;

	ExportDirectory(RVAConverter *, IMAGE_SECTION_HEADER **, int n, IMAGE_EXPORT_DIRECTORY *, istream*, uptr export_rva, TraceCtx *);
	~ExportDirectory();

	FunctionInfo *get_functioninfo_by_ord(int);
	FunctionInfo *get_functioninfo_by_index(int);
	FunctionInfo *get_functioninfo_by_name_idx(int);
};

#endif	/* _EXPORTDIRECTORY_HPP */

