/*
 * File:   PeHeader.hpp
 * Author: antek
 *
 * Created on 22 lipiec 2008, 15:33
 *
 */

#ifndef _PEHEADER_HPP
#define	_PEHEADER_HPP

#include "Section.hpp"
#include "ExportDirectory.hpp"
#include "ImportDirectory.hpp"

class PeHeader {
private:
	bool use_first_thunk;
	TraceCtx *trace_ctx;
	bool tracing;
	uptr lastsec_ptr;

	bool validate_machine();
	bool validate_subsystem();

	bool sec_build(istream*);
	void dd_build(istream*);
	void dd_exports(istream*);
	void dd_imports(istream*);

	void sync_csections_with_sections(int nos, istream *input = NULL, uptr *ptrs = NULL);
	void add_section(IMAGE_SECTION_HEADER *usect, Section *nsect);
	void flush_sectn_in_header(Section *nsect);
	void grow_and_remap_sections(IMAGE_SECTION_HEADER *usect);
	void grow_and_remap_csections(Section *newsection);
	void read_code_in_header(istream*);

public:
	PeHeader(istream*, bool, TraceCtx *);
	virtual ~PeHeader();

	RVAConverter *rvac;
	ExportDirectory *exports;
	ImportDirectory *imports;
	ImportDirectory *imp_ft; // use `imports', not this one.
	ImportDirectory *imp_oft; // use `imports', not this one.
	Section **sections_data;
	byte *hdata; // data in header
	uint hdata_sz;

	uint signature;
	struct IMAGE_FILE_HEADER *ifh;
	struct IMAGE_OPTIONAL_HEADER *ioh;
	struct IMAGE_SECTION_HEADER **sections;
	struct IMAGE_EXPORT_DIRECTORY *export_dir;

	Section *get_csection_for_section(IMAGE_SECTION_HEADER*);
	Section *get_csection_for_rva(uptr rva);
	Section *get_csection_for_ptr(uptr ptr);

	void csection_to_section(Section *in, IMAGE_SECTION_HEADER *out);
	void section_to_csection(IMAGE_SECTION_HEADER *in, Section *out);
	Section *add_section(string name, int size);
	bool remove_section(Section*);

	bool ok;
	bool is_dll();

	void dump_trace_result(ostringstream &);
};

#endif	/* _PEHEADER_HPP */

