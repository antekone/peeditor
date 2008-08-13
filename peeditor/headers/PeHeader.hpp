/*
 * File:   PeHeader.hpp
 * Author: antek
 *
 * Created on 22 lipiec 2008, 15:33
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

	bool validate_machine();
	bool validate_subsystem();

	bool sec_build(istream*);
	void dd_build(istream*);
	void dd_exports(istream*);
	void dd_imports(istream*);

	// Characteristics.
public:
	PeHeader(istream*, bool, TraceCtx *);
	virtual ~PeHeader();

	RVAConverter *rvac;
	ExportDirectory *exports;
	ImportDirectory *imports_first_thunk;
	ImportDirectory *imports_original_first_thunk;
	Section **sections_data;

	uint signature;
	struct IMAGE_FILE_HEADER *ifh;
	struct IMAGE_OPTIONAL_HEADER *ioh;
	struct IMAGE_SECTION_HEADER **sections;
	struct IMAGE_EXPORT_DIRECTORY *export_dir;

	Section *get_csection_for_section(IMAGE_SECTION_HEADER*);

	bool ok;
	bool is_dll();

	void dump_trace_result(ostringstream &);
};

#endif	/* _PEHEADER_HPP */

