/* 
 * File:   PeHeader.hpp
 * Author: antek
 *
 * Created on 22 lipiec 2008, 15:33
 */

#ifndef _PEHEADER_HPP
#define	_PEHEADER_HPP

#include "ExportDirectory.hpp"
#include "ImportDirectory.hpp"

class PeHeader {
private:
	uint signature;
	struct IMAGE_FILE_HEADER *ifh;
	struct IMAGE_OPTIONAL_HEADER *ioh;
	struct IMAGE_SECTION_HEADER **sections;
	struct IMAGE_EXPORT_DIRECTORY *export_dir;
	
	RVAConverter *rvac;
	
	bool use_first_thunk;
	
	bool validate_machine();
	bool validate_subsystem();
	
	bool sec_build(istream*);
	void dd_build(istream*);
	void dd_exports(istream*);
	void dd_imports(istream*);
	
	// Characteristics.
public:
	PeHeader(istream*, bool);
	virtual ~PeHeader();

	ExportDirectory *exports;
	ImportDirectory *imports;

	bool ok;
	bool is_dll();
};

#endif	/* _PEHEADER_HPP */

