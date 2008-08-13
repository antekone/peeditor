/*
 * PeBuilder.hpp
 *
 *  Created on: 2008-08-08
 *      Author: antek
 */

#ifndef PEBUILDER_HPP_
#define PEBUILDER_HPP_

#include "Structure.hpp"

class PeBuilder {
private:
	Structure *s;

	byte *mz_header;

	byte *file_header;
	byte *optional_header;
	byte *section_descriptors;
	ulong section_descriptors_len;
	byte *section_data;
	ulong section_data_len;

	byte *imptbl;
	uint imptblsz;

	void create_mz_header();
	void create_pe_header();
	void build_import_table();
	uptr calc_e_lfanew(MzHeader *mzs);

	uint get_it_size();

public:
	PeBuilder(Structure *);
	virtual ~PeBuilder();

	byte *build_pe();
};

#endif /* PEBUILDER_HPP_ */
