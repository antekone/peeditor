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

	// mz header.
	byte *mzh;

	// file header.
	byte *filehdr;

	// optional header.
	byte *opthdr;

	// section descriptors (headers).
	byte *secthdrs;

	// section descriptors (headers) length.
	ulong secthdrs_sz;

	// section data (all sections).
	byte *sectdata;
	ulong sectdata_sz;

	byte *imptbl;
	uint imptbl_sz;

	void new_mz();
	void new_pe();
	void new_imptbl();

	uptr get_pe_start_aligned(MzHeader *mzs);

	// Only for use with get_pe_start_aligned().
	uptr get_pe_start_unaligned(MzHeader *mzs);

	uint get_dll_names_sz();
	uint get_all_names_sz();

	ulong pe_start_delta;

public:
	PeBuilder(Structure *);
	virtual ~PeBuilder();

	byte *build_pe();
};

#endif /* PEBUILDER_HPP_ */
