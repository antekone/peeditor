/*
 * File:   Structure.hpp
 * Author: antek
 *
 * Created on 21 lipiec 2008, 21:47
 */

#ifndef _STRUCTURE_HPP
#define	_STRUCTURE_HPP

#include "MzHeader.hpp"
#include "PeHeader.hpp"

class Structure {
private:
	istream *input;
	void parse();
	void parse_mz();
	bool use_first_thunk;

	TraceCtx *trace_ctx;
	bool tracing;

public:
	Structure(istream*, bool, uint addr_trace = UINT_NOVALUE);
	virtual ~Structure();

	MzHeader *mz;
	PeHeader *pe;

	bool is_dll();

	// header pointers.
	bool hdr_ptrs();
};

#endif	/* _STRUCTURE_HPP */

