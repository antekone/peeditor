/*
 * File:   MzHeader.hpp
 * Author: antek
 *
 * Created on 21 lipiec 2008, 20:35
 */

#ifndef _MZHEADER_HPP
#define	_MZHEADER_HPP

#include "TraceCtx.hpp"

struct MZ_HEADER {
	ushort e_magic;
	ushort e_cblp;
	ushort e_cp;
	ushort e_crlc;
	ushort e_cparhdr;
	ushort e_minalloc;
	ushort e_maxalloc;
	ushort e_ss;
	ushort e_sp;
	ushort e_csum;
	ushort e_ip;
	ushort e_cs;
	ushort e_lsarlc;
	ushort e_ovno;
	ushort e_res[4];
	ushort e_oemid;
	ushort e_oeminfo;
	ushort e_res2[10];
	ulong e_lfanew;
};
//typedef struct MZ_HEADER MZ_HEADER;

class MzHeader {
private:
	bool tracing;
	TraceCtx *trace_ctx;

public:
	MZ_HEADER *hdr;
	byte *dos_stub;
	uint dos_stub_size;
	bool valid;

	MzHeader(istream*, TraceCtx *);
	virtual ~MzHeader();

	uptr get_e_lfanew();

	ushort get_e_magic();

	byte *get_dos_stub();
	void set_dos_stub(byte*, uint);
	uint get_dos_stub_size();
	bool has_dos_stub();

	void invalidate();
	bool is_valid();

	bool ok;
};

#endif	/* _MZHEADER_HPP */

