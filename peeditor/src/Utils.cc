/*
 *
 * Utils.cc
 *
 * This file is a part of PED.
 * Written by antonone.
 *
 * Visit http://anadoxin.org/blog
 *
 */

#include "ped.hpp"
#include "Utils.hpp"

Utils::Utils() {

}

Utils::~Utils() {

}

void Utils::string_to_bytearray(byte *dst, string src, int len) {
	uint l = src.size() < (uint)len? src.size(): len;

	for(uint i = 0; i < l; i++) {
		dst[i] = src.at(i);
	}

	return;
}

NUMERIC_SYSTEM Utils::get_numeric_system(string saddr) {
	const char *ptr = saddr.c_str();
	int len = saddr.size();

	if(len < 2)
		return SYS_UNKNOWN;

	char lch = ptr[len - 1];

	// by prefixes
	if(ptr[0] == '0' && (ptr[1] == 'x' || ptr[1] == 'X'))
		return SYS_HEX;

	// by suffixes
	if(lch == 'h' || lch == 'H')
		return SYS_HEX;

	if(lch == 'd' || lch == 'D')
		return SYS_DEC;

	if(lch == 'o' || lch == 'O')
		return SYS_OCT;

	if(lch == 'b' || lch == 'B')
		return SYS_BIN;

	if(ptr[0] == '0')
		return SYS_OCT;

	return SYS_DEC;
}

uint Utils::string_to_uint(string saddr) {

	NUMERIC_SYSTEM sys = Utils::get_numeric_system(saddr);

	// use decimal by default
	if(sys == SYS_UNKNOWN)
		sys = SYS_DEC;

	switch(sys) {
	case SYS_HEX:
		if(saddr.at(0) == '0' && (saddr.at(1) == 'x' || saddr.at(1) == 'X'))
			saddr = saddr.substr(2);

		if(saddr.at(saddr.size() - 1) == 'h' || saddr.at(saddr.size() - 1) == 'H')
			saddr = saddr.substr(0, saddr.size() - 1);

		uint value;
		sscanf(saddr.c_str(), "%X", &value);
		return value;
	case SYS_OCT:
		cout << "octal numbers not supported yet" << endl;
		assert(0);
	case SYS_DEC:
		return atoi(saddr.c_str());
	case SYS_BIN:
		cout << "binary numbers not supported yet" << endl;
		assert(0);
	case SYS_UNKNOWN:
		cout << "unknown numeric value" << endl;
		assert(0);
	}

	return 0;
}

bool Utils::traced_io_read(void *buf, istream *input, int len, uint traced) {
	uptr this_offset = input->tellg();
	uptr last_offset = this_offset + len;

	// perform the read
	input->read((char *) buf, len);

	if(traced >= this_offset && traced <= last_offset) {
		return true;
	} else
		return false;
}

bool Utils::traced_io_seek_beg(istream *input, uint pos, uint traced) {
	uptr new_offset = pos;
	input->seekg(pos, ios_base::beg);
	return traced == new_offset;
}

uint Utils::align(uint value, uint align_val) {
	if(value % align_val)
		return value + align_val - (value % align_val);
	else
		// `value' already is properly aligned.
		return value;
}

string _(string sfmt, ...) {
	const char *fmt = sfmt.c_str();
	int n, size = 100;
	char *p, *np;
	va_list ap;
	string s;

	if((p = (char*) malloc(size)) == NULL) {
		s = "(no memory!)";
		return s;
	}

	while(true) {
		va_start(ap, fmt);
		n = vsnprintf(p, size, fmt, ap);
		va_end(ap);

		if(n > -1 && n < size) {
			s = p;
			free(p);
			return s;
		}

		if(n > -1)
			size = n + 1;
		else
			size *= 2;

		if((np = (char*) realloc(p, size)) == NULL) {
			free(p);
			s = "(no memory!)";
			return s;
		} else {
			p = np;
		}
	}
}
