/*
 *
 * Utils.hpp
 *
 * This file is a part of PED.
 * Written by antonone.
 *
 * Visit http://anadoxin.org/blog
 *
 */

#ifndef UTILS_HPP_
#define UTILS_HPP_

class Utils {
public:
	Utils();
	virtual ~Utils();

	static void string_to_bytearray(byte *out, string in, int len);
	static uint string_to_uint(string addr);
	static NUMERIC_SYSTEM get_numeric_system(string addr);
	static bool traced_io_read(void *, istream*, int len, uint traced);
	static bool traced_io_seek_beg(istream*, uint pos, uint traced);
	static uint align(uint value, uint align_val);
};

#endif /* UTILS_HPP_ */
