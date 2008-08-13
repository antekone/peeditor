/*
 * Utils.hpp
 *
 *  Created on: 2008-08-09
 *      Author: antek
 */

#ifndef UTILS_HPP_
#define UTILS_HPP_

class Utils {
public:
	Utils();
	virtual ~Utils();

	static void string_to_bytearray(byte *, string, int);
	static uint string_to_uint(string addr);
	static NUMERIC_SYSTEM get_numeric_system(string addr);
	static bool traced_io_read(void *, istream*, int len, uint traced);
	static bool traced_io_seek_beg(istream*, uint pos, uint traced);
};

#endif /* UTILS_HPP_ */
