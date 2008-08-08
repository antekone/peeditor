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
	
public:
	Structure(istream*, bool);
	virtual ~Structure();
	
	MzHeader *mz;
	PeHeader *pe;
	
	bool is_dll();
};

#endif	/* _STRUCTURE_HPP */

