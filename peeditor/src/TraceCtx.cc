/*
 * TraceCtx.cc
 *
 *  Created on: 2008-08-11
 *      Author: antek
 */

#include "ped.hpp"
#include "TraceCtx.hpp"

TraceCtx::TraceCtx(uint address) {
	this->address = address;
	messages.clear();
}

TraceCtx::~TraceCtx() {

}

bool TraceCtx::range_check(istream *stream, uint len) {
	uint this_addr = stream->tellg();
	uint max_addr = this_addr + len;

	//log(_("(range check: %08X/%08X", this_addr, max_addr));
	bool flag = (address >= this_addr && address < max_addr);

	if(flag) {
		string& str = messages.at(messages.size() - 1);
		str.insert(0, "HIT: ");

		hit();

		uint delta = address - this_addr;
		log(_("HIT: Offset to read base pointer (delta): 0x%08X/%dd, delta + base = 0x%08X/%dd", delta, delta, delta + this_addr, delta + this_addr));
	}

	return flag;
}

void TraceCtx::log(string msg) {
	messages.push_back(msg);
}

void TraceCtx::hit() {
	// ... :P
}

void TraceCtx::dump(ostringstream &out) {
	int pos = 1;
	for(vector<string>::iterator i = messages.begin(); i != messages.end(); ++i) {
		string msg = (*i);

		out << setw(5) << dec << pos++ << ". " << msg << endl;
	}
}
