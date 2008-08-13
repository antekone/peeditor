/*
 * TraceCtx.hpp
 *
 *  Created on: 2008-08-11
 *      Author: antek
 */

#ifndef TRACECTX_HPP_
#define TRACECTX_HPP_

class TraceCtx {
private:
	uint address;
	istream *stream;
	vector<string> messages;

public:
	TraceCtx(uint address);
	virtual ~TraceCtx();

	void log(string);
	void dump(ostringstream &);
	void hit();
	bool range_check(istream *, uint);
};

#endif /* TRACECTX_HPP_ */
