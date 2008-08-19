/*
 * File:   Instance.hpp
 * Author: antek
 *
 * Created on 21 lipiec 2008, 20:47
 */

#ifndef _INSTANCE_HPP
#define	_INSTANCE_HPP

class Instance {
private:
	/* properties */
	INSTANCE_MODE working_mode;
	string f_input_file;
	string f_dump_args;
	string f_calc_addr;
	string f_traced_address;
	bool f_verbose;
	bool f_use_first_thunk;

public:
	Instance();
	virtual ~Instance();

	INSTANCE_MODE mode();

	void mode(INSTANCE_MODE m);
	void dump_args(string args);
	void input_file(string file);
	void verbose(bool);
	void first_thunk(bool);
	void calc_addr(string addr);
	void traced_address(string addr);

	string input_file();
	string dump_args();
	string calc_addr();
	string traced_address();
	bool verbose();
	bool first_thunk();
};

#endif	/* _INSTANCE_HPP */

