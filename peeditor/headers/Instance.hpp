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
	string input_file;
	string dump_args;
	string calc_addr;
	string traced_address;
	bool verbose;
	bool use_first_thunk;

public:
	Instance();
	virtual ~Instance();

	INSTANCE_MODE get_mode();

	void set_mode(INSTANCE_MODE m);
	void set_dump_args(string args);
	void set_input_file(string file);
	void set_verbose(bool);
	void set_first_thunk(bool);
	void set_calc_addr(string addr);
	void set_traced_address(string addr);

	string get_input_file();
	string get_dump_args();
	string get_calc_addr();
	string get_traced_address();
	bool is_verbose();
	bool is_first_thunk();
};

#endif	/* _INSTANCE_HPP */

