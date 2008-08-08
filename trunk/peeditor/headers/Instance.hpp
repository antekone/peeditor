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
	/* właściwości */
	INSTANCE_MODE working_mode;
	string input_file;
	string dump_args;
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
	
	string get_input_file();
	string get_dump_args();
	bool is_verbose();
	bool is_first_thunk();
};

#endif	/* _INSTANCE_HPP */

