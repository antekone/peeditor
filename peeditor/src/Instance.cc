#include "ped.hpp"

#include "Instance.hpp"

Instance::Instance() {
	this->working_mode = USAGE;
	this->f_verbose = false;
	this->f_use_first_thunk = false;
}

Instance::~Instance() {

}

void Instance::mode(INSTANCE_MODE m) {
	this->working_mode = m;
}

INSTANCE_MODE Instance::mode() {
	return this->working_mode;
}

void Instance::input_file(string file) {
	auto_ptr<ifstream> ifs(new ifstream(file.c_str(), ifstream::in));
	if(ifs->good()) {
		this->f_input_file = file;
		ifs->close();
	} else
		this->f_input_file = emptystr;
}

string Instance::input_file() {
	return this->f_input_file;
}

void Instance::dump_args(string args) {
	f_dump_args = args;
}

string Instance::dump_args() {
	return f_dump_args;
}

bool Instance::verbose() {
	return f_verbose;
}

void Instance::verbose(bool flag) {
	f_verbose = flag;
}

bool Instance::first_thunk() {
	return f_use_first_thunk;
}

void Instance::first_thunk(bool flag) {
	f_use_first_thunk = flag;
}

void Instance::calc_addr(string addr) {
	f_calc_addr = addr;
}

string Instance::calc_addr() {
	return f_calc_addr;
}

void Instance::traced_address(string addr) {
	f_traced_address = addr;
}

string Instance::traced_address() {
	return f_traced_address;
}
