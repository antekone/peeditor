#include "ped.hpp"

#include "Instance.hpp"

Instance::Instance() {
	this->working_mode = USAGE;
	this->verbose = false;
	this->use_first_thunk = false;
}

Instance::~Instance() {
	
}

void Instance::set_mode(INSTANCE_MODE m) {
	this->working_mode = m;
}

INSTANCE_MODE Instance::get_mode() {
	return this->working_mode;
}

void Instance::set_input_file(string file) {
	auto_ptr<ifstream> ifs(new ifstream(file.c_str(), ifstream::in));
	if(ifs->good()) {
		this->input_file = file;
		ifs->close();
	} else
		this->input_file = emptystr;
}

string Instance::get_input_file() {
	return this->input_file;
}

void Instance::set_dump_args(string args) {
	dump_args = args;
}

string Instance::get_dump_args() {
	return dump_args;
}

bool Instance::is_verbose() {
	return verbose;
}

void Instance::set_verbose(bool flag) {
	verbose = flag;
}

bool Instance::is_first_thunk() {
	return use_first_thunk;
}

void Instance::set_first_thunk(bool flag) {
	use_first_thunk = flag;
}
