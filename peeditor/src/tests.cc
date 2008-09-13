#include "ped.hpp"
#include "Instance.hpp"
#include "Structure.hpp"
#include "PeHeader.hpp"
#include "PeBuilder.hpp"

#include <sys/stat.h>

#ifdef TESTS

int tests(Instance *inst) {
	string filename = inst->input_file();
	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);

	auto_ptr<istream> ifs(file_stream);
	auto_ptr<Structure> pe_file(new Structure(file_stream, inst->first_thunk()));
	Structure *s = pe_file.get();
	if(!s->ok) {
		cout << "Exiting.\n";
		return 1;
	}


	PeHeader *pe = s->pe;

	Section *sec = pe->add_section(".new", 512);
	pe->add_section("X", 100);

	PeBuilder *builder = new PeBuilder(s);
	byte *file_data = builder->build_pe();

	return 0;
}
#endif
