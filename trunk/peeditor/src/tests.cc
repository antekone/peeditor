#include "ped.hpp"
#include "Instance.hpp"
#include "Structure.hpp"
#include "PeHeader.hpp"
#include "PeBuilder.hpp"

#ifdef TESTS


int tests(Instance *inst) {
	string filename = inst->get_input_file();
	istream *file_stream = new ifstream(filename.c_str(), ifstream::in);

	auto_ptr<istream> ifs(file_stream);
	auto_ptr<Structure> pe_file(new Structure(file_stream, inst->is_first_thunk()));
	Structure *s = pe_file.get();

	PeBuilder *builder = new PeBuilder(s);
	byte *file_data = builder->build_pe();

	return 0;
}
#endif
