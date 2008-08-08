#include "ped.hpp"

#ifdef TESTS
bool test_converter() {
	const int sec_len = 5;
	IMAGE_SECTION_HEADER **sections = Alloc<IMAGE_SECTION_HEADER>::anewarray(sec_len);

	sections[0]->VirtualAddress = 0x1000;
	sections[0]->Misc.VirtualSize = 0xbeb0;
	sections[0]->PointerToRawData = 0x200;
	
	sections[1]->VirtualAddress = 0xD000;
	sections[1]->Misc.VirtualSize = 0xC7C31;
	sections[1]->PointerToRawData = 0xc200;
	
	sections[2]->VirtualAddress = 0xD5000;
	sections[2]->Misc.VirtualSize = 0x158;
	sections[2]->PointerToRawData = 0xd4000;

	sections[3]->VirtualAddress = 0xD6000;
	sections[3]->Misc.VirtualSize = 0x6A8;
	sections[3]->PointerToRawData = 0xd4200;

	sections[4]->VirtualAddress = 0xD7000;
	sections[4]->Misc.VirtualSize = 0x1146;
	sections[4]->PointerToRawData = 0xd4a00;
			
	RVAConverter *c = new RVAConverter(sections, sec_len);
	
	c->ptr_from_rva(0);
	
	delete c;
	
	Alloc<IMAGE_SECTION_HEADER>::adeletearray(sections, sec_len);
	return true;
}

int tests() {
	srand(time(NULL));
	cout << "Running tests. " << endl;
	
	cout << "1. RVA Converter" << endl;
	for(int i = 0; i < 1000; i++) {
		cout << ".";
		if(!test_converter())
			return 1;
	}
	cout << endl;
	
	return 0;
}
#endif
