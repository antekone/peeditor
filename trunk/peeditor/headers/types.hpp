/* 
 * File:   types.hpp
 * Author: antek
 *
 * Created on 21 lipiec 2008, 20:36
 */

#ifndef _TYPES_HPP
#define	_TYPES_HPP

typedef unsigned short ushort;
typedef unsigned long ulong;
typedef unsigned int uint;
typedef ulong uptr;
typedef unsigned char byte;

#define null NULL
#define emptystr ((string)"")

enum INSTANCE_MODE {
	USAGE, DUMPING, QUIT, SELFDIAG
};

extern char *FATAL;
extern char *WARNING;
extern char *INFO;

enum {
	IMAGE_FILE_MACHINE_I386 = 0x14C,
	IMAGE_FILE_MACHINE_I486 = 0x14D,
	IMAGE_FILE_MACHINE_PENTIUM = 0x14E,
	IMAGE_FILE_MACHINE_R3000_BE = 0x160,
	IMAGE_FILE_MACHINE_R3000_LE = 0x162,
	IMAGE_FILE_MACHINE_R4000_BE = 0x166,
	IMAGE_FILE_MACHINE_R10000_LE = 0x168,
	IMAGE_FILE_MACHINE_ALPHA = 0x184,
	IMAGE_FILE_MACHINE_PPC = 0x1f0
};

enum {
	IMAGE_SUBSYSTEM_NATIVE = 1,
	IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
	IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
	IMAGE_SUBSYSTEM_OS2_CUI = 5,
	IMAGE_SUBSYSTEM_POSIX_CUI = 7,
	IMAGE_SUBSYSTEM_WINCE_GUI = 9,
	IMAGE_SUBSYSTEM_EFI = 0x0a,
	IMAGE_SUBSYSTEM_EFI_BOOT = 0x0b,
	IMAGE_SUBSYSTEM_EFI_RUNTIME = 0x0c
};

struct IMAGE_FILE_HEADER {
	ushort Machine;
	ushort NumberOfSections;
	ulong TimeDateStamp;
	ulong PointerToSymbolTable;
	ulong NumberOfSymbols;
	ushort SizeOfOptionalHeader;
	
	union {
		ushort word;
		struct {
			// Used on relocations in sections, not base relocations section.
			bool relocs_stripped :1;
			bool executable_image :1;
			bool line_nums_stripped :1;
			bool local_symbols_stripped :1;
			bool aggressive_paging :1;
			bool reserved1 :3;
			bool expect_32bit :1;
			bool not_relocatable :1;
			bool run_from_fixed_medium :1;
			bool run_from_localhost :1;
			bool driver :1;
			bool dll :1;
			bool single_processor :1;
		};
	} Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
	ulong rva;
	ulong size;
};

struct IMAGE_OPTIONAL_HEADER {
	ushort Magic;
	byte MajorLinkerVersion;
	byte MinorLinkerVersion;
	ulong SizeOfCode;
	ulong SizeOfInitializedData;
	ulong SizeOfUninitializedData;
	ulong AddressOfEntryPoint;
	ulong BaseOfCode;
	ulong BaseOfData;
	ulong ImageBase;
	ulong SectionAlignment;
	ulong FileAlignment;
	ushort MajorOperatingSystemVersion;
	ushort MinorOperatingSystemVersion;
	ushort MajorImageVersion;
	ushort MinorImageVersion;
	ushort MajorSubsystemVersion;
	ushort MinorSubsystemVersion;
	ulong Reserved1;
	ulong SizeOfImage;
	ulong SizeOfHeaders;
	ulong CheckSum;
	ushort Subsystem;
	ushort DllCharacteristics;
	ulong SizeOfStackReserve; // not in dll
	ulong SizeOfStackCommit; // not in dll
	ulong SizeOfHeapReserve; // not in dll
	ulong SizeOfHeapCommit; // not in dll
	ulong LoaderFlags;
	ulong NumberOfRvaAndSizes;
	struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_SECTION_HEADER {
	byte Name[8];
	union {
		ulong PhysicalAddress;
		ulong VirtualSize;
	} Misc;
	ulong VirtualAddress;
	ulong SizeOfRawData; // rounded up to next `FileAlignment`
	ulong PointerToRawData;
	ulong PointerToRelocations;
	ulong PointerToLinenumbers;
	ushort NumberOfRelocations; // not in .exe
	ushort NumberOfLinenumbers; // not in .exe
	union {
		ulong dword;
		struct {
			bool nothing1 :5;
			bool code :1;
			bool initialized_data :1;
			bool uninitialized_data :1; // will be zeroed
			bool nothing2 :1;
			bool linker_info :1; // not in exe
			bool nothing3 :1;
			bool linker_info2 :1; // not in exe
			bool comdat :1;
			bool nothing4 :3;
			bool fardata :1;
			bool purgable :1;
			bool locked :1;
			bool preload :1;
			bool nothing5 :4;
			bool extended_relocations :1;
			bool discardable :1;
			bool not_cacheable :1;
			bool not_pageable :1;
			bool shared :1;
			bool executable :1;
			bool readable :1;
			bool writable :1;
		};
	} Characteristics;
};

// export forwarding - http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
struct IMAGE_EXPORT_DIRECTORY {
	ulong Characteristics; // always 0
	ulong TimeDataStamp;
	ushort MajorVersion; // always 0
	ushort MinorVersion; // always 0
	ulong nName; // rva to name of dll
	ulong nBase; // base ordinal
	ulong NumberOfFunctions;
	ulong NumberOfNames;
	ulong AddressOfFunctions; // rva to eat
	ulong AddressOfNames; // rva to names
	ulong AddressOfNameOrdinals; // rva to ordinals
};

struct IMAGE_IMPORT_BY_NAME {
	ushort Hint;
};

struct IMAGE_THUNK_DATA {
	union {
		ulong Function; // memory address
		ulong Ordinal; // ulong
		ulong AddressOfData; // rva to IMAGE_IMPORT_BY_NAME
		ulong ForwarderString; // rva
	};
};

struct IMAGE_IMPORT_DESCRIPTOR {
	ulong OriginalFirstThunk;
	ulong TimeDateStamp;
	ulong ForwarderChain;
	ulong Name;
	ulong FirstThunk;
};

#endif	/* _TYPES_HPP */

