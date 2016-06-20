#include "PEUtils.h"
#include <iostream>

using namespace std;

IMAGE_DOS_HEADER GetDosHeader(const wstring& pe) {
	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);

	IMAGE_DOS_HEADER res = { 0 };
	pe_file.read(reinterpret_cast<char*>(&res), sizeof(IMAGE_DOS_HEADER));
	pe_file.close();
	return res;
}

address_size GetPEHeaderOffset(const wstring& pe) {
	return GetDosHeader(pe).e_lfanew;
}

IMAGE_NT_HEADERS GetPeHeader(const wstring& pe) {
	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);
	pe_file.seekg(GetPEHeaderOffset(pe), ios::beg);

	IMAGE_NT_HEADERS res = { 0 };
	pe_file.read(reinterpret_cast<char*>(&res), sizeof(IMAGE_NT_HEADERS));
	pe_file.close();
	return res;
}

IMAGE_DATA_DIRECTORY GetDataDirectories(const wstring& pe, unsigned index) {
	return GetPeHeader(pe).OptionalHeader.DataDirectory[index];
}

address_size GetSectionTableOffset(const wstring& pe) {
	return GetPEHeaderOffset(pe) + sizeof(IMAGE_NT_HEADERS);
}

bool FindSectionForVA(const wstring& pe, address_size va, IMAGE_SECTION_HEADER& section) {
	// Get Number Of Sections
	unsigned numOfSection = GetNumberOfSections(pe);

	IMAGE_SECTION_HEADER curr_section;
	for (size_t i = 0; i < numOfSection; i++) {
		curr_section = GetSectionHeaderByIdx(pe, i);
		if (curr_section.VirtualAddress <= va &&
			curr_section.Misc.VirtualSize + curr_section.VirtualAddress >= va) {
			section = curr_section;
			return true;
		}
	}
	return false;
}

address_size GetFileOffsetForVA(const wstring& pe, address_size va) {
	IMAGE_SECTION_HEADER section = { 0 };
	bool ret = FindSectionForVA(pe, va, section);

	if (!ret)
		return 0;

	return section.PointerToRawData + va - section.VirtualAddress;
}

bool GetExportDirectory(const wstring& pe, IMAGE_EXPORT_DIRECTORY& exp_dir) {
	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);

	address_size export_dir_file_offset = GetFileOffsetForVA(pe, GetDataDirectories(pe, 0).VirtualAddress);
	if (export_dir_file_offset == 0)
		return false;

	pe_file.seekg(export_dir_file_offset, ios::beg);

	IMAGE_EXPORT_DIRECTORY res = { 0 };
	pe_file.read(reinterpret_cast<char*>(&res), sizeof(IMAGE_EXPORT_DIRECTORY));
	exp_dir = res;
	pe_file.close();
	return true;
}

wstring GetStringAtOffset(const wstring& pe, address_size offset) {
	wstring res = L"";
	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);
	pe_file.seekg(offset, ios::beg);

	char curr = 0;
	pe_file.read(&curr, sizeof(char));
	while (curr != 0) {
		res += curr;
		pe_file.read(&curr, sizeof(char));
	}

	pe_file.close();
	return res;
}

wstring GetProcNameByIndex(const wstring& pe, unsigned index) {
	IMAGE_EXPORT_DIRECTORY ex_dir;
	bool ret = GetExportDirectory(pe, ex_dir);

	if (!ret)
		return L"";

	if (index >= ex_dir.NumberOfFunctions)
		return L"";

	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);

	address_size name_offset = 0;
	pe_file.seekg(GetFileOffsetForVA(pe, ex_dir.AddressOfNames) + sizeof(address_size) * index);
	pe_file.read(reinterpret_cast<char*>(&name_offset), sizeof(address_size));

	pe_file.close();
	return GetStringAtOffset(pe, GetFileOffsetForVA(pe, name_offset));
}

address_size GetProcOffsetByIndex(const wstring& pe, unsigned index) {
	IMAGE_EXPORT_DIRECTORY ex_dir;
	bool ret = GetExportDirectory(pe, ex_dir);

	if (!ret)
		return 0;

	if (index >= ex_dir.NumberOfFunctions)
		return 0;

	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);

	short ordinal = 0;
	pe_file.seekg(GetFileOffsetForVA(pe, ex_dir.AddressOfNameOrdinals) + sizeof(short) * index);
	pe_file.read(reinterpret_cast<char*>(&ordinal), sizeof(short));

	address_size address = 0;
	pe_file.seekg(GetFileOffsetForVA(pe, ex_dir.AddressOfFunctions) + sizeof(address_size) * ordinal);
	pe_file.read(reinterpret_cast<char*>(&address), sizeof(address_size));

	pe_file.close();
	return address;
}

address_size MyGetProcAddress(const wstring& pe, const wstring& procname) {
	wstring curr;

	unsigned i = 0;
	curr = GetProcNameByIndex(pe, i);
	while (curr.compare(L"")) {
		if (!curr.compare(procname))
			return GetProcOffsetByIndex(pe, i);
		i++;
		curr = GetProcNameByIndex(pe, i);
	}
	return 0;
}

bool GetImportDescriptorByIndex(const wstring& pe, unsigned index, IMAGE_IMPORT_DESCRIPTOR& import_desc) {
	IMAGE_DATA_DIRECTORY import_dir = GetDataDirectories(pe, 1);

	unsigned numOfImportDescs = import_dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); // Include last structure of zeroes
	if (index >= numOfImportDescs - 1)
		return false;

	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);

	pe_file.seekg(GetFileOffsetForVA(pe, import_dir.VirtualAddress) + index*sizeof(IMAGE_IMPORT_DESCRIPTOR), ios::beg);
	pe_file.read(reinterpret_cast<char*>(&import_desc), sizeof(IMAGE_IMPORT_DESCRIPTOR));
	return true;
}

map<wstring, map<wstring, address_size>> GetImportedFunctions(const wstring& pe) {
	IMAGE_IMPORT_DESCRIPTOR iid;
	map<wstring, map<wstring, address_size>> res;
	bool ret;
	wstring dllname;

	int index = 0;
	while ((ret = GetImportDescriptorByIndex(pe, index, iid))) {
		fstream pe_file;
		address_size name_address = 0;
		dllname.clear();

		dllname = GetStringAtOffset(pe, GetFileOffsetForVA(pe, iid.Name));

		pe_file.open(pe.c_str(), ios::in | ios::binary);
		pe_file.seekg(GetFileOffsetForVA(pe, iid.OriginalFirstThunk));

		unsigned i = 0;
		pe_file.read(reinterpret_cast<char*>(&name_address), sizeof(address_size));
		while (name_address != 0) {
			res[dllname][GetStringAtOffset(pe, GetFileOffsetForVA(pe, name_address) + 2)] = iid.FirstThunk + sizeof(address_size)*i;
			pe_file.read(reinterpret_cast<char*>(&name_address), sizeof(address_size));
			i++;
		}

		pe_file.close();
		index++;
	}
	return res;
}

unsigned GetNumberOfSections(const wstring& pe) {
	return GetPeHeader(pe).FileHeader.NumberOfSections;
}

IMAGE_SECTION_HEADER GetSectionHeaderByIdx(const wstring& pe, unsigned index) {
	IMAGE_SECTION_HEADER res_section = { 0 };

	// Get Number Of Sections
	unsigned numOfSection = GetNumberOfSections(pe);

	if (index >= numOfSection)
		return res_section;

	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);

	// Iterate Over Sections
	pe_file.seekg(GetPEHeaderOffset(pe) + sizeof(IMAGE_NT_HEADERS) + index*sizeof(IMAGE_SECTION_HEADER), ios::beg);

	pe_file.read(reinterpret_cast<char*>(&res_section), sizeof(IMAGE_SECTION_HEADER));
	pe_file.close();

	return res_section;
}


unsigned CalculateAllocationSize(const wstring& pe) {
	IMAGE_SECTION_HEADER last_sec = GetSectionHeaderByIdx(pe, GetNumberOfSections(pe) - 1);
	return last_sec.VirtualAddress + last_sec.SizeOfRawData;
}

vector<RELOC> GetRelocations(const wstring& pe) {
	IMAGE_DATA_DIRECTORY reloc_dir = GetDataDirectories(pe, 5);
	vector<RELOC> relocs;
	address_size curr_rva = 0;
	unsigned curr_size = 0;
	short curr_reloc_data;
	RELOC curr_reloc;

	fstream pe_file;
	pe_file.open(pe.c_str(), ios::in | ios::binary);
	pe_file.seekg(GetFileOffsetForVA(pe, reloc_dir.VirtualAddress), ios::beg);

	pe_file.read(reinterpret_cast<char*>(&curr_rva), sizeof(address_size));
	while (curr_rva != 0) {
		pe_file.read(reinterpret_cast<char*>(&curr_size), sizeof(unsigned));
		curr_size -= 8;
		curr_size /= 2;

		for (size_t i = 0; i < curr_size; i++) {
			pe_file.read(reinterpret_cast<char*>(&curr_reloc_data), sizeof(short));
			curr_reloc.rva = curr_rva + (curr_reloc_data & 0x0fff);
			curr_reloc.type = curr_reloc_data >> 12;
			relocs.push_back(curr_reloc);
		}
		pe_file.read(reinterpret_cast<char*>(&curr_rva), 4);
	}
	return relocs;
}

string UnicodeToAnsi(const wstring& ws) {
	string res;
	for (auto i = ws.begin(); i != ws.end(); i++)
		res += static_cast<char>(*i);
	return res;
}