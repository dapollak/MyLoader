#include "PEUtils.h"
#include "DLL.h"
#include <fstream>
#include <iostream>

using namespace std;

DLL::DLL(const wstring& dll_path) : m_path(dll_path) { }

void* DLL::RVAtoAd(address_size rva) {
	return reinterpret_cast<char*>(m_base) + rva;
}

bool DLL::MyLoadLibrary() {
	bool ret_val = true;

	m_base = VirtualAlloc(0, CalculateAllocationSize(m_path), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (m_base == NULL)
		return false;

	LoadSections();

	ret_val = FillImportTable();
	if (!ret_val)
		return false;

	Relocations();

	wcout << L"Dll Loaded Successfuly" << endl;
	return ret_val;
}


void DLL::LoadSections() {
	IMAGE_SECTION_HEADER curr_sec = { 0 };
	void *buff = 0;
	unsigned sizeOfSection = 0;

	for (size_t i = 0; i < GetNumberOfSections(m_path); i++) {
		fstream pe_file;
		pe_file.open(m_path.c_str(), ios::in | ios::binary);

		curr_sec = GetSectionHeaderByIdx(m_path, i);
		sizeOfSection = curr_sec.SizeOfRawData;
		buff = new char[sizeOfSection];
		ZeroMemory(buff, sizeOfSection);

		pe_file.seekg(curr_sec.PointerToRawData, ios::beg);
		pe_file.read(reinterpret_cast<char*>(buff), sizeOfSection);
		CopyMemory(RVAtoAd(curr_sec.VirtualAddress), (void*)buff, sizeOfSection);

		delete[] buff;
		pe_file.close();
	}
}

DLL::~DLL() {
	MyFreeLibrary();
	wcout << L"Dll Unloaded Successfully" << endl;
}

bool DLL::MyFreeLibrary() {
	return VirtualFree(m_base, 0, MEM_RELEASE);
}

void* DLL::MyGetProcAddress(const wstring& procName) {
	return RVAtoAd(::MyGetProcAddress(m_path, procName));
}

bool DLL::FillImportTable() {
	map<wstring, map<wstring, address_size>> imports;
	address_size proc_addr;
	HMODULE loaded = 0;
	void *proc = 0;
	void *dll_mem = 0;

	imports = GetImportedFunctions(m_path);
	for (auto dll = imports.begin(); dll != imports.end(); dll++) {
		loaded = LoadLibraryW((*dll).first.c_str());
		if (loaded == NULL)
			return false;

		for (auto funcs = (*dll).second.begin(); funcs != (*dll).second.end(); funcs++) {
			proc = GetProcAddress(loaded, UnicodeToAnsi(funcs->first).c_str());
			if (proc == NULL)
				return false;

			proc_addr = (address_size)proc;
			dll_mem = RVAtoAd(funcs->second);
			CopyMemory(dll_mem, &proc_addr, sizeof(address_size));
		}
	}
}

void DLL::Relocations() {
	vector<RELOC> relocs = GetRelocations(m_path);
	void *mem = 0;
	address_size orig_add = 0;
	address_size new_add = 0;

	for (auto i = relocs.begin(); i != relocs.end(); i++) {
		mem = RVAtoAd((*i).rva);
		if ((*i).type != 3)
			continue;

		orig_add = *reinterpret_cast<address_size*>(mem);
		new_add = orig_add - GetPeHeader(m_path).OptionalHeader.ImageBase + (address_size)m_base;

		MoveMemory(mem, &new_add, 4);
	}
}


