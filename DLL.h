#pragma once
#include <Windows.h>
#include <string>

typedef unsigned char byte;

class DLL {
public:
	DLL(const std::wstring& path);
	
	// copy cTor
	DLL(const DLL& other);
	
	// move cTor
	DLL(DLL && other);

	~DLL();

	bool MyLoadLibrary();

	void* MyGetProcAddress(const std::wstring& procName);

	bool FillImportTable();

	void Relocations();

	void LoadSections();

	bool MyFreeLibrary();

	void* RVAtoAd(address_size rva);


private:
	std::wstring m_path;
	void *m_base;
};