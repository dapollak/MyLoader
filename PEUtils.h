#include <Windows.h>
#include <winnt.h>
#include <string>
#include <fstream>
#include <vector>
#include <map>

typedef ULONG address_size;

typedef struct _RELOC {
	unsigned rva;
	byte type;
} RELOC;


IMAGE_DOS_HEADER GetDosHeader(const std::wstring& pe);
IMAGE_NT_HEADERS GetPeHeader(const std::wstring& pe);
address_size GetPEHeaderOffset(const std::wstring& pe);
IMAGE_DATA_DIRECTORY GetDataDirectories(const std::wstring& pe, unsigned index);
unsigned GetNumberOfSections(const std::wstring& pe);
IMAGE_SECTION_HEADER GetSectionHeaderByIdx(const std::wstring& pe, unsigned index);
address_size GetSectionTableOffset(const std::wstring& pe);
bool FindSectionForVA(const std::wstring& pe, address_size va, IMAGE_SECTION_HEADER& section);
address_size GetFileOffsetForVA(const std::wstring& pe, unsigned va);

bool GetExportDirectory(const std::wstring& pe, IMAGE_EXPORT_DIRECTORY& exp_dir);
std::wstring GetStringAtOffset(const std::wstring& pe, address_size offset);
std::wstring GetProcNameByIndex(const std::wstring& pe, unsigned index);
address_size GetProcOffsetByIndex(const std::wstring& pe, unsigned index);

address_size MyGetProcAddress(const std::wstring& pe, const std::wstring& procname);
bool GetImportDescriptorByIndex(const std::wstring& pe, unsigned index, IMAGE_IMPORT_DESCRIPTOR& import_desc);
std::map<std::wstring, std::map<std::wstring, address_size>> GetImportedFunctions(const std::wstring& pe);

unsigned CalculateAllocationSize(const std::wstring& pe);
std::vector<RELOC> GetRelocations(const std::wstring& pe);

std::string UnicodeToAnsi(const std::wstring& ws);