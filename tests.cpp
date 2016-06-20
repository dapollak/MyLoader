#include "PEUtils.h"
#include "DLL.h"
#include <iostream>

using namespace std;
wchar_t *pe = L"C:\\Users\\Daniel\\Documents\\visual studio 2015\\Projects\\WindowsProjects\\Debug\\dlldemo.dll";
wchar_t *exe = L"C:\\Users\\Daniel\\Documents\\visual studio 2015\\Projects\\WindowsProjects\\Debug\\Usedlldemo.exe";
typedef int(*foo)(int y);

int main() {
	DLL demo(pe);

	demo.MyLoadLibrary();

	foo proc = (foo)demo.MyGetProcAddress(L"foo");

	int i = proc(3);
 	return 0;
}