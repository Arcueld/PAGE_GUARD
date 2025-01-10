#pragma once
#include "definition.h"
#include <vector>
#include <string>
#include <sstream>
#include <unordered_map>
#include "resource1.h"

typedef HMODULE(WINAPI* pLoadLibrary)(
	_In_ LPCWSTR lpLibFileName
	);

typedef VOID(WINAPI* pSwitchToFiber)(
	_In_ LPVOID lpFiber
	);

typedef LPVOID(WINAPI* pConvertThreadToFiber)(
	_In_opt_ LPVOID lpParameter
	);

typedef LPVOID(WINAPI* pCreateFiber)(
	_In_     SIZE_T dwStackSize,
	_In_     LPFIBER_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter
	);

extern HMODULE hNtdll;
extern pNtClose NtClose;
extern pNtWriteVirtualMemory NtWriteVirtualMemory;
extern pNtProtectVirtualMemory NtProtectVirtualMemory;
extern pZwAllocateVirtualMemory ZwAllocateVirtualMemory;
extern pNtQueryVirtualMemory myNtQueryVirtualMemory;
extern pConvertThreadToFiber myConvertThreadToFiber;
extern pCreateFiber myCreateFiber;
extern pSwitchToFiber mySwitchToFiber;

void doSome();
HMODULE WINAPI R0myGetModuleHandle(LPCWSTR lpModuleName);
HMODULE WINAPI R3myGetModuleHandle(LPCWSTR lpModuleName);
FARPROC myGetProcAddr(HMODULE module, LPCSTR funcName);
HANDLE WINAPI myGetCurrentProcess(VOID);
HANDLE WINAPI myGetCurrentThread(VOID);
std::vector<unsigned char> loadShellcode();
