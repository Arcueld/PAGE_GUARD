#include "checkVM.h"
#include "helper.h"

BOOL query_license_value()
{
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)(myGetProcAddr(R0myGetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString"));
	pZwQueryLicenseValue NtQueryLicenseValue = (pZwQueryLicenseValue)(myGetProcAddr(R0myGetModuleHandle(L"ntdll.dll"), "ZwQueryLicenseValue"));

	if (RtlInitUnicodeString == nullptr || NtQueryLicenseValue == nullptr)
		return FALSE;

	UNICODE_STRING LicenseValue;
	RtlInitUnicodeString(&LicenseValue, L"Kernel-VMDetection-Private");

	ULONG Result = 0, ReturnLength;

	NTSTATUS Status = NtQueryLicenseValue(&LicenseValue, NULL, reinterpret_cast<PVOID>(&Result), sizeof(ULONG), &ReturnLength);

	if (NT_SUCCESS(Status)) {
		return !Result;
	}

	return FALSE;
}