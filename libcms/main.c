#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>
#include "libcms.h"

VOID
NTAPI
DriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
)
{

}

NTSTATUS
NTAPI
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status;
    UNICODE_STRING ImagePath;

    DriverObject->DriverUnload = DriverUnload;

    Status = CmsTestVerifyPkcs7Data();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CmsTestVerifyPkcs7Data = %08X\n", Status);

    Status = STATUS_UNSUCCESSFUL;

    return Status;
}
