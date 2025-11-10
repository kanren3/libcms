#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>

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

    DriverObject->DriverUnload = DriverUnload;

    Status = STATUS_UNSUCCESSFUL;

    return Status;
}
