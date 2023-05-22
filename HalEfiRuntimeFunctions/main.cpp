#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include "structs.h"

VOID DriverUnload(struct _DRIVER_OBJECT* DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+ ]Out!\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath) {
    DriverObject->DriverUnload = DriverUnload;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Entry!\n");
   
    auto ntoskrnl = util::GetModuleBase(0);
    if (!ntoskrnl) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Could not find ntoskrnl!\n");
        return STATUS_UNSUCCESSFUL;
    }


/*00000001404C1E1C               push    rbx
00000001404C1E1E                 sub     rsp, 30h
00000001404C1E22                 mov     rax, cs:HalEfiRuntimeServicesTable
00000001404C1E29                 mov     r10, r8
00000001404C1E2C                 mov     r11, rdx
00000001404C1E2F                 mov     rbx, rcx
00000001404C1E32                 test    rax, rax
00000001404C1E35                 jz      short loc_1404C1E94
00000001404C1E37                 cmp     qword ptr [rax+18h], 0
00000001404C1E3C                 jz      short loc_1404C1E94
00000001404C1E3E                 lock inc cs:HalpEfiVariableCalls
00000001404C1E45                 mov     ecx, 8
00000001404C1E4A                 call    HalpEfiStartRuntimeCode
00000001404C1E4F                 mov     rax, cs:HalEfiRuntimeServicesTable
00000001404C1E56                 mov     r8, r10
00000001404C1E59                 mov     rcx, [rsp+38h+arg_20]
00000001404C1E5E                 mov     rdx, r11
00000001404C1E61                 mov     [rsp+38h+var_18], rcx
00000001404C1E66                 mov     rcx, rbx
00000001404C1E69                 mov     rax, [rax+18h]
00000001404C1E6D                 call    rax
00000001404C1E6F                 nop     dword ptr [rax]
*/
    //Found at 00000001404C1E1E HalEfiGetEnvironmentVariable
    auto runtimetable = (unsigned long long)util::FindPattern(ntoskrnl, "\x48\x83\xEC\x30\x48\x8B\x05\x00\x00\x00\x00\x4D\x8B\xD0", "xxxxxxx????xxx");
    if (!runtimetable) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Could not find HalEfiRuntimeServicesTable!\n");
        return STATUS_UNSUCCESSFUL;
    }

    runtimetable = runtimetable + 0x04;
    runtimetable = (unsigned long long)util::ResolveRelativeAddress((PVOID)runtimetable, 3, 7);
    runtimetable = *(unsigned long long*)runtimetable;

    unsigned long long runtimefuncs[9];

    for (int i = 0; i < 9; i++) {
        MM_COPY_ADDRESS address;
        address.VirtualAddress = (PVOID)(runtimetable + (i * 8)); //HalEfiRuntimeServicesTable == __int64 HalEfiRuntimeServicesTable[9]
        SIZE_T read;
        if (!NT_SUCCESS(MmCopyMemory(&runtimefuncs[i], address, 8, MM_COPY_MEMORY_VIRTUAL, &read))){
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Could not copy the runtime func!\n");
            return STATUS_UNSUCCESSFUL;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Addr %d: 0x%p \n", i, runtimefuncs[i]);

    }

    //Here the magic will happen soon...

    return STATUS_SUCCESS;

}



//Could only find 9 runtime funcs that is used by ntoskrnl/windows after ExitBootTime/uefi. Even if it is more.
/*__int64 __fastcall HalEfiQueryVariableInfo(unsigned int a1)
{
  __int64 v2; // r10
  __int64 v3; // r11
  __int64 v4; // rax

  if ( !HalEfiRuntimeServicesTable || !HalEfiRuntimeServicesTable[8] )
    return 3221225474i64;
  HalpEfiStartRuntimeCode(256i64);
  v4 = ((__int64 (__fastcall *)(_QWORD, __int64, __int64))HalEfiRuntimeServicesTable[8])(a1, v3, v2);
  _InterlockedAnd((volatile signed __int32 *)KeGetPcr()->NtTib.SubSystemTib + 56, 0xFFFFFEFF);
  return HalpConvertEfiToNtStatus(v4);
}*/
//HalpConvertEfiToNtStatus is patch guard protected btw
//The addresses in the HalEfiRuntimeServicesTable should not be.