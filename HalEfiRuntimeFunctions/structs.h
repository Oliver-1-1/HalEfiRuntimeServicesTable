#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemInformationClassMin = 0,
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemNotImplemented1 = 4,
	SystemProcessInformation = 5,
	SystemProcessesAndThreadsInformation = 5,
	SystemCallCountInfoInformation = 6,
	SystemCallCounts = 6,
	SystemDeviceInformation = 7,
	SystemConfigurationInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemProcessorTimes = 8,
	SystemFlagsInformation = 9,
	SystemGlobalFlag = 9,
	SystemCallTimeInformation = 10,
	SystemNotImplemented2 = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemLockInformation = 12,
	SystemStackTraceInformation = 13,
	SystemNotImplemented3 = 13,
	SystemPagedPoolInformation = 14,
	SystemNotImplemented4 = 14,
	SystemNonPagedPoolInformation = 15,
	SystemNotImplemented5 = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemPagefileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemInstructionEmulationCounts = 19,
	SystemVdmBopInformation = 20,
	SystemInvalidInfoClass1 = 20,
	SystemFileCacheInformation = 21,
	SystemCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemProcessorStatistics = 23,
	SystemDpcBehaviourInformation = 24,
	SystemDpcInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemNotImplemented6 = 25,
	SystemLoadImage = 26,
	SystemUnloadImage = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemTimeAdjustment = 28,
	SystemSummaryMemoryInformation = 29,
	SystemNotImplemented7 = 29,
	SystemNextEventIdInformation = 30,
	SystemNotImplemented8 = 30,
	SystemEventIdsInformation = 31,
	SystemNotImplemented9 = 31,
	SystemCrashDumpInformation = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLoadAndCallImage = 38,
	SystemPrioritySeparation = 39,
	SystemPlugPlayBusInformation = 40,
	SystemNotImplemented10 = 40,
	SystemDockInformation = 41,
	SystemNotImplemented11 = 41,
	SystemInvalidInfoClass2 = 42,
	SystemProcessorSpeedInformation = 43,
	SystemInvalidInfoClass3 = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemSetTimeSlipEvent = 46,
	SystemCreateSession = 47,
	SystemDeleteSession = 48,
	SystemInvalidInfoClass4 = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemAddVerifier = 52,
	SystemSessionProcessesInformation = 53,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];

} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


extern "C" NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

//This will trigger patch-guard D:

namespace util {
	PVOID GetModuleBase(LPCSTR moduleName) {
		PVOID moduleBase = NULL;
		ULONG info = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);

		if (!info) {
			return moduleBase;
		}

		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, info, 'HELL');
		status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);
		if (!NT_SUCCESS(status)) {
			return moduleBase;
		}
		PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
		if (modules->NumberOfModules > 0) {
			if (!moduleName) {
				moduleBase = modules->Modules[0].ImageBase;
			}
			else {
				for (auto i = 0; i < modules->NumberOfModules; i++) {
					if (!strcmp((CHAR*)module[i].FullPathName, moduleName)) {
						moduleBase = module[i].ImageBase;
					}
				}
			}
		}

		if (modules) {
			ExFreePoolWithTag(modules, 'HELL');
		}

		return moduleBase;
	}
	PIMAGE_NT_HEADERS GetHeader(PVOID module) {
		return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
	}

	PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {
		auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
		{
			for (auto x = buffer; *mask; pattern++, mask++, x++) {
				auto addr = *(BYTE*)(pattern);
				if (addr != *x && *mask != '?')
					return FALSE;
			}

			return TRUE;
		};

		for (auto x = 0; x < size - strlen(mask); x++) {

			auto addr = (PBYTE)module + x;
			if (checkMask(addr, pattern, mask))
				return addr;
		}

		return NULL;
	}

	PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask) {
		auto header = GetHeader(base);
		auto section = IMAGE_FIRST_SECTION(header);
		for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {
			if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4)) {
				auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (addr) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Found in Section -> [ %s ]", section->Name);
					return addr;
				}
			}
		}

		return NULL;
	}

	PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, LONG InstructionSize){
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
		PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
		return ResolvedAddr;
	}
}