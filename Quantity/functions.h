#pragma once
#pragma warning(disable : 4996)
#include "includes.h"


using namespace std;

namespace Functions
{


	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Load Library
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	bool DoesFileExist(const char* name) {
		if (FILE* file = fopen(name, "r")) {
			fclose(file);
			return true;
		}

		return false;
	}


	DWORD FindProcessId(string processName)
	{
		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);

		HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processSnapshot == INVALID_HANDLE_VALUE)
			return 0;

		Process32First(processSnapshot, &processInfo);
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}

		while (Process32Next(processSnapshot, &processInfo))
		{
			if (!processName.compare(processInfo.szExeFile))
			{
				CloseHandle(processSnapshot);
				return processInfo.th32ProcessID;
			}
		}

		CloseHandle(processSnapshot);
		return 0;
	}

	uintptr_t GetModuleBaseAddress(DWORD pid, const char* modName) {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (hSnap != INVALID_HANDLE_VALUE) {
			MODULEENTRY32 modEntry;
			modEntry.dwSize = sizeof(modEntry);
			if (Module32First(hSnap, &modEntry)) {
				do {
					if (!strcmp(modEntry.szModule, modName)) {
						CloseHandle(hSnap);
						return (uintptr_t)modEntry.modBaseAddr;
					}
				} while (Module32Next(hSnap, &modEntry));
			}
		}
	}



	bool LoadLibraryInject(DWORD ProcessId, const char* Dll)
	{
		if (ProcessId == NULL)
			return false;

		char CustomDLL[MAX_PATH];
		GetFullPathName(Dll, MAX_PATH, CustomDLL, 0);

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
		LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(CustomDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (!WriteProcessMemory(hProcess, allocatedMem, CustomDLL, sizeof(CustomDLL), NULL))
			return FALSE;

		CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);

		if (hProcess)
			CloseHandle(hProcess);

		return TRUE;
	}




	namespace Internal
	{
		LPVOID NTOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");

		bool ExecuteBypass(HANDLE hProcess)
		{
			if (NTOpenFile) {
				char originalBytes[5];
				memcpy(originalBytes, NTOpenFile, 5);
				if (WriteProcessMemory(hProcess, NTOpenFile, originalBytes, 5, NULL)) {
					return TRUE;
				}

			}

			return FALSE;

		}

		bool Backup(HANDLE hProcess)
		{
			if (NTOpenFile) {
				char Orig[5];
				memcpy(Orig, NTOpenFile, 5);
				WriteProcessMemory(hProcess, NTOpenFile, Orig, 0, 0);
				return TRUE;
			}

			return FALSE;
		}

	}


	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// manual map
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
	typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

	typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);


	struct loaderdata
	{
		LPVOID ImageBase;

		PIMAGE_NT_HEADERS NtHeaders;
		PIMAGE_BASE_RELOCATION BaseReloc;
		PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

		pLoadLibraryA fnLoadLibraryA;
		pGetProcAddress fnGetProcAddress;

	};
	

	DWORD __stdcall LibraryLoader(LPVOID Memory)
	{

		loaderdata* LoaderParams = (loaderdata*)Memory;

		PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

		DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); 

		while (pIBR->VirtualAddress)
		{
			if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				PWORD list = (PWORD)(pIBR + 1);

				for (int i = 0; i < count; i++)
				{
					if (list[i])
					{
						PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
						*ptr += delta;
					}
				}
			}

			pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
		}

		PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;


		while (pIID->Characteristics)
		{
			PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
			PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

			HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

			if (!hModule)
				return FALSE;

			while (OrigFirstThunk->u1.AddressOfData)
			{
				if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{

					DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
						(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

					if (!Function)
						return FALSE;

					FirstThunk->u1.Function = Function;
				}
				else
				{

					PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
					DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
					if (!Function)
						return FALSE;

					FirstThunk->u1.Function = Function;
				}
				OrigFirstThunk++;
				FirstThunk++;
			}
			pIID++;
		}

		if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
		{
			dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

			return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); 
		}
		return TRUE;
	}


	DWORD __stdcall stub()
	{
		return 0;
	}


	int ManualMap(string dll, DWORD ProcessId)
	{


		LPCSTR Dll = dll.c_str();

		//DWORD ProcessId = FindProcessId("csgo.exe");

		loaderdata LoaderParams;

		HANDLE hFile = CreateFileA(Dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);

		DWORD FileSize = GetFileSize(hFile, NULL);
		PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;

		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);


		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

		PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		WriteProcessMemory(hProcess, ExecutableImage, FileBuffer,
			pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

		PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);

		for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
		{
			WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
				(PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
		}


		PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		LoaderParams.ImageBase = ExecutableImage;
		LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);

		LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
			+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
			+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		LoaderParams.fnLoadLibraryA = LoadLibraryA;
		LoaderParams.fnGetProcAddress = GetProcAddress;


		WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata),
			NULL);


		WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader,
			(DWORD)stub - (DWORD)LibraryLoader, NULL);


		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1),
			LoaderMemory, 0, NULL);



		WaitForSingleObject(hThread, INFINITE);

		std::cin.get();

		VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);

		return 0;
	}







}







