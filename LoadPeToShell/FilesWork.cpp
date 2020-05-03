#include <Windows.h>
#include <iostream>
#include <lm.h>
#include <stdio.h>
#include <stdint.h>

PBYTE ReadFileHelper(LPCWSTR lpwName, LPDWORD dwFileSize_out)
{
	HANDLE hFile;
	if ((hFile = CreateFile(lpwName, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return NULL;
	DWORD dwStubSize;
	if ((dwStubSize = GetFileSize(hFile, 0)) == INVALID_FILE_SIZE)
		return NULL;
	if (dwFileSize_out)
		*dwFileSize_out = dwStubSize;
	LPVOID lpStubData;
	if (!(lpStubData = VirtualAlloc(NULL, dwStubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
		return NULL;
	DWORD VeryUsefulDword;
	if (!ReadFile(hFile, lpStubData, dwStubSize, &VeryUsefulDword, NULL))
		return NULL;
	CloseHandle(hFile);
	return (PBYTE)lpStubData;
}

bool WriteFileHelper(LPCWSTR lpwName, PBYTE lpStubData, DWORD dwFileSize_in)
{
	HANDLE hFile;
	if ((hFile = CreateFile(lpwName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return false;
	DWORD VeryUsefulDword;
	if (!WriteFile(hFile, lpStubData, dwFileSize_in, &VeryUsefulDword, NULL))
		return false;
	CloseHandle(hFile);
	return true;
}
