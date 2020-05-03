#pragma once
PBYTE ReadFileHelper(LPCWSTR lpwName, LPDWORD dwFileSize_out);
bool WriteFileHelper(LPCWSTR lpwName, PBYTE lpStubData, DWORD dwFileSize_in);

