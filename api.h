#pragma once
#include"pch.h"

#define		UE_ACCESS_READ 0
#define		UE_ACCESS_WRITE 1
#define		UE_ACCESS_ALL 2

class api
{
private:
	static	ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, ULONG_PTR APIAddress);
	static	bool MapFileExW(wchar_t* szFileName, DWORD ReadOrWrite, LPHANDLE FileHandle, LPDWORD FileSize, LPHANDLE FileMap, LPVOID FileMapVA, DWORD SizeModifier);
	static	void UnMapFileEx(HANDLE FileHandle, DWORD FileSize, HANDLE FileMap, ULONG_PTR FileMapVA);
	static	bool EngineValidateHeader(ULONG_PTR FileMapVA, HANDLE hFileProc, LPVOID ImageBase, PIMAGE_DOS_HEADER DOSHeader, bool IsFile);
	static	ULONG_PTR ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
public:
	static	bool GetFuncName(HANDLE hProc, ULONG_PTR APIAddress, std::string& apiname, std::wstring& modulepath);
};


