#include "Process.h"
#include"utils.h"

mem::Process::Process()
{
	EnableDebugPriv();
}

mem::Process::Process(DWORD pid)
{
	EnableDebugPriv();
	Pid = pid;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
}

mem::Process::~Process()
{
	CloseHandle(hProcess);
}

void mem::Process::Attach(uint32_t pid)
{
	if (hProcess)
		CloseHandle(hProcess);
	Pid = pid;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
}

std::string mem::Process::GetProcessName()
{
	char name[1024]{};
	GetModuleFileNameExA(hProcess, NULL, name, sizeof(name));
	std::string ret(name);
	return ret.substr(ret.rfind("\\") + 1);
}
std::vector<DWORD> mem::Process::GetProcessIdByName(std::string name)
{
	std::vector<DWORD> found;
	auto hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hProcSnap)
		return found;

	PROCESSENTRY32 tEntry = { 0 };
	tEntry.dwSize = sizeof(PROCESSENTRY32W);

	// Iterate threads
	for (BOOL success = Process32First(hProcSnap, &tEntry);
		success != FALSE;
		success = Process32Next(hProcSnap, &tEntry))
	{
		if (name.empty() || utils::to_string(tEntry.szExeFile) == name.c_str())
			found.emplace_back(tEntry.th32ProcessID);
	}

	return found;
}
void mem::Process::EnableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		return;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		CloseHandle(hToken);
	}
}
HANDLE mem::Process::GetBaseModule()
{
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid); //  获取进程快照中包含在th32ProcessID中指定的进程的所有的模块。
	if (!handle)
	{
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry))
	{
		CloseHandle(handle);
		return NULL;
	}

	CloseHandle(handle);
	return moduleEntry.hModule;
}
bool mem::Process::ReadMemory(PVOID address, PVOID buffer, size_t size)
{
	SIZE_T ret_size;
	return ReadProcessMemory(hProcess, address, buffer, size, &ret_size);
}
bool mem::Process::WriteMemory(PVOID address, PVOID buffer, size_t size)
{
	SIZE_T ret_size;
	return WriteProcessMemory(hProcess, address, buffer, size, &ret_size);
}
HANDLE mem::Process::GetProcessModuleHandle(std::string ModuleName)
{
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid); //  获取进程快照中包含在th32ProcessID中指定的进程的所有的模块。
	if (!handle)
	{
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry))
	{
		CloseHandle(handle);
		return NULL;
	}
	do
	{
		if (utils::to_string(moduleEntry.szModule) == ModuleName)
		{
			return moduleEntry.hModule;
		}
	} while (Module32Next(handle, &moduleEntry));
	CloseHandle(handle);
	return 0;
}
uint32_t mem::Process::AllocMem(uint32_t size, uint32_t attr)
{
	return (uint32_t)VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, attr);
}
std::string mem::Process::GetProcessNameByPid(uint32_t pid)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 创建进程快照
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return "";

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32))
	{ // 遍历进程快照
		do
		{
			if (pe32.th32ProcessID == pid)
			{
				// 如果找到pid对应的进程
				CloseHandle(hSnapshot);
				return utils::to_string(pe32.szExeFile);
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	CloseHandle(hSnapshot);
	return "";
}
bool mem::Process::EnumModulesInProcess(HANDLE hProc, std::vector<ModuleInformation>& modules)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProc, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				MODULEINFO info{};
				GetModuleInformation(hProc, hMods[i], &info, sizeof info);

				modules.emplace_back(utils::to_string(szModName), (std::uint64_t)hMods[i], info.SizeOfImage);
			}
		}
	}

	return modules.size() > 0;
}

uint32_t mem::Process::QueryMemAttr(PVOID addr)
{
	// 获取指定地址所在页面的内存信息
	MEMORY_BASIC_INFORMATION memInfo;
	if (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == 0)
		return 0;
	return memInfo.Protect;
}