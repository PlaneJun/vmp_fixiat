#pragma once
#include"pch.h"

namespace mem
{
	struct ModuleInformation
	{
		std::string module_path;
		uint64_t base_address;
		uint32_t module_size;
	};

	class Process
	{
	private:
		HANDLE hProcess;
		DWORD Pid;
	public:
		Process();
		Process(DWORD pid);
		~Process();
		template<class T> T Read(PVOID address)
		{
			T buffer{};
			ReadProcessMemory(hProcess, address, &buffer, sizeof(T), 0);
			return buffer;
		}
		template<class T> T Read(ULONG64 address)
		{

			return Read<T>((PVOID)address);
		}
		template <class T> static bool Write(PVOID address, T buffer)
		{
			SIZE_T ret_size;
			return WriteProcessMemory(hProcess, address, &buffer, sizeof(T), &ret_size);
		}
		void				Attach(uint32_t pid);
		void				EnableDebugPriv();
		std::string			GetProcessName();
		std::string			GetProcessNameByPid(uint32_t pid);
		bool				ReadMemory(PVOID address, PVOID buffer, size_t size);
		bool				WriteMemory(PVOID address, PVOID buffer, size_t size);
		HANDLE				GetProcessModuleHandle(std::string ModuleName);
		HANDLE				GetBaseModule();
		uint32_t			AllocMem(uint32_t size, uint32_t attr);
		std::vector<DWORD>	GetProcessIdByName(std::string ProcessName);
		bool				EnumModulesInProcess(HANDLE hProc, std::vector<ModuleInformation>& modules);
		uint32_t			QueryMemAttr(PVOID addr);

		HANDLE				get_handler() const { return hProcess; }
		uint32_t			get_pid() const { return Pid; }
	};

}


