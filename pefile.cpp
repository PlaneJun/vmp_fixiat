#include"pefile.h"
#include"utils.h"
#include"process.h"
pe::pe()
{

}

pe::pe(uint32_t pid)
{
	mem::Process process{ pid };

	uint16_t size = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32);
	std::vector<uint8_t> buf{};
	buf.resize(size);
	process.ReadMemory(process.GetBaseModule(), buf.data(), buf.size());

	PIMAGE_DOS_HEADER pdos = reinterpret_cast<PIMAGE_DOS_HEADER>(buf.data());
	PIMAGE_NT_HEADERS pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(buf.data() + pdos->e_lfanew);
	buf.clear();
	buf.resize(pNt->OptionalHeader.SizeOfImage);
	process.ReadMemory(process.GetBaseModule(), buf.data(), buf.size());

	loadPE(buf.data(), buf.size());
}

pe::pe(uint8_t* data, uint32_t size)
{
	loadPE(data, size);
}
pe::pe(uint32_t pid, std::string modulename)
{
	loadPE(pid, modulename);
}
pe::pe(const char* path)
{
	loadPE(path);
}

bool pe::loadPE(const char* path)
{
	FILE* f = fopen(path, "rb+");
	if (!f)
	{
		MessageBoxA(NULL, "open pe failed", "pjvmp", NULL);
		return false;
	}
	fseek(f, 0, SEEK_END);
	uint32_t size = ftell(f);
	fseek(f, 0, SEEK_SET);
	uint8_t* data = new uint8_t[size];
	fread(data, size, 1, f);
	fclose(f);
	loadPE(data, size);
	delete[] data;
	return true;
}
bool pe::loadPE(uint8_t* data, uint32_t size)
{
	m_data.resize(size);
	std::memcpy(&m_data[0], data, m_data.size());
	initPEStruct();
	return true;
}
bool pe::loadPE(uint32_t pid, std::string modulename)
{
	uint8_t* buf{};
	std::vector<mem::ModuleInformation> mis{};
	mem::Process process{ pid };
	process.EnumModulesInProcess(process.get_handler(), mis);
	for (auto m : mis)
	{
		std::string mn = m.module_path.substr(m.module_path.rfind("\\") + 1);
		if (mn == modulename)
		{
			buf = new uint8_t[m.module_size];
			process.ReadMemory((LPVOID)m.base_address, buf, m.module_size);
			loadPE(buf, m.module_size);
			delete[] buf;
			return true;
		}
	}
	return false;
}
bool pe::initPEStruct()
{
	m_MZHeader = (PIMAGE_DOS_HEADER)m_data.data();
	if (m_MZHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		m_data.clear();
		MessageBoxA(NULL, "load pe failed", "pjvmp", NULL);
		return false;
	}
	m_NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(m_data.data() + m_MZHeader->e_lfanew);
	m_FileHeader = &m_NtHeader->FileHeader;
	m_OptionalHeader = &m_NtHeader->OptionalHeader;
	m_SectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((uint8_t*)m_OptionalHeader + m_FileHeader->SizeOfOptionalHeader);
	m_importDirectory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(m_data.data() + m_OptionalHeader->DataDirectory[1].VirtualAddress);
	return true;
}
bool pe::_validate()
{
	if (m_data.size() <= 0)
		return false;

	if (m_MZHeader->e_magic == 0x5A4D && m_NtHeader->Signature == 0x4550)
		return true;
	return false;
}
PIMAGE_SECTION_HEADER pe::GetSectionHeader(std::string name)
{
	static IMAGE_SECTION_HEADER dummy{ .Name = ".dummy" };
	for (std::uint16_t n = 0; n < m_FileHeader->NumberOfSections; n++)
	{
		if (std::string((char*)m_SectionHeader[n].Name)._Equal(name))
		{
			return &m_SectionHeader[n];
		}
	}
	return &dummy;
}

PIMAGE_SECTION_HEADER pe::GetSectionHeader(uint32_t rva)
{
	static IMAGE_SECTION_HEADER dummy{ .Name = ".dummy" };
	for (std::uint16_t n = 0; n < m_FileHeader->NumberOfSections; n++)
	{
		if (m_SectionHeader[n].Misc.PhysicalAddress <= rva && rva < (m_SectionHeader[n].Misc.PhysicalAddress + m_SectionHeader[n].Misc.VirtualSize))
		{
			return &m_SectionHeader[n];
		}
	}
	return &dummy;
}

bool pe::AppendSection(std::string string, std::uint32_t size, std::uint32_t chrs, PIMAGE_SECTION_HEADER& newSec)
{
	PIMAGE_SECTION_HEADER p_image_section_header = m_SectionHeader;

	for (int i = 0; i < m_FileHeader->NumberOfSections; i++)
	{
		DWORD virtual_address = p_image_section_header->VirtualAddress;

		DWORD virtaul_size = p_image_section_header->Misc.VirtualSize;
		char* name = (char*)p_image_section_header->Name;
		//fix section file alignment offset and size
		p_image_section_header->PointerToRawData = p_image_section_header->VirtualAddress;
		p_image_section_header->SizeOfRawData = p_image_section_header->Misc.VirtualSize;

		p_image_section_header++;
	}

	//p_image_section_header=p_image_section_header + section_num ;
	//add section header
	strncpy((char*)p_image_section_header->Name, string.c_str(), string.length());
	p_image_section_header->Characteristics = chrs;
	p_image_section_header->PointerToRawData = m_OptionalHeader->SizeOfImage;
	p_image_section_header->SizeOfRawData = Align(size);
	p_image_section_header->VirtualAddress = m_OptionalHeader->SizeOfImage;
	p_image_section_header->Misc.VirtualSize = Align(size);
	m_FileHeader->NumberOfSections = m_FileHeader->NumberOfSections + 1;


	// Fill in some temp data
	std::vector<std::uint8_t> section_data(p_image_section_header->SizeOfRawData);
	std::fill(section_data.begin(), section_data.end(), 0);

	m_data.insert_data(p_image_section_header->PointerToRawData, section_data.data(), section_data.size());
	initPEStruct();

	if (newSec)
		newSec = &m_SectionHeader[m_FileHeader->NumberOfSections - 1];
	return true;
}

bool pe::WriteToFile(std::string filepath)
{
	FILE* f = fopen(filepath.c_str(), "wb+");
	if (!f)
		return false;
	fwrite((const char*)m_data.data(), m_data.size(), 1, f);
	fclose(f);
	return true;
}

void pe::AddModuleImport(uint64_t base, uint32_t rva_oep, std::map<std::string, std::map<std::string, std::vector<uint64_t>>> AddedImports)
{
	//计算导入表大小
	uint32_t thunk_count = 0;
	uint32_t dllName_count = 0;
	uint32_t funcName_count = 0; //IMAGE_IMPORT_BY_NAME总大小
	for (auto m : AddedImports)
	{
		for (auto f : m.second)
		{
			thunk_count = thunk_count + 1;
			funcName_count = funcName_count + f.first.size() + 3;
		}
		thunk_count = thunk_count + 1; //每个模块thunk的结尾处留空
		dllName_count = dllName_count + m.first.size() + 1;
	}

	uint32_t newSize = thunk_count * sizeof(IMAGE_THUNK_DATA64) + dllName_count + funcName_count;
	//添加新节区
	PIMAGE_SECTION_HEADER newSec{};
	if (newSec = GetSectionHeader(".pjvmp"); std::string((char*)newSec->Name)._Equal(".dummy"))
	{
		AppendSection(".pjvmp",
			newSize,
			IMAGE_SCN_MEM_READ |
			IMAGE_SCN_MEM_WRITE |
			IMAGE_SCN_MEM_EXECUTE, newSec);

		newSec->PointerToRelocations = 0;
		newSec->PointerToLinenumbers = 0;
		newSec->NumberOfRelocations = 0;
		newSec->PointerToLinenumbers = 0;

		memcpy(GetSectionHeader(".pjvmp"), newSec, sizeof(newSec));
	}
	// 重定向导入表RVA
	m_importDirectory = reinterpret_cast<decltype(m_importDirectory)>(&m_data.data()[newSec->VirtualAddress]);

	m_OptionalHeader->ImageBase = base;
	m_OptionalHeader->SizeOfImage = m_OptionalHeader->SizeOfImage + Align(newSize);
	m_OptionalHeader->AddressOfEntryPoint = rva_oep;
	m_OptionalHeader->FileAlignment = 0x1000;
	m_OptionalHeader->DllCharacteristics = m_OptionalHeader->DllCharacteristics & (~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	// 重定向目录项中导入表的RVA
	m_OptionalHeader->DataDirectory[1].VirtualAddress = newSec->VirtualAddress;
	m_OptionalHeader->DataDirectory[1].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * AddedImports.size() + sizeof(IMAGE_IMPORT_DESCRIPTOR);


	//计算descriptor的起始FOA
	PIMAGE_IMPORT_DESCRIPTOR offset_descriptor = (PIMAGE_IMPORT_DESCRIPTOR) & (buffer().data()[newSec->PointerToRawData]);
	//计算thunk的起始FOA
	PIMAGE_THUNK_DATA64 offset_thunk = (PIMAGE_THUNK_DATA64)(offset_descriptor + AddedImports.size() + 1); //+1是结尾的空描述符
	//计算存放dll名字的起始FOA
	char* offset_dllName = (char*)(offset_thunk + thunk_count);
	//计算存放BY_NAME的起始FOA
	PIMAGE_IMPORT_BY_NAME offset_imp = (PIMAGE_IMPORT_BY_NAME)(offset_dllName + dllName_count);
	for (auto m : AddedImports)
	{
		//设置描述符
		offset_descriptor->OriginalFirstThunk = 0;
		offset_descriptor->ForwarderChain = 0;
		offset_descriptor->TimeDateStamp = 0;
		offset_descriptor->Name = (uint32_t)((uint64_t)offset_dllName - (uint64_t)buffer().data());
		offset_descriptor->FirstThunk = (uint32_t)((uint64_t)offset_thunk - (uint64_t)buffer().data());
		offset_descriptor = offset_descriptor + 1;
		//写dll名
		strcpy(offset_dllName, m.first.c_str());
		offset_dllName = offset_dllName + m.first.size() + 1;
		//写thunk和by_name
		for (auto f : m.second)
		{
			offset_imp->Hint = 0;
			strcpy(offset_imp->Name, f.first.c_str());
			offset_thunk->u1.AddressOfData = ((uint64_t)offset_imp - (uint64_t)buffer().data());

			//修复api的引用
			for (auto r : f.second)
			{
				//x64是相对位移
				uint32_t tmp = ((uint64_t)offset_thunk - (uint64_t)buffer().data()) - r - 4;
				buffer().copy_data(r, &tmp, sizeof(uint32_t));
			}
			offset_thunk = offset_thunk + 1;
			offset_imp = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)offset_imp + f.first.size() + sizeof(WORD) + 1);
		}
		//结束thunk
		offset_thunk->u1.AddressOfData = 0;
		offset_thunk = offset_thunk + 1;
	}
	memset(offset_descriptor, 0, sizeof(decltype(*offset_descriptor)));
}