#pragma once
#include"pch.h"
#include"bytes.hpp"

class pe
{
private:
	ByteVector	                m_data;
	PIMAGE_DOS_HEADER			m_MZHeader;
	PIMAGE_NT_HEADERS           m_NtHeader;
	PIMAGE_FILE_HEADER			m_FileHeader;
	PIMAGE_OPTIONAL_HEADER		m_OptionalHeader;
	PIMAGE_IMPORT_DESCRIPTOR	m_importDirectory;
	PIMAGE_EXPORT_DIRECTORY	m_exportDirectory;
	PIMAGE_SECTION_HEADER		m_SectionHeader;

	bool initPEStruct();
public:

	pe();
	pe(uint32_t pid);
	pe(uint32_t pid, std::string modulename);
	pe(const char* path);
	pe(uint8_t* data, uint32_t size);
	bool loadPE(const char* path);
	bool loadPE(uint8_t* data, uint32_t size);
	bool loadPE(uint32_t pid, std::string modulename);
	uint32_t Align(uint32_t size)
	{
		return (size & 0xfffff000) + 0x1000;
	}

	void AddModuleImport(uint64_t base, uint32_t rva_oep, std::map<std::string, std::map<std::string, std::vector<uint64_t>>> AddedImports);
	bool AppendSection(std::string section_name, std::uint32_t size, std::uint32_t chrs, PIMAGE_SECTION_HEADER& newSec);
	PIMAGE_SECTION_HEADER GetSectionHeader(std::string name);
	PIMAGE_SECTION_HEADER GetSectionHeader(uint32_t rva);
	bool WriteToFile(std::string filepath);

	bool _validate();

	ByteVector& buffer()
	{
		return m_data;
	}


	decltype(m_MZHeader) GetMzHeader() { return m_MZHeader; }
	decltype(m_NtHeader) GetNtHeader() { return m_NtHeader; }
	decltype(m_FileHeader) GetFileHeader() { return m_FileHeader; }
	decltype(m_OptionalHeader) GetOptionalHeader() { return m_OptionalHeader; }
	decltype(m_SectionHeader) GetSectionHeader() { return m_SectionHeader; }
};