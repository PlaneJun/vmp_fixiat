#pragma once
#include"pch.h"
#include"process.h"
#include"pefile.h"
struct IatInfo
{
	uint64_t		addr;				//要修复的位置
	EDirection		direct;				//判断是1+5还是5+1
	ECommandType	origin_mnemonic;	//原始指令 call,mov,jmp
	x86_reg			api_reg;			//存放api地址的寄存器
	uint64_t		api_addr;			//api地址
	std::string		api_module;			//api模块名
	std::string		api_name;			//api函数名
	uint32_t		fix_offset;			//填充地址与修复地址的相对位置
};

class iat
{
private:
	uc_engine* m_uc;
	REGS m_regs;
	csh m_cshandle;
	mem::Process m_Process;
	std::unique_ptr<pe> m_pe;
	std::string m_targetModule;

	void write_regs(REGS regs);
	REGS read_regs();
public:
	iat(uint32_t pid, std::string module_name);
	~iat();
	std::vector<uint64_t> search_IAT(uint64_t code_begin, uint64_t code_size, uint64_t vmp0_begin, uint64_t vmp0_size);
	std::vector<IatInfo> process_IAT(std::vector<uint64_t> iats);
	bool fix_IAT(std::vector<IatInfo>& iatInfos);
	bool fix_Dump(uint32_t rva_oep, std::vector<IatInfo> iatList, std::string output);
};