#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <map>
#pragma warning(disable : 4996)
#include "emu.h"
#pragma comment(lib, "./unicorn/unicorn.lib")
#pragma comment(lib, "./capstone/capstone_dll.lib")

SEG_MAP segs[] = {
	//base			size			file name
	{0xD11000,		0x2000,			"./dump/vmpfuck.vmp_00D11000.bin",				NULL},// .text
	{0xD13000,		0x1000,			"./dump/vmpfuck.vmp_00D13000.bin",				NULL},// .rdata
	{0xD14000,		0x1000,			"./dump/vmpfuck.vmp_00D14000.bin",				NULL},// .data
	{0xD15000,		0x316000,		"./dump/vmpfuck.vmp_00D15000.bin",				NULL},// .vmp0
	{0x102B000,		0x540000,		"./dump/vmpfuck.vmp_0102B000.bin",				NULL},// .vmp1
	{0x156B000,		0x1000,			"./dump/vmpfuck.vmp_0156B000.bin",				NULL},// .reloc
	{0x9FB000,		0x5000,			"./dump/vmpfuck.vmp_009FB000.bin",				NULL},// 堆栈
};


#define INIT_EAX			0x01D92A4E
#define INIT_EBX			0x00A3A000
#define INIT_ECX			0x009FFB24
#define INIT_EDX			0xAEC5853B
#define INIT_EBP			0x009FFB30
#define INIT_ESP			0x009FFB1C
#define INIT_ESI			0xFFFF0000
#define INIT_EDI			0xBB40E64E
#define INIT_EIP			0x00D118F4
#define INIT_EFL			0x00000344

uc_engine* uc;

REGS regs;

std::vector<DWORD> vec_iatList{};
std::map<DWORD, DWORD> map_fixIat{};

std::string to_string(const std::wstring& str, const std::locale& loc = std::locale())
{
	std::vector<char>buf(str.size());
	std::use_facet<std::ctype<wchar_t>>(loc).narrow(str.data(), str.data() + str.size(), '*', buf.data());
	return std::string(buf.data(), buf.size());
}



ULONG_PTR search_callIAT(ULONG_PTR addr,ULONG memSize)
{
	ULONG_PTR maxAddress = addr + memSize;
	int i = memSize;
	unsigned char c;
	BYTE code[32];
	csh handle;
	cs_insn* insn;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	while (i-- && addr < maxAddress) {
		uc_mem_read(uc, addr, &c, 1);
		if (c == 0xE8) {
			
			//读取5个字节,call指令大小
			uc_mem_read(uc, addr, code, 5);
			int ret = cs_disasm(handle, code, 5, addr, 1, &insn);
			if (ret<=0) {
				addr+=5; //跳5个字节
				continue;
			}

			cs_detail* detail = insn->detail;
			if (!detail->x86.op_count) {
				addr += insn->size;
				continue;
			}


			for (int n = 0; n < detail->x86.op_count; n++) {
				cs_x86_op* op = &(detail->x86.operands[n]);
				switch (op->type)
				{
				case X86_OP_IMM:
				{
					ULONG_PTR callAddr = op->imm;
					if (callAddr > segs[3].base &&
						callAddr < segs[3].base + segs[3].size) //是否在VMP0段
					{
						unsigned char nop=NULL;
						uc_mem_read(uc, callAddr,&nop,1);
						if (nop == 0x90)
							vec_iatList.push_back(insn->address);//添加
							
					}
				}
				default:
					break;
				}
			}
			addr += insn->size; //跳到下一条指令
		}
		addr++;
	}
}

void print_stack(DWORD esp)
{
	DWORD val;
	for (int i = 0; i < 10; i++)
	{
		uc_mem_read(uc, esp, &val, 4);
		printf("|%p|\n", val);
		esp += 4;
	}
}

void read_regs()
{
	uc_reg_read(uc, UC_X86_REG_EAX, &regs.regs.r_eax);
	uc_reg_read(uc, UC_X86_REG_ECX, &regs.regs.r_ecx);
	uc_reg_read(uc, UC_X86_REG_EDX, &regs.regs.r_edx);
	uc_reg_read(uc, UC_X86_REG_EBX, &regs.regs.r_ebx);
	uc_reg_read(uc, UC_X86_REG_ESP, &regs.regs.r_esp);
	uc_reg_read(uc, UC_X86_REG_EBP, &regs.regs.r_ebp);
	uc_reg_read(uc, UC_X86_REG_ESI, &regs.regs.r_esi);
	uc_reg_read(uc, UC_X86_REG_EDI, &regs.regs.r_edi);
	uc_reg_read(uc, UC_X86_REG_EIP, &regs.regs.r_eip);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &regs.regs.r_efl);
}

void write_regs() {
	uc_reg_write(uc, UC_X86_REG_EAX, &regs.regs.r_eax);
	uc_reg_write(uc, UC_X86_REG_ECX, &regs.regs.r_ecx);
	uc_reg_write(uc, UC_X86_REG_EDX, &regs.regs.r_edx);
	uc_reg_write(uc, UC_X86_REG_EBX, &regs.regs.r_ebx);
	uc_reg_write(uc, UC_X86_REG_ESP, &regs.regs.r_esp);
	uc_reg_write(uc, UC_X86_REG_EBP, &regs.regs.r_ebp);
	uc_reg_write(uc, UC_X86_REG_ESI, &regs.regs.r_esi);
	uc_reg_write(uc, UC_X86_REG_EDI, &regs.regs.r_edi);
	uc_reg_write(uc, UC_X86_REG_EIP, &regs.regs.r_eip);
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &regs.regs.r_efl);
}

void print_regs() {
	printf("eax = %p\n", regs.regs.r_eax);
	printf("ebx = %p\n", regs.regs.r_ebx);
	printf("ecx = %p\n", regs.regs.r_ecx);
	printf("edx = %p\n", regs.regs.r_edx);
	printf("ebp = %p\n", regs.regs.r_ebp);
	printf("esp = %p\n", regs.regs.r_esp);
	printf("esi = %p\n", regs.regs.r_esi);
	printf("edi = %p\n", regs.regs.r_edi);
	printf("eip = %p\n", regs.regs.r_eip);
	printf("efl = %p\n", regs.regs.r_efl);
}

int main(int argc, char** argv, char** envp)
{
	regs.regs.r_eax = INIT_EAX;
	regs.regs.r_ecx = INIT_ECX;
	regs.regs.r_edx = INIT_EDX;
	regs.regs.r_ebx = INIT_EBX;
	regs.regs.r_esp = INIT_ESP;
	regs.regs.r_ebp = INIT_EBP;
	regs.regs.r_esi = INIT_ESI;
	regs.regs.r_edi = INIT_EDI;
	regs.regs.r_eip = INIT_EIP;
	regs.regs.r_efl = INIT_EFL;

	uc_err err;
	csh handle;
	cs_insn* insn=NULL;

	printf("Emulate i386 code\n");

	// Initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}

	for (int i = 0; i < sizeof(segs) / sizeof(SEG_MAP); i++) {
		segs[i].buf = (unsigned char*)malloc(segs[i].size);
		FILE* fp = fopen(segs[i].file_name, "rb");
		fread(segs[i].buf, segs[i].size, 1, fp);
		fclose(fp);
		// map memory for this emulation
		err = uc_mem_map(uc, segs[i].base, segs[i].size, UC_PROT_ALL);
		// write machine code to be emulated to memory
		err = uc_mem_write(uc, segs[i].base, segs[i].buf, segs[i].size);
		free(segs[i].buf);
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	write_regs();
	init_gdt(uc);

	//搜索IAT调用位置
	search_callIAT(segs[0].base,  segs[0].size);

	BYTE code[32];
	int count = 0;

	std::string apiname;
	std::wstring moduelpath;
	
	for (auto addr : vec_iatList)
	{
		regs.regs.r_eip = addr; //设置开始模拟的eip
		write_regs();
		while (1)
		{
			uc_mem_read(uc, regs.regs.r_eip, code, 32);
			cs_disasm(handle, code, 32, regs.regs.r_eip, 1, &insn);
			//开始模拟
			err = uc_emu_start(uc, regs.regs.r_eip, 0xffffffff, 0, 1); //模拟到执行API时会抛出异常
			if (err) {
				if (!strcmp(insn->mnemonic, "ret"))
				{
					DWORD curtEsp = regs.regs.r_esp;
					DWORD apiAddr = NULL;

					//读取返回地址,即API地址
					uc_mem_read(uc, curtEsp, &apiAddr, sizeof(DWORD));

					std::string apiName{};
					std::wstring apiModuleNamae{};
					if(GetFuncName(GetCurrentProcess(), apiAddr, apiName, apiModuleNamae))
					{
						map_fixIat[addr] = apiAddr;
						std::cout << "[+]find iat:0x" << std::hex << addr << "->"<< apiAddr <<"\t//" << apiName << std::endl;
					}

					//直接让模拟器返回，不调用函数
					uc_mem_read(uc,(regs.regs.r_esp+4), &curtEsp, sizeof(DWORD));
					regs.regs.r_eip = curtEsp;//设置为返回到地址

					//计算ret xx,修复堆栈平衡
					int detal = 8;
					if (insn->detail->x86.op_count > 0)
						detal = 8 + insn->detail->x86.operands[0].imm;
					else
						detal = 8;
					regs.regs.r_esp -= detal;
					break;
				}
			}
			read_regs();
			cs_free(insn, 1);
		}
	}
	cs_close(&handle);
	uc_close(uc);



	

	system("pause");
	return 0;
}