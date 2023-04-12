#include"api.h"
#include"utils.h"

#include"iat.h"


#define STACK_ADDR 0x0
#define STACK_SIZE  1024*1024


iat::iat(uint32_t pid, std::string module_name)
{
	m_Process.Attach(pid);
	m_targetModule = module_name;

	//初始化unicorn
	uc_err uc_err = uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
	if (uc_err != UC_ERR_OK)
	{
		MessageBoxA(NULL, ("Failed on uc_open() with error returned: " + std::to_string(uc_err)).c_str(), "pjvmp", NULL);
		return;
	}
	//初始化capstone
	cs_err cs_err = cs_open(CS_ARCH_X86, CS_MODE_64, &m_cshandle);
	if (cs_err != CS_ERR_OK)
	{
		MessageBoxA(NULL, ("Failed on cs_open() with error returned: " + std::to_string(cs_err)).c_str(), "pjvmp", NULL);
		uc_close(m_uc);
		return;
	}
	cs_option(m_cshandle, CS_OPT_DETAIL, CS_OPT_ON);

	m_pe.reset(new pe(pid, module_name));
	if (!m_pe->_validate())
	{
		MessageBoxA(NULL, "invaild pe file", "pjvmp", NULL);
		uc_close(m_uc);
		cs_close(&m_cshandle);
	}

	//映射程序区段到unicorn
	auto pSection = m_pe->GetSectionHeader();
	for (int i = 0; i < m_pe->GetFileHeader()->NumberOfSections; i++)
	{

		auto vAddr = m_pe->GetOptionalHeader()->ImageBase + pSection->VirtualAddress;
		auto vSize = m_pe->Align(pSection->Misc.VirtualSize);

		uint8_t* buf = new uint8_t[vSize];
		m_Process.ReadMemory((LPVOID)vAddr, buf, vSize);
		// map memory for this emulation
		uc_mem_map(m_uc, vAddr, vSize, UC_PROT_ALL);
		// write machine code to be emulated to memory
		uc_mem_write(m_uc, vAddr, buf, vSize);
		delete[] buf;
		pSection++;
	}
}
iat::~iat()
{
	uc_close(m_uc);
	cs_close(&m_cshandle);
}
std::vector<uint64_t> iat::search_IAT(uint64_t code_begin, uint64_t code_size, uint64_t vmp0_begin, uint64_t vmp0_size)
{
	std::vector<uint64_t> IatList{};
	cs_insn* insn{};
	uint64_t max_addr = code_begin + code_size;
	int i = code_size;
	while (i-- && code_begin <= max_addr)
	{
		uint8_t c{};
		m_Process.ReadMemory((LPVOID)code_begin, &c, 1);
		if (c == 0xE8)
		{
			//读取5个字节,call指令大小
			BYTE code[32];
			m_Process.ReadMemory((LPVOID)code_begin, code, 5);
			int ret = cs_disasm(m_cshandle, code, 5, code_begin, 1, &insn);
			if (ret <= 0)
			{
				code_begin += 1; //非法指令指令直接跳走
				cs_free(insn, ret);
				continue;
			}

			if (!strcmp(insn->mnemonic, "call") && insn->detail->x86.operands[0].type == X86_OP_IMM)
			{
				ULONG_PTR callAddr = insn->detail->x86.operands[0].imm;
				if (callAddr > vmp0_begin &&
					callAddr < vmp0_begin + vmp0_size) //是否在VMP0段
				{
					unsigned char nop = NULL;
					m_Process.ReadMemory((LPVOID)callAddr, &nop, 1);
					if (nop == 0x90)
					{
						IatList.push_back(insn->address);//添加
					}
				}
			}
			code_begin += insn->size; //跳到下一条指令
			cs_free(insn, ret);
		}
		else
		{
			code_begin++;
		}
	}
	return IatList;
}

void iat::write_regs(REGS regs)
{
	uc_reg_write(m_uc, UC_X86_REG_RSP, &regs.regs.r_rsp);
	uc_reg_write(m_uc, UC_X86_REG_RAX, &regs.regs.r_rax);
	uc_reg_write(m_uc, UC_X86_REG_RBX, &regs.regs.r_rbx);
	uc_reg_write(m_uc, UC_X86_REG_RCX, &regs.regs.r_rcx);
	uc_reg_write(m_uc, UC_X86_REG_RDX, &regs.regs.r_rdx);
	uc_reg_write(m_uc, UC_X86_REG_RBP, &regs.regs.r_rbp);
	uc_reg_write(m_uc, UC_X86_REG_RSI, &regs.regs.r_rsi);
	uc_reg_write(m_uc, UC_X86_REG_RDI, &regs.regs.r_rdi);

	uc_reg_write(m_uc, UC_X86_REG_R8, &regs.regs.r_r8);
	uc_reg_write(m_uc, UC_X86_REG_R9, &regs.regs.r_r9);
	uc_reg_write(m_uc, UC_X86_REG_R10, &regs.regs.r_r10);
	uc_reg_write(m_uc, UC_X86_REG_R11, &regs.regs.r_r11);
	uc_reg_write(m_uc, UC_X86_REG_R12, &regs.regs.r_r12);
	uc_reg_write(m_uc, UC_X86_REG_R13, &regs.regs.r_r13);
	uc_reg_write(m_uc, UC_X86_REG_R14, &regs.regs.r_r14);
	uc_reg_write(m_uc, UC_X86_REG_R15, &regs.regs.r_r15);

	uc_reg_write(m_uc, UC_X86_REG_RIP, &regs.regs.r_rip);
	uc_reg_write(m_uc, UC_X86_REG_EFLAGS, &regs.regs.r_rfl);
}
REGS iat::read_regs()
{
	REGS regs{};
	uc_reg_read(m_uc, UC_X86_REG_RAX, &regs.regs.r_rax);
	uc_reg_read(m_uc, UC_X86_REG_RCX, &regs.regs.r_rcx);
	uc_reg_read(m_uc, UC_X86_REG_RDX, &regs.regs.r_rdx);
	uc_reg_read(m_uc, UC_X86_REG_RBX, &regs.regs.r_rbx);
	uc_reg_read(m_uc, UC_X86_REG_RSP, &regs.regs.r_rsp);
	uc_reg_read(m_uc, UC_X86_REG_RBP, &regs.regs.r_rbp);
	uc_reg_read(m_uc, UC_X86_REG_RSI, &regs.regs.r_rsi);
	uc_reg_read(m_uc, UC_X86_REG_RDI, &regs.regs.r_rdi);

	uc_reg_read(m_uc, UC_X86_REG_R8, &regs.regs.r_r8);
	uc_reg_read(m_uc, UC_X86_REG_R9, &regs.regs.r_r9);
	uc_reg_read(m_uc, UC_X86_REG_R10, &regs.regs.r_r10);
	uc_reg_read(m_uc, UC_X86_REG_R11, &regs.regs.r_r11);
	uc_reg_read(m_uc, UC_X86_REG_R12, &regs.regs.r_r12);
	uc_reg_read(m_uc, UC_X86_REG_R13, &regs.regs.r_r13);
	uc_reg_read(m_uc, UC_X86_REG_R14, &regs.regs.r_r14);
	uc_reg_read(m_uc, UC_X86_REG_R15, &regs.regs.r_r15);

	uc_reg_read(m_uc, UC_X86_REG_RIP, &regs.regs.r_rip);
	uc_reg_read(m_uc, UC_X86_REG_EFLAGS, &regs.regs.r_rfl);
	return regs;
}


std::vector<IatInfo> iat::process_IAT(std::vector<uint64_t> iats)
{
	std::vector<IatInfo> result{};
	uc_err err{};
	REGS regs{};
	BYTE code[32];
	cs_insn* insn = NULL;

	//初始化堆栈
	uint8_t* stack = new uint8_t[STACK_SIZE];
	memset(stack, 0xff, STACK_SIZE);
	err = uc_mem_map(m_uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);
	err = uc_mem_write(m_uc, STACK_ADDR, stack, STACK_SIZE);
	delete[] stack;
	//初始化寄存器
	regs.regs.r_rsp = STACK_ADDR + STACK_SIZE - sizeof(ULONG_PTR) * 100;
	for (auto addr : iats)
	{
		IatInfo iatinfo{}; //默认为Mov类型的call
		iatinfo.addr = addr;
		iatinfo.origin_mnemonic = cmCall;
		iatinfo.direct = dNone;//5或者6
		regs.regs.r_rip = addr;
		write_regs(regs);
		while (1)
		{
			err = uc_mem_read(m_uc, regs.regs.r_rip, code, 32);
			cs_disasm(m_cshandle, code, 32, regs.regs.r_rip, 1, &insn);
			//开始模拟
			err = uc_emu_start(m_uc, regs.regs.r_rip, 0xffffffff, 0, 1);
			if (!strcmp(insn->mnemonic, "ret"))
			{
				if (insn->detail->x86.op_count > 0) //jmp
					iatinfo.origin_mnemonic = cmJmp;

				if (iatinfo.origin_mnemonic == cmMov)
					uc_reg_read(m_uc, iatinfo.api_reg, &iatinfo.api_addr); //如果是mov就读取寄存器
				else
					uc_mem_read(m_uc, regs.regs.r_rsp, &iatinfo.api_addr, sizeof(uint64_t)); //否则读取堆栈

				std::string apiName{};
				std::wstring modulename{};
				if (api::GetFuncName(m_Process.get_handler(), iatinfo.api_addr, apiName, modulename))
				{
					iatinfo.api_module = utils::to_string(modulename.substr(modulename.rfind(L"\\") + 1));
					iatinfo.api_name = apiName;
				}
				result.push_back(iatinfo); //记录
				break;
			}
			else if (!strcmp(insn->mnemonic, "pop") || !strcmp(insn->mnemonic, "push"))
			{
				uint64_t ret_addr = 0;
				regs = read_regs();
				uc_reg_read(m_uc, insn->detail->x86.operands[0].reg, &ret_addr);
				if (ret_addr == (addr + 5)) //push call
					iatinfo.direct = dBefore;
			}
			else if (!strcmp(insn->mnemonic, "lea"))
			{
				if (insn->detail->x86.operands[0].reg == insn->detail->x86.operands[1].mem.base)
				{
					if (insn->detail->x86.operands[1].mem.disp > 0x100000)
						iatinfo.api_reg = insn->detail->x86.operands[0].reg; //保存计算后api地址的寄存器
					else if (insn->detail->x86.operands[1].mem.disp == 1)
						iatinfo.direct = dAfter;
				}
			}
			else if (!strcmp(insn->mnemonic, "mov"))
			{
				if (iatinfo.api_reg != X86_REG_INVALID && iatinfo.api_reg == insn->detail->x86.operands[1].reg && insn->detail->x86.operands[0].reg != X86_REG_INVALID)
				{
					iatinfo.api_reg = insn->detail->x86.operands[0].reg;
					iatinfo.origin_mnemonic = cmMov; //把保存了api地址的寄存器重新赋值给另一个,说明为mov指令 
				}
			}
			regs = read_regs();
			cs_free(insn, 1);
		}
	}

	//释放内存
	uc_mem_unmap(m_uc, STACK_ADDR, STACK_SIZE);
	return result;
}
bool iat::fix_IAT(std::vector<IatInfo>& iatInfos)
{
	/*
		这里也要注意，因为x64和x86存在差异，修复的时候call/jmp/mov使用的是内存地址

		x86:
			mov eax,[12345678]  使用的硬编码是 A1 78 56 34 12
		x64
			mov reg,[12345678]  使用的硬编码是相对位移
	*/
	if (iatInfos.size() <= 0)
		return false;
	//生成iat表
	uint64_t lpMem = (uint64_t)m_Process.GetBaseModule() + m_pe->GetSectionHeader(".vmp0")->VirtualAddress;
	if (!lpMem)
		return false;

	DWORD oldatt{};
	VirtualProtectEx(m_Process.get_handler(), (LPVOID)lpMem, iatInfos.size() * 8 + 8, PAGE_EXECUTE_READWRITE, &oldatt);
	int i = 0;
	std::map<uint64_t, uint64_t> iat_map{}; // <api地址,存放api地址的ptr>
	for (auto& iat : iatInfos)
	{
		//是否已经存在api地址
		if (iat_map.count(iat.api_addr) == 0)
		{
			uint64_t new_addr = lpMem + i * 8;
			m_Process.WriteMemory((LPVOID)new_addr, &iat.api_addr, sizeof(uint64_t));
			iat_map[iat.api_addr] = new_addr;
		}


		uint64_t origin_addr = iat.addr;
		if (iat.direct == dBefore)
			origin_addr = origin_addr - 1;
		iat.addr = origin_addr;

		if (iat.api_module.empty())
		{
			//模块名为空说明此处不是iat调用,直接call 目的地址+nop
			/*
				1007B3C8 | 56                       | push esi                                                         |
				1007B3C9 | E8 37390000              | call <2.sub_1007ED05>                                            |
				1007B3CE | FF7424 10                | push dword ptr ss:[esp+10]                                       |
				1007B3D2 | 8B7424 10                | mov esi,dword ptr ss:[esp+10]                                    |
				1007B3D6 | 8B40 0C                  | mov eax,dword ptr ds:[eax+C]                                     |
				1007B3D9 | 56                       | push esi                                                         |
				1007B3DA | FF7424 10                | push dword ptr ss:[esp+10]                                       |
				1007B3DE | 50                       | push eax                                                         |
				1007B3DF | E8 AC4B3800              | call 2.103FFF90                                                  |
				1007B3E4 | C3                       | ret                                                              |

				103FFF90 | 90                       | nop                                                              |
				104BEBF4 | 50                       | push eax                                                         |
				104BEBF5 | 66:0F42C3                | cmovb ax,bx                                                      |
				104BEBF9 | 8AC6                     | mov al,dh                                                        |
				104BEBFB | 8B4424 04                | mov eax,dword ptr ss:[esp+4]                                     |
				104BEBFF | 8D40 01                  | lea eax,dword ptr ds:[eax+1]                                     |
				10482606 | 894424 04                | mov dword ptr ss:[esp+4],eax                                     |
				1048260A | 0F9EC4                   | setle ah                                                         |
				1048260D | 66:0F4EC3                | cmovle ax,bx                                                     |
				10482611 | B8 EDD40710              | mov eax,2.1007D4ED                                               |
				101FF555 | 8B80 AA494400            | mov eax,dword ptr ds:[eax+4449AA]                                | [eax]=[104C1E97]=ADFF1A33
				10171407 | 8D80 EE0D3B62            | lea eax,dword ptr ds:[eax+623B0DEE]                              | eax:103A2821
				10343D40 | 870424                   | xchg dword ptr ss:[esp],eax                                      | [esp]:EntryPoint
				10409930 | C3                       | ret                                                              |

				103A2821 | 55                       | push ebp                                                         |
				103A2822 | 8BEC                     | mov ebp,esp                                                      |
				10332834 | 53                       | push ebx                                                         |
				10268020 | 56                       | push esi                                                         |
				10268021 | 57                       | push edi                                                         |
				103D3B91 | E8 606EF0FF              | call 2.102DA9F6                                                  |

				102DA9F6 | 68 AD083225              | push 253208AD                                                    |
				102DA9FB | E8 888D1900              | call 2.10473788                                                  |

			*/
			char code[6] = { 0xE8,0x00,0x00,0x00,0x00,0x90 };
			*(int*)&code[1] = (iat.api_addr - origin_addr - 5);
			m_Process.WriteMemory((LPVOID)origin_addr, code, sizeof(code));
			iat.fix_offset = 0;
		}
		else
		{
			if (iat.origin_mnemonic == cmJmp || iat.origin_mnemonic == cmCall)
			{
				char code[] = { 0xFF,0x00,0x00,0x00,0x00,0x00 };
				if (iat.origin_mnemonic == cmJmp)
					code[1] = 0x25;
				else if (iat.origin_mnemonic == cmCall)
					code[1] = 0x15;

				*((int*)&code[2]) = iat_map[iat.api_addr] - origin_addr - 6;
				m_Process.WriteMemory((LPVOID)origin_addr, code, sizeof(code));
				iat.fix_offset = 2;
			}
			else if (iat.origin_mnemonic == cmMov)
			{
				if (iat.api_reg == X86_REG_RAX)
				{
					char code[] = { 0x48,0xA1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
					*((int64_t*)&code[2]) = iat_map[iat.api_addr];
					m_Process.WriteMemory((LPVOID)origin_addr, code, sizeof(code));
					iat.fix_offset = 2;
				}
				else
				{
					char code[] = { 0x48,0x8B,0x00,0x00,0x00,0x00,0x00 };
					if (iat.api_reg == X86_REG_RBX)
						code[2] = 0x1D;
					else if (iat.api_reg == X86_REG_RCX)
						code[2] = 0x0D;
					else if (iat.api_reg == X86_REG_RDX)
						code[2] = 0x15;
					else if (iat.api_reg == X86_REG_RBP)
						code[2] = 0x2D;
					else if (iat.api_reg == X86_REG_RSP)
						code[2] = 0x25;
					else if (iat.api_reg == X86_REG_RSI)
						code[2] = 0x35;
					else if (iat.api_reg == X86_REG_RDI)
						code[2] = 0x3D;
					else if (iat.api_reg == X86_REG_R8)
					{
						code[0] = 0x4c;
						code[2] = 0x05;
					}
					else if (iat.api_reg == X86_REG_R9)
					{
						code[0] = 0x4c;
						code[2] = 0x0D;
					}
					else if (iat.api_reg == X86_REG_R10)
					{
						code[0] = 0x4c;
						code[2] = 0x15;
					}
					else if (iat.api_reg == X86_REG_R11)
					{
						code[0] = 0x4c;
						code[2] = 0x1d;
					}
					else if (iat.api_reg == X86_REG_R12)
					{
						code[0] = 0x4c;
						code[2] = 0x25;
					}
					else if (iat.api_reg == X86_REG_R13)
					{
						code[0] = 0x4c;
						code[2] = 0x2d;
					}
					else if (iat.api_reg == X86_REG_R14)
					{
						code[0] = 0x4c;
						code[2] = 0x35;
					}
					else if (iat.api_reg == X86_REG_R15)
					{
						code[0] = 0x4c;
						code[2] = 0x3d;
					}

					*((int*)&code[3]) = iat_map[iat.api_addr] - origin_addr - 7;
					m_Process.WriteMemory((LPVOID)origin_addr, code, sizeof(code));
					iat.fix_offset = 3;
				}
			}
			else
			{
				iat.fix_offset = 1;
			}
		}
		i++;
	}

	return true;
}
bool iat::fix_Dump(uint32_t rva_oep, std::vector<IatInfo> iatList, std::string output)
{
	pe p{ m_Process.get_pid(),m_targetModule };
	if (!p._validate())
		return false;
	//分类
	std::map<std::string, std::map<std::string, std::vector<uint64_t>>> AddedImports;
	for (auto iat : iatList)
	{
		if (!iat.api_module.empty())
			AddedImports[iat.api_module][iat.api_name].push_back(iat.addr + iat.fix_offset - p.GetOptionalHeader()->ImageBase);
	}

	p.AddModuleImport(p.GetOptionalHeader()->ImageBase, rva_oep, AddedImports);

	return p.WriteToFile(output);
}