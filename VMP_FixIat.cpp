// VMP_FixIat.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include"iat.h"
int main()
{
    iat _iat{ 9024,"contest.exe" };
    std::vector<uint64_t> iatlist = _iat.search_IAT(0x00007FF7A27A1000, 0x26000, 0x00007FF7A2889000, 0x370000);
    if (iatlist.size() <= 0)
    {
        MessageBoxA(NULL, "not found iat", "pjvmp", NULL);
        return 0;
    }

    std::vector<IatInfo> fix_result = _iat.process_IAT(iatlist);
    if (_iat.fix_IAT(fix_result))
        MessageBoxA(NULL, "fix iat success", "pjvmp", NULL);
    else
    {
        MessageBoxA(NULL, "fix iat failed", "pjvmp", NULL);
        fix_result.clear();
    }


    if (_iat.fix_Dump(0x1945C, fix_result, "contest.exe.pjvmp"))
        MessageBoxA(NULL, "fix dump success", "pjvmp", NULL);
    else
        MessageBoxA(NULL, "fix dump failed", "pjvmp", NULL);

    return 0;
}

