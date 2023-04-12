#include"utils.h"

std::map<ECommandType, std::string> utils::mnemonicColor = {
	{cmUnknown,FONT_COLOR_NONE},
	{cmVMEntry,FONT_COLOR_WHITE},
	{cmPush,FONT_COLOR_BLUE},
	{cmPop,FONT_COLOR_BLUE},
	{cmRet,FONT_COLOR_CYAN},
	{cmMov,FONT_COLOR_YELLOW},
	{cmAnd,FONT_COLOR_YELLOW},
	{cmOr,FONT_COLOR_YELLOW},
	{cmNand,FONT_COLOR_YELLOW},
	{cmNor,FONT_COLOR_YELLOW},
	{cmSub,FONT_COLOR_YELLOW},
	{cmAdd,FONT_COLOR_YELLOW},
	{cmShl,FONT_COLOR_YELLOW},
	{cmShr,FONT_COLOR_YELLOW},
	{cmShld,FONT_COLOR_YELLOW},
	{cmShrd,FONT_COLOR_YELLOW},
	{cmJmp,FONT_COLOR_RED},
	{cmMul,FONT_COLOR_YELLOW},
	{cmImul,FONT_COLOR_YELLOW},
	{cmDiv,FONT_COLOR_YELLOW},
	{cmIdiv,FONT_COLOR_YELLOW},
};


std::string utils::get_curt_time()
{
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	char buf[1024]{};
	sprintf(buf, "%4d-%02d-%02d-%02d-%02d-%02d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
	return buf;
}

std::string utils::get_current_path()
{
	char buf[1024]{};
	GetModuleFileNameA(NULL, buf, 1024);

	std::string path(buf);
	return path.substr(0, path.rfind("\\"));
}

std::set<x86_reg> utils::_union(std::set<x86_reg> a, std::set<x86_reg> b)
{
	std::set<x86_reg> ret;
	std::set_union(a.begin(), a.end(), b.begin(), b.end(), inserter(ret, ret.begin()));
	return ret;
}

std::set<x86_reg> utils::_difference(std::set<x86_reg> a, std::set<x86_reg> b)
{
	std::set<x86_reg> ret;
	set_difference(a.begin(), a.end(), b.begin(), b.end(), inserter(ret, ret.begin()));
	return ret;
}

std::set<x86_reg> utils::_intersection(std::set<x86_reg> a, std::set<x86_reg> b)
{
	std::set<x86_reg> ret;
	set_intersection(a.begin(), a.end(), b.begin(), b.end(), inserter(ret, ret.begin()));
	return ret;
}

std::string utils::get_dataWeight(int d)
{
	static std::string prefix[] = { "?","b","w","f","d","?","?","?","q" };
	int l = sizeof(prefix) / sizeof(std::string);
	if (d > l)
		return prefix[0];
	return prefix[d];
}

std::string utils::utf8_to_gbk(const char* utf8)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len + 1];
	memset(wstr, 0, len + 1);
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wstr, len);
	len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
	char* str = new char[len + 1];
	memset(str, 0, len + 1);
	WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, NULL, NULL);
	if (wstr) delete[] wstr;
	std::string ret(str);
	if (str) delete[] str;
	return ret;
}

std::string utils::str_replace(std::string str, const std::string old_value, const std::string new_value)
{
	for (std::string::size_type pos(0); pos != std::string::npos; pos += new_value.length())
	{
		if ((pos = str.find(old_value, pos)) != std::string::npos)
			str.replace(pos, old_value.length(), new_value);
		else break;
	}
	return str;
}

uint64_t utils::hexToInteger(std::string hex)
{
	std::stringstream ss2;
	uint64_t d2;
	ss2 << std::hex << hex; //选用十六进制输出
	ss2 >> d2;

	return d2;
}

// 12 -> C
std::string utils::IntegerTohex(uint64_t dec)
{
	std::stringstream ss2;
	ss2 << std::hex << dec;
	return ss2.str();
}

// 12 -> 0000000C
std::string utils::IntegerTohex2(uint64_t dec)
{
	char buffer[100]{};
	sprintf(buffer, "%p", dec);
	return buffer;
}

std::string utils::to_string(const std::wstring& str)
{
	std::string result;
	//获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
	int len = WideCharToMultiByte(CP_ACP, 0, str.c_str(), str.size(), NULL, 0, NULL, NULL);
	char* buffer = new char[len + 1];
	//宽字节编码转换成多字节编码  
	WideCharToMultiByte(CP_ACP, 0, str.c_str(), str.size(), buffer, len, NULL, NULL);
	buffer[len] = '\0';
	//删除缓冲区并返回值  
	result.append(buffer);
	delete[] buffer;
	return result;
}

std::string utils::openFileDlg()
{
	OPENFILENAME ofn;
	char szFile[300];
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = (LPWSTR)szFile;
	ofn.lpstrFile[0] = '\0';
	LPTSTR lpstrCustomFilter;
	DWORD nMaxCustFilter;
	ofn.nFilterIndex = 1;
	LPTSTR lpstrFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"ALL\0*.*\0Text\0*.TXT\0";
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	std::string path_image = "";
	if (GetOpenFileName(&ofn))
	{
		path_image = utils::to_string(ofn.lpstrFile);//文件路径转化为字符串
		return path_image;
	}
	else
	{
		return "";
	}
}

std::string utils::get_midString(const std::string src, const std::string left, const std::string right)
{
	int left_index = src.find(left) + 1;
	if (left_index == std::string::npos)
		return "";
	int right_index = src.find(right);
	if (right_index == std::string::npos)
		return "";

	int len = right_index - left_index;
	if (len <= 0)
		return "";
	return src.substr(left_index, len);
}


void utils::split(const std::string& str, const std::string& split, std::vector<std::string>& res)
{
	std::regex reg(split);		// 匹配split
	std::sregex_token_iterator pos(str.begin(), str.end(), reg, -1);
	decltype(pos) end;              // 自动推导类型 
	for (; pos != end; ++pos)
	{
		res.push_back(pos->str());
	}
}

void utils::_assert(bool expression, const char* format, ...)
{
	if (expression)
	{
		char message[1024];
		va_list args;
		va_start(args, format);
		vsprintf(message, format, args);
		va_end(args);
		MessageBoxA(NULL, message, "Assertion failed", MB_OK | MB_ICONERROR);
		exit(EXIT_FAILURE);
	}
}

