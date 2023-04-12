#pragma once
#include"pch.h"


#define     FONT_COLOR_NONE					"</font>"
#define		FONT_COLOR_BLACK				"<font color=black>"
#define     FONT_COLOR_RED					"<font color=red>"
#define     FONT_COLOR_GREEN				"<font color=green>"
#define		FONT_COLOR_BROWN				"<font color=brown>"
#define		FONT_COLOR_BLUE					"<font color=blue>"
#define		FONT_COLOR_PINK					"<font color=pink>"
#define		FONT_COLOR_CYAN					"<font color=cyan>"
#define		FONT_COLOR_GRAY					"<font color=gray>"
#define		FONT_COLOR_YELLOW				"<font color=yellow>"
#define		FONT_COLOR_WHITE				"<font color=white>"

class utils
{
public:
	static std::map<ECommandType, std::string> mnemonicColor;


	static std::string get_curt_time();
	static std::string get_current_path();
	static std::set<x86_reg> _union(std::set<x86_reg> a, std::set<x86_reg> b);
	static std::set<x86_reg> _difference(std::set<x86_reg> a, std::set<x86_reg> b);
	static std::set<x86_reg> _intersection(std::set<x86_reg> a, std::set<x86_reg> b);
	static std::string get_dataWeight(int d);
	static std::string utf8_to_gbk(const char* utf8);
	static std::string str_replace(std::string str, const std::string old_value, const std::string new_value);
	static uint64_t hexToInteger(std::string hex);
	// 12 -> C
	static std::string IntegerTohex(uint64_t dec);
	// 12 -> 0000000C
	static std::string IntegerTohex2(uint64_t dec);
	static std::string to_string(const std::wstring& str);
	static std::string openFileDlg();
	static std::string get_midString(const std::string src, const std::string left, const std::string right);
	static void split(const std::string& str, const std::string& split, std::vector<std::string>& res);
	static void _assert(bool expression, const char* format, ...);
};
