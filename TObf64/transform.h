#pragma once
#include <iostream>
#include <vector>
#include <map>
#include "obfhandler.h"


static std::map<uint32_t, PFN_OBF_PROCESS> g_obf_processes = {
	{ZYDIS_MNEMONIC_LEA, process_lea},
	{ZYDIS_MNEMONIC_MOV, process_mov},
	{ZYDIS_MNEMONIC_CALL, process_call},
};

class Transform {
public:

	static bool process(std::vector<INST_INFO> code, uint64_t& addr, std::vector<uint8_t>& obf_code) {

		//TODO: 为jcc指令的跳转目标做修复(指令混淆后从一条变为多条，jcc指令的跳转目标也因此需要修复)
		for (size_t i = 0; i < code.size(); i++)
		{

			auto handler = g_obf_processes.find(code[i].instruction.mnemonic);
			if (handler == g_obf_processes.end()) {
				//未找到对应混淆处理逻辑的，按照原字节放回去，此处不考虑重定位问题
				obf_code.insert(obf_code.end(), &code[i].bytes[0], &code[i].bytes[0] + code[i].instruction.length);

				addr += code[i].instruction.length;

				continue;
			}

			if (!handler->second(code[i], obf_code, addr)) {
				//同理，如果处理失败，则原封不动放回去，此处不考虑重定位问题
				obf_code.insert(obf_code.end(), &code[i].bytes[0], &code[i].bytes[0] + code[i].instruction.length);

				addr += code[i].instruction.length;

				continue;
			}
		}

		return true;
	}

};