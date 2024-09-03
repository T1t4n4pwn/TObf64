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

		//TODO: Ϊjccָ�����תĿ�����޸�(ָ��������һ����Ϊ������jccָ�����תĿ��Ҳ�����Ҫ�޸�)
		for (size_t i = 0; i < code.size(); i++)
		{

			auto handler = g_obf_processes.find(code[i].instruction.mnemonic);
			if (handler == g_obf_processes.end()) {
				//δ�ҵ���Ӧ���������߼��ģ�����ԭ�ֽڷŻ�ȥ���˴��������ض�λ����
				obf_code.insert(obf_code.end(), &code[i].bytes[0], &code[i].bytes[0] + code[i].instruction.length);

				addr += code[i].instruction.length;

				continue;
			}

			if (!handler->second(code[i], obf_code, addr)) {
				//ͬ���������ʧ�ܣ���ԭ�ⲻ���Ż�ȥ���˴��������ض�λ����
				obf_code.insert(obf_code.end(), &code[i].bytes[0], &code[i].bytes[0] + code[i].instruction.length);

				addr += code[i].instruction.length;

				continue;
			}
		}

		return true;
	}

};