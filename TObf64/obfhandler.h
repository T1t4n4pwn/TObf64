#pragma once
#include <iostream>
#include <vector>
#include "disasm.h"


typedef bool(*PFN_OBF_PROCESS)(INST_INFO code, std::vector<uint8_t>& obf_code, uint64_t& current_addr);

bool process_lea(INST_INFO insn, std::vector<uint8_t>& obf_code, uint64_t& current_addr);
bool process_mov(INST_INFO insn, std::vector<uint8_t>& obf_code, uint64_t& current_addr);
bool process_call(INST_INFO insn, std::vector<uint8_t>& obf_code, uint64_t& current_addr);